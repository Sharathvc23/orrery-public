"""The booking store keeps every accepted booking, and every booking has a receipt.

Both properties were false and both were found by driving the SMB host over HTTP
rather than by reading the skill:

* 20 bookings issued concurrently against ONE tenant returned HTTP 200 twenty
  times, wrote 20 signed receipts, and left 7 bookings on disk. Three at once was
  enough to lose one. On another tenant the same run left ``bookings.json``
  holding a closing "]" followed by another object — invalid JSON, which
  ``_load`` then reported as an empty store, so the damage read as "no bookings
  yet" and ids restarted at 1 and collided across receipts.
* With the Agency Log unwritable, a booking was saved and the receipt then
  failed: the store went from 1 booking to 2 while receipts stayed at 1, and the
  caller got a 500. The booking was durable and unaccountable, and a retry would
  add another.

These tests drive the skill directly rather than the host, so they run without a
server, and they assert COUNTS on disk rather than the return value — the return
value was correct in both failures.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading

import pytest

from community_member import arp, keystore
from community_member import config as cm_config
from community_member.builtin_skills.booking import skill
from community_member.config import Config


@pytest.fixture
def _isolated_home(tmp_path, monkeypatch):
    """Same isolation as test_booking_skill.py — device keystore, temp home."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    yield tmp_path
    keystore.reset_for_tests()


@pytest.fixture
def home(_isolated_home):
    """An agent home holding a real identity, so receipts are genuinely signed."""
    cfg = Config()
    cfg.agent_id = "booking-integrity-agent"
    cfg.ensure_keypair()
    cfg.save()
    return _isolated_home


def _counts(home) -> tuple[int, int]:
    """(bookings on disk, receipts in the Agency Log).

    Reads the raw file rather than going through ``_load``, so these counts stay
    a measurement of what is on disk and do not depend on the loader being the
    thing under test in the tests below.
    """
    path = home / "bookings.json"
    if not path.exists():
        bookings = 0
    else:
        bookings = len(json.loads(path.read_text()))  # raises if corrupt — that is a failure

    db = home / "agency-log.sqlite"
    if not db.exists():
        return bookings, 0
    con = sqlite3.connect(db)
    try:
        return bookings, con.execute("select count(*) from receipts").fetchone()[0]
    except sqlite3.OperationalError:
        return bookings, 0
    finally:
        con.close()


def test_receipt_and_booking_are_both_written_on_the_happy_path(home):
    """The baseline. Without this the two tests below could pass on a skill
    that never books at all."""
    out = skill.book_appointment(
        {"service": "haircut", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    assert out["receipt_id"]
    assert _counts(home) == (1, 1)


def test_concurrent_bookings_are_all_kept(home):
    """N bookings accepted concurrently leave N on disk and N receipts.

    The store is a read-modify-write over one JSON file and the SMB host serves
    `book` from a threadpool, so this is the real access pattern, not a stress
    test for its own sake.
    """
    n = 12
    errors: list[BaseException] = []
    barrier = threading.Barrier(n)

    def book(i: int) -> None:
        try:
            barrier.wait(timeout=30)  # start together, so the writes really overlap
            skill.book_appointment(
                {"service": f"order-{i}", "provider": "Ada", "datetime": f"2026-09-01T{10 + i:02d}:00:00Z"},
                home=home,
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=book, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, f"booking raised under concurrency: {errors[:3]}"

    bookings, receipts = _counts(home)
    assert bookings == n, f"{n - bookings} of {n} concurrent bookings were lost"
    assert receipts == n, f"{n - receipts} of {n} concurrent bookings have no receipt"

    ids = [b["id"] for b in json.loads((home / "bookings.json").read_text())]
    assert len(set(ids)) == n, f"booking ids repeat under concurrency: {sorted(ids)}"


def test_a_booking_is_not_recorded_when_the_log_cannot_take_the_attempt(home):
    """A signing agent whose Agency Log is unwritable must not leave a booking.

    The attempt is written BEFORE the booking (write-ahead), so an unwritable
    log refuses at that write and nothing is stored. The fault is injected as
    it actually happens: sqlite3.OperationalError('attempt to write a readonly
    database') out of the first Agency Log write.
    """
    skill.book_appointment(
        {"service": "first", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    before = _counts(home)
    assert before == (1, 1)

    def boom(self, **kw):  # noqa: ANN001, ARG001
        raise sqlite3.OperationalError("attempt to write a readonly database")

    original = arp.AgencyLog.begin_action
    arp.AgencyLog.begin_action = boom
    try:
        with pytest.raises(sqlite3.OperationalError):
            skill.book_appointment(
                {"service": "second", "provider": "Ada", "datetime": "2026-09-01T12:00:00Z"},
                home=home,
            )
    finally:
        arp.AgencyLog.begin_action = original

    assert _counts(home) == before, (
        "a booking was recorded even though the Agency Log could not record the attempt — "
        "the store now holds a booking with no record of it anywhere"
    )


def test_a_receipt_that_fails_after_the_booking_is_written_is_owed_not_forged(home):
    """The receipt is signed only for a booking that EXISTS. If its write fails
    after the booking was stored, the booking stands and is reported, and the
    attempt records that a receipt is owed — the previous ordering signed a
    ``completed`` receipt before the booking was written, so a failing store
    write left a receipt for an appointment that did not exist.
    """
    before = _counts(home)

    def boom(self, receipt):  # noqa: ANN001, ARG001
        raise sqlite3.OperationalError("attempt to write a readonly database")

    original = arp.AgencyLog.append
    arp.AgencyLog.append = boom
    try:
        out = skill.book_appointment(
            {"service": "second", "provider": "Ada", "datetime": "2026-09-01T12:00:00Z"},
            home=home,
        )
    finally:
        arp.AgencyLog.append = original

    assert out["booked"]["id"] == before[0] + 1
    assert out["receipt_id"] is None and "owed" in out["receipt_note"]
    assert _counts(home) == (before[0] + 1, before[1]), (
        "a receipt was signed for a booking whose write was not observed"
    )
    log = arp.AgencyLog(home)
    owed = log.get_attempt(out["attempt_id"])
    assert owed["state"] == "succeeded" and owed["receipt_id"] is None
    assert [a["attempt_id"] for a in log.unresolved_actions()] == [owed["attempt_id"]]
    # The slot is taken: a retry is refused by the log even before the store is consulted.
    again = skill.book_appointment(
        {"service": "second", "provider": "Ada", "datetime": "2026-09-01T12:00:00Z"},
        home=home,
    )
    assert "error" in again and _counts(home) == (before[0] + 1, before[1])


def test_a_keyless_agent_still_books(_isolated_home):
    """The ordering change must not turn a keyless agent into a failure.

    A keyless agent has no receipt to persist; it books and says so. This is the
    contract test_booking_skill.py already pins, restated here because the
    ordering change is exactly what could break it.
    """
    out = skill.book_appointment(
        {"service": "haircut", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=_isolated_home,
    )
    assert out["booked"]["service"] == "haircut"
    assert out["receipt_id"] is None
    assert out["receipt_note"]
    assert _counts(_isolated_home)[0] == 1


def test_a_damaged_store_is_not_reported_as_an_empty_one(home):
    """The defining defect: `except (ValueError, OSError): return []`.

    A store that exists but does not parse used to read as zero bookings. That
    is what turned a lost write into lost data — the agent showed no bookings
    while customers held valid signed receipts, and nothing said the file was
    broken.
    """
    skill.book_appointment(
        {"service": "first", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    store = home / "bookings.json"
    # Exactly the shape the host produced: a complete array, then a second one.
    store.write_text(store.read_text() + "  " + store.read_text())

    with pytest.raises(skill.BookingStoreUnreadable) as caught:
        skill._load(home)
    assert str(store) in str(caught.value), "the error must name the file an operator has to open"


def test_a_damaged_store_is_never_overwritten(home):
    """Refusing is only worth anything if the surviving rows stay recoverable.

    The old behaviour read the damaged file as empty and the next write replaced
    it, destroying both the surviving bookings and the evidence.
    """
    skill.book_appointment(
        {"service": "first", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    store = home / "bookings.json"
    damaged = store.read_text() + "  " + store.read_text()
    store.write_text(damaged)

    with pytest.raises(skill.BookingStoreUnreadable):
        skill.book_appointment(
            {"service": "second", "provider": "Ada", "datetime": "2026-09-02T10:00:00Z"},
            home=home,
        )

    assert store.read_text() == damaged, "the damaged store was modified, so its contents are unrecoverable"


def test_a_store_holding_the_wrong_type_is_also_a_refusal(home):
    """`return data if isinstance(data, list) else []` was the same defect.

    A JSON object where a list belongs read as an empty store just as silently.
    """
    (home / "bookings.json").write_text('{"bookings": []}')
    with pytest.raises(skill.BookingStoreUnreadable):
        skill._load(home)


def test_a_missing_store_is_still_empty(home):
    """The case that must NOT raise: no file is genuinely no bookings.

    This is every agent's first booking, so getting it wrong would refuse the
    common path in the name of the rare one.
    """
    assert not (home / "bookings.json").exists()
    assert skill._load(home) == []

    out = skill.book_appointment(
        {"service": "first", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    assert out["receipt_id"]


def test_an_unreadable_store_does_not_read_as_empty_either(home):
    """OSError was swallowed by the same handler.

    A store that cannot be read for permission or I/O reasons is not an empty
    one, and booking on top of it would write over whatever it holds.
    """
    skill.book_appointment(
        {"service": "first", "provider": "Ada", "datetime": "2026-09-01T10:00:00Z"},
        home=home,
    )
    store = home / "bookings.json"
    store.chmod(0o000)
    try:
        if os.access(store, os.R_OK):
            pytest.skip("running as a user that ignores file permissions (root)")
        with pytest.raises(OSError):
            skill._load(home)
    finally:
        store.chmod(0o644)


def test_concurrent_writers_never_leave_the_store_unparseable(home):
    """Overlapping writes must leave the whole old store or the whole new one.

    ``write_text`` truncates and then fills, so two writers overlapping in that
    window interleave into invalid JSON. That is what happened on the host, and
    it is worse than losing a booking: ``_load`` catches the decode error and
    returns [], so a damaged store reads as an empty one and the next booking
    starts numbering at 1 again.

    A single pass would only fail when the scheduler cooperates, so this runs
    repeated rounds of differently-sized concurrent writes; the pre-fix
    implementation failed 18 of 60 such rounds.
    """
    payloads = [[{"id": i, "service": "y" * (i * 40)} for i in range(n)] for n in (1, 25, 2, 30)]

    for round_no in range(25):
        threads = [threading.Thread(target=skill._save, args=(p,), kwargs={"home": home}) for p in payloads]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        raw = (home / "bookings.json").read_text()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"round {round_no}: concurrent writes left the store unparseable "
                f"({exc}); first 200 bytes: {raw[:200]!r}"
            )
        assert parsed in payloads, f"round {round_no}: store is parseable but is not any single write"
