"""Built-in 'booking' skill — book an appointment + emit a signed ARP receipt.

The SMB "operate" stage of the demo loop: the agent performs a concrete action
(booking) and mints a signed, independently-verifiable ``appointment_booked``
receipt for it. This test proves both halves against a real generated identity
in an isolated home:

  HAPPY  — book_appointment persists the booking to bookings.json AND emits a
           receipt that ``arp.verify_receipt`` strict-accepts offline.
  HAPPY  — the receipt lands in the local Agency Log under the same home.
  EDGE   — a keyless agent still books, and returns a clear "receipt skipped"
           note instead of crashing.
  FAILURE— a missing required field is a clean error, not a booking.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import arp, keystore
from community_member import config as cm_config
from community_member import skill_runtime as sr
from community_member.config import Config


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect config + keystore to an isolated temp home, device backend.

    Pinning ``COMMUNITY_MEMBER_KEYSTORE=device`` keeps the store deterministic
    regardless of the host's OS keyring / tty (mirrors test_keystore.py).
    """
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    yield tmp_path
    keystore.reset_for_tests()


def _book_tool():
    loaded = sr.load_builtin_skills()
    skill = next(s for s in loaded if s.name == "booking")
    return skill.tools["book_appointment"]


def _make_identity() -> Config:
    cfg = Config()
    cfg.agent_id = "booking-test-agent"
    cfg.ensure_keypair()
    cfg.save()  # persists config.json + stores the private key in the keystore
    return cfg


def test_booking_skill_is_discovered_and_active(home):
    """The skill is in the starter pack, so the built-in loader exposes it."""
    names = {s.name for s in sr.load_builtin_skills()}
    assert "booking" in names


def test_book_appointment_persists_and_receipt_verifies(home):
    _make_identity()
    book = _book_tool()

    out = book(
        {
            "service": "haircut",
            "provider": "Sharp Cuts",
            "datetime": "2026-08-01T14:30:00Z",
            "notes": "trim only",
        }
    )

    # (a) booking persisted to bookings.json
    assert out["booked"]["id"] == 1
    assert out["booked"]["service"] == "haircut"
    saved = (home / "bookings.json").read_text()
    assert "Sharp Cuts" in saved

    # (b) a receipt was emitted
    receipt_id = out["receipt_id"]
    assert receipt_id

    # It's in the local Agency Log and strict-verifies OFFLINE.
    log = arp.AgencyLog(home)
    receipt = log.get(receipt_id)
    assert receipt is not None
    assert receipt["action"]["category"] == "appointment_booked"
    assert receipt["action"]["machine_payload"]["provider"] == "Sharp Cuts"

    res = arp.verify_receipt(receipt)
    assert res.ok and res.stage == "accepted"


def test_book_appointment_keyless_agent_books_but_skips_receipt(home):
    """A keyless agent is still a valid agent: it books, and says the receipt
    was skipped, rather than crashing."""
    book = _book_tool()
    out = book(
        {
            "service": "consult",
            "provider": "Acme Advisors",
            "datetime": "2026-08-02T09:00:00Z",
        }
    )
    assert out["booked"]["id"] == 1
    assert out["receipt_id"] is None
    assert "receipt_note" in out
    # No receipt written to the Agency Log.
    assert arp.AgencyLog(home).count() == 0


def test_book_appointment_missing_field_is_clean_error(home):
    _make_identity()
    out = _book_tool()({"service": "haircut", "provider": "Sharp Cuts"})
    assert "error" in out
    assert "datetime" in out["error"]
    # Nothing was booked.
    assert not (home / "bookings.json").exists()


# ── the booking reaches the business ─────────────────────────────────────────


def test_the_attempt_is_persisted_before_the_booking(home, monkeypatch):
    """The ordering this module documents survives the delivery change.

    A booking must not exist without a record of it. The record is the
    write-ahead attempt in the Agency Log, written before the store; delivery
    was added after the booking is recorded and must not have moved that
    write behind it. Asserted by making the attempt write raise and checking
    the store is empty. (The receipt itself is signed AFTER the booking is
    written, so it never attests a booking that failed to store.)
    """
    from community_member.arp import AgencyLog
    from community_member.builtin_skills.booking import skill

    _make_identity()

    def _boom(self, **kw):
        raise RuntimeError("agency log is unwritable")

    monkeypatch.setattr(AgencyLog, "begin_action", _boom)
    with pytest.raises(RuntimeError):
        skill.book_appointment(
            {"service": "haircut", "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"},
            home=home,
        )
    assert skill._load(home) == [], "a booking survived an attempt that could not be written"


def test_delivery_failure_does_not_destroy_a_receipted_booking(tmp_path):
    """A business that cannot be reached must not cost the customer the booking.

    The customer already holds a signed receipt by the time delivery is
    attempted, so an undeliverable channel is reported and the booking stands.
    """
    from community_member.builtin_skills.booking import notify, skill

    class _Exploding:
        kind = notify.CONTACT_WEBHOOK

        def send(self, contact, booking, ics):
            raise RuntimeError("this sender must not be allowed to escape")

    contact = notify.parse_contact("https://bookings.example/hook")
    # deliver() never raises, so even a sender that does is contained
    result = notify.deliver(
        {"id": 1, "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"},
        contact,
        senders={notify.CONTACT_WEBHOOK: notify.WebhookSender(post=_raiser)},
    )
    assert result.delivered is False
    assert "webhook post failed" in result.reason

    out = skill.book_appointment(
        {"service": "haircut", "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"},
        home=tmp_path,
        contact=contact,
    )
    assert out["delivered"] is False
    assert len(skill._load(tmp_path)) == 1, "an undelivered booking was not recorded"


def _raiser(url, json):
    raise ConnectionError("unreachable")


def test_the_ics_parses_and_carries_the_booked_appointment():
    """The calendar event is built from the booking, so it cannot drift from it."""
    from community_member.builtin_skills.booking import notify

    booking = {
        "id": 7,
        "service": "birthday cake",
        "provider": "Moon Bakery",
        "datetime": "2026-09-02T10:30:00Z",
        "notes": "vanilla, no nuts",
    }
    ics = notify.build_ics(booking, business_name="Moon Bakery")

    lines = [line for line in ics.split("\r\n") if line]
    assert lines[0] == "BEGIN:VCALENDAR"
    assert lines[-1] == "END:VCALENDAR"
    assert lines.count("BEGIN:VEVENT") == 1 and lines.count("END:VEVENT") == 1

    fields = dict(line.split(":", 1) for line in lines if ":" in line and not line.startswith("ORGANIZER"))
    assert fields["DTSTART"] == "20260902T103000Z"
    assert fields["DTEND"] == "20260902T113000Z", "the event has no end, so a calendar cannot place it"
    assert booking["provider"] in fields["SUMMARY"]
    assert booking["service"] in fields["SUMMARY"]


def test_a_datetime_a_calendar_cannot_express_is_refused_not_guessed():
    """An event at a time nobody booked is worse than no event."""
    from community_member.builtin_skills.booking import notify

    with pytest.raises(ValueError, match="not an ISO-8601 timestamp"):
        notify.build_ics({"id": 1, "provider": "Sam", "datetime": "next tuesday"})


def test_a_contact_is_classified_by_shape_not_by_a_caller_label():
    from community_member.builtin_skills.booking import notify

    assert notify.parse_contact("https://x.example/hook").kind == notify.CONTACT_WEBHOOK
    assert notify.parse_contact("owner@x.example").kind == notify.CONTACT_EMAIL
    with pytest.raises(notify.ContactError, match="must be https"):
        notify.parse_contact("http://x.example/hook")
    with pytest.raises(notify.ContactError, match="names no channel"):
        notify.parse_contact("call me maybe")
    with pytest.raises(notify.ContactError, match="no contact was given"):
        notify.parse_contact("")


def test_no_configured_sender_is_reported_not_treated_as_delivered():
    from community_member.builtin_skills.booking import notify

    booking = {"id": 1, "provider": "Sam", "datetime": "2026-09-01T10:00:00Z"}
    email = notify.deliver(booking, notify.parse_contact("owner@x.example"))
    assert email.delivered is False
    assert "no sender is configured for the email channel" in email.reason

    none_at_all = notify.deliver(booking, None)
    assert none_at_all.delivered is False
    assert "no contact channel is recorded" in none_at_all.reason
