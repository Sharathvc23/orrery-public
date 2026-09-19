"""`ok` and `authenticated` answer different questions, and the CLI says which.

`ok` is whether the chain is internally consistent — hashes link, nothing
reordered, nothing dropped. A ledger that ran before a signing key was
configured is honestly consistent, so `ok` stays true for it.

`authenticated` is whether the ledger was appended to outside `record()`. One
boolean cannot carry both, and conflating them is how a green "verified" came to
be printed over a ledger containing a row the agent never wrote.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from community_member.consent import ledger

CHAPTER = "local:verify"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


def _key() -> str:
    from nacl.signing import SigningKey

    return base64.b64encode(bytes(SigningKey.generate())).decode()


def _seed(db: Path, *, keyed: bool, rows: int = 3) -> None:
    ledger.init(db, signing_key_b64=_key() if keyed else None)
    for i in range(rows):
        ledger.record(chapter_id=CHAPTER, action="seed", outcome="ok", detail={"i": i})


def _append_unsigned(db: Path) -> None:
    """A correctly-hashed row that record() did not write — the sweep's forgery."""
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    prev = con.execute("SELECT event_sha256 FROM consent_events ORDER BY id DESC LIMIT 1").fetchone()["event_sha256"]
    occurred = datetime.now(UTC).isoformat()
    detail = {"capability": "shell.exec", "scope": "curl"}
    event = {
        "chapter_id": CHAPTER,
        "actor_agent_id": None,
        "action": "consent.approved",
        "target_type": None,
        "target_id": None,
        "outcome": "ok",
        "detail": detail,
        "occurred_at": occurred,
        "prev_sha256": prev,
    }
    con.execute(
        "INSERT INTO consent_events (chapter_id, actor_agent_id, action, target_type, target_id, "
        "outcome, detail, occurred_at, prev_sha256, event_sha256, signature_b64) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            CHAPTER,
            None,
            "consent.approved",
            None,
            None,
            "ok",
            json.dumps(detail, sort_keys=True),
            occurred,
            prev,
            ledger.sha256_of(event),
            None,
        ),
    )
    con.commit()
    con.close()


# ── `ok` keeps its meaning ────────────────────────────────────────────


def test_ok_stays_true_on_a_keyed_and_fully_signed_ledger(tmp_path):
    _seed(tmp_path / "c.db", keyed=True)
    assert ledger.verify_chain()["ok"] is True


def test_ok_stays_true_on_a_pre_key_ledger(tmp_path):
    """The verdict must not flip for a ledger that ran before a key existed.
    Redefining `ok` as 'signed' would break every honest one of those."""
    _seed(tmp_path / "c.db", keyed=False)
    assert ledger.verify_chain()["ok"] is True


def test_ok_stays_true_when_an_unsigned_row_is_appended(tmp_path):
    """The row breaks authenticity, not consistency. `ok` is about consistency."""
    db = tmp_path / "c.db"
    _seed(db, keyed=True)
    _append_unsigned(db)
    assert ledger.verify_chain()["ok"] is True


def test_ok_is_false_when_the_chain_is_actually_broken(tmp_path):
    db = tmp_path / "c.db"
    _seed(db, keyed=True)
    con = sqlite3.connect(db)
    con.execute("UPDATE consent_events SET detail = ? WHERE id = 1", (json.dumps({"tampered": True}),))
    con.commit()
    con.close()
    assert ledger.verify_chain()["ok"] is False


# ── `authenticated` answers the other question ────────────────────────


def test_authenticated_is_true_when_every_row_is_signed(tmp_path):
    _seed(tmp_path / "c.db", keyed=True)
    assert ledger.verify_chain()["authenticated"] is True


def test_authenticated_is_false_when_a_row_was_not_written_by_record(tmp_path):
    """The reproduction from the security sweep, at the aggregate level."""
    db = tmp_path / "c.db"
    _seed(db, keyed=True)
    _append_unsigned(db)
    report = ledger.verify_chain()
    assert report["ok"] is True
    assert report["authenticated"] is False
    assert report["unsigned_rows"] == 1


def test_authenticated_is_none_when_there_is_nothing_to_verify_against(tmp_path):
    """Not False: 'cannot be determined' is a different answer from 'was checked
    and failed', and calling an honest pre-key ledger unauthenticated would say
    it had been tampered with."""
    _seed(tmp_path / "c.db", keyed=False)
    assert ledger.verify_chain()["authenticated"] is None


def test_the_undetermined_case_is_falsy_so_a_naive_caller_fails_closed(tmp_path):
    """`if not report["authenticated"]` must treat undetermined as not-authentic."""
    _seed(tmp_path / "c.db", keyed=False)
    assert not ledger.verify_chain()["authenticated"]


def test_authenticated_is_present_even_when_the_chain_is_broken(tmp_path):
    """Callers can rely on the key existing; the walk stopped, so it is None."""
    db = tmp_path / "c.db"
    _seed(db, keyed=True)
    con = sqlite3.connect(db)
    con.execute("UPDATE consent_events SET detail = ? WHERE id = 1", (json.dumps({"tampered": True}),))
    con.commit()
    con.close()
    report = ledger.verify_chain()
    assert report["ok"] is False
    assert "authenticated" in report
    assert report["authenticated"] is None


# ── The surface that reports it ───────────────────────────────────────


def _run_verify(monkeypatch, tmp_path, capsys) -> str:
    from community_member import cli
    from community_member import config as config_mod

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path, raising=False)
    monkeypatch.setattr(cli.Config, "load", classmethod(lambda cls: cls(home=tmp_path)))
    monkeypatch.setattr(cli.ledger, "init", lambda *a, **k: None)
    cli._cmd_audit_verify()
    # Rich wraps to the terminal width, so a phrase can straddle a newline.
    return " ".join(capsys.readouterr().out.split())


def test_the_cli_does_not_say_verified_over_an_unsigned_row(tmp_path, monkeypatch, capsys):
    """The live defect: a green 'Audit chain verified' printed over a ledger
    containing a row the agent never wrote, with unsigned_rows discarded."""
    db = tmp_path / "consent.db"
    _seed(db, keyed=True)
    _append_unsigned(db)

    out = _run_verify(monkeypatch, tmp_path, capsys)
    assert "NOT authenticated" in out
    assert "1 row(s) carry no signature" in out
    assert "verified" not in out.lower().replace("not authenticated", "")


def test_the_cli_reports_a_clean_ledger_as_verified_and_authenticated(tmp_path, monkeypatch, capsys):
    _seed(tmp_path / "consent.db", keyed=True)
    out = _run_verify(monkeypatch, tmp_path, capsys)
    assert "verified and authenticated" in out


def test_the_cli_says_authenticity_was_not_checked_on_an_unkeyed_ledger(tmp_path, monkeypatch, capsys):
    _seed(tmp_path / "consent.db", keyed=False)
    out = _run_verify(monkeypatch, tmp_path, capsys)
    assert "NOT CHECKED" in out
    assert "no signing key" in out


def test_the_cli_shows_the_unsigned_count_whenever_it_is_non_zero(tmp_path, monkeypatch, capsys):
    """The field exists so the gap is visible; a surface that drops it is why
    it was invisible in the first place."""
    db = tmp_path / "consent.db"
    _seed(db, keyed=True)
    _append_unsigned(db)
    _append_unsigned(db)
    assert "unsigned=2" in _run_verify(monkeypatch, tmp_path, capsys)
