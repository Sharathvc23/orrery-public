"""An approval is verified before it is honoured.

`find_valid_approval` reads a row's `expires_at` and its four match fields out
of the SQLite ledger. Without a per-row check, anything able to write that file
can append an approval for any capability with any expiry and have it honoured.

Recomputing a correct `event_sha256` is trivial — the algorithm is public — so
the hash alone is not the control. The Ed25519 signature over it is.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest

CHAPTER = "local:verify"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


def _key() -> str:
    from nacl.signing import SigningKey

    return base64.b64encode(bytes(SigningKey.generate())).decode()


@pytest.fixture
def keyed_ledger(tmp_path: Path) -> Path:
    db = tmp_path / "consent.db"
    ledger.init(db, signing_key_b64=_key())
    ledger.record(chapter_id=CHAPTER, action="seed", outcome="ok", detail={})
    return db


def _req(scope: str = "curl", capability: str = "shell.exec") -> ActionRequest:
    return ActionRequest(capability=capability, scope=scope, context="forged", provenance="trusted")


def _append_row(db: Path, *, scope: str, event_sha256: str | None, signature_b64: str | None) -> str:
    """Append a consent.approved row directly, the way file-write access would.

    `event_sha256=None` means "compute the correct one", which is the case that
    the hash check alone does not catch.
    """
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    prev = con.execute("SELECT event_sha256 FROM consent_events ORDER BY id DESC LIMIT 1").fetchone()["event_sha256"]
    occurred = datetime.now(UTC).isoformat()
    detail = {
        "capability": "shell.exec",
        "scope": scope,
        "context": "forged",
        "provenance": "trusted",
        "source_ref": None,
        "prompt_event_sha256": "none",
        "expires_at": (datetime.now(UTC) + timedelta(days=3650)).isoformat(),
        "extra": {},
    }
    event = {
        "chapter_id": CHAPTER,
        "actor_agent_id": None,
        "action": "consent.approved",
        "target_type": "capability",
        "target_id": "shell.exec",
        "outcome": "ok",
        "detail": detail,
        "occurred_at": occurred,
        "prev_sha256": prev,
    }
    sha = event_sha256 or ledger.sha256_of(event)
    con.execute(
        "INSERT INTO consent_events (chapter_id, actor_agent_id, action, target_type, target_id, "
        "outcome, detail, occurred_at, prev_sha256, event_sha256, signature_b64) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            CHAPTER,
            None,
            "consent.approved",
            "capability",
            "shell.exec",
            "ok",
            json.dumps(detail, sort_keys=True),
            occurred,
            prev,
            sha,
            signature_b64,
        ),
    )
    con.commit()
    con.close()
    return sha


# ── The reproduction from the security sweep ──────────────────────────


def test_a_hand_appended_row_with_a_junk_hash_is_not_honoured(keyed_ledger):
    _append_row(keyed_ledger, scope="junk", event_sha256="f" * 64, signature_b64=None)
    assert gate.find_valid_approval(_req("junk"), chapter_id=CHAPTER) is None


def test_a_hand_appended_row_with_a_correct_hash_is_not_honoured(keyed_ledger):
    """The case the hash check alone does not catch.

    An attacker who can write the file can also run `sha256_of`. Only the
    signature distinguishes a row record() wrote from one it did not.
    """
    _append_row(keyed_ledger, scope="correct-hash", event_sha256=None, signature_b64=None)
    assert gate.find_valid_approval(_req("correct-hash"), chapter_id=CHAPTER) is None


def test_a_row_signed_with_the_wrong_key_is_not_honoured(keyed_ledger):
    from nacl.signing import SigningKey

    other = SigningKey.generate()
    row_sha = ledger.sha256_of(
        {
            "chapter_id": CHAPTER,
            "actor_agent_id": None,
            "action": "consent.approved",
            "target_type": "capability",
            "target_id": "shell.exec",
            "outcome": "ok",
            "detail": {},
            "occurred_at": "x",
            "prev_sha256": None,
        }
    )
    sig = base64.b64encode(other.sign(row_sha.encode()).signature).decode()
    _append_row(keyed_ledger, scope="wrong-key", event_sha256=None, signature_b64=sig)
    assert gate.find_valid_approval(_req("wrong-key"), chapter_id=CHAPTER) is None


def test_an_expiry_edited_in_place_is_not_honoured(keyed_ledger):
    """A genuine, signed approval whose expires_at is pushed into the future."""
    req = _req(scope="https://a.example", capability="browser.navigate")
    sha = gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")
    assert gate.find_valid_approval(req, chapter_id=CHAPTER) is not None

    con = sqlite3.connect(keyed_ledger)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT detail FROM consent_events WHERE event_sha256 = ?", (sha,)).fetchone()
    detail = json.loads(row["detail"])
    detail["expires_at"] = (datetime.now(UTC) + timedelta(days=3650)).isoformat()
    con.execute(
        "UPDATE consent_events SET detail = ? WHERE event_sha256 = ?",
        (json.dumps(detail, sort_keys=True), sha),
    )
    con.commit()
    con.close()

    assert gate.find_valid_approval(req, chapter_id=CHAPTER) is None


# ── The legitimate path must survive the fix ──────────────────────────


def test_a_genuine_approval_is_still_honoured(keyed_ledger):
    req = _req(scope="https://a.example", capability="browser.navigate")
    sha = gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")
    hit = gate.find_valid_approval(req, chapter_id=CHAPTER)
    assert hit is not None and hit["event_sha256"] == sha


# ── The disposition decision, asserted ────────────────────────────────


def test_one_unverifiable_row_does_not_disable_the_others(keyed_ledger):
    """Refuse the row, not the ledger.

    Refusing the whole ledger on one bad row would let a single hand-appended
    row stop every future approval — a denial of service on the consent system,
    triggerable by the same file-write access the attack needs.
    """
    _append_row(keyed_ledger, scope="forged", event_sha256=None, signature_b64=None)
    good = _req(scope="https://a.example", capability="browser.navigate")
    sha = gate.approve(good, chapter_id=CHAPTER, prompt_event_sha256="click")

    assert gate.find_valid_approval(_req("forged"), chapter_id=CHAPTER) is None
    hit = gate.find_valid_approval(good, chapter_id=CHAPTER)
    assert hit is not None and hit["event_sha256"] == sha


def test_the_refusal_is_reported(keyed_ledger, capsys):
    """A row record() did not write is an operator-visible event, not a silent skip."""
    _append_row(keyed_ledger, scope="loud", event_sha256=None, signature_b64=None)
    gate.find_valid_approval(_req("loud"), chapter_id=CHAPTER)
    out = capsys.readouterr().out
    assert "failed verification" in out
    assert "unsigned_row" in out


# ── What is NOT verified, and why ─────────────────────────────────────


def test_a_denial_is_honoured_without_verification(tmp_path):
    """Verification is applied where a row GRANTS authority, not where it withholds it.

    `find_recent_denial` returning a row causes the executor to refuse the
    action. Skipping an unverifiable denial would therefore make the action
    executable — the unsafe direction. A forged denial can only suppress, which
    is a nuisance, not an escalation.
    """
    ledger.init(tmp_path / "consent.db", signing_key_b64=_key())
    req = _req(scope="https://a.example", capability="browser.navigate")
    prompt = gate.record_decision(req, gate.evaluate(req), chapter_id=CHAPTER)
    gate.deny(req, chapter_id=CHAPTER, prompt_event_sha256=prompt)

    con = sqlite3.connect(tmp_path / "consent.db")
    con.execute("UPDATE consent_events SET signature_b64 = NULL WHERE action = 'consent.denied'")
    con.commit()
    con.close()

    assert gate.find_recent_denial(req, chapter_id=CHAPTER) is not None


# ── The unkeyed ledger, stated rather than assumed ────────────────────


def test_an_unkeyed_ledger_still_checks_integrity(tmp_path):
    ledger.init(tmp_path / "consent.db")
    ledger.record(chapter_id=CHAPTER, action="seed", outcome="ok", detail={})
    _append_row(tmp_path / "consent.db", scope="junk", event_sha256="f" * 64, signature_b64=None)
    assert gate.find_valid_approval(_req("junk"), chapter_id=CHAPTER) is None


def test_an_unkeyed_ledger_cannot_check_authenticity(tmp_path):
    """Recorded so the limit is visible: with no signing key there is nothing to
    verify a signature against, so a correctly-hashed appended row is honoured.
    A keyed ledger — what the agent configures when it has an identity — refuses
    the same row."""
    ledger.init(tmp_path / "consent.db")
    ledger.record(chapter_id=CHAPTER, action="seed", outcome="ok", detail={})
    _append_row(tmp_path / "consent.db", scope="correct", event_sha256=None, signature_b64=None)
    assert gate.find_valid_approval(_req("correct"), chapter_id=CHAPTER) is not None
    assert ledger.verify_row({"event_sha256": "x"})[1] in ("hash_mismatch", "unsigned_ledger")


# ── verify_chain surfaces what it cannot judge ────────────────────────


def test_verify_chain_reports_unsigned_rows(keyed_ledger):
    """A correctly-hashed unsigned row keeps the chain intact, so verify_chain
    still reports ok. The count is what makes it visible."""
    _append_row(keyed_ledger, scope="correct", event_sha256=None, signature_b64=None)
    report = ledger.verify_chain()
    assert report["ok"] is True
    assert report["unsigned_rows"] >= 1
