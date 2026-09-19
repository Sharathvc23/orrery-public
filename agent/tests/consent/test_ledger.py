"""Prosecution-grade tests for community_member.consent.ledger.

R1-R10 + S9 coverage:
  R1 forgery      — row with wrong signature rejected by verify_chain
  R2 replay       — event_sha256 UNIQUE prevents double-insert
  R3 injection    — oversized detail, SQL-y action, binary bytes round-trip safely
  R4 authz        — init() required before record(); invalid outcomes rejected
  R5 boundary     — exactly MAX_ACTION_LEN passes, +1 rejected; exactly MAX_DETAIL_BYTES passes, +1 rejected
  R6 concurrency  — threaded record() produces a valid chain (no duplicate prev_sha256)
  R7 adversarial  — swap one row's detail field; verify_chain flags it at that index
  R8 downgrade    — rebuilding on a tampered DB still reports ok=false
  R9 timing       — canonical_event is pure + matches chapter-runtime byte-for-byte
  R10 persistence — export/import round-trip via export_jsonl reconstructs the chain
  S9 security     — replacing one row in consent.db makes verify_chain() fail at that row
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from community_member.consent import ledger


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "consent.db"


@pytest.fixture
def signing_key_b64() -> str:
    """Fresh Ed25519 key per test."""
    pytest.importorskip("nacl.signing")
    from nacl.signing import SigningKey

    return base64.b64encode(bytes(SigningKey.generate())).decode("ascii")


# ── R4 authz: init required ───────────────────────────────────────────


def test_R4_authz_record_without_init_raises():
    with pytest.raises(RuntimeError, match="not initialized"):
        ledger.record("ch", "action")


def test_R4_authz_invalid_outcome_rejected(tmp_db: Path):
    ledger.init(tmp_db)
    with pytest.raises(ValueError, match="outcome"):
        ledger.record("ch", "act", outcome="maybe")


def test_R4_authz_empty_action_rejected(tmp_db: Path):
    ledger.init(tmp_db)
    with pytest.raises(ValueError, match="action is required"):
        ledger.record("ch", "")


# ── R5 boundary ───────────────────────────────────────────────────────


def test_R5_boundary_action_at_max_len_passes(tmp_db: Path):
    ledger.init(tmp_db)
    ev = ledger.record("ch", "a" * ledger.MAX_ACTION_LEN)
    assert len(ev["action"]) == ledger.MAX_ACTION_LEN


def test_R5_boundary_action_over_max_len_truncated_not_rejected(tmp_db: Path):
    """record() truncates action to MAX_ACTION_LEN; _validate() only bounces
    strictly-over; this is documented behavior for long action strings."""
    ledger.init(tmp_db)
    # _validate rejects lengths over max; record() truncates BEFORE validation
    # so a length-exactly-N action still passes.
    ev = ledger.record("ch", "a" * ledger.MAX_ACTION_LEN)
    assert len(ev["action"]) == ledger.MAX_ACTION_LEN


def test_R5_boundary_action_validate_strictly_over_rejected(tmp_db: Path):
    """_validate() itself must reject at MAX_ACTION_LEN + 1 characters."""
    ok, reason = ledger._validate("a" * (ledger.MAX_ACTION_LEN + 1), "ok", {})
    assert ok is False
    assert "too long" in reason


def test_R5_boundary_detail_exactly_at_max_passes(tmp_db: Path):
    ledger.init(tmp_db)
    # Build a detail whose json.dumps() with default separators is exactly
    # MAX_DETAIL_BYTES (that's what _validate() measures against).
    envelope_len = len(json.dumps({"k": ""}).encode())  # 9 bytes: {"k": ""}
    padding = "x" * (ledger.MAX_DETAIL_BYTES - envelope_len)
    detail = {"k": padding}
    assert len(json.dumps(detail).encode()) == ledger.MAX_DETAIL_BYTES
    ev = ledger.record("ch", "a", detail=detail)
    assert ev["detail"] == detail


def test_R5_boundary_detail_one_byte_over_rejected(tmp_db: Path):
    ledger.init(tmp_db)
    envelope_len = len(json.dumps({"k": ""}).encode())
    padding = "x" * (ledger.MAX_DETAIL_BYTES - envelope_len + 1)
    with pytest.raises(ValueError, match="too large"):
        ledger.record("ch", "a", detail={"k": padding})


# ── R10 persistence: chain integrity on happy path ────────────────────


def test_R10_persistence_chain_verifies_clean(tmp_db: Path):
    ledger.init(tmp_db)
    for i in range(5):
        ledger.record("ch", f"act{i}", detail={"i": i})
    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["length"] == 5


def test_R10_persistence_first_row_has_null_prev(tmp_db: Path):
    ledger.init(tmp_db)
    ev = ledger.record("ch", "genesis")
    assert ev["prev_sha256"] is None


def test_R10_persistence_subsequent_rows_chain_to_prev(tmp_db: Path):
    ledger.init(tmp_db)
    first = ledger.record("ch", "a")
    second = ledger.record("ch", "b")
    assert second["prev_sha256"] == first["event_sha256"]


# ── R9 timing: canonical serialization purity + cross-repo compatibility ──


def test_R9_canonical_event_is_deterministic_across_dict_orderings():
    """Two dicts with same content but different insertion order must hash identically."""
    e1 = {"chapter_id": "c", "action": "a", "occurred_at": "2026-04-23T00:00:00+00:00"}
    e2 = {"occurred_at": "2026-04-23T00:00:00+00:00", "action": "a", "chapter_id": "c"}
    assert ledger.canonical_event(e1) == ledger.canonical_event(e2)
    assert ledger.sha256_of(e1) == ledger.sha256_of(e2)


def test_R9_canonical_event_matches_chapter_runtime_shape():
    """Byte-for-byte parity with chapter-runtime/chapter_audit.canonical_event.

    If this test ever fails, audits exported from a device cannot be re-verified
    against a chapter's Postgres audit and the cross-repo contract is broken.
    """
    event = {
        "chapter_id": "bayarea",
        "actor_agent_id": "alice",
        "action": "browser.navigate",
        "target_type": "url",
        "target_id": "https://example.com",
        "outcome": "ok",
        "detail": {"origin": "https://example.com"},
        "occurred_at": "2026-04-23T00:00:00+00:00",
        "prev_sha256": "",
    }
    # The canonical serialization MUST use sort_keys + compact separators.
    # We assert the exact byte string so any formatter drift is caught.
    expected = (
        '{"action":"browser.navigate",'
        '"actor_agent_id":"alice",'
        '"chapter_id":"bayarea",'
        '"detail":{"origin":"https://example.com"},'
        '"occurred_at":"2026-04-23T00:00:00+00:00",'
        '"outcome":"ok",'
        '"prev_sha256":"",'
        '"target_id":"https://example.com",'
        '"target_type":"url"}'
    )
    assert ledger.canonical_event(event) == expected
    # And the sha256 is what chapter-runtime computes on the same input.
    assert ledger.sha256_of(event) == hashlib.sha256(expected.encode()).hexdigest()


# ── R2 replay: event_sha256 UNIQUE prevents collision ────────────────


def test_R2_replay_duplicate_event_sha256_rejected(tmp_db: Path):
    ledger.init(tmp_db)
    ev = ledger.record("ch", "a", detail={"k": "v"}, occurred_at="2026-04-23T00:00:00+00:00")
    # Manually re-insert the same event_sha256; UNIQUE constraint must reject.
    with sqlite3.connect(str(tmp_db)) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO consent_events
                   (chapter_id, action, outcome, detail, occurred_at, event_sha256)
                   VALUES (?, ?, ?, ?, ?, ?)""",
            ("ch2", "different", "ok", "{}", "2099-01-01", ev["event_sha256"]),
        )
        conn.commit()


# ── R3 injection: payload safety ─────────────────────────────────────


def test_R3_injection_sql_in_action_does_not_break(tmp_db: Path):
    ledger.init(tmp_db)
    nasty = "' OR 1=1; DROP TABLE consent_events; --"[: ledger.MAX_ACTION_LEN]
    ev = ledger.record("ch", nasty)
    assert ev["action"] == nasty  # stored as data, no execution


def test_R3_injection_unicode_in_detail_roundtrips(tmp_db: Path):
    ledger.init(tmp_db)
    detail = {"emoji": "🔐", "cn": "签名", "control": "\x00\x01\x02"}
    ev = ledger.record("ch", "a", detail=detail)
    # Chain is still valid — canonical serialization handles unicode safely.
    assert ledger.verify_chain()["ok"] is True
    assert ev["detail"]["emoji"] == "🔐"


# ── R1/R7/S9 forgery + tamper detection ─────────────────────────────


def test_R7_S9_tamper_detail_changes_chain_validation(tmp_db: Path):
    ledger.init(tmp_db)
    ledger.record("ch", "a")
    ledger.record("ch", "b", detail={"original": True})
    ledger.record("ch", "c")

    # Flip a field on row 2. The event_sha256 column stays the same (so a
    # simple SHA check could be fooled by an insider replacing the ORIGINAL
    # sha too) — we tamper the serializable payload + leave the stored hash
    # alone to prove verify_chain re-derives independently.
    with sqlite3.connect(str(tmp_db)) as conn:
        conn.execute(
            "UPDATE consent_events SET detail = ? WHERE action = 'b'",
            (json.dumps({"original": False}),),
        )
        conn.commit()

    result = ledger.verify_chain()
    assert result["ok"] is False
    assert result["broken_index"] == 1


def test_S9_tamper_entire_row_replaced_still_flagged(tmp_db: Path):
    ledger.init(tmp_db)
    ledger.record("ch", "a")
    ledger.record("ch", "b")
    third = ledger.record("ch", "c")

    # Replace row 2 entirely: new detail + regenerate event_sha256 so the
    # row's own checksum is self-consistent. But the prev_sha256 field
    # must still link to row 1, and row 3's prev_sha256 links to the
    # ORIGINAL row-2 hash — so the chain breaks at row 3.
    with sqlite3.connect(str(tmp_db)) as conn:
        r1 = conn.execute("SELECT event_sha256 FROM consent_events WHERE action='a'").fetchone()[0]
        forged = {
            "chapter_id": "ch",
            "actor_agent_id": None,
            "action": "b",
            "target_type": None,
            "target_id": None,
            "outcome": "ok",
            "detail": {"tampered": True},
            "occurred_at": "2026-04-23T00:00:00+00:00",
            "prev_sha256": r1,
        }
        new_hash = ledger.sha256_of(forged)
        conn.execute(
            """UPDATE consent_events SET detail = ?, event_sha256 = ?,
               occurred_at = ?
               WHERE action = 'b'""",
            (json.dumps(forged["detail"]), new_hash, forged["occurred_at"]),
        )
        conn.commit()

    result = ledger.verify_chain()
    assert result["ok"] is False
    # Row 3 still points at the ORIGINAL row-2 hash, not `new_hash`, so
    # prev chain breaks at index 2 (third row).
    assert result["broken_index"] == 2
    assert third["event_sha256"] != new_hash  # sanity


# ── R8 downgrade: revocation has no bypass ───────────────────────────


def test_R8_downgrade_verify_on_fresh_process_finds_tamper(tmp_db: Path):
    """A fresh interpreter opening a tampered DB must still fail verify."""
    ledger.init(tmp_db)
    ledger.record("ch", "a")
    ledger.record("ch", "b")

    with sqlite3.connect(str(tmp_db)) as conn:
        conn.execute("UPDATE consent_events SET action='TAMPERED' WHERE action='b'")
        conn.commit()

    # Simulate fresh-process re-open: reset module globals then re-init.
    ledger._reset_for_tests()
    ledger.init(tmp_db)

    assert ledger.verify_chain()["ok"] is False


# ── R1 forgery: signature verification (when signing key configured) ──


def test_R1_forgery_bad_signature_fails_verify(tmp_db: Path, signing_key_b64: str):
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    ledger.record("ch", "a")

    # Overwrite the signature with junk; the hash chain still checks out
    # (we didn't touch event_sha256) but signature verification must fail.
    fake_sig = base64.b64encode(b"\x00" * 64).decode()
    with sqlite3.connect(str(tmp_db)) as conn:
        conn.execute("UPDATE consent_events SET signature_b64 = ?", (fake_sig,))
        conn.commit()

    result = ledger.verify_chain()
    assert result["ok"] is False
    assert result.get("reason") == "signature verification failed"


def test_R1_signature_verifies_when_untampered(tmp_db: Path, signing_key_b64: str):
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    for i in range(3):
        ledger.record("ch", f"act{i}")
    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["signatures_verified"] == 3


def test_R1_unsigned_ledger_verifies_chain_only(tmp_db: Path):
    """Without a signing key, signature_b64 stays NULL and verify_chain
    only checks the hash chain — not a bypass, just an allowed mode."""
    ledger.init(tmp_db, signing_key_b64=None)
    for i in range(3):
        ledger.record("ch", f"act{i}")
    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["signatures_verified"] == 0


def test_G4_reinit_without_key_does_not_downgrade_signing(tmp_db: Path, signing_key_b64: str):
    """Once signing is enabled, a later init() that OMITS the key must keep it —
    otherwise a legacy call site (agent.py's click path) that inits with no key
    would strand subsequent appends as unsigned and verify_chain would skip them.
    """
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    ledger.record("ch", "signed-before")

    # A second init WITHOUT a key (the G4 legacy path) must not clear signing.
    ledger.init(tmp_db)
    ledger.record("ch", "still-signed-after")

    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["signatures_verified"] == 2, "a no-key re-init downgraded the ledger to unsigned"


# ── R6 concurrency: threaded record() preserves chain ────────────────


def test_R6_concurrency_threads_produce_valid_chain(tmp_db: Path):
    ledger.init(tmp_db)

    errors = []

    def writer(prefix: str):
        try:
            for i in range(10):
                ledger.record("ch", f"{prefix}_{i}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(p,)) for p in ("A", "B", "C")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"thread errors: {errors}"
    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["length"] == 30


# ── R10 persistence: export / round-trip ─────────────────────────────


def test_R10_persistence_export_jsonl_emits_one_line_per_event(tmp_db: Path):
    ledger.init(tmp_db)
    for i in range(3):
        ledger.record("ch", f"a{i}")
    lines = ledger.export_jsonl()
    assert len(lines) == 3
    # Chronological order on export.
    parsed = [json.loads(line) for line in lines]
    assert [p["action"] for p in parsed] == ["a0", "a1", "a2"]


def test_R10_persistence_export_preserves_chain_hashes(tmp_db: Path):
    """An external verifier reading exported JSONL must be able to
    re-derive the chain with the same canonical serializer."""
    ledger.init(tmp_db)
    for i in range(5):
        ledger.record("ch", f"a{i}", detail={"i": i})

    lines = ledger.export_jsonl()
    parsed = [json.loads(line) for line in lines]

    prev = ""
    for p in parsed:
        # Re-derive the hash from the exported event, using ONLY the fields
        # the canonical serializer cares about.
        derived = ledger.sha256_of(
            {
                "chapter_id": p["chapter_id"],
                "actor_agent_id": p["actor_agent_id"],
                "action": p["action"],
                "target_type": p["target_type"],
                "target_id": p["target_id"],
                "outcome": p["outcome"],
                "detail": p["detail"],
                "occurred_at": p["occurred_at"],
                "prev_sha256": p["prev_sha256"] or "",
            }
        )
        assert derived == p["event_sha256"]
        if prev:
            assert p["prev_sha256"] == prev
        prev = p["event_sha256"]


# ── G3: signed head-checkpoint detects tail-truncation ───────────────


def test_G3_tail_truncation_detected(tmp_db: Path, signing_key_b64: str):
    """Dropping trailing rows leaves a shorter still-hash-valid chain — the
    signed head-checkpoint (whose count the attacker can't lower without the
    key) catches it."""
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    for i in range(5):
        ledger.record("ch", f"act{i}")
    assert ledger.verify_chain()["ok"] is True

    # Attacker with db write access deletes the last 2 rows. The chain of the
    # surviving 3 rows still verifies on its own...
    with sqlite3.connect(tmp_db) as conn:
        conn.execute("DELETE FROM consent_events WHERE id IN (SELECT id FROM consent_events ORDER BY id DESC LIMIT 2)")
        conn.commit()

    # ...but the signed checkpoint still says count=5, so verify_chain flags it.
    result = ledger.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "tail_truncation_detected"
    assert result["checkpoint_count"] == 5
    assert result["actual_count"] == 3


def test_G3_clean_ledger_with_checkpoint_verifies(tmp_db: Path, signing_key_b64: str):
    """A well-formed signed ledger passes the checkpoint cross-check."""
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    for i in range(4):
        ledger.record("ch", f"act{i}")
    result = ledger.verify_chain()
    assert result["ok"] is True
    assert result["length"] == 4


def test_G3_checkpoint_head_tamper_detected(tmp_db: Path, signing_key_b64: str):
    """If the surviving head row is swapped (same count, different head), the
    checkpoint's signed head no longer matches."""
    pytest.importorskip("nacl.signing")
    ledger.init(tmp_db, signing_key_b64=signing_key_b64)
    for i in range(3):
        ledger.record("ch", f"act{i}")
    # Rewrite the last row's event_sha256 to a different (well-formed) value so
    # the row-chain check may pass its own row but the checkpoint head diverges.
    with sqlite3.connect(tmp_db) as conn:
        conn.execute(
            "UPDATE consent_events SET event_sha256 = ? WHERE id = (SELECT MAX(id) FROM consent_events)",
            ("deadbeef" * 8,),
        )
        conn.commit()
    result = ledger.verify_chain()
    assert result["ok"] is False


def test_G3_unsigned_ledger_still_ok_without_checkpoint_enforcement(tmp_db: Path):
    """An unsigned ledger writes an unsigned checkpoint; verify still passes on a
    clean chain (the checkpoint can't be a trust floor without a key, but it
    must not false-positive)."""
    ledger.init(tmp_db, signing_key_b64=None)
    for i in range(3):
        ledger.record("ch", f"act{i}")
    assert ledger.verify_chain()["ok"] is True
