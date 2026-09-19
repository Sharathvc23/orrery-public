"""F4: an EXTERNAL verifier can re-derive the consent-ledger chain from the
exported JSONL alone.

ledger.export_jsonl claims the output lets "an external verifier re-derive the
chain" (ledger.py). The existing suite checks line count + that chain hashes
are preserved, but never rebuilds the chain in a fresh, ledger-independent
verifier. This test ships such a verifier — it re-implements the canonical
hash form from the documented spec (canonical_event: minimal field set, sorted
keys, tight separators; sha256 of that) WITHOUT importing the ledger's hasher —
and proves a clean export re-derives, while a tampered line breaks.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from community_member.consent import gate, ledger

SEED = b"ledger-extverify".ljust(32, b"!")
KEY_B64 = base64.b64encode(SEED).decode()
CHAPTER = "local:ext-verify"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


# ── the INDEPENDENT verifier — no ledger internals imported ──────────


def _canonical(event: dict) -> str:
    """Re-implemented from the documented canonical form (ledger.py:108).
    Deliberately NOT ledger.canonical_event — an external auditor wouldn't
    have it."""
    minimal = {
        "chapter_id": event.get("chapter_id"),
        "actor_agent_id": event.get("actor_agent_id"),
        "action": event.get("action"),
        "target_type": event.get("target_type"),
        "target_id": event.get("target_id"),
        "outcome": event.get("outcome"),
        "detail": event.get("detail") or {},
        "occurred_at": event.get("occurred_at"),
        "prev_sha256": event.get("prev_sha256") or "",
    }
    return json.dumps(minimal, sort_keys=True, separators=(",", ":"))


def _verify_export(lines: list[str]) -> tuple[bool, str]:
    """Re-derive the chain from JSONL text alone. Returns (ok, reason)."""
    prev = ""
    for i, line in enumerate(lines):
        e = json.loads(line)
        if (e.get("prev_sha256") or "") != prev:
            return False, f"line {i}: prev_sha256 does not match running tip"
        recomputed = hashlib.sha256(_canonical(e).encode()).hexdigest()
        if recomputed != e.get("event_sha256"):
            return False, f"line {i}: event_sha256 mismatch (tampered payload)"
        prev = e["event_sha256"]
    return True, "ok"


def _make_events():
    req = gate.ActionRequest(
        capability="fs.read",
        scope="/tmp/x",
        context="c",
        provenance="trusted",
    )
    p = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=p.event_sha256)
    req2 = gate.ActionRequest(capability="net.http", scope="https://x", context="c2", provenance="trusted")
    gate.check_and_record(req2, chapter_id=CHAPTER)


def test_clean_export_rederivable(tmp_path: Path):
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    _make_events()

    lines = ledger.export_jsonl()
    assert len(lines) >= 3
    ok, reason = _verify_export(lines)
    assert ok, reason


def test_tampered_line_breaks_rederivation(tmp_path: Path):
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    _make_events()
    lines = ledger.export_jsonl()

    # Tamper a payload field WITHOUT updating its event_sha256 → the
    # external recompute must catch it.
    mid = json.loads(lines[1])
    mid["outcome"] = "denied" if mid.get("outcome") != "denied" else "approved"
    lines[1] = json.dumps(mid, sort_keys=True, default=str)

    ok, reason = _verify_export(lines)
    assert not ok, "external verifier failed to detect a tampered event payload"


def test_dropped_line_breaks_chain(tmp_path: Path):
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    _make_events()
    lines = ledger.export_jsonl()

    del lines[1]  # gap
    ok, reason = _verify_export(lines)
    assert not ok, "external verifier failed to detect a dropped event"
