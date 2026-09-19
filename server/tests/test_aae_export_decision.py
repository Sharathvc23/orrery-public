"""sm-aae envelope → AttestationEvent (type "decision") conversion.

The receipt → ``type:"action"`` path keeps its own regression suite
(test_aae_export.py, unchanged); this covers the new decision half:
verification-gated, chained, and carrying the full signed envelope.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sm_aae", reason="needs sm-aae")

from sm_aae import envelope_hash, issue_envelope

import aae_export

SK_HEX = b"aae-export-decision-test-seed-32".hex()
ISSUED = "2026-07-07T00:00:00+00:00"


def _envelope(outcome: str = "authorized", prev_hash: str | None = None) -> dict:
    return issue_envelope(
        SK_HEX,
        agent_id="did:key:zAgentTest",
        verb="browser.navigate",
        resource="https://example.com",
        params={"context": "ctx-1", "consent_event_sha256": "ab" * 32},
        policy_id="consent-gate:user_approved",
        outcome=outcome,
        prev_hash=prev_hash,
        issued_at=ISSUED,
    )


def test_valid_envelope_maps_to_decision_event():
    env = _envelope()
    ev = aae_export.aae_envelope_to_attestation_event(env, tenant="alice")
    assert ev["v"] == 1
    assert ev["type"] == "decision"
    assert ev["lifecycle"] == "signed"
    assert ev["id"] == envelope_hash(env)
    assert ev["ts"] == ISSUED
    assert ev["tenant"] == "alice"
    assert ev["topic"] == "chapter.decision.browser.navigate"
    assert ev["classification"] == "internal"
    assert ev["actor"]["did"] == "did:key:zAgentTest"
    payload = ev["payload"]
    assert payload["kind"] == "browser.navigate"
    assert payload["resource"] == "https://example.com"
    assert payload["outcome"] == "authorized"
    assert payload["policy_id"] == "consent-gate:user_approved"
    assert payload["envelope"] == env  # the full signed artifact rides along
    assert "prev_envelope_hash" not in payload  # genesis envelope


def test_denied_and_chained_envelope():
    first = _envelope(outcome="denied")
    second = _envelope(outcome="denied", prev_hash=envelope_hash(first))
    ev = aae_export.aae_envelope_to_attestation_event(second, tenant="alice")
    assert ev["payload"]["outcome"] == "denied"
    assert ev["payload"]["prev_envelope_hash"] == envelope_hash(first)


def test_public_classification():
    ev = aae_export.aae_envelope_to_attestation_event(_envelope(), tenant="alice", public=True)
    assert ev["classification"] == "public"


def test_tampered_envelope_converts_to_empty():
    env = _envelope()
    env["outcome"] = "denied"  # mutate a signed field
    assert aae_export.aae_envelope_to_attestation_event(env, tenant="alice") == {}


def test_malformed_input_converts_to_empty():
    assert aae_export.aae_envelope_to_attestation_event({}, tenant="alice") == {}
    assert aae_export.aae_envelope_to_attestation_event("junk", tenant="alice") == {}  # type: ignore[arg-type]
