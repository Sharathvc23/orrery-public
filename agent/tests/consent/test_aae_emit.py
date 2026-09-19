"""consent-gate decisions → signed, per-agent-chained sm-aae envelopes.

The gate's verdict engine now emits an sm-aae Attested Action Envelope per
decision — allow AND refuse — chained per agent via ``prev_hash`` and
cross-linked to the consent ledger row. The consent ledger stays authoritative:
without a signing key the emitter is disabled and the gate works unchanged.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
from pathlib import Path

import pytest

pytest.importorskip("sm_aae", reason="needs sm-aae")

from sm_aae import envelope_hash, order_chain, verify_envelope

from community_member.consent import aae_emit, gate, ledger

SEED = b"consent-aae-test".ljust(32, b"!")
KEY_B64 = base64.b64encode(SEED).decode()
CHAPTER = "local:test-device"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def signed_ledger(tmp_path: Path) -> Path:
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    return tmp_path


def _req(provenance: str = "trusted", **kw) -> gate.ActionRequest:
    defaults = {
        "capability": "browser.navigate",
        "scope": "https://example.com",
        "context": "ctx-1",
        "provenance": provenance,
    }
    defaults.update(kw)
    return gate.ActionRequest(**defaults)


def test_reject_emits_denied_envelope(signed_ledger):
    """S3 refusal is a first-class SIGNED artifact, not a silent absence."""
    decision = gate.check_and_record(_req(provenance="untrusted", source_ref="mail:msg-1"), chapter_id=CHAPTER)
    assert decision.state == "reject"

    envelopes = aae_emit.list_envelopes()
    assert len(envelopes) == 1
    env = envelopes[0]
    assert verify_envelope(env) is True
    assert env["outcome"] == "denied"
    assert env["policy_id"] == "consent-gate:untrusted_provenance"
    assert env["action"]["verb"] == "browser.navigate"
    assert env["action"]["resource"] == "https://example.com"
    # Cross-linked to the authoritative consent-ledger row.
    assert env["action"]["params"]["consent_event_sha256"] == decision.event_sha256
    assert env["prev_hash"] is None  # genesis


def test_prompt_emits_conditional_envelope(signed_ledger):
    decision = gate.check_and_record(_req(), chapter_id=CHAPTER)
    assert decision.state == "prompt"
    (env,) = aae_emit.list_envelopes()
    assert env["outcome"] == "conditional"
    assert env["policy_id"] == "consent-gate:user_confirmation_required"


def test_user_approve_and_deny_emit_envelopes(signed_ledger):
    req = _req()
    prompt = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=prompt.event_sha256)
    gate.deny(req, chapter_id=CHAPTER, prompt_event_sha256=prompt.event_sha256)

    envelopes = aae_emit.list_envelopes()
    assert [e["outcome"] for e in envelopes] == ["conditional", "authorized", "denied"]
    approval = envelopes[1]
    assert approval["policy_id"] == "consent-gate:user_approved"
    assert approval["action"]["params"]["prompt_event_sha256"] == prompt.event_sha256
    assert "expires_at" in approval["action"]["params"]
    denial = envelopes[2]
    assert denial["policy_id"] == "consent-gate:user_denied"
    assert all(verify_envelope(e) for e in envelopes)


def test_chain_links_and_verifies(signed_ledger):
    for i in range(4):
        gate.check_and_record(_req(context=f"ctx-{i}"), chapter_id=CHAPTER)

    envelopes = aae_emit.list_envelopes()
    assert len(envelopes) == 4
    # Each envelope points at its predecessor's hash — one intact chain.
    for prev, cur in zip(envelopes, envelopes[1:]):
        assert cur["prev_hash"] == envelope_hash(prev)
    assert order_chain(envelopes) is not None
    result = aae_emit.verify_chain()
    assert result["ok"] is True
    assert result["length"] == 4


def test_tampered_stored_envelope_breaks_chain(signed_ledger):
    """ADVERSARIAL: mutating a persisted envelope is detected by the
    per-agent chain re-derivation (signature breaks; order_chain rejects)."""
    for i in range(3):
        gate.check_and_record(_req(context=f"ctx-{i}"), chapter_id=CHAPTER)
    assert aae_emit.verify_chain()["ok"] is True

    db = signed_ledger / "aae.db"
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT id, envelope_json FROM aae_envelopes ORDER BY id LIMIT 1").fetchone()
        env = json.loads(row[1])
        env["outcome"] = "authorized"  # rewrite history: the refusal becomes a grant
        conn.execute("UPDATE aae_envelopes SET envelope_json = ? WHERE id = ?", (json.dumps(env), row[0]))
        conn.commit()

    assert aae_emit.verify_chain()["ok"] is False


def test_unsigned_ledger_disables_emitter_but_gate_works(tmp_path):
    """No signing key ⇒ no envelopes (they must be signed) — and the gate is
    entirely unaffected: decision returned, consent-ledger row written."""
    ledger.init(tmp_path / "consent.db")
    decision = gate.check_and_record(_req(), chapter_id=CHAPTER)
    assert decision.state == "prompt"
    assert decision.event_sha256
    assert aae_emit.list_envelopes() == []


def test_concurrent_decisions_keep_one_intact_chain(signed_ledger):
    """R6: parallel gate decisions must not fork the envelope chain."""
    threads = [
        threading.Thread(target=gate.check_and_record, args=(_req(context=f"t-{i}"),), kwargs={"chapter_id": CHAPTER})
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = aae_emit.verify_chain()
    assert result["ok"] is True
    assert result["length"] == 8
