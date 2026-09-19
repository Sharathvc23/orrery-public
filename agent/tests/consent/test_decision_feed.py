"""consent decisions render in sm-decision-inspector; gestures round-trip
through the EXISTING gate paths.

``_derive_quorum`` replicates the inspector's ``deriveQuorumState`` (pure
function in quorum-logic.ts, keyed on distinct ``verificationMethod``) so this
suite derives quorum exactly the way the inspector will; the real component is
additionally exercised end-to-end by the JS render drill in the PR.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("sm_aae", reason="needs sm-aae")

from fastapi.testclient import TestClient

from community_member import decision_feed
from community_member.config import Config
from community_member.consent import gate, ledger
from community_member.server import create_app

SEED = b"decision-feed-tt".ljust(32, b"!")
KEY_B64 = base64.b64encode(SEED).decode()
CHAPTER = "local:test-device"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def consent_env(tmp_path: Path, monkeypatch):
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)
    return tmp_path


def _req(context: str = "ctx-0", provenance: str = "trusted", **kw) -> gate.ActionRequest:
    defaults = {
        "capability": "browser.navigate",
        "scope": "https://example.com",
        "context": context,
        "provenance": provenance,
    }
    defaults.update(kw)
    return gate.ActionRequest(**defaults)


def _derive_quorum(proofs: list[dict], required: int = 1) -> dict:
    """quorum-logic.ts deriveQuorumState: distinct non-blank verificationMethod."""
    signers = {p["verificationMethod"].strip() for p in proofs if str(p.get("verificationMethod") or "").strip()}
    return {"signers": len(signers), "required": required, "satisfied": len(signers) >= required}


def test_pending_prompt_is_proposed_and_actionable(consent_env):
    decision = gate.check_and_record(_req(), chapter_id=CHAPTER)
    assert decision.state == "prompt"

    (env,) = decision_feed.export_decision_envelopes(tenant="alice")
    assert env["type"] == "decision"
    assert env["lifecycle"] == "proposed"  # unresolved + within TTL: actionable
    assert env["payload"]["kind"] == "operator_prompt"
    assert env["payload"]["prompt_event_sha256"] == decision.event_sha256
    assert env["trace_id"] == decision.event_sha256
    # The signer roster/quorum derive from the agent's real signature.
    quorum = _derive_quorum(env["payload"]["proofs"], decision_feed.QUORUM_POLICY["required"])
    assert quorum == {"signers": 1, "required": 1, "satisfied": True}
    assert env["payload"]["proofs"][0]["verificationMethod"].startswith("did:key:z")


def test_approve_gesture_resolves_through_the_gate(consent_env):
    req = _req()
    prompt = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=prompt.event_sha256)

    envelopes = decision_feed.export_decision_envelopes(tenant="alice")
    assert [e["payload"]["kind"] for e in envelopes] == ["operator_prompt", "operator_authorize"]
    prompt_env, approval_env = envelopes
    assert prompt_env["lifecycle"] == "signed"  # resolved: no longer actionable
    assert "prompt_event_sha256" not in prompt_env["payload"]
    # trace_id ties the resolution to its prompt — the inspector's chain link.
    assert approval_env["trace_id"] == prompt.event_sha256 == prompt_env["trace_id"]


def test_refusals_are_first_class_rows(consent_env):
    gate.check_and_record(_req(provenance="untrusted", source_ref="mail:1"), chapter_id=CHAPTER)
    (env,) = decision_feed.export_decision_envelopes(tenant="alice")
    assert env["payload"]["kind"] == "operator_deny"
    assert env["payload"]["annotation"] == "untrusted_provenance"
    assert env["lifecycle"] == "signed"


def test_expired_prompt_is_not_proposed(consent_env):
    decision = gate.check_and_record(_req(), chapter_id=CHAPTER)
    later = datetime.now(timezone.utc) + decision_feed.PROMPT_TTL + timedelta(seconds=1)
    (env,) = decision_feed.export_decision_envelopes(tenant="alice", now=later)
    assert env["lifecycle"] == "signed"
    assert "prompt_event_sha256" not in env["payload"]
    assert decision.event_sha256  # the ledger row itself is untouched


def _cfg() -> Config:
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    c = Config()
    c.agent_id = "alice-agent"
    c.name = "Alice"
    c.api_key = "x"
    c.private_key = base64.b64encode(bytes(sk)).decode()
    c.public_key = base64.b64encode(bytes(sk.verify_key)).decode()
    return c


def test_gesture_roundtrip_via_existing_endpoints(consent_env):
    """The full that change loop over HTTP: prompt appears in the feed as proposed →
    the inspector's deny gesture posts to the EXISTING /api/local/consent/deny
    (gate.deny inside) → the feed shows the refusal and the prompt resolved.
    No new authorization surface anywhere."""
    pytest.importorskip("nacl.signing", reason="needs PyNaCl")
    req = _req(context="ctx-http")
    prompt = gate.check_and_record(req, chapter_id="local:alice-agent")

    client = TestClient(create_app(_cfg()))
    feed = client.get("/api/local/consent/decisions").json()
    assert feed["quorum_policy"] == {"required": 1}
    proposed = [e for e in feed["envelopes"] if e["lifecycle"] == "proposed"]
    assert len(proposed) == 1
    sha = proposed[0]["payload"]["prompt_event_sha256"]
    assert sha == prompt.event_sha256

    resp = client.post(
        "/api/local/consent/deny",
        json={
            "prompt_event_sha256": sha,
            "request": {
                "capability": req.capability,
                "scope": req.scope,
                "context": req.context,
                "provenance": req.provenance,
            },
        },
    )
    assert resp.status_code == 200

    feed = client.get("/api/local/consent/decisions").json()
    kinds = [e["payload"]["kind"] for e in feed["envelopes"]]
    assert kinds == ["operator_prompt", "operator_deny"]
    assert all(e["lifecycle"] == "signed" for e in feed["envelopes"])  # nothing pending
    assert feed["envelopes"][1]["trace_id"] == sha  # denial chained to its prompt
