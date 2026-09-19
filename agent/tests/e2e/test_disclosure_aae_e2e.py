"""Selective disclosure + AAE audit surface, against a live member.

Claims driven (STELLARMINDS.md:48,50,254-262,295-296):
  - /api/local/disclose reveals k receipts, each with an sm-parc Merkle
    inclusion proof against the signed PARC's behavioral_merkle_root; the
    bundle verifies FULLY OFFLINE, and a tampered receipt fails
  - every consent-gate decision issues a signed, per-agent hash-chained
    sm-aae envelope; /api/local/aae/audit exports the auditor-shaped chain +
    a checkpoint whose Merkle commitment (sha256-concat) verifies offline,
    and per-leaf inclusion proofs fold to the checkpoint root
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time

import pytest

from tests.e2e.conftest import (
    AGENT_DIR,
    PASSPHRASE,
    e2e_gate,
    plan_intent,
)

pytestmark = e2e_gate

# Seeds one self-issued receipt into the member's OWN Agency Log using its
# persisted identity (run with the member's HOME) and prints the receipt id.
_SEED_RECEIPT = """
import base64, json
from community_member import keystore
from community_member.arp import AgencyLog, did_from_private_key
from community_member.config import CONFIG_DIR, Config
from community_member.interactions import record_interaction

cfg = Config.load()
priv = keystore.load_private_key(cfg.agent_id)
seed = base64.b64decode(priv)
receipt = record_interaction(
    sk_bytes=seed,
    agency_log=AgencyLog(home=CONFIG_DIR),
    counterparty_did="did:key:z6MkexampleCounterparty",
    counterparty_label="E2E Counterparty",
    summary="e2e disclosure seed interaction",
)
print(json.dumps({"receipt_id": receipt["receipt_id"]}))
"""


def _run_in_member_home(member, code: str) -> dict:
    env = {
        "PATH": "/usr/bin:/bin",
        "COMMUNITY_MEMBER_HOME": str(member.home),
        "COMMUNITY_MEMBER_KEYSTORE": "passphrase",
        "COMMUNITY_MEMBER_PASSPHRASE": PASSPHRASE,
    }
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=AGENT_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_disclosure_bundle_verifies_offline_and_tamper_fails(member_factory):
    from community_member.receipt_disclosure import verify_disclosure

    m = member_factory("e2e-disclose")
    receipt_id = _run_in_member_home(m, _SEED_RECEIPT)["receipt_id"]

    resp = m.post("/api/local/disclose", json={"receipt_ids": [receipt_id]})
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle.get("credential") and bundle.get("disclosed"), list(bundle)

    # Fully offline verification (sm-parc inclusion proof + credential sig).
    result = verify_disclosure(bundle, expected_issuer=bundle["credential"]["issuer"])
    assert result.get("ok") is True, result

    # Tampering with the disclosed receipt must break the proof.
    tampered = json.loads(json.dumps(bundle))
    tampered["disclosed"][0]["receipt"]["summary"] = "forged summary"
    bad = verify_disclosure(tampered, expected_issuer=tampered["credential"]["issuer"])
    assert bad.get("ok") is False, bad

    # Unknown receipt id → 400, not a bundle.
    r400 = m.post("/api/local/disclose", json={"receipt_ids": ["nonexistent-id"]})
    assert r400.status_code == 400, r400.text


def _fold(leaf_hash: str, siblings: list[dict], expected_root: str) -> bool:
    """The auditor's verifyMerkleInclusion: plain SHA-256(left||right)."""
    running = bytes.fromhex(leaf_hash)
    for step in siblings:
        sib = bytes.fromhex(step["hash"])
        running = hashlib.sha256(sib + running if step["position"] == "left" else running + sib).digest()
    return running.hex() == expected_root.lower()


@pytest.fixture()
def consent_active_member(org_server, llm_stub, member_factory):
    """A member whose consent gate has actually decided things (via the
    deterministic planner stub), so its AAE chain is non-empty."""
    m = member_factory("e2e-aae", with_llm_stub=True)
    ws = m.home / "workspace"
    ws.mkdir(exist_ok=True)
    (ws / "f.txt").write_text("x\n")
    prop = {
        "capability": "fs.read",
        "scope": str(ws / "f.txt"),
        "context": "e2e-aae-ctx",
        "provenance": "trusted",
        "rationale": "aae drive",
        "extra": {"path": str(ws / "f.txt")},
    }
    r = m.post("/api/local/intent/dispatch", json={"text": plan_intent([prop])}).json()
    assert r.get("queued") == 1, r

    # Resolve it (deny — also proves refuse-decisions are enveloped).
    deadline = time.time() + 15
    row = None
    while time.time() < deadline and row is None:
        rows = m.get("/api/local/consent/pending").json()["pending"]
        row = next((x for x in rows if x["capability"] == "fs.read"), None)
        time.sleep(0.5)
    assert row is not None
    m.post(
        "/api/local/consent/deny",
        json={
            "prompt_event_sha256": row["prompt_event_sha256"],
            "request": {
                "capability": prop["capability"],
                "scope": prop["scope"],
                "context": prop["context"],
                "provenance": prop["provenance"],
            },
        },
    )
    return m


def test_aae_chain_exports_and_folds_offline(consent_active_member):
    m = consent_active_member
    bundle = m.get("/api/local/aae/audit").json()
    envelopes = bundle["envelopes"]
    checkpoint = bundle["checkpoint"]
    assert envelopes, "consent decisions must produce AAE envelopes"
    assert checkpoint, "non-empty chain must produce a checkpoint"

    # Chain linkage: each envelope names its predecessor.
    hashes = [e["envelope_hash"] for e in envelopes]
    for prev, cur in zip(envelopes, envelopes[1:]):
        assert cur.get("predecessor_hash") == prev["envelope_hash"], (prev, cur)

    # The checkpoint's commitment is honest sha256-concat, offline.
    payload = checkpoint["payload"]
    root = payload["merkle_root"]
    assert payload["merkle_inclusion_proof_method"] == "sha256-concat", payload
    assert payload["predecessor_hashes"] == hashes
    assert checkpoint["predecessor_hash"] == hashes[-1]

    # Every leaf's inclusion proof (served per-leaf) folds to the root.
    for leaf in hashes:
        proof = m.get(f"/api/local/aae/audit/proof/{leaf}").json()
        assert proof["expectedRoot"] == root, proof
        assert _fold(leaf, proof["siblings"], root), (leaf, proof)

    # Unknown leaf → 404.
    r = m.get("/api/local/aae/audit/proof/" + "0" * 64)
    assert r.status_code == 404
