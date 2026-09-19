"""the agent's AAE chain passes sm-attest-auditor's bidirectional drill.

The auditor is a React component; its verification core is two pure functions
(``buildChainWalk`` + ``verifyMerkleInclusion`` in audit-logic.ts). ``_walk``
and ``_fold`` below replicate those functions' exact semantics — hash-by-map
chain-walk trusting ``envelope_hash``, and plain ``SHA-256(left || right)``
folding over hex nodes (no RFC 6962 domain prefixes) — so this suite drills
our export exactly the way the auditor will.

Forward: every envelope collected genesis-first, every link intact.
Reverse: every leaf's inclusion proof folds to the checkpoint's root.
Adversarial: a tampered stored envelope breaks the walk; a tampered leaf
breaks the fold.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("sm_aae", reason="needs sm-aae")

from fastapi.testclient import TestClient

from community_member import aae_audit
from community_member.config import Config
from community_member.consent import gate, ledger
from community_member.server import create_app

SEED = b"aae-audit-test-!".ljust(32, b"!")
KEY_B64 = base64.b64encode(SEED).decode()
CHAPTER = "local:test-device"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def chain(tmp_path: Path):
    """A real 4-envelope chain: three gate verdicts + one user approval."""
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    req = gate.ActionRequest(
        capability="browser.navigate", scope="https://example.com", context="ctx-0", provenance="trusted"
    )
    prompt = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=prompt.event_sha256)
    for i in (1, 2):
        gate.check_and_record(
            gate.ActionRequest(capability="fs.read", scope=f"/tmp/{i}", context=f"ctx-{i}", provenance="trusted"),
            chapter_id=CHAPTER,
        )
    return tmp_path


# ── auditor-logic replicas (audit-logic.ts semantics, verbatim) ──────


def _walk(envelopes: list[dict], start_hash: str) -> list[dict]:
    """buildChainWalk: follow predecessor_hash by envelope_hash map, cycle-safe,
    halting at a missing predecessor; returns genesis-first ChainStep dicts."""
    by_hash = {e["envelope_hash"]: e for e in envelopes if e.get("envelope_hash")}
    collected, seen, cursor = [], set(), start_hash
    while cursor and cursor not in seen:
        seen.add(cursor)
        env = by_hash.get(cursor)
        if env is None:
            break
        collected.append(env)
        cursor = env.get("predecessor_hash") or None
    chronological = list(reversed(collected))
    steps = []
    for index, envelope in enumerate(chronological):
        pred = envelope.get("predecessor_hash") or None
        prev_hash = chronological[index - 1]["envelope_hash"] if index > 0 else None
        link_intact = (index == 0) if pred is None else (prev_hash is not None and pred == prev_hash)
        steps.append({"envelope": envelope, "linkIntact": link_intact})
    return steps


def _fold(leaf_hash: str, siblings: list[dict], expected_root: str) -> bool:
    """verifyMerkleInclusion: plain SHA-256(left || right) over hex nodes."""
    running = bytes.fromhex(leaf_hash)
    for step in siblings:
        sib = bytes.fromhex(step["hash"])
        running = hashlib.sha256(sib + running if step["position"] == "left" else running + sib).digest()
    return running.hex() == expected_root.lower()


# ── forward drill ────────────────────────────────────────────────────


def test_forward_chain_walk_passes(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    assert len(envelopes) == 4
    steps = _walk(envelopes, envelopes[-1]["envelope_hash"])
    assert len(steps) == 4  # the walk reaches genesis
    assert all(s["linkIntact"] for s in steps)
    assert steps[0]["envelope"].get("predecessor_hash") is None  # genesis first
    # Every exported envelope is a decision event carrying its signed artifact.
    assert all(e["type"] == "decision" and e["payload"]["envelope"]["sig"] for e in envelopes)


def test_checkpoint_reverse_walk_reaches_genesis(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    checkpoint = aae_audit.build_checkpoint_envelope(envelopes, tenant="alice", scope_key="did:key:zX")
    assert checkpoint is not None
    assert checkpoint["type"] == "checkpoint"
    assert checkpoint["predecessor_hash"] == envelopes[-1]["envelope_hash"]
    # The auditor's reverse drill: walk from the CHECKPOINT back to genesis.
    steps = _walk([*envelopes, checkpoint], checkpoint["envelope_hash"])
    assert len(steps) == 5
    assert all(s["linkIntact"] for s in steps)


# ── reverse (inclusion) drill ────────────────────────────────────────


def test_every_leaf_inclusion_proof_folds_to_root(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    checkpoint = aae_audit.build_checkpoint_envelope(envelopes, tenant="alice", scope_key="did:key:zX")
    payload = checkpoint["payload"]
    assert payload["merkle_inclusion_proof_method"] == "sha256-concat"
    assert payload["checkpoint_subject"]["covered_envelopes_count"] == 4
    assert payload["predecessor_hashes"] == [e["envelope_hash"] for e in envelopes]
    for env in envelopes:
        proof = aae_audit.inclusion_proof(envelopes, env["envelope_hash"])
        assert proof is not None
        assert proof["expectedRoot"] == payload["merkle_root"]
        assert _fold(proof["leafHash"], proof["siblings"], payload["merkle_root"])


def test_odd_sized_chain_and_single_leaf(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    # Odd (3): exercises the duplicated-node edge.
    odd = envelopes[:3]
    root3 = aae_audit.build_checkpoint_envelope(odd, tenant="alice", scope_key="k")["payload"]["merkle_root"]
    for env in odd:
        proof = aae_audit.inclusion_proof(odd, env["envelope_hash"])
        assert _fold(proof["leafHash"], proof["siblings"], root3)
    # Single leaf: the auditor's 1-leaf case — root == leaf, empty path.
    one = envelopes[:1]
    proof = aae_audit.inclusion_proof(one, one[0]["envelope_hash"])
    assert proof["siblings"] == []
    assert proof["expectedRoot"] == one[0]["envelope_hash"]


def test_unknown_leaf_has_no_proof(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    assert aae_audit.inclusion_proof(envelopes, "ab" * 32) is None
    assert aae_audit.build_checkpoint_envelope([], tenant="alice", scope_key="k") is None


# ── adversarial: tampering fails the drill ───────────────────────────


def test_tampered_stored_envelope_breaks_the_forward_walk(chain):
    envelopes_before = aae_audit.export_auditable_envelopes(tenant="alice")
    victim = envelopes_before[1]["payload"]["envelope"]

    db = chain / "aae.db"
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT id, envelope_json FROM aae_envelopes WHERE envelope_hash = ?",
            (envelopes_before[1]["envelope_hash"],),
        ).fetchone()
        tampered = json.loads(row[1])
        assert tampered == victim
        tampered["action"]["resource"] = "https://evil.example.com"  # rewrite history
        conn.execute("UPDATE aae_envelopes SET envelope_json = ? WHERE id = ?", (json.dumps(tampered), row[0]))
        conn.commit()

    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    assert len(envelopes) == 3  # the forged envelope fails verify_envelope and drops out
    steps = _walk(envelopes, envelopes[-1]["envelope_hash"])
    assert len(steps) < 3  # the walk halts at the gap — it never reaches genesis


def test_tampered_leaf_fails_the_fold(chain):
    envelopes = aae_audit.export_auditable_envelopes(tenant="alice")
    root = aae_audit.build_checkpoint_envelope(envelopes, tenant="alice", scope_key="k")["payload"]["merkle_root"]
    proof = aae_audit.inclusion_proof(envelopes, envelopes[0]["envelope_hash"])
    assert _fold("00" * 32, proof["siblings"], root) is False  # swapped leaf
    bad_path = [dict(proof["siblings"][0], hash="00" * 32), *proof["siblings"][1:]]
    assert _fold(proof["leafHash"], bad_path, root) is False  # tampered sibling


# ── local API ────────────────────────────────────────────────────────


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


def test_audit_routes(chain, monkeypatch):
    pytest.importorskip("nacl.signing", reason="needs PyNaCl")
    monkeypatch.setattr("community_member.config.CONFIG_DIR", chain)
    client = TestClient(create_app(_cfg()))

    bundle = client.get("/api/local/aae/audit").json()
    assert len(bundle["envelopes"]) == 4
    assert bundle["checkpoint"]["payload"]["checkpoint_subject"]["scope_key"].startswith("did:key:z")
    leaf = bundle["envelopes"][0]["envelope_hash"]
    proof = client.get(f"/api/local/aae/audit/proof/{leaf}").json()
    assert _fold(proof["leafHash"], proof["siblings"], bundle["checkpoint"]["payload"]["merkle_root"])

    assert client.get("/api/local/aae/audit/proof/" + "ab" * 32).status_code == 404


def test_audit_routes_empty_chain(tmp_path, monkeypatch):
    pytest.importorskip("nacl.signing", reason="needs PyNaCl")
    ledger.init(tmp_path / "consent.db", signing_key_b64=KEY_B64)
    monkeypatch.setattr("community_member.config.CONFIG_DIR", tmp_path)
    client = TestClient(create_app(_cfg()))
    bundle = client.get("/api/local/aae/audit").json()
    assert bundle == {"envelopes": [], "checkpoint": None}
