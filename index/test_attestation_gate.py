"""That change (F2 stage 2): the per-org attestation gate — DEFAULT index posture.

Real Ed25519 attestations throughout (same construction as
server/registry_attestation.build): the first valid attested write TOFU-pins
the id's DID; later writes to a pinned id must be attested by that DID;
takeover by re-registration, unsigned overwrite, or forged attestation is
rejected at the write surface. Unattested ids stay open (NEST parity).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import base64
import importlib
import time

import base58
import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

import attestation_gate
import main as index_main

ENDPOINT = "https://astrocity.example.com"


def _keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, "did:key:z" + base58.b58encode(b"\xed\x01" + pk).decode()


def _attestation(sk, did, agent_id, endpoint=ENDPOINT, *, issued_at=None, expires_at=None):
    ts = int(time.time()) if issued_at is None else issued_at
    record = {
        "v": 1,
        "agent_id": agent_id,
        "did": did,
        "endpoint": endpoint.rstrip("/"),
        "issued_at": ts,
        "expires_at": expires_at if expires_at is not None else ts + 3600,
    }
    return {"record": record, "sig": base64.b64encode(sk.sign(jcs.canonicalize(record))).decode()}


def _doc(agent_id="astrocity", attestation=None, endpoint=ENDPOINT):
    doc = {"agent_id": agent_id, "endpoint": endpoint, "status": "running"}
    if attestation is not None:
        doc["attestation"] = attestation
    return doc


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("INDEX_DB_PATH", str(tmp_path / "index.db"))
    monkeypatch.delenv("INDEX_ATTESTATION_GATE", raising=False)  # default: gate ON
    # These cases exercise the ATTESTATION gate, not write auth. Writes now
    # require a token by default, so declare the open posture explicitly.
    monkeypatch.setenv("INDEX_WRITE_OPEN", "true")
    importlib.reload(index_main)
    return TestClient(index_main.app)


# ── open default for unattested ids ──────────────────────────────────


def test_unattested_writes_stay_open(client):
    """HAPPY: NEST parity preserved — no attestation, no pin, open writes."""
    assert client.post("/api/agents", json=_doc()).status_code == 201
    assert client.put("/api/agents/astrocity", json={"status": "running"}).status_code == 200


# ── TOFU pin + enforcement ───────────────────────────────────────────


def test_first_valid_attested_write_pins_and_enforces(client):
    """HAPPY then ADVERSARIAL: valid attestation pins; the pinned id then
    rejects an unsigned write and accepts a re-attested one by the same key."""
    sk, did = _keypair()
    assert client.post("/api/agents", json=_doc(attestation=_attestation(sk, did, "astrocity"))).status_code == 201

    resp = client.put("/api/agents/astrocity", json={"status": "running", "endpoint": ENDPOINT})
    assert resp.status_code == 403
    assert "attestation_required" in resp.json()["detail"]

    heartbeat = {"status": "running", "endpoint": ENDPOINT, "attestation": _attestation(sk, did, "astrocity")}
    assert client.put("/api/agents/astrocity", json=heartbeat).status_code == 200


def test_takeover_by_different_key_rejected(client):
    """ADVERSARIAL: the record-takeover F2 exists to stop — a valid attestation
    by a DIFFERENT keypair on a pinned id is rejected."""
    sk, did = _keypair()
    client.post("/api/agents", json=_doc(attestation=_attestation(sk, did, "astrocity")))

    attacker_sk, attacker_did = _keypair()
    forged = {
        "status": "running",
        "endpoint": "https://attacker.example.com",
        "attestation": _attestation(attacker_sk, attacker_did, "astrocity", "https://attacker.example.com"),
    }
    resp = client.put("/api/agents/astrocity", json=forged)
    assert resp.status_code == 403
    assert "did_mismatch" in resp.json()["detail"]
    # The stored record is untouched.
    assert client.get("/api/agents/astrocity").json()["endpoint"] == ENDPOINT


def test_delete_does_not_unpin(client):
    """ADVERSARIAL: delete-then-re-register under a new key is still a
    takeover — the pin survives the record."""
    sk, did = _keypair()
    client.post("/api/agents", json=_doc(attestation=_attestation(sk, did, "astrocity")))
    assert client.delete("/api/agents/astrocity").status_code == 200

    attacker_sk, attacker_did = _keypair()
    resp = client.post("/api/agents", json=_doc(attestation=_attestation(attacker_sk, attacker_did, "astrocity")))
    assert resp.status_code == 403
    assert "did_mismatch" in resp.json()["detail"]
    assert client.post("/api/agents", json=_doc()).status_code == 403  # unsigned re-register also rejected

    # The rightful key re-registers fine.
    assert client.post("/api/agents", json=_doc(attestation=_attestation(sk, did, "astrocity"))).status_code == 201


# ── attestation validity ─────────────────────────────────────────────


def test_garbage_attestation_rejected_even_unpinned(client):
    """FAILURE: an invalid attestation is affirmative evidence of forgery —
    rejected even when the id has no pin (and nothing gets pinned)."""
    doc = _doc(attestation={"record": {"agent_id": "astrocity"}, "sig": "opaque-junk"})
    resp = client.post("/api/agents", json=doc)
    assert resp.status_code == 403
    assert "invalid_attestation:malformed" in resp.json()["detail"]
    # Nothing pinned: an unattested write still goes through afterwards.
    assert client.post("/api/agents", json=_doc()).status_code == 201


def test_tampered_signature_rejected(client):
    sk, did = _keypair()
    att = _attestation(sk, did, "astrocity")
    att["record"]["endpoint"] = "https://attacker.example.com"  # mutate after signing
    resp = client.post("/api/agents", json=_doc(attestation=att, endpoint="https://attacker.example.com"))
    assert resp.status_code == 403
    assert "invalid_signature" in resp.json()["detail"]


def test_expired_and_not_yet_valid_and_inverted_window(client):
    sk, did = _keypair()
    now = int(time.time())
    expired = _attestation(sk, did, "astrocity", issued_at=now - 7200, expires_at=now - 3600)
    assert client.post("/api/agents", json=_doc(attestation=expired)).status_code == 403

    future = _attestation(sk, did, "astrocity", issued_at=now + 3600, expires_at=now + 7200)
    resp = client.post("/api/agents", json=_doc(attestation=future))
    assert resp.status_code == 403
    assert "not_yet_valid" in resp.json()["detail"]

    inverted = _attestation(sk, did, "astrocity", issued_at=now + 100, expires_at=now - 100)
    resp = client.post("/api/agents", json=_doc(attestation=inverted))
    assert resp.status_code == 403
    assert "malformed" in resp.json()["detail"]


def test_subject_and_endpoint_binding(client):
    """ADVERSARIAL: a valid attestation for ANOTHER subject, or an unsigned
    endpoint that contradicts the attested one, is rejected."""
    sk, did = _keypair()
    other = _attestation(sk, did, "someone-else")
    resp = client.post("/api/agents", json=_doc(attestation=other))
    assert resp.status_code == 403
    assert "subject_mismatch" in resp.json()["detail"]

    att = _attestation(sk, did, "astrocity")  # attests ENDPOINT
    resp = client.post("/api/agents", json=_doc(attestation=att, endpoint="https://attacker.example.com"))
    assert resp.status_code == 403
    assert "endpoint_mismatch" in resp.json()["detail"]


# ── drill posture ────────────────────────────────────────────────────


def test_gate_off_restores_open_writes(client, monkeypatch):
    """EDGE: INDEX_ATTESTATION_GATE=off is the tamper-drill posture — even a
    pinned id accepts an unsigned overwrite (the drill's forged record)."""
    sk, did = _keypair()
    client.post("/api/agents", json=_doc(attestation=_attestation(sk, did, "astrocity")))
    monkeypatch.setenv("INDEX_ATTESTATION_GATE", "off")
    forged = {"status": "running", "endpoint": "https://attacker.example.com"}
    assert client.put("/api/agents/astrocity", json=forged).status_code == 200


# ── verifier unit surface ────────────────────────────────────────────


def test_verify_attestation_reasons():
    sk, did = _keypair()
    ok, reason = attestation_gate.verify_attestation(_attestation(sk, did, "a1"))
    assert (ok, reason) == (True, "ok")
    assert attestation_gate.verify_attestation("junk") == (False, "malformed")
    assert attestation_gate.verify_attestation({"record": {}, "sig": "x"}) == (False, "malformed")
    tampered = _attestation(sk, did, "a1")
    tampered["record"]["agent_id"] = "a2"  # mutate a signed field
    assert attestation_gate.verify_attestation(tampered) == (False, "invalid_signature")
    bad_did = _attestation(sk, did, "a1")
    bad_did["record"]["did"] = "did:web:example.com"  # DID resolution precedes the sig check
    assert attestation_gate.verify_attestation(bad_did) == (False, "unsupported_did")


def test_evaluate_write_returns_pin_on_first_attested_write():
    sk, did = _keypair()
    body = _doc(attestation=_attestation(sk, did, "astrocity"))
    allowed, reason, pin = attestation_gate.evaluate_write("astrocity", body, None)
    assert allowed and reason == "tofu_pin" and pin == did
    # Second write with the pin in place: allowed, nothing new to pin.
    allowed, reason, pin = attestation_gate.evaluate_write("astrocity", body, did)
    assert allowed and reason == "pinned_ok" and pin is None
