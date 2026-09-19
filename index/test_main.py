"""Tests for the Lean Index — the NEST-compatible corroboration registry.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import importlib
import time

import pytest
from fastapi.testclient import TestClient

import main as index_main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("INDEX_DB_PATH", str(tmp_path / "index.db"))
    # This suite pins the ORIGINAL open-write contract (NEST parity, attestations
    # opaque to the registry) — still reachable as the tamper-drill posture. The
    # default posture (attestation gate ON) is covered by
    # test_attestation_gate.py, where attestations are real and verified.
    monkeypatch.setenv("INDEX_ATTESTATION_GATE", "off")
    # These cases are about body caps, rate limits and capacity, not about
    # write auth. Writes now require a token by default, so opt them
    # explicitly into the open posture rather than letting an absent variable
    # decide — which is the habit the change is correcting.
    monkeypatch.setenv("INDEX_WRITE_OPEN", "true")
    importlib.reload(index_main)
    return TestClient(index_main.app)


RECORD = {
    "agent_id": "astrocity",
    "endpoint": "https://astrocity.example.com",
    "facts": {"agent_name": "astrocity"},
    "attestation": {"record": {"agent_id": "astrocity"}, "sig": "opaque-to-the-registry"},
    "status": "running",
}


def test_register_and_fetch_roundtrip(client):
    """HAPPY: POST then GET by id returns the full doc, attestation intact."""
    assert client.post("/api/agents", json=RECORD).status_code == 201
    doc = client.get("/api/agents/astrocity").json()
    assert doc["endpoint"] == "https://astrocity.example.com"
    assert doc["attestation"]["sig"] == "opaque-to-the-registry"


def test_list_serves_full_docs(client):
    """HAPPY: the LIST endpoint does NOT strip attestations — the exact NEST
    behavior this registry exists to improve on."""
    client.post("/api/agents", json=RECORD)
    agents = client.get("/api/agents").json()["agents"]
    assert len(agents) == 1
    assert agents[0]["attestation"]["sig"] == "opaque-to-the-registry"


def test_duplicate_register_conflicts_then_put_updates(client):
    """HAPPY: NEST parity — second POST 409s, the client's PUT fallback works
    and merge-updates without wiping stored fields."""
    client.post("/api/agents", json=RECORD)
    assert client.post("/api/agents", json=RECORD).status_code == 409
    resp = client.put("/api/agents/astrocity", json={"status": "running", "endpoint": "https://new.example.com"})
    assert resp.status_code == 200
    doc = client.get("/api/agents/astrocity").json()
    assert doc["endpoint"] == "https://new.example.com"
    assert doc["attestation"]["sig"] == "opaque-to-the-registry"  # merge, not replace


def test_put_creates_when_absent(client):
    """EDGE: heartbeat PUT against an empty index self-heals the record."""
    resp = client.put("/api/agents/astrocity", json={"endpoint": "https://astrocity.example.com"})
    assert resp.status_code == 200
    assert client.get("/api/agents/astrocity").status_code == 200


def test_missing_agent_404s(client):
    """EDGE: hard 404 (not a soft-404 body) for unknown ids — the divergence
    detector reads this as a positive claim of absence."""
    assert client.get("/api/agents/ghost").status_code == 404
    assert client.delete("/api/agents/ghost").status_code == 404


def test_delete_removes(client):
    """HAPPY: DELETE then GET 404s (clean_stale_agents path)."""
    client.post("/api/agents", json=RECORD)
    assert client.delete("/api/agents/astrocity").status_code == 200
    assert client.get("/api/agents/astrocity").status_code == 404


def test_register_requires_agent_id(client):
    """FAILURE: a body without agent_id is a 400, not a stored junk row."""
    assert client.post("/api/agents", json={"endpoint": "https://x.example.com"}).status_code == 400


def test_put_path_is_authoritative_for_identity(client):
    """ADVERSARIAL: a PUT body claiming a different agent_id cannot re-key the
    record — the path wins."""
    client.post("/api/agents", json=RECORD)
    client.put("/api/agents/astrocity", json={"agent_id": "attacker"})
    assert client.get("/api/agents/astrocity").json()["agent_id"] == "astrocity"
    assert client.get("/api/agents/attacker").status_code == 404


def test_health_is_not_org_shaped(client):
    """EDGE: /health must not look like an org server (no agent_id/members),
    or federation discovery's structural probe would treat the index as a
    peer org."""
    h = client.get("/health").json()
    assert h["status"] == "ok"
    assert "agent_id" not in h and "members" not in h


# ── F2: write-surface guards (DoS caps + optional token) ─────────────────────


def _client_with_env(tmp_path, monkeypatch, **env):
    monkeypatch.setenv("INDEX_DB_PATH", str(tmp_path / "index.db"))
    # Legacy open-posture suite (see the `client` fixture note): the gate's
    # default posture is covered by test_attestation_gate.py.
    monkeypatch.setenv("INDEX_ATTESTATION_GATE", "off")
    # These cases are about body caps, rate limits and capacity, not about
    # write auth. Writes now require a token by default, so opt them
    # explicitly into the open posture rather than letting an absent variable
    # decide — which is the habit the change is correcting.
    monkeypatch.setenv("INDEX_WRITE_OPEN", "true")
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    importlib.reload(index_main)
    return TestClient(index_main.app)


def test_oversized_body_rejected(tmp_path, monkeypatch):
    """A body over the size cap is refused (413) before it can bloat the db."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_MAX_BODY_BYTES=2048)
    big = {"agent_id": "x", "blob": "A" * 5000}
    resp = client.post("/api/agents", json=big)
    assert resp.status_code == 413


def test_oversized_chunked_body_rejected_without_content_length(tmp_path, monkeypatch):
    """The cap must hold when Content-Length is absent (chunked upload) — the
    size is enforced while streaming, so an oversized body can't be buffered into
    RAM before a post-hoc length check. Streaming an iterator makes httpx use
    chunked transfer with no Content-Length."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_MAX_BODY_BYTES=2048)

    def gen():
        # Two chunks whose total exceeds the cap; no Content-Length is sent.
        yield b"A" * 1500
        yield b"A" * 1500

    resp = client.post("/api/agents", content=gen())
    assert resp.status_code == 413


def test_write_token_required_when_set(tmp_path, monkeypatch):
    """With INDEX_WRITE_TOKEN set, an unauthenticated write is 401; the correct
    token passes."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_WRITE_TOKEN="s3cret")
    assert client.post("/api/agents", json=RECORD).status_code == 401
    ok = client.post("/api/agents", json=RECORD, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 201
    # Reads stay open regardless of the write token.
    assert client.get("/api/agents/astrocity").status_code == 200


def test_write_rate_limit(tmp_path, monkeypatch):
    """Per-IP write rate limit returns 429 once the window budget is spent."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_WRITE_RATE_MAX=2, INDEX_WRITE_RATE_WINDOW_S=60)
    assert client.put("/api/agents/a", json={"status": "up"}).status_code == 200
    assert client.put("/api/agents/b", json={"status": "up"}).status_code == 200
    assert client.put("/api/agents/c", json={"status": "up"}).status_code == 429


def test_record_capacity_cap(tmp_path, monkeypatch):
    """New ids are refused (507) once the registry is at capacity; updates to
    existing ids still work."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_MAX_RECORDS=1)
    assert client.post("/api/agents", json={"agent_id": "first"}).status_code == 201
    assert client.post("/api/agents", json={"agent_id": "second"}).status_code == 507
    # Updating the existing record is not a new id → allowed.
    assert client.put("/api/agents/first", json={"status": "up"}).status_code == 200


def test_writes_are_REFUSED_when_no_token_is_configured(tmp_path, monkeypatch):
    """an index that cannot authenticate a write must refuse it.

    This test previously asserted the OPPOSITE — that writes stay open with no
    token — because HARDENING F2 stage 1 deliberately preserved the open-write
    default. That decision is superseded, not overlooked: the deployed index was
    measured with NEITHER gate variable set, and its writer set is exactly the
    three orgs we operate, so the "open ecosystem / NEST parity" rationale that
    justified the default no longer describes reality. The reversal is recorded
    in docs/HARDENING.md under F2.
    """
    monkeypatch.setenv("INDEX_DB_PATH", str(tmp_path / "index.db"))
    monkeypatch.setenv("INDEX_ATTESTATION_GATE", "off")
    monkeypatch.delenv("INDEX_WRITE_TOKEN", raising=False)
    monkeypatch.delenv("INDEX_WRITE_OPEN", raising=False)
    import importlib

    import main as index_main

    importlib.reload(index_main)
    from fastapi.testclient import TestClient

    with TestClient(index_main.app) as c:
        r = c.post("/api/agents", json=RECORD)
    assert r.status_code == 503, r.text
    assert "INDEX_WRITE_TOKEN" in r.json()["detail"]


def test_the_open_posture_is_still_reachable_but_must_be_declared(client):
    """The tamper-drill posture is preserved — as an explicit opt-in.

    F2's open-write mode still exists; what changed is that it must be chosen.
    The `client` fixture sets INDEX_WRITE_OPEN=true, so this asserts the opt-out
    genuinely restores the old behaviour rather than the mode being removed.
    """
    assert client.post("/api/agents", json=RECORD).status_code == 201


def test_rate_limit_key_ignores_forwarded_for(tmp_path, monkeypatch):
    """The rate-limit key must NOT be the spoofable X-Forwarded-For — otherwise
    an attacker rotates the header to mint unlimited buckets and dodge the limit
    (and grow memory). All requests share the peer key regardless of XFF."""
    client = _client_with_env(tmp_path, monkeypatch, INDEX_WRITE_RATE_MAX=2, INDEX_WRITE_RATE_WINDOW_S=60)
    h1 = {"X-Forwarded-For": "1.1.1.1"}
    h2 = {"X-Forwarded-For": "2.2.2.2"}
    assert client.put("/api/agents/a", json={"s": 1}, headers=h1).status_code == 200
    assert client.put("/api/agents/b", json={"s": 1}, headers=h2).status_code == 200
    # A third write with yet another forged XFF is still throttled — the forged
    # header bought no fresh budget.
    assert client.put("/api/agents/c", json={"s": 1}, headers={"X-Forwarded-For": "3.3.3.3"}).status_code == 429


def test_sweep_evicts_stale_keys(tmp_path, monkeypatch):
    """_sweep_write_times drops keys whose whole window has aged out, so the map
    can't retain a deque per client that ever wrote (the limiter must not become
    its own memory-DoS)."""
    _client_with_env(tmp_path, monkeypatch)  # reload for a clean module
    from collections import deque

    now = time.time()
    index_main._write_times.clear()
    index_main._write_times["stale"] = deque([now - 999])  # fully aged out
    index_main._write_times["fresh"] = deque([now])  # still in window
    index_main._sweep_write_times(cutoff=now - index_main._RATE_WINDOW_S)
    assert "stale" not in index_main._write_times
    assert "fresh" in index_main._write_times


def test_rate_key_count_is_capped(tmp_path, monkeypatch):
    """A new key is refused (429) rather than growing the map past the backstop
    cap when every existing bucket is still live (can't be swept)."""
    _client_with_env(tmp_path, monkeypatch, INDEX_RATE_MAX_KEYS=2, INDEX_WRITE_RATE_WINDOW_S=600)
    from collections import deque

    now = time.time()
    index_main._write_times.clear()
    index_main._write_times["a"] = deque([now])
    index_main._write_times["b"] = deque([now])

    class _Req:
        class client:
            host = "c"

        headers: dict = {}

    with pytest.raises(index_main.HTTPException) as exc:
        index_main._check_rate(_Req())
    assert exc.value.status_code == 429
