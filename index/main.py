"""Lean Index — a minimal NEST-compatible agent registry.

The cross-registry divergence detector (server/registry_divergence.py) needs
two independent registries to corroborate against, and NEST is the only
public one that speaks the legacy ``/api/agents`` contract the orgs use.
This service is the second: the same wire surface, run on our own
infrastructure, so a registry that omits, re-points, or re-keys an org
diverges from its sibling and the orgs' event logs get the alarm.

Deliberately better than NEST in one respect: the LIST endpoint serves full
documents — signed endpoint attestations included — instead of a trimmed
projection. A registry that strips the very field that makes records
self-certifying forces consumers into per-id fetches; this one doesn't.

Deliberately NEST-like in another: writes are open (no auth), exactly like
the sandbox. That is not a hole — it is the threat model this registry
exists inside. Records are self-certifying (Ed25519 attestations, verified
client-side) and consumers pin DIDs, so a tampered record is *detectable*,
which is the property the whole series is built on. An open write surface
also makes live tamper drills honest.

Storage: sqlite (stdlib) at ``INDEX_DB_PATH`` (default ``/data/index.db`` —
mount a persistent volume there for durability). Orgs re-publish their records
on heartbeat, so even a wiped index self-heals within a cycle.

Health surface: intentionally NOT org-shaped (no ``agent_id``/``members``),
so federation discovery's structural probe never mistakes the index for a
peer org.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections import deque
from typing import Any

from fastapi import FastAPI, HTTPException, Request

import attestation_gate
import env_flags

app = FastAPI(title="lean-index", docs_url=None, redoc_url=None)


# ── F2: write-surface guards ─────────────────────────────────────────────────
# The write surface is open BY DESIGN (self-certifying records + consumer-side
# DID pinning / divergence detection are the tamper defense). Open ≠ unbounded,
# though: without caps it is a trivial DoS/record-takeover primitive. These
# always-on limits bound the damage; INDEX_WRITE_TOKEN optionally locks writes
# entirely for a non-drill deployment. Stage 2 adds the per-org
# attestation gate (attestation_gate.py + _gate_write): the first VALID Ed25519
# endpoint attestation TOFU-pins the id's DID, and every later write to a
# pinned id must be attested by that DID — takeover rejected at the surface.
# INDEX_ATTESTATION_GATE=off restores the pure-open drill posture.
_MAX_BODY_BYTES = int(os.environ.get("INDEX_MAX_BODY_BYTES", str(64 * 1024)))
_MAX_RECORDS = int(os.environ.get("INDEX_MAX_RECORDS", str(100_000)))
_RATE_MAX = int(os.environ.get("INDEX_WRITE_RATE_MAX", "60"))
_RATE_WINDOW_S = float(os.environ.get("INDEX_WRITE_RATE_WINDOW_S", "60"))
# Backstop cap on distinct rate-limit keys so the map can never grow unbounded.
_MAX_RATE_KEYS = int(os.environ.get("INDEX_RATE_MAX_KEYS", "10000"))

# Per-client sliding window of recent write timestamps.
_write_times: dict[str, deque[float]] = {}


def _client_key(request: Request) -> str:
    """Rate-limit key = the socket peer (the proxy in front of us, or a direct
    client). Deliberately NOT X-Forwarded-For: a client sets XFF freely, so
    keying on it would let an attacker mint unlimited buckets — unbounded memory
    AND a fresh rate budget per forged hop, defeating the very limit. The peer
    IP is unspoofable. Behind a reverse proxy this is coarse (all clients share
    the proxy's IP, so the limit acts as a near-global write cap) — size
    INDEX_WRITE_RATE_MAX for that, or terminate the limit at the proxy."""
    return request.client.host if request.client else "unknown"


def _sweep_write_times(cutoff: float) -> None:
    """Drop keys whose entire window has aged out — keeps ``_write_times`` from
    retaining a deque per client that ever wrote."""
    for k in list(_write_times.keys()):
        bucket = _write_times[k]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if not bucket:
            del _write_times[k]


def write_token_required() -> bool:
    """Whether a write must present INDEX_WRITE_TOKEN.

    Defaults TRUE. Unset used to mean "open writes", which made the token
    opt-in: the deployed index ran with no token set and accepted
    unauthenticated writes (measured 2026-08-03 — neither gate variable was set
    on the live service). See the HARDENING F2 note for why the open-write
    default was originally deliberate and why that reasoning no longer holds.

    ``INDEX_WRITE_OPEN=true`` is the explicit opt-out that restores the open
    posture for a tamper drill — a decision recorded in the environment rather
    than emerging from an absent variable.
    """
    return not env_flags.security_flag("INDEX_WRITE_OPEN", default=False)


def _check_write_token(request: Request) -> None:
    """Enforce INDEX_WRITE_TOKEN on every write unless writes are explicitly open."""
    token = os.environ.get("INDEX_WRITE_TOKEN", "").strip()
    if not token:
        if not write_token_required():
            return
        raise HTTPException(
            status_code=503,
            detail=(
                "INDEX_WRITE_TOKEN is not set, so this index cannot authenticate writes. "
                "Set it, or set INDEX_WRITE_OPEN=true to deliberately accept unauthenticated "
                "writes (tamper-drill posture)."
            ),
        )
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-index-token", "")
    if presented != token:
        raise HTTPException(status_code=401, detail="write token required")


def _check_rate(request: Request) -> None:
    """Per-peer sliding-window rate limit on writes (429 when exceeded)."""
    key = _client_key(request)
    now = time.time()
    cutoff = now - _RATE_WINDOW_S
    bucket = _write_times.get(key)
    if bucket is None:
        # New key: sweep stale buckets before growing the map, and hard-cap the
        # key count as a final backstop against runaway growth.
        if len(_write_times) >= _MAX_RATE_KEYS:
            _sweep_write_times(cutoff)
        if len(_write_times) >= _MAX_RATE_KEYS:
            raise HTTPException(status_code=429, detail="write rate limit exceeded")
        bucket = _write_times.setdefault(key, deque())
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX:
        raise HTTPException(status_code=429, detail="write rate limit exceeded")
    bucket.append(now)


async def _read_capped_json(request: Request) -> Any:
    """Read + parse the JSON body, rejecting anything over the size cap (413)
    so a huge doc can't exhaust memory/disk.

    The size is enforced WHILE STREAMING, not after buffering: ``request.body()``
    accumulates the whole payload in RAM first and honors no limit, so a
    ``Transfer-Encoding: chunked`` upload (or a lying/absent Content-Length) would
    OOM the worker before a post-hoc length check ever ran. We read chunk by
    chunk and abort the moment the running total exceeds the cap."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request body too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        return json.loads(raw) if raw else None
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid JSON body") from e


def _db_path() -> str:
    return os.environ.get("INDEX_DB_PATH", "/data/index.db")


def _db() -> sqlite3.Connection:
    path = _db_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS agents ( agent_id TEXT PRIMARY KEY, doc TEXT NOT NULL, updated_at REAL NOT NULL)"
    )
    # F2 stage 2: TOFU DID pins. Deliberately a separate table from the
    # record itself — a pin survives DELETE, so takeover-via-delete-then-
    # re-register under a new key still 403s.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS did_pins ( agent_id TEXT PRIMARY KEY, did TEXT NOT NULL, pinned_at REAL NOT NULL)"
    )
    return conn


def _gate_write(conn: sqlite3.Connection, agent_id: str, body: dict[str, Any]) -> None:
    """F2 stage 2: the per-org attestation gate. Verifies an attached
    attestation, enforces the TOFU-pinned DID for known ids, and records the
    pin on the first valid attested write. 403 on any rejection.

    ``INDEX_ATTESTATION_GATE=off|0|false`` restores the pure-open write posture
    (tamper-drill mode); the gate is ON by default.

    That default used to be an ACCIDENT of the expression rather than a decision:
    the old inline check tested membership in ("off","0","false"), so an unset
    var landed ON — and so did a typo, and so did "no". Safe, but nothing
    declared it safe, and nobody could tell the direction from the call site.
    security_flag makes it a written-down default that a typo cannot flip."""
    if not env_flags.security_flag("INDEX_ATTESTATION_GATE", default=True):
        return
    row = conn.execute("SELECT did FROM did_pins WHERE agent_id = ?", (agent_id,)).fetchone()
    pinned_did = str(row[0]) if row else None
    allowed, reason, pin_did = attestation_gate.evaluate_write(agent_id, body, pinned_did)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"attestation gate: {reason}")
    if pin_did is not None:
        conn.execute(
            "INSERT OR IGNORE INTO did_pins (agent_id, did, pinned_at) VALUES (?, ?, ?)",
            (agent_id, pin_did, time.time()),
        )
        conn.commit()


def _load(conn: sqlite3.Connection, agent_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT doc FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return json.loads(row[0]) if row else None


def _store(conn: sqlite3.Connection, agent_id: str, doc: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO agents (agent_id, doc, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(agent_id) DO UPDATE SET doc = excluded.doc, updated_at = excluded.updated_at",
        (agent_id, json.dumps(doc), time.time()),
    )
    conn.commit()


@app.get("/health")
def health() -> dict[str, Any]:
    with _db() as conn:
        (count,) = conn.execute("SELECT COUNT(*) FROM agents").fetchone()
    return {"status": "ok", "service": "lean-index", "agents": count}


@app.get("/api/agents")
def list_agents() -> dict[str, Any]:
    with _db() as conn:
        rows = conn.execute("SELECT doc FROM agents ORDER BY agent_id").fetchall()
    return {"agents": [json.loads(r[0]) for r in rows]}


@app.get("/api/agents/{agent_id}")
def get_agent(agent_id: str) -> dict[str, Any]:
    with _db() as conn:
        doc = _load(conn, agent_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return doc


@app.post("/api/agents", status_code=201)
async def register_agent(request: Request) -> dict[str, Any]:
    _check_write_token(request)
    _check_rate(request)
    body = await _read_capped_json(request)
    if not isinstance(body, dict) or not str(body.get("agent_id") or "").strip():
        raise HTTPException(status_code=400, detail="agent_id required")
    agent_id = str(body["agent_id"]).strip()
    with _db() as conn:
        _gate_write(conn, agent_id, body)
        if _load(conn, agent_id) is not None:
            # NEST parity: create conflicts; the client falls back to PUT.
            raise HTTPException(status_code=409, detail="agent_id already registered")
        # Bound total rows so an attacker can't grow the table without limit.
        # Updates to existing ids (PUT) are always allowed; only NEW ids are capped.
        (count,) = conn.execute("SELECT COUNT(*) FROM agents").fetchone()
        if count >= _MAX_RECORDS:
            raise HTTPException(status_code=507, detail="registry at capacity")
        _store(conn, agent_id, body)
    return {"success": True, "agent_id": agent_id}


@app.put("/api/agents/{agent_id}")
async def update_agent(agent_id: str, request: Request) -> dict[str, Any]:
    _check_write_token(request)
    _check_rate(request)
    body = await _read_capped_json(request)
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="object body required")
    with _db() as conn:
        _gate_write(conn, agent_id, body)
        existing = _load(conn, agent_id)
        # A PUT that creates a NEW id is subject to the same capacity cap as POST.
        if existing is None:
            (count,) = conn.execute("SELECT COUNT(*) FROM agents").fetchone()
            if count >= _MAX_RECORDS:
                raise HTTPException(status_code=507, detail="registry at capacity")
        doc = existing or {"agent_id": agent_id}
        # Merge-update, NEST-style: a heartbeat PUT of {status, endpoint,
        # attestation} must not wipe the rest of the record.
        doc.update(body)
        doc["agent_id"] = agent_id  # the path is authoritative for identity
        _store(conn, agent_id, doc)
    return {"success": True, "agent_id": agent_id}


@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: str, request: Request) -> dict[str, Any]:
    _check_write_token(request)
    _check_rate(request)
    with _db() as conn:
        if _load(conn, agent_id) is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        conn.commit()
    return {"success": True, "agent_id": agent_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "7100")))
