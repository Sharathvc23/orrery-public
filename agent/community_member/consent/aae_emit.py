"""Consent-gate → sm-aae envelope emission — the authorization half.

ARP receipts record what the agent DID; an sm-aae Attested Action Envelope
records what the agent MAY DO — the pre-action verdict, signed before
execution, with refusals as first-class signed artifacts. Orrery's consent
gate is its pre-action verdict engine; this module gives every gate decision
a portable, independently verifiable form: a signed envelope chained per
agent (``prev_hash``), persisted beside the consent ledger and cross-linked
to its row via ``params.consent_event_sha256``.

``sm-aae`` is upstream (``docs/integrations/STELLARMINDS.md``); this is the
thin downstream adapter — envelopes are minted only through
``sm_aae.issue_envelope`` and chain-checked with ``sm_aae.order_chain``.

The consent ledger remains the authoritative local record. Emission is wired
through ``ledger.init`` (same signing key, same directory) and must never
wedge the gate: no signing key ⇒ the emitter stays disabled; a failure logs
loudly and the gate decision stands.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_db_path: Path | None = None
_signing_key_hex: str | None = None
_agent_did: str | None = None
_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS aae_envelopes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    envelope_hash TEXT NOT NULL UNIQUE,
    prev_hash     TEXT,
    issued_at     TEXT NOT NULL,
    envelope_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aae_envelopes_agent
    ON aae_envelopes(agent_id, id);
"""


def configure(db_path: str | Path, signing_key_b64: str | None = None) -> None:
    """Wire the emitter — called by ``consent.ledger.init`` with the same
    signing key and directory, so every existing init call site gets envelope
    emission for free.

    Envelopes MUST be signed, so without a usable 32-byte Ed25519 key the
    emitter stays disabled (``emit_decision`` returns None). Mirroring the
    ledger's G4 rule, a later ``configure()`` without a key KEEPS a previously
    configured one. The envelope ``agent_id`` is the did:key derived from the
    signing key — stable, and independently checkable against ``pubkey``.
    """
    global _db_path, _signing_key_hex, _agent_did
    _db_path = Path(db_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    if signing_key_b64 is not None:
        try:
            seed = base64.b64decode(signing_key_b64)
            if len(seed) != 32:
                raise ValueError(f"expected a 32-byte Ed25519 seed, got {len(seed)} bytes")
            from community_member.arp import did_from_private_key

            _signing_key_hex = seed.hex()
            _agent_did = did_from_private_key(seed)
        except Exception as e:  # noqa: BLE001 — a bad key disables emission, never blocks ledger init
            print(f"[aae] emitter disabled — unusable signing key: {e}")
            _signing_key_hex = None
            _agent_did = None
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def _connect() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("consent.aae_emit not configured — ledger.init() wires it")
    conn = sqlite3.connect(str(_db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def _tip(conn: sqlite3.Connection, agent_id: str) -> str | None:
    row = conn.execute(
        "SELECT envelope_hash FROM aae_envelopes WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    return str(row["envelope_hash"]) if row else None


def emit_decision(
    *,
    capability: str,
    scope: str,
    params: dict[str, Any],
    policy_id: str,
    outcome: str,
    issued_at: str | None = None,
) -> dict[str, Any] | None:
    """Issue + persist one chained envelope for a gate decision.

    ``outcome`` is sm-aae's closed set (``authorized`` / ``denied`` /
    ``conditional``). Returns the signed envelope, or None when the emitter is
    disabled or emission fails — the caller's gate decision is never blocked,
    and failures are logged loudly (the consent ledger stays authoritative).
    """
    if _db_path is None or _signing_key_hex is None or _agent_did is None:
        return None
    try:
        from sm_aae import envelope_hash, issue_envelope

        with _write_lock:  # serialize: two emitters chaining to the same tip would fork
            with _connect() as conn:
                env = issue_envelope(
                    _signing_key_hex,
                    agent_id=_agent_did,
                    verb=capability,
                    resource=scope,
                    params=params,
                    policy_id=policy_id,
                    outcome=outcome,
                    prev_hash=_tip(conn, _agent_did),
                    issued_at=issued_at or datetime.now(UTC).isoformat(),
                )
                conn.execute(
                    "INSERT INTO aae_envelopes"
                    " (agent_id, envelope_hash, prev_hash, issued_at, envelope_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        env["agent_id"],
                        envelope_hash(env),
                        env["prev_hash"],
                        env["issued_at"],
                        json.dumps(env, ensure_ascii=False),
                    ),
                )
                conn.commit()
        return env
    except Exception as e:  # noqa: BLE001 — emission must never wedge the consent gate
        print(f"[aae] envelope emission failed ({policy_id!r}, {outcome!r}): {e}")
        return None


def list_envelopes(agent_id: str | None = None, *, limit: int = 1000) -> list[dict[str, Any]]:
    """Stored envelopes, oldest first. ``agent_id`` None means the configured
    agent's chain (the common case); pass an explicit id to inspect others."""
    if _db_path is None:
        return []
    aid = agent_id or _agent_did
    if aid is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT envelope_json FROM aae_envelopes WHERE agent_id = ? ORDER BY id ASC LIMIT ?",
            (aid, limit),
        ).fetchall()
    return [json.loads(r["envelope_json"]) for r in rows]


def verify_chain(agent_id: str | None = None) -> dict[str, Any]:
    """Re-derive the agent's envelope chain end-to-end via ``sm_aae.order_chain``.

    Returns ``{"ok", "length", "agent_id"}``. ``ok`` is False when any envelope
    fails signature verification or the set does not form exactly one intact
    chain (gap, fork, splice, duplicate) — the same tamper classes the consent
    ledger's ``verify_chain`` catches, proven here on the portable artifact.
    """
    from sm_aae import order_chain

    envelopes = list_envelopes(agent_id)
    aid = agent_id or _agent_did or ""
    ordered = order_chain(envelopes)
    return {"ok": ordered is not None, "length": len(envelopes), "agent_id": aid}


def _reset_for_tests() -> None:
    """Drop state so tests can re-configure cleanly. NOT for production use."""
    global _db_path, _signing_key_hex, _agent_did
    _db_path = None
    _signing_key_hex = None
    _agent_did = None


__all__ = ["configure", "emit_decision", "list_envelopes", "verify_chain"]
