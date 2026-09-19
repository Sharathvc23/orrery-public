"""ARP v0.1 — chapter-side Issuer Log and verification.

This module implements the chapter's responsibilities under ARP v0.1
(see ``spec/arp/0.1/spec.md``):

* Validate incoming receipts against the canonical JSON Schema
  (``schema/arp/0.1/receipt.schema.json``).
* Verify the Ed25519 signature against canonical (JCS-RFC8785) bytes.
* Optionally verify hash-chain continuity when ``previous_receipt_hash``
  is present.
* Persist the accepted receipt to the chapter's Issuer Log
  (Postgres ``arp_receipts`` table) and compute the chain link this
  receipt produces for the next link.
* Surface receipts back to the principal via a query API.
* **Emit receipts FROM the chapter** for actions the chapter takes on
  behalf of its members (intent matching, mentor invites, governance
  approvals, broadcasts, etc.). See ``emit_chapter_action``.

The module is intentionally thin glue: every signature / schema decision
lives in ``conformance/arp/`` so the chapter side and the conformance
suite share one canonical implementation. Drift between them is impossible
by construction.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _arp_verify import (
    VerificationResult,
    compute_chain_link,
    verify_receipt,
)

_logger = logging.getLogger(__name__)

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""
_offline: bool = False
_local_log: LocalIssuerLog | None = None


class LocalIssuerLog:
    """SQLite-backed Issuer Log for offline / no-Postgres operation.

    Production chapters persist the Issuer Log to Postgres ``arp_receipts``.
    When a chapter runs without Postgres configured (local dev, demos, an
    air-gapped deployment), receipts would otherwise vanish — the writes
    no-op. This store gives the chapter the same Issuer Log semantics
    (persist, query-by-principal, today, recent) against a local file, so
    receipts are viewable exactly as they are in production. The row shape
    mirrors the Postgres ``arp_receipts`` columns this module writes.
    """

    def __init__(self, home: str | Path) -> None:
        self.home = Path(home).expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / "issuer-log.sqlite"
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS arp_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    issuer_did TEXT,
                    principal_did TEXT,
                    issued_at TEXT,
                    action_category TEXT,
                    action_outcome TEXT,
                    human_summary TEXT,
                    counterparty_did TEXT,
                    previous_receipt_hash TEXT,
                    chain_link TEXT,
                    receipt_json TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_principal ON arp_receipts(principal_did)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_issued_at ON arp_receipts(issued_at)")

    def persist(self, row: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                """
                INSERT OR REPLACE INTO arp_receipts (
                    receipt_id, issuer_did, principal_did, issued_at,
                    action_category, action_outcome, human_summary,
                    counterparty_did, previous_receipt_hash, chain_link, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["receipt_id"],
                    row.get("issuer_did"),
                    row.get("principal_did"),
                    row.get("issued_at"),
                    row.get("action_category"),
                    row.get("action_outcome"),
                    row.get("human_summary"),
                    row.get("counterparty_did"),
                    row.get("previous_receipt_hash"),
                    row.get("chain_link"),
                    json.dumps(row["receipt_json"], separators=(",", ":")),
                ),
            )

    def _query(self, where: str, args: tuple[Any, ...], limit: int) -> list[dict[str, Any]]:
        # `where` is one of a few hardcoded literals in this module (never user
        # input); all runtime values are bound as ? parameters below.
        with self._conn() as c:
            rows = c.execute(
                f"SELECT receipt_json FROM arp_receipts {where} ORDER BY issued_at DESC LIMIT ?",  # noqa: S608
                (*args, limit),
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    def list_for_principal(self, principal_did: str, limit: int = 100) -> list[dict[str, Any]]:
        return self._query("WHERE principal_did = ?", (principal_did,), limit)

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._query("", (), limit)

    def todays(self, day_iso: str, limit: int = 200) -> list[dict[str, Any]]:
        return self._query("WHERE issued_at LIKE ?", (f"{day_iso}%",), limit)

    def todays_rows(self, day_iso: str, principal_did: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Today's receipts as flat rows matching the Postgres select shape the
        chronicle surface builder consumes (action_category, human_summary, …)."""
        args: tuple[str, ...]
        if principal_did:
            where, args = "WHERE issued_at LIKE ? AND principal_did = ?", (f"{day_iso}%", principal_did)
        else:
            where, args = "WHERE issued_at LIKE ?", (f"{day_iso}%",)
        receipts = self._query(where, args, limit)
        rows: list[dict[str, Any]] = []
        for rc in receipts:
            action = rc.get("action", {})
            amount = action.get("amount") or {}
            rows.append(
                {
                    "receipt_json": rc,
                    "issued_at": rc.get("issued_at"),
                    "action_category": action.get("category"),
                    "action_outcome": action.get("outcome"),
                    "human_summary": action.get("human_summary"),
                    "amount_currency": amount.get("currency"),
                    "amount_cents": amount.get("cents"),
                    "counterparty_did": action.get("counterparty_did"),
                }
            )
        return rows


def init(
    pg_request: Callable[..., Awaitable[Any]],
    chapter_id: str,
    *,
    offline: bool = False,
    local_log_home: str | Path | None = None,
) -> None:
    """Wire dependencies. Mirrors the pattern of other chapter modules.

    When ``offline`` is True (no Postgres configured), the Issuer Log is
    backed by a local SQLite ``LocalIssuerLog`` under ``local_log_home``
    instead of Postgres, so receipts persist and are viewable locally.
    """
    global _pg_request, _chapter_id, _offline, _local_log
    _pg_request = pg_request
    _chapter_id = chapter_id
    _offline = offline
    if offline:
        home = local_log_home or (Path.cwd() / ".org")
        _local_log = LocalIssuerLog(home)
    else:
        _local_log = None


def is_offline() -> bool:
    """True when the chapter Issuer Log is backed by local SQLite, not Postgres."""
    return _offline


async def todays_receipts_local(day_iso: str, *, limit: int = 200) -> list[dict[str, Any]]:
    """Today's receipts from the local Issuer Log (offline mode); [] if not offline."""
    if _local_log is None:
        return []
    return _local_log.todays(day_iso, limit=limit)


async def todays_rows_local(
    day_iso: str, principal_did: str | None = None, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Today's receipts as flat surface-rows from the local Issuer Log; [] if online."""
    if _local_log is None:
        return []
    return _local_log.todays_rows(day_iso, principal_did=principal_did, limit=limit)


# ── server-side issuance ──────────────────────────────────────────


async def emit_authority_grant(
    *,
    principal_did: str,
    granted_to_did: str,
    granted_scope: list[str],
    grant_expires_at: str,
    human_summary: str = "",
) -> str:
    """Emit a chapter-signed authority_granted receipt.

    Returns the new receipt's UUID on success (so the caller can pass
    it as ``granted_by_receipt_id`` on subsequent action receipts),
    empty string on failure.

    The principal grants ``granted_to_did`` the authority to take
    actions in ``granted_scope`` (e.g., ``["intent_submitted", "message_sent"]``)
    until ``grant_expires_at`` (RFC 3339).

    Strict verifiers will check this grant exists, hasn't expired, and
    covers the scope of any action that references it. See spec §4.6.

    Note: in v0.1 the chapter (acting as the principal's delegate per
    its standing authority) can emit this on the principal's behalf
    during onboarding. v0.2 will require the principal's own SDK to
    emit grants — the chapter cannot self-grant authority.
    """
    summary = human_summary or (
        f"Granted {granted_to_did[:30]}... authority for {', '.join(granted_scope[:3])} until {grant_expires_at[:10]}."
    )
    ok = await emit_chapter_action(
        principal_did=principal_did,
        category="authority_granted",
        human_summary=summary,
        machine_payload={
            "granted_scope": list(granted_scope),
            "granted_to_did": granted_to_did,
            "grant_expires_at": grant_expires_at,
        },
    )
    if not ok:
        return ""

    # Look up the just-emitted receipt to return its UUID. The server
    # persistence path doesn't return the ID directly, so fetch the
    # most-recent authority_granted receipt for this principal.
    if _pg_request is None:
        return ""
    try:
        rows = await _pg_request(
            "GET",
            "arp_receipts",
            params={
                "principal_did": f"eq.{principal_did}",
                "action_category": "eq.authority_granted",
                "order": "issued_at.desc",
                "limit": "1",
                "select": "receipt_id",
            },
        )
        if rows and isinstance(rows, list):
            return rows[0].get("receipt_id", "") or ""
    except Exception:  # noqa: BLE001
        pass
    return ""


def did_key_for_member(agent_id: str) -> str:
    """Resolve a chapter-member's did:key from their stored Ed25519 pubkey.

    The chapter's auth_verify stores each member's pubkey under
    ``auth_verify._agent_keys[agent_id]``. The did:key is derived from
    that pubkey via the standard W3C did:key derivation.

    Returns an empty string if the agent isn't found or has no Ed25519
    pubkey on file — callers should treat that as "skip receipt emission
    for this agent" rather than as an error.
    """
    try:
        import auth_verify
        import sovereign_identity

        stored = auth_verify._agent_keys.get(agent_id, {}) if hasattr(auth_verify, "_agent_keys") else {}
        pubkey = stored.get("ed25519_pubkey") or ""
        if not pubkey:
            return ""
        return sovereign_identity.build_did_key_from_ed25519(pubkey)
    except Exception:  # noqa: BLE001 — best-effort resolver
        return ""


async def resolve_member_did(agent_id: str) -> str:
    """Resolve a member's agent_id → did:key, durable across restarts.

    Fast path: the in-memory auth store (``did_key_for_member``). Fallback: the
    did persisted in ``agent_facts.provider.did`` on the agents row, so resolution
    works even when the in-memory key store has not been (re)populated for this
    agent — the failure mode that left reputation/standing surfaces empty after a
    redeploy.

    Returns "" if neither path resolves (caller treats as "no identity on file").
    """
    did = did_key_for_member(agent_id)
    if did:
        return did
    if _pg_request is None:
        return ""
    try:
        rows = await _pg_request(
            "GET",
            "agents",
            params={"agent_id": f"eq.{agent_id}", "select": "agent_facts", "limit": "1"},
        )
        facts = (rows or [{}])[0].get("agent_facts") if rows else None
        did = ((facts.get("provider") or {}).get("did") or "") if isinstance(facts, dict) else ""
        return did if did.startswith("did:key:") else ""
    except Exception:  # noqa: BLE001 — best-effort resolver
        return ""


def _utc_now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _chapter_keypair_bytes() -> tuple[bytes, str] | None:
    """Resolve the chapter's Ed25519 keypair → (sk_bytes, issuer_did).

    The chapter generates its own Ed25519 keypair at startup via
    ``sovereign_identity.generate_ed25519_keypair(AGENT_ID)``. The pair
    lives in-process at ``sovereign_identity._ed25519_keypairs[AGENT_ID]``.

    Returns None if the chapter has not been initialised yet (tests in
    isolation, etc.) so callers can fall back to silent no-op rather
    than crash.
    """
    try:
        import sovereign_identity

        kp = sovereign_identity._ed25519_keypairs.get(_chapter_id)
        if not kp:
            return None
        sk_bytes = kp.get("private_key")
        pk_bytes = kp.get("public_key")
        if not (isinstance(sk_bytes, bytes) and isinstance(pk_bytes, bytes)):
            return None
        # Derive did:key via the existing helper (re-uses the multibase /
        # multicodec convention used by every other server primitive).
        public_b64 = base64.b64encode(pk_bytes).decode()
        issuer_did = sovereign_identity.build_did_key_from_ed25519(public_b64)
        return sk_bytes, issuer_did
    except Exception:  # noqa: BLE001 — receipt emission must never raise
        return None


def _sign_receipt(sk_bytes: bytes, receipt: dict[str, Any]) -> None:
    """JCS-canonicalize the receipt sans-signature, Ed25519-sign,
    insert the base64 signature in place. Mutates the receipt."""
    body = {k: v for k, v in receipt.items() if k != "signature"}
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    sig = sk.sign(jcs.canonicalize(body))
    receipt["signature"] = base64.b64encode(sig).decode("ascii")


# ── Merkle checkpoints (reverse-audit seam; see merkle.py) ─────────────


def checkpoint_leaves(receipts: list[dict[str, Any]]) -> list[bytes]:
    """Canonical leaf bytes for the Merkle tree — JCS over the FULL receipt
    (including signature). Receipts must be passed in the committed order."""
    return [jcs.canonicalize(r) for r in receipts]


def build_checkpoint(receipts: list[dict[str, Any]], *, sk_bytes: bytes, signer_did: str) -> dict[str, Any]:
    """Sign a checkpoint committing to ``receipts`` by RFC 6962 Merkle root.

    Any holder of a receipt + its inclusion proof + this signed root can verify
    membership offline, without the rest of the log.
    """
    import merkle

    root = merkle.merkle_root(checkpoint_leaves(receipts))
    payload = {
        "version": "aae-checkpoint/0.1",
        "type": "checkpoint",
        "signer_did": signer_did,
        "created_at": _utc_now_rfc3339(),
        "tree_size": len(receipts),
        "merkle_root": "sha256:" + root.hex(),
        "receipt_ids": [r["receipt_id"] for r in receipts],
    }
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    sig = sk.sign(jcs.canonicalize(payload))
    return {
        "payload": payload,
        "signer_did": signer_did,
        "signature": base64.b64encode(sig).decode("ascii"),
    }


async def emit_chapter_action(
    *,
    principal_did: str,
    category: str,
    human_summary: str,
    counterparty_did: str | None = None,
    counterparty_label: str | None = None,
    amount: dict[str, Any] | None = None,
    machine_payload: dict[str, Any] | None = None,
    outcome: str = "completed",
    jurisdiction: dict[str, Any] | None = None,
    accessibility: dict[str, Any] | None = None,
    compliance_attestations: list[dict[str, Any]] | None = None,
    granted_by_receipt_id: str | None = None,
) -> bool:
    """Emit a chapter-signed ARP receipt for an action taken on behalf
    of ``principal_did``.

    Fire-and-forget by design: returns True if the receipt was emitted
    cleanly, False otherwise, but **never raises** into business logic.
    Telemetry / receipt-emission failures must not wedge intent matching,
    mentor invites, governance, or any other chapter action.

    The issuer is the chapter itself (issuer_did derived from the
    chapter's own Ed25519 keypair). The action category, summary, and
    structured payload come from the caller — typically the action
    handler that just ran.

    Usage::

        await arp.emit_chapter_action(
            principal_did="did:key:zMember...",
            category="commitment_entered",
            human_summary="Chapter matched your intent with Bob.",
            counterparty_did="did:key:zBob...",
            machine_payload={"intent_id": "...", "match_score": 0.87},
        )

    Authority chain: empty by design in v0.1. The chapter acts under
    "standing authority" recorded at member registration time; DAT v0.2
    will normalize that to an explicit grant.
    """
    if _pg_request is None or not principal_did or not category or not human_summary:
        return False
    keypair = _chapter_keypair_bytes()
    if keypair is None:
        return False
    sk_bytes, issuer_did = keypair

    # Truncate summary to spec §4.1 (≤280 chars). Long inputs from action
    # handlers get politely shortened rather than rejected — callers
    # don't need to know the limit.
    if len(human_summary) > 280:
        human_summary = human_summary[:277] + "..."

    action: dict[str, Any] = {
        "category": category,
        "human_summary": human_summary,
        "outcome": outcome,
    }
    if counterparty_did:
        action["counterparty_did"] = counterparty_did
    if counterparty_label:
        action["counterparty_label"] = counterparty_label
    if amount:
        action["amount"] = amount
    # Compliance-1: per-action authority chain. Optional — when present,
    # ties this action to a prior authority_granted receipt the
    # principal emitted. Strict verifiers (see spec §4.5) check the
    # chain on read. v0.1 servers MAY emit without it; v0.2 will
    # require it for certain high-stakes categories.
    if granted_by_receipt_id:
        action["granted_by_receipt_id"] = granted_by_receipt_id

    # ── A1: optional sm-locp ComplianceCredential minting ──
    # Caller passes a list of attestation specs; we mint a signed
    # W3C VC for each and embed in machine_payload. The server's
    # ARP receipt is the primary evidence; the VCs are companion
    # evidence answering "did this satisfy regulation X?". Both
    # ship in the same persisted row so the relationship is
    # preserved without a join.
    if compliance_attestations:
        try:
            import compliance as _compliance_mod

            minted: list[dict[str, Any]] = []
            for spec in compliance_attestations:
                if not isinstance(spec, dict):
                    continue
                vc = _compliance_mod.emit_compliance_attestation(
                    subject_did=spec.get("subject_did") or principal_did,
                    rule_id=spec.get("rule_id", ""),
                    status=spec.get("status", ""),
                    confidence=float(spec.get("confidence", 0.0)),
                    evaluation_state=spec.get("evaluation_state"),
                    agency=spec.get("agency", ""),
                    cfr_reference=spec.get("cfr_reference", ""),
                    ttl_seconds=spec.get("ttl_seconds"),
                )
                if vc:
                    minted.append(vc)
            if minted:
                machine_payload = dict(machine_payload or {})
                machine_payload["compliance_attestations"] = minted
        except Exception as e:  # noqa: BLE001
            # Compliance VC issuance failure must NEVER block the underlying
            # ARP receipt — the receipt is the primary evidence; the VCs
            # are augmentation. Log and continue.
            print(f"[arp] compliance VC minting failed: {e}")

    if machine_payload:
        action["machine_payload"] = machine_payload

    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": str(uuid.uuid4()),
        "issuer_did": issuer_did,
        "principal_did": principal_did,
        "issued_at": _utc_now_rfc3339(),
        "action": action,
    }
    if jurisdiction:
        receipt["jurisdiction"] = jurisdiction
    if accessibility:
        receipt["accessibility"] = accessibility

    try:
        _sign_receipt(sk_bytes, receipt)
        result = await emit(receipt)
        if not result.ok:
            # Same swallow one function over: the bool told the caller nothing
            # about WHY. Emission stays non-fatal here (it is telemetry on an
            # action path, unlike attestation which is the artifact itself), but
            # it is no longer silent.
            print(
                f"[arp][WARN] chapter-action receipt refused at the {result.stage} stage: "
                f"{result.detail}"
            )
        return result.ok
    except Exception:  # noqa: BLE001 — receipt emission must never raise
        return False


async def emit_audit_chain_snapshot(
    *,
    tip_sha256: str,
    chain_length: int,
    snapshot_at: str,
    first_occurred_at: str | None = None,
    last_occurred_at: str | None = None,
) -> dict[str, Any] | None:
    """Emit a chapter-signed Signed Tree Head over the audit chain.

    Self-attestation: issuer_did == principal_did == the chapter's own
    did:key. The chapter cryptographically commits to its chain state at
    ``snapshot_at``; anyone with the chapter's public key can verify the
    signature, then compare the claimed (tip, length) against later
    snapshots to detect chain mutation.

    Unlike ``emit_chapter_action`` (which returns ``bool`` because it's
    invoked from action handlers where receipt emission is telemetry),
    this function returns the signed receipt itself — the admin endpoint
    needs to hand it back to the caller for publication. Returns ``None``
    if the chapter has no keypair available or persistence failed.
    """
    if _pg_request is None or chain_length is None or snapshot_at is None:
        return None
    keypair = _chapter_keypair_bytes()
    if keypair is None:
        return None
    sk_bytes, issuer_did = keypair

    human_summary = f"Audit chain snapshot — {chain_length} events"
    if tip_sha256:
        human_summary += f", tip {tip_sha256[:12]}…"
    if len(human_summary) > 280:
        human_summary = human_summary[:277] + "..."

    machine_payload: dict[str, Any] = {
        "tip_sha256": tip_sha256,
        "chain_length": chain_length,
        "snapshot_at": snapshot_at,
    }
    if first_occurred_at:
        machine_payload["first_occurred_at"] = first_occurred_at
    if last_occurred_at:
        machine_payload["last_occurred_at"] = last_occurred_at

    # this said "audit.chain.snapshot", which is NOT in ARP's closed
    # category enum, so every attestation failed the schema gate and was
    # discarded silently — org self-attestation has never once succeeded on a
    # deployed org. `attestation_issued` is the spec's category for exactly this
    # (the org issues an attestation about its own chain state); the specific
    # kind stays in machine_payload, so nothing is lost and no spec change is
    # needed. The category enum is the ARP spec's, not ours to widen from here.
    machine_payload["attestation_type"] = "audit.chain.snapshot"
    action: dict[str, Any] = {
        "category": "attestation_issued",
        "human_summary": human_summary,
        "outcome": "completed",
        "machine_payload": machine_payload,
    }

    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": str(uuid.uuid4()),
        "issuer_did": issuer_did,
        "principal_did": issuer_did,  # self-attestation — STH pattern
        "issued_at": _utc_now_rfc3339(),
        "action": action,
    }

    try:
        _sign_receipt(sk_bytes, receipt)
        result = await emit(receipt)
        if not result.ok:
            # this used to `return None`, discarding the reason, and the
            # HTTP layer turned that into a 503 naming two possible causes and
            # telling you neither. The discarded reason WAS the bug: the receipt
            # failed the SCHEMA gate, and nothing said so for as long as the
            # endpoint has existed.
            print(
                f"[arp][ERROR] audit-chain attestation refused at the {result.stage} stage: "
                f"{result.detail}"
            )
            raise AttestationRefused(stage=result.stage, detail=result.detail)
        return receipt
    except AttestationRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[arp][ERROR] audit-chain attestation failed: {type(exc).__name__}: {exc}")
        raise AttestationRefused(stage="emit", detail=f"{type(exc).__name__}: {exc}") from exc


# ── helpers ────────────────────────────────────────────────────────


def _canonical_hash(obj: dict) -> str:
    """sha256: of JCS-canonical bytes of ``obj`` (no field removal)."""
    canonical = jcs.canonicalize(obj)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


async def _lookup_prior_by_chain_link(issuer_did: str, chain_link: str) -> dict | None:
    """Resolve a previous_receipt_hash → the prior receipt under the same issuer.

    The chain is per-issuer (ARP §6.4), so we MUST scope the lookup by
    issuer; otherwise two different issuers using the same chain_link
    (collision-resistant but nominally possible across issuers) would
    cross-link.
    """
    if _pg_request is None:
        return None
    rows = await _pg_request(
        "GET",
        "arp_receipts",
        params={
            "issuer_did": f"eq.{issuer_did}",
            "chain_link": f"eq.{chain_link}",
            "select": "receipt_json",
            "limit": "1",
        },
    )
    if not rows:
        return None
    row = rows[0] if isinstance(rows, list) else rows
    return row.get("receipt_json")


# ── public API ────────────────────────────────────────────────────


class AttestationRefused(RuntimeError):
    """An attestation could not be persisted, WITH the reason attached.

    Exists so the HTTP layer can report what actually happened. A refusal that
    names two possible causes and tells you neither is worse than a bare 500,
    because it looks diagnostic.
    """

    def __init__(self, *, stage: str, detail: str) -> None:
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


async def emit(
    receipt: dict,
    *,
    require_principal_match: str | None = None,
) -> VerificationResult:
    """Verify and persist one receipt.

    Returns a :class:`VerificationResult`. On ``ok=True`` the receipt has
    been validated, signature-verified, hash-chain-checked (when applicable),
    and written to the Issuer Log. On ``ok=False`` nothing is written.

    ``require_principal_match`` — when set, the receipt's ``principal_did``
    MUST equal this value. Used by the HTTP layer to enforce that an
    authenticated principal cannot publish receipts attributing actions
    to a *different* principal.
    """
    # 1. Schema + signature gate (no DB hit yet).
    chain_priors: dict[str, dict] = {}
    prev = receipt.get("previous_receipt_hash")
    if prev:
        prior = await _lookup_prior_by_chain_link(receipt.get("issuer_did", ""), prev)
        if prior is not None:
            chain_priors[prev] = prior

    # Tolerant chain ingest for foreign issuers (spec/arp/0.2 §0.6). The per-issuer
    # hash chain is the ISSUER's invariant over the ISSUER's authoritative log.
    # Schema + signature are ALWAYS strict. For the chain: we strict-verify
    # continuity for our OWN receipts (we hold the full chain) and for any receipt
    # whose prior we already hold; a foreign (member-issued) receipt whose prior we
    # do NOT hold is accepted rather than rejected — our Issuer Log is only a
    # partial replica of that member's chain, so it is not the authority on its
    # completeness (proven instead via the member's log or a Merkle checkpoint).
    own_did = ""
    keypair = _chapter_keypair_bytes()
    if keypair is not None:
        own_did = keypair[1]
    chain_mode = "strict" if receipt.get("issuer_did") == own_did else "tolerant"

    result = verify_receipt(receipt, mode=chain_mode, prior_receipts=chain_priors)
    if not result.ok:
        return result

    if require_principal_match is not None:
        if receipt.get("principal_did") != require_principal_match:
            return VerificationResult(
                False,
                "schema",
                "principal_did does not match authenticated principal",
            )

    # Idempotency: a re-submitted (issuer_did, receipt_id) is a duplicate,
    # NOT a persistence failure. Detect it explicitly and return a distinct
    # ``duplicate`` stage so the HTTP layer answers 409 (idempotent) instead of
    # conflating it with a real DB outage (503). Signature is already verified,
    # so this only fires for genuinely-owned re-submits.
    if not _offline and _pg_request is not None:
        existing = await _pg_request(
            "GET",
            "arp_receipts",
            params={
                "issuer_did": f"eq.{receipt.get('issuer_did', '')}",
                "receipt_id": f"eq.{receipt.get('receipt_id', '')}",
                "select": "receipt_id",
                "limit": 1,
            },
        )
        if existing:
            return VerificationResult(False, "duplicate", "receipt already recorded (idempotent re-submit)")

    # 2. Compute the chain link this receipt produces (= sha256 over the
    # full canonical bytes INCLUDING signature). The NEXT receipt's
    # previous_receipt_hash MUST equal this value.
    chain_link = compute_chain_link(receipt)

    # 3. Persist.
    if _pg_request is None and not _offline:
        return VerificationResult(False, "schema", "arp module not initialised — pg_request missing")

    action = receipt["action"]
    amount = action.get("amount") or {}
    row = {
        "receipt_id": receipt["receipt_id"],
        "issuer_did": receipt["issuer_did"],
        "principal_did": receipt["principal_did"],
        "issued_at": receipt["issued_at"],
        "arp_version": receipt["version"],
        "action_category": action["category"],
        "action_outcome": action["outcome"],
        "human_summary": action["human_summary"],
        "amount_currency": amount.get("currency"),
        "amount_cents": amount.get("cents"),
        "counterparty_did": action.get("counterparty_did"),
        "previous_receipt_hash": prev,
        "chain_link": chain_link,
        "receipt_json": receipt,
    }

    # Offline mode: persist to the local SQLite Issuer Log instead of Postgres.
    if _offline:
        if _local_log is None:
            return VerificationResult(False, "schema", "offline mode but local Issuer Log missing")
        _local_log.persist(row)
        return VerificationResult.accepted()

    persisted = await _pg_request("POST", "arp_receipts", body=row)  # type: ignore[misc]
    if persisted is None:
        # ``pg_request`` returns None on outage OR a 4xx/5xx (e.g. the
        # arp_receipts table missing). We've already signature-verified the
        # receipt; the caller decides whether to surface as a 5xx or accept
        # (degraded mode). LOUDLY log it — a silent drop here is exactly how a
        # missing-table/outage can starve the Issuer Log for weeks unnoticed.
        _logger.warning(
            "ARP receipt verified but NOT persisted (pg_request returned None) — "
            "receipt_id=%s issuer=%s principal=%s category=%s. Check the arp_receipts "
            "table exists and the service role can insert.",
            row.get("receipt_id"),
            (row.get("issuer_did") or "")[:24],
            (row.get("principal_did") or "")[:24],
            row.get("action_category"),
        )
        return VerificationResult(False, "accepted", "verified but persistence failed")

    return VerificationResult.accepted()


async def list_for_principal(principal_did: str, *, limit: int = 100) -> list[dict]:
    """Return receipts where the principal_did matches, newest first.

    Used by ``GET /api/receipts`` after auth has confirmed the caller IS
    the principal in question. The HTTP layer MUST NOT call this without
    first verifying the request signature against ``principal_did``.
    """
    if _offline:
        return _local_log.list_for_principal(principal_did, limit=limit) if _local_log else []
    if _pg_request is None:
        return []
    rows = await _pg_request(
        "GET",
        "arp_receipts",
        params={
            "principal_did": f"eq.{principal_did}",
            "select": "receipt_json,issued_at,chain_link",
            "order": "issued_at.desc",
            "limit": str(limit),
        },
    )
    if not rows:
        return []
    return [row["receipt_json"] for row in rows]


async def list_principals_with_receipts(*, scan_limit: int = 1000, limit: int = 200) -> list[str]:
    """Distinct ``principal_did``s that have at least one receipt in the Issuer
    Log, most-recently-active first.

    The reputation leaderboard ranks by corroborated standing, which only the
    receipt-bearing principals have — a member with zero receipts has nothing to
    rank, and a principal with receipts may not be in the chapter's in-memory
    member roster at all (e.g. a freshly-registered sovereign agent). So the
    board is built from this list, not the roster.

    ``scan_limit`` bounds how many recent receipts we read to derive the distinct
    set; ``limit`` caps the returned principal count.
    """
    seen: set[str] = set()
    ordered: list[str] = []

    def _add(did: str | None) -> None:
        if did and did not in seen:
            seen.add(did)
            ordered.append(did)

    if _offline:
        if _local_log is None:
            return []
        for r in _local_log.list_recent(limit=scan_limit):
            _add(r.get("principal_did"))
        return ordered[:limit]

    if _pg_request is None:
        return []
    rows = await _pg_request(
        "GET",
        "arp_receipts",
        params={"select": "principal_did", "order": "issued_at.desc", "limit": str(scan_limit)},
    )
    for r in rows or []:
        _add(r.get("principal_did"))
    return ordered[:limit]


async def get_receipt(issuer_did: str, receipt_id: str) -> dict | None:
    """Fetch a single receipt by its issuer + receipt_id composite key."""
    if _pg_request is None:
        return None
    rows = await _pg_request(
        "GET",
        "arp_receipts",
        params={
            "issuer_did": f"eq.{issuer_did}",
            "receipt_id": f"eq.{receipt_id}",
            "select": "receipt_json",
            "limit": "1",
        },
    )
    if not rows:
        return None
    row = rows[0] if isinstance(rows, list) else rows
    return row.get("receipt_json")


__all__ = [
    "init",
    "emit",
    "emit_chapter_action",
    "did_key_for_member",
    "resolve_member_did",
    "list_for_principal",
    "list_principals_with_receipts",
    "get_receipt",
]
