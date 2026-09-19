"""ARP v0.1 — sovereign member-side issuer + Agency Log.

This module is the member-sdk's side of the Agency Receipt Protocol
(see ``spec/arp/0.1/spec.md``). The sovereign member:

* **issues** receipts when its agent takes an action (it is the
  ``issuer_did``).
* **owns** the Agency Log — the principal-controlled store. Because in
  the sovereign-SDK case the principal IS the same human who runs the
  agent, the Agency Log lives locally under ``$COMMUNITY_MEMBER_HOME``.
* optionally **pushes** the same receipt to a chapter's Issuer Log over
  HTTP (``POST /api/receipts``).

Public surface::

    build_receipt(*, action_dict, principal_did=..., issuer_did=...,
                  issued_at=..., ...) -> dict
    sign_receipt(receipt, private_key_bytes) -> dict
    canonical_bytes_for_signing(receipt) -> bytes
    AgencyLog(home).append(receipt) / list_recent / get(receipt_id)
    emit(action_dict, sk_bytes, *, chapter_url=None, push=True) -> dict

The module is intentionally framework-light: no NANDA-chapter imports,
no Postgres, no portal. Any sovereign Python runtime can import and use
it. The chapter-side counterpart lives at ``chapter/arp.py`` and shares
the same canonicalization + signature verification path via
``conformance/arp/``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._arp_verify import VerificationResult
from ._arp_verify import verify_receipt as _strict_verify_receipt

ARP_VERSION = "arp/0.1"


# ── crypto helpers ─────────────────────────────────────────────────


def _did_from_pubkey(pk_bytes: bytes) -> str:
    """W3C did:key — multibase z-base58btc over multicodec 0xed01 ‖ pubkey32."""
    import base58  # type: ignore[import-not-found]

    prefixed = b"\xed\x01" + pk_bytes
    return "did:key:z" + base58.b58encode(prefixed).decode("ascii")


def did_from_private_key(sk_bytes: bytes) -> str:
    """Build the issuer did:key from a 32-byte Ed25519 private key seed."""
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _did_from_pubkey(pk)


def canonical_bytes_for_signing(receipt: dict) -> bytes:
    """JCS-canonical bytes of receipt sans ``signature`` field.

    This is exactly what gets signed (§6.1). Re-canonicalization on the
    verifier side must produce the same bytes; that's RFC 8785's
    guarantee, hence the use of the ``jcs`` library rather than Python's
    json.dumps.
    """
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return jcs.canonicalize(body)


# ── receipt construction + signing ─────────────────────────────────


def _utc_now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_receipt(
    *,
    action: dict,
    issuer_did: str,
    principal_did: str,
    receipt_id: str | None = None,
    issued_at: str | None = None,
    authority_chain: list[str] | None = None,
    evidence: dict | None = None,
    previous_receipt_hash: str | None = None,
    jurisdiction: dict | None = None,
    accessibility: dict | None = None,
    extensions: dict | None = None,
) -> dict:
    """Build a receipt dict ready for signing.

    Every field is validated against the schema later; this helper just
    assembles the envelope so the caller doesn't have to remember the
    field names.
    """
    receipt: dict[str, Any] = {
        "version": ARP_VERSION,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "issuer_did": issuer_did,
        "principal_did": principal_did,
        "issued_at": issued_at or _utc_now_rfc3339(),
        "action": action,
    }
    if authority_chain is not None:
        receipt["authority_chain"] = authority_chain
    if evidence is not None:
        receipt["evidence"] = evidence
    if previous_receipt_hash is not None:
        receipt["previous_receipt_hash"] = previous_receipt_hash
    if jurisdiction is not None:
        receipt["jurisdiction"] = jurisdiction
    if accessibility is not None:
        receipt["accessibility"] = accessibility
    if extensions is not None:
        receipt["extensions"] = extensions
    return receipt


def sign_receipt(receipt: dict, sk_bytes: bytes) -> dict:
    """Sign the receipt in-place with the given 32-byte Ed25519 seed.

    Returns the same dict with a ``signature`` field added.
    """
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    canonical = canonical_bytes_for_signing(receipt)
    sig = sk.sign(canonical)
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


def verify_receipt(
    receipt: dict,
    *,
    mode: str = "strict",
    prior_receipts: dict[str, dict] | None = None,
) -> VerificationResult:
    """Strict-verify ANY receipt — schema + signature + hash chain.

    This is the member's half of peer-symmetric verification. Unlike
    :func:`verify_receipt_signature` (signature only), this runs the SAME
    canonical pipeline the chapter runs on ingest, so a member can
    independently decide whether a *counterparty's* receipt is valid
    instead of trusting its chapter to vouch for it.

    Delegates to the vendored canonical verifier (``_arp_verify``), which
    is kept byte-for-byte in lockstep with ``conformance/arp`` — the
    single source of verification truth. See spec §6.

    ``mode`` / ``prior_receipts`` are passed straight through; in
    ``strict`` mode a ``previous_receipt_hash`` with no matching prior is
    a ``hash_chain`` failure (the chain claim can't be evaluated).
    """
    return _strict_verify_receipt(receipt, mode=mode, prior_receipts=prior_receipts)


def verify_receipt_signature(receipt: dict) -> bool:
    """Return True iff the receipt's signature verifies under its issuer_did.

    Mirrors the chapter-side check; useful for local sanity testing
    before pushing to the chapter. For full verification (schema + chain),
    prefer :func:`verify_receipt`.
    """
    sig_b64 = receipt.get("signature", "")
    issuer_did = receipt.get("issuer_did", "")
    if not sig_b64 or not issuer_did:
        return False
    if not issuer_did.startswith("did:key:z"):
        return False
    import base58  # type: ignore[import-not-found]

    decoded = base58.b58decode(issuer_did[len("did:key:z") :])
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        return False
    pk = Ed25519PublicKey.from_public_bytes(decoded[2:])
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    if len(sig_bytes) != 64:
        return False
    try:
        pk.verify(sig_bytes, canonical_bytes_for_signing(receipt))
    except Exception:
        return False
    return True


def receipt_chain_link(receipt: dict) -> str:
    """sha256: of canonical-bytes-INCLUDING-signature.

    The value the NEXT receipt's ``previous_receipt_hash`` MUST equal.
    """
    canonical = jcs.canonicalize(receipt)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# ── Agency Log (local, principal-controlled) ───────────────────────


#: Identifies THIS process's in-flight action attempts. An attempt row that is
#: still ``pending`` and carries a different token was begun by a process that
#: no longer exists — it died between the external call and the receipt write —
#: and its outcome is UNKNOWN. Generated once per import, never persisted
#: anywhere but on the rows it stamps.
_PROCESS_TOKEN = uuid.uuid4().hex

#: Attempt states. ``pending`` is written BEFORE the external call; exactly one
#: of the other three replaces it afterwards. ``unknown`` is the honest state
#: for a timeout after the request left, a non-2xx after the counterparty may
#: have acted, and any attempt orphaned by a process death.
ATTEMPT_STATES = frozenset({"pending", "succeeded", "failed", "unknown"})


class DuplicateActionError(RuntimeError):
    """A new attempt was begun for an ``action_ref`` whose last attempt already
    succeeded or is unresolved. Retrying it would perform the action again.

    Raised BEFORE the external call, so the refusal has no side effect."""

    def __init__(self, action_ref: str, attempt: dict) -> None:
        super().__init__(
            f"action_ref {action_ref!r} already has an attempt in state {attempt['state']!r} "
            f"(attempt {attempt['attempt_id']}); a retry would perform it again. "
            f"Resolve the earlier attempt first."
        )
        self.action_ref = action_ref
        self.attempt = attempt


@dataclass
class AgencyLog:
    """Local SQLite-backed Agency Log under the member's config dir.

    The Agency Log is the principal-controlled store of their own
    receipts (spec §10.1). It is never pushed to a remote service by
    this module; if the same agent ALSO writes to a chapter's Issuer
    Log, that is a separate call (see :func:`emit`).

    ATTEMPTS, NOT ONLY RECEIPTS. A receipt attests an action that happened, and
    it is written after the action; anything that dies between the two — a kill,
    a raise in the co-sign fetch, an unwritable log — used to leave an action
    that happened with no trace at all. ``begin_action`` writes a ``pending``
    attempt BEFORE the external call and ``finalize_action`` resolves it after,
    so the log always holds at least the fact that the action was attempted.
    A ``pending`` row stamped by a process that no longer exists is an action
    whose outcome nobody observed: ``reconcile_orphans`` marks it ``unknown``
    durably, and nothing here retries it.

    Attempts are local log state. The wire receipt is unchanged: a receipt is
    still emitted only for an observed success, and an attempt that did not
    succeed produces no receipt rather than a receipt claiming less.
    """

    home: Path

    def __post_init__(self) -> None:
        self.home = Path(self.home).expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / "agency-log.sqlite"
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id     TEXT PRIMARY KEY,
                    issuer_did     TEXT NOT NULL,
                    principal_did  TEXT NOT NULL,
                    issued_at      TEXT NOT NULL,
                    category       TEXT NOT NULL,
                    summary        TEXT NOT NULL,
                    receipt_json   TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_receipts_issued ON receipts (issued_at DESC)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS action_attempts (
                    attempt_id         TEXT PRIMARY KEY,
                    action_ref         TEXT,
                    issuer_did         TEXT NOT NULL,
                    category           TEXT NOT NULL,
                    summary            TEXT NOT NULL,
                    counterparty_did   TEXT,
                    counterparty_label TEXT,
                    state              TEXT NOT NULL,
                    started_at         TEXT NOT NULL,
                    finalized_at       TEXT,
                    receipt_id         TEXT,
                    process_token      TEXT NOT NULL,
                    detail_json        TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_attempts_ref ON action_attempts (action_ref)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_attempts_state ON action_attempts (state)")

    # ── write-ahead attempts ───────────────────────────────────────

    def begin_action(
        self,
        *,
        issuer_did: str,
        category: str,
        summary: str,
        counterparty_did: str | None = None,
        counterparty_label: str | None = None,
        action_ref: str | None = None,
        detail: dict | None = None,
    ) -> str:
        """Durably record that an action is ABOUT to be attempted. Returns the
        attempt id the caller finalizes afterwards.

        Must be called before the external call, and must be allowed to raise:
        a log that cannot record the attempt cannot record the receipt either,
        and the right time to find that out is before the action, not after.

        ``action_ref`` is the caller's idempotency key for the action (an A2A
        task id, a booking id). When given, a new attempt is REFUSED while the
        latest attempt for that ref is ``succeeded``, ``unknown`` or still
        ``pending``: a retry of any of those would perform the action a second
        time, and a retry after an unknown outcome is a human's decision, not
        the runtime's. A ``failed`` attempt may be retried; the new row links
        to the same ref so one action never yields two receipts.
        """
        if action_ref is not None:
            latest = self.latest_attempt(action_ref)
            if latest is not None and latest["state"] != "failed":
                raise DuplicateActionError(action_ref, latest)
        attempt_id = str(uuid.uuid4())
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO action_attempts
                  (attempt_id, action_ref, issuer_did, category, summary,
                   counterparty_did, counterparty_label, state, started_at,
                   finalized_at, receipt_id, process_token, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, ?, ?)
                """,
                (
                    attempt_id,
                    action_ref,
                    issuer_did,
                    category,
                    summary,
                    counterparty_did,
                    counterparty_label,
                    _utc_now_rfc3339(),
                    _PROCESS_TOKEN,
                    json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                ),
            )
        return attempt_id

    def finalize_action(
        self,
        attempt_id: str,
        state: str,
        *,
        receipt_id: str | None = None,
        detail: dict | None = None,
    ) -> None:
        """Resolve a pending attempt to ``succeeded`` / ``failed`` / ``unknown``.

        ``receipt_id`` links the attempt to the receipt that attests it; a
        ``succeeded`` attempt with no receipt is one whose receipt stage failed
        after the action was observed — listed by :meth:`unresolved_actions`
        because a receipt is still owed. Extra ``detail`` keys are merged over
        the ones recorded at ``begin_action``.
        """
        if state not in ATTEMPT_STATES or state == "pending":
            raise ValueError(f"state must be one of succeeded/failed/unknown, got {state!r}")
        with self._conn() as c:
            row = c.execute("SELECT detail_json FROM action_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise KeyError(f"no attempt {attempt_id!r}")
            merged = json.loads(row["detail_json"])
            merged.update(detail or {})
            c.execute(
                """
                UPDATE action_attempts
                   SET state = ?, finalized_at = ?, receipt_id = ?, detail_json = ?
                 WHERE attempt_id = ?
                """,
                (
                    state,
                    _utc_now_rfc3339(),
                    receipt_id,
                    json.dumps(merged, ensure_ascii=False, sort_keys=True),
                    attempt_id,
                ),
            )

    @staticmethod
    def _attempt_row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["detail"] = json.loads(d.pop("detail_json"))
        return d

    def get_attempt(self, attempt_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM action_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
        return self._attempt_row(row) if row else None

    def latest_attempt(self, action_ref: str) -> dict | None:
        """The most recently begun attempt for ``action_ref`` (by insertion order)."""
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM action_attempts WHERE action_ref = ? ORDER BY rowid DESC LIMIT 1",
                (action_ref,),
            ).fetchone()
        return self._attempt_row(row) if row else None

    def list_attempts(self, *, action_ref: str | None = None, state: str | None = None, limit: int = 100) -> list[dict]:
        query = "SELECT * FROM action_attempts"
        clauses: list[str] = []
        args: list[Any] = []
        if action_ref is not None:
            clauses.append("action_ref = ?")
            args.append(action_ref)
        if state is not None:
            clauses.append("state = ?")
            args.append(state)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY rowid DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(query, tuple(args)).fetchall()
        return [self._attempt_row(r) for r in rows]

    def orphaned_actions(self) -> list[dict]:
        """``pending`` attempts begun by a process other than this one.

        Their process is gone and nothing will finalize them: each is an action
        that may or may not have happened. Read-only; :meth:`reconcile_orphans`
        is what durably records that verdict.
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM action_attempts WHERE state = 'pending' AND process_token != ? ORDER BY rowid",
                (_PROCESS_TOKEN,),
            ).fetchall()
        return [self._attempt_row(r) for r in rows]

    def reconcile_orphans(self) -> list[dict]:
        """Mark every orphaned attempt ``unknown`` and return them.

        Called at process start. The rows are NOT retried and NOT deleted: an
        action nobody observed the outcome of stays in the log as exactly that,
        for a human to resolve against the counterparty.
        """
        orphans = self.orphaned_actions()
        for a in orphans:
            self.finalize_action(
                a["attempt_id"],
                "unknown",
                detail={"unknown_reason": "process_died_before_finalize", "orphaned_process_token": a["process_token"]},
            )
        return [self.get_attempt(a["attempt_id"]) or a for a in orphans]

    def unresolved_actions(self, *, limit: int = 100) -> list[dict]:
        """Attempts a human still has to look at: ``unknown`` outcomes, orphaned
        ``pending`` rows not yet reconciled, and ``succeeded`` attempts whose
        receipt was never written (a receipt is owed for an observed action)."""
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT * FROM action_attempts
                 WHERE state = 'unknown'
                    OR (state = 'pending' AND process_token != ?)
                    OR (state = 'succeeded' AND receipt_id IS NULL)
                 ORDER BY rowid DESC LIMIT ?
                """,
                (_PROCESS_TOKEN, limit),
            ).fetchall()
        return [self._attempt_row(r) for r in rows]

    def append(self, receipt: dict) -> None:
        """Persist a receipt. Idempotent on ``receipt_id``."""
        with self._conn() as c:
            c.execute(
                """
                INSERT OR IGNORE INTO receipts
                  (receipt_id, issuer_did, principal_did, issued_at,
                   category, summary, receipt_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt["receipt_id"],
                    receipt["issuer_did"],
                    receipt["principal_did"],
                    receipt["issued_at"],
                    receipt["action"]["category"],
                    receipt["action"]["human_summary"],
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )

    def list_recent(self, *, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT receipt_json FROM receipts ORDER BY issued_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    def get(self, receipt_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return json.loads(row["receipt_json"]) if row else None

    def count(self) -> int:
        with self._conn() as c:
            row = c.execute("SELECT COUNT(*) as n FROM receipts").fetchone()
        return int(row["n"])

    def tip(self, *, issuer_did: str | None = None) -> str | None:
        """Chain link of the most-recently-appended receipt, or None if empty.

        The return value is exactly what the NEXT receipt's
        ``previous_receipt_hash`` must be to extend the chain. "Most recent"
        is by insertion order (SQLite ``rowid``), not ``issued_at`` — robust
        against same-second timestamp collisions.

        The ARP hash chain is per-issuer (spec §6.4), so pass ``issuer_did``
        to get the tip of a single issuer's sub-chain. Without it, the tip is
        the latest receipt regardless of issuer (correct only when the log
        holds a single issuer's receipts, the sovereign-SDK common case).
        """
        query = "SELECT receipt_json FROM receipts"
        args: tuple[Any, ...] = ()
        if issuer_did is not None:
            query += " WHERE issuer_did = ?"
            args = (issuer_did,)
        query += " ORDER BY rowid DESC LIMIT 1"
        with self._conn() as c:
            row = c.execute(query, args).fetchone()
        if row is None:
            return None
        return receipt_chain_link(json.loads(row["receipt_json"]))


# ── high-level emit ────────────────────────────────────────────────


def emit(
    action: dict,
    sk_bytes: bytes,
    *,
    agency_log: AgencyLog | None = None,
    principal_did: str | None = None,
    chapter_url: str | None = None,
    push: bool = True,
    issued_at: str | None = None,
    **envelope_extras: object,
) -> dict:
    """Build, sign, persist locally, optionally push to a chapter.

    Returns the signed receipt dict. On chapter-push failure the local
    write succeeds (the principal's Agency Log is authoritative); the
    caller can re-push later if needed.

    ``principal_did`` defaults to the issuer's own did:key — the
    sovereign-SDK common case where the agent acts on behalf of the
    human who owns it.

    Optional envelope fields (jurisdiction, accessibility, evidence,
    authority_chain, extensions, previous_receipt_hash, receipt_id)
    flow through via ``**envelope_extras``.
    """
    issuer_did = did_from_private_key(sk_bytes)
    principal_did = principal_did or issuer_did

    receipt = build_receipt(
        action=action,
        issuer_did=issuer_did,
        principal_did=principal_did,
        issued_at=issued_at,
        **envelope_extras,  # type: ignore[arg-type]
    )
    sign_receipt(receipt, sk_bytes)

    if agency_log is not None:
        agency_log.append(receipt)

    if push and chapter_url:
        _push_to_chapter(receipt, chapter_url)

    return receipt


def emit_authority_grant(
    *,
    sk_bytes: bytes,
    granted_to_did: str,
    granted_scope: list[str],
    grant_expires_at: str,
    human_summary: str = "",
    agency_log: AgencyLog | None = None,
    chapter_url: str | None = None,
    push: bool = True,
) -> dict:
    """Emit an authority_granted receipt — the principal grants an
    agent (``granted_to_did``) explicit authority for a set of action
    categories (``granted_scope``) until ``grant_expires_at`` (RFC 3339).

    Returns the signed receipt dict; the caller uses
    ``receipt["receipt_id"]`` as ``action.granted_by_receipt_id`` on
    subsequent action receipts to chain them to this grant.

    The principal is always the issuer (the sovereign SDK case — only
    the principal can authorize their own agent). Strict verifiers
    enforce this rule on read.

    See spec §4.6 for the authority-chain model.
    """
    summary = human_summary or (
        f"Granted {granted_to_did[:30]}... authority for {', '.join(granted_scope[:3])} until {grant_expires_at[:10]}."
    )
    if len(summary) > 280:
        summary = summary[:277] + "..."

    action = {
        "category": "authority_granted",
        "human_summary": summary,
        "outcome": "completed",
        "machine_payload": {
            "granted_scope": list(granted_scope),
            "granted_to_did": granted_to_did,
            "grant_expires_at": grant_expires_at,
        },
    }
    return emit(
        action=action,
        sk_bytes=sk_bytes,
        agency_log=agency_log,
        chapter_url=chapter_url,
        push=push,
    )


def emit_authority_revocation(
    *,
    sk_bytes: bytes,
    revokes_receipt_id: str,
    reason: str = "",
    agency_log: AgencyLog | None = None,
    chapter_url: str | None = None,
    push: bool = True,
) -> dict:
    """Revoke a previously-issued authority_granted receipt.

    After this is persisted, any action receipt referencing the
    revoked grant via ``action.granted_by_receipt_id`` fails strict
    verification per spec §4.5 step 6.

    Only the original grant's principal may revoke it. Strict verifiers
    enforce this on read.
    """
    summary = f"Revoked grant {revokes_receipt_id[:8]}..."
    if reason:
        summary += f" ({reason[:200]})"
    if len(summary) > 280:
        summary = summary[:277] + "..."

    action = {
        "category": "authority_revoked",
        "human_summary": summary,
        "outcome": "completed",
        "machine_payload": {
            "revokes_receipt_id": revokes_receipt_id,
        },
    }
    return emit(
        action=action,
        sk_bytes=sk_bytes,
        agency_log=agency_log,
        chapter_url=chapter_url,
        push=push,
    )


def _push_to_chapter(receipt: dict, chapter_url: str) -> None:
    """POST the receipt to a chapter's /api/receipts endpoint.

    Best-effort: a network failure here MUST NOT prevent the local
    Agency Log write from succeeding (the local write happened before
    this call in :func:`emit`). If the chapter rejects the receipt
    (HTTP 400), the function logs and returns — the local copy is the
    authoritative principal-side record regardless.

    Note: this helper deliberately uses ``urllib.request`` rather than
    httpx to keep the runtime dependency surface small. Operational
    deployments will typically replace this with the SDK's existing
    HTTP client for connection pooling and retry policy.
    """
    import urllib.error
    import urllib.request

    body = json.dumps(receipt).encode()
    url = chapter_url.rstrip("/") + "/api/receipts"
    if not (url.startswith("http://") or url.startswith("https://")):
        # Defensive: refuse any non-HTTP(S) scheme to keep urllib from
        # walking into ``file:`` / ``ftp:`` / custom-scheme territory.
        raise ValueError(f"chapter_url must be http(s); got {url!r}")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as _:
            pass
    except urllib.error.HTTPError as e:
        # Body unreadable for many subclasses; best-effort
        try:
            detail = e.read()[:200].decode("utf-8", "replace")
        except Exception:
            detail = ""
        print(f"[arp.emit] chapter push failed http={e.code}: {detail}")
    except Exception as e:
        print(f"[arp.emit] chapter push failed: {type(e).__name__}: {e}")


__all__ = [
    "ARP_VERSION",
    "AgencyLog",
    "VerificationResult",
    "build_receipt",
    "canonical_bytes_for_signing",
    "did_from_private_key",
    "emit",
    "receipt_chain_link",
    "sign_receipt",
    "verify_receipt",
    "verify_receipt_signature",
]
