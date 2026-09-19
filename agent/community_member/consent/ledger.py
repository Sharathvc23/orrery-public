"""Local hash-chained append-only audit ledger.

Every row forms a hash chain with the row before it: `event_sha256` is
sha256 of the canonical serialization of (chapter_id, actor_agent_id,
action, target_type, target_id, outcome, detail, occurred_at,
prev_sha256). Any mutation to a prior row is detected by `verify_chain()`
which re-derives the chain top-to-bottom and fails loud on the first
mismatch.

When an Ed25519 signing key is provided to `init()`, every row is also
signed — so tampering requires not just hash consistency but also a valid
signature from the agent's private key.

Design mirrors chapter-runtime/chapter_audit.py so a chapter auditor can
re-derive a device-exported ledger with the same `canonical_event()`
serialization. The two files use identical JSON keys, sorted-key ordering,
and separator bytes for this reason — do not diverge lightly.

Thread-safety: a single `threading.Lock` serializes `record()` calls so
simultaneous threads chaining to the same `prev_sha256` are impossible.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_db_path: Path | None = None
_signing_key_b64: str | None = None
_write_lock = threading.Lock()

MAX_DETAIL_BYTES = 32 * 1024
MAX_ACTION_LEN = 64
VALID_OUTCOMES = frozenset({"ok", "fail", "denied", "deferred"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS consent_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    chapter_id      TEXT NOT NULL,
    actor_agent_id  TEXT,
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    outcome         TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '{}',
    occurred_at     TEXT NOT NULL,
    prev_sha256     TEXT,
    event_sha256    TEXT NOT NULL UNIQUE,
    signature_b64   TEXT
);
CREATE INDEX IF NOT EXISTS idx_consent_events_occurred
    ON consent_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_consent_events_action
    ON consent_events(action);
"""


def init(db_path: str | Path, signing_key_b64: str | None = None) -> None:
    """Configure the ledger. Creates the SQLite schema if missing.

    Args:
        db_path: Filesystem location for the ledger (typically
            `~/.community-member/consent.db`).
        signing_key_b64: Optional Ed25519 private key (base64). When
            present every recorded row is Ed25519-signed.

    Never silently downgrades a signed ledger to unsigned: once a signing key
    has been configured, a later ``init()`` that omits one KEEPS it (G4 —
    otherwise a legacy call site that inits without the key would strand the
    tamper-evidence, and ``verify_chain`` would skip the unsigned rows). A
    no-key init on a fresh process still yields an unsigned ledger. Use
    ``_reset_for_tests()`` to deliberately clear the key.
    """
    global _db_path, _signing_key_b64
    _db_path = Path(db_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    if signing_key_b64 is not None:
        _signing_key_b64 = signing_key_b64
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.commit()
    # sm-aae envelope emission rides the same configuration (same signing key,
    # same directory) so every init call site wires the consent gate's
    # authorization envelopes for free — see consent/aae_emit.py.
    from community_member.consent import aae_emit

    aae_emit.configure(_db_path.parent / "aae.db", signing_key_b64=_signing_key_b64)


def _connect() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("consent.ledger not initialized — call init(db_path) first")
    conn = sqlite3.connect(str(_db_path), isolation_level=None, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


# ── Pure: canonical serialization + hash ─────────────────────────────


def canonical_event(event: dict) -> str:
    """Deterministic JSON serialization for hashing.

    Fields, ordering, and whitespace match chapter-runtime/chapter_audit.py
    exactly — a cross-repo audit MUST produce identical sha256s.
    """
    minimal = {
        "chapter_id": event.get("chapter_id"),
        "actor_agent_id": event.get("actor_agent_id"),
        "action": event.get("action"),
        "target_type": event.get("target_type"),
        "target_id": event.get("target_id"),
        "outcome": event.get("outcome"),
        "detail": event.get("detail") or {},
        "occurred_at": event.get("occurred_at"),
        "prev_sha256": event.get("prev_sha256") or "",
    }
    return json.dumps(minimal, sort_keys=True, separators=(",", ":"))


def sha256_of(event: dict) -> str:
    return hashlib.sha256(canonical_event(event).encode("utf-8")).hexdigest()


def _sign(message: str) -> str | None:
    """Ed25519-sign `message` with the configured key. Returns base64 or None."""
    if _signing_key_b64 is None:
        return None
    try:
        from nacl.signing import SigningKey
    except ImportError as e:
        raise RuntimeError(
            "consent.ledger was initialized with a signing key but pynacl is not "
            "installed. It is a core dependency, so this install is incomplete: "
            "pip install -e . from the agent/ directory."
        ) from e
    sk = SigningKey(base64.b64decode(_signing_key_b64))
    return base64.b64encode(sk.sign(message.encode("utf-8")).signature).decode("ascii")


# ── Validation ───────────────────────────────────────────────────────


def _validate(action: str, outcome: str, detail: dict) -> tuple[bool, str]:
    if not action or not isinstance(action, str):
        return False, "action is required"
    if len(action) > MAX_ACTION_LEN:
        return False, f"action too long (max {MAX_ACTION_LEN})"
    if outcome not in VALID_OUTCOMES:
        return False, f"outcome must be one of {sorted(VALID_OUTCOMES)}"
    if not isinstance(detail, dict):
        return False, "detail must be a dict"
    if len(json.dumps(detail).encode("utf-8")) > MAX_DETAIL_BYTES:
        return False, f"detail too large (max {MAX_DETAIL_BYTES} bytes)"
    return True, "ok"


# ── Append ───────────────────────────────────────────────────────────


def record(
    chapter_id: str,
    action: str,
    *,
    actor_agent_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "ok",
    detail: dict | None = None,
    occurred_at: str | None = None,
) -> dict:
    """Append one event. Returns the persisted row including event_sha256.

    `occurred_at` defaults to now(UTC); accept an explicit value only so
    tests can force deterministic timestamps. Real callers should not pass it.

    Raises ValueError on validation failure; RuntimeError if init() wasn't
    called; sqlite3 errors propagate if the row cannot be written.
    """
    detail = detail or {}
    ok, reason = _validate(action, outcome, detail)
    if not ok:
        raise ValueError(reason)

    with _write_lock, _connect() as conn:
        row = conn.execute("SELECT event_sha256 FROM consent_events ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row["event_sha256"] if row else ""

        event: dict[str, Any] = {
            "chapter_id": chapter_id,
            "actor_agent_id": actor_agent_id,
            "action": action[:MAX_ACTION_LEN],
            "target_type": (target_type or "")[:64] or None,
            "target_id": (target_id or "")[:128] or None,
            "outcome": outcome,
            "detail": detail,
            "occurred_at": occurred_at or datetime.now(UTC).isoformat(),
            "prev_sha256": prev_hash or None,
        }
        event["event_sha256"] = sha256_of(event)
        event["signature_b64"] = _sign(event["event_sha256"])

        conn.execute(
            """
            INSERT INTO consent_events
                (chapter_id, actor_agent_id, action, target_type, target_id,
                 outcome, detail, occurred_at, prev_sha256, event_sha256, signature_b64)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["chapter_id"],
                event["actor_agent_id"],
                event["action"],
                event["target_type"],
                event["target_id"],
                event["outcome"],
                json.dumps(event["detail"], sort_keys=True),
                event["occurred_at"],
                event["prev_sha256"],
                event["event_sha256"],
                event["signature_b64"],
            ),
        )
        # G3: refresh the signed head-checkpoint inside the write lock so the
        # persisted (count, head) always reflects the row we just committed.
        count = conn.execute("SELECT COUNT(*) AS n FROM consent_events").fetchone()["n"]
        _write_checkpoint(int(count), event["event_sha256"])
        return event


# ── Read ─────────────────────────────────────────────────────────────


def list_events(
    action: str | None = None,
    actor_agent_id: str | None = None,
    since: str | None = None,
    limit: int = 100,
) -> list[dict]:
    with _connect() as conn:
        clauses = []
        params: list[Any] = []
        if action:
            clauses.append("action = ?")
            params.append(action[:MAX_ACTION_LEN])
        if actor_agent_id:
            clauses.append("actor_agent_id = ?")
            params.append(actor_agent_id)
        if since:
            clauses.append("occurred_at >= ?")
            params.append(since)
        # `clauses` is composed of literal strings this function controls —
        # all user-supplied values go through `?` placeholders in `params`.
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(min(max(int(limit), 1), 1000))
        query = f"SELECT * FROM consent_events {where} ORDER BY occurred_at DESC LIMIT ?"
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["detail"] = json.loads(d.get("detail") or "{}")
    except (ValueError, TypeError):
        d["detail"] = {}
    return d


# ── Verify chain ─────────────────────────────────────────────────────


def verify_row(row: dict) -> tuple[bool, str]:
    """Verify one row on its own. Returns ``(ok, reason)``.

    Checks the two properties an authorization read needs, both O(1):

      * **integrity** — ``event_sha256`` re-derives from the row's own fields,
        so a field edited in place (an ``expires_at`` pushed into the future)
        is caught.
      * **authenticity** — the Ed25519 signature over ``event_sha256``
        verifies against the configured key, so a row appended by anything
        without that key is caught. Recomputing a correct ``event_sha256`` is
        trivial (the algorithm is public); producing a signature is not.

    When the ledger has no signing key configured there is nothing to verify
    authenticity against, so only integrity is checked and the reason is
    ``"unsigned_ledger"``. On such a ledger, write access to the file is still
    enough to forge a row that passes.

    Chain position (``prev_sha256`` linkage) is deliberately NOT checked here:
    it is O(chain), and it answers a different question — whether the audit
    trail is complete and in order, which is :func:`verify_chain`'s job.
    Integrity plus authenticity is what decides whether a single row may be
    acted on.
    """
    event = {
        "chapter_id": row.get("chapter_id"),
        "actor_agent_id": row.get("actor_agent_id"),
        "action": row.get("action"),
        "target_type": row.get("target_type"),
        "target_id": row.get("target_id"),
        "outcome": row.get("outcome"),
        "detail": row.get("detail") or {},
        "occurred_at": row.get("occurred_at"),
        "prev_sha256": row.get("prev_sha256") or None,
    }
    if sha256_of(event) != row.get("event_sha256"):
        return False, "hash_mismatch"

    verify_key = _verify_key_or_none()
    if verify_key is None:
        return True, "unsigned_ledger"

    signature = row.get("signature_b64")
    if not signature:
        # The ledger is keyed, so every row it wrote carries a signature. One
        # that does not was not written through record().
        return False, "unsigned_row"
    try:
        verify_key.verify(str(row["event_sha256"]).encode("utf-8"), base64.b64decode(signature))
    except Exception:
        return False, "bad_signature"
    return True, "ok"


def verify_chain() -> dict:
    """Re-derive the hash chain. Returns a report dict.

    Shape on success: {"ok": True, "length": N, "signatures_verified": M,
    "unsigned_rows": U, "authenticated": True | False | None}.

    ``ok`` answers ONE question: is the chain internally consistent — do the
    hashes link, is nothing reordered, is nothing dropped. It stays true on a
    ledger that ran before a signing key was configured, because such a ledger
    is honestly consistent.

    ``authenticated`` answers the DIFFERENT question a caller usually means:
    was this ledger appended to outside record()? It is True only when the
    ledger is keyed AND every row carries a verifying signature. It is None —
    not False — when no signing key is configured, because there is nothing to
    verify against and 'cannot be determined' is not the same answer as 'was
    checked and failed'. None is falsy, so a caller writing
    ``if not report["authenticated"]`` fails closed on the undetermined case,
    and a caller that needs the distinction can test for None.

    The split mirrors verify_row, which separates integrity from authenticity
    for the same reason: they are different properties with different
    consequences, and one boolean cannot carry both.

    ``unsigned_rows`` counts rows carrying no signature. They do not make the
    chain broken — a ledger that ran before a signing key was configured has
    them legitimately — but on a keyed ledger a row with no signature was not
    written by record(), which is what drives ``authenticated`` to False. The
    authorization read does not rely on either: gate.find_valid_approval calls
    verify_row, which refuses an unsigned row outright when the ledger is keyed.

    Shape on drift: {"ok": False, "length": N, "broken_index": i,
    "first_broken_at": iso, "expected_sha256": ..., "actual_sha256": ...}.

    If the row was originally signed and the public key is derivable from
    the configured signing key, signatures are also verified; a bad
    signature counts as a broken row.
    """
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM consent_events ORDER BY id ASC").fetchall()

    prev = ""
    signatures_verified = 0
    unsigned_rows = 0
    verify_key = _verify_key_or_none()

    for i, r in enumerate(rows):
        event = {
            "chapter_id": r["chapter_id"],
            "actor_agent_id": r["actor_agent_id"],
            "action": r["action"],
            "target_type": r["target_type"],
            "target_id": r["target_id"],
            "outcome": r["outcome"],
            "detail": json.loads(r["detail"] or "{}"),
            "occurred_at": r["occurred_at"],
            "prev_sha256": (r["prev_sha256"] or prev) or None,
        }
        expected = sha256_of(event)
        if expected != r["event_sha256"]:
            return {
                "ok": False,
                "length": len(rows),
                # The walk stopped early, so authenticity was not determined.
                "authenticated": None,
                "broken_index": i,
                "first_broken_at": r["occurred_at"],
                "expected_sha256": expected,
                "actual_sha256": r["event_sha256"],
            }
        if (r["prev_sha256"] or "") != (prev or ""):
            return {
                "ok": False,
                "length": len(rows),
                # The walk stopped early, so authenticity was not determined.
                "authenticated": None,
                "broken_index": i,
                "first_broken_at": r["occurred_at"],
                "reason": "prev_sha256 does not match chain",
                "expected_prev": prev,
                "actual_prev": r["prev_sha256"],
            }
        if verify_key is not None and not r["signature_b64"]:
            unsigned_rows += 1
        if verify_key is not None and r["signature_b64"]:
            try:
                verify_key.verify(
                    r["event_sha256"].encode("utf-8"),
                    base64.b64decode(r["signature_b64"]),
                )
                signatures_verified += 1
            except Exception:
                return {
                    "ok": False,
                    "length": len(rows),
                    # The walk stopped early, so authenticity was not determined.
                    "authenticated": None,
                    "broken_index": i,
                    "first_broken_at": r["occurred_at"],
                    "reason": "signature verification failed",
                }
        prev = r["event_sha256"]

    # G3: the hash chain verified, but a tail-truncation leaves a shorter valid
    # chain. Cross-check the signed head-checkpoint — it detects rows dropped
    # off the end (the checkpoint's signed count exceeds the surviving rows).
    head_sha256 = rows[-1]["event_sha256"] if rows else ""
    drift = _check_head_checkpoint(len(rows), head_sha256)
    if drift is not None:
        return drift

    return {
        "ok": True,
        "length": len(rows),
        "signatures_verified": signatures_verified,
        "unsigned_rows": unsigned_rows,
        # None on an unkeyed ledger: undetermined rather than failed.
        "authenticated": (unsigned_rows == 0) if verify_key is not None else None,
    }


def _verify_key_or_none() -> Any:
    if _signing_key_b64 is None:
        return None
    try:
        from nacl.signing import SigningKey

        return SigningKey(base64.b64decode(_signing_key_b64)).verify_key
    except ImportError:
        return None


# ── G3: signed head-checkpoint (tail-truncation detection) ───────────
#
# The hash chain alone is tail-truncatable: dropping trailing rows leaves a
# shorter chain that still verifies. We persist a signed checkpoint of
# (count, head_sha256) to a sidecar file next to the db and re-check it in
# verify_chain. Because the count is signed, an attacker who truncates the db
# cannot lower it without the signing key — the stale checkpoint then reports
# more rows than exist, which verify_chain flags as truncation.
#
# Residual (documented, not closed here): an attacker who ALSO deletes the
# sidecar reverts the ledger to legacy "no checkpoint" mode, and a rollback to
# a previously-captured signed checkpoint is possible. Full protection needs an
# external monotonic anchor; the checkpoint raises the bar to "must also forge
# or destroy a signed sidecar".

_CHECKPOINT_VERSION = "consent-checkpoint:v1"


def _checkpoint_path() -> Path | None:
    return Path(str(_db_path) + ".checkpoint") if _db_path is not None else None


def _checkpoint_message(count: int, head_sha256: str) -> str:
    return f"{_CHECKPOINT_VERSION}:{count}:{head_sha256}"


def _write_checkpoint(count: int, head_sha256: str) -> None:
    """Persist the signed (count, head) checkpoint to the sidecar. Non-fatal on
    write error: the row is already committed, so a missed checkpoint only lags
    by one and self-heals on the next record()."""
    path = _checkpoint_path()
    if path is None:
        return
    payload = {
        "version": _CHECKPOINT_VERSION,
        "count": count,
        "head_sha256": head_sha256,
        "signature_b64": _sign(_checkpoint_message(count, head_sha256)),
    }
    try:
        tmp = Path(str(path) + ".tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True))
        tmp.replace(path)  # atomic swap
    except OSError as e:
        print(f"[consent.ledger][WARN] could not write head-checkpoint: {type(e).__name__}: {e}")


def _load_checkpoint() -> dict | None:
    path = _checkpoint_path()
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _check_head_checkpoint(rows_len: int, head_sha256: str) -> dict | None:
    """Return a drift report dict if the checkpoint indicates tampering, else
    None. Only the truncation direction (checkpoint claims MORE rows than exist)
    and a head mismatch at equal length are hard failures; a checkpoint that
    lags BEHIND the ledger is treated as benign (crash between the row insert and
    the checkpoint write, or legitimately newer rows)."""
    cp = _load_checkpoint()
    if cp is None:
        return None  # legacy / pre-checkpoint ledger — nothing to enforce

    verify_key = _verify_key_or_none()
    sig = cp.get("signature_b64")
    count = cp.get("count")
    cp_head = cp.get("head_sha256") or ""
    if not isinstance(count, int):
        return None  # malformed checkpoint — ignore rather than false-positive

    # A signed ledger MUST carry a verifiable checkpoint signature.
    if verify_key is not None and sig:
        try:
            verify_key.verify(_checkpoint_message(count, cp_head).encode("utf-8"), base64.b64decode(sig))
        except Exception:
            return {"ok": False, "length": rows_len, "reason": "checkpoint_signature_invalid"}
    elif verify_key is not None and not sig:
        # Signing is on but the checkpoint is unsigned → it was not produced by
        # this ledger's key. Refuse to trust it as a floor, and flag it.
        return {"ok": False, "length": rows_len, "reason": "checkpoint_unsigned"}

    if count > rows_len:
        return {
            "ok": False,
            "length": rows_len,
            "reason": "tail_truncation_detected",
            "checkpoint_count": count,
            "actual_count": rows_len,
        }
    if count == rows_len and cp_head != head_sha256:
        return {
            "ok": False,
            "length": rows_len,
            "reason": "head_mismatch",
            "checkpoint_head": cp_head,
            "actual_head": head_sha256,
        }
    return None


# ── Export ───────────────────────────────────────────────────────────


def export_jsonl(since: str | None = None) -> list[str]:
    """Return events as JSON Lines strings in chronological order.

    Suitable for `community-member audit export > audit.jsonl` → ship to
    a SIEM or let an external verifier re-derive the chain.
    """
    events = list_events(since=since, limit=10_000)
    return [json.dumps(e, sort_keys=True, default=str) for e in reversed(events)]


# ── Test hook ────────────────────────────────────────────────────────


def _reset_for_tests() -> None:
    """Drop state so tests can re-init cleanly. NOT for production use."""
    global _db_path, _signing_key_b64
    cp = _checkpoint_path()
    if cp is not None:
        try:
            cp.unlink(missing_ok=True)
        except OSError:
            pass
    _db_path = None
    _signing_key_b64 = None
    from community_member.consent import aae_emit

    aae_emit._reset_for_tests()
