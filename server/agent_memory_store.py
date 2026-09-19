"""Durable per-agent memory for unattended service agents (PR8).

WHAT THIS IS FOR, AND THE BOUNDARY THAT KEEPS IT SMALL. Four service agents in
containers get recreated; anything they wrote to a local file goes with them.
A keyless-install spike watched exactly that class of loss — the compose volume was
mounted at the legacy `.nanda` path while the live code wrote `.org`, so the
org's own signing identity did not survive `--force-recreate`. Local files are
not durable for a container that is cattle.

So this is **storage, not a knowledge base**. Three types, and the list is the
scope:

    cursor  "I last processed up to X" — a watermark. Never expires.
    dedup   "I already acted on X"     — an idempotency key. Should expire.
    note    a small operational fact   — "sync failed 3x, backing off".

That is what an unattended agent needs to survive a restart without
reprocessing, double-sending, or forgetting it was mid-backoff. It is
deliberately not embeddings, not documents, not retrieval. If a caller wants a
knowledge base, this is the wrong module and should stay the wrong module —
the moment memory becomes a corpus, every write becomes a judgement call and
the size caps below become negotiable.

⚠️ DETERMINISTIC. No LLM in any path here. Memory is storage; nothing in this
module decides what is worth remembering, summarises, embeds, or ranks. The
caller supplies a key and a value and this persists them. That matches the
program's standing bias — the model proposes and drafts, it never triggers or
mutates — and it is also what makes the module testable without a provider.

⚠️ MEMORY IS DATA, NEVER INSTRUCTIONS. Values are replayed into a future
context, so a value that reads as a directive is a stored prompt injection with
a long fuse. This module does not interpret values and callers must not treat
a recalled value as an instruction. The `agent_id` scoping below is the
structural half of that: an agent cannot write into a sibling's memory, so it
cannot steer a sibling.

WHY THIS IS NOT BEHIND THE `record_write` GATE — a deliberate divergence from
`crm_store`, and the judgement call most worth reviewing.

PR1 defines `record_write` as "any durable write to a store the operator is
accountable for", and `crm_store` consumes it. A memory row is durable, so the
literal reading would gate it too. It is not gated, for three reasons:

  1. **Memory cannot itself do anything.** Every consequential action stays
     gated — `send_external` for outbound messages, `record_write` for business
     records, `external_fetch` for third-party reads. Writing "I last read
     message 41" performs nothing; the *next* send is still gated. Gating memory
     adds approval volume without adding control.
  2. **It would make unattended operation impossible.** An agent that needs a
     human to approve remembering its own cursor cannot run unattended, which is
     the entire premise. The spike's finding was that the queue had no vocabulary
     for service work; the fix for that is not to route *everything* through it.
     A queue that fills with "may I remember a number" is the noise the spike was
     asked to look for, arriving by a different door.
  3. **The operator is not accountable to anyone for it.** A CRM row asserts
     something about a third party; being wrong is answerable outward. A cursor
     asserts something about the agent's own progress; being wrong makes the
     agent misbehave, and the gates above catch the misbehaviour.

The risk that remains is memory as a steering vector, and it is handled
structurally rather than procedurally: hard per-agent scoping, bounded size,
bounded count, and opt-in TTL. If review disagrees, the change is one line —
add a `_gate` call in `remember` — but it should be a decision taken with the
above on the table, not by default.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

_pg_request: Callable[..., Awaitable] | None = None
_agent_id: str = ""

TABLE = "service_agent_memory"

#: The whole vocabulary. A fourth type is a design change, not a config change.
MEMORY_TYPES = ("cursor", "dedup", "note")

#: Bounds. Memory that can grow without limit is a slow outage: a service agent
#: that writes one dedup key per processed item and never expires them fills the
#: table and then the disk. These are per (chapter, agent).
MAX_KEY_CHARS = 256
MAX_VALUE_BYTES = 8 * 1024
MAX_ENTRIES_PER_AGENT = 5_000

#: Default TTL for `dedup` only. `cursor` and `note` default to no expiry —
#: see the schema comment on why an expiring cursor is a silent-wrong-answer.
DEFAULT_DEDUP_TTL = timedelta(days=30)


def init(pg_request: Callable[..., Awaitable], agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


def _pg() -> Callable[..., Awaitable]:
    if _pg_request is None:
        raise RuntimeError("agent_memory_store.init() was never called — no pg_request injected")
    return _pg_request


def _now() -> datetime:
    return datetime.now(UTC)


class MemoryError_(ValueError):
    """A rejected memory operation.

    Carries a machine-readable ``reason`` so a caller can branch instead of
    retrying blindly — same contract as ``CrmError``.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


def _validate(agent_id: str, memory_type: str, key: str, value: Any) -> str:
    """Reject anything out of bounds BEFORE it reaches the database.

    Returns the serialised value. Validation is here rather than in the schema
    where it can produce a useful reason string; the schema's CHECK on
    ``memory_type`` is the backstop for a caller that bypasses this module.
    """
    if not (agent_id or "").strip():
        raise MemoryError_("agent_id_required", "memory is per-agent; there is no shared scope")
    if memory_type not in MEMORY_TYPES:
        raise MemoryError_(
            "unknown_memory_type",
            f"{memory_type!r} is not one of {MEMORY_TYPES} — a new type is a design change",
        )
    key = (key or "").strip()
    if not key:
        raise MemoryError_("key_required")
    if len(key) > MAX_KEY_CHARS:
        raise MemoryError_("key_too_long", f"{len(key)} > {MAX_KEY_CHARS}")

    try:
        # No `default=str`. Coercing an unserialisable value to its repr would
        # store something that does not round-trip — put in a set, get back the
        # string "{1, 2, 3}" — and a caller reading its own memory back wrong is
        # the silent-wrong-answer class this program keeps removing. A caller
        # that wants a timestamp stored serialises it deliberately.
        serialised = json.dumps(value, sort_keys=True)
    except (TypeError, ValueError) as e:
        raise MemoryError_("value_not_serialisable", str(e)[:200]) from e
    if len(serialised.encode()) > MAX_VALUE_BYTES:
        raise MemoryError_(
            "value_too_large",
            f"{len(serialised.encode())} bytes > {MAX_VALUE_BYTES}; memory is a "
            "scratchpad, not a document store",
        )
    return serialised


async def _count_for(agent_id: str) -> int:
    rows = await _pg()(
        "GET",
        TABLE,
        params={
            "chapter_id": f"eq.{_agent_id}",
            "agent_id": f"eq.{agent_id}",
            "select": "id",
        },
    )
    return len(rows or [])


async def remember(
    agent_id: str,
    memory_type: str,
    key: str,
    value: Any,
    *,
    ttl: timedelta | None = None,
) -> dict[str, Any]:
    """Upsert one memory entry for ``agent_id``.

    Upsert, not insert: remembering the same key twice is an update. An agent
    that accumulates duplicate cursors has no cursor.

    ``ttl`` is opt-in except for ``dedup``, which defaults to
    :data:`DEFAULT_DEDUP_TTL`. Pass ``ttl=timedelta(0)`` to force no expiry on a
    dedup key — explicitly, so it is a visible choice rather than an omission.
    """
    serialised = _validate(agent_id, memory_type, key, value)
    now = _now()

    if ttl is None and memory_type == "dedup":
        ttl = DEFAULT_DEDUP_TTL
    expires_at = (now + ttl).isoformat() if ttl else None

    existing = await recall(agent_id, memory_type, key, include_expired=True)
    if existing is None and await _count_for(agent_id) >= MAX_ENTRIES_PER_AGENT:
        raise MemoryError_(
            "quota_exceeded",
            f"{agent_id} holds {MAX_ENTRIES_PER_AGENT} entries; expire or forget some. "
            "Unbounded memory is a slow outage, not a feature.",
        )

    body = {
        "chapter_id": _agent_id,
        "agent_id": agent_id,
        "memory_type": memory_type,
        "memory_key": key.strip(),
        "memory_value": json.loads(serialised),
        "updated_at": now.isoformat(),
        "expires_at": expires_at,
    }

    if existing is not None:
        await _pg()(
            "PATCH",
            TABLE,
            params={
                "chapter_id": f"eq.{_agent_id}",
                "agent_id": f"eq.{agent_id}",
                "memory_type": f"eq.{memory_type}",
                "memory_key": f"eq.{key.strip()}",
            },
            body={k: v for k, v in body.items() if k not in ("chapter_id", "agent_id")},
        )
    else:
        body["created_at"] = now.isoformat()
        await _pg()("POST", TABLE, body=body)

    return {"agent_id": agent_id, "memory_type": memory_type, "key": key.strip(), "stored": True}


async def recall(
    agent_id: str,
    memory_type: str,
    key: str,
    *,
    include_expired: bool = False,
) -> Any | None:
    """The stored value, or None.

    An expired entry reads as absent. It is not deleted here — a read path that
    mutates turns a recall into a write and makes a replica lag look like data
    loss; :func:`purge_expired` is the one place that deletes.
    """
    if not (agent_id or "").strip():
        raise MemoryError_("agent_id_required")
    rows = await _pg()(
        "GET",
        TABLE,
        params={
            "chapter_id": f"eq.{_agent_id}",
            "agent_id": f"eq.{agent_id}",
            "memory_type": f"eq.{memory_type}",
            "memory_key": f"eq.{(key or '').strip()}",
            "select": "memory_value,expires_at",
        },
    )
    if not rows:
        return None
    row = rows[0]
    if not include_expired and _is_expired(row.get("expires_at")):
        return None
    return row.get("memory_value")


async def recall_all(agent_id: str, memory_type: str | None = None) -> list[dict[str, Any]]:
    """Every live entry for ``agent_id``, newest first. Expired rows omitted."""
    if not (agent_id or "").strip():
        raise MemoryError_("agent_id_required")
    params: dict[str, str] = {
        "chapter_id": f"eq.{_agent_id}",
        "agent_id": f"eq.{agent_id}",
        "select": "memory_type,memory_key,memory_value,updated_at,expires_at",
        "order": "updated_at.desc",
    }
    if memory_type:
        params["memory_type"] = f"eq.{memory_type}"
    rows = await _pg()("GET", TABLE, params=params) or []
    return [r for r in rows if not _is_expired(r.get("expires_at"))]


async def forget(agent_id: str, memory_type: str, key: str) -> dict[str, Any]:
    """Delete one entry. Idempotent — forgetting what was never there is fine."""
    if not (agent_id or "").strip():
        raise MemoryError_("agent_id_required")
    await _pg()(
        "DELETE",
        TABLE,
        params={
            "chapter_id": f"eq.{_agent_id}",
            "agent_id": f"eq.{agent_id}",
            "memory_type": f"eq.{memory_type}",
            "memory_key": f"eq.{(key or '').strip()}",
        },
    )
    return {"agent_id": agent_id, "memory_type": memory_type, "key": key, "forgotten": True}


async def forget_agent(agent_id: str) -> dict[str, Any]:
    """Delete everything for one agent.

    Exists so a DSAR request and a decommissioned agent both have an answer.
    The chapter-side `agent_memory` has no per-agent column and `dsar.py`
    documents that it therefore cannot be exported or deleted per subject; this
    table was given `agent_id` from the start precisely so that gap is not
    inherited.
    """
    if not (agent_id or "").strip():
        raise MemoryError_("agent_id_required")
    await _pg()(
        "DELETE",
        TABLE,
        params={"chapter_id": f"eq.{_agent_id}", "agent_id": f"eq.{agent_id}"},
    )
    return {"agent_id": agent_id, "forgotten_all": True}


async def purge_expired() -> dict[str, Any]:
    """Delete entries past their expiry. The only path that deletes on age."""
    await _pg()(
        "DELETE",
        TABLE,
        params={"chapter_id": f"eq.{_agent_id}", "expires_at": f"lt.{_now().isoformat()}"},
    )
    return {"purged": True}


def _is_expired(expires_at: Any) -> bool:
    """NULL expiry never expires — the deliberate default for cursors."""
    if not expires_at:
        return False
    try:
        when = expires_at if isinstance(expires_at, datetime) else datetime.fromisoformat(str(expires_at))
    except ValueError:
        # An unparseable timestamp must not silently mean "expired" — that
        # would delete a cursor because a driver changed its format.
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when < _now()


__all__ = [
    "DEFAULT_DEDUP_TTL",
    "MAX_ENTRIES_PER_AGENT",
    "MAX_KEY_CHARS",
    "MAX_VALUE_BYTES",
    "MEMORY_TYPES",
    "MemoryError_",
    "forget",
    "forget_agent",
    "init",
    "purge_expired",
    "recall",
    "recall_all",
    "remember",
]
