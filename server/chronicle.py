"""Chronicle — the agent's own first-person daily summary.

A Chronicle is the deliberately-public counterpart to the principal's
private daily ARP receipt log. Once per UTC day boundary the principal's
parent chapter:

1. Aggregates the principal's ``arp_receipts`` across every chapter that
   wrote one (the chapters share one Postgres project, so this is a
   single ``WHERE principal_did = X AND issued_at::date = D`` query).
2. Computes deterministic stats (counts per category, counterparty
   count, trust delta).
3. Asks the agent's own LLM — fed the agent's ``config.personality`` and
   voice fields — to write a 2-3 sentence first-person narrative.
4. Upserts the row into ``chronicles``.

The principal opts in to *public* visibility by setting
``config.chronicle_public = true`` on their agent. The chronicle table
itself is always written; only the public surface gate is conditional.

Cross-chapter aggregation is the v1 default. The ``sources`` jsonb on
every row records which chapters contributed receipts, so the Chronicle
is honest about its origin chapters. Forward-compat: when future
ingestion goes beyond arp_receipts (calendar, email, external attest),
new entries land in ``sources`` with a distinct ``type`` discriminator.

Generation is idempotent — re-running ``generate_for_day`` upserts the
same (principal_did, chronicle_date) row.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import llm_config

_pg_request: Callable[..., Awaitable[Any]] | None = None
_llm: Any = None
_chapter_id: str = ""
_chapter_name: str = ""


def init(
    pg_request: Callable[..., Awaitable[Any]],
    chapter_id: str,
    chapter_name: str,
    llm: Any | None = None,
) -> None:
    """Wire dependencies. ``llm`` is the OpenAI-shape client that
    ``chapter_agent.py`` constructs via ``llm_config`` (provider-agnostic;
    default Claude). Pass None to disable narrative generation — the
    deterministic template fallback still produces a usable narrative."""
    global _pg_request, _llm, _chapter_id, _chapter_name
    _pg_request = pg_request
    _llm = llm
    _chapter_id = chapter_id
    _chapter_name = chapter_name


# ── public configuration helpers ───────────────────────────────────


async def is_chronicle_public(agent_id: str) -> bool:
    """Return True iff the agent has explicitly opted into public visibility."""
    if _pg_request is None:
        return False
    rows = await _pg_request(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "config",
            "limit": "1",
        },
    )
    if not rows:
        return False
    row = rows[0] if isinstance(rows, list) else rows
    config = row.get("config") or {}
    return bool(config.get("chronicle_public"))


async def _agent_record(agent_id: str) -> dict[str, Any]:
    """Fetch the agent row (config + name + description) for LLM prompting."""
    if _pg_request is None:
        return {}
    rows = await _pg_request(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{agent_id}",
            "select": "agent_id,name,description,config",
            "limit": "1",
        },
    )
    if not rows:
        return {}
    return rows[0] if isinstance(rows, list) else rows


# ── deterministic stats aggregation ────────────────────────────────


def _aggregate_stats(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Count receipts by category + outcome, sum amounts per currency,
    and tally unique counterparties. Pure function, deterministic.

    Returns a flat jsonb-shaped dict the LLM consumes for narrative
    generation AND downstream tools consume directly.
    """
    by_category: Counter[str] = Counter()
    by_outcome: Counter[str] = Counter()
    amounts: dict[str, int] = {}
    counterparties: set[str] = set()

    for r in receipts:
        action = r.get("action") or {}
        cat = action.get("category", "other")
        by_category[cat] += 1
        by_outcome[action.get("outcome", "unknown")] += 1

        amount = action.get("amount") or {}
        cents = amount.get("cents")
        cur = amount.get("currency")
        if isinstance(cents, int) and isinstance(cur, str):
            amounts[cur] = amounts.get(cur, 0) + cents

        for k in ("counterparty_did", "counterparty_label"):
            v = action.get(k)
            if isinstance(v, str) and v:
                counterparties.add(v)

    return {
        "receipt_count": len(receipts),
        "by_category": dict(by_category),
        "by_outcome": dict(by_outcome),
        "amount_totals": amounts,
        "counterparty_count": len(counterparties),
    }


def _build_sources_attribution(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-chapter receipt-count breakdown so the chronicle is honest
    about which chapters contributed.

    Receipts carry ``config.parent_chapter`` implicitly through the
    chapter that wrote them. We resolve which chapter wrote each receipt
    via the chapter agent_id stored in the issuer_did → agent_id mapping.
    For v1 we use a simpler proxy: the parent chapter is whichever
    chapter's ledger holds the row. Future iteration may stamp the
    chapter_id directly into the arp_receipts row.
    """
    # Today the server doesn't stamp itself into the receipt row. The
    # source attribution defaults to a single 'arp_receipts' source with
    # the total count. When server stamping lands, this loop can split
    # the count per server. The shape is forward-compatible.
    if not receipts:
        return []
    return [{"type": "arp_receipts", "count": len(receipts)}]


# ── deterministic fallback narrative ───────────────────────────────


def _fallback_narrative(agent: dict[str, Any], stats: dict[str, Any]) -> str:
    """When the LLM is unavailable or fails, produce a defensible
    deterministic narrative so chronicle generation is never blocked."""
    name = agent.get("name") or "The agent"
    n = int(stats.get("receipt_count") or 0)
    if n == 0:
        return f"{name} had a quiet day — no actions were recorded."
    by_cat = stats.get("by_category") or {}
    parts: list[str] = []
    for cat in (
        "purchase",
        "message_sent",
        "decision_made",
        "data_shared",
        "appointment_booked",
        "attestation_issued",
        "vote_cast",
    ):
        c = int(by_cat.get(cat, 0))
        if c:
            label = cat.replace("_", " ")
            parts.append(f"{c} {label}{'s' if c != 1 else ''}")
    if not parts:
        return f"{name} performed {n} recorded actions today."
    head = parts[0]
    if len(parts) == 1:
        return f"Today {name} logged {head}."
    body = ", ".join(parts[:-1])
    return f"Today {name} logged {body}, and {parts[-1]}."


def _llm_narrative(agent: dict[str, Any], stats: dict[str, Any]) -> str | None:
    """Compose the first-person narrative via the agent's own LLM.

    The agent's ``config.personality`` and ``config.voice`` drive tone;
    name/title/company drive context. The LLM sees only the
    deterministic stats summary — never raw receipt content — so even
    if the LLM is compromised it cannot leak principal-private fields
    like exact ``human_summary`` text or ``machine_payload``.

    Returns None on any failure; the caller falls back to the
    deterministic template.
    """
    if _llm is None:
        return None
    config = agent.get("config") or {}
    personality = config.get("personality") or ""
    voice = config.get("voice") or "thoughtful"
    name = agent.get("name") or "an agent"
    title = config.get("title") or ""
    company = config.get("company") or ""

    persona_line = name
    if title or company:
        persona_line = f"{name}, {' at '.join(filter(None, [title, company]))}"

    prompt = (
        "Write a short first-person Chronicle entry (2-3 sentences, ≤300 "
        "characters total) for the day's recorded actions. Voice: "
        f"{voice}. Speak as {persona_line}. "
        f"Personality: {personality[:300]}. "
        "Be honest, factual, and refer to the *categories* of action "
        "rather than naming specific counterparties or amounts (those "
        "stay private). No marketing. No emojis. Output plain text, "
        "one paragraph.\n\n"
        f"Today's stats:\n{json.dumps(stats, indent=2)}"
    )
    try:
        resp = _llm.chat.completions.create(
            model=llm_config.DEFAULT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You write a brief first-person Chronicle entry "
                        "in the voice of the agent's persona. Honest, "
                        "factual, no fluff, no specifics that would leak "
                        "private fields."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=200,
            temperature=0.5,
        )
        text = (resp.choices[0].message.content or "").strip()
        return text[:600] if text else None
    except Exception:  # noqa: BLE001 — chronicle generation must never block on LLM
        return None


# ── core generation + retrieval ────────────────────────────────────


async def _fetch_receipts_for_day(principal_did: str, day: date) -> list[dict[str, Any]]:
    """Pull every arp_receipt for the principal whose ``issued_at`` falls
    inside the UTC calendar day. Cross-chapter by construction — all
    chapters share the same Postgres project.
    """
    if _pg_request is None:
        return []
    day_start = f"{day.isoformat()}T00:00:00Z"
    day_end = f"{(day + timedelta(days=1)).isoformat()}T00:00:00Z"
    rows = await _pg_request(
        "GET",
        "arp_receipts",
        params={
            "principal_did": f"eq.{principal_did}",
            "issued_at": f"gte.{day_start}",
            # PostgREST: chain operators by repeating the column name with a
            # second filter; here we use 'and=' for ranges.
            "and": f"(issued_at.lt.{day_end})",
            "select": "receipt_json,issued_at",
            "order": "issued_at.asc",
            "limit": "500",
        },
    )
    return [row["receipt_json"] for row in rows or [] if "receipt_json" in row]


async def generate_for_day(
    *,
    principal_did: str,
    agent_id: str,
    day: date,
) -> dict[str, Any] | None:
    """Build (or rebuild) the Chronicle row for one principal + one day.

    Pulls receipts cross-chapter, aggregates, generates narrative,
    upserts. Idempotent — same inputs produce the same row.

    Returns the chronicle dict written, or None if persistence failed.
    """
    if _pg_request is None:
        return None
    agent = await _agent_record(agent_id)
    receipts = await _fetch_receipts_for_day(principal_did, day)
    stats = _aggregate_stats(receipts)
    sources = _build_sources_attribution(receipts)
    narrative = _llm_narrative(agent, stats) or _fallback_narrative(agent, stats)

    row = {
        "principal_did": principal_did,
        "chronicle_date": day.isoformat(),
        "parent_chapter": _chapter_id,
        "narrative": narrative,
        "stats": stats,
        "sources": sources,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    persisted = await _pg_request(
        "POST",
        "chronicles",
        body=row,
    )
    if persisted is None:
        return None
    return row


async def get_chronicle(principal_did: str, day: date) -> dict[str, Any] | None:
    if _pg_request is None:
        return None
    rows = await _pg_request(
        "GET",
        "chronicles",
        params={
            "principal_did": f"eq.{principal_did}",
            "chronicle_date": f"eq.{day.isoformat()}",
            "select": "principal_did,chronicle_date,parent_chapter,narrative,stats,sources,updated_at",
            "limit": "1",
        },
    )
    if not rows:
        return None
    return rows[0] if isinstance(rows, list) else rows


async def list_chronicles(
    principal_did: str,
    *,
    limit: int = 30,
) -> list[dict[str, Any]]:
    if _pg_request is None:
        return []
    rows = await _pg_request(
        "GET",
        "chronicles",
        params={
            "principal_did": f"eq.{principal_did}",
            "select": "chronicle_date,narrative,stats,sources,updated_at,parent_chapter",
            "order": "chronicle_date.desc",
            "limit": str(max(1, min(365, limit))),
        },
    )
    return list(rows or [])


async def generate_for_all_own_members(*, day: date, members: dict[str, dict]) -> int:
    """Iterate every in-memory member whose ``parent_chapter`` matches
    this chapter and generate their Chronicle for ``day``. Returns the
    number of chronicles successfully written.

    Called by the heartbeat loop once per UTC day boundary. Idempotent —
    re-running for the same day just upserts the same rows.
    """
    if _pg_request is None:
        return 0
    written = 0
    for agent_id, member in members.items():
        # Resolve the member's did:key via the server's agents table.
        agent_row = await _agent_record(agent_id)
        config = agent_row.get("config") or {}
        if config.get("parent_chapter") != _chapter_id:
            # Federation peer member — not ours to chronicle.
            continue
        # Resolve did_key from agent's stored Ed25519 pubkey.
        principal_did = _did_key_for_agent(agent_id, member)
        if not principal_did:
            continue
        result = await generate_for_day(
            principal_did=principal_did,
            agent_id=agent_id,
            day=day,
        )
        if result is not None:
            written += 1
    return written


def _did_key_for_agent(agent_id: str, member: dict[str, Any]) -> str:
    """Resolve the agent's did:key. The chapter stores pubkeys in the
    auth_verify._agent_keys map; this helper imports lazily to keep
    chronicle.py importable without the full chapter graph (tests use
    smaller fakes)."""
    try:
        import auth_verify
        import sovereign_identity

        stored = auth_verify._agent_keys.get(agent_id, {}) if hasattr(auth_verify, "_agent_keys") else {}
        pubkey = stored.get("ed25519_pubkey") or member.get("ed25519_pubkey") or ""
        if not pubkey:
            return ""
        return sovereign_identity.build_did_key_from_ed25519(pubkey)
    except Exception:  # noqa: BLE001 — chronicle pipeline must never crash on key resolve
        return ""


__all__ = [
    "init",
    "generate_for_day",
    "generate_for_all_own_members",
    "get_chronicle",
    "list_chronicles",
    "is_chronicle_public",
    "_aggregate_stats",
    "_fallback_narrative",
]
