"""Chapter weekly digest — aggregate the past N days of event_log activity
into a single ``chapter.digest.weekly`` event subscribers can consume.

Build path:

  build_digest(window_days=7) → reads event_log rows in the window,
  groups by event_type, builds top-N highlight lists per category,
  composes a headline + markdown summary via the agent's LLM (best-
  effort; fallback to a deterministic template if the LLM is down),
  and returns the payload dict.

  publish_digest(window_days=7) → calls build_digest then
  event_bus.publish("chapter.digest.weekly", payload). Returns the
  resulting event_id from event_log.

Trigger paths:

  - POST /api/digest/build       — manual on-demand trigger (handler
                                   wired in chapter_agent.py)
  - think_cycle digest_due check — runs once per scheduled window
                                   (weekly by default), state tracked
                                   in agent_memory under
                                   "last_digest_published_at"

The digest is INTENTIONALLY low-trust (tier 0) so the podcast-as-agent
and public newsletter generators can subscribe without elevated
trust. Per-member private signals (trust score changes, private
intents the matchmaker rejected, etc.) are NEVER included — only
aggregates + tier-0 highlights.

"Tier 0" is a SUBSCRIBER tier, not "anonymous". A subscriber is a signed
member holding a subscription; the SSE stream 401s without one. The
highlights are member-authored: ``top_intents[].text`` is the intent as the
member typed it and ``new_members`` names who joined this week, both of which
also reach the deterministic fallback summary. The on-demand trigger
(POST /api/digest/build) therefore requires a signed member or the operator
bearer — audit M11 found it open, and the middleware comment that let it
through argued from the previous sentence's "low-trust" as if it meant
"public". ``server/tests/test_digest_build_gate.py`` holds the gate.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import event_bus
import llm_config

logger = logging.getLogger(__name__)

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""
_chapter_name: str = ""
_llm: Any = None  # OpenAI client; optional — fallback summary used when missing


def init(
    pg_request: Callable[..., Awaitable[Any]],
    chapter_id: str,
    chapter_name: str = "",
    llm: Any = None,
) -> None:
    """Wire dependencies. Called at chapter startup."""
    global _pg_request, _chapter_id, _chapter_name, _llm  # noqa: PLW0603
    _pg_request = pg_request
    _chapter_id = chapter_id
    _chapter_name = chapter_name or chapter_id
    _llm = llm


def is_initialized() -> bool:
    return _pg_request is not None


async def _fetch_events_in_window(start_iso: str, end_iso: str) -> list[dict]:
    """Pull every event_log row in the window. Ordered by id ASC for stable
    aggregation order."""
    if _pg_request is None:
        return []
    params = {
        "created_at": f"gte.{start_iso}",
        "and": f"(created_at.lt.{end_iso})",
        "order": "id.asc",
        "limit": "5000",
        "select": "id,event_type,publisher_agent_id,payload,created_at",
    }
    # PostgREST: an unindexed `and()` in the filter URL is finicky; simpler
    # to pass two filters separately via the column-level syntax.
    params = {
        "created_at": f"gte.{start_iso}",
        "order": "id.asc",
        "limit": "5000",
        "select": "id,event_type,publisher_agent_id,payload,created_at",
    }
    rows = await _pg_request("GET", "event_log", params=params)
    if not isinstance(rows, list):
        return []
    # Apply BOTH bounds in Python (belt + suspenders).  PostgREST already
    # filters >= start_iso via params, but defending against a mock or a
    # backend that returns more than asked makes the digest deterministic
    # regardless of upstream.
    return [r for r in rows if isinstance(r, dict) and start_iso <= r.get("created_at", "") < end_iso]


def _top_n_intents(rows: list[dict], n: int = 5) -> list[dict]:
    out: list[dict] = []
    for r in rows:
        if r.get("event_type") != "intent.published":
            continue
        p = r.get("payload") or {}
        if not isinstance(p, dict):
            continue
        out.append(
            {
                "intent_id": p.get("intent_id", ""),
                "submitter": p.get("submitter_agent_id", ""),
                "text": str(p.get("text") or "")[:280],
                "tags": (p.get("tags") or [])[:8],
                "ts": r.get("created_at", ""),
            }
        )
    return out[-n:][::-1]  # most recent N, newest first


def _new_members(rows: list[dict], n: int = 10) -> list[dict]:
    out: list[dict] = []
    for r in rows:
        if r.get("event_type") != "member.joined":
            continue
        p = r.get("payload") or {}
        if not isinstance(p, dict):
            continue
        out.append(
            {
                "agent_id": p.get("agent_id", ""),
                "name": p.get("name", ""),
                "origin": p.get("origin", "sovereign"),
                "skills": (p.get("skills") or [])[:8],
                "ts": r.get("created_at", ""),
            }
        )
    return out[-n:][::-1]


def _federation_changes(rows: list[dict], n: int = 10) -> list[dict]:
    out: list[dict] = []
    for r in rows:
        et = r.get("event_type") or ""
        if not et.startswith("federation.peer."):
            continue
        p = r.get("payload") or {}
        if not isinstance(p, dict):
            continue
        out.append(
            {
                "type": et.replace("federation.peer.", ""),  # "online" | "offline"
                "peer_chapter_id": p.get("peer_chapter_id", ""),
                "ts": r.get("created_at", ""),
            }
        )
    return out[-n:][::-1]


def _fallback_headline(payload: dict) -> tuple[str, str]:
    """Deterministic summary when the LLM isn't available."""
    nm = payload.get("new_member_count", 0)
    ip = payload.get("intent_published_count", 0)
    im = payload.get("intent_matched_count", 0)
    headline = (
        f"This week on {_chapter_name}: "
        f"{nm} new member{'s' if nm != 1 else ''}, "
        f"{ip} intent{'s' if ip != 1 else ''} published, "
        f"{im} matched."
    )
    bullets: list[str] = []
    for it in (payload.get("top_intents") or [])[:3]:
        bullets.append(f"- intent by @{it.get('submitter', '?')}: {it.get('text', '')[:100]}")
    body = "\n".join(bullets) if bullets else "No standout activity this week."
    return headline, body


async def _llm_summarize(payload: dict) -> tuple[str, str]:
    """LLM-composed headline + markdown summary. Falls back to the
    deterministic template on any error so digest publishing is never
    blocked by LLM availability."""
    if _llm is None:
        return _fallback_headline(payload)
    try:
        import json as _json

        compact = {
            k: v
            for k, v in payload.items()
            if k
            in {
                "window_start",
                "window_end",
                "new_member_count",
                "intent_published_count",
                "intent_matched_count",
                "top_intents",
                "new_members",
                "federation_changes",
            }
        }
        prompt = (
            f"You're writing a weekly community digest for {_chapter_name} — "
            "an org agent. Style: short, energetic, factual. No "
            "marketing fluff. Output JSON:\n"
            '  {"headline": "one sentence, ≤140 chars", '
            '"summary_markdown": "3-6 short bullets in markdown"}'
            "\n\nDigest data:\n" + _json.dumps(compact, indent=2)
        )
        resp = _llm.chat.completions.create(
            model=llm_config.DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You write tight community recaps."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            max_tokens=600,
            temperature=0.4,
        )
        parsed = _json.loads(resp.choices[0].message.content or "{}")
        return (
            str(parsed.get("headline") or _fallback_headline(payload)[0])[:280],
            str(parsed.get("summary_markdown") or _fallback_headline(payload)[1])[:2000],
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("digest LLM summary failed: %s — using fallback", e)
        return _fallback_headline(payload)


async def build_digest(window_days: int = 7) -> dict:
    """Aggregate the past ``window_days`` of event_log into a digest payload.

    Pure-ish: reads, doesn't write. Caller (publish_digest or the manual
    endpoint) decides what to do with the result.
    """
    end = datetime.now(UTC)
    start = end - timedelta(days=max(1, int(window_days)))
    rows = await _fetch_events_in_window(start.isoformat(), end.isoformat())

    counts_by_type: dict[str, int] = {}
    for r in rows:
        counts_by_type[r.get("event_type", "")] = counts_by_type.get(r.get("event_type", ""), 0) + 1

    payload: dict = {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "new_member_count": counts_by_type.get("member.joined", 0),
        "intent_published_count": counts_by_type.get("intent.published", 0),
        "intent_matched_count": counts_by_type.get("intent.matched", 0),
        "top_intents": _top_n_intents(rows),
        "new_members": _new_members(rows),
        "federation_changes": _federation_changes(rows),
    }
    headline, summary_md = await _llm_summarize(payload)
    payload["headline"] = headline
    payload["summary_markdown"] = summary_md
    return payload


async def publish_digest(window_days: int = 7) -> int | None:
    """Build + publish in one call. Returns the persisted event_id.

    Safe to call from think_cycle (weekly cadence) OR from the manual
    endpoint (anytime). Fire-and-forget at the caller; this DOES return
    the id so a test/demo can confirm it landed.
    """
    payload = await build_digest(window_days=window_days)
    return await event_bus.publish("chapter.digest.weekly", payload)
