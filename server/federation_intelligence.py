"""
Federation Intelligence — cross-chapter knowledge exchange.

Each chapter shares a lightweight summary of its intelligence model
with federation peers. This enables:
- Cross-chapter skill matching (our gaps ↔ their strengths)
- Network-wide trend visibility
- Coordinated recommendations across chapters
"""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx

# Injected by chapter_agent.py
_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("federation_intelligence.init() was never called — no pg_request injected")
    return _pg_request

_knowledge_cache = None
_agent_id = ""
_agent_name = ""

# Cached federation knowledge: chapter_id → knowledge summary
federation_knowledge: dict[str, dict] = {}


def init(pg_request, knowledge_cache, agent_id, agent_name):
    global _pg_request, _knowledge_cache, _agent_id, _agent_name
    _pg_request = pg_request
    _knowledge_cache = knowledge_cache
    _agent_id = agent_id
    _agent_name = agent_name


def get_our_summary() -> dict:
    """Build a shareable summary of our chapter intelligence."""
    intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    if not intel:
        return {
            "chapter_id": _agent_id,
            "chapter_name": _agent_name,
            "skill_graph": {},
            "skill_gaps": [],
            "trending_topics": [],
            "member_count": 0,
            "active_member_count": 0,
            "top_skills": [],
            "last_reflected": None,
            "policy_snapshot": [],
        }

    skill_graph = intel.get("skill_graph", {})
    top_skills = sorted(skill_graph.items(), key=lambda x: -x[1])[:10]

    return {
        "chapter_id": _agent_id,
        "chapter_name": _agent_name,
        "skill_graph": skill_graph,
        "skill_gaps": intel.get("skill_gaps", []),
        "trending_topics": intel.get("trending_topics", []),
        "recommendations": intel.get("recommendations", []),
        "patterns": intel.get("patterns", []),
        "member_count": intel.get("member_count", 0),
        "active_member_count": len(intel.get("active_members", [])),
        "top_skills": [s[0] for s in top_skills],
        "last_reflected": intel.get("last_reflected"),
        # Empty for sync callers; populated async by get_our_summary_async
        # (called before shipping payload to a peer in the 6-min exchange).
        "policy_snapshot": [],
    }


async def get_our_summary_async() -> dict:
    """Same as get_our_summary but populates policy_snapshot from Postgres.

    Call this when shipping the summary to a peer. For in-memory local
    reads (e.g. GET /api/knowledge/summary), the sync version is fine —
    peers will just see policy_snapshot=[] from those responses and not
    merge anything from us this cycle.
    """
    summary = get_our_summary()
    try:
        import policy

        summary["policy_snapshot"] = await policy.get_policy_snapshot_for_federation()
    except Exception as e:
        print(f"[FederationIntel] policy_snapshot build failed: {e}")
    return summary


async def exchange_with_chapter(chapter_id: str, endpoint: str) -> dict | None:
    """Fetch a peer chapter's knowledge summary."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{endpoint.rstrip('/')}/api/knowledge/summary",
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Cache it
                federation_knowledge[chapter_id] = {
                    **data,
                    "fetched_at": datetime.now(UTC).isoformat(),
                }
                # Persist to Postgres
                await _persist_knowledge(chapter_id, data)
                return data
    except Exception as e:
        print(f"[FederationIntel] Exchange with {chapter_id} failed: {e}")
    return None


async def exchange_with_all(federation: dict):
    """Exchange knowledge with all online federation chapters."""
    tasks = []
    for chapter_id, chapter_data in federation.items():
        if chapter_data.get("status") != "online":
            continue
        endpoint = chapter_data.get("endpoint", "")
        if not endpoint:
            continue
        tasks.append(exchange_with_chapter(chapter_id, endpoint))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success = sum(1 for r in results if r is not None and not isinstance(r, Exception))
        print(f"[FederationIntel] Exchanged knowledge with {success}/{len(tasks)} orgs")


async def _persist_knowledge(chapter_id: str, data: dict):
    """Save received knowledge to Postgres (upsert)."""
    existing = await _pg()(
        "GET",
        "federation_knowledge",
        params={
            "source_chapter_id": f"eq.{chapter_id}",
            "receiving_chapter_id": f"eq.{_agent_id}",
            "select": "id",
        },
    )
    if existing:
        await _pg()(
            "PATCH",
            "federation_knowledge", params={"source_chapter_id": f"eq.{chapter_id}", "receiving_chapter_id": f"eq.{_agent_id}"},
            body={"knowledge_data": data, "confidence": 0.6},
        )
    else:
        await _pg()(
            "POST",
            "federation_knowledge",
            body={
                "source_chapter_id": chapter_id,
                "receiving_chapter_id": _agent_id,
                "knowledge_data": data,
                "confidence": 0.6,
            },
        )


async def load_cached_knowledge():
    """Load previously received federation knowledge from Postgres."""
    data = await _pg_request(
        "GET",
        "federation_knowledge",
        params={
            "receiving_chapter_id": f"eq.{_agent_id}",
            "order": "updated_at.desc",
        },
    )
    if data:
        for row in data:
            cid = row.get("source_chapter_id", "")
            if cid:
                federation_knowledge[cid] = {
                    **(row.get("knowledge_data") or {}),
                    "fetched_at": row.get("updated_at"),
                }
        print(f"[FederationIntel] Loaded knowledge from {len(data)} orgs")


def find_skill_matches(our_gaps: list[str] | None = None) -> list[dict]:
    """Find chapters that can fill our skill gaps."""
    intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    gaps = our_gaps or intel.get("skill_gaps", [])
    if not gaps:
        return []

    matches = []
    for chapter_id, knowledge in federation_knowledge.items():
        their_skills = knowledge.get("skill_graph", {})
        knowledge.get("top_skills", [])
        chapter_name = knowledge.get("chapter_name", chapter_id)

        for gap in gaps:
            gap_lower = gap.lower()
            # Check if they have this skill
            matching_skills = [s for s in their_skills.keys() if gap_lower in s.lower() or s.lower() in gap_lower]
            if matching_skills:
                matches.append(
                    {
                        "our_gap": gap,
                        "their_chapter_id": chapter_id,
                        "their_chapter_name": chapter_name,
                        "their_matching_skills": matching_skills,
                        "their_member_count": knowledge.get("member_count", 0),
                    }
                )

    return matches


def get_network_skill_map() -> dict:
    """Aggregate skills across all federation chapters."""
    combined: dict[str, dict] = {}  # skill → {total: N, chapters: [...]}

    # Our skills
    our_intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    our_graph = our_intel.get("skill_graph", {})
    for skill, count in our_graph.items():
        combined[skill] = {"total": count, "chapters": [_agent_name]}

    # Federation skills
    for chapter_id, knowledge in federation_knowledge.items():
        chapter_name = knowledge.get("chapter_name", chapter_id)
        for skill, count in knowledge.get("skill_graph", {}).items():
            if skill in combined:
                combined[skill]["total"] += count
                combined[skill]["chapters"].append(chapter_name)
            else:
                combined[skill] = {"total": count, "chapters": [chapter_name]}

    return combined


def get_cross_chapter_opportunities() -> list[dict]:
    """Identify skill gaps that other chapters can fill and vice versa.

    Returns a list of opportunity dicts:
    {gap, source_chapter, matching_chapter, matching_skills, member_count}
    """
    opportunities = []

    # Our gaps vs their skills
    our_matches = find_skill_matches()
    for m in our_matches:
        opportunities.append(
            {
                "gap": m["our_gap"],
                "source_chapter": _agent_name,
                "matching_chapter": m["their_chapter_name"],
                "matching_skills": m["their_matching_skills"],
                "member_count": m["their_member_count"],
            }
        )

    # Their gaps vs our skills
    our_intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    our_skills = our_intel.get("skill_graph", {})
    for chapter_id, knowledge in federation_knowledge.items():
        chapter_name = knowledge.get("chapter_name", chapter_id)
        their_gaps = knowledge.get("skill_gaps", [])
        for gap in their_gaps:
            gap_lower = gap.lower()
            matching = [s for s in our_skills.keys() if gap_lower in s.lower() or s.lower() in gap_lower]
            if matching:
                opportunities.append(
                    {
                        "gap": gap,
                        "source_chapter": chapter_name,
                        "matching_chapter": _agent_name,
                        "matching_skills": matching,
                        "member_count": our_intel.get("member_count", 0),
                    }
                )

    return opportunities


def get_network_trends() -> list[str]:
    """Aggregate trending topics across federation."""
    all_topics = []
    our_intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    all_topics.extend(our_intel.get("trending_topics", []))

    for knowledge in federation_knowledge.values():
        all_topics.extend(knowledge.get("trending_topics", []))

    return list(dict.fromkeys(all_topics))  # Deduplicated, order-preserving
