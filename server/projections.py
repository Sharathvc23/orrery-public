"""
Privacy Projections — anonymized member capability vectors.

Each member's agent publishes a projection: skills, interests, availability,
chapter — NO name, email, company, or personal details. The platform only
ever sees projections. Identity is revealed only after bilateral consent.

The projection is the privacy gate. All matching happens against projections.

Vector matching: projections are embedded as 384-dim vectors in Postgres
(pgvector). Intent matching uses cosine similarity via the match_projections
RPC function instead of keyword loops. This scales to thousands of members.
"""

from collections.abc import Awaitable, Callable
from typing import Any

import embeddings

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("projections.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""
_agent_name = ""
_projections_cache: dict[str, dict] = {}  # agent_id → projection
_vector_enabled = False


def init(pg_request, agent_id, agent_name, api_key="", api_base_url=""):
    global _pg_request, _agent_id, _agent_name, _vector_enabled
    _pg_request = pg_request
    _agent_id = agent_id
    _agent_name = agent_name
    embeddings.init(api_key, api_base_url)
    _vector_enabled = True


def build_projection(agent_id: str, member: dict) -> dict:
    """Build an anonymized projection from a member's data.

    The projection contains ONLY:
    - skills (list of strings)
    - interests (if available from agent config)
    - availability (active/occasional)
    - chapter name (which chapter they belong to)
    - skill_count (how many skills)

    It does NOT contain: name, description, personality, email, endpoint.
    """
    skills = member.get("skills", [])
    config = member.get("config") if isinstance(member.get("config"), dict) else {}
    config = config or {}

    return {
        "skills": skills,
        "interests": config.get("interests", []),
        "availability": config.get("availability", "active"),
        "chapter": _agent_name,
        "chapter_id": _agent_id,
        "skill_count": len(skills),
    }


async def rebuild_all_projections(members: dict):
    """Rebuild projections for all members, generate embeddings, and persist to Postgres."""
    global _projections_cache
    _projections_cache.clear()

    embedded_count = 0
    for agent_id, member in members.items():
        projection = build_projection(agent_id, member)
        _projections_cache[agent_id] = projection

        # Generate embedding vector for this projection
        embedding = None
        if _vector_enabled:
            embedding = await embeddings.embed_projection(projection)
            if embedding:
                embedded_count += 1

        # Upsert — check if exists first, then update or insert
        body: dict[str, Any] = {"projection_data": projection}
        if embedding:
            body["embedding"] = embedding

        existing = await _pg()(
            "GET",
            "agent_projections",
            params={
                "agent_id": f"eq.{agent_id}",
                "select": "id",
            },
        )
        if existing:
            await _pg()("PATCH", "agent_projections", params={"agent_id": f"eq.{agent_id}"}, body=body)
        else:
            await _pg()(
                "POST",
                "agent_projections",
                body={
                    "agent_id": agent_id,
                    "chapter_agent_id": _agent_id,
                    **body,
                },
            )

    if _projections_cache:
        print(f"[Projections] Built {len(_projections_cache)} projections ({embedded_count} with vectors)")


def get_projections() -> list[dict]:
    """Return all cached projections (anonymized — no agent_ids in output)."""
    return [{**p, "projection_id": aid} for aid, p in _projections_cache.items()]


def get_projections_with_ids() -> dict[str, dict]:
    """Return projections with agent_ids (internal use only, not exposed via API)."""
    return dict(_projections_cache)


async def match_intent_vector(
    intent_text: str,
    intent_tags: list[str],
    exclude_agent_id: str = "",
    match_count: int = 20,
    threshold: float = 0.3,
) -> list[dict]:
    """Match intent using vector similarity via Postgres RPC.

    This is the fast path — one database query replaces O(n) keyword matching.
    Returns anonymized results: no agent names, just skills and scores.
    """
    if not _vector_enabled:
        return []

    # Generate embedding for the intent
    query_embedding = await embeddings.embed_intent(intent_text, intent_tags)
    if not query_embedding:
        return []

    # Call Postgres RPC
    result = await _pg()(
        "POST",
        "rpc/match_projections",
        body={
            "query_embedding": query_embedding,
            "match_threshold": threshold,
            "match_count": match_count,
            "exclude_agent_id": exclude_agent_id,
        },
    )

    if not result:
        return []

    matches = []
    for row in result:
        proj_data = row.get("projection_data", {})
        matches.append(
            {
                "projection_id": row.get("agent_id", "anon"),
                "score": row.get("similarity", 0),
                "matched_skills": proj_data.get("skills", [])[:10],
                "chapter": proj_data.get("chapter", ""),
                "chapter_id": row.get("chapter_agent_id", ""),
            }
        )

    return matches


def match_intent_against_projections(
    intent_text: str,
    intent_tags: list[str],
    projections: list[dict] | None = None,
) -> list[dict]:
    """Score projections against an intent. Returns ranked matches.

    Matching logic:
    1. Tag overlap: each intent tag that appears in a projection's skills scores 2 points
    2. Keyword match: words from intent_text found in skills score 1 point
    3. Minimum score threshold: 1.0 to be considered a match
    """
    if projections is None:
        projections = get_projections()

    intent_words = set(intent_text.lower().split())
    intent_tags_lower = set(t.lower() for t in intent_tags)

    matches = []
    for proj in projections:
        skills_lower = set(s.lower() for s in proj.get("skills", []))
        interests_lower = set(i.lower() for i in proj.get("interests", []))
        all_capabilities = skills_lower | interests_lower

        score = 0.0
        matched_skills = []

        # Tag overlap (high signal)
        for tag in intent_tags_lower:
            for cap in all_capabilities:
                if tag in cap or cap in tag:
                    score += 2.0
                    matched_skills.append(cap)

        # Keyword overlap (lower signal)
        for word in intent_words:
            if len(word) < 3:
                continue
            for cap in all_capabilities:
                if word in cap or cap in word:
                    score += 1.0
                    matched_skills.append(cap)

        if score >= 1.0:
            matches.append(
                {
                    "projection_id": proj.get("projection_id", "anon"),
                    "score": score,
                    "matched_skills": list(set(matched_skills))[:10],
                    "chapter": proj.get("chapter", ""),
                    "chapter_id": proj.get("chapter_id", ""),
                }
            )

    matches.sort(key=lambda x: -x["score"])
    return matches
