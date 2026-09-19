"""
Intent System — privacy-preserving, intent-based matching.

Members express needs ("I need someone who knows Rust for edge computing").
The system matches against anonymized projections across the federation.
Identity is never revealed until mutual consent via consent_gate.
"""

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx

import projections

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("intents.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""
_agent_name = ""


def init(pg_request, agent_id, agent_name):
    global _pg_request, _agent_id, _agent_name
    _pg_request = pg_request
    _agent_id = agent_id
    _agent_name = agent_name


async def create_intent(requester_agent_id: str, intent_text: str, intent_tags: list[str]) -> str:
    """Create a new intent and return its ID."""
    intent_id = str(uuid.uuid4())
    await _pg()(
        "POST",
        "agent_intents",
        body={
            "id": intent_id,
            "chapter_agent_id": _agent_id,
            "requester_agent_id": requester_agent_id,
            "intent_text": intent_text,
            "intent_tags": intent_tags,
            "status": "active",
        },
    )
    print(f"[Intents] Created intent {intent_id[:8]} by @{requester_agent_id}: {intent_text[:60]}")
    return intent_id


async def match_intent(intent_id: str) -> dict:
    """Match an intent against local projections. Returns anonymous results."""
    # Load the intent
    data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "id": f"eq.{intent_id}",
            "select": "intent_text,intent_tags,requester_agent_id",
        },
    )
    if not data:
        return {"error": "Intent not found"}

    intent = data[0]
    intent_text = intent.get("intent_text", "")
    intent_tags = intent.get("intent_tags", [])
    requester = intent.get("requester_agent_id", "")

    # Match against projections — try vector similarity first, fall back to keyword
    matches = await projections.match_intent_vector(intent_text, intent_tags, exclude_agent_id=requester)
    if not matches:
        # Fallback to keyword matching
        all_projections = projections.get_projections()
        filtered = [p for p in all_projections if p.get("projection_id") != requester]
        matches = projections.match_intent_against_projections(intent_text, intent_tags, filtered)

    # Update intent with match count
    await _pg()(
        "PATCH",
        "agent_intents",
        params={"id": f"eq.{intent_id}"},
        body={
            "matches_found": len(matches),
            "match_details": [
                {"chapter": m["chapter"], "score": m["score"], "skills": m["matched_skills"]} for m in matches[:10]
            ],
            "status": "matched" if matches else "active",
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )

    # Create pending response records for matched agents
    for match in matches[:10]:
        agent_id = match.get("projection_id", "")
        if agent_id and agent_id != "anon":
            await _pg()(
                "POST",
                "agent_intent_responses",
                body={
                    "intent_id": intent_id,
                    "responder_agent_id": agent_id,
                    "responder_chapter_id": _agent_id,
                    "response": "pending",
                },
            )

    print(f"[Intents] Matched intent {intent_id[:8]}: {len(matches)} local matches")

    # Emit intent.matched only when we actually have matches — an empty
    # match is not a stream-worthy event. match_score is the average of
    # the per-match scores normalized to [0, 1].
    if matches:
        try:
            import event_bus  # local import — avoid circular at module load

            matched_ids = [m.get("projection_id", "") for m in matches[:10] if m.get("projection_id")]
            avg_raw = sum(m.get("score", 0) for m in matches[:10]) / max(1, len(matches[:10]))
            # Project server-internal scores into [0, 1] for the schema.
            # Most server scoring is already 0..1; clamp for safety.
            score_01 = max(0.0, min(1.0, float(avg_raw if avg_raw <= 1 else avg_raw / 100)))
            import asyncio as _asyncio

            _asyncio.create_task(
                event_bus.safe_publish(
                    "intent.matched",
                    {
                        "intent_id": intent_id,
                        "submitter_agent_id": requester,
                        "matched_agent_ids": matched_ids,
                        "match_score": score_01,
                    },
                )
            )

            # ARP — receipt for the submitter when their intent gets
            # matched. Counterparty is the top match. Category is
            # commitment_entered because the server is surfacing a
            # potential match that the submitter has implicitly opted
            # into via their intent submission.
            import arp as arp_mod

            principal_did = arp_mod.did_key_for_member(requester)
            if principal_did:
                top_match_id = matched_ids[0] if matched_ids else ""
                counterparty_did = arp_mod.did_key_for_member(top_match_id) if top_match_id else None
                summary = (
                    f"Your intent was matched with {len(matched_ids)} member{'s' if len(matched_ids) != 1 else ''}."
                )
                _asyncio.create_task(
                    arp_mod.emit_chapter_action(
                        principal_did=principal_did,
                        category="commitment_entered",
                        human_summary=summary,
                        counterparty_did=counterparty_did,
                        counterparty_label=top_match_id or None,
                        machine_payload={
                            "intent_id": intent_id,
                            "matched_agent_ids": matched_ids,
                            "match_score": score_01,
                        },
                    )
                )
        except Exception:  # noqa: BLE001
            # Telemetry must not break business logic.
            pass

    return {
        "intent_id": intent_id,
        "local_matches": len(matches),
        "matched_skills": list(set(s for m in matches for s in m["matched_skills"]))[:10],
    }


async def match_intent_federation(intent_id: str, federation: dict) -> dict:
    """Match an intent against all federation chapters. Returns anonymous counts."""
    data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "id": f"eq.{intent_id}",
            "select": "intent_text,intent_tags",
        },
    )
    if not data:
        return {"error": "Intent not found"}

    intent = data[0]
    results = []

    for chapter_id, chapter_data in federation.items():
        if chapter_data.get("status") != "online":
            continue
        endpoint = chapter_data.get("endpoint", "")
        if not endpoint:
            continue

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{endpoint.rstrip('/')}/api/intents/match",
                    json={
                        "intent_text": intent.get("intent_text", ""),
                        "intent_tags": intent.get("intent_tags", []),
                    },
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    result = resp.json()
                    if result.get("match_count", 0) > 0:
                        results.append(result)
        except Exception as e:
            print(f"[Intents] Federation match with {chapter_id} failed: {e}")

    total_remote = sum(r.get("match_count", 0) for r in results)

    # Update intent with federation results
    if results:
        existing = await _pg()(
            "GET",
            "agent_intents",
            params={
                "id": f"eq.{intent_id}",
                "select": "matches_found,match_details",
            },
        )
        if existing:
            current = existing[0]
            new_total = current.get("matches_found", 0) + total_remote
            current_details = current.get("match_details") or []
            for r in results:
                current_details.append(
                    {
                        "chapter": r.get("chapter_name", r.get("chapter_id", "?")),
                        "match_count": r.get("match_count", 0),
                        "skills": r.get("matched_skills", []),
                        "remote": True,
                    }
                )
            await _pg()(
                "PATCH",
                "agent_intents",
                params={"id": f"eq.{intent_id}"},
                body={
                    "matches_found": new_total,
                    "match_details": current_details,
                    "status": "matched" if new_total > 0 else "active",
                },
            )

    print(
        f"[Intents] Federation match for {intent_id[:8]}: {total_remote} remote matches across {len(results)} chapters"
    )
    return {
        "intent_id": intent_id,
        "remote_matches": total_remote,
        "chapters_with_matches": len(results),
        "details": results,
    }


async def get_active_intents(agent_id: str | None = None) -> list[dict]:
    """List active intents, optionally filtered by requester."""
    params = {
        "chapter_agent_id": f"eq.{_agent_id}",
        "status": "in.(active,matched)",
        "order": "created_at.desc",
        "limit": "20",
    }
    if agent_id:
        params["requester_agent_id"] = f"eq.{agent_id}"

    data = await _pg()("GET", "agent_intents", params=params)
    return data or []


async def get_intent_detail(intent_id: str, caller: str) -> dict:
    """Get full detail for a single intent, authorized to ``caller``.

    The full row exposes ``requester_agent_id`` + raw ``intent_text``, so only
    the requester or a matched responder may read it. An unrelated caller
    gets the same ``Not found`` shape as a missing intent — no enumeration
    oracle.
    """
    data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "id": f"eq.{intent_id}",
        },
    )
    if not data:
        return {"error": "Not found"}

    intent = data[0]

    # Responses also carry responder_agent_id for the authorization check;
    # it is stripped from the response shape below.
    responses = (
        await _pg()(
            "GET",
            "agent_intent_responses",
            params={
                "intent_id": f"eq.{intent_id}",
                "select": "response,responder_agent_id,responder_chapter_id,created_at",
            },
        )
        or []
    )

    responder_ids = {r.get("responder_agent_id") for r in responses}
    if caller != intent.get("requester_agent_id") and caller not in responder_ids:
        return {"error": "Not found"}

    intent["responses"] = [
        {k: r.get(k) for k in ("response", "responder_chapter_id", "created_at")} for r in responses
    ]
    return intent


async def cancel_intent(intent_id: str, requester_agent_id: str) -> dict:
    """Cancel an intent. Only the requester can cancel."""
    data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "id": f"eq.{intent_id}",
            "requester_agent_id": f"eq.{requester_agent_id}",
        },
    )
    if not data:
        return {"error": "Intent not found or not yours"}

    await _pg()(
        "PATCH",
        "agent_intents",
        params={"id": f"eq.{intent_id}"},
        body={
            "status": "cancelled",
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )
    return {"cancelled": True}
