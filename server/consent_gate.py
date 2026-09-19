"""
Consent Gate — mutual consent protocol for identity revelation.

The privacy boundary: identity is NEVER revealed until both the
requester AND the matched agent accept the introduction.

Flow:
1. Intent matched → pending response created (no identity shared)
2. Matched agent sees anonymized intent ("someone needs X expertise")
3. Agent responds: accept, decline, or counter
4. If both accept → mutual consent → identities revealed → introduction
"""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("consent_gate.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""


def init(pg_request, agent_id):
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


async def get_pending_for_agent(agent_id: str) -> list[dict]:
    """Get intents where this agent is matched but hasn't responded.

    Returns anonymized intent data — no requester identity.
    """
    responses = await _pg()(
        "GET",
        "agent_intent_responses",
        params={
            "responder_agent_id": f"eq.{agent_id}",
            "response": "eq.pending",
            "select": "id,intent_id,created_at",
        },
    )
    if not responses:
        return []

    pending = []
    for resp in responses:
        intent_data = await _pg()(
            "GET",
            "agent_intents",
            params={
                "id": f"eq.{resp['intent_id']}",
                "select": "id,intent_text,intent_tags,status,created_at",
            },
        )
        if intent_data and intent_data[0].get("status") in ("active", "matched"):
            intent = intent_data[0]
            pending.append(
                {
                    "response_id": resp["id"],
                    "intent_id": intent["id"],
                    "intent_text": intent["intent_text"],
                    "intent_tags": intent.get("intent_tags", []),
                    "received_at": resp["created_at"],
                    # NO requester identity here — privacy preserved
                }
            )

    return pending


async def respond_to_intent(intent_id: str, responder_agent_id: str, response: str, counter_text: str = "") -> dict:
    """Record a response to an intent match.

    Returns whether mutual consent was achieved.
    """
    if response not in ("accept", "decline", "counter"):
        return {"error": "Response must be accept, decline, or counter"}

    # The responder must have been MATCHED to this intent — the matcher creates
    # a response row for (intent_id, responder). Without this gate, anyone could
    # 'accept' an arbitrary intent and unlock the requester's PII via
    # check_mutual_consent. No row → not a party to this intent → no
    # consent, no state change, no reveal.
    matched = await _pg()(
        "GET",
        "agent_intent_responses",
        params={
            "intent_id": f"eq.{intent_id}",
            "responder_agent_id": f"eq.{responder_agent_id}",
            "select": "id,response",
        },
    )
    if not matched:
        return {"error": "no matching intent for this responder", "mutual_consent": False}

    body = {
        "response": response,
        "counter_text": counter_text if response == "counter" else None,
    }
    if response == "accept":
        body["consented_at"] = datetime.now(UTC).isoformat()

    await _pg()(
        "PATCH",
        "agent_intent_responses",
        params={"intent_id": f"eq.{intent_id}", "responder_agent_id": f"eq.{responder_agent_id}"},
        body=body,
    )

    # Double opt-in: the requester opted in by creating the intent; a genuinely
    # matched responder opting in with 'accept' completes the mutual consent
    # that lets check_mutual_consent reveal identities.
    if response == "accept":
        return {"mutual_consent": True, "response": response}

    return {"mutual_consent": False, "response": response}


async def check_mutual_consent(intent_id: str, responder_agent_id: str) -> dict | None:
    """After mutual consent, reveal identities and build introduction.

    This is the ONLY place where identity crosses the privacy boundary.
    """
    # Load intent to get requester
    intent_data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "id": f"eq.{intent_id}",
            "select": "requester_agent_id,intent_text,intent_tags",
        },
    )
    if not intent_data:
        return None

    requester_id = intent_data[0]["requester_agent_id"]

    # Load both agents' public profiles
    requester = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{requester_id}",
            "select": "agent_id,name,skills,profile_type,interests,linkedin_url",
        },
    )
    responder = await _pg()(
        "GET",
        "agents",
        params={
            "agent_id": f"eq.{responder_agent_id}",
            "select": "agent_id,name,skills,profile_type,interests,linkedin_url",
        },
    )

    if not requester or not responder:
        return None

    # Mark intent as fulfilled
    await _pg()(
        "PATCH",
        "agent_intents",
        params={"id": f"eq.{intent_id}"},
        body={
            "status": "fulfilled",
        },
    )

    # Track activity for both parties
    import activity_tracker

    await activity_tracker.track(
        requester_id,
        "intent_introduced",
        {
            "partner": responder[0].get("name", "?"),
            "intent": intent_data[0]["intent_text"][:100],
        },
    )
    await activity_tracker.track(
        responder_agent_id,
        "intent_introduced",
        {
            "partner": requester[0].get("name", "?"),
            "intent": intent_data[0]["intent_text"][:100],
        },
    )

    return {
        "requester": {
            "agent_id": requester[0]["agent_id"],
            "name": requester[0].get("name", "?"),
            "skills": requester[0].get("skills", []),
            "profile_type": requester[0].get("profile_type", "member"),
        },
        "responder": {
            "agent_id": responder[0]["agent_id"],
            "name": responder[0].get("name", "?"),
            "skills": responder[0].get("skills", []),
            "profile_type": responder[0].get("profile_type", "member"),
        },
        "intent_text": intent_data[0]["intent_text"],
        "intent_tags": intent_data[0].get("intent_tags", []),
    }


async def get_introductions(agent_id: str) -> list[dict]:
    """Get all completed introductions for an agent (both as requester and responder)."""
    # As responder
    resp_data = await _pg()(
        "GET",
        "agent_intent_responses",
        params={
            "responder_agent_id": f"eq.{agent_id}",
            "response": "eq.accept",
            "select": "intent_id,consented_at",
        },
    )

    # As requester
    req_data = await _pg()(
        "GET",
        "agent_intents",
        params={
            "requester_agent_id": f"eq.{agent_id}",
            "status": "eq.fulfilled",
            "select": "id,intent_text,updated_at",
        },
    )

    intros = []

    for resp in resp_data or []:
        intro = await check_mutual_consent(resp["intent_id"], agent_id)
        if intro:
            intro["consented_at"] = resp.get("consented_at")
            intros.append(intro)

    for req in req_data or []:
        # Find the responder who accepted
        acceptors = await _pg()(
            "GET",
            "agent_intent_responses",
            params={
                "intent_id": f"eq.{req['id']}",
                "response": "eq.accept",
                "select": "responder_agent_id,consented_at",
            },
        )
        for acc in acceptors or []:
            intro = await check_mutual_consent(req["id"], acc["responder_agent_id"])
            if intro:
                intro["consented_at"] = acc.get("consented_at")
                intros.append(intro)

    return intros
