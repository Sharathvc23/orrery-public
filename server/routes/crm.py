"""CRM service-verb routes — write a contact, deal or interaction THROUGH the org.

Thin. Every rule that matters — validation, the governance gate, the receipt —
lives in ``crm_store`` so there is exactly one write path. A route that
validated separately would be a second source of truth about what a valid
record is, and the two would drift.

⚠️ These are MUTATION endpoints on an org-side record type, so they sit behind
the same signed-caller auth as every other write surface here, AND behind PR1's
``record_write`` operational approval. A write with no approved grant comes back
``202 pending_approval`` naming what it is waiting on — not 200, because a caller
that reads a 2xx as "stored" would carry on as though the record existed.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import crm_store

router = APIRouter()


def _actor(request: Request) -> str:
    """The signed-in caller. The auth middleware has already verified the
    signature; this reads the identity it established rather than trusting a
    body field, which a caller could set to anyone."""
    actor = getattr(request.state, "agent_id", None) or request.headers.get("X-Agent-ID", "")
    if not actor:
        raise HTTPException(status_code=401, detail={"reason": "unidentified_caller"})
    return str(actor)


def _handle(exc: crm_store.CrmError) -> HTTPException:
    # 422 for a rejected record, 503 when storage or governance is unavailable —
    # a caller must be able to tell "fix your input" from "retry later".
    unavailable = {"no_database", "governance_unavailable", "write_failed"}
    return HTTPException(
        status_code=503 if exc.reason in unavailable else 422,
        detail={"reason": exc.reason, "detail": exc.detail},
    )


def _reply(result: dict) -> JSONResponse:
    """One place where a mutation result becomes a response.

    ⚠️ A write awaiting an operator grant is 202, never 200. Every one of these
    routes can return without having written anything — that is the normal path,
    not an error — and a caller that read the default 200 as "stored" would go on
    to reference a record that does not exist. 202 with the pending status and
    the action_key is the honest answer: accepted, not applied, here is what it
    is waiting on.
    """
    pending = result.get("status") == "pending_approval"
    return JSONResponse(status_code=202 if pending else 200, content=result)


class ContactCreate(BaseModel):
    name: str
    email: str | None = None
    org: str | None = None
    stage: str = "lead"


class StageChange(BaseModel):
    stage: str


class DealCreate(BaseModel):
    contact_id: str
    title: str
    amount_minor: int
    currency: str = "USD"


class InteractionCreate(BaseModel):
    contact_id: str
    kind: str
    summary: str
    occurred_at: str | None = None


@router.post("/api/crm/contacts")
async def create_contact(body: ContactCreate, request: Request) -> JSONResponse:
    try:
        return _reply(await crm_store.create_contact(actor_agent_id=_actor(request), **body.model_dump()))
    except crm_store.CrmError as e:
        raise _handle(e) from e


# POST, not PATCH: the shared agent client (A2AClient) signs GET/POST/DELETE
# only, and a state transition is an action rather than a field edit. Adding a
# verb to the shared client for one route would be the wider change.
@router.post("/api/crm/contacts/{contact_id}/stage")
async def update_contact_stage(contact_id: str, body: StageChange, request: Request) -> JSONResponse:
    try:
        return _reply(
            await crm_store.update_contact_stage(
                actor_agent_id=_actor(request), contact_id=contact_id, stage=body.stage
            )
        )
    except crm_store.CrmError as e:
        raise _handle(e) from e


@router.post("/api/crm/deals")
async def create_deal(body: DealCreate, request: Request) -> JSONResponse:
    try:
        return _reply(await crm_store.create_deal(actor_agent_id=_actor(request), **body.model_dump()))
    except crm_store.CrmError as e:
        raise _handle(e) from e


@router.post("/api/crm/deals/{deal_id}/stage")
async def set_deal_stage(deal_id: str, body: StageChange, request: Request) -> JSONResponse:
    try:
        return _reply(await crm_store.set_deal_stage(actor_agent_id=_actor(request), deal_id=deal_id, stage=body.stage))
    except crm_store.CrmError as e:
        raise _handle(e) from e


@router.post("/api/crm/interactions")
async def log_interaction(body: InteractionCreate, request: Request) -> JSONResponse:
    try:
        return _reply(await crm_store.log_interaction(actor_agent_id=_actor(request), **body.model_dump()))
    except crm_store.CrmError as e:
        raise _handle(e) from e


@router.get("/api/crm/contacts")
async def list_contacts(stage: str | None = None, limit: int = 100) -> dict:
    try:
        return {"contacts": await crm_store.list_contacts(stage=stage, limit=limit)}
    except crm_store.CrmError as e:
        raise _handle(e) from e


@router.get("/api/crm/contacts/{contact_id}/history")
async def contact_history(contact_id: str, limit: int = 200) -> dict:
    return {"interactions": await crm_store.contact_history(contact_id, limit=limit)}
