"""The org's outbound-send endpoint — what an agent's outbox drains into.

Thin, like ``routes/crm``: validation, the ``send_external`` gate, the transport
choice and the receipt all live in ``external_send`` so there is exactly one send
path. A route that decided any of that separately would be a second policy.

⚠️ STATUS CODES ARE THE CONTRACT HERE, because the caller is an unattended drain
loop rather than a person:

  * **200** — sent (to Klaviyo, or to the sandbox; the body says which).
  * **202** — accepted, NOT sent: an operator approval is queued. The drain must
    KEEP the message and retry later. A 4xx here would be read as "give up" and
    the message would be dropped for the crime of waiting on a human.
  * **422** — the message itself is wrong (bad address, empty body). Retrying is
    pointless; the drain should surface it, not loop.
  * **503** — governance or the upstream is unavailable. Retry with backoff.

The distinction between 202 and 422 is the one that matters: they are the two
outcomes an automated caller has to tell apart, and getting them backwards either
discards mail or spins forever.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import external_send

router = APIRouter()

#: Reasons that mean "try again later", not "this message is wrong".
_RETRYABLE = {"governance_unavailable", "upstream_error"}


class ExternalMessage(BaseModel):
    to: str
    subject: str
    body: str
    metric: str = "Orrery Agent Message"


def _actor(request: Request) -> str:
    """The signed-in caller, from the identity the auth middleware established —
    never a body field, which a caller could set to anyone."""
    actor = getattr(request.state, "agent_id", None) or request.headers.get("X-Agent-ID", "")
    if not actor:
        raise HTTPException(status_code=401, detail={"reason": "unidentified_caller"})
    return str(actor)


@router.post("/api/send/external")
async def send_external_message(body: ExternalMessage, request: Request) -> JSONResponse:
    try:
        result = await external_send.send_external(actor_agent_id=_actor(request), **body.model_dump())
    except external_send.SendRefused as e:
        if e.reason == "pending_approval":
            return JSONResponse(
                status_code=202,
                content={
                    "status": "pending_approval",
                    "reason": e.detail,
                    "approval_id": (e.approval or {}).get("id"),
                },
            )
        raise HTTPException(
            status_code=503 if e.reason in _RETRYABLE else 422,
            detail={"reason": e.reason, "detail": e.detail},
        ) from e
    return JSONResponse(status_code=200, content=result)


@router.get("/api/send/external/mode")
async def send_mode() -> dict:
    """Whether this org can actually send, and by what route.

    ⚠️ Exists so "are we sandboxed?" is an observable fact rather than an
    assumption. Every incident in this class starts with someone believing a
    deployment was in sandbox because that is how it was configured last time.
    Deliberately exposes only the MODE — never the key, nor whether one is set,
    since that is enough to confirm a guess about the environment.
    """
    return {
        "live_sends_enabled": external_send.live_sends_enabled(),
        "transport": "klaviyo" if external_send.live_sends_enabled() else "sandbox",
        "sandbox_recipients": "RFC 2606 reserved only (example.com, *.test, *.invalid)",
    }
