"""Invite tokens for the ``invite`` join policy.

Generate (admin/leader), atomically consume (a joining agent redeems), list, and
revoke single-use-by-default invite tokens. The token is the AUTHORIZATION on the
open ``/api/members`` path, so:

  * tokens are unguessable (``secrets.token_urlsafe``),
  * consumption is ATOMIC — a single ``consume_org_invite`` SQL function checks
    (active, unexpired, uses < max_uses) and increments in one statement, so two
    concurrent redeems of a single-use token can't both succeed.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

_pg_request: Callable[..., Awaitable[Any]] | None = None

DEFAULT_TTL_DAYS = 7
_TABLE = "org_invites"


def init(pg_request: Callable[..., Awaitable[Any]]) -> None:
    global _pg_request
    _pg_request = pg_request


async def generate(created_by: str, *, max_uses: int = 1, ttl_days: int = DEFAULT_TTL_DAYS) -> dict | None:
    """Mint a new invite token. Single-use (max_uses=1) by default; ttl 7 days."""
    if _pg_request is None:
        return None
    token = secrets.token_urlsafe(32)
    max_uses = max(1, int(max_uses))
    expires_at = (datetime.now(UTC) + timedelta(days=max(1, int(ttl_days)))).isoformat()
    rows = await _pg_request(
        "POST",
        _TABLE,
        body={"token": token, "created_by": created_by, "max_uses": max_uses, "expires_at": expires_at},
    )
    if not rows:
        return None
    return {"token": token, "expires_at": expires_at, "max_uses": max_uses}


async def consume(token: str, *, agent_id: str) -> bool:
    """Atomically record one redemption. True iff the token was valid (active,
    unexpired, uses < max_uses). TOCTOU-safe via the consume_org_invite function."""
    if _pg_request is None or not token:
        return False
    try:
        res = await _pg_request(
            "POST", "rpc/consume_org_invite", body={"p_token": token, "p_agent_id": agent_id}
        )
    except Exception:  # noqa: BLE001 — a store error is a failed (denied) redeem, never a crash
        return False
    # PostgREST returns a scalar function result as the bare value, or wrapped.
    if isinstance(res, bool):
        return res
    if isinstance(res, list) and res:
        v = res[0]
        return bool(v.get("consume_org_invite") if isinstance(v, dict) else v)
    if isinstance(res, dict):
        return bool(res.get("consume_org_invite"))
    return bool(res)


async def list_active(limit: int = 100) -> list[dict]:
    """Active (non-revoked) invites, newest first — for the admin/leader view."""
    if _pg_request is None:
        return []
    rows = await _pg_request(
        "GET",
        _TABLE,
        params={
            "status": "eq.active",
            "select": "token,created_by,max_uses,uses,expires_at,created_at",
            "order": "created_at.desc",
            "limit": str(min(limit, 500)),
        },
    )
    return rows or []


async def revoke(token: str) -> bool:
    """Revoke a token so it can no longer be redeemed. True if a row changed."""
    if _pg_request is None or not token:
        return False
    rows = await _pg_request(
        "PATCH", _TABLE, params={"token": f"eq.{token}"}, body={"status": "revoked"}
    )
    return bool(rows)
