"""
Chapter auth — SSO / OIDC bridge.

Binds a chapter to an external IdP (Okta, Azure AD, Google Workspace,
or any generic OIDC provider). This module does NOT perform the OIDC
handshake itself — that's FastAPI endpoint territory with httpx. It
manages the *configuration* of the binding and helper utilities the
endpoints call.

Client secrets live in agent_private_memory, not here. This module
only touches the public IdP binding (issuer URL, client_id).

Public API
----------
init(pg_request)            — DI
set_sso_config(chapter_id, ...)   — upsert the IdP binding
get_sso_config(chapter_id)        — read current binding
clear_sso_config(chapter_id)      — disable SSO
valid_providers()                 — catalog for the A2UI Select

Pure validation
---------------
validate_issuer_url(url)          — must be https and well-formed
validate_provider(provider)       — must be in VALID_PROVIDERS
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

_pg_request: Callable[..., Awaitable[Any]] | None = None

VALID_PROVIDERS: list[dict[str, Any]] = [
    {"id": "okta", "label": "Okta", "discovery": "/.well-known/openid-configuration"},
    {"id": "azure_ad", "label": "Microsoft Entra ID (Azure AD)", "discovery": "/v2.0/.well-known/openid-configuration"},
    {"id": "google_workspace", "label": "Google Workspace", "discovery": "/.well-known/openid-configuration"},
    {"id": "generic_oidc", "label": "Generic OIDC provider", "discovery": "/.well-known/openid-configuration"},
]

VALID_PROVIDER_IDS = frozenset(p["id"] for p in VALID_PROVIDERS)

_RE_HTTPS = re.compile(r"^https://[a-zA-Z0-9][a-zA-Z0-9._-]*(\.[a-zA-Z]{2,})+(:\d+)?(/[^ ?#]*)?$")


def init(pg_request_fn: Callable[..., Awaitable[Any]]) -> None:
    global _pg_request
    _pg_request = pg_request_fn


# ── Validation ──────────────────────────────────────


def validate_issuer_url(url: str) -> tuple[bool, str]:
    if not url or not isinstance(url, str):
        return False, "issuer_url is required"
    if not url.startswith("https://"):
        return False, "issuer_url must use https://"
    if not _RE_HTTPS.match(url):
        return False, "issuer_url is malformed"
    if len(url) > 500:
        return False, "issuer_url too long (max 500)"
    return True, "ok"


def validate_provider(provider: str) -> tuple[bool, str]:
    if provider not in VALID_PROVIDER_IDS:
        return False, f"provider must be one of {sorted(VALID_PROVIDER_IDS)}"
    return True, "ok"


def valid_providers() -> list[dict[str, Any]]:
    return list(VALID_PROVIDERS)


# ── Config CRUD ─────────────────────────────────────


async def set_sso_config(
    chapter_id: str,
    provider: str,
    issuer_url: str,
    client_id: str,
    enforce_sso: bool = False,
    metadata: dict | None = None,
) -> dict:
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized — call init()")

    ok, reason = validate_provider(provider)
    if not ok:
        raise ValueError(reason)
    ok, reason = validate_issuer_url(issuer_url)
    if not ok:
        raise ValueError(reason)
    if not client_id or not isinstance(client_id, str) or len(client_id) > 256:
        raise ValueError("client_id must be 1..256 chars")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a dict")

    existing = await _pg_request(
        "GET",
        "chapter_sso_configs",
        params={"chapter_id": f"eq.{chapter_id}", "select": "chapter_id", "limit": "1"},
    )

    row = {
        "chapter_id": chapter_id,
        "provider": provider,
        "issuer_url": issuer_url,
        "client_id": client_id,
        "metadata": metadata or {},
        "enforce_sso": bool(enforce_sso),
    }

    if existing:
        await _pg_request(
            "PATCH",
            "chapter_sso_configs",
            params={"chapter_id": f"eq.{chapter_id}"},
            body=row,
        )
        return row
    inserted = await _pg_request("POST", "chapter_sso_configs", body=row)
    return inserted[0] if isinstance(inserted, list) and inserted else row


async def get_sso_config(chapter_id: str) -> dict | None:
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized")
    rows = await _pg_request(
        "GET",
        "chapter_sso_configs",
        params={"chapter_id": f"eq.{chapter_id}", "limit": "1"},
    )
    return rows[0] if rows else None


async def clear_sso_config(chapter_id: str) -> dict:
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized")
    await _pg_request(
        "DELETE",
        "chapter_sso_configs",
        params={"chapter_id": f"eq.{chapter_id}"},
    )
    return {"chapter_id": chapter_id, "sso": "disabled"}


# ── Federation allowlist ────────────────────────────


async def add_federation_peer(
    chapter_id: str,
    peer_chapter_id: str,
    added_by_agent_id: str,
    reason: str = "",
) -> dict:
    """Add a peer to this chapter's federation allowlist."""
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized")
    if chapter_id == peer_chapter_id:
        raise ValueError("cannot allowlist the chapter itself")
    if not peer_chapter_id or len(peer_chapter_id) > 128:
        raise ValueError("peer_chapter_id required, max 128 chars")

    row = {
        "chapter_id": chapter_id,
        "peer_chapter_id": peer_chapter_id,
        "added_by_agent_id": added_by_agent_id,
        "reason": (reason or "")[:500],
    }
    inserted = await _pg_request("POST", "chapter_federation_allowlist", body=row)
    return inserted[0] if isinstance(inserted, list) and inserted else row


async def remove_federation_peer(chapter_id: str, peer_chapter_id: str) -> dict:
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized")
    # PATCH doesn't delete; use DELETE via PostgREST path filter.
    await _pg_request(
        "DELETE",
        "chapter_federation_allowlist", params={"chapter_id": f"eq.{chapter_id}", "peer_chapter_id": f"eq.{peer_chapter_id}"},
    )
    return {"removed": peer_chapter_id}


async def list_federation_allowlist(chapter_id: str) -> list[dict]:
    if _pg_request is None:
        raise RuntimeError("chapter_auth not initialized")
    return (
        await _pg_request(
            "GET",
            "chapter_federation_allowlist",
            params={"chapter_id": f"eq.{chapter_id}", "order": "added_at.desc"},
        )
        or []
    )


async def is_peer_allowed(chapter_id: str, peer_chapter_id: str) -> bool:
    """Return True if peer_chapter_id is on this chapter's allowlist.

    A public chapter with an empty allowlist allows everyone (the social
    default). A private chapter that has populated even one allowlist
    entry switches to default-deny — unlisted peers are refused.
    """
    allowed = await list_federation_allowlist(chapter_id)
    if not allowed:
        return True  # open federation (social default)
    return any(a.get("peer_chapter_id") == peer_chapter_id for a in allowed)
