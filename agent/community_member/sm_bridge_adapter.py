"""Sovereign agent ↔ sm-bridge adapter.

Makes a single community-member agent projectnanda-compatible by emitting the
**canonical NANDA AgentFacts** shape from ``sm-bridge`` (``SmAgentFacts``),
served at ``GET /agentfacts.json``.

This module used to also mount sm-bridge's registry routers at ``/sm-bridge/*``,
mirroring the org server. That was removed: ``LocalAuthMiddleware`` is
deny-by-default over an exact-path ``OPEN_ROUTES`` allowlist and no
``/sm-bridge/*`` entry was ever added, so every one of those routes answered 401
to the NANDA/NEST consumers the mount existed to serve. The document it was
meant to publish is already public at ``/agentfacts.json``, which IS on the
allowlist. The org server still mounts the routers, where they are reachable and
serve a registry of many members rather than of one.

This replaces the agent's old bespoke ``nanda_models.NandaAgentFacts`` (which
declared a made-up ``did:nanda:`` id and, wrongly, ``hmac-sha256`` auth even
though the agent signs with Ed25519). sm-bridge is the upstream source of truth
for the AgentFacts schema; we never fork it.

Public API:
  build_self_agentfacts(config, base_url) -> SmAgentFacts | None
      The agent's own NANDA AgentFacts. Used by GET /agentfacts.json.
"""

from __future__ import annotations

# sm-bridge imports live inside functions so this module imports even when
# sm-bridge is absent (graceful no-op), matching the server adapter.


def _agent_did(config, base_url: str) -> str:
    """The agent's DID. Prefer did:key from the Ed25519 public key (self-
    contained, verifiable offline); fall back to did:web from the host."""
    if config.public_key:
        try:
            from .crypto import build_did_key

            return build_did_key(config.public_key)
        except Exception:
            pass
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]
    return f"did:web:{host}" if host else f"did:web:{config.agent_id}"


def _skill_names(config) -> list[str]:
    raw = config.skills or []
    if isinstance(raw, str):
        raw = [s.strip() for s in raw.split(",") if s.strip()]
    return [s for s in raw if isinstance(s, str) and s.strip()][:20]


def _skill_urn(name: str) -> str:
    return f"urn:nanda:skill:{name.lower().replace(' ', '-')}"


def _provider(config, base: str, did: str, organization: str | None, url: str | None):
    """The ``SmProvider`` for this document — see ``build_self_agentfacts``.

    Imported inside the function body so this module still imports without
    sm-bridge, matching the rest of the adapter.
    """
    from sm_bridge import SmProvider

    if organization is None and url is None:
        # No override: the agent is its own provider, so its did:key genuinely
        # identifies the provider.
        return SmProvider(name=config.name or config.agent_id, url=config.chapter_url or base, did=did)
    return SmProvider(
        name=organization if organization is not None else (config.name or config.agent_id),
        url=url if url is not None else (config.chapter_url or base),
        # deliberately absent: this DID is the agent's, not this provider's.
        did=None,
    )


def build_self_agentfacts(
    config,
    base_url: str,
    *,
    exposed_skills: list[str] | None = None,
    supports_streaming: bool = True,
    authentication_methods: list[str] | None = None,
    provider_organization: str | None = None,
    provider_url: str | None = None,
):
    """Build this agent's canonical NANDA ``SmAgentFacts``.

    Returns None if sm-bridge isn't installed (caller falls back).

    ``exposed_skills`` names capabilities the CALLER serves for this agent, for
    hosts that expose actions the agent's own config does not list. The SMB host
    answers ``POST /t/<tenant>/book`` for every tenant while the tenant's config
    carries no skills, so without this its AgentFacts fell back to the
    "general-purpose agent" placeholder below — a resolving client was told the
    agent does nothing in particular, on a document whose purpose is to say what
    it does. They are merged with the configured names rather than replacing
    them, because both are true of the agent.

    ``supports_streaming`` / ``authentication_methods`` are per-surface, same
    reasoning as ``a2a_card.build_agent_card``'s equivalents: this function is
    shared between the member runtime (which genuinely implements streaming and
    genuinely authenticates with Ed25519) and ``smb_host`` (whose tenant routes
    do neither). Defaults preserve the member runtime's truthful values; a
    caller whose surface cannot back them must say so rather than inherit them.
    ``authentication_methods=["none"]`` is sm-bridge's own documented value for
    "no authentication required" (see ``SmAuthentication``'s docstring) — used
    here rather than an empty list, which that field does not document as
    meaningful.

    ``provider_organization`` / ``provider_url`` name WHO OPERATES THE ENDPOINT,
    the same per-surface override ``a2a_card.build_agent_card`` already takes,
    and for the same reason. sm-bridge documents ``SmProvider`` as "the
    organization running the agent", so for the member runtime — where the
    person whose agent it is runs the process and holds the key — the default
    below (the agent's own name) is correct and stays the default. It is NOT
    correct for a host that runs OTHER people's agents: ``smb_host`` holds every
    tenant's key, serves every tenant's routes from one process, and the tenant
    name it would otherwise put here is a display label nobody verified. Such a
    caller must supply its own operator identity rather than let the tenant
    stand in as if the tenant ran itself.

    An override also drops ``provider.did``. That field is documented as the
    PROVIDER's DID; the value available here is the AGENT's did:key. Emitting it
    beside a provider name that is somebody else asserts that the operator's key
    is the tenant's key — the grantor-collapsed-into-grantee shape — so when the
    provider is a third party we say nothing about its DID instead of saying
    something false. With no override the agent IS its own provider and the
    did:key genuinely identifies it, so it is emitted.
    """
    try:
        from sm_bridge import (
            SmAgentFacts,
            SmAuthentication,
            SmCapabilities,
            SmEndpoints,
            SmSkill,
        )
    except ImportError:
        return None

    base = base_url.rstrip("/")
    did = _agent_did(config, base)
    names = _skill_names(config)
    for extra in exposed_skills or []:
        if extra and extra not in names:
            names.append(extra)
    sm_skills = [SmSkill(id=_skill_urn(n), description=f"Expertise in {n}") for n in names]
    if not sm_skills:
        # NANDA AgentFacts requires >=1 skill (sm-bridge minItems:1). Advertise a
        # general capability when this agent has none configured yet.
        sm_skills = [SmSkill(id=_skill_urn("general"), description="General-purpose agent")]

    return SmAgentFacts(
        id=did,
        agent_name=config.agent_id,
        handle=f"@{config.agent_id}",
        label=config.name or config.agent_id,
        description=(config.description or f"Sovereign agent @{config.agent_id}")[:500],
        # Source from the SDK __version__ so AgentFacts and the A2A card agree on
        # the agent version (they diverged: agentfacts 1.0.0 vs a2a __version__).
        version=__import__("community_member").__version__,
        provider=_provider(config, base, did, provider_organization, provider_url),
        endpoints=SmEndpoints(
            # The agent's A2A JSON-RPC transport is served at POST / (root).
            static=[f"{base}/"],
        ),
        capabilities=SmCapabilities(
            modalities=["text"],
            skills=[s.id for s in sm_skills],
            # The agent signs every request with Ed25519 (see auth.py) — NOT
            # hmac, which the old bespoke facts wrongly advertised.
            authentication=SmAuthentication(
                methods=authentication_methods if authentication_methods is not None else ["ed25519", "did-auth"]
            ),
            streaming=supports_streaming,
        ),
        skills=sm_skills,
    )


__all__ = ["build_self_agentfacts"]
