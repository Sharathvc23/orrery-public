"""Publish this sovereign agent to NANDA — NEST + the NANDA Index, ON CONSENT.

⚠️ PUBLICATION IS OPT-IN AND CONSENT-GATED. It did not used to be, and the change
is deliberate. Until this module was gated, launching the agent published it to
``https://nest.projectnanda.org`` — a live public registry — automatically, on
OPT-OUT semantics, with no consent artifact of any kind: ``should_announce()``
asked only "not opted out, configured, not a TEST- id". That made Orrery register
a real person to a public directory on **its own authority**, which is precisely
what the self-registration removal forbids. That change took self-registration
out of the SMB stack and left the agent runtime doing it; this closes that.

Now: **no valid owner-signed listing grant, no announce.** The gate is
``community_member.owner.listing_grant_verdict`` and it fails closed — an absent
binding, a self-granted one (grantor == grantee), one issued to a different
agent, an expired one, or OIDC evidence with no nonce all refuse, each by name.
Nothing auto-fires. ``COMMUNITY_MEMBER_NO_REGISTRY`` is kept as an additional
hard opt-out, so a user can stay private even after consenting.

Two layers, mirroring the org server's ``nanda_registry``:

  - **NEST-shaped registry** (``REGISTRY_URL``, NO DEFAULT) — the directory.
    A flat agent record: id, did:key, name, endpoint, facts URL, skills.
  - **NANDA Index** (``NANDA_INDEX_URL``, comma-separated, optional) — the
    production discovery layer. Carries the FULL canonical AgentFacts document
    (the same ``SmAgentFacts`` the agent serves at /agentfacts.json), so what's
    discoverable on the Index is byte-for-byte what the agent publishes.

Sovereign **and** discoverable: only public card data leaves the machine
(agent_id, did:key, name, offerings, the AgentFacts). Private keys, memory, the
consent ledger, and the owner's key never do.

Knobs:
  REGISTRY_URL                 registry base URL; unset or empty = publish to no registry
  NANDA_INDEX_URL              comma-separated NANDA Index URL(s); empty = none
  AGENT_PUBLIC_URL             the endpoint to advertise (default: the local URL)
  COMMUNITY_MEMBER_NO_REGISTRY truthy -> stay private even with consent on file

Gating also mirrors the org server: ``TEST-`` agents are kept off public
discovery, and an unconfigured agent never publishes. Every network failure is
swallowed — a registry that's down must never stop the agent from running
locally. A missing CONSENT is not a network failure and is never swallowed into
a publish.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from .config import Config

#: Kept ONLY to be named in the "nothing configured" notice, so an operator who
#: upgraded from a version that inherited it can see what changed. Never returned.
FORMER_DEFAULT_REGISTRY_URL = "https://nest.projectnanda.org"
REANNOUNCE_INTERVAL_SECONDS = 900
_TRUTHY = {"1", "true", "yes", "on"}


def registry_url() -> str:
    """The registry base URL to publish to, or ``""`` for "do not publish".

    ⚠️ **THERE IS NO DEFAULT.** Matches ``server/registry_policy.registry_url``
    exactly — one variable name must not mean opposite things in two runtimes of
    one repo, and the server dropped its default first: an unset
    ``REGISTRY_URL`` used to resolve to ``https://nest.projectnanda.org``, so a
    consenting owner who named no registry was published to a directory run by
    somebody else. Consent to be listed is consent to be listed *somewhere the
    owner chose*; a default supplies the "where" on the owner's behalf. NANDA is
    a discovery integration this agent can be pointed at, not a dependency it
    reaches for.

    Unset and explicitly empty both mean "none". The empty case is kept
    distinct in the tests because compose's ``${VAR:-default}`` substitutes for
    an empty value, which is why the default had to go from the code rather than
    from a compose file.
    """
    return (os.environ.get("REGISTRY_URL") or "").strip().rstrip("/")


def index_urls() -> list[str]:
    """The configured NANDA Index URL(s) — comma-separated, optional."""
    raw = os.environ.get("NANDA_INDEX_URL", "")
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def publication_targets() -> list[str]:
    """Every base URL a consenting agent would publish to: the registry, then
    the index(es). Empty when nothing is configured — consent with no target
    publishes nowhere, and callers say so rather than printing an empty URL."""
    targets = [u for u in [registry_url()] if u]
    for idx in index_urls():
        if idx not in targets:
            targets.append(idx)
    return targets


def is_opted_out() -> bool:
    """True when the user asked to stay off public discovery."""
    return os.environ.get("COMMUNITY_MEMBER_NO_REGISTRY", "").strip().lower() in _TRUTHY


def public_endpoint(local_url: str) -> str:
    """The endpoint to advertise: AGENT_PUBLIC_URL if set, else the local URL."""
    override = os.environ.get("AGENT_PUBLIC_URL", "").strip().rstrip("/")
    return override or local_url.rstrip("/")


def agent_did_key(config: Config) -> str:
    """This agent's ``did:key`` — the identity a listing consent is granted TO.

    Empty when real Ed25519 is unavailable (the HMAC fallback has no verify key,
    so there is no did:key to be the grantee of anything). Empty means refuse.
    """
    try:
        from .crypto import build_did_key

        return build_did_key(config.public_key)
    except Exception:  # noqa: BLE001 — no did:key is a refusal, not a crash
        return ""


def consent_verdict(config: Config) -> Any:
    """The owner's listing consent for THIS agent, as a named verdict.

    Returns an ``owner.GrantVerdict``; falsy when publication is not authorised,
    with ``.reason`` naming which check refused.
    """
    from . import owner

    return owner.listing_grant_verdict(owner.load_binding(config.home), agent_did_key(config))


def should_announce(config: Config) -> bool:
    """Whether this agent may be published.

    ⚠️ FAIL CLOSED. Requires a valid owner-signed listing grant on disk. Also
    False when opted out, unconfigured, or a ``TEST-`` agent (matching the org
    server's member gate). There is no default that publishes.
    """
    if is_opted_out():
        return False
    if not config.is_configured():
        return False
    if config.agent_id.startswith("TEST-"):
        return False
    # The consent check is LAST so the cheap gates short-circuit, but it is not
    # optional: without it this function returns True for any configured agent,
    # which is the behaviour that made the self-registration removal true on this path.
    return bool(consent_verdict(config))


def build_facts(config: Config, endpoint: str) -> dict | None:
    """This agent's canonical NANDA AgentFacts (``SmAgentFacts``) as a dict.

    The single source of truth — the same document the agent serves at
    /agentfacts.json (sm-bridge). None if sm-bridge can't build it."""
    try:
        from .sm_bridge_adapter import build_self_agentfacts

        facts = build_self_agentfacts(config, endpoint)
        if facts is not None:
            return facts.model_dump(mode="json", exclude_none=True)
    except Exception:
        pass
    return None


def build_payload(config: Config, endpoint: str, facts: dict | None = None) -> dict:
    """The flat NEST ``/api/agents`` record for this agent.

    Sourced from the canonical AgentFacts where possible (so the NEST did:key
    matches the served AgentFacts id), with config fallbacks. Public data only.
    """
    if facts is None:
        facts = build_facts(config, endpoint)
    did = (facts or {}).get("id", "")
    payload: dict = {
        "agent_id": config.agent_id,
        "name": (facts or {}).get("label") or config.name or config.agent_id,
        "endpoint": endpoint,
        "facts_url": f"{endpoint}/agentfacts.json",
        "description": (facts or {}).get("description") or config.description or "",
        "capabilities": list(config.skills or []),
        "agent_type": "skill",
        "status": "running",
    }
    if did:
        payload["did_key"] = did
    return payload


async def _register_nest(client: httpx.AsyncClient, base: str, agent_id: str, payload: dict, endpoint: str) -> bool:
    """POST to NEST; fall back to PUT on conflict. Best-effort.

    An empty ``base`` means the operator disabled publication (``REGISTRY_URL=``)
    and is returned as a clean no-op. Without this check the empty string is
    interpolated into a relative URL that raises inside httpx and is swallowed
    below, so "publication disabled" and "the registry is unreachable" produced
    the identical silent ``False``.
    """
    if not base:
        return False
    try:
        resp = await client.post(f"{base}/api/agents", json=payload, timeout=10.0)
        if resp.status_code < 300:
            return True
        resp2 = await client.put(
            f"{base}/api/agents/{agent_id}",
            json={"status": "running", "endpoint": endpoint},
            timeout=10.0,
        )
        return resp2.status_code < 300
    except Exception:
        return False


async def _register_index(
    client: httpx.AsyncClient, index_url: str, agent_id: str, facts: dict, facts_url: str
) -> bool:
    """Register the FULL AgentFacts on one NANDA Index. Best-effort.

    Payload shape mirrors the org server's ``nanda_registry`` Index call so a
    sovereign agent and an org-published member look identical to the Index."""
    try:
        payload = {"agent_id": agent_id, "facts": facts, "facts_url": facts_url, "status": "running"}
        resp = await client.post(f"{index_url}/api/agents", json=payload, timeout=10.0)
        return resp.status_code < 300
    except Exception:
        return False


async def announce(
    config: Config,
    *,
    local_url: str,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """Publish/refresh this agent on NEST + any configured NANDA Index.

    Returns True iff the NEST registration succeeded (the always-present layer).
    Index registration is additive and best-effort. Never raises — a registry
    problem must not affect the local agent.
    """
    if not should_announce(config):
        return False

    endpoint = public_endpoint(local_url)
    facts = build_facts(config, endpoint)
    payload = build_payload(config, endpoint, facts)
    facts_url = f"{endpoint}/agentfacts.json"

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient()
    try:
        nest_ok = await _register_nest(client, registry_url(), config.agent_id, payload, endpoint)
        # NANDA Index(es) — full AgentFacts, additive, never gates the result.
        if facts is not None:
            for idx in index_urls():
                await _register_index(client, idx, config.agent_id, facts, facts_url)
        return nest_ok
    except Exception:
        return False
    finally:
        if owns_client:
            await client.aclose()


async def announce_loop(
    config: Config,
    *,
    local_url: str,
    interval: int = REANNOUNCE_INTERVAL_SECONDS,
) -> None:
    """Announce once at startup, then re-announce every ``interval`` seconds.

    Bulletproof: any exception is swallowed and the loop continues, so this can
    be gathered alongside the web server and agent loop without ever bringing
    them down. Returns immediately (no loop) when opted out or not eligible.
    """
    if not should_announce(config):
        return
    if not publication_targets():
        # Consent is on file but the owner named no registry and no index.
        # Nothing to publish TO, so there is nothing to loop over — and a loop
        # that ran anyway would look, from the outside, like publication.
        print(
            "[registry] listing consent is on file, but REGISTRY_URL and NANDA_INDEX_URL are "
            "both unset — this agent publishes to no registry. Set one to opt in. "
            f"(Earlier versions silently defaulted to {FORMER_DEFAULT_REGISTRY_URL}.)",
            flush=True,
        )
        return
    while True:
        try:
            await announce(config, local_url=local_url)
        except Exception:
            pass
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
