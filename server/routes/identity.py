"""Identity & discovery routes — the NANDA-facing discovery surface.

Extracted from chapter_agent.py. Serves the A2A AgentCard, AgentFacts (org +
ca.members), the registry hop (/agents/{id}), the AI catalog, conformance badge,
registries probe, and the did:web document.

Shared state lives in chapter_agent: set-once config + the mutated-in-place
`ca.members`/`ca.federation` dicts are bound by value-safe from-import; the rebound
`PUBLIC_URL` (and `_ORG_DATA_DIR`) are reached via `ca.` so handlers see the
live value at request time. chapter_agent imports this module LAST (after all
globals + `app` exist), so the import cycle is benign.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any
from urllib.parse import urlparse

import sm_federation
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import agent_telemetry
import federation_feed
import member_listing
import nanda_registry
import sovereign_identity
import think_cycle
from routes import ca

router = APIRouter()


def org_did() -> str:
    """This org's ``did:web`` — the ONE source every surface that publishes it reads.

    Four documents advertise this org's DID (``did.json``, ``nanda-agent.json``,
    the A2A card, and the federation node descriptor). Before this helper, three
    of them derived it independently — two by ``urlparse(...).netloc``, one by
    ``PUBLIC_URL.replace('https://', '').replace('http://', '').split('/')[0]``.
    They agreed for a normal ``https://host`` and disagreed when ``PUBLIC_URL``
    was empty (``did:web:localhost`` vs the malformed ``did:web:``).

    Two independent reads of one identity is the drift class, and adding a
    fourth copy for the descriptor would have made it worse. The descriptor's
    ``did`` MUST be byte-identical to the ``id`` in ``/.well-known/did.json``,
    which is asserted over a running app in
    ``tests/test_agent_community_descriptor.py``; deriving both from here is
    what makes that assertion structural rather than coincidental.

    Note what this does NOT depend on: key material. A ``did:web`` is a function
    of the domain alone, so this is a pure string derivation and never a reason
    to mint anything.
    """
    domain = urlparse(ca.PUBLIC_URL).netloc if ca.PUBLIC_URL else "localhost"
    return f"did:web:{domain}"


@router.get("/.well-known/nanda-agent.json")
async def well_known_agent() -> dict:
    """Discovery endpoint for NANDA Index crawlers.

    Returns a minimal pointer document so crawlers can find the full
    AgentFacts and A2A endpoint without guessing paths. Per NANDA Index
    convention, crawlers that discover an agent's domain fetch this first.
    """
    return {
        "agent_id": ca.AGENT_ID,
        "facts_url": f"{ca.PUBLIC_URL}/agentfacts.json",
        "a2a_url": f"{ca.PUBLIC_URL}/a2a",
        "did": org_did(),
        "registries": nanda_registry.get_registry_status(),
        "conformance": f"{ca.PUBLIC_URL}/.well-known/conformance.json",
    }


@router.get("/.well-known/agent.json")
async def well_known_a2a_card() -> JSONResponse:
    """Standard A2A AgentCard — the canonical, by-the-book NANDA card.

    A standards-compliant NANDA resolver (Index → registry → card → invoke)
    consumes THIS, not the custom ``nanda-agent.json`` dialect. ``url`` is the
    runtime base such that ``POST <url>/run`` reaches the agent, so it MUST be
    ca.PUBLIC_URL (not localhost) for a remote resolver to invoke. NANDA-specific
    extras (``did``, ``facts_url``) ride as additive extension fields — the A2A
    card schema tolerates unknown keys (host39's own card carries ``_meta``).

    Public/OPEN (classified in auth_verify): a resolver fetches the card before
    it can know how to authenticate. Content-Type per the A2A convention.
    """
    skills = [{"name": s.strip()} for s in ca.AGENT_FOCUS.split(",") if s.strip()]
    card = {
        "name": ca.AGENT_NAME,
        "description": ca.AGENT_DESCRIPTION,
        "url": ca.PUBLIC_URL,
        "version": sovereign_identity.SERVER_VERSION,
        "capabilities": {"streaming": False, "pushNotifications": False},
        "authentication": {"schemes": ["ed25519"]},
        "skills": skills,
        "provider": {"organization": ca.AGENT_NAME, "url": ca.PUBLIC_URL},
        # NANDA extension fields (additive; standard resolvers ignore unknowns).
        "did": org_did(),
        "facts_url": f"{ca.PUBLIC_URL}/agentfacts.json",
    }
    return JSONResponse(content=card, media_type="application/a2a-agent-card+json")


def _org_catalog_entry() -> dict:
    """CatalogEntry for this org's agent — the registry hop's payload.

    Points a NANDA resolver at the standard A2A card. Note the two-level media
    type: the ORG is registered at the Index as ``application/ai-catalog+json``,
    but THIS entry's ``mediaType`` is ``application/a2a-agent-card+json`` — the
    card it links to. Field names are camelCase per the Index v2 CatalogEntry.
    """
    return {
        "identifier": ca.AGENT_ID,
        "displayName": ca.AGENT_NAME,
        "mediaType": "application/a2a-agent-card+json",
        "url": f"{ca.PUBLIC_URL}/.well-known/agent.json",
        "description": ca.AGENT_DESCRIPTION,
        "tags": [s.strip().lower() for s in ca.AGENT_FOCUS.split(",") if s.strip()],
        "version": sovereign_identity.SERVER_VERSION,
    }


# Marks a member whose host39 card has actually been published. Written by the
# publisher (scripts/publish_host39_card.py --record-on-org, or POST
# /admin/api/host39/record-publication); never inferred.
#
# the catalog previously emitted a host39 URL for EVERY member whenever
# ORG_HOST39_CARD_BASE was set, while publishing a card is an explicit operator
# trigger that registration deliberately does not fire. So the catalog
# advertised a URL for every member who had ever registered, whether or not a
# card was ever created for them. Measured live on 2026-08-02: 24 entries, 6
# resolved, 18 returned 404. "The base is configured" is a fact about the ORG's
# configuration; it says nothing about whether THIS member's card exists.
def _host39_card_url(member_id: str, member: dict) -> str | None:
    """The member's host39 card URL, but only when it was actually published.

    Returns None when the org has no card base configured, or when this member
    carries no publication record — the two cases where emitting the URL would
    be a guess.
    """
    base = os.environ.get("ORG_HOST39_CARD_BASE", "").strip().rstrip("/")
    if not base:
        return None
    if not (member.get(ca.HOST39_PUBLISHED_AT) or "").strip():
        return None
    prefix = os.environ.get("ORG_AGENT_PREFIX", "").strip()
    slug = member_id[len(prefix) :] if prefix and member_id.startswith(prefix) else member_id
    return f"{base}/{slug}.json"


def _self_served_card_url(member: dict) -> str | None:
    """The card the member's own runtime serves (self-serve fallback).

    Only http(s) qualifies: the endpoint field is member-supplied text and ends
    up in a public catalog URL.
    """
    endpoint = (member.get("endpoint") or "").strip().rstrip("/")
    if not endpoint.startswith(("http://", "https://")):
        return None
    return f"{endpoint}/.well-known/agent.json"


def _member_catalog_entry(member_id: str, member: dict) -> dict | None:
    """CatalogEntry for an org MEMBER → the A2A card that describes it.

    Resolution order, and the rule is that the catalog advertises only what is
    backed by something:

    1. A host39 card **known to have been published** — publication state on the
       member record, written by the publisher. Not "the org has a card base".
    2. Else the member's own ``{endpoint}/.well-known/agent.json``.
    3. Else **no entry**. The member is dropped from the crawl surface, not from
       existence: it stays resolvable by id through the normal routes.

    Why omission rather than a placeholder or an error state: this endpoint is an
    ENUMERATION. A crawler that follows an advertised entry to a 404 learns the
    registry is unreliable — a plausible wrong answer. An entry that is simply
    absent is honest. That is the opposite call from the owner-attested rework, which was about a
    caller asking after a SPECIFIC subject, where silence is ambiguous and a
    state has to be returned.

    Omissions are counted by the caller and surfaced on the catalog document, so
    "my member is missing" is diagnosable rather than mysterious.
    """
    url = _host39_card_url(member_id, member) or _self_served_card_url(member)
    if url is None:
        return None
    return {
        "identifier": member_id,
        "displayName": member.get("name", member_id),
        "mediaType": "application/a2a-agent-card+json",
        "url": url,
        # NEVER the member row's ``description``. This is an unauthenticated
        # hop, and that field is member-authored free text — the one an audit
        # found carrying an email address and a phone number, and the one the
        # consented Listing forbids outright (sm-listing 0.1 §4.2). The profile
        # route stopped publishing it; this entry and the AgentFacts document
        # were the two routes still doing so. The card the URL points at is
        # what describes the agent.
        "description": "",
    }


def _registry_aliases() -> set[str]:
    """All identifiers (lowercased) that resolve to this org's PRIMARY agent.

    A NANDA resolver hands hop-2 whatever the Index passed through as the
    identifier, which may be:
      * the agent_id (``urn:ai:domain:<DOM>:agent:<slug>`` → slug), or
      * the org DOMAIN (an org-level ``urn:ai:domain:<DOM>`` with no ``:agent:``
        slug → the Index hands the DOMAIN as the identifier), or
      * the org_id registered at the Index.
    All three must resolve to the same primary-agent CatalogEntry, or the live
    NANDA UI 404s the listing.
    """
    from urllib.parse import urlparse

    parsed = urlparse(ca.PUBLIC_URL)
    org_id_raw = os.environ.get("INDEX_ORG_ID", "").strip() or ca.AGENT_ID
    candidates = {
        ca.AGENT_ID,  # agent-level (exact match preserved)
        parsed.hostname or "",  # org DOMAIN (host, no port)
        parsed.netloc or "",  # host:port form (local/dev)
        os.environ.get("ORG_DOMAIN", "").strip(),  # explicit registered domain
        org_id_raw,  # org_id as configured
        nanda_registry._sanitize_org_id(org_id_raw),  # org_id as registered at the Index
    }
    return {c.lower() for c in candidates if c}


@router.get("/agents/{identifier}")
async def registry_agent_record(identifier: str) -> JSONResponse:
    """Registry hop: ``GET /agents/<id>`` → CatalogEntry.

    Orrery is its own registry (``hosting_path=registry``). A NANDA resolver
    that found ``registry_url=ca.PUBLIC_URL`` in the Index fetches THIS, then
    follows ``CatalogEntry.url`` to the standard A2A card. Public/OPEN — the
    registry hop is unauthenticated. The org's PRIMARY agent answers to its
    agent_id, its org_id, AND its domain (see _registry_aliases). An org MEMBER
 resolves to its host39 card. Anything else 404s.
    """
    if identifier.lower() in _registry_aliases():
        return JSONResponse(content=_org_catalog_entry())
    # MEMBER: resolve to its host39 card. Exact match first, then a
    # case-insensitive fallback so an Index-passed slug still matches.
    member_id, member = identifier, ca.members.get(identifier)
    if member is None:
        for mid, m in ca.members.items():
            if mid.lower() == identifier.lower():
                member_id, member = mid, m
                break
    if member is not None:
        entry = _member_catalog_entry(member_id, member)
        if entry is not None:
            return JSONResponse(content=entry)
    raise HTTPException(status_code=404, detail="agent not found in this registry")


@router.get("/.well-known/ai-catalog.json")
async def ai_catalog(request: Request) -> JSONResponse:
    """The org's AI Catalog — ``application/ai-catalog+json``.

    ⚠️ **THE DOCUMENT IS PUBLIC; THE MEMBER LIST IS NOT.** These are separable
    and the distinction is the whole point of this gate, so it is written here rather
    than inferred from the code:

    * **That change opened this path deliberately** — the registry hop is
      unauthenticated. An org registers at the Index with
      ``media_type: application/ai-catalog+json`` and ``registry_url`` pointing
      here (``nanda_registry.py``), so a resolver that has never met this org
      fetches THIS document as its next hop. Gating it breaks the 4-hop
      resolution the org itself asked to be resolved by. That reason has not
      stopped being true.
    * **But anonymously it also enumerated every member** — identifier,
      displayName, the member's own free-text description and their endpoint —
      which is the population ``GET /api/members`` is gated for. An audit
      put an email address and a phone number in a member's
      description and both came back to an unauthenticated GET.

    So an anonymous caller gets the ORG's entry and the catalog envelope: the
    hop resolves, the media type is right, and the crawler learns what the org
    is. Member entries require a verified caller.

    ``omittedMembers`` keeps its meaning EXACTLY — members with no
    resolvable card URL — and ``withheldMembers`` is a separate count for
    members withheld because the caller is unauthenticated. Folding the two
    together would have made a privacy decision indistinguishable from an
    unpublished card, and the resolvable-card rule exists because a silently absent member is
    undiagnosable. The count itself discloses nothing new: ``GET /health``
    already publishes ``members`` to anonymous callers (measured), so this
    neither widens nor narrows what a stranger can learn about the org's size.
    """
    # Read request.state directly rather than through the `ca` proxy: the proxy
    # resolves chapter_agent from sys.modules, and the catalog's own unit tests
    # import this module standalone — going through it turned those into
    # KeyError('chapter_agent'). The value is the same one the middleware sets,
    # and only ever on a verified signature.
    caller = getattr(request.state, "agent_id", "") or ""
    entries = [_org_catalog_entry()]
    omitted = 0
    withheld = 0
    for member_id, member in ca.members.items():
        if not caller:
            withheld += 1
            continue
        entry = _member_catalog_entry(member_id, member)
        if entry is not None:
            entries.append(entry)
        else:
            omitted += 1
    if omitted:
        print(
            f"[catalog] {omitted} member(s) omitted from /.well-known/ai-catalog.json — "
            f"no published host39 card and no http(s) endpoint. They remain resolvable by id."
        )
    return JSONResponse(
        content={
            "specVersion": "1.0",
            "entries": entries,
            "omittedMembers": omitted,
            "withheldMembers": withheld,
        },
        media_type="application/ai-catalog+json",
    )




@router.get("/.well-known/conformance.json")
async def well_known_conformance() -> dict:
    """The chapter's signed conformance badge — public, no auth, offline-verifiable.

    The badge proves this chapter passed the conformance suite against a pinned
    vector corpus (``suite_digest``). Served unauthenticated by design: anyone
    verifies it against the embedded ``signed_by`` did:key, with no service on
    the path. Absent badge → 404.
    """
    try:
        return json.loads(ca._CONFORMANCE_BADGE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="no conformance badge published") from exc


@router.get("/.well-known/registries")
async def well_known_registries() -> dict:
    """Live reachability probe of configured NANDA Indexes.

    Callable by ops dashboards and the admin surface to verify
    Index connectivity without reading process logs.
    """
    return {"probe": await nanda_registry.probe_indexes()}


@router.get("/.well-known/agentfacts.json")
@router.get("/agentfacts.json")
async def agentfacts(request: Request):
    """Serve NANDA Index-compliant AgentFacts for this chapter agent.

    Served under ``/.well-known/`` (the canonical web-discovery location, alongside
    nanda-agent.json / conformance.json / did.json); the legacy root
    ``/agentfacts.json`` path is retained as a back-compat alias.

    Supports conditional GET: If-None-Match with ETag for cache efficiency.
    """
    chapter_member = {
        "name": ca.AGENT_NAME,
        "description": ca.AGENT_DESCRIPTION,
        "skills": [s.strip() for s in ca.AGENT_FOCUS.split(",") if s.strip()],
    }
    facts = sovereign_identity.build_nanda_facts(
        agent_id=ca.AGENT_ID,
        member=chapter_member,
        public_url=ca.PUBLIC_URL,
        evaluations=agent_telemetry.get_evaluations(
            activity_score=len(ca.members) * 2.0,
            think_cycles=think_cycle.think_cycle_count if hasattr(think_cycle, "think_cycle_count") else 0,
        ),
        telemetry=agent_telemetry.get_telemetry(),
    )
    facts["ca.federation"] = {"chapters": list(ca.federation.keys()), "member_count": len(ca.members)}

    # Conditional GET support (CRDT-lite)
    version = facts.get("facts_version", 1)
    etag = f'"v{version}"'
    if request.headers.get("if-none-match") == etag:
        return JSONResponse(status_code=304, content=None, headers={"ETag": etag})

    return JSONResponse(
        content=facts,
        headers={"ETag": etag, "Last-Modified": facts.get("updated_at", "")},
    )


@router.get("/.well-known/agentfacts/{member_id}.json")
@router.get("/agentfacts/{member_id}.json")
async def member_agentfacts(member_id: str, request: Request):
    """Serve NANDA Index-compliant AgentFacts for a member agent.

    Served under ``/.well-known/`` (canonical) with the legacy root
    ``/agentfacts/{member_id}.json`` retained as a back-compat alias.

    Supports conditional GET and ?since_version=N query param.
    """
    if member_id not in ca.members:
        raise HTTPException(status_code=404, detail=f"Member '{member_id}' not found")

    # Optional ?scoring_method= selects the verifiable_receipts scoring (spec/vrp/0.3
    # §3.1). Defaults to nanda-rep/0.1 so live standings are unchanged; nanda-rep/0.2
    # returns the counterparty-corroborated, collusion-resistant score (corroboration_rate
    # + gated reputation_score). Flipping the published DEFAULT is a separate deployment
    # decision — this only lets a resolver request 0.2 explicitly. Unknown method → 400
    # (methods are not comparable, so we never silently coerce).
    import vrp as _vrp_mod

    scoring_method = request.query_params.get("scoring_method", _vrp_mod.DEFAULT_SCORING_METHOD)
    if scoring_method not in _vrp_mod.SUPPORTED_SCORING_METHODS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported scoring_method {scoring_method!r}; expected one of {list(_vrp_mod.SUPPORTED_SCORING_METHODS)}",
        )

    m = ca.members[member_id]
    # The member row's free-text ``description`` does not go out on this
    # unauthenticated document. It is member-authored prose — the field an
    # audit found carrying contact details, the one sm-listing 0.1 §4.2 forbids
    # in a published entry, and the one the profile route stopped serving for
    # that reason. build_nanda_facts substitutes its neutral placeholder.
    facts = sovereign_identity.build_nanda_facts(
        agent_id=member_id,
        member={**m, "description": ""},
        public_key=m.get("public_key", ""),
        public_url=ca.PUBLIC_URL,
    )
    facts["chapter"] = {"agent_id": ca.AGENT_ID, "name": ca.AGENT_NAME, "region": ca.AGENT_REGION}

    # VRP verifiable_receipts facet (spec/vrp/0.1 §5): the server-attested
    # behavioral_merkle_root + nanda-rep scores for this member, as recorded in
    # the server's Issuer Log. Contents-free (no receipt bodies) → safe to
    # publish. Best-effort: a failure here must never break AgentFacts.
    try:
        import arp as _arp_mod

        _principal_did = _arp_mod.did_key_for_member(member_id)
        if _principal_did:
            _ledger_uri = f"{ca.PUBLIC_URL}/api/receipts/ledger/{_principal_did}"
            _ledger, _facet = await _vrp_mod.build_principal_ledger(
                _principal_did, ledger_uri=_ledger_uri, method=scoring_method
            )
            if _facet.get("behavioral_merkle_root"):  # omit the facet for an empty ledger (spec/vrp/0.1 §2)
                facts["verifiable_receipts"] = _facet
    except Exception as e:  # noqa: BLE001 — facet is augmentation; never wedge AgentFacts
        print(f"[vrp] verifiable_receipts facet build failed for {member_id}: {e}")

    # VRP 0.2 AgentFacts Attestation (spec/vrp/0.2 §A): the server signs a claim
    # binding this agent's identity + a digest of the whole facts record + the facet's
    # root/ledger_uri, so a resolver verifies the standing is THIS agent's — and the
    # ledger was not substituted — without trusting our live server. Built LAST: the
    # digest covers every other member. Best-effort + observable: a failure leaves the
    # record un-attested (a resolver treats its standing as unverifiable, never as
    # forged), it must never wedge AgentFacts.
    try:
        import vrp as _vrp_mod

        _vrp_mod.attest_facts_record(facts, version=int(facts.get("facts_version", 1)))
    except Exception as e:  # noqa: BLE001 — attestation is the binding; degrade safe, never wedge
        # LOUD by design: an un-attested card means this member's standing is
        # UNVERIFIABLE to every resolver. Safe against forgery (un-attested = rejected,
        # not trusted), but a real availability failure of the binding — a 500 here
        # would break discovery entirely, which is worse, so we degrade and shout.
        print(f"[vrp][ERROR] AgentFacts attestation FAILED for {member_id} — standing now UNVERIFIABLE: {e}")

    version = facts.get("facts_version", 1)
    # The facet differs by scoring_method, so the ETag must too — otherwise a
    # conditional GET for nanda-rep/0.2 could be answered 304 against a cached 0.1 card.
    method_tag = "" if scoring_method == _vrp_mod.DEFAULT_SCORING_METHOD else f"+{scoring_method}"
    etag = f'"v{version}{method_tag}"'

    # ?since_version=N indexes facts_version, not the facet method — only honour its
    # 304 shortcut for the default-method card (a non-default request needs that
    # method's facet actually served, even at the same facts_version).
    since = request.query_params.get("since_version")
    if scoring_method == _vrp_mod.DEFAULT_SCORING_METHOD and since and since.isdigit() and int(since) >= version:
        return JSONResponse(status_code=304, content=None, headers={"ETag": etag})

    if request.headers.get("if-none-match") == etag:
        return JSONResponse(status_code=304, content=None, headers={"ETag": etag})

    return JSONResponse(
        content=facts,
        headers={"ETag": etag, "Last-Modified": facts.get("updated_at", "")},
    )


@router.get("/.well-known/did.json", response_model=None)
async def did_document() -> JSONResponse | dict:
    """W3C DID Document for this org (did:web resolution). Public by design —
    see the OPEN_PATHS entry in auth_verify for why gating it breaks both
    did:web and inbound federation signature verification.

    READS the signing key; never mints one. This handler used to call
    ``generate_ed25519_keypair()`` when the key was absent, which looks harmless
    and is not:

      * the minted key is IN-MEMORY ONLY — ``generate_ed25519_keypair`` neither
        writes ``chapter_keys`` nor the local file — so this org would publish,
        as its identity, a key that disappears on restart;
      * worse, it POISONS the cache. ``ensure_chapter_keypair()`` returns
        immediately when the id is already in ``_ed25519_keypairs``, so once an
        anonymous read has minted an ephemeral key, the DURABLE key in
        ``chapter_keys`` is never loaded. The org then signs receipts and
        federation broadcasts with a throwaway key while its real identity sits
        unused in the database — and every peer that pinned the real DID
        rejects it.

    Minting identity is ``ensure_chapter_keypair``'s job at startup, where it is
    persisted. A read surface answers with what exists; if nothing exists yet,
    the honest answer is 503, not a fresh identity invented on the spot.
    """
    did = org_did()
    kp = sovereign_identity._ed25519_keypairs.get(ca.AGENT_ID)
    if not kp:
        # Not ready, not broken — and explicitly not a reason to invent a key.
        print(
            f"[identity] did.json requested before {ca.AGENT_ID!r} has a signing key; "
            "returning 503 rather than minting an ephemeral identity"
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "identity_not_initialized",
                "detail": (
                    "This org has no Ed25519 signing key yet. The key is minted and persisted at "
                    "startup by ensure_chapter_keypair; a DID document is not generated on demand."
                ),
            },
        )
    public_key_b64 = base64.b64encode(kp["public_key"]).decode()

    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                # Ed25519VerificationKey2020 REQUIRES publicKeyMultibase
                # (z-base58btc over 0xed01||key) — standard DID tooling could
                # not parse the nonstandard publicKeyBase64. Same key bytes,
                # standard encoding.
                "publicKeyMultibase": sovereign_identity.build_did_key_from_ed25519(public_key_b64).removeprefix(
                    "did:key:"
                ),
                # Legacy field, kept ONE transition window: live federation
                # peers still read publicKeyBase64 from each other's did.json
                # (federation_signing) — a hard swap would break the mesh
                # mid-rollout. Drop at 1.0.
                "publicKeyBase64": public_key_b64,
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [
            {
                "id": f"{did}#a2a",
                "type": "A2AEndpoint",
                "serviceEndpoint": f"{ca.PUBLIC_URL}/a2a",
            },
            {
                "id": f"{did}#agentfacts",
                "type": "AgentFacts",
                "serviceEndpoint": f"{ca.PUBLIC_URL}/agentfacts.json",
            },
        ],
    }


# ---------------------------------------------------------------------------
# sm-federation 0.1 — the community federation node descriptor
# ---------------------------------------------------------------------------


def _prune_absent(descriptor: dict[str, Any]) -> dict[str, Any]:
    """Drop optional fields the node has no real value for.

    ``build_node_descriptor`` emits every optional key, defaulting to ``""`` or
    ``[]``. Both validate — the schema requires only ``version`` and ``node_id``
    — but ``"feed_url": ""`` is not the same statement as no ``feed_url``: it
    hands a peer a string to resolve, and an empty string resolves against the
    peer's own base. The published ``minimal`` vector
    (``vectors/federation/v01/descriptors-valid.json``) omits absent fields
    rather than emptying them, so absence is the protocol's own idiom.

    ``version`` and ``node_id`` are never pruned — they are required, and an
    org with no ``node_id`` is a bug to surface, not a key to drop.
    """
    required = {"version", "node_id"}
    return {k: v for k, v in descriptor.items() if k in required or v}


def _agent_community_descriptor() -> dict[str, Any]:
    """Build this org's node descriptor from what actually exists.

    Built with the PUBLISHED builder rather than a dict literal assembled here.
    A hand-written descriptor is a second copy of the wire contract with nothing
    comparing it to the first — the mirror-without-a-guard shape that
    ``a2ui_helpers`` and ``_conformance_vectors`` each needed a drift guard to
    close. ``sm_federation.build_node_descriptor`` IS the contract, so a field
    renamed upstream surfaces as a ``TypeError`` here instead of as a document
    that quietly stopped matching.

    Every field below is either read from live org state or omitted. Nothing is
    synthesised to fill a slot the schema would have accepted empty.
    """
    base = ca.PUBLIC_URL.rstrip("/") if ca.PUBLIC_URL else ""

    # READ, never mint. A did:web derives from the domain, so org_did()
    # would happily return a string for an org that has no key at all — and that
    # string would point at a /.well-known/did.json answering 503. Advertising a
    # DID whose document does not resolve is the mistake (the catalog
    # emitted a host39 URL for every member whether or not a card existed): a
    # pointer to nothing costs the peer a round trip and tells it nothing true.
    # So the DID is published only once the identity it names is resolvable.
    has_signing_key = bool(sovereign_identity._ed25519_keypairs.get(ca.AGENT_ID))

    # Same rule, same precedent: /.well-known/conformance.json 404s until a badge
    # has actually been written to the org data dir. Advertise the URL only when
    # the artifact behind it exists.
    has_badge = ca._CONFORMANCE_BADGE_PATH.exists()

    return _prune_absent(
        sm_federation.build_node_descriptor(
            node_id=ca.AGENT_ID,
            did=org_did() if has_signing_key else "",
            facts_url=f"{base}/.well-known/agentfacts.json" if base else "",
            a2a_url=f"{base}/a2a" if base else "",
            conformance_url=f"{base}/.well-known/conformance.json" if (base and has_badge) else "",
            # §4, and gated on the DURABLE LOG ACTUALLY EXISTING — not on
            # DATABASE_URL, and not on the code being present. A node whose role
            # could not create the feed table has a database and still cannot
            # honour completeness, so it must not advertise the exchange.
            # federation_feed.feed_url() returns "" in that case and the field
            # prunes away, which is what keeps the descriptor honest with no
            # extra logic here: build_node_descriptor DERIVES federation/0.1#4
            # from a non-empty feed_url, so no feed means no claim and the two
            # cannot disagree.
            #
            # ⚠️ NEVER point this at /api/knowledge/summary. That surface is an
            # unsigned, cursorless full snapshot — the v0.1 model §4 replaced —
            # and aiming feed_url at it would satisfy the schema while breaking
            # the guarantee the schema exists to express.
            feed_url=federation_feed.feed_url(base),
            # ⚠️ GATED ON THE PROFILE BEING IMPLEMENTED, NEVER ON THE LISTING
            # HAVING MEMBERS. `listing_url` present ⟺ the listing/0.1 token is
            # claimed; it does NOT imply the listing is non-empty. An org that
            # runs the surface with nobody opted in advertises it and serves an
            # empty document, and that is conformant and CORRECT — it says "I run
            # this surface; nobody has opted in", which is a different and more
            # useful fact than silence.
            #
            # Gating on entry count would be the degrade trap in a new costume:
            # the descriptor would flap as members opt in and out, an empty-but-
            # consented org would be indistinguishable from one that never
            # implemented the profile, and the URL would disappear at exactly the
            # moment a peer most needs to know the surface exists.
            listing_url=f"{base}{member_listing.LISTING_PATH}" if (base and member_listing.is_enabled()) else "",
            registries=nanda_registry.configured_registries(),
            # "profile versions the node speaks". Orrery speaks the descriptor
            # profile of 0.1 — this document — and does NOT speak §4's exchange.
            # The schema has no way to say that: one flat list covers a protocol
            # with two separable halves. Claimed here because the descriptor is
            # genuine and the absent feed_url is what tells a peer the exchange
            # is unavailable; the two fields must be read together. Reported as
            # a gap in the protocol's vocabulary rather than resolved silently.
            federation_versions=["0.1"],
            # Section tokens are DERIVED by the builder, never passed in: §2
            # because serving this document implements §2 by definition, and §4
            # exactly when feed_url is set. Passing [] and letting the builder
            # assemble them is what makes the declaration true by construction —
            # a caller cannot build an overclaiming descriptor through it, and
            # since sm-federation 0.4.0 the JSON Schema enforces both directions
            # anyway (feed_url ⇒ #4, and #4 ⇒ feed_url).
            capabilities=[],
        )
    )


@router.get("/.well-known/agent-community.json")
async def well_known_agent_community() -> dict[str, Any]:
    """sm-federation 0.1 node descriptor — the community peering entry point.

    PUBLIC/OPEN by design, and listed explicitly in ``auth_verify.OPEN_PATHS``
    for the reason ``did.json`` had to learn: a discovery document behind
    auth defeats its own purpose. A peer that has never met this org fetches
    this FIRST — before it knows the org's identity, and therefore before it
    could possibly authenticate to it. Gating this path does not protect
    anything; it makes the org undiscoverable to exactly the strangers
    federation exists to reach. Its neighbours carry that sentence; ``did.json``
    did not, and the absence of the sentence is why it stayed gated.

    PURE READ. It mints nothing, reads no key material, and creates no state —
    an org with no signing key gets an honest descriptor with ``did`` omitted,
    never an identity invented by an anonymous GET.

    Contains only public pointers (org id, DID, published URLs) — the same class
    of material as ``did.json``. Publishing it is the point.
    """
    return _agent_community_descriptor()

