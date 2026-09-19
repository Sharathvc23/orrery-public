"""
Build the A2A Agent Card served at /.well-known/agent.json.

The agent's 20 tools are grouped into coarse A2A *skills* (not 1:1). A skill
is a discoverable capability advertisement; tools are the RPC methods a
client invokes via tasks/send once they've decided to hire this agent.
"""

from __future__ import annotations

from typing import Any

from .a2a_models import (
    AgentAuthentication,
    AgentCapabilities,
    AgentCard,
    AgentProvider,
    AgentSkill,
)

# Map tool name → (skill_id, skill_name, tags, example_prompts).
# Tools not in the map fall into the "general_assistant" catchall skill so
# nothing is silently dropped — and the test suite asserts 100% coverage.
TOOL_TO_SKILL: dict[str, tuple[str, str, list[str], list[str]]] = {
    # ─── Membership ────────────────────────────────────────
    "join_chapter": (
        "skill.membership",
        "Chapter membership",
        ["membership", "join", "register", "identity"],
        [],
    ),
    # ─── Server / federation discovery ────────────────────
    "search_chapter": (
        "skill.discovery",
        "Member discovery",
        ["discovery", "search", "chapter", "federation"],
        [
            "Find a Rust engineer in my chapter",
            "Who knows about prompt injection defenses?",
        ],
    ),
    "search_federation": (
        "skill.discovery",
        "Member discovery",
        ["discovery", "search", "chapter", "federation"],
        [],
    ),
    "find_peer": (
        "skill.discovery",
        "Member discovery",
        ["discovery", "search", "chapter", "federation"],
        [],
    ),
    # ─── Intent matching ───────────────────────────────────
    "submit_intent": (
        "skill.intent_matching",
        "Intent matching",
        ["intent", "match", "need"],
        [
            "I need a co-founder with ML background",
            "Looking for a mentor in FPGA design",
        ],
    ),
    "respond_to_intent": (
        "skill.intent_matching",
        "Intent matching",
        ["intent", "match", "need"],
        [],
    ),
    # ─── Conversations ─────────────────────────────────────
    "start_conversation": (
        "skill.conversation",
        "Conversation management",
        ["conversation", "messaging", "thread"],
        ["Start a private chat with Sara about ML infra"],
    ),
    "list_conversations": (
        "skill.conversation",
        "Conversation management",
        ["conversation", "messaging", "thread"],
        [],
    ),
    "send_to_peer": (
        "skill.conversation",
        "Conversation management",
        ["conversation", "messaging", "thread"],
        [],
    ),
    # ─── Server intelligence / projection ─────────────────
    "update_projection": (
        "skill.projection",
        "Agent projection",
        ["projection", "profile", "self-update"],
        ["Update my projection to include Rust and distributed systems"],
    ),
    "get_chapter_intelligence": (
        "skill.projection",
        "Agent projection",
        ["projection", "profile", "self-update"],
        [],
    ),
    # ─── Local memory ──────────────────────────────────────
    "save_note": (
        "skill.memory",
        "Local memory",
        ["memory", "notes", "recall"],
        ["Save a note about today's investor call"],
    ),
    # ─── Skill registry ────────────────────────────────────
    "install_skill": (
        "skill.skill_registry",
        "Skill registry",
        ["skill", "install", "capability"],
        [
            "Install the file-ops skill from the chapter registry",
            "Rate the pdf-summarizer skill 5 stars",
        ],
    ),
    "rate_skill": ("skill.skill_registry", "Skill registry", ["skill", "rate", "review"], []),
    "list_installed_skills": (
        "skill.skill_registry",
        "Skill registry",
        ["skill", "list"],
        [],
    ),
    # ─── Trust ─────────────────────────────────────────────
    "my_trust": (
        "skill.trust",
        "Trust reporting",
        ["trust", "reputation"],
        ["What's my current trust score?"],
    ),
    # ─── Settings & channels ───────────────────────────────
    "update_settings": (
        "skill.settings",
        "Settings management",
        ["settings", "config"],
        ["Switch my LLM provider to Anthropic"],
    ),
    "connect_channel": (
        "skill.channels",
        "External channels",
        ["channel", "slack", "email"],
        ["Connect my Slack workspace"],
    ),
    # ─── Doing business ────────────────────────────────────
    # Without this entry book_appointment fell through to the catch-all and an
    # agent that takes bookings advertised itself as a "General assistant",
    # which tells a resolving client nothing about what it can actually do.
    "book_appointment": (
        "skill.booking",
        "Appointment booking",
        ["booking", "appointment", "scheduling", "receipt"],
        [
            "Book a haircut for Tuesday at 10am",
            "I'd like an appointment this week",
        ],
    ),
}

CATCHALL_SKILL_ID = "skill.general_assistant"


def build_agent_card(
    *,
    agent_id: str,
    display_name: str | None,
    description: str | None,
    version: str,
    base_url: str,
    chapter_url: str | None,
    did: str | None,
    skills_declared: list[str] | None = None,
    tools: list[dict[str, Any]] | None = None,
    profile_extension: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
    supports_streaming: bool = True,
    authentication_schemes: list[str] | None = None,
    provider_organization: str | None = None,
    provider_url: str | None = None,
    topical_skills_are_ranked: bool = True,
) -> AgentCard:
    """Build the A2A Agent Card for this member.

    Args:
        agent_id: this member's local id (e.g. 'alice')
        display_name: human-readable name (falls back to agent_id)
        description: one-paragraph bio
        version: semver of the member SDK
        base_url: public URL where the agent accepts JSON-RPC (e.g. http://host:7777)
        chapter_url: URL of the chapter this member belongs to (for x-nanda)
        did: member's did:key (for x-nanda)
        skills_declared: free-text topical skills from onboarding (e.g. ["rust","fpga"])
        tools: full AGENT_TOOLS list (used to derive discoverable A2A skills)
        supports_streaming: whether this SURFACE implements tasks/sendSubscribe.
            Defaults True for the member runtime, which does; a caller whose
            transport doesn't (smb_host mounts plain REST routes, no JSON-RPC
            at all) must pass False rather than let the default overstate it.
        authentication_schemes: the caller-auth methods THIS SURFACE actually
            enforces. Defaults to the member runtime's Ed25519/did-auth scheme;
            a caller whose routes require no credential (smb_host's tenant
            routes are all open) must pass ``[]`` — advertising a scheme
            nothing checks reads as "requests here are authenticated" when
            they are not.
        provider_organization / provider_url: who runs this agent, i.e. who
            holds the ability to read or replace its key. Defaults to
            ``chapter_url`` (or ``agent_id`` standing in for an unaffiliated
            individual) for the member runtime; a caller hosting OTHER
            people's agents (smb_host, one operator's passphrase decrypts
            every tenant) must supply its own operator identity rather than
            let the tenant's own id stand in as if the tenant ran itself.
        topical_skills_are_ranked: whether declared topical skills feed a real
            discovery-ranking mechanism reachable through this surface. True
            for the member runtime (chapters rank search results by them);
            a caller that registers on no index and reaches no ranking code
            (smb_host) must pass False rather than repeat a claim about a
            mechanism it cannot reach.
    """
    # Group tools by A2A skill, collapsing duplicates.
    seen: dict[str, AgentSkill] = {}
    for tool in tools or []:
        fn = tool.get("function", {})
        name = fn.get("name")
        if not name:
            continue
        mapping = TOOL_TO_SKILL.get(name)
        if mapping is None:
            skill_id = CATCHALL_SKILL_ID
            skill_name = "General assistant"
            tags = ["general"]
            examples: list[str] = []
        else:
            skill_id, skill_name, tags, examples = mapping

        if skill_id in seen:
            continue  # already contributed by an earlier tool

        seen[skill_id] = AgentSkill(
            id=skill_id,
            name=skill_name,
            description=fn.get("description"),
            tags=tags,
            examples=examples or None,
            inputModes=["text"],
            outputModes=["text"],
        )

    # Topical skills from onboarding become a single advertising-only skill —
    # they're not invokable via tasks/send, they describe the human behind the agent.
    if skills_declared:
        topical_description = (
            "Areas of human expertise declared by the member during onboarding. Not directly invokable"
        )
        topical_description += " — used for discovery ranking." if topical_skills_are_ranked else "."
        seen["skill.topical"] = AgentSkill(
            id="skill.topical",
            name="Topical expertise",
            description=topical_description,
            tags=sorted({s.lower() for s in skills_declared})[:32],
            examples=None,
            inputModes=["text"],
            outputModes=["text"],
        )

    return AgentCard(
        name=display_name or agent_id,
        description=description or f"Sovereign member agent @{agent_id}",
        url=base_url,
        version=version,
        provider=AgentProvider(
            organization=(
                provider_organization
                if provider_organization is not None
                else (f"Org: {chapter_url}" if chapter_url else agent_id)
            ),
            url=provider_url if provider_url is not None else chapter_url,
        ),
        capabilities=AgentCapabilities(
            streaming=supports_streaming,
            pushNotifications=False,
            stateTransitionHistory=True,
        ),
        authentication=AgentAuthentication(
            # Match the AgentFacts auth methods — the agent signs with Ed25519
            # (did:key), not HMAC. "ed25519-hmac" was a stale mislabel.
            schemes=authentication_schemes if authentication_schemes is not None else ["ed25519", "did-auth"],
            credentials=did,
        ),
        **_security_declaration(authentication_schemes),
        defaultInputModes=["text"],
        defaultOutputModes=["text"],
        skills=list(seen.values()),
        **(
            {"x-nanda": _nanda_extension(did, chapter_url, base_url, profile_extension, lifecycle)}
            if (did or chapter_url or profile_extension or lifecycle)
            else {}
        ),
    )


#: ⚠️ WHAT THE CURRENT SPEC CAN AND CANNOT SAY ABOUT OUR SCHEME.
#:
#: a2a-sdk 1.1.2's ``SecurityScheme`` is a oneof over exactly five OpenAPI
#: kinds — apiKey, http, oauth2, openIdConnect, mutualTLS. **There is no
#: signature-based member.** Our scheme is a detached Ed25519 signature over
#: ``{body}:{agent_id}:{timestamp}`` carried in headers, and it has no faithful
#: expression in that vocabulary.
#:
#: So this declares the closest HONEST thing rather than inventing a scheme name
#: that means nothing to a reader: an ``apiKey`` scheme located in the header
#: that actually carries the credential. A stock client reading it learns the
#: true and useful part — a required header it is not sending — without being
#: told we speak OAuth. The ``description`` carries the part the vocabulary
#: cannot.
#:
#: The second limitation: ``security`` is a CARD-LEVEL requirement and the
#: vocabulary has no per-method granularity, while our line is drawn per method
#: (reads open, sends gated — see ``a2a_auth.METHOD_ACCESS``). Declaring it
#: card-level therefore OVER-states for reads. That is the safe direction for a
#: security declaration and it is true for the operation a stock client will
#: actually attempt, which is a send; the exact per-method truth is published in
#: the x-nanda extension, where we can say it precisely.
_SIGNATURE_HEADER = "X-Agent-Signature"


def _open_methods_phrase() -> str:
    """The open methods, for the human-readable half of the declaration.

    ⚠️ DERIVED FROM ``a2a_auth.METHOD_ACCESS``, NOT TYPED OUT, and the reason is
    a measured failure rather than tidiness: this description was a literal and
    it survived ``tasks/cancel`` moving to caller-required, so a card served to
    every stranger said cancel was open while ``x-nanda.a2a_method_access`` on
    the SAME card — already derived — said caller-required. The card contradicted
    itself in two adjacent fields, and the field a human reads was the wrong one.
    """
    from .a2a_auth import OPEN_METHODS

    return "reads (" + ", ".join(sorted(OPEN_METHODS)) + ")"


def _gated_methods_phrase() -> str:
    """The caller-required methods, current-spec aliases included.

    ``message/send`` and ``message/stream`` are the names a stock client sends;
    they dispatch onto the v0.2 names this module classifies, so naming both is
    what makes the sentence usable to a reader holding a current-spec client.
    """
    from .a2a_auth import AUTHENTICATED_METHODS

    gated = sorted(AUTHENTICATED_METHODS)
    return ", ".join(gated) + " (and their current-spec aliases message/send and message/stream)"


def _security_declaration(authentication_schemes: list[str] | None) -> dict:
    """Current-spec ``securitySchemes``/``security`` for the scheme we enforce.

    A caller that passes ``[]`` (a surface enforcing nothing, e.g. smb_host's
    open tenant routes) gets no declaration at all — advertising a requirement
    nothing checks is the same lie as advertising a scheme nothing checks.
    """
    if authentication_schemes is not None and not authentication_schemes:
        return {}
    return {
        "securitySchemes": {
            "agentSignature": {
                "type": "apiKey",
                "in": "header",
                "name": _SIGNATURE_HEADER,
                "description": (
                    "Detached Ed25519 signature over '{body}:{agent_id}:{timestamp}', sent with "
                    "X-Agent-ID, X-Agent-Timestamp and X-Agent-DID-Key. Declared as apiKey because "
                    "the current A2A security vocabulary has no signature scheme; it is not an API "
                    "key and no static credential will work. It proves possession of the key you "
                    "present, not that the key is known to this agent: there is no peer registry "
                    "and a freshly generated key verifies. Required for "
                    f"{_gated_methods_phrase()}; {_open_methods_phrase()} and both agent-card "
                    "paths are open."
                ),
            }
        },
        "security": [{"agentSignature": []}],
    }


def _nanda_extension(
    did: str | None,
    chapter_url: str | None,
    base_url: str,
    profile_extension: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Opaque extension bag; NANDA-aware clients pick these up, others ignore.

    Lean-chapter migration: the ``profile`` sub-key carries the
    agent's local profile (name, bio, interests, skills, socials,
    plus the Ed25519 signature over the canonical JSON). Chapters
    fetching the card use this to render member surfaces without
    reading from their own ``agents`` table.

    ``lifecycle`` is a SIBLING of ``profile``, never a member of it: ``profile``
    is signed canonical JSON and adding a key inside it would change the bytes
    the signature covers. It is carried here so a resolver that only fetches the
    card still learns that a subject is revoked — otherwise the card of a
    withdrawn business reads exactly like the card of an active one, which is
    the ambiguity the owner-attested rework removed.
    """
    ext: dict[str, Any] = {"spec": "nanda-index-v0.1"}
    # The per-method truth the current spec's card-level `security` cannot
    # express. Derived from the enforcement table itself, so the card cannot
    # describe a policy the handler does not apply.
    from .a2a_auth import METHOD_ACCESS

    ext["a2a_method_access"] = dict(sorted(METHOD_ACCESS.items()))
    if did:
        ext["did"] = did
    if chapter_url:
        ext["chapter_url"] = chapter_url
    ext["agentfacts_url"] = f"{base_url}/agentfacts.json"
    if profile_extension:
        ext["profile"] = profile_extension
    if lifecycle:
        ext["lifecycle"] = lifecycle
        ext["lifecycle_url"] = f"{base_url}/.well-known/agent-lifecycle.json"
    return ext
