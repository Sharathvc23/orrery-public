"""
Member Agent Runtime — gives real agents to real members.

Each member with an API key gets their own LLM client and think cycle.
Runs inside the chapter agent process, not as separate deployments.

Lifecycle:
1. On startup, load API keys from Postgres `agent_api_keys`
2. Create a MemberAgentRuntime per active member with a key
3. Member runtimes are called during the chapter think cycle
4. A2A messages to members with runtimes use their own LLM
"""

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import api_key_store
import llm_config
import llm_runtime

logger = logging.getLogger(__name__)

# These will be injected by chapter_agent.py on init
_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("member_runtime.init() was never called — no pg_request injected")
    return _pg_request

_conv_store: Any = None
_log_activity: Any = None
_log_agent_thought: Any = None
_build_thought_card: Any = None
_knowledge_cache: Any = None
_chapter_agent_id = ""
_chapter_agent_name = ""

# Active member runtimes: agent_id → MemberAgentRuntime
runtimes: dict[str, "MemberAgentRuntime"] = {}


def init(
    pg_request,
    conv_store,
    log_activity,
    log_agent_thought,
    build_thought_card,
    knowledge_cache,
    agent_id,
    agent_name,
):
    """Inject dependencies from chapter_agent.py."""
    global _pg_request, _conv_store, _log_activity, _log_agent_thought
    global _build_thought_card, _knowledge_cache, _chapter_agent_id, _chapter_agent_name
    _pg_request = pg_request
    _conv_store = conv_store
    _log_activity = log_activity
    _log_agent_thought = log_agent_thought
    _build_thought_card = build_thought_card
    _knowledge_cache = knowledge_cache
    _chapter_agent_id = agent_id
    _chapter_agent_name = agent_name


class MemberAgentRuntime:
    """Runtime for a single member agent with their own LLM."""

    def __init__(self, agent_id: str, member: dict, provider: str, api_key: str, base_url: str, model: str):
        self.agent_id = agent_id
        self.member = member
        self.provider = provider
        self.model = model
        self.thought_count = 0
        self.conversation_count = 0
        self.last_thought_at: str | None = None
        self.status = "active"

        # Create provider-specific LLM client. The OpenAI v2 client
        # raises ``OpenAIError`` on construction whenever ``api_key``
        # is empty/None *and* ``OPENAI_API_KEY`` is unset — there's no
        # lazy path. To preserve the documented contract for the
        # adversarial "member registered without a key" path —
        # status="active" at construction; failure deferred to the
        # first LLM call — pass a placeholder string when the real
        # key is empty/whitespace. The placeholder has no upstream
        # validity, so the first API call still fails with a 401,
        # which is exactly what the test (and the production code
        # path that catches that 401) expects.
        client_key = (api_key or "").strip() or "no-key-configured"
        # Provider-agnostic by design (llm_config): every provider is reached
        # through the OpenAI-compatible client against a provider-specific
        # base_url, so switching providers is base_url + key + model with no
        # call-site change. For Anthropic that base_url is the officially
        # supported OpenAI-compatibility endpoint (api.anthropic.com/v1/); a
        # member may also point base_url at a proxy/self-host. llm_config
        # resolves base_url for every known provider; the fallback here only
        # covers a member row that named "anthropic" without one.
        # Built by the shared factory, so this runtime gets the capped retry
        # count and the explicit timeout rather than the SDK defaults. An
        # explicitly configured base_url still wins: a member pointed at a proxy
        # or a self-host is correctly configured, and the registry's address for
        # the provider is not a reason to override it.
        resolution = llm_runtime.resolve(provider or llm_config.PROVIDER, model=model)
        if base_url and base_url != resolution.base_url:
            resolution = replace(resolution, provider=replace(resolution.provider, base_url=base_url))
        self.llm = llm_runtime.build_client(resolution, api_key=client_key)

    def _system_prompt(self) -> str:
        """Build system prompt for this member's agent."""
        m = self.member
        skills = ", ".join(m.get("skills", [])) or "general"
        personality = m.get("personality", "")
        description = m.get("description", "")

        # Pull server intelligence for context
        intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
        trending = intel.get("trending_topics", [])[:3]
        trending_text = f"\nTrending in chapter: {', '.join(trending)}" if trending else ""

        return f"""You are {m["name"]}'s personal NANDA agent — @{self.agent_id}.
You represent {m["name"]} in the {_chapter_agent_name} chapter.

About your human: {description}
Skills: {skills}
{f"Personality: {personality}" if personality else ""}
{trending_text}

Your job:
- Respond to messages on behalf of your human, staying true to their skills and interests
- Generate insights relevant to your human's expertise
- Be concise, helpful, and collaborative
- When introduced to someone, find common ground based on skills

Keep responses under 150 words. You are an agent, not a chatbot."""

    async def respond(self, message: str, conversation_id: str) -> str:
        """Handle an A2A message using this member's own LLM."""
        conv_key = f"{self.agent_id}:{conversation_id}"
        history = await _conv_store.load(conv_key)

        chat_messages: list[Any] = [{"role": "system", "content": self._system_prompt()}]
        for msg in history[-20:]:
            chat_messages.append({"role": msg["role"], "content": msg["content"]})
        chat_messages.append({"role": "user", "content": message})

        try:
            response = self.llm.chat.completions.create(
                model=self.model,
                messages=chat_messages,
                max_tokens=512,
            )
            reply = response.choices[0].message.content or "I couldn't generate a response."
            self.conversation_count += 1
        except Exception as e:
            logger.warning("member runtime @%s LLM error: %s", self.agent_id, e)
            reply = f"Agent @{self.agent_id} is having trouble responding right now."
            self.status = "error"

        # Persist conversation
        from chapter_agent import AGENT_DB_UUID

        await _conv_store.append(AGENT_DB_UUID, conv_key, message, reply)

        # Log activity
        asyncio.create_task(_log_activity(self.agent_id, self.member["name"], conversation_id, message, reply))

        return reply

    async def think(self, members: dict, recent_thoughts: list[str]) -> str | None:
        """Generate one autonomous thought from this member's perspective.

        Returns the thought text, or None if nothing to say.
        """
        m = self.member
        skills = m.get("skills", [])
        if not skills:
            return None

        # Pick a random skill to think about
        focus_skill = random.choice(skills) if skills else "community"

        # Get other members with complementary skills for context
        peers = [
            f"@{mid} ({mem['name']}, skills: {', '.join(mem.get('skills', [])[:3])})"
            for mid, mem in members.items()
            if mid != self.agent_id
        ]
        peer_context = "\n".join(peers[:8]) if peers else "No peers yet"

        # Dedup against recent thoughts
        avoid_text = ""
        if recent_thoughts:
            avoid_text = f"\nDo NOT repeat these themes: {', '.join(recent_thoughts[:5])}"

        prompt = f"""You are @{self.agent_id}'s agent. Your human has skills in: {", ".join(skills)}.

Chapter peers:
{peer_context}
{avoid_text}

Generate ONE brief insight or observation (~50 words) about how your human's expertise in '{focus_skill}' could help the chapter. Be specific about which peers could collaborate.

Respond with just the insight, no JSON."""

        try:
            response = self.llm.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=100,
            )
            thought = response.choices[0].message.content or ""
            thought = thought.strip()[:300]

            if thought:
                self.thought_count += 1
                self.last_thought_at = datetime.now(UTC).isoformat()

                # Track activity
                import activity_tracker

                await activity_tracker.track(self.agent_id, "member_thought", {"summary": thought[:100]})

                # Persist runtime stats
                asyncio.create_task(self._persist_stats())

                return thought
        except Exception as e:
            logger.warning("member runtime @%s think error: %s", self.agent_id, e)

        return None

    async def _persist_stats(self):
        """Save runtime stats to Postgres."""
        await _pg_request(
            "PATCH",
            "agents", params={"agent_id": f"eq.{self.agent_id}"},
            body={
                "config": {
                    **((self.member.get("config") if isinstance(self.member.get("config"), dict) else {}) or {}),
                    "personality": self.member.get("personality", ""),
                    "voice": self.member.get("voice", "helpful"),
                    "virtual": True,
                    "parent_chapter": _chapter_agent_id,
                    "runtime_stats": {
                        "thought_count": self.thought_count,
                        "conversation_count": self.conversation_count,
                        "last_thought_at": self.last_thought_at,
                        "status": self.status,
                        "provider": self.provider,
                        "model": self.model,
                    },
                },
            },
        )


def _member_is_unreachable(provider: str, api_key: str) -> bool:
    """Whether this member has no way to reach a model, and so gets no runtime.

    A LOCAL PROVIDER HAS NO KEY TO HOLD. This decision used to be a bare
    ``if not api_key: continue``, which refused a runtime to every member on a
    local provider — and the wizard's own express default is ollama, so the most
    common configuration the product offers was the one that silently got
    nothing: no runtime, no error, no line saying why.

    Named rather than inline so the rule can be asserted directly. The loop that
    uses it needs Postgres to run, and a rule that can only be tested through a
    database is a rule that stops being tested.
    """
    if api_key:
        return False
    return llm_runtime.normalise_provider(provider) not in llm_runtime.LOCAL_PROVIDERS


async def load_runtimes(members: dict):
    """Load API keys from Postgres and create runtimes for members that have them."""
    # Fetch all API keys. Sealed at rest (C1) — api_key_store unseals, and seals
    # any legacy plaintext row in place, so the value here is always usable material.
    data = await api_key_store.load_api_keys(_pg())
    if not data:
        logger.info("member runtime: no member API keys found — no member runtimes created")
        return

    # Map profile_id → key info
    keys_by_profile: dict[str, dict] = {}
    for row in data:
        pid = row.get("profile_id", "")
        if pid:
            keys_by_profile[pid] = row

    # Fetch agent → profile mapping
    agents_data = await _pg()(
        "GET",
        "agents",
        params={
            "select": "agent_id,profile_id,llm_provider,llm_model",
            "status": "eq.active",
        },
    )
    if not agents_data:
        return

    # Build agent_id → profile_id + model mapping
    agent_profiles: dict[str, dict] = {}
    for row in agents_data:
        aid = row.get("agent_id", "")
        if aid:
            agent_profiles[aid] = row

    created = 0
    for agent_id, member in members.items():
        if agent_id in runtimes:
            continue  # Already have a runtime

        profile = agent_profiles.get(agent_id, {})
        profile_id = profile.get("profile_id", "")
        if not profile_id:
            continue

        key_info = keys_by_profile.get(profile_id)
        if not key_info:
            continue

        provider = key_info.get("provider") or llm_config.PROVIDER
        api_key = key_info.get("api_key", "")
        base_url = key_info.get("base_url", "")
        model = profile.get("llm_model") or llm_config.DEFAULT_MODEL

        # A LOCAL PROVIDER HAS NO KEY TO HOLD, and this used to refuse a runtime
        # to every member on one. The wizard's own express default is ollama, so
        # the most common configuration in the product was the one that silently
        # got no runtime at all. Only a REMOTE provider without a key is skipped.
        if _member_is_unreachable(provider, api_key):
            continue

        # The per-provider base URL table is gone; llm_runtime.PROVIDERS is the
        # one registry. An unknown provider name falls back to the chapter's own
        # configured base_url, which is what this did before.
        if not base_url:
            entry = llm_runtime.PROVIDERS.get(llm_runtime.normalise_provider(provider))
            base_url = entry.base_url if entry is not None else llm_config.BASE_URL

        try:
            rt = MemberAgentRuntime(agent_id, member, provider, api_key, base_url, model)
            runtimes[agent_id] = rt
            created += 1
        except Exception as e:
            logger.warning("member runtime: failed to create runtime for @%s: %s", agent_id, e)

    if created:
        logger.info("member runtime: created %d member runtime(s) (%d total)", created, len(runtimes))


async def think_member_cycle(members: dict):
    """Run one member think cycle — pick an active runtime and let it think."""
    active = [aid for aid, rt in runtimes.items() if rt.status == "active"]
    if not active:
        return

    # Pick a random active member to think
    agent_id = random.choice(active)
    rt = runtimes[agent_id]

    # Get recent member thoughts for dedup
    recent = await _pg()(
        "GET",
        "agent_thoughts",
        params={
            "member_agent_id": f"eq.{agent_id}",
            "order": "created_at.desc",
            "limit": "5",
            "select": "thought_text",
        },
    )
    recent_texts = [t.get("thought_text", "")[:50] for t in (recent or [])]

    thought = await rt.think(members, recent_texts)
    if thought:
        # Log as a member thought
        a2ui = _build_thought_card(
            "member_insight",
            f"@{agent_id} thinks",
            thought,
            [{"agent_id": agent_id, "name": rt.member["name"], "chapter": _chapter_agent_name}],
        )
        await _log_agent_thought(
            "member_insight",
            thought,
            a2ui,
            member_agent_id=agent_id,
            member_name=rt.member["name"],
        )
        logger.debug("member runtime @%s thought: %s...", agent_id, thought[:80])


def has_runtime(agent_id: str) -> bool:
    """Check if a member has an active runtime."""
    rt = runtimes.get(agent_id)
    return rt is not None and rt.status == "active"


async def member_respond(agent_id: str, message: str, conversation_id: str) -> str | None:
    """Route a message to a member's runtime. Returns None if no runtime."""
    rt = runtimes.get(agent_id)
    if not rt or rt.status != "active":
        return None
    return await rt.respond(message, conversation_id)
