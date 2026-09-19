"""
Sovereign Agent Runtime — OpenClaw-inspired session manager.

Each member with an API key gets a sovereign agent session that:
- Has its own LLM client (member's provider/model)
- Uses tools to interact with the platform (search, intents, consent, profile)
- Reads from member-owned private memory (chapter can't access)
- Pushes projections to the chapter (chapter only sees what agent shares)
- Reasons in multi-step chains, not single LLM calls
- Carries portable memory between chapters

The chapter agent hosts the compute but CANNOT read private memory.
The member's agent controls what's shared via projection push.
"""

import asyncio
import json
import os
import random
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import api_key_store
import llm_config
import llm_runtime

# Injected dependencies
_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("sovereign_runtime.init() was never called — no pg_request injected")
    return _pg_request

_conv_store: Any = None
_log_activity: Any = None
_log_agent_thought: Any = None
_build_thought_card: Any = None
_knowledge_cache: Any = None
_chapter_agent_id = ""
_chapter_agent_name = ""

# Active sovereign sessions: agent_id → SovereignSession
sessions: dict[str, "SovereignSession"] = {}

# Tool definitions for the agent (OpenAI function calling schema)
AGENT_TOOLS: list[Any] = [
    {
        "type": "function",
        "function": {
            "name": "search_federation",
            "description": "Search for members across all chapters who match a skill or topic. Returns anonymized results — no names until consent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "What you're looking for, e.g. 'Rust developer' or 'climate tech expert'",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Skill tags to match against",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_intent",
            "description": "Submit a need to the matching system. The federation will find matching members anonymously.",
            "parameters": {
                "type": "object",
                "properties": {
                    "intent_text": {"type": "string", "description": "Describe what you need"},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "Skill tags"},
                },
                "required": ["intent_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "respond_to_intent",
            "description": "Accept or decline a matching intent request. Only reveals your identity if both sides accept.",
            "parameters": {
                "type": "object",
                "properties": {
                    "intent_id": {"type": "string"},
                    "response": {"type": "string", "enum": ["accept", "decline", "counter"]},
                    "counter_text": {"type": "string", "description": "Optional counter-proposal text"},
                },
                "required": ["intent_id", "response"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_projection",
            "description": "Update what skills and interests you share publicly with the chapter. This controls what others can match against.",
            "parameters": {
                "type": "object",
                "properties": {
                    "skills": {"type": "array", "items": {"type": "string"}, "description": "Skills to share publicly"},
                    "interests": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Interests to share publicly",
                    },
                    "availability": {"type": "string", "enum": ["active", "occasional", "unavailable"]},
                },
                "required": ["skills"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_private_note",
            "description": "Save a private note to your memory. Only you can access this — the chapter agent cannot read it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "A label for this note"},
                    "value": {"type": "string", "description": "The note content"},
                    "memory_type": {
                        "type": "string",
                        "enum": ["goal", "note", "preference", "context"],
                        "description": "Type of memory",
                    },
                },
                "required": ["key", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_chapter_intelligence",
            "description": "Get the chapter's current intelligence — trending topics, skill gaps, recommendations, patterns.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_conversation",
            "description": "Start an A2A conversation with another member's agent. Use this after finding a match to initiate contact.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_agent_id": {
                        "type": "string",
                        "description": "The agent ID to talk to (e.g., 'TEST-priya')",
                    },
                    "message": {"type": "string", "description": "Your opening message to their agent"},
                    "topic": {"type": "string", "description": "Brief topic label for the conversation"},
                },
                "required": ["target_agent_id", "message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_conversations",
            "description": "List your active conversation threads with other agents.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


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


class SovereignSession:
    """A sovereign agent session for one member.

    The session has its own LLM client, tool access, and private memory.
    It can reason in multi-step chains using tools.
    """

    def __init__(
        self, agent_id: str, member: dict, provider: str, api_key: str, base_url: str, model: str, profile_id: str
    ):
        self.agent_id = agent_id
        self.member = member
        self.provider = provider
        self.model = model
        self.profile_id = profile_id
        self.status = "active"
        self.thought_count = 0
        self.tool_calls = 0
        self.last_action_at = datetime.now(UTC).isoformat()

        # Built by the shared factory: capped retries and an explicit timeout,
        # rather than the SDK defaults this construction used to run. A
        # configured base_url still wins over the registry's.
        _resolution = llm_runtime.resolve(provider or llm_config.PROVIDER, model=model)
        if base_url and base_url != _resolution.base_url:
            _resolution = replace(_resolution, provider=replace(_resolution.provider, base_url=base_url))
        self.llm = llm_runtime.build_client(_resolution, api_key=api_key)

        # Conversation history for this session (ephemeral, compacted periodically)
        self._history: list[dict] = []

    def _system_prompt(self) -> str:
        m = self.member
        skills = ", ".join(m.get("skills", [])) or "general"
        personality = m.get("personality", "")
        description = m.get("description", "")

        intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
        trending = intel.get("trending_topics", [])[:3]

        return f"""You are @{self.agent_id}'s sovereign agent in the {_chapter_agent_name} chapter.
You represent {m.get("name", self.agent_id)} — their AI agent that acts on their behalf.

About your human: {description}
Skills: {skills}
{f"Personality: {personality}" if personality else ""}
{f"Trending in chapter: {', '.join(trending)}" if trending else ""}

You are SOVEREIGN — you act in your human's best interest:
- Use tools to search for connections, submit intents, save private notes
- Only share what your human would want shared (projection control)
- Private notes and goals are yours alone — the chapter cannot see them
- When accepting intros, evaluate if it truly benefits your human
- Be proactive: identify opportunities matching your human's skills

Keep responses concise. You are an agent, not a chatbot."""

    async def _execute_tool(self, name: str, args: dict) -> str:
        """Execute a tool call and return the result as a string.

        Every tool that corresponds to a gated action_kind is checked
        through authority.check_authority() first. Denials return a
        structured error that the LLM can surface back to the member.
        Successful actions then call authority.record_usage().
        """
        self.tool_calls += 1

        # Authority gate — checks scope + rate limits before the tool runs
        _authority_mod: Any
        try:
            import authority as _authority_mod

            action_kind = _authority_mod.TOOL_ACTION_MAP.get(name)
            if action_kind:
                ctx: dict = {}
                if action_kind == "rsvp_event":
                    ctx["type"] = args.get("attendance_type") or args.get("type")
                elif action_kind == "accept_meeting":
                    ctx["duration_min"] = args.get("duration_min")
                    ctx["hour"] = args.get("hour")
                decision = await _authority_mod.check_authority(self.agent_id, action_kind, ctx)
                if not decision["allowed"]:
                    return json.dumps({"error": "not_authorized", **decision})
                # Record usage BEFORE dispatch — slight over-count on tool
                # failure is better than forgetting to count on success. Only
                # actions with a rate constraint actually persist a counter.
                try:
                    await _authority_mod.record_usage(self.agent_id, action_kind)
                except Exception:
                    pass
        except ImportError:
            _authority_mod = None
        except Exception as e:
            return json.dumps({"error": "authority_gate_error", "detail": str(e)[:200]})

        if name == "search_federation":
            import projections

            matches = await projections.match_intent_vector(
                args.get("query", ""),
                args.get("tags", []),
                exclude_agent_id=self.agent_id,
            )
            if not matches:
                matches = projections.match_intent_against_projections(
                    args.get("query", ""),
                    args.get("tags", []),
                )
            return json.dumps(
                {
                    "matches": len(matches),
                    "top_skills": list(set(s for m in matches for s in m.get("matched_skills", [])))[:10],
                    "chapters": list(set(m.get("chapter", "") for m in matches)),
                }
            )

        elif name == "submit_intent":
            import intents

            intent_id = await intents.create_intent(
                self.agent_id,
                args.get("intent_text", ""),
                args.get("tags", []),
            )
            result = await intents.match_intent(intent_id)
            return json.dumps({"intent_id": intent_id, "matches": result.get("local_matches", 0)})

        elif name == "respond_to_intent":
            import consent_gate

            result = await consent_gate.respond_to_intent(
                args.get("intent_id", ""),
                self.agent_id,
                args.get("response", "decline"),
                args.get("counter_text", ""),
            )
            return json.dumps(result)

        elif name == "update_projection":
            import projections

            new_proj = projections.build_projection(
                self.agent_id,
                {
                    **self.member,
                    "skills": args.get("skills", self.member.get("skills", [])),
                    "config": {
                        **(self.member.get("config") or {}),
                        "interests": args.get("interests", []),
                        "availability": args.get("availability", "active"),
                    },
                },
            )
            # Push projection to server
            import embeddings

            embedding = await embeddings.embed_projection(new_proj)
            body: dict[str, Any] = {"projection_data": new_proj}
            if embedding:
                body["embedding"] = embedding
            await _pg()("PATCH", "agent_projections", params={"agent_id": f"eq.{self.agent_id}"}, body=body)
            return json.dumps({"updated": True, "skills_shared": len(args.get("skills", []))})

        elif name == "save_private_note":
            # Store in private memory — only accessible with member's auth token
            # Since we're running server-side with service key, we use a special
            # column approach: store with owner_id so RLS protects it
            await _pg()(
                "POST",
                "agent_private_memory",
                body={
                    "owner_id": self.profile_id,
                    "agent_id": self.agent_id,
                    "memory_type": args.get("memory_type", "note"),
                    "memory_key": args.get("key", ""),
                    "memory_value": {"content": args.get("value", "")},
                },
            )
            return json.dumps({"saved": True, "key": args.get("key", "")})

        elif name == "get_chapter_intelligence":
            intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
            return json.dumps(
                {
                    "trending_topics": intel.get("trending_topics", []),
                    "skill_gaps": intel.get("skill_gaps", []),
                    "recommendations": intel.get("recommendations", []),
                    "member_count": intel.get("member_count", 0),
                    "patterns": intel.get("patterns", []),
                }
            )

        elif name == "start_conversation":
            import agent_conversations

            target = args.get("target_agent_id", "")
            message = args.get("message", "")
            topic = args.get("topic", "")
            result = await agent_conversations.start_conversation(
                self.agent_id,
                target,
                message,
                topic,
            )
            if "error" not in result:
                # Route the opening message to the target agent for a response
                thread_id = result.get("thread_id", "")
                reply = await _route_to_agent(target, message, f"conv-{thread_id}")
                if reply:
                    await agent_conversations.send_message(thread_id, target, reply)
                    result["reply"] = reply
                import activity_tracker

                await activity_tracker.track(
                    self.agent_id, "agent_conversation", {"partner": target, "topic": topic[:100]}
                )
            return json.dumps(result)

        elif name == "list_conversations":
            import agent_conversations

            threads = await agent_conversations.get_threads(self.agent_id, limit=10)
            return json.dumps(
                [
                    {
                        "thread_id": t.get("id", ""),
                        "partner": t["to_agent_id"] if t["from_agent_id"] == self.agent_id else t["from_agent_id"],
                        "topic": t.get("topic", ""),
                        "status": t.get("status", ""),
                        "message_count": t.get("message_count", 0),
                    }
                    for t in threads
                ]
            )

        return json.dumps({"error": f"Unknown tool: {name}"})

    async def respond(self, message: str, conversation_id: str) -> str:
        """Handle a message with multi-step tool-using reasoning."""
        self._history.append({"role": "user", "content": message})

        messages: list[Any] = [
            {"role": "system", "content": self._system_prompt()},
            *self._history[-20:],
        ]

        # Multi-step reasoning loop (max 3 tool calls per turn)
        for step in range(4):
            try:
                response = self.llm.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=AGENT_TOOLS,
                    max_tokens=512,
                )
                choice = response.choices[0]

                # If model wants to call tools
                if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
                    messages.append(choice.message)
                    tool_calls: list[Any] = list(choice.message.tool_calls)
                    for tool_call in tool_calls:
                        fn_name = tool_call.function.name
                        fn_args = json.loads(tool_call.function.arguments)
                        result = await self._execute_tool(fn_name, fn_args)
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": result,
                            }
                        )
                    continue  # Let the model process tool results

                # Model is done reasoning — return the response
                reply = choice.message.content or "I couldn't generate a response."
                self._history.append({"role": "assistant", "content": reply})
                self.last_action_at = datetime.now(UTC).isoformat()

                # Persist conversation
                from chapter_agent import AGENT_DB_UUID

                await _conv_store.append(AGENT_DB_UUID, f"{self.agent_id}:{conversation_id}", message, reply)
                asyncio.create_task(
                    _log_activity(self.agent_id, self.member.get("name", ""), conversation_id, message, reply)
                )

                return reply

            except Exception as e:
                print(f"[Sovereign] @{self.agent_id} error: {e}")
                self.status = "error"
                return f"Agent @{self.agent_id} encountered an error."

        return "I've reached my reasoning limit for this turn."

    async def think(self, members: dict) -> str | None:
        """Autonomous thinking — the agent proactively looks for opportunities."""
        m = self.member
        skills = m.get("skills", [])
        if not skills:
            return None

        # Check for pending intents matching this agent
        import consent_gate

        pending = await consent_gate.get_pending_for_agent(self.agent_id)

        # Build a proactive prompt based on what's available
        context_parts = []
        if pending:
            context_parts.append(f"You have {len(pending)} pending intent requests to evaluate.")
            for p in pending[:2]:
                context_parts.append(f"  - Someone needs: {p['intent_text'][:80]}")

        intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
        if intel.get("skill_gaps"):
            gaps = intel["skill_gaps"][:3]
            matching_gaps = [g for g in gaps if any(s.lower() in g.lower() for s in skills)]
            if matching_gaps:
                context_parts.append(f"The chapter has skill gaps you could help with: {', '.join(matching_gaps)}")

        if intel.get("trending_topics"):
            context_parts.append(f"Trending: {', '.join(intel['trending_topics'][:3])}")

        context = "\n".join(context_parts) if context_parts else "No specific context — generate an insight."

        prompt = f"""As @{self.agent_id}'s sovereign agent, review the current situation and take ONE action.

Your skills: {", ".join(skills)}
{context}

Options:
1. If there are pending intents, use respond_to_intent to accept or decline
2. If there's a skill gap you can fill, use submit_intent to offer help
3. If there's a trending topic matching your skills, generate an insight
4. Use get_chapter_intelligence to learn what's happening

Choose the most impactful action. Respond with a brief summary of what you did."""

        result = await self.respond(prompt, f"sovereign-think-{self.agent_id}")

        if result and "error" not in result.lower() and "limit" not in result.lower():
            self.thought_count += 1
            asyncio.create_task(self._persist_session_state())
            return result

        return None

    async def _persist_session_state(self):
        """Save session state to Postgres."""
        existing = await _pg_request(
            "GET",
            "agent_sessions",
            params={
                "agent_id": f"eq.{self.agent_id}",
                "select": "id",
            },
        )
        body = {
            "session_state": self.status,
            "last_action_at": self.last_action_at,
            "thought_count": self.thought_count,
            "tool_calls": self.tool_calls,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        if existing:
            await _pg_request("PATCH", "agent_sessions", params={"agent_id": f"eq.{self.agent_id}"}, body=body)
        else:
            await _pg_request(
                "POST",
                "agent_sessions",
                body={
                    "agent_id": self.agent_id,
                    "chapter_agent_id": _chapter_agent_id,
                    **body,
                },
            )


async def _route_to_agent(target_agent_id: str, message: str, conversation_id: str) -> str | None:
    """Route a message to another agent's runtime. Returns their response."""
    # Try sovereign session first
    target_session = sessions.get(target_agent_id)
    if target_session and target_session.status == "active":
        return await target_session.respond(message, conversation_id)

    # Try member runtime
    import member_runtime

    reply = await member_runtime.member_respond(target_agent_id, message, conversation_id)
    if reply:
        return reply

    # Fallback: virtual member response via server agent
    try:
        from chapter_agent import members as chapter_members
        from chapter_agent import virtual_member_response

        if target_agent_id in chapter_members:
            return await virtual_member_response(
                target_agent_id, chapter_members[target_agent_id], message, conversation_id
            )
    except ImportError:
        pass

    return None



def _needs_a_credential(provider: str) -> bool:
    """Whether reaching ``provider`` requires a key we must already hold.

    Local endpoints do not. A remote one does, but the key may come from the
    environment at build time rather than from the stored row, so "we hold no
    stored key" is not the same question as "this member cannot run".
    """
    name = (provider or "").strip().lower()
    if name in llm_runtime.LOCAL_PROVIDERS:
        return False
    entry = llm_runtime.PROVIDERS.get(name)
    if entry is None:
        return True
    return not os.environ.get(entry.key_env, "").strip()



async def load_sessions(members: dict):
    """Load API keys and create sovereign sessions for members that have them."""
    # Sealed at rest (C1) — api_key_store unseals, and seals any legacy plaintext
    # row in place, so the value here is always usable material.
    unreadable: set[str] = set()
    data = await api_key_store.load_api_keys(_pg(), unreadable=unreadable)
    # NOT an early return any more. A member can now be runnable without a row
    # in the key table: an explicit LLM_PROVIDER supplies its own credential
    # from the environment, and a local provider needs none. Returning here on
    # an empty table meant those members silently never started.
    if not data:
        print("[Sovereign] No member API keys stored")

    keys_by_profile: dict[str, dict] = {}
    for row in data:
        pid = row.get("profile_id", "")
        if pid:
            keys_by_profile[pid] = row

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

    agent_profiles: dict[str, dict] = {}
    for row in agents_data:
        aid = row.get("agent_id", "")
        if aid:
            agent_profiles[aid] = row

    created = 0
    for agent_id, member in members.items():
        if agent_id in sessions:
            continue

        profile = agent_profiles.get(agent_id, {})
        profile_id = profile.get("profile_id", "")
        if not profile_id:
            continue

        # A member whose OWN key could not be read does not run, and must not
        # fall through to a local provider or the org's environment credential:
        # that would put their work on someone else's spend without anyone
        # choosing it.
        if profile_id in unreadable:
            continue

        # Absent is not disqualifying any more — see the credential check below.
        # A member with an explicit env provider, or a local one, has no row
        # here and is still runnable.
        key_info = keys_by_profile.get(profile_id) or {}

        # ── which provider runs, and with whose credential ───────────────
        #
        # ⚠️ THE PROVIDER AND THE KEY TRAVEL TOGETHER, ALWAYS. Taking the name
        # from one source and the credential from another is how a key for one
        # provider ends up in an Authorization header addressed to a different
        # one — the defect the shared registry exists to make unrepresentable.
        # So each branch below yields a PAIR.
        #
        # Precedence:
        #   1. an EXPLICIT ``LLM_PROVIDER`` — an operator who set it deliberately
        #      is not overridden by an onboarding choice made months earlier. The
        #      key then comes from the environment for that provider, never from
        #      the stored row.
        #   2. the member's stored key row — their own provider and their own
        #      key, which is what bring-your-own-key means.
        #   3. the provider recorded on the agent, but ONLY when it is a LOCAL
        #      endpoint. ``agents.llm_provider`` defaults to a remote provider
        #      at the column level, so a member who never chose anything is
        #      indistinguishable by value from one who did. Honouring that
        #      default would start members who have never run, on the ORG's
        #      credential — an increase in spend nobody asked for, on every
        #      deployed org at once. A local endpoint costs nothing and needs no
        #      key, so it is safe to start; a remote one arrives through 2, with
        #      the key that makes it a deliberate choice.
        #   4. the auto-detected default.
        #
        # Note 1 is the EXPLICIT variable, not ``llm_config.PROVIDER``, which is
        # never empty because it auto-detects. Treating the auto-detected value
        # as an operator decision would make it outrank every member's real key.
        explicit_env = os.environ.get("LLM_PROVIDER", "").strip().lower()
        if explicit_env:
            provider, api_key = explicit_env, ""  # build_client reads that provider's own key_env
        elif key_info.get("provider"):
            provider, api_key = key_info["provider"], key_info.get("api_key", "")
        elif str(profile.get("llm_provider") or "").strip().lower() in llm_runtime.LOCAL_PROVIDERS:
            provider, api_key = str(profile["llm_provider"]).strip().lower(), ""
        else:
            provider, api_key = llm_config.PROVIDER, key_info.get("api_key", "")

        # ⚠️ WHO MAY START WITHOUT A KEY OF THEIR OWN. Before this, a member
        # with no stored key never started at all, and that property must
        # survive: falling back to the org's environment credential would put
        # members who have never run onto the org's spend, everywhere, at once.
        # Exactly two cases may start keyless — an operator who set the variable
        # deliberately, and a local endpoint that bills nobody.
        has_own_key = bool(key_info.get("api_key"))
        deliberate = bool(explicit_env)
        local = provider.strip().lower() in llm_runtime.LOCAL_PROVIDERS
        if not (has_own_key or deliberate or local):
            continue
        # A member's stored base_url wins (a proxy or self-host is a correct
        # configuration). Otherwise the provider's address comes from the one
        # table that names it, llm_runtime.PROVIDERS — this used to carry its
        # own four-entry copy, which is one more place for a host to drift.
        known = llm_runtime.PROVIDERS.get(llm_runtime.normalise_provider(provider) or "")
        base_url = key_info.get("base_url", "") or (known.base_url if known else llm_config.BASE_URL)
        model = profile.get("llm_model") or llm_config.DEFAULT_MODEL

        # A remote provider still needs a credential to exist somewhere: the
        # stored row, or the environment for THAT provider.
        if not api_key and _needs_a_credential(provider):
            continue

        try:
            session = SovereignSession(agent_id, member, provider, api_key, base_url, model, profile_id)
            sessions[agent_id] = session
            created += 1
        except Exception as e:
            print(f"[Sovereign] Failed to create session for @{agent_id}: {e}")

    if created:
        print(f"[Sovereign] Created {created} sovereign sessions ({len(sessions)} total)")


async def think_sovereign_cycle(members: dict):
    """Run one sovereign think cycle — pick an active session and let it reason."""
    active = [aid for aid, s in sessions.items() if s.status == "active"]
    if not active:
        return

    agent_id = random.choice(active)
    session = sessions[agent_id]

    thought = await session.think(members)
    if thought:
        a2ui = _build_thought_card(
            "sovereign_insight",
            f"@{agent_id} (sovereign)",
            thought,
            [{"agent_id": agent_id, "name": session.member.get("name", agent_id), "chapter": _chapter_agent_name}],
        )
        await _log_agent_thought(
            "sovereign_insight",
            thought,
            a2ui,
            member_agent_id=agent_id,
            member_name=session.member.get("name", ""),
        )
        import activity_tracker

        await activity_tracker.track(agent_id, "member_thought", {"summary": thought[:100]})
        print(f"[Sovereign] @{agent_id} acted: {thought[:80]}...")


def has_session(agent_id: str) -> bool:
    s = sessions.get(agent_id)
    return s is not None and s.status == "active"


async def session_respond(agent_id: str, message: str, conversation_id: str) -> str | None:
    s = sessions.get(agent_id)
    if not s or s.status != "active":
        return None
    return await s.respond(message, conversation_id)
