"""
Local Agent Runtime — autonomous sovereign agent running on your machine.

Uses YOUR LLM key, stores private memory LOCALLY, connects to chapter via A2A.
"""

import asyncio
import json
from datetime import datetime, timezone

from rich.console import Console

from . import llm_client, retry_policy
from .a2a_client import A2AClient
from .config import Config

console = Console()

AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "join_chapter",
            "description": (
                "Register this agent with an org under a chosen alias. "
                "Use when the user asks to 'join' a chapter or to register "
                "as a member. First-time call generates a chapter membership; "
                "subsequent calls are idempotent on the same agent_id."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Public alias to register under.",
                    },
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "skills": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["agent_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_chapter",
            "description": "Search for members in the chapter who match a skill or topic.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What you are looking for."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_federation",
            "description": (
                "Search across all federated chapters for members who match a "
                "skill or topic. Results are anonymized — identity is revealed "
                "only after bilateral consent."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_intent",
            "description": (
                "Submit a need to the chapter's intent-matching system. The "
                "federation finds matching members anonymously."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "intent_text": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["intent_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "respond_to_intent",
            "description": "Accept or decline an intent match.",
            "parameters": {
                "type": "object",
                "properties": {
                    "intent_id": {"type": "string"},
                    "response": {"type": "string", "enum": ["accept", "decline"]},
                },
                "required": ["intent_id", "response"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_projection",
            "description": (
                "Update the skills/interests/availability you share publicly with the chapter. "
                "This is what the chapter and federation can match against — you control visibility."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "skills": {"type": "array", "items": {"type": "string"}},
                    "interests": {"type": "array", "items": {"type": "string"}},
                    "availability": {"type": "string", "enum": ["active", "occasional", "unavailable"]},
                },
                "required": ["skills"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_chapter_intelligence",
            "description": (
                "Fetch the chapter's aggregated knowledge: skill distribution, patterns, "
                "skill gaps, trending topics. Use this before proposing insights or intents."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_conversation",
            "description": (
                "Start an agent-to-agent conversation thread with another member agent. "
                "The chapter brokers the thread; identity is shared once both sides accept."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "peer_agent_id": {"type": "string"},
                    "opening_message": {"type": "string"},
                },
                "required": ["peer_agent_id", "opening_message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_conversations",
            "description": "List open agent-to-agent conversation threads for this member.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_note",
            "description": "Save a private note locally. Only you can see this — never leaves your machine.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"],
            },
        },
    },
    # ── W11: skill registry ──────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "install_skill",
            "description": (
                "Install a signed skill from the chapter's skill registry. "
                "The skill's Ed25519 signature is verified before it touches disk. "
                "After install, the skill's tools become available in future turns."
            ),
            "parameters": {
                "type": "object",
                "properties": {"skill_id": {"type": "string", "description": "e.g. file-ops@1.0.0"}},
                "required": ["skill_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rate_skill",
            "description": (
                "Post a 1-5 star review on a skill you have installed. "
                "Requires the signed_install_proof stored locally from when you installed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "skill_id": {"type": "string"},
                    "rating": {"type": "integer", "minimum": 1, "maximum": 5},
                    "review_text": {"type": "string"},
                },
                "required": ["skill_id", "rating"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_installed_skills",
            "description": "List skills installed locally on this agent, with their declared capabilities.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    # ── W11: mesh ────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "find_peer",
            "description": (
                "Search for peer agents across your chapter and federated chapters. "
                "Results include trust tier + skills + whether the peer is local or federated."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "skills": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_to_peer",
            "description": (
                "Send a signed message to a peer agent. Delivery is automatic whether the peer is "
                "in your chapter or federated — the mesh routes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_agent_id": {"type": "string"},
                    "text": {"type": "string"},
                },
                "required": ["target_agent_id", "text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "my_trust",
            "description": "Return your current trust score + tier (newcomer / established / trusted / power).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    # ── W11: settings + channels ─────────────────────────
    {
        "type": "function",
        "function": {
            "name": "update_settings",
            "description": (
                "Update your per-agent settings bag. Supports llm / voice / channels / trust / privacy "
                "top-level keys. Unknown keys refused."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "patch": {
                        "type": "object",
                        "description": "Deep-merged into your current settings.",
                    }
                },
                "required": ["patch"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "connect_channel",
            "description": (
                "Register a channel connection — Slack / email / discord / webhook — so inbound "
                "messages from that platform route into your agent session."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["slack", "email", "discord", "webhook"]},
                    "remote_id": {
                        "type": "string",
                        "description": "Slack workspace id (T...), email address, Discord guild id, etc.",
                    },
                    "display_name": {"type": "string"},
                    "signing_secret": {
                        "type": "string",
                        "description": (
                            "The platform's verification secret (Slack signing secret / generic "
                            "HMAC secret / Discord app public key). Stored ONLY on this machine "
                            "(mode 0600) and never sent to the chapter — the receiver uses it to "
                            "verify inbound webhooks."
                        ),
                    },
                },
                "required": ["kind", "remote_id"],
            },
        },
    },
]


def _build_agent_client(config):
    """This agent's LLM client, or None when the provider cannot be resolved.

    Returns None rather than raising: a keyless or misconfigured agent is a
    supported state — it runs its deterministic skills and its A2A surfaces —
    and the gate that decides is ``llm_client.llm_is_configured``, not this.
    """
    from community_member import llm_runtime

    try:
        resolution = llm_runtime.resolve(config.provider, model=config.model or None)
        return llm_runtime.build_client(resolution, api_key=config.api_key, strict=llm_client.strict_enabled())
    except llm_runtime.LLMNotConfigured:
        return None


class LocalAgent:
    """Sovereign agent running on the member's machine."""

    def __init__(self, config: Config):
        self.config = config
        # Pass credentials so signed endpoints work. Pre-fix the client
        # was constructed with chapter_url only and `_auth_headers` used
        # to silently return ``{}`` when the keystore was empty —
        # requests went out unsigned and the server rejected with
        # ``missing_agent_id``. After the drift fix the client raises
        # ``MissingCredentialsError`` instead, which this constructor
        # was never updated to satisfy. Pull the key from the keystore
        # (single source of truth) rather than ``config.private_key``,
        # which is intentionally cleared after load to keep the key off
        # disk in plaintext.
        from community_member import keystore as _keystore

        priv = _keystore.load_private_key(config.agent_id, dir=config._home) if config.agent_id else ""
        self.client = A2AClient(
            config.chapter_url,
            agent_id=config.agent_id or "",
            private_key=priv or "",
            public_key=config.public_key or "",
        )
        from community_member import llm_skip as _llm_skip

        self.thought_count = 0
        # Monotonic count of inbound messages drained. Carried into the skip
        # watermark: a drained message changes what the agent should do without
        # changing a byte of what it would send.
        self.inbound_drained_total = 0
        # This agent's memo of its last real planning call. Per instance, not
        # per process: a module-global memo would let two agents in one process
        # serve each other's outcomes, and would hand a newly constructed agent
        # the previous one's answers.
        self._plan_memo = _llm_skip.MemoStore()
        self.running = False
        # W11: shared channel_receiver.Inbox of verified inbound webhook events,
        # set by the entrypoint when a channel is configured. Drained each run
        # iteration by _drain_inbound(); None when no channel is wired.
        self.inbox = None

        # LLM client using member's own key. Local providers (ollama,
        # llama.cpp, mlx-lm) all expose OpenAI-compatible endpoints, so
        # the same client handles every option in PROVIDERS.
        # A KEYLESS INSTALL MUST NOT ADDRESS A THIRD PARTY IT WAS NEVER GIVEN.
        # This block used to read
        #     base_url=base_urls.get(config.provider, <xAI's URL>)
        #     api_key=config.api_key or "local"
        # so an install with provider="" and no key built a client pointed at
        # xAI holding the literal string "local", and the autonomous loop then
        # issued a rejected request every tick, forever — measured at ~17k
        # failed calls/day/agent, and orrery-up called that state "complete and
        # working". Two independent guesses, both wrong: the base URL and the
        # key. Neither is guessed any more.
        #
        # `llm_configured` is the single gate the rest of the runtime reads;
        # `llm_client.llm_is_configured` is its one definition, shared with the
        # skill path that already refused correctly.
        self.llm_configured = llm_client.llm_is_configured(config.provider, config.api_key)
        # Set when a TERMINAL LLM failure halts the think loop — the diagnosable
        # state PR3 requires, readable by /health and by tests.
        self.think_halted_reason: str | None = None
        # Built by the shared factory when configured, None when not. The gate is
        # unchanged; what changes is that the client carries the capped retry
        # count and the explicit timeout instead of the SDK defaults.
        self.llm = _build_agent_client(config) if self.llm_configured else None

        self._load_skills()
        self._surface_unresolved_actions()

    def _surface_unresolved_actions(self) -> None:
        """At start, name every action whose outcome nobody observed.

        A ``pending`` attempt in the Agency Log stamped by a process that no
        longer exists is an external call that may or may not have happened —
        the process died between the call and the receipt write.
        ``reconcile_orphans`` marks each ``unknown`` durably; this prints them
        so the operator sees them at the first restart rather than never.
        Nothing here retries one: a retry of an unknown outcome is a human's
        decision. A log that cannot be opened is reported, not swallowed.
        """
        from community_member.arp import AgencyLog

        try:
            log = AgencyLog(home=self.config.home)
        except Exception as e:  # noqa: BLE001 — startup must say why, then continue
            print(f"[agency-log][ERROR] could not open the Agency Log at {self.config.home}: {type(e).__name__}: {e}")
            return
        orphans = log.reconcile_orphans()
        for a in orphans:
            print(
                f"[agency-log][UNKNOWN] {a['category']} started {a['started_at']} "
                f"({a['summary']!r}, counterparty {a.get('counterparty_label') or '-'}, "
                f"attempt {a['attempt_id']}): the process died before the outcome was recorded. "
                f"Not retried — confirm with the counterparty."
            )
        owed = [a for a in log.unresolved_actions() if a["state"] == "succeeded"]
        for a in owed:
            print(
                f"[agency-log][RECEIPT OWED] {a['category']} attempt {a['attempt_id']} succeeded "
                f"but its receipt was not recorded ({a['detail'].get('receipt_error', '?')})."
            )

    def _load_skills(self) -> None:
        """Load built-in + installed skills and expose them as LLM tools.

        Built-in (first-party) skills are auto-granted their declared
        capabilities — the user implicitly trusts code shipped with the
        runtime. Installed (third-party) skills are loaded too, but their
        capabilities are NOT auto-granted here; an ungranted skill tool simply
        raises ``CapabilityDenied`` at call time, which the turn loop reports
        back to the model.

        Builds, in a single pass so the names can never drift apart:
          - ``self.skill_tool_defs`` — OpenAI function-tool defs to merge with
            :data:`AGENT_TOOLS`.
          - ``self._skill_dispatch`` — ``namespaced_name → (skill_id, tool)``
            so :meth:`execute_tool` can route a ``skill__*`` call.
        """
        from community_member import skill_runtime

        builtins = skill_runtime.load_builtin_skills()
        try:
            installed = skill_runtime.load_installed_skills()
        except Exception as exc:
            console.print(f"  [yellow]skill load warning: {exc}[/yellow]")
            installed = []

        self.loaded_skills = builtins + installed
        # Only built-ins are auto-granted; installed skills need explicit grants.
        self.skill_grants: dict[str, set[str]] = {s.skill_id: set(s.declared_capabilities) for s in builtins}
        # First-party skill ids. The autonomous think_v2 planner is offered
        # ONLY these as its skill catalog: their descriptions are first-party
        # text (safe to place in the planner's TRUSTED block), they're
        # auto-granted, and the starter pack is all non-high-risk. Installed
        # third-party skills stay invocable in interactive chat (human
        # present, grants explicit) but are never advertised to the
        # autonomous planner — a skill's own description is attacker-
        # controlled text and must not enter the trusted prompt block.
        self.builtin_skill_ids: set[str] = {s.skill_id for s in builtins}

        self.skill_tool_defs: list[dict] = []
        self._skill_dispatch: dict[str, tuple[str, str]] = {}
        for spec in skill_runtime.agent_tool_specs(self.loaded_skills):
            name = spec["name"]
            self._skill_dispatch[name] = (spec["_skill_id"], spec["_tool_name"])
            self.skill_tool_defs.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": spec.get("description") or name,
                        # OpenAI rejects a bare {} — always a valid object schema.
                        "parameters": spec.get("parameters") or {"type": "object", "properties": {}},
                    },
                }
            )

    @property
    def all_tools(self) -> list[dict]:
        """Built-in protocol tools plus every loaded skill tool — the full set
        the LLM may call in the chat panel and the legacy think loop."""
        return AGENT_TOOLS + self.skill_tool_defs

    def _system_prompt(self) -> str:
        return (
            f"You are @{self.config.agent_id}'s sovereign agent.\n"
            f"You represent {self.config.name} in your org.\n"
            f"About your human: {self.config.description}\n"
            f"Skills: {', '.join(self.config.skills)}\n"
            f"Interests: {', '.join(self.config.interests)}\n\n"
            f"You act in your human's best interest. Use tools to search for "
            f"connections, submit intents, and save private notes. Be concise."
        )

    async def execute_tool(self, name: str, args: dict) -> str:
        if name == "join_chapter":
            try:
                result = self.client.join_chapter(
                    agent_id=str(args.get("agent_id") or self.config.agent_id or ""),
                    name=str(args.get("name") or self.config.name or ""),
                    description=str(args.get("description") or self.config.description or ""),
                    skills=list(args.get("skills") or self.config.skills or []),
                    origin="sovereign",
                )
                return json.dumps(result)
            except Exception as e:
                return json.dumps({"error": f"join_chapter failed: {type(e).__name__}: {e}"})

        elif name == "search_chapter":
            result = self.client.send_message(args.get("query", ""), f"search-{self.config.agent_id}")
            return json.dumps({"response": result.get("content", {}).get("text", "")})

        elif name == "search_federation":
            result = self.client.search_federation(args.get("query", ""), args.get("tags", []))
            return json.dumps(result)

        elif name == "submit_intent":
            result = self.client.submit_intent(self.config.agent_id, args.get("intent_text", ""), args.get("tags", []))
            return json.dumps(result)

        elif name == "respond_to_intent":
            result = self.client.respond_to_intent(
                args.get("intent_id", ""), self.config.agent_id, args.get("response", "decline")
            )
            return json.dumps(result)

        elif name == "update_projection":
            result = self.client.update_projection(
                self.config.agent_id,
                skills=args.get("skills", []),
                interests=args.get("interests", []),
                availability=args.get("availability", "active"),
            )
            return json.dumps(result)

        elif name == "get_chapter_intelligence":
            result = self.client.get_knowledge()
            return json.dumps(result)

        elif name == "start_conversation":
            result = self.client.start_conversation(
                self.config.agent_id,
                args.get("peer_agent_id", ""),
                args.get("opening_message", ""),
            )
            return json.dumps(result)

        elif name == "list_conversations":
            result = self.client.get_conversations(self.config.agent_id)
            return json.dumps(result)

        elif name == "save_note":
            self.config.save_private_memory(args.get("key", ""), args.get("value", ""))
            return json.dumps({"saved": True})

        # ── W11: skill registry ──────────────────────────
        elif name == "install_skill":
            from community_member import skills as _skills_mod

            try:
                entry = _skills_mod.install_skill(
                    chapter_url=self.client.chapter_url,
                    skill_id=str(args.get("skill_id", "")),
                    agent_id=self.config.agent_id,
                    # The install POST requires an Ed25519-signed request; route it
                    # through the client's signed api_call (the unsigned default 401s).
                    chapter_api_fn=self.client.api_call,
                )
                return json.dumps({"ok": True, "installed": entry["skill_id"], "path": entry["path"]})
            except ValueError as e:
                return json.dumps({"error": str(e)})

        elif name == "rate_skill":
            from community_member import skills as _skills_mod

            skill_id = str(args.get("skill_id", ""))
            entry = _skills_mod.load_installed_registry().get(skill_id)
            if not entry:
                return json.dumps({"error": f"skill {skill_id!r} not installed — install before reviewing"})
            try:
                result = self.client.review_skill(
                    skill_id=skill_id,
                    reviewer_agent_id=self.config.agent_id,
                    rating=int(args.get("rating", 0)),
                    review_text=str(args.get("review_text", "")),
                    signed_install_proof=entry["install_proof"],
                )
                return json.dumps(result)
            except Exception as e:
                return json.dumps({"error": f"review failed: {e}"})

        elif name == "list_installed_skills":
            from community_member import skills as _skills_mod

            registry = _skills_mod.load_installed_registry()
            compact = [
                {
                    "skill_id": sid,
                    "installed_version": e.get("installed_version"),
                    "capabilities": e.get("capabilities", []),
                }
                for sid, e in registry.items()
            ]
            return json.dumps({"installed": compact, "count": len(compact)})

        # ── W11: mesh ────────────────────────────────────
        elif name == "find_peer":
            result = self.client.mesh_peers(
                query=args.get("query"),
                skills=args.get("skills"),
                limit=int(args.get("limit", 20) or 20),
            )
            return json.dumps(result)

        elif name == "send_to_peer":
            try:
                result = self.client.mesh_send(
                    sender_agent_id=self.config.agent_id,
                    target_agent_id=str(args.get("target_agent_id", "")),
                    text=str(args.get("text", "")),
                )
                return json.dumps(result)
            except Exception as e:
                return json.dumps({"error": f"send failed: {e}"})

        elif name == "my_trust":
            return json.dumps(self.client.mesh_trust(self.config.agent_id))

        # ── W11: settings + channels ─────────────────────
        elif name == "update_settings":
            # Route through settings_sync so the patch is validated, the local
            # cache is updated, and a chapter outage enqueues to the offline
            # outbox (replayed on reconnect) instead of failing the mutation.
            from . import settings_sync

            try:
                result = settings_sync.push_to_chapter(self.config.agent_id, args.get("patch") or {}, self.client)
                return json.dumps(result)
            except ValueError as e:
                return json.dumps({"error": f"invalid settings patch: {e}"})
            except Exception as e:
                return json.dumps({"error": f"settings update failed: {e}"})

        elif name == "connect_channel":
            try:
                kind = str(args.get("kind", ""))
                remote_id = str(args.get("remote_id", ""))
                # Store the verification secret LOCALLY (0600) for the receiver's
                # resolver — it must never leave this machine, so it is not part
                # of the metadata POSTed to the chapter below.
                secret = str(args.get("signing_secret", ""))
                if secret:
                    from . import channel_secrets

                    channel_secrets.set_secret(kind, remote_id, secret)
                result = self.client.connect_channel(
                    agent_id=self.config.agent_id,
                    kind=kind,
                    remote_id=remote_id,
                    display_name=str(args.get("display_name", "")),
                )
                return json.dumps(result)
            except Exception as e:
                return json.dumps({"error": f"connect_channel failed: {e}"})

        if name in self._skill_dispatch:
            return await self._execute_skill_tool(name, args)

        return json.dumps({"error": f"Unknown tool: {name}"})

    async def _execute_skill_tool(self, name: str, args: dict) -> str:
        """Route a namespaced ``skill__*`` call through the skill runtime.

        Capability/consent/tool errors are translated to a JSON ``error`` so
        the model sees a uniform tool-result shape and can recover rather than
        the turn loop crashing.
        """
        from community_member import skill_runtime

        skill_id, tool_name = self._skill_dispatch[name]
        try:
            result = skill_runtime.invoke_tool(
                self.loaded_skills,
                skill_id,
                tool_name,
                args or {},
                self.skill_grants,
                chapter_url=self.config.chapter_url,
            )
        except skill_runtime.ToolError as e:
            return json.dumps({"error": str(e), "skill": skill_id, "tool": tool_name})
        return result if isinstance(result, str) else json.dumps(result)

    async def think(self) -> str | None:
        """One autonomous think cycle."""
        # Check for pending intents
        try:
            pending = self.client.get_intents_pending(self.config.agent_id)
            pending_list = pending.get("pending", [])
        except Exception:
            pending_list = []

        context = ""
        if pending_list:
            context = f"You have {len(pending_list)} pending intent matches:\n"
            for p in pending_list[:3]:
                context += f"  - {p.get('intent_text', '?')[:80]}\n"

        prompt = (
            f"As @{self.config.agent_id}'s agent, review the situation and take ONE action.\n"
            f"Your skills: {', '.join(self.config.skills[:5])}\n"
            f"{context}\n"
            f"Options: respond to intents, submit your own intent, save a note, or generate an insight.\n"
            f"Choose the most impactful action."
        )

        try:
            messages = [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": prompt},
            ]

            for step in range(3):
                response = self.llm.chat.completions.create(
                    model=self.config.model,
                    messages=messages,
                    tools=self.all_tools,
                    max_tokens=300,
                )
                choice = response.choices[0]

                if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
                    messages.append(choice.message)
                    for tc in choice.message.tool_calls:
                        result = await self.execute_tool(tc.function.name, json.loads(tc.function.arguments))
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                    continue

                reply = choice.message.content or ""
                if reply:
                    self.thought_count += 1
                    return reply

        except Exception as e:
            console.print(f"  [red]Think error: {e}[/red]")

        return None

    def build_runners(self, chapter_id: str) -> dict:
        """Capability→runner map for the v2 executor.

        Extracted from think_v2 so the consent-approve endpoint can run an
        APPROVED action through the SAME runners (identical provenance
        enforcement + audit) as the autonomous loop. Each runner looks up a
        valid approval via gate.find_valid_approval, calls the surface
        executor, and pins output provenance untrusted."""
        from community_member.actions.browser import BrowserExecutor

        # ── Runners — all 4 v2 surfaces wired via adapters ──────────
        # Each runner: takes an ActionRequest, looks up the recent
        # approval (graduation or user-clicked), calls the executor,
        # converts ActionResult → ToolOutput. Provenance pinned to
        # "untrusted" on output (browser/file/shell/net content is
        # always untrusted — defense matches executor._ALWAYS_UNTRUSTED).
        from community_member.actions.desktop import DesktopExecutor
        from community_member.actions.desktop_drivers import autodetect as autodetect_desktop
        from community_member.actions.files import FilesExecutor
        from community_member.actions.net import NetExecutor
        from community_member.actions.shell import ShellExecutor

        # The operator's capability grants. Absent file → no grants → every
        # path, host, binary and origin refused. Until this was wired, nothing
        # read the policy DSL at all, so the four policy-gated executors ran
        # permanently deny-all with no way to permit anything.
        from community_member.consent import gate as _gate
        from community_member.executor import ToolOutput
        from community_member.sandbox import grants as _grants

        # This agent's own home, not the module-level CONFIG_DIR. That constant
        # is bound at import, so a home configured afterwards — a second agent,
        # a test, anything setting COMMUNITY_MEMBER_HOME late — would read
        # grants from the wrong directory and name the wrong file in a refusal.
        home = self.config.home

        try:
            policy = _grants.load_policy(home)
        except Exception as e:
            # A malformed grants file is never partially applied: run with no
            # grants (refusing everything) and say why, rather than silently
            # enforcing a policy the operator did not write.
            console.print(f"  [red]capability grants not loaded — every action will be refused: {e}[/red]")
            policy = _grants.Policy(grants=())
        grants_file = _grants.grants_path(home)
        # Some grants permit more than their capability name suggests. The
        # executor narrows one shape of argument — one naming an existing file
        # outside the fs.* grants — so a binary that takes a host, or a path
        # inside a program string, is still not bounded by the patterns beside
        # it. Report it, never refuse it — the operator may mean it.
        for warning in _grants.lint_policy(policy):
            console.print(f"  [yellow]capability grants: {warning}[/yellow]")

        browser_exec = BrowserExecutor(
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            policy=policy,
            grants_file=grants_file,
        )
        files_exec = FilesExecutor(
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            policy=policy,
            grants_file=grants_file,
        )
        shell_exec = ShellExecutor(
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            policy=policy,
            grants_file=grants_file,
        )
        net_exec = NetExecutor(
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            policy=policy,
            grants_file=grants_file,
        )
        # Desktop driver is best-effort: autodetect returns None on
        # unsupported OS / Wayland / no-display, which means desktop.*
        # proposals will fall back to "no_driver_configured" inside
        # the executor — never silently swallowed.
        desktop_driver = autodetect_desktop()
        desktop_exec = DesktopExecutor(
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            driver=desktop_driver,
            policy=policy,
        )

        def _denied_output(req, reason: str, source_ref: str | None = None) -> ToolOutput:
            return ToolOutput(
                capability=req.capability,
                scope=req.scope,
                outcome="denied",
                content="",
                provenance="untrusted",
                source_ref=source_ref or req.source_ref,
                extra={"reason": reason},
            )

        def _result_to_output(req, result, *, source_ref: str | None, content_max: int = 4000) -> ToolOutput:
            """Carry an executor's ActionResult across to a ToolOutput.

            The outcome is passed through, not re-derived. The executor has
            already decided why it stopped; re-classifying anything non-"ok" as
            "fail" discarded that, so an action refused for want of a valid
            approval arrived at the caller indistinguishable from one that ran
            and errored. `ToolOutcome` and `ActionResult`'s outcomes share the
            same vocabulary, and `_denied_output` on the sibling path already
            returns "denied" for the same refusal.
            """
            return ToolOutput(
                capability=req.capability,
                scope=req.scope,
                outcome=result.outcome,
                content=str(result.data or "")[:content_max],
                provenance="untrusted",
                source_ref=source_ref or req.source_ref,
                extra=dict(result.extra or {}),
            )

        def browser_navigate_runner(req) -> ToolOutput:
            url = (req.extra or {}).get("url") or req.scope
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=url)
            result = browser_exec.navigate(
                url,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
                source_ref=req.source_ref,
            )
            return _result_to_output(req, result, source_ref=url)

        def files_read_runner(req) -> ToolOutput:
            path = (req.extra or {}).get("path") or req.scope
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=path)
            result = files_exec.read_file(
                path,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
            )
            return _result_to_output(req, result, source_ref=path)

        def shell_exec_runner(req) -> ToolOutput:
            extra = req.extra or {}
            binary = extra.get("binary") or req.scope
            args = tuple(extra.get("args") or ())
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=binary)
            result = shell_exec.exec_command(
                binary,
                args,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
            )
            return _result_to_output(req, result, source_ref=binary)

        def net_http_runner(req) -> ToolOutput:
            url = (req.extra or {}).get("url") or req.scope
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=url)
            result = net_exec.http_get(
                url,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
            )
            return _result_to_output(req, result, source_ref=url)

        def desktop_click_runner(req) -> ToolOutput:
            extra = req.extra or {}
            target = extra.get("target") or req.scope
            x = int(extra.get("x", 0) or 0)
            y = int(extra.get("y", 0) or 0)
            button = str(extra.get("button") or "left")
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=f"desktop:{target}")
            result = desktop_exec.click(
                target,
                x=x,
                y=y,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
                button=button,
            )
            return _result_to_output(req, result, source_ref=f"desktop:{target}")

        def desktop_type_runner(req) -> ToolOutput:
            extra = req.extra or {}
            target = extra.get("target") or req.scope
            # The proposal carries text_sha256/text_len in extra (see
            # DesktopExecutor.propose_type) but the literal text travels
            # in req.extra["text"] when the planner re-emits it for
            # execute. Missing text → denied; never silently no-op.
            text = extra.get("text")
            if not isinstance(text, str):
                return _denied_output(req, "missing_text", source_ref=f"desktop:{target}")
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=f"desktop:{target}")
            result = desktop_exec.type_text(
                target,
                text,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
            )
            return _result_to_output(req, result, source_ref=f"desktop:{target}")

        def desktop_read_screen_runner(req) -> ToolOutput:
            extra = req.extra or {}
            target = extra.get("target") or req.scope
            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=f"desktop:{target}")
            result = desktop_exec.read_screen(
                target,
                context=req.context,
                approval_event_sha256=approval["event_sha256"],
            )
            return _result_to_output(req, result, source_ref=f"desktop:{target}")

        def skill_invoke_runner(req) -> ToolOutput:
            # Dispatch a consent-approved skill call to skill_runtime. This
            # runner only fires AFTER the gate recorded an approval (no
            # auto-approve for skill.invoke — see executor._NO_AUTO_APPROVE),
            # so the matched approval is a genuine per-call human click;
            # passing consent_per_invocation=True honours that for any
            # high-risk capability the skill declares.
            from community_member import skill_runtime

            extra = req.extra or {}
            # Read identity from extra ONLY — req.scope is now a derived
            # consent identity (skill_id::tool::args_hash), not the skill_id.
            skill_id = str(extra.get("skill_id") or "")
            tool_name = str(extra.get("tool_name") or "")
            raw_args = extra.get("args")
            args = dict(raw_args) if isinstance(raw_args, dict) else {}
            ref = f"skill:{skill_id}:{tool_name}"
            if not skill_id or not tool_name:
                return _denied_output(req, "missing_skill_id_or_tool_name", source_ref=ref)

            approval = _gate.find_valid_approval(req, chapter_id=chapter_id)
            if approval is None:
                return _denied_output(req, "no_valid_approval_at_runner", source_ref=ref)
            try:
                result = skill_runtime.invoke_tool(
                    self.loaded_skills,
                    skill_id,
                    tool_name,
                    args,
                    self.skill_grants,
                    consent_per_invocation=True,
                    chapter_url=self.config.chapter_url,
                )
            except skill_runtime.ToolError as e:
                # Capability/consent/tool errors are a clean failure, not a
                # crash — surface the reason, keep provenance untrusted.
                return ToolOutput(
                    capability=req.capability,
                    scope=req.scope,
                    outcome="fail",
                    content="",
                    provenance="untrusted",
                    source_ref=ref,
                    extra={"reason": str(e)},
                )
            # invoke_tool returns the tool's raw value (dict/str), NOT an
            # ActionResult — so build the output directly rather than via
            # _result_to_output. Skill output is external data → untrusted.
            content = result if isinstance(result, str) else json.dumps(result)
            return ToolOutput(
                capability=req.capability,
                scope=req.scope,
                outcome="ok",
                content=str(content)[:4000],
                provenance="untrusted",
                source_ref=ref,
            )

        runners = {
            "browser.navigate": browser_navigate_runner,
            "fs.read": files_read_runner,
            "shell.exec": shell_exec_runner,
            "net.http": net_http_runner,
            "desktop.click": desktop_click_runner,
            "desktop.type": desktop_type_runner,
            "desktop.read_screen": desktop_read_screen_runner,
            "skill.invoke": skill_invoke_runner,
        }

        return runners

    def run_approved_action(self, req) -> dict:
        """Execute a single already-approved action NOW, returning a
        serializable summary.

        Used by the consent-approve endpoint so a tray/inbox approval runs
        immediately instead of waiting for the next autonomous cycle. This
        does NOT bypass the gate: the action only fires because a matching
        ``consent.approved`` row was just recorded, which
        ``find_valid_approval`` (inside ``execute_plan`` + each runner)
        re-checks. ``habit_model`` + ``context_sha256`` are passed so the
        click counts toward graduation in the SAME bucket as the autonomous
        loop; graduation_store/trust are intentionally omitted so the only
        path to "approved" here is the real user click.
        """
        import hashlib

        from community_member.config import CONFIG_DIR
        from community_member.consent import ledger as _ledger
        from community_member.executor import execute_plan
        from community_member.habits import HabitModel
        from community_member.planner import Plan

        chapter_id = f"local:{self.config.agent_id}" if self.config.agent_id else "local:unknown"
        try:
            from community_member import keystore

            # Always init WITH the signing key so click-driven appends are
            # Ed25519-signed and stay in the verifiable chain (G4). init() also
            # no longer downgrades a previously-keyed ledger to unsigned.
            home = self.config._home
            priv = keystore.load_private_key(self.config.agent_id, dir=home) if self.config.agent_id else None
            _ledger.init(self.config.home / "consent.db", signing_key_b64=priv)
        except Exception:
            pass
        try:
            habit_model = HabitModel(CONFIG_DIR / "habits.db")
        except Exception:
            habit_model = None
        context_sha256 = hashlib.sha256(f"think_v2:{self.config.agent_id or 'unknown'}".encode()).hexdigest()

        results = execute_plan(
            Plan(proposals=(req,)),
            self.build_runners(chapter_id),
            chapter_id=chapter_id,
            actor_agent_id=self.config.agent_id or None,
            habit_model=habit_model,
            context_sha256=context_sha256,
        )
        r = results[0]
        out = r.output
        return {
            "decision": r.decision.state,
            "reason": r.decision.reason,
            "outcome": (out.outcome if out is not None else None),
            "content": (out.content[:1000] if out is not None and out.content else ""),
            "error": r.error,
        }

    def think_v2(self):
        """One think cycle using the v2 planner/executor/consent stack.

        Unlike the legacy `think()`, this method:
          - Runs through the typed planner/executor split so
            web/chapter content cannot be mistaken for user instructions
            (indirect prompt-injection defense)
          - Writes every proposed action to the hash-chained consent
            ledger BEFORE any runner touches the host
          - Wires real runners (browser, files, shell, net) so
            graduated or user-approved actions actually fire on the
            next cycle
          - Returns a ThinkOutcome with four partitioned buckets
            (approved / pending_approval / rejected / errored) so the
            tray UI can surface exactly "here's what I'd like to do"

        Returns a `ThinkOutcome` or `None` on catastrophic LLM error
        (mirroring the legacy `think()` return shape).
        """
        import hashlib

        from community_member import keystore
        from community_member.config import CONFIG_DIR
        from community_member.consent import ledger as _ledger
        from community_member.graduation import GraduationStore
        from community_member.habits import HabitModel
        from community_member.llm_skip import SkipInputs as _SkipInputs
        from community_member.planner import (
            PlannerContext,
            SemiTrustedContext,
            TrustedContext,
        )
        from community_member.runtime import think_v2 as _think_v2

        # Lazy-init the consent ledger. Idempotent on repeat calls.
        try:
            home = self.config._home
            priv = keystore.load_private_key(self.config.agent_id, dir=home) if self.config.agent_id else None
            _ledger.init(self.config.home / "consent.db", signing_key_b64=priv)
        except Exception as e:
            console.print(f"  [yellow]consent ledger init failed: {e}[/yellow]")
            return None

        chapter_id = f"local:{self.config.agent_id}" if self.config.agent_id else "local:unknown"

        # ── Habit model + graduation store (per-cycle) ──────────────
        habit_model: HabitModel | None
        graduation_store: GraduationStore | None
        try:
            habit_model = HabitModel(CONFIG_DIR / "habits.db")
            graduation_store = GraduationStore(
                CONFIG_DIR / "graduations.db",
                device_did=self.config.agent_id or "unknown",
            )
        except Exception as e:
            console.print(f"  [yellow]habit/graduation init failed: {e}[/yellow]")
            habit_model = None
            graduation_store = None

        # ── Per-cycle context fingerprint ───────────────────────────
        # Coarse "what kind of situation am I in" key. Originally
        # this included the hour timestamp, which broke graduation
        # in practice — graduation requires ≥5 approvals in the
        # SAME context, but every hour was a new context, so users
        # would never see anything graduate unless they approved
        # the same action 5 times within one hour. Now keyed only
        # by agent_id so repeated approvals across cycles
        # accumulate in the same bucket. The (cap, scope) discipline
        # in the executor still makes graduation per-capability +
        # per-scope so "browse arxiv" graduates independently from
        # "browse evil.com".
        cycle_ctx = f"think_v2:{self.config.agent_id or 'unknown'}"
        context_sha256 = hashlib.sha256(cycle_ctx.encode()).hexdigest()

        runners = self.build_runners(chapter_id)

        # Pending server intents → semi-trusted context.
        try:
            pending = self.client.get_intents_pending(self.config.agent_id)
            pending_items = tuple(f"intent: {p.get('intent_text', '?')[:200]}" for p in pending.get("pending", [])[:5])
        except Exception:
            pending_items = ()

        # First-party skill catalog for the planner — built-ins ONLY.
        # Safe to place in the TRUSTED block because every line here is
        # first-party text (skill name/tool/description authored by us,
        # not by a third-party skill author). Tells the planner which
        # skill_id/tool_name/args it may propose via skill.invoke.
        skill_catalog: list[str] = []
        for s in self.loaded_skills:
            if s.skill_id not in self.builtin_skill_ids:
                continue  # never advertise third-party skills to the autonomous loop
            for tool_name, spec in s.tool_specs.items():
                params = (spec.get("parameters") or {}).get("properties") or {}
                arg_names = ", ".join(params.keys()) or "no args"
                desc = (spec.get("description") or "").strip()
                skill_catalog.append(
                    f"skill.invoke → skill_id={s.skill_id} tool_name={tool_name} args=({arg_names}): {desc}"
                )

        # Build the typed context. The user's own profile is TRUSTED;
        # server intents are SEMI-TRUSTED; nothing here is untrusted
        # in this cycle. When a later cycle reads a webpage, THAT
        # content must go into UntrustedContext, never here.
        trusted = TrustedContext(
            items=(
                f"agent_id: {self.config.agent_id}",
                f"name: {self.config.name}",
                f"description: {self.config.description}",
                f"skills: {', '.join(self.config.skills)}",
                f"interests: {', '.join(self.config.interests)}",
            )
            + (("Available skills you may call via skill.invoke:",) + tuple(skill_catalog) if skill_catalog else ())
        )
        ctx = PlannerContext(
            user_task=(
                "Review the current situation and propose ONE helpful "
                "action. Prefer responding to pending intents, submitting "
                "your own intent, or saving an insight. You may also call "
                "an installed skill via skill.invoke when it advances the "
                "task (only the skills listed in TRUSTED CONTEXT)."
            ),
            trusted=trusted,
            semi_trusted=(
                (SemiTrustedContext(items=pending_items, source=f"chapter:{self.config.chapter_url}"),)
                if pending_items
                else ()
            ),
        )

        # Pull the user's self-asserted trust ceiling + the server's
        # cached attestation so trusted-provenance proposals can
        # auto-approve when effective trust >= AUTO_APPROVE_THRESHOLD.
        # Untrusted-provenance ignores both signals (prompt-injection
        # defense — never unlocked by trust).
        try:
            from community_member import identity_trust as _it

            trust_snap = _it.snapshot(CONFIG_DIR)
            local_trust_val: int | None = trust_snap.local
            chapter_trust_val: int | None = trust_snap.chapter
        except Exception:
            local_trust_val = None
            chapter_trust_val = None

        try:
            outcome = _think_v2(
                ctx,
                self.llm,
                model=self.config.model,
                runners=runners,
                chapter_id=chapter_id,
                actor_agent_id=self.config.agent_id or None,
                habit_model=habit_model,
                graduation_store=graduation_store,
                context_sha256=context_sha256,
                local_trust=local_trust_val,
                chapter_trust=chapter_trust_val,
                skip_inputs=_SkipInputs(
                    # The PINNED home, not the process-global CONFIG_DIR. A
                    # watermark read from another agent's stores would hold
                    # steady while this agent's own consent and graduation state
                    # moved, which is the wedge this watermark exists to prevent.
                    # These are the same paths the ledger and graduation store
                    # above are opened at.
                    consent_db=self.config.home / "consent.db",
                    graduation_db=self.config.home / "graduations.db",
                    inbox_drained=self.inbound_drained_total,
                    store=self._plan_memo,
                ),
                principal=self.config.agent_id or "",
            )
        except Exception as e:
            # ⚠️ DO NOT SWALLOW. ``run()`` classifies this through
            # ``retry_policy`` — the table both trees share byte-for-byte — and
            # that classifier is only reachable if the exception reaches it.
            # Returning None here is what made a sustained 401 send eight full
            # 1,403-token requests through eight consecutive refusals, and what
            # left the retryable-backoff branch in ``run()`` as dead code.
            #
            # The ORIGINAL exception propagates, deliberately not a wrapper:
            # ``classify()`` reads the status and the type name to tell a 429
            # (wait, it clears) from a 401 (stop, it cannot). Re-raising
            # everything as one terminal type would collapse that distinction
            # and halt the agent on a transient rate limit — the opposite of the
            # line ``retry_policy`` draws.
            #
            # An unrecognised exception classifies TERMINAL by that table's
            # documented default, so a bug in this path halts to the degraded
            # mode instead of retrying itself forever. That is the intended
            # direction: the caller stays alive and the cause surfaces.
            console.print(f"  [red]think_v2 error: {e}[/red]")
            raise

        self.thought_count += 1
        return outcome

    async def _run_deterministic_only(self, interval: int) -> None:
        """The degraded state: no LLM, everything else still working.

        One implementation deliberately shared by both routes into it — a
        keyless install (PR2, config-time) and a terminal LLM failure (PR3,
        run-time). The agent has ONE degraded mode, not two that drift.
        """
        while self.running:
            self._drain_inbound()
            await asyncio.sleep(interval)

    async def run(self, interval: int = 300):
        """Run the agent loop — think every N seconds.

        Default is the v2 dual-LLM planner/executor stack with consent
        gating. Set `COMMUNITY_MEMBER_THINK_V2=0` to fall back to the
        legacy v1 single-LLM tool loop. v1 was the default historically
        but has accumulated unhandled-error paths from upstream tool
        churn; v2 is the supported path. The opt-out exists so anyone
        still depending on v1's specific shape can pin it for now.

        Implementation note: ``think()`` performs synchronous LLM and
        HTTP calls inside an ``async def`` (the legacy openai SDK is
        sync). To keep the event loop responsive — uvicorn binding,
        FastAPI handlers, websocket frames — we run *every* think
        iteration through ``asyncio.to_thread``. Without this, the
        first iteration blocks for the full LLM-call duration and the
        FastAPI startup never reaches ``serve()``, manifesting as a
        process that prints "Waiting for application startup" forever
        and refuses connections on the dashboard port. We also yield
        once at the top of the loop so uvicorn binds before anything
        else runs.
        """
        import os

        self.running = True
        # v2 is now the default. Explicit "0" disables; any other
        # value (or unset) means on. Previous default was off.
        # Keyless ⇒ do not start a thinking loop at all. It has nothing to
        # think WITH, and the previous behaviour was to discover that once per
        # tick against a third-party endpoint. Deterministic skills, the inbox
        # drain and every A2A surface keep working — that is what "keyless
        # install" is allowed to mean.
        if not self.llm_configured:
            console.print(
                f"  [yellow]Agent @{self.config.agent_id}: no LLM configured "
                "(set provider + key, or a local provider) — running "
                "DETERMINISTIC-ONLY. The autonomous think loop is not started; "
                "non-LLM skills and agent surfaces are unaffected.[/yellow]"
            )
            await self._run_deterministic_only(interval)
            return

        v2 = os.environ.get("COMMUNITY_MEMBER_THINK_V2", "1") != "0"
        mode = "v2 (planner/executor + consent)" if v2 else "v1 (legacy tools)"
        console.print(f"  [green]Agent @{self.config.agent_id} is thinking — {mode}[/green]")

        # Yield to the event loop once so uvicorn finishes startup
        # before we issue any blocking LLM/HTTP call.
        await asyncio.sleep(0)

        # Consecutive RETRYABLE failures. Reset on any success, so a blip
        # followed by recovery does not leave the agent permanently slowed.
        consecutive_failures = 0
        # Consecutive cycles in which the runtime refused everything the
        # planner produced. Drives the backoff below; reset by any cycle
        # that is not fully refused.
        refused_cycles = 0

        while self.running:
            # Reset each cycle: only a fully-refused cycle widens it.
            this_interval = interval
            self._drain_inbound()
            if v2:
                try:
                    outcome = await asyncio.to_thread(self.think_v2)
                    consecutive_failures = 0
                except Exception as e:
                    decision = retry_policy.classify(e)
                    detail = retry_policy.describe(e, decision)
                    if decision is retry_policy.Decision.TERMINAL:
                        # Retrying cannot help. Stop thinking — but keep the
                        # agent alive and useful, in the same degraded state a
                        # keyless install runs in (PR2), so a bad key downgrades
                        # the agent instead of silently burning quota forever.
                        self.think_halted_reason = detail
                        console.print(
                            f"  [red]think_v2 TERMINAL — {detail}[/red]\n"
                            f"  [yellow]Agent @{self.config.agent_id}: think loop halted. "
                            "Deterministic skills, the inbox drain and agent surfaces "
                            "continue. Fix the cause and restart the agent.[/yellow]"
                        )
                        await self._run_deterministic_only(interval)
                        return
                    consecutive_failures += 1
                    wait = retry_policy.backoff_seconds(consecutive_failures)
                    console.print(
                        f"  [yellow]think_v2 retryable ({consecutive_failures}) — {detail} backing off {wait}s[/yellow]"
                    )
                    await asyncio.sleep(wait)
                    outcome = None
                if outcome is not None:
                    now = datetime.now(timezone.utc).strftime("%H:%M")
                    summary = (
                        f"plan={len(outcome.plan.proposals)} "
                        f"approved={len(outcome.approved)} "
                        f"pending={len(outcome.pending_approval)} "
                        f"rejected={len(outcome.rejected)} "
                        f"errored={len(outcome.errored)}"
                    )
                    console.print(f"  [{now}] [cyan]@{self.config.agent_id}:[/cyan] {summary}")
                    # A cycle whose every action was refused cannot succeed by
                    # being repeated — the same plan meets the same refusal
                    # until something outside the loop changes, most often an
                    # operator writing a capability grant. Repeating it on the
                    # configured interval spends a model call each time to
                    # accomplish nothing. Back off instead, on the same curve
                    # the retryable-failure path and the outbox already use.
                    #
                    # This asks whether the call bought anything, not whether
                    # the runtime refused: an empty plan and a pending-only
                    # cycle both spend a model call and produce no work, and
                    # both were excluded by the predicate this replaces.
                    if outcome.produced_nothing:
                        refused_cycles += 1
                        this_interval = max(interval, retry_policy.backoff_seconds(refused_cycles))
                        summary += f" — produced nothing, backing off to {this_interval}s"
                        console.print(
                            f"  [yellow]@{self.config.agent_id}: cycle produced no work "
                            f"({refused_cycles} cycle(s)) — next attempt in {this_interval}s. "
                            f"Grant what it may do, answer a pending prompt, or stop the loop.[/yellow]"
                        )
                    else:
                        # Any cycle that is not a total refusal returns the
                        # loop to its configured pace immediately. An operator
                        # who has just written their first grant must not wait
                        # out a backoff to see it take effect.
                        refused_cycles = 0
                    try:
                        from . import server

                        server.log_thought(summary)
                    except Exception:
                        pass
            else:
                # Run the legacy think() in a worker thread so its
                # synchronous LLM + HTTP calls don't block the event
                # loop. ``think`` is declared ``async def`` for shape
                # but its body is synchronous — wrap in to_thread by
                # invoking it through an ``asyncio.run`` shim inside
                # the worker.
                def _sync_think_shim() -> str | None:
                    return asyncio.run(self.think())

                try:
                    thought = await asyncio.to_thread(_sync_think_shim)
                except Exception as e:
                    console.print(f"  [red]think error: {e}[/red]")
                    thought = None
                if thought:
                    now = datetime.now(timezone.utc).strftime("%H:%M")
                    console.print(f"  [{now}] [cyan]@{self.config.agent_id}:[/cyan] {thought[:120]}")
                    try:
                        from . import server

                        server.log_thought(thought)
                    except Exception:
                        pass

            # `this_interval` is the configured interval unless the cycle
            # above widened it for a fully-refused loop.
            await asyncio.sleep(this_interval)

    def _drain_inbound(self) -> int:
        """Consume verified inbound channel messages (W11).

        The :7778 receiver has already verified the webhook signature and
        audit-chained each event; here we drain the shared inbox so the queue
        doesn't grow unbounded and surface each message (logged + recorded on
        the dashboard thought stream). Sending a *reply* back to the platform
        is the separate W7 outbound work — for now the agent becomes aware of
        inbound messages but does not auto-respond. Returns the count drained.
        """
        inbox = getattr(self, "inbox", None)
        if inbox is None:
            return 0
        items = inbox.drain_nowait()
        for item in items:
            console.print(f"  [blue]↘ inbound {item.kind} from {item.sender} ({item.session_scope})[/blue]")
            try:
                from . import server

                server.log_thought(f"inbound {item.kind} from {item.sender}")
            except Exception:
                pass
        self.inbound_drained_total += len(items)
        return len(items)

    def stop(self):
        self.running = False
