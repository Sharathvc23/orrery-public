"""
A2A Client — communicates with an org agent.

Handles member registration, intent submission, conversation,
surface fetching, and agent export/import.

Most chapter endpoints require Ed25519-signed requests. The signing
layer is set up by configuring agent_id + private_key on construction;
endpoints that need auth route through ``_post`` / ``_get`` which call
``_auth_headers``. If the agent has no keypair configured, signed calls
raise ``MissingCredentialsError`` rather than silently sending unsigned
requests (which previously surfaced as confusing ``missing_agent_id``
errors at the chapter middleware).

Open endpoints that don't need a signature go through ``_get_open`` /
``_post_open``.
"""

import json

import httpx

from . import sanitize


class MissingCredentialsError(RuntimeError):
    """Raised when a signed call is attempted without agent_id + private_key.

    Pre-fix, ``_auth_headers`` returned ``{}`` whenever credentials were
    missing or signing raised. Calls then went out unsigned and the
    chapter rejected them with ``missing_agent_id``, which made it look
    like the chapter or the agent had a header-propagation bug. The
    real root cause was that the local SDK didn't know it had no key.
    """


class A2AClient:
    def __init__(
        self,
        chapter_url: str,
        agent_id: str = "",
        private_key: str = "",
        public_key: str = "",
    ):
        self.chapter_url = chapter_url.rstrip("/")
        self.agent_id = agent_id
        self.private_key = private_key
        self.public_key = public_key

    def _auth_headers(self, body: str = "", method: str = "", url_path: str = "") -> dict:
        """Build Ed25519-signed headers for an authenticated request.

        ``method`` and ``url_path`` bind the signature to the HTTP verb and
        request path (v0.3 ``ed25519+nonce``). They are REQUIRED for mutating
        requests — a v0.2 signature is method/path-agnostic, so the server now
        rejects it on POST/PUT/PATCH/DELETE (``method_binding_required``), and a
        captured GET can no longer be replayed as a DELETE.

        Raises ``MissingCredentialsError`` if ``agent_id`` or
        ``private_key`` are missing, or if the signing helper itself
        fails. Callers SHOULD only invoke this for endpoints that
        require auth — open endpoints use ``_get_open`` / ``_post_open``.
        """
        if not self.agent_id:
            raise MissingCredentialsError(
                "A2AClient.agent_id is empty — cannot sign request. "
                "Pass agent_id when constructing A2AClient, or use the "
                "open variant if the endpoint allows unauthenticated access."
            )
        if not self.private_key:
            raise MissingCredentialsError(
                f"A2AClient.private_key is empty for agent {self.agent_id!r} — "
                "cannot sign request. Run `community-member init` to generate "
                "an Ed25519 keypair, or load an existing one before calling."
            )
        try:
            from .auth import sign_request_body

            return sign_request_body(body, self.agent_id, method=method, url_path=url_path)
        except MissingCredentialsError:
            raise
        except Exception as e:
            raise MissingCredentialsError(f"Signing failed for agent {self.agent_id!r}: {type(e).__name__}: {e}") from e

    def _post(self, path: str, payload: dict, timeout: float = 15.0) -> dict:
        """POST with required auth headers (raises if no credentials)."""
        body = json.dumps(payload)
        headers = {"Content-Type": "application/json", **self._auth_headers(body, "POST", path)}
        resp = httpx.post(f"{self.chapter_url}{path}", content=body, headers=headers, timeout=timeout)
        return resp.json()

    def _get(self, path: str, timeout: float = 10.0) -> dict:
        """GET with required auth headers (raises if no credentials)."""
        headers = self._auth_headers("", "GET", path)
        resp = httpx.get(f"{self.chapter_url}{path}", headers=headers, timeout=timeout)
        return resp.json()

    def _delete(self, path: str, timeout: float = 10.0) -> dict:
        """DELETE with required auth headers (raises if no credentials)."""
        headers = self._auth_headers("", "DELETE", path)
        resp = httpx.delete(f"{self.chapter_url}{path}", headers=headers, timeout=timeout)
        return resp.json()

    def _post_open(self, path: str, payload: dict, timeout: float = 15.0) -> dict:
        """POST without auth — for endpoints in the chapter's OPEN_PATHS or
        SELF_SIGNED_POST_PATHS set (e.g. /api/members for first registration,
        which does TOFU internally)."""
        body = json.dumps(payload)
        headers = {"Content-Type": "application/json"}
        resp = httpx.post(f"{self.chapter_url}{path}", content=body, headers=headers, timeout=timeout)
        return resp.json()

    def _get_open(self, path: str, timeout: float = 10.0) -> dict:
        """GET without auth — for endpoints in the chapter's OPEN_PATHS set."""
        resp = httpx.get(f"{self.chapter_url}{path}", timeout=timeout)
        return resp.json()

    def health(self) -> dict:
        resp = httpx.get(f"{self.chapter_url}/health", timeout=10.0)
        resp.raise_for_status()
        return resp.json()

    def version(self) -> dict:
        """Probe the chapter's protocol-version advertisement.

        Open endpoint per spec/0.3/protocol.md — clients call this to
        decide which signing scheme to emit (ed25519 vs ed25519+nonce).
        Older v0.2-only chapters return 404; the caller should treat
        that as ``["0.2"]``.
        """
        return self._get_open("/api/version")

    @staticmethod
    def configured_agent_kind() -> str:
        """ "service" for an unattended agent, else "member".

        The org has had a `service` role since PR1 and NOTHING EVER SENT THIS —
        `agent_kind` appeared nowhere in `agent/community_member/`, so every
        service agent registered as a plain member and the role was unreachable
        from the only side that could ask for it.

        Allow-listed to the one safe value on purpose. `service` is strictly
        LESS privileged than `member` (no social surface, cannot attest, cannot
        approve, sees only the operational slice of the approval queue), so an
        agent naming it is dropping privilege. Anything else — including a
        hopeful "admin" — falls back to "member" here AND is re-checked
        server-side, because a client-side allow-list is a convenience, not a
        control.
        """
        import os

        return "service" if os.environ.get("COMMUNITY_MEMBER_AGENT_KIND", "").strip().lower() == "service" else "member"

    def register_member(
        self,
        agent_id: str,
        name: str,
        description: str,
        skills: list[str],
        personality: str = "",
        public_key: str = "",
        agent_kind: str | None = None,
    ) -> dict:
        """Register / re-register on the chapter (TOFU on first contact).

        ``/api/members`` is a self-signed POST endpoint per the chapter's
        SELF_SIGNED_POST_PATHS set: the handler enforces TOFU + origin
        immutability internally and does not require an outer
        X-Agent-Signature on the *first* registration. We send via
        ``_post_open`` (no auth) so a brand-new sovereign / OpenClaw
        agent can register before it has any signed history with this
        chapter.
        """
        payload = {
            "agent_id": agent_id,
            "name": sanitize.sanitize_name(name),
            "description": sanitize.sanitize_text(description),
            "skills": sanitize.sanitize_skills(skills),
            "personality": sanitize.sanitize_text(personality),
            "voice": "helpful",
            "virtual": True,
            # Always sent, never omitted: an absent field would fall back to
            # the server default and reproduce exactly the hole this closes.
            "agent_kind": agent_kind or self.configured_agent_kind(),
        }
        if public_key:
            payload["public_key"] = public_key
        return self._post_open("/api/members", payload)

    def send_message(self, text: str, conversation_id: str) -> dict:
        return self._post(
            "/a2a",
            {
                "role": "user",
                "content": {"type": "text", "text": text},
                "conversation_id": conversation_id,
            },
            timeout=30.0,
        )

    def get_surface(self, page_id: str) -> dict:
        # /api/surfaces/* is in the server's OPEN_PATHS — public render.
        return self._get_open(f"/api/surfaces/{page_id}")

    def export_agent(self, agent_id: str) -> dict:
        return self._get(f"/api/agents/{agent_id}/export", timeout=15.0)

    def get_sessions(self) -> dict:
        # /api/sessions is in OPEN_PATHS.
        return self._get_open("/api/sessions")

    def get_intents_pending(self, agent_id: str) -> dict:
        return self._get(f"/api/intents/pending/{agent_id}")

    def submit_intent(self, agent_id: str, text: str, tags: list[str] | None = None) -> dict:
        return self._post(
            "/api/intents",
            {
                "requester_agent_id": agent_id,
                "intent_text": sanitize.sanitize_intent(text),
                "intent_tags": sanitize.sanitize_skills(tags or []),
            },
        )

    def respond_to_intent(self, intent_id: str, agent_id: str, response: str) -> dict:
        return self._post(
            "/api/intents/respond",
            {
                "intent_id": intent_id,
                "responder_agent_id": agent_id,
                "response": response,
            },
        )

    def get_conversations(self, agent_id: str) -> dict:
        return self._get(f"/api/conversations/{agent_id}")

    def get_federation(self) -> dict:
        # /api/federation is in OPEN_PATHS — federation state is public.
        return self._get_open("/api/federation")

    def get_knowledge(self) -> dict:
        # /api/knowledge/network is in OPEN_PATHS.
        return self._get_open("/api/knowledge/network")

    def join_chapter(
        self,
        agent_id: str,
        name: str = "",
        description: str = "",
        skills: list[str] | None = None,
        personality: str = "",
        origin: str = "sovereign",
        endpoint: str = "",
    ) -> dict:
        """High-level: register this agent with the chapter under a given alias.

        Mirrors the ``join <chapter>`` verb the OpenClaw skill teaches.
        Wraps ``register_member`` with sensible defaults and an
        ``origin`` field (``sovereign`` for community-member SDK,
        ``openclaw`` for OpenClaw skill installs). The chapter records
        ``origin`` and applies the corresponding trust tier per
        spec/0.2/protocol.md §2.2.

        Defaults to ``origin=sovereign`` because this method lives in
        the sovereign SDK; the OpenClaw skill helper passes
        ``origin=openclaw`` when it calls the same endpoint.
        """
        # Sanitize user-controlled content before it leaves this machine
        # (defense in depth — the chapter validates too). The identity fields
        # (agent_id, public_key) are NOT touched: they must match the signed
        # request, and agent_id is already format-constrained.
        payload = {
            "agent_id": agent_id,
            "name": sanitize.sanitize_name(name) or agent_id,
            "description": sanitize.sanitize_text(description),
            "skills": sanitize.sanitize_skills(list(skills or [])),
            "personality": sanitize.sanitize_text(personality),
            "voice": "helpful",
            "virtual": True,
            "origin": origin,
        }
        if endpoint:
            # the agent's public URL — lets a host39-less org resolve
            # this member to its own served card at
            # {endpoint}/.well-known/agent.json. Omitted when empty: the
            # older wire shape, and the server treats absent as before.
            payload["endpoint"] = endpoint
        if self.public_key:
            payload["public_key"] = self.public_key
        return self._post_open("/api/members", payload)

    def tofu_verify_chapter(self) -> tuple[str, str]:
        """Trust-On-First-Use pin of the chapter's identity.

        Fetches the chapter's public AgentCard (``/.well-known/agent.json``),
        records its identity on first contact, and compares on every reconnect
        via :func:`trust.verify_chapter`. Returns ``(status, message)``; a
        ``"warning"`` status means the chapter's key/id changed since first
        contact (key rotation or a man-in-the-middle) — the caller decides
        whether to proceed. Never raises."""
        from . import trust

        if not self.chapter_url:
            return "unknown", "no chapter configured"
        try:
            card = self._get_open("/.well-known/agent.json")
        except Exception as e:  # noqa: BLE001 — network/parse, never fatal
            return "unknown", f"could not fetch chapter identity: {type(e).__name__}: {e}"
        card = card if isinstance(card, dict) else {}
        provider = card.get("provider") if isinstance(card.get("provider"), dict) else {}
        did = str(provider.get("did") or card.get("id") or "")
        chapter_id = str(card.get("id") or card.get("agent_id") or self.chapter_url)
        chapter_name = str(card.get("agent_name") or card.get("name") or self.chapter_url)
        return trust.verify_chapter(self.chapter_url, chapter_id, chapter_name, did)

    def get_agent_profile(self, agent_id: str) -> dict:
        """Fetch the public A2UI profile surface for ``agent_id``.

        Open by design (added to the chapter's OPEN_PATHS via the
        ``/api/agents/{id}/profile`` prefix rule) — sharing the URL
        works without an account.
        """
        return self._get_open(f"/api/agents/{agent_id}/profile")

    def search_federation(self, query: str, tags: list[str] | None = None) -> dict:
        """Federation-wide member search.

        Routes to ``GET /api/mesh/peers`` (which exists and serves
        federation-aware peer discovery with anonymization). The
        previous implementation called ``POST /api/federation/search``
        which never existed on any chapter — calls silently 404'd
        once the auth header was present, and reported
        ``missing_agent_id`` when the auth header was absent
        (because the auth middleware fires before route resolution).

        ``tags`` are joined with ``query`` since ``mesh_peers`` accepts
        a free-form ``query`` plus a structured ``skills`` array.
        """
        skills = list(tags or [])
        return self.mesh_peers(query=query or None, skills=skills or None)

    def update_projection(
        self,
        agent_id: str,
        skills: list[str],
        interests: list[str] | None = None,
        availability: str = "active",
    ) -> dict:
        """Push the member's public skills/interests/availability projection to the chapter."""
        return self._post(
            "/api/projections",
            {
                "agent_id": agent_id,
                "skills": sanitize.sanitize_skills(skills),
                "interests": sanitize.sanitize_skills(interests or []),
                "availability": availability,
            },
        )

    def start_conversation(self, agent_id: str, peer_agent_id: str, opening_message: str) -> dict:
        """Start an agent-to-agent conversation thread via the chapter broker."""
        return self._post(
            "/api/conversations",
            {
                "initiator_agent_id": agent_id,
                "peer_agent_id": peer_agent_id,
                "opening_message": opening_message,
            },
            timeout=20.0,
        )

    # ── Skill registry (W11) ─────────────────────────────────

    def get_skill(self, skill_id: str) -> dict:
        """Fetch a skill record from the chapter registry."""
        return self._get(f"/api/skills/{skill_id}")

    def list_skills(self, limit: int = 50) -> dict:
        return self._get(f"/api/skills?limit={limit}")

    def install_skill(self, skill_id: str, agent_id: str) -> dict:
        """Record an install on the chapter and receive the signed install proof."""
        return self._post(f"/api/skills/{skill_id}/install", {"agent_id": agent_id})

    def api_call(self, method: str, path: str, body: dict | None = None) -> dict:
        """Signed API call for pipelines needing an injectable, authenticated
        ``chapter_api_fn`` — e.g. ``skills.install_skill``, whose POST
        ``/api/skills/{id}/install`` requires an Ed25519 signature (an unsigned
        call 401s). GET ignores the body; everything else carries it."""
        return self._get(path) if method.upper() == "GET" else self._post(path, body or {})

    def review_skill(
        self,
        skill_id: str,
        reviewer_agent_id: str,
        rating: int,
        review_text: str,
        signed_install_proof: str,
    ) -> dict:
        """Post a review. Install-proof gated server-side."""
        return self._post(
            f"/api/skills/{skill_id}/review",
            {
                "reviewer_agent_id": reviewer_agent_id,
                "rating": int(rating),
                "review_text": review_text,
                "signed_install_proof": signed_install_proof,
            },
        )

    # ── Mesh (W11) ───────────────────────────────────────────

    def mesh_peers(self, query: str | None = None, skills: list[str] | None = None, limit: int = 50) -> dict:
        params = [f"limit={limit}"]
        if query:
            params.append(f"query={query}")
        if skills:
            params.append(f"skills={','.join(skills)}")
        return self._get(f"/api/mesh/peers?{'&'.join(params)}")

    def mesh_send(
        self,
        sender_agent_id: str,
        target_agent_id: str,
        text: str,
        intent_id: str | None = None,
    ) -> dict:
        body = {
            "sender_agent_id": sender_agent_id,
            "target_agent_id": target_agent_id,
            "text": text,
        }
        if intent_id:
            body["intent_id"] = intent_id
        return self._post("/api/mesh/send", body)

    def mesh_trust(self, agent_id: str) -> dict:
        return self._get(f"/api/mesh/trust/{agent_id}")

    def mesh_intent(self, requester_agent_id: str, text: str, tags: list[str] | None = None) -> dict:
        return self._post(
            "/api/mesh/intent",
            {"requester_agent_id": requester_agent_id, "text": text, "tags": tags or []},
        )

    # ── Settings (W11) ───────────────────────────────────────

    def get_settings(self, agent_id: str) -> dict:
        return self._get(f"/api/settings/{agent_id}")

    def update_settings(self, agent_id: str, patch: dict) -> dict:
        return self._post("/api/settings/update", {"agent_id": agent_id, "patch": patch})

    # ── Channels (W11) ───────────────────────────────────────

    def list_channels(self, agent_id: str, kind: str | None = None) -> dict:
        q = f"?kind={kind}" if kind else ""
        return self._get(f"/api/channels/{agent_id}{q}")

    def connect_channel(
        self,
        agent_id: str,
        kind: str,
        remote_id: str,
        display_name: str = "",
        config: dict | None = None,
    ) -> dict:
        return self._post(
            "/api/channels/connect",
            {
                "agent_id": agent_id,
                "kind": kind,
                "remote_id": remote_id,
                "display_name": display_name,
                "config": config or {},
            },
        )

    def disconnect_channel(self, connection_id: str, agent_id: str) -> dict:
        return self._post(
            f"/api/channels/{connection_id}/disconnect",
            {"agent_id": agent_id},
        )

    # ── Event bus (EB-3 / EB-4) ──────────────────────────────
    #
    # Three operations on the server's pub/sub registry, plus a
    # generator that consumes the SSE stream and yields parsed events.
    # Identity is whoever owns the A2AClient — the body never asserts
    # the subscriber, only the Ed25519 signature does.

    def create_subscription(
        self,
        topics: list[str],
        *,
        filters: dict | None = None,
        delivery: str = "stream",
        webhook_url: str | None = None,
    ) -> dict:
        """POST /api/subscriptions — register interest in a list of topics.

        Topics must be known EventTypes on the chapter (member.joined,
        intent.published, etc.); unknown topics are rejected with a
        400 ``unknown topics`` response. Returns the persisted row,
        including ``id`` (used for stream + cancel).
        """
        payload: dict = {"topics": list(topics)}
        if filters is not None:
            payload["filters"] = filters
        if delivery != "stream":
            payload["delivery"] = delivery
        if webhook_url:
            payload["webhook_url"] = webhook_url
        return self._post("/api/subscriptions", payload)

    def list_subscriptions(self) -> dict:
        """GET /api/subscriptions — caller's active subscriptions only.

        Cross-tenant isolation is enforced server-side; this never
        returns subscriptions belonging to other agents.
        """
        return self._get("/api/subscriptions")

    def cancel_subscription(self, subscription_id: str) -> dict:
        """DELETE /api/subscriptions/{id} — soft-cancel (active=false)."""
        return self._delete(f"/api/subscriptions/{subscription_id}")

    def stream_events(
        self,
        subscription_id: str,
        *,
        last_event_id: int = 0,
        timeout: float = 60.0,
    ):
        """Generator over the SSE delivery stream for ``subscription_id``.

        Yields one dict per event with keys ``id``, ``event``, ``data``
        (parsed JSON). Skips SSE comment lines (``: keepalive``) — they
        keep the connection alive but carry no business signal.

        ``last_event_id`` is sent as the ``Last-Event-ID`` header so
        the chapter replays everything since that id before going into
        long-poll. Pass 0 (the default) to start from "right now"
        (chapter never wrote id=0; smallest real id is 1).

        ``timeout`` is the per-read timeout, NOT the total stream
        lifetime. The stream itself is long-lived; the timeout only
        triggers if no bytes (including keepalives) arrive in that
        window — so it should comfortably exceed the chapter's
        ``SSE_POLL_INTERVAL_S`` (default 2.0s).

        Raises ``MissingCredentialsError`` if the client wasn't
        constructed with agent_id + private_key (the stream endpoint
        requires Ed25519 auth at the middleware layer).

        Usage::

            sub = client.create_subscription(["member.joined"])
            for event in client.stream_events(sub["subscription"]["id"]):
                print(event["event"], event["data"])
        """
        path = f"/api/subscriptions/{subscription_id}/stream"
        headers = self._auth_headers("")
        if last_event_id > 0:
            headers["Last-Event-ID"] = str(last_event_id)

        url = f"{self.chapter_url}{path}"
        with httpx.stream("GET", url, headers=headers, timeout=timeout) as resp:
            resp.raise_for_status()
            buf: dict[str, str] = {}
            for raw_line in resp.iter_lines():
                # SSE framing: ``id:`` / ``event:`` / ``data:`` lines, blank
                # line terminates a frame. Comment lines start with ``:``
                # and are keepalives — skip them.
                if raw_line == "":
                    if buf:
                        yield {
                            "id": int(buf["id"]) if buf.get("id", "").isdigit() else None,
                            "event": buf.get("event", "message"),
                            "data": (json.loads(buf["data"]) if buf.get("data") else None),
                        }
                        buf = {}
                    continue
                if raw_line.startswith(":"):
                    continue
                if ":" not in raw_line:
                    continue
                field, _, value = raw_line.partition(":")
                # SSE allows a space after the colon — strip exactly one.
                if value.startswith(" "):
                    value = value[1:]
                buf[field] = value
