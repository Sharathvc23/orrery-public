"""
Local Dashboard Server — FastAPI app serving the agent API.

Proxy routes forward signed requests to the chapter agent.
Local routes expose agent state and require the local API token; see local_auth.py.
No HTML is served from this module.
"""

import json
import logging
import time
from collections import deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from community_member import llm_client
from community_member import llm_runtime as _llm_runtime

from . import DASHBOARD_PORT, local_auth
from .a2a_client import A2AClient
from .config import Config

logger = logging.getLogger(__name__)


def _agent_base_url(request: Request) -> str:
    """Compute the externally-visible base URL for this agent.

    Prefers the Host header (so Agent Cards advertise a URL that actually
    reaches us from wherever the client fetched them) and falls back to
    localhost:DASHBOARD_PORT for contexts without a request (tests,
    CLI-time logging).
    """
    host = request.headers.get("host") if request else None
    scheme = request.url.scheme if request else "http"
    if host:
        return f"{scheme}://{host}"
    return f"http://localhost:{DASHBOARD_PORT}"


# Will be set by create_app()
_agent = None
_config = None
_client = None
_thought_log: deque = deque(maxlen=50)
_start_time = time.time()


class MemoryRequest(BaseModel):
    key: str
    value: str
    memory_type: str = "note"


class DiscloseRequest(BaseModel):
    receipt_ids: list[str]


class IntentRequest(BaseModel):
    text: str
    tags: list[str] = []


# ─── W5 PR1 request shapes ─────────────────────────────────────────


class ActionRequestBody(BaseModel):
    """Subset of consent.gate.ActionRequest shipped over the wire.

    Kept structurally compatible with ActionRequest so the server can
    reconstruct it without extra translation. The consent gate's
    validator is the authority on whether the shape is actually legal.
    """

    capability: str
    scope: str
    context: str
    provenance: str  # "trusted" | "semi_trusted" | "untrusted"
    source_ref: str | None = None
    rationale: str = ""


class ConsentApproveRequest(BaseModel):
    prompt_event_sha256: str
    request: ActionRequestBody


class ConsentDenyRequest(BaseModel):
    prompt_event_sha256: str
    request: ActionRequestBody


class GraduationRevokeRequest(BaseModel):
    capability: str
    scope: str
    context_sha256: str


class DuressVerifyRequest(BaseModel):
    passphrase: str


class DuressRegisterRequest(BaseModel):
    normal: str
    duress: str


class SettingsUpdate(BaseModel):
    """Runtime LLM-provider switch from the dashboard.

    Local providers (ollama, llama_cpp, mlx_lm) accept an empty
    ``api_key``. The endpoint validates against ``PROVIDERS`` so a
    typo can't silently swap the agent's brain.
    """

    provider: str
    model: str
    api_key: str = ""


class ChatMessage(BaseModel):
    """One turn in a conversation.

    Content is a string for text-only turns, or a list of content
    blocks (text + image_url) for multimodal turns. Mirrors the
    OpenAI Chat Completions content shape so providers that already
    speak that protocol need no translation.
    """

    role: str  # "system" | "user" | "assistant"
    content: str | list[dict] = ""


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    # Optional image data URLs the user attached on this turn. Merged
    # into the last user message as `image_url` content blocks before
    # the request leaves the host, so providers see one well-formed
    # multimodal turn.
    images: list[str] = []


_RISK_LEVELS = {"safe", "caution", "dangerous"}

# THE TABLE IS GONE — see llm_runtime.PROVIDERS, which is the union of the five
# that used to disagree. These names are kept for this module's readers and now
# derive from the registry.
_PROVIDER_BASE_URLS = {name: p.base_url for name, p in _llm_runtime.PROVIDERS.items()}
_LOCAL_PROVIDERS = set(_llm_runtime.LOCAL_PROVIDERS)
_PROVIDER_LABELS = {
    "xai": "xAI (Grok)",
    "openai": "OpenAI (GPT)",
    "anthropic": "Anthropic (Claude)",
    "groq": "Groq (Llama)",
    "ollama": "Ollama (local)",
    "llama_cpp": "llama.cpp (local)",
    "mlx_lm": "mlx-lm (local, Apple Silicon)",
}
# BASE URLS COME FROM THE REGISTRY; the model column does not, and the
# difference is deliberate.
#
# The URLs were duplicated here, in wizard.py, in llm_client.py, in this file's
# own _PROVIDER_BASE_URLS and in the server's llm_config — five tables that
# disagreed, which is how an unrecognised provider reached OpenAI's endpoint.
# There is one now.
#
# The MODELS stay where they are. The agent's offered default and the server's
# resolved default genuinely differ today — openai is gpt-4o here and
# gpt-4o-mini on the server; groq is llama-3.1-70b-versatile here and
# llama-3.3-70b-versatile there — and reconciling them changes what an already
# deployed chapter resolves when it sets no LLM_MODEL. That is a behaviour
# change, and this unit moves construction without changing behaviour.
_PROVIDER_MODELS = {
    "xai": "grok-3-mini",
    "openai": "gpt-4o",
    # Retired model (see wizard.py::PROVIDERS) — kept in lockstep with it.
    "anthropic": "claude-sonnet-4-6",
    "groq": "llama-3.1-70b-versatile",
    "ollama": "llama3.2",
    "llama_cpp": "local-model",
    "mlx_lm": "local-model",
}
_PROVIDER_CATALOGUE = [(pid, _llm_runtime.PROVIDERS[pid].base_url, model) for pid, model in _PROVIDER_MODELS.items()]


def _chapter_label(url: str) -> str:
    """Pull a human-readable chapter name out of a Railway-shaped URL.

    ``https://org.example.com`` → ``Bay Area``.
    Falls back to the host when the convention doesn't match.
    """
    if not url:
        return "(no chapter)"
    try:
        from urllib.parse import urlparse

        host = urlparse(url).netloc.split(".")[0]
        # Strip the deployment-environment suffix Railway appends.
        for sfx in ("-agent-production", "-production", "-agent"):
            if host.endswith(sfx):
                host = host[: -len(sfx)]
                break
        return host.replace("-", " ").title() if host else url
    except Exception:
        return url


def _chat_system_prompt(cfg) -> str:
    """System prompt for the chat panel.

    The autonomous think loop has its own (shorter) prompt — this one
    is richer because the chat is conversational and benefits from
    extra context the user might ask follow-up questions about.
    """
    if cfg is None:
        return "You are a sovereign personal agent. The host has not yet been configured."
    chapter = _chapter_label(cfg.chapter_url or "")
    return (
        f"You are @{cfg.agent_id}'s sovereign personal agent, running locally on their machine.\n"
        f"You represent {cfg.name or cfg.agent_id} in the federation.\n"
        f"About them: {cfg.description or '(no description set)'}\n"
        f"Skills: {', '.join(cfg.skills or []) or '(none listed)'}\n"
        f"Interests: {', '.join(cfg.interests or []) or '(none listed)'}\n"
        f"Chapter: {chapter} — {cfg.chapter_url or '(none)'}\n\n"
        "Use the available tools whenever a question can be answered "
        "directly: `search_chapter` and `search_federation` for "
        "members and skill matches, `get_chapter_intelligence` for "
        "chapter-wide context, `submit_intent` to ask the federation "
        "for help, `save_note` to remember something locally for the "
        "user.\n\n"
        "When you propose to *do* something on the host (open a web "
        "page, read a file, run a shell command, click on the "
        "screen), describe what you want clearly — the consent inbox "
        "handles approval. Be direct, helpful, and brief."
    )


def _fallback_summary(capability: str, scope: str, rationale: str) -> tuple[str, str]:
    """Deterministic plain-English summary when the LLM is unavailable.

    Used when no API key is configured, the LLM call fails, or the
    user opted out of cloud LLM use. Keeps the inbox legible
    without a network round-trip.
    """
    cap_summaries = {
        "browser.navigate": ("Open a web page", "caution"),
        "browser.extract": ("Read content from a web page", "caution"),
        "fs.read": ("Read a file from your filesystem", "caution"),
        "fs.write": ("Write or overwrite a file on your filesystem", "dangerous"),
        "shell.exec": ("Run a shell command on your machine", "dangerous"),
        "net.http": ("Make an HTTP request to an external service", "caution"),
        "desktop.click": ("Click somewhere on your screen", "dangerous"),
        "desktop.type": ("Type text into the focused window", "dangerous"),
        "desktop.read_screen": ("Take a screenshot for analysis", "caution"),
    }
    label, risk = cap_summaries.get(capability, (capability, "caution"))
    target_phrase = f" — target: {scope}" if scope else ""
    why = f" Reason: {rationale.strip()}" if rationale.strip() else ""
    return f"{label}{target_phrase}.{why}", risk


def _explain_with_llm(
    *,
    capability: str,
    scope: str,
    rationale: str,
    source_ref: object | None,
    extra: dict,
) -> tuple[str, str] | None:
    """Ask the agent's configured LLM to summarise the proposal.

    Returns (summary, risk_level) or None on any failure (missing
    key, network error, malformed response). The caller falls back
    to ``_fallback_summary`` in that case so the inbox always
    renders something legible.
    """
    if _config is None:
        return None
    # Config exposes ``provider`` (not ``llm_provider``); the older
    # attribute name was leftover from a pre-wizard prototype and
    # silently broke this endpoint until 2026-04-25.
    provider = (getattr(_config, "provider", "") or "").lower()
    model = getattr(_config, "model", "") or ""

    # Build a tight system prompt + a structured user message.
    system = (
        "You translate raw agent action proposals into 2-sentence "
        "plain-English summaries for a non-technical user reviewing "
        "a consent prompt. Output JSON: "
        '{"summary": "...", "risk_level": "safe|caution|dangerous"}. '
        "Sentence 1 says what the action will do in human terms. "
        "Sentence 2 says why the agent wants to do it. Risk levels: "
        "safe = read-only / no side effects; caution = network or "
        "browser activity; dangerous = filesystem write, shell, or "
        "desktop input."
    )
    user_payload = {
        "capability": capability,
        "scope": scope,
        "rationale": rationale,
        "source_ref": source_ref,
        "extra": extra,
    }

    # Use whichever provider the wizard configured. Local providers
    # (ollama, llama_cpp, mlx_lm) skip the API key check — their server
    # serves the same OpenAI-compatible shape.
    try:
        import json as _json

        # The provider table and the key fall-through are both gone. The table
        # defaulted an unknown provider to OpenAI's endpoint, and the
        # fall-through sent whichever of OPENAI_API_KEY or XAI_API_KEY happened
        # to be set — so a misspelt provider posted a third party's key to
        # OpenAI. build_client reads the key belonging to the provider it
        # resolved, and resolves nothing for a name it does not know.
        from community_member import llm_runtime

        try:
            resolution = llm_runtime.resolve(provider, model=model or None)
            client = llm_runtime.build_client(
                resolution, api_key=getattr(_config, "api_key", None), strict=llm_client.strict_enabled()
            )
        except llm_runtime.LLMNotConfigured:
            return None

        resp = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": _json.dumps(user_payload)},
            ],
            temperature=0.2,
            max_tokens=200,
            response_format={"type": "json_object"},
        )
        text = resp.choices[0].message.content or ""
        parsed = _json.loads(text)
        summary = str(parsed.get("summary") or "").strip()
        risk = str(parsed.get("risk_level") or "caution").strip().lower()
        if risk not in _RISK_LEVELS:
            risk = "caution"
        if not summary:
            return None
        return summary, risk
    except Exception:
        return None


def create_app(config: Config, agent=None) -> FastAPI:
    """Create the FastAPI app with injected config and agent."""
    global _agent, _config, _client, _start_time
    _config = config
    _agent = agent
    _start_time = time.time()

    _client = A2AClient(
        config.chapter_url,
        agent_id=config.agent_id,
        private_key=config.private_key,
        public_key=config.public_key,
    )

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        # the conformance surface is live out of the box — run the
        # signing-conformance self-checks and sign a badge (labelled
        # self-attested) unless an operator badge already verifies. Lifespan,
        # not create_app body, so building the app in unit tests doesn't mint
        # badges (TestClient only runs it as a context manager).
        from .conformance_boot import ensure_boot_badge

        ensure_boot_badge(_config)
        yield

    app = FastAPI(title=f"@{config.agent_id} Dashboard", docs_url=None, redoc_url=None, lifespan=_lifespan)
    # Every route requires the local token unless local_auth.OPEN_ROUTES
    # declares it open. Added before CORSMiddleware so CORS ends up the
    # outer layer and answers preflight without consulting the token.
    app.add_middleware(local_auth.LocalAuthMiddleware, token=local_auth.load_or_create_token(config.home))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[f"http://localhost:{DASHBOARD_PORT}", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ─── Local Agency Log routes (no server round-trip) ──────
    #
    # The Agency Log is the principal's local store of ARP receipts
    # (spec/arp/0.1/spec.md §10.1). Endpoints below read the local
    # SQLite store directly and never proxy to the server — sovereignty
    # principle. The server's view of the same receipts is at
    # /api/surfaces/today (proxied below).

    @app.get("/api/agency-log/today")
    async def agency_log_today():
        """Return today's A2UI surface built from the LOCAL Agency Log.

        Offline-first: works even if the chapter is unreachable. The
        principal's Agency Log is authoritative for the principal; the
        chapter's Issuer Log is the chapter's parallel view. Divergence
        between them is itself evidence under dispute (per ARP §10.1).
        """
        from . import config as config_mod
        from .arp import AgencyLog
        from .arp_surfaces import build_today_surface_from_log

        log = AgencyLog(home=config_mod.CONFIG_DIR)
        return build_today_surface_from_log(log)

    @app.get("/api/agency-log/receipts")
    async def agency_log_receipts(limit: int = 100):
        """Raw list of the local Agency Log's most recent receipts.

        Use ?limit=N to bound the page; max 500. Order: newest first.

        Each receipt is also classified for the UI via ``corroboration``: a
        receipt_id -> bool map where True means the counterparty co-signed it
        (``nanda-rep/0.2`` corroborated, VRP 0.3 §A). Computed by the authoritative
        published verifier (``sm_arp.vrp.is_corroborated``) so the badge can never drift
        from what actually scores. Receipts are returned pristine — corroboration
        is a sibling annotation, never a field on the signed envelope.
        """
        from sm_arp.vrp import is_corroborated

        from . import config as config_mod
        from .arp import AgencyLog

        clamped = max(1, min(500, int(limit)))
        log = AgencyLog(home=config_mod.CONFIG_DIR)
        receipts = log.list_recent(limit=clamped)
        corroboration = {
            r["receipt_id"]: is_corroborated(r) for r in receipts if isinstance(r, dict) and r.get("receipt_id")
        }
        return {"receipts": receipts, "total_returned": clamped, "corroboration": corroboration}

    @app.get("/api/agency-log/unresolved")
    async def agency_log_unresolved(limit: int = 100):
        """Action attempts whose outcome a human still has to look at.

        Each attempt is written to the Agency Log BEFORE its external call and
        resolved after (``AgencyLog.begin_action`` / ``finalize_action``). This
        lists the ones that did not resolve cleanly: ``unknown`` outcomes (a
        timeout after the request left, a process that died mid-call — marked
        at the next start by ``reconcile_orphans``), ``pending`` rows from a
        process that is gone, and ``succeeded`` attempts whose receipt was
        never written. None of them is retried by the runtime; the list exists
        so they are not silently dropped. Attempts are local log state, not
        receipts, and never leave this host through this surface.
        """
        from . import config as config_mod
        from .arp import AgencyLog

        clamped = max(1, min(500, int(limit)))
        log = AgencyLog(home=config_mod.CONFIG_DIR)
        attempts = log.unresolved_actions(limit=clamped)
        return {"attempts": attempts, "total_returned": len(attempts)}

    @app.get("/api/agency-log/aae-events")
    async def agency_log_aae_events(limit: int = 100):
        """Return the local Agency Log's receipts in AAE-shaped JSON
        for ``@sharathvc/sm-attest-viewer`` consumption.

        Same wire shape as the chapter's GET /api/agents/{id}/aae-events
        — downstream consumers (an SDK-side React frontend, the desktop
        Electron shell, etc.) can render this with the upstream
        sm-attest-viewer without differentiating chapter-emitted vs
        SDK-emitted events.

        Visibility: classification='internal' by default. SDK receipts
        are local; opting into public requires the principal to mirror
        them up to the chapter, where chronicle_public controls public
        visibility.
        """
        from . import aae_export
        from . import config as config_mod
        from .arp import AgencyLog

        clamped = max(1, min(500, int(limit)))
        log = AgencyLog(home=config_mod.CONFIG_DIR)
        receipts = log.list_recent(limit=clamped)
        cfg = config_mod.Config.load()
        tenant = cfg.agent_id or "sdk"
        events = aae_export.arp_receipts_to_aae_events(receipts, tenant=tenant, public=False)
        return {
            "events": events,
            "total": len(events),
            "tenant": tenant,
            "classification": "internal",
        }

    @app.get("/api/reputation-ledger")
    async def reputation_ledger(method: str = "nanda-rep/0.2"):
        """The member's OWN corroborated standing, computed LOCALLY from the
        Agency Log — it never asks the chapter for its reputation.

        Sovereignty: the member recomputes its standing from its own receipts
        with the published ``sm_arp.vrp`` math — the same math a chapter or any
        resolver runs — so the number it shows itself is the number anyone else
        would derive from the same receipts. Returns the AgentFacts
        ``verifiable_receipts`` facet: ``reputation_score``, ``corroboration_rate``,
        ``receipt_count``, ``behavioral_merkle_root``.

        ``nanda-rep/0.2`` (counterparty-corroborated) by default;
        ``?method=nanda-rep/0.1`` for the self-attested score. An unsupported
        method is rejected rather than silently coerced (scores are method-
        namespaced — comparing across methods is meaningless).
        """
        from datetime import UTC, datetime

        from . import config as config_mod
        from .arp import AgencyLog
        from .crypto import build_did_key
        from .ledger import agentfacts_facet, export_ledger

        if method not in ("nanda-rep/0.1", "nanda-rep/0.2"):
            return {"error": f"Unsupported scoring method: {method!r}."}
        if not _config.public_key:
            return {"error": "No local identity yet — generate a keypair first."}
        try:
            subject_did = build_did_key(_config.public_key)
        except Exception as e:
            return {"error": f"Could not derive your did:key: {e}"}

        # The SDK timestamps at the call site; ledger.py takes no wall-clock.
        as_of = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        log = AgencyLog(home=config_mod.CONFIG_DIR)
        ledger = export_ledger(log, subject_did=subject_did, as_of=as_of, method=method, inline=False)
        # ledger_uri blank — this is an in-place local computation, not a
        # published document; the facet carries the scores regardless.
        facet = agentfacts_facet(ledger, ledger_uri="")
        return {"subject_did": subject_did, "method": method, "as_of": as_of, "facet": facet}

    # ─── Proxy routes (forward to server, signed) ────────────

    @app.get("/api/surfaces/{page_id}")
    async def proxy_surface(page_id: str, target: str | None = None):
        try:
            return _client.get_surface(page_id)
        except Exception as e:
            return {"error": f"Chapter unreachable: {e}"}

    @app.post("/api/surfaces/action")
    async def proxy_action(request: Request):
        try:
            body = await request.body()
            payload = json.loads(body)
            return _client._post("/api/surfaces/action", payload)
        except Exception as e:
            return {"error": f"Action failed: {e}"}

    @app.post("/api/surfaces/compose")
    async def proxy_compose(request: Request):
        """Forward to the chapter's Surface Composer endpoint. The
        chapter's xAI/OpenAI key generates the surface; the local
        agent just relays. The endpoint on the chapter is open
        (see chapter-runtime auth_verify is_open_path)."""
        try:
            body = await request.body()
            payload = json.loads(body)
            return _client._post("/api/surfaces/compose", payload)
        except Exception as e:
            return {"error": f"Compose failed: {e}"}

    @app.get("/api/surfaces/{page_id}/stream")
    async def proxy_stream(page_id: str, request: Request):
        """Stream AG-UI events from the chapter for a given page.

        The chapter's /api/surfaces/{id}/stream is open (GET prefix)
        so we just proxy without authentication overhead. We use
        httpx streaming to avoid buffering the entire SSE on disk.
        """
        from urllib.parse import urlencode

        from fastapi.responses import StreamingResponse

        chapter_url = (_config.chapter_url or "").rstrip("/")
        if not chapter_url:
            return {"error": "chapter not configured"}

        params = dict(request.query_params)
        upstream = f"{chapter_url}/api/surfaces/{page_id}/stream"
        if params:
            upstream = f"{upstream}?{urlencode(params)}"

        async def _relay():
            import httpx

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(None)) as client:
                    async with client.stream("GET", upstream) as resp:
                        async for chunk in resp.aiter_raw():
                            if chunk:
                                yield chunk
            except Exception as e:
                msg = json.dumps({"type": "RunError", "message": str(e)})
                yield f"data: {msg}\n\n".encode()

        return StreamingResponse(
            _relay(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.get("/api/chapter/receipts")
    async def proxy_chapter_receipts(limit: int = 50):
        """The chapter's record of *your* receipts.

        The chapter-side counterpart to your local Agency Log: a *signed*,
        principal-scoped read of your home chapter (``GET /api/receipts``),
        returning the receipts it holds where you are the principal
        (spec/arp/0.1 §10.1). The same local Ed25519 identity that signed the
        receipts signs this request, so the chapter scopes the reply to you.

        A genuinely empty list means you are enrolled but have published no
        receipts yet — your local Agency Log is sovereign and is never pushed
        to a chapter unless you ask. A chapter that is unreachable or declines
        the request is reported via ``error`` and never masqueraded as an empty
        result, so the dashboard cannot claim "no receipts" when it actually
        could not ask.

        Returns ``{"receipts": [...], "source": <home chapter url>,
        "error"?: <message>}``.
        """
        home = (_config.chapter_url or "").rstrip("/")
        if not home:
            return {"receipts": [], "source": home, "error": "No home chapter is configured."}
        try:
            scoped = _client._get(f"/api/receipts?limit={limit}")
        except Exception as e:
            logger.warning("chapter receipts proxy failed for %s: %s", home, e)
            return {"receipts": [], "source": home, "error": f"Could not reach your chapter ({home}): {e}"}
        if not isinstance(scoped, dict):
            return {"receipts": [], "source": home, "error": "Your chapter returned an unexpected response."}
        if "receipts" not in scoped:
            # Server declined/errored (not enrolled, auth, etc.); its body
            # carries the reason — surface it instead of a misleading "empty".
            detail = scoped.get("detail") or scoped.get("error") or "request declined"
            return {"receipts": [], "source": home, "error": f"Your chapter declined the request: {detail}"}
        # Success. An empty list here is an *honest* empty (enrolled, nothing
        # published yet), distinct from the unreachable/declined cases above.
        # Classify corroboration with the same authoritative verifier used for the
        # local Agency Log, so the badge means the same thing from either vantage.
        from sm_arp.vrp import is_corroborated

        receipts = scoped.get("receipts") or []
        corroboration = {
            r["receipt_id"]: is_corroborated(r) for r in receipts if isinstance(r, dict) and r.get("receipt_id")
        }
        return {"receipts": receipts, "source": home, "corroboration": corroboration}

    @app.post("/api/intent")
    async def submit_intent(req: IntentRequest):
        try:
            return _client.submit_intent(_config.agent_id, req.text, req.tags)
        except Exception as e:
            return {"error": f"Intent submission failed: {e}"}

    # ─── Server event-bus passthrough (EB-3 / EB-4) ──────────────
    #
    # The browser cannot hit the server directly (CORS + Ed25519
    # signing both block it). The local daemon is the trusted bridge:
    # it signs requests with the user's key and forwards to the server,
    # and proxies the SSE stream so the browser sees a same-origin EventSource.

    class _SubscriptionCreate(BaseModel):
        topics: list[str]
        filters: dict | None = None
        delivery: str = "stream"
        webhook_url: str | None = None

    @app.get("/api/local/subscriptions")
    async def local_list_subscriptions():
        """List the local agent's active subscriptions on its chapter."""
        try:
            return _client.list_subscriptions()
        except Exception as e:
            return {"error": f"list failed: {e}", "subscriptions": [], "total": 0}

    @app.post("/api/local/subscriptions")
    async def local_create_subscription(req: _SubscriptionCreate):
        """Create a subscription on the local agent's chapter."""
        try:
            return _client.create_subscription(
                req.topics,
                filters=req.filters,
                delivery=req.delivery,
                webhook_url=req.webhook_url,
            )
        except Exception as e:
            return {"error": f"create failed: {e}"}

    @app.delete("/api/local/subscriptions/{subscription_id}")
    async def local_cancel_subscription(subscription_id: str):
        """Soft-cancel a subscription owned by the local agent."""
        try:
            return _client.cancel_subscription(subscription_id)
        except Exception as e:
            return {"error": f"cancel failed: {e}"}

    # The "system" subscription is the workspace's firehose — one
    # always-on connection that surfaces every server event to the
    # browser so reactive tiles (GenerativeCanvas, DigestSummary,
    # etc.) can update without per-tile subscription bookkeeping.
    # Idempotent: a marker ``{"system": true}`` in the filters
    # column lets us recognise our own sub on subsequent calls so
    # reloads / restarts don't keep minting new ones.
    _SYSTEM_TOPICS = [
        "member.joined",
        "member.left",
        "intent.published",
        "intent.matched",
        "startup.submitted",
        "startup.evaluated",
        "mentor.invited",
        "mentor.responded",
        "federation.peer.online",
        "federation.peer.offline",
        "chapter.digest.weekly",
    ]

    @app.get("/api/local/system-subscription")
    async def local_system_subscription():
        """Return (or auto-create) the workspace's firehose subscription.

        Browser calls this once on workspace mount to know which sub
        id to open the SSE stream on. The chapter still applies
        trust-tier gating per delivery — subscribing to mentor.invited
        is fine even at trust=0; you just won't receive any until
        promoted.
        """
        if _client is None:
            return {"error": "agent_not_initialized"}
        try:
            existing = _client.list_subscriptions() or {}
            for sub in existing.get("subscriptions") or []:
                if not isinstance(sub, dict):
                    continue
                filters = sub.get("filters") or {}
                if isinstance(filters, dict) and filters.get("system") is True:
                    return {"subscription": sub, "created": False}
            # No system sub yet — mint one with the marker filter.
            resp = _client.create_subscription(
                _SYSTEM_TOPICS,
                filters={"system": True},
            )
            row = (resp or {}).get("subscription") if isinstance(resp, dict) else None
            if not row:
                return {"error": f"create failed: {resp}"}
            return {"subscription": row, "created": True}
        except Exception as e:
            return {"error": f"system subscription unavailable: {e}"}

    @app.get("/api/local/subscriptions/{subscription_id}/stream")
    async def local_stream_subscription(subscription_id: str, request: Request):
        """Proxy the chapter's SSE stream to the local browser.

        Browser opens ``new EventSource("/api/local/subscriptions/X/stream")``,
        and we forward each event from the chapter unchanged. Identity +
        signing happen inside ``_client.stream_events``; the browser never
        sees the Ed25519 keypair.

        ``Last-Event-ID`` is honored — browsers' EventSource send it
        automatically on reconnect.
        """
        from fastapi.responses import StreamingResponse

        last_event_id = 0
        try:
            last_event_id = int(request.headers.get("Last-Event-ID", "0") or "0")
        except (TypeError, ValueError):
            last_event_id = 0

        def gen():
            try:
                for event in _client.stream_events(
                    subscription_id,
                    last_event_id=last_event_id,
                ):
                    # Re-frame as SSE for the browser. Compact JSON keeps
                    # bytes-per-event small. Skip events the client
                    # generator couldn't parse (data=None).
                    sse_id = event.get("id") if event.get("id") is not None else ""
                    event_type = event.get("event") or "message"
                    data = json.dumps(event.get("data") or {}, separators=(",", ":"))
                    yield f"id: {sse_id}\nevent: {event_type}\ndata: {data}\n\n"
            except Exception as e:
                # Surface as an SSE error event the UI can render.
                err = json.dumps({"error": str(e)})
                yield f"event: stream-error\ndata: {err}\n\n"

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/local/surfaces/compose")
    async def local_compose_surface(request: Request):
        """Generate an A2UI v0.9 surface from a free-text intent
        using the agent's local LLM. The Surface Composer pattern,
        but local instead of via chapter.

        Body: ``{intent: str}``. Returns a JSON A2UI surface:
        ``{components: [...], envelope: {...}}``. The renderer
        already knows how to display this.

        On any error (no API key, LLM down, malformed JSON) the
        endpoint returns an error envelope so the UI shows a
        graceful fallback rather than a blank page.
        """
        try:
            body = await request.json()
        except Exception:
            return {"error": "invalid_json"}
        intent = str(body.get("intent") or "").strip()
        if not intent:
            return {"error": "empty_intent"}
        if _config is None:
            return {"error": "agent_not_initialized"}

        # Pull live state context so the agent's surface is grounded
        # in what's actually happening, not abstract. Cheap reads —
        # subscriptions list + a peek at the local agent's status.
        ctx_parts: list[str] = []
        try:
            subs_resp = _client.list_subscriptions() if _client else {}
            subs = (subs_resp or {}).get("subscriptions") or []
            if subs:
                topics = sorted({t for s in subs for t in (s.get("topics") or [])})
                ctx_parts.append(f"Active subscriptions: {len(subs)} (topics: {', '.join(topics[:8])})")
            else:
                ctx_parts.append("No active chapter subscriptions yet.")
        except Exception:
            ctx_parts.append("Subscription state unavailable.")
        if _config:
            ctx_parts.append(f"Local agent: @{_config.agent_id} on {_config.chapter_url}.")
        live_context = " ".join(ctx_parts)

        system = (
            "You are a UI composer for an AI-native agent workspace. "
            "Given the user intent + live context, output JSON: "
            "{components: [...]} — an ordered list of A2UI v0.9 / v0.10 "
            "components the renderer will draw as the agent's response.\n\n"
            "WIRE FORMAT (v0.9, REQUIRED):\n"
            "  Every node MUST use the flat discriminator `component:` "
            "(NOT `type:`). Children go in `children: [<id1>, <id2>]` "
            "and the referenced ids must appear as siblings in the same "
            "components list. Every node must have a unique `id` string.\n\n"
            '  Correct:   {"id": "t1", "component": "Text", "text": "hi"}\n'
            '  WRONG:     {"type": "Text", "children": "hi"}\n\n'
            '  Heading uses `usageHint: "h1"|"h2"|"h3"`, NOT `level`.\n'
            "  Row/Column/Grid wrap children by id:\n"
            '    {"id":"row1","component":"Row","children":["t1","t2"]}\n\n'
            "Compose a LAYOUT, not a list. Use Row + Column + Grid to "
            "arrange tiles in space (not just stacked).\n\n"
            "Available components:\n"
            "  Layout: Row, Column, Grid, Card, Divider\n"
            "  Text:   Heading (level 1-6), Text, Markdown, Callout\n"
            "          (variant: info|success|warning|danger), Badge,\n"
            "          List, CodeBlock\n"
            "  Data:   Metric, Stat, StatGroup, Timeline, MemberCard,\n"
            "          TrustBadge, Progress, Table, Accordion\n"
            "  Media:  Image, VideoEmbed, AudioPlayer, GenerativeCanvas\n"
            "  Live:   DigestSummary (self-subscribing weekly digest)\n"
            "  Action: ActionButton, Link\n\n"
            "GenerativeCanvas is reactive art — pick preset "
            "(particle-field | pulse-rings | starfield | constellation), "
            "palette (3-6 hex colours that match the mood), and "
            "reactiveTopic (one of: member.joined, intent.published, "
            "intent.matched, mentor.invited, federation.peer.online — "
            "the canvas pulses when that topic emits). Use this as a "
            "hero tile when the intent is observational ('show me my "
            "chapter', 'what's happening').\n\n"
            "VideoEmbed accepts YouTube/Vimeo URLs (transformed to "
            "embed form) or direct .mp4/.webm. AudioPlayer takes any "
            "audio URL. Both default to autoplay; muted=true is "
            "required for autoplay in modern browsers.\n\n"
            "DigestSummary is a special live tile: provide an inline "
            "seed (headline + summaryMarkdown + 3-6 {label,value} "
            "stats) so it renders immediately, AND the tile will "
            "self-upgrade when a fresh chapter.digest.weekly event "
            "lands on the bus. Use it whenever the intent is 'show me "
            "the weekly digest', 'how is my chapter doing this week', "
            "or any other weekly-recap framing. windowStart/windowEnd "
            "are ISO timestamps for the digest window when known.\n\n"
            "RULES:\n"
            "  - 4-10 components total, NOT a wall of text.\n"
            "  - Top-level should usually start with a Heading (h1 or "
            "    h2 usageHint) and a hero tile (Card, GenerativeCanvas, "
            "    or VideoEmbed) that visually anchors the answer.\n"
            "  - Use Grid or Row to put 2-4 tiles side-by-side when "
            "    the answer has parallel parts.\n"
            "  - Use Metric / Stat / StatGroup for numeric quantities; "
            "    don't write them in prose.\n"
            "  - Callout for emphasis, Badge for tags, TrustBadge for "
            "    member trust tiers.\n"
            "  - Compose, don't narrate. The visual IS the answer.\n\n"
            f"Live context: {live_context}"
        )

        try:
            import json as _json
            import os as _os

            provider = (getattr(_config, "provider", "") or "").lower()
            model = getattr(_config, "model", "") or ""
            is_local = provider in _LOCAL_PROVIDERS
            api_key = (
                getattr(_config, "openai_api_key", None)
                or getattr(_config, "xai_api_key", None)
                or getattr(_config, "anthropic_api_key", None)
                or getattr(_config, "api_key", None)
                or _os.environ.get("OPENAI_API_KEY")
                or _os.environ.get("XAI_API_KEY")
            )
            # Local providers (ollama / llama.cpp / mlx-lm) serve an OpenAI-compatible
            # endpoint and need NO key — only cloud providers require one.
            if not api_key and not is_local:
                return {"error": "no_api_key_configured"}

            # One construction where there were two, and no model-name sniffing.
            # The "grok in the model name means xAI" branch guessed a provider
            # from a string the model returns; the resolver is told which
            # provider it is and looks up the rest.
            from community_member import llm_runtime

            try:
                client = llm_runtime.build_client(
                    llm_runtime.resolve(provider, model=model or None),
                    api_key=api_key,
                    strict=llm_client.strict_enabled(),
                )
            except llm_runtime.LLMNotConfigured as exc:
                # This function's own error convention. Previously an
                # unresolvable provider reached OpenAI's endpoint instead of
                # being reported, which is the substitution being removed.
                return {"error": "llm_not_configured", "detail": str(exc)}

            resp = client.chat.completions.create(
                model=model or "gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": intent},
                ],
                temperature=0.3,
                max_tokens=1200,
                response_format={"type": "json_object"},
            )
            text = resp.choices[0].message.content or "{}"
            parsed = _json.loads(text)
            # Wrap in the standard envelope so A2UIRenderer accepts it.
            return {
                "version": "0.9",
                "id": "local-composed",
                "components": parsed.get("components") or [],
                "envelope": {"composed_by": "local-agent"},
            }
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    @app.post("/api/local/intent/dispatch")
    async def intent_dispatch(req: IntentRequest):
        """Run the planner LLM right now against the user's typed
        intent. Any proposed actions land in the consent gate
        (which puts them in the inbox at /Consent).

        This is what the search bar should call. Unlike
        /api/intent (which forwards to the chapter for matching
        with other members), this endpoint is the "agent does
        something with my request" path.

        Returns ``{queued: int, summary: str}``. The UI can
        show "Agent queued N action(s); review in Consent."
        """
        if not req.text.strip():
            return {"queued": 0, "summary": "Empty intent — nothing to do."}
        if _agent is None or _config is None:
            return {"queued": 0, "summary": "Agent not initialized."}

        from community_member.executor import execute_plan
        from community_member.planner import (
            PlannerContext,
            TrustedContext,
        )
        from community_member.planner_llm import plan_from_llm

        _ensure_ledger_init()
        chapter_id = _chapter_id()

        # Build context from the user's typed intent + their profile.
        trusted_items: list[str] = [f"User typed this intent: {req.text}"]
        try:
            from community_member.config import CONFIG_DIR
            from community_member.profile import load_profile

            prof = load_profile(CONFIG_DIR)
            if prof.name:
                trusted_items.append(f"My name is {prof.name}")
            if prof.bio:
                trusted_items.append(f"About me: {prof.bio}")
            if prof.interests:
                trusted_items.append(f"My interests: {', '.join(prof.interests)}")
        except Exception:
            pass

        ctx = PlannerContext(
            user_task=req.text.strip(),
            trusted=TrustedContext(items=tuple(trusted_items)),
            semi_trusted=(),
        )

        # Run the planner. Any failure surfaces a human-readable
        # error rather than a 500.
        try:
            plan = plan_from_llm(
                ctx,
                _agent.llm,
                model=_config.model,
            )
        except Exception as e:
            return {
                "queued": 0,
                "summary": f"Planner error: {type(e).__name__}: {e}",
            }

        if not plan.proposals:
            return {
                "queued": 0,
                "summary": (plan.summary or "Agent didn't see any concrete action it could take for that."),
            }

        # Push every proposal through the executor with NO runners
        # so the gate writes consent.prompt rows but nothing fires.
        # (The user will explicitly approve in the inbox.)
        results = execute_plan(
            plan,
            runners={},  # no runners → all pass through to gate.prompt path
            chapter_id=chapter_id,
            actor_agent_id=_config.agent_id,
        )
        queued = sum(1 for r in results if r.decision.state == "prompt")
        rejected = sum(1 for r in results if r.decision.state == "reject")

        bits = []
        if queued:
            bits.append(f"{queued} action(s) waiting in your inbox")
        if rejected:
            bits.append(f"{rejected} rejected by the gate")
        return {
            "queued": queued,
            "rejected": rejected,
            "summary": plan.summary or ("Queued: " + ", ".join(bits) if bits else "Nothing to do."),
        }

    @app.get("/api/health")
    async def proxy_health():
        try:
            return _client.health()
        except Exception as e:
            return {"status": "chapter_unreachable", "error": str(e)}

    # ─── NANDA AgentFacts (protocol compliance) ────────────────

    @app.get("/agentfacts.json")
    async def local_agentfacts(request: Request):
        """Serve canonical NANDA AgentFacts (sm-bridge ``SmAgentFacts``) for
        this local agent — the projectnanda-compatible identity document."""
        base_url = _agent_base_url(request)

        from .sm_bridge_adapter import build_self_agentfacts

        facts = build_self_agentfacts(_config, base_url)
        if facts is not None:
            return facts.model_dump(mode="json", exclude_none=True)

        # Fallback only if sm-bridge isn't installed: a minimal, honest
        # document. did:key + Ed25519 auth (NOT the old hmac/did:nanda bug).
        did = f"did:web:{base_url.split('//')[-1].split('/')[0]}"
        if _config.public_key:
            try:
                from .crypto import build_did_key

                did = build_did_key(_config.public_key)
            except Exception:
                pass
        return {
            "id": did,
            "agent_name": _config.agent_id,
            "label": _config.name,
            "description": _config.description or f"Sovereign agent @{_config.agent_id}",
            "version": "1.0.0",
            "endpoints": {"static": [f"{base_url}/"]},
            "capabilities": {
                "modalities": ["text"],
                "skills": (_config.skills or [])[:20],
                "authentication": {"methods": ["ed25519", "did-auth"]},
            },
        }

    # ─── Google A2A JSON-RPC endpoint ─────────────────────────

    from .a2a_rpc import A2ARPCHandler
    from .task_store import TaskStore

    _task_store = TaskStore()

    async def _tool_dispatcher(name: str, args: dict) -> str:
        """Bridge A2A RPC to agent.execute_tool(). Raises KeyError for
        unknown tools so the RPC handler can return ERROR_TOOL_NOT_FOUND.

        Tool set is read from the agent if it exposes AGENT_TOOLS (tests
        use a FakeAgent with a narrower tool list), otherwise from the
        canonical module-level list in agent.py."""
        if _agent is None:
            raise RuntimeError("Agent not initialized")
        tools = getattr(_agent, "AGENT_TOOLS", None)
        if tools is None:
            from .agent import AGENT_TOOLS as tools
        if name not in {t["function"]["name"] for t in tools}:
            raise KeyError(name)
        return await _agent.execute_tool(name, args)

    def _build_cosigner():
        """Witness (B) side of the co-sign handshake: bind this agent's Ed25519
        seed so it can co-sign receipts naming it as counterparty
        (spec/arp/0.2/cosign-companion.md §1). Returns ``None`` — co-signing
        simply disabled — if the agent has no valid 32-byte Ed25519 seed (e.g. a
        legacy HMAC keypair), so a misconfigured key can never mint a bad witness.
        """
        import base64

        from .cosign import make_cosigner

        try:
            seed = base64.b64decode(config.private_key or "")
        except (ValueError, TypeError):
            return None
        if len(seed) != 32:
            return None
        return make_cosigner(seed)

    _rpc_handler = A2ARPCHandler(store=_task_store, dispatcher=_tool_dispatcher, cosigner=_build_cosigner())

    @app.post("/")
    async def a2a_rpc(request: Request):
        """Google A2A JSON-RPC 2.0 endpoint. Handles tasks/send, tasks/get,
        tasks/cancel synchronously; tasks/sendSubscribe and tasks/resubscribe
        stream via SSE. The method field in the envelope decides which."""
        from fastapi.responses import StreamingResponse

        from . import a2a_auth
        from .a2a_rpc import ERROR_PARSE, STREAMING_METHODS, rpc_error

        # ⚠️ THE RAW BYTES, NOT A RE-SERIALISED DICT. The signature is over the
        # body exactly as sent; ``json.dumps`` of the parsed object produces
        # different bytes (key order, separators) and would fail every genuine
        # signature while looking like a crypto problem.
        raw = await request.body()
        try:
            body = json.loads(raw)
        except Exception as e:
            return rpc_error(None, ERROR_PARSE, f"JSON parse error: {e}")

        # Verified here because this is the only layer that has the headers.
        # The DECISION about which methods need it lives in a2a_auth, and the
        # refusal is produced by the handler as a JSON-RPC error object.
        caller = a2a_auth.verify_caller(dict(request.headers), raw.decode("utf-8", "replace"))

        method = body.get("method") if isinstance(body, dict) else None
        if method in STREAMING_METHODS:
            return StreamingResponse(
                _rpc_handler.stream(body, caller=caller),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
        return await _rpc_handler.handle(body, caller=caller)

    # ─── Google A2A Agent Card (protocol compliance) ──────────

    @app.get("/.well-known/agent-card.json")
    async def a2a_agent_card_current(request: Request):
        """The card at the path a CURRENT A2A client fetches.

        ⚠️ SERVED, NOT REDIRECTED, AND THE OLD PATH STAYS. Measured against the
        official a2a-sdk: a current client asks for this path and nothing else,
        so an agent publishing only ``/.well-known/agent.json`` is undiscoverable
        to it — it fails here, before any method is ever attempted.

        A redirect would be the smaller change and the wrong one: whether a v0.2
        client follows one is not something this repository has tested, and the
        old path is what our own client uses today. Two routes, one payload,
        nothing removed.
        """
        return await a2a_agent_card(request)

    @app.get("/.well-known/agent.json")
    async def a2a_agent_card(request: Request):
        """Serve Google A2A v0.2 Agent Card so any A2A-speaking client
        can discover and talk to this member. Dual-published alongside
        /agentfacts.json — A2A covers the wire, NANDA covers identity.

        Also served at ``/.well-known/agent-card.json`` for current clients."""
        from .a2a_card import build_agent_card
        from .agent import AGENT_TOOLS
        from .crypto import build_did_key

        base_url = _agent_base_url(request)
        did = None
        if _config.public_key:
            try:
                did = build_did_key(_config.public_key)
            except Exception:
                did = None

        # Lean-server migration: if the user has a local profile,
        # publish it as the x-nanda.profile extension so servers
        # can render from the card instead of their own DB rows.
        profile_extension = None
        try:
            from .config import CONFIG_DIR
            from .profile import load_profile, to_card_extension

            prof = load_profile(CONFIG_DIR)
            if prof.name or prof.bio or prof.interests or prof.skills or prof.socials:
                profile_extension = to_card_extension(prof)
        except Exception:
            profile_extension = None

        # The listing lifecycle rides on the card as a sibling of `profile` (never
        # inside it — `profile` is signed canonical JSON). Without it, the card of
        # a business that withdrew reads exactly like the card of an active one.
        lifecycle = None
        try:
            from . import owner

            lifecycle = owner.resolve_lifecycle(owner.load_binding(_config.home)).to_public_dict()
        except Exception:
            lifecycle = None

        card = build_agent_card(
            agent_id=_config.agent_id,
            display_name=_config.name,
            description=_config.description,
            version=__import__("community_member").__version__,
            base_url=base_url,
            chapter_url=_config.chapter_url or None,
            did=did,
            skills_declared=_config.skills,
            tools=AGENT_TOOLS,
            profile_extension=profile_extension,
            lifecycle=lifecycle,
        )
        return card.model_dump(mode="json", by_alias=True, exclude_none=True)

    @app.get("/.well-known/agent-lifecycle.json")
    async def well_known_agent_lifecycle():
        """Whether this subject's listing is active, suspended, revoked — or was
        never established. **Always 200, always a state.**

        ⚠️ This endpoint exists because presence-or-absence is not an answer. A
        caller that gets nothing back cannot tell "this business no longer has an
        agent" from "resolution failed", and a stale endpoint then produces a
        plausible transaction with a party that no longer exists. It is the same
        defect as an unrecognised ``?schema=`` selector returning a plausible
        wrong answer instead of a 400, one layer up.

        So it never 404s: a subject with no binding resolves to
        ``not_established``, which is a distinct answer from ``revoked``, and
        that distinction is the entire point.

        ``owner_attested`` says whether the transition carries a verified owner
        signature. False means *this runtime says so* — self-enforcing and true,
        because the runtime is the party being asked — NOT that the owner did
        not sign. Reporting it as owner-attested when it is not would be the same
        plausible wrong answer in a different costume.
        """
        from . import owner

        return owner.resolve_lifecycle(owner.load_binding(_config.home)).to_public_dict()

    @app.post("/webhooks/platform/{platform}/uninstall")
    async def platform_uninstall_webhook(platform: str, request: Request):
        """A commerce platform reporting that its app was uninstalled.

        ⚠️ SUSPENDS, never revokes. The platform observed its own billing; the
        owner asserted nothing, and ``revoked`` would attribute a withdrawal to
        someone who never made one — as well as being terminal, so a business
        that switches POS and comes back would need fresh consent for an event
        it never performed. See ``platform_events`` for the full argument.

        ⚠️ Open by route, closed by signature. The caller is a platform with no
        agent credentials, so this cannot sit behind agent auth — instead the
        raw body must carry a valid HMAC over a configured per-platform secret.
        With no secret configured every request is refused, so the endpoint is
        inert until someone deliberately turns it on. An unsigned POST that could
        suspend a listing would be a denial-of-listing primitive.

        The body is read as BYTES: the signature covers what was sent, and
        re-serialising the JSON would change them.
        """
        from fastapi import Response

        from . import platform_events

        raw = await request.body()
        signature = (
            request.headers.get("x-orrery-signature")
            or request.headers.get("x-hub-signature-256")
            or request.headers.get("x-signature")
            or ""
        )
        result = platform_events.receive_uninstall(_config.home, platform, raw, signature)
        body = {
            "outcome": result.outcome,
            "reason": result.reason,
            "state_changed": result.state_changed,
            "lifecycle": result.lifecycle.to_public_dict() if result.lifecycle else None,
        }
        # 202 rather than 200 on success: this is an accepted notification, not a
        # completed negotiation. 401 on refusal so a misconfigured or hostile
        # sender is told loudly rather than getting a quiet 200 that reads as
        # "handled" — the ambiguity the owner-attested rework exists to remove, one surface over.
        status = 401 if result.outcome == platform_events.REFUSED else 202
        return Response(content=json.dumps(body), media_type="application/json", status_code=status)

    @app.get("/.well-known/conformance.json")
    async def well_known_conformance():
        """This agent's signed conformance badge — public, no auth, offline-
        verifiable against the embedded did:key. Generated at boot from a real
        in-process run of the signing-conformance checks (labelled
        self-attested — no third-party witness; see conformance_boot.py), or
        by an operator via scripts/gen_conformance_badge.py, which always wins
        while it verifies. 404 only when no signable identity exists yet."""
        from fastapi import HTTPException

        from .conformance_badge import load_badge

        badge = load_badge()
        if badge is None:
            raise HTTPException(status_code=404, detail="no conformance badge published")
        return badge

    @app.get("/.well-known/reputation.json")
    async def well_known_reputation():
        """This agent's Portable Agent Reputation Credential (PARC) — public,
        offline-verifiable. Built on-demand from the local receipt ledger and
        signed with the agent's did:key. 404 until the agent has an identity."""
        from datetime import UTC, datetime, timedelta

        from fastapi import HTTPException

        from .reputation_credential import build_self_credential

        now = datetime.now(UTC)
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            return build_self_credential(
                _config,
                as_of=stamp,
                valid_from=stamp,
                valid_until=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    # ─── Local routes (agent state, no auth) ──────────────────

    @app.get("/api/local/status")
    async def get_status():
        uptime = int(time.time() - _start_time)
        if _agent:
            return {
                "status": "thinking" if _agent.running else "idle",
                "thought_count": _agent.thought_count,
                "last_thought": _thought_log[-1]["text"] if _thought_log else None,
                "uptime_seconds": uptime,
                "agent_id": _config.agent_id,
                "chapter_url": _config.chapter_url,
                "provider": _config.provider,
                "model": _config.model,
            }
        return {
            "status": "not_started",
            "thought_count": 0,
            "uptime_seconds": uptime,
            "agent_id": _config.agent_id,
        }

    @app.get("/api/local/llm/spend")
    async def get_llm_spend():
        """What this agent's LLM calls actually cost in tokens.

        RECORD-ONLY, and every figure is an OBSERVATION — what a provider
        reported in ``response.usage``, never a tokenizer estimate and never a
        ``max_tokens`` ceiling. ``calls_without_usage`` counts calls whose
        provider reported nothing; those contribute no tokens, so a reader can
        see how much of the total is actually covered.

        Protected by the local token like every route that is not explicitly
        opened — spend is operator-visible only.
        """
        from . import llm_meter

        return llm_meter.spend()

    @app.get("/api/local/memory")
    async def get_memory():
        return {"notes": _config.load_private_memory()}

    @app.post("/api/local/disclose")
    async def disclose_receipts(req: DiscloseRequest):
        """Selective disclosure: reveal the chosen Agency Log receipts, each with
        a Merkle inclusion proof against this agent's signed PARC (sm-parc). The
        returned bundle verifies fully offline — see ``receipt_disclosure``.
        404 until the agent has an identity; 400 for unknown/empty receipt ids."""
        from datetime import UTC, datetime, timedelta

        from fastapi import HTTPException

        from .receipt_disclosure import build_disclosure

        if not _config.public_key:
            raise HTTPException(status_code=404, detail="no local identity yet")
        now = datetime.now(UTC)
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            return build_disclosure(
                _config,
                receipt_ids=req.receipt_ids,
                as_of=stamp,
                valid_from=stamp,
                valid_until=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/local/consent/decisions")
    async def consent_decisions():
        """The consent chain as sm-decision-inspector envelopes: the
        verify-gated DecisionEnvelope[] plus the quorum policy (1-of-1 —
        M-of-N is out of scope). Pending prompts are lifecycle:"proposed" and
        carry prompt_event_sha256; the inspector's approve/deny gestures wire
        to the EXISTING /api/local/consent/{approve,deny} endpoints."""
        from .decision_feed import QUORUM_POLICY, export_decision_envelopes

        _ensure_ledger_init()
        return {
            "envelopes": export_decision_envelopes(tenant=_config.agent_id or "local-agent"),
            "quorum_policy": QUORUM_POLICY,
        }

    @app.get("/api/local/aae/audit")
    async def aae_audit_bundle():
        """The agent's AAE authorization chain, auditor-ready: the
        verify-gated ``AuditableEnvelope[]`` plus a checkpoint envelope whose
        Merkle commitment the sm-attest-auditor drill verifies offline —
        no call-back to this agent. Empty chain → empty envelopes, no
        checkpoint."""
        from .aae_audit import build_checkpoint_envelope, export_auditable_envelopes
        from .crypto import build_did_key

        tenant = _config.agent_id or "local-agent"
        envelopes = export_auditable_envelopes(tenant=tenant)
        scope_key = build_did_key(_config.public_key) if _config.public_key else tenant
        checkpoint = build_checkpoint_envelope(envelopes, tenant=tenant, scope_key=scope_key)
        return {"envelopes": envelopes, "checkpoint": checkpoint}

    @app.get("/api/local/aae/audit/proof/{leaf_hash}")
    async def aae_audit_proof(leaf_hash: str):
        """The auditor-shaped Merkle inclusion proof for one envelope of the
        chain — verifies against the checkpoint's root offline. 404 when the
        hash is not a chain member."""
        from fastapi import HTTPException

        from .aae_audit import export_auditable_envelopes, inclusion_proof

        envelopes = export_auditable_envelopes(tenant=_config.agent_id or "local-agent")
        proof = inclusion_proof(envelopes, leaf_hash)
        if proof is None:
            raise HTTPException(status_code=404, detail="envelope hash not in this agent's chain")
        return proof

    @app.post("/api/local/memory")
    async def save_memory(req: MemoryRequest):
        _config.save_private_memory(req.key, req.value, req.memory_type)
        return {"saved": True}

    @app.delete("/api/local/memory/{index}")
    async def delete_memory(index: int):
        memories = _config.load_private_memory()
        if 0 <= index < len(memories):
            memories.pop(index)
            import community_member.config as config_mod

            memory_file = config_mod.CONFIG_DIR / "memory.json"
            memory_file.write_text(json.dumps(memories, indent=2))
            return {"deleted": True}
        return {"error": "Index out of range"}

    @app.get("/api/local/config")
    async def get_config():
        return {
            "agent_id": _config.agent_id,
            "name": _config.name,
            "description": _config.description,
            "skills": _config.skills,
            "interests": _config.interests,
            "chapter_url": _config.chapter_url,
            "provider": _config.provider,
            "model": _config.model,
            "has_keypair": _config.has_keypair(),
            "public_key": _config.public_key[:20] + "..." if _config.public_key else "",
            "api_key": _mask_key(_config.api_key or _config.get_api_key("")),
        }

    @app.get("/api/local/settings")
    async def get_settings():
        """Return the LLM provider config + the catalogue of switchable
        options. The dashboard renders both: current selection on the
        left, the seven available options on the right.
        """
        return {
            "current": {
                "provider": _config.provider,
                "model": _config.model,
                "base_url": _PROVIDER_BASE_URLS.get(_config.provider, ""),
                "is_local": _config.provider in _LOCAL_PROVIDERS,
                "api_key_masked": _mask_key(_config.api_key) if _config.api_key else "",
            },
            "providers": [
                {
                    "id": pid,
                    "label": _PROVIDER_LABELS[pid],
                    "base_url": base_url,
                    "is_local": pid in _LOCAL_PROVIDERS,
                    "default_model": default_model,
                }
                for pid, base_url, default_model in _PROVIDER_CATALOGUE
            ],
        }

    @app.put("/api/local/settings")
    async def put_settings(body: SettingsUpdate):
        """Switch the agent's LLM provider at runtime.

        For local providers we accept an empty key — the OpenAI client
        just needs a non-empty string, so we substitute ``"local"``.
        For cloud providers we require a key and probe ``models.list``
        before persisting; a wrong key is much worse to discover during
        the next think cycle than now.
        """
        from fastapi import HTTPException

        provider = body.provider.strip()
        if provider not in _PROVIDER_BASE_URLS:
            raise HTTPException(status_code=400, detail=f"unknown provider: {provider}")
        is_local = provider in _LOCAL_PROVIDERS
        api_key = (body.api_key or "").strip()
        if not is_local and not api_key:
            raise HTTPException(status_code=400, detail="api_key required for cloud providers")

        # Probe before saving so a bad key doesn't get persisted.
        try:
            from community_member import llm_runtime

            probe = llm_runtime.build_client(llm_runtime.resolve(provider), api_key=api_key)
            probe.models.list()
        except Exception as err:
            # Local servers may refuse models.list yet still serve
            # chat.completions — accept that failure mode but warn.
            if not is_local:
                raise HTTPException(
                    status_code=400,
                    detail=f"could not verify provider: {type(err).__name__}",
                ) from err

        _config.provider = provider
        _config.model = (body.model or "").strip() or _config.model
        _config.api_key = api_key or ("local" if is_local else _config.api_key)
        _config.save()
        return {"updated": True, "provider": provider, "model": _config.model}

    @app.get("/api/local/identity-trust")
    async def get_identity_trust():
        """Return the user's self-asserted trust + the chapter's
        cached attestation + the effective-trust snapshot the gate
        would apply right now.

        Use ``POST /api/local/identity-trust/refresh`` to force-fetch
        the chapter score; the cache is otherwise refreshed in the
        background on a 15-minute TTL.
        """
        from community_member import identity_trust as _it
        from community_member.config import CONFIG_DIR

        snap = _it.snapshot(CONFIG_DIR)
        return {
            "local": snap.local,
            "chapter": snap.chapter,
            "chapter_refreshed_at": snap.chapter_refreshed_at,
            "effective": snap.effective,
            "threshold": snap.threshold,
            "auto_approves_trusted": snap.effective >= snap.threshold,
        }

    class IdentityTrustUpdate(BaseModel):
        local_trust: int  # 0-100

    @app.put("/api/local/identity-trust")
    async def put_identity_trust(body: IdentityTrustUpdate):
        """Set the user's self-asserted trust ceiling (0-100).

        At 0 every trusted-provenance action prompts. At
        :data:`AUTO_APPROVE_THRESHOLD` (70) and above, the executor
        auto-approves trusted-provenance actions without writing a
        consent prompt; an audit row is still written with the
        decision_reason ``trust_threshold`` and the effective scores
        so the chain stays replay-verifiable.
        """
        from community_member import identity_trust as _it
        from community_member.config import CONFIG_DIR

        v = max(0, min(100, int(body.local_trust)))
        _it.save_local_trust(CONFIG_DIR, v)
        return await get_identity_trust()

    @app.post("/api/local/identity-trust/refresh")
    async def refresh_chapter_trust():
        """Force-fetch the chapter's trust score for this agent.

        Network call to ``{chapter_url}/api/agents/{agent_id}/trust``.
        Falls back to the previous cache on failure (the cached score
        keeps working until the cache TTL expires or this endpoint
        succeeds).
        """
        from fastapi import HTTPException

        from community_member import identity_trust as _it
        from community_member.config import CONFIG_DIR

        if not _config or not _config.chapter_url or not _config.agent_id:
            raise HTTPException(
                status_code=400,
                detail="chapter not configured",
            )
        try:
            # Signed as this agent: the org serves a member's score to a
            # stranger only once that member opted into the listing, and
            # answers 404 otherwise — so the agent asks as itself.
            trust_path = f"/api/agents/{_config.agent_id}/trust"
            signed = _client._auth_headers("", "GET", trust_path) if _client.private_key else {}
            score, raw = _it.fetch_chapter_trust(_config.chapter_url, _config.agent_id, headers=signed)
        except Exception as err:
            raise HTTPException(
                status_code=502,
                detail=f"chapter unreachable: {err}",
            ) from err
        _it.save_chapter_trust(CONFIG_DIR, score, raw=raw)
        return await get_identity_trust()

    @app.get("/api/local/capabilities")
    async def get_capabilities():
        """Surface the 9 capabilities + example intents so users
        discover what the agent can actually do without reading code.

        The capability set must match
        :data:`community_member.skills.HIGH_RISK_CAPABILITIES` plus
        the read-side complements (browser.navigate, fs.read, etc).
        Keeping this hardcoded here is fine — when a new capability
        ships, this list and the gate's allowlist update together.
        """
        return {
            "capabilities": [
                {
                    "id": "browser.navigate",
                    "label": "Open a web page",
                    "risk": "caution",
                    "example": "Find the abstract of Anthropic's most recent paper on agent safety",
                },
                {
                    "id": "browser.extract",
                    "label": "Read content from a web page",
                    "risk": "caution",
                    "example": "Summarize the top three Hacker News posts from this morning",
                },
                {
                    "id": "fs.read",
                    "label": "Read files",
                    "risk": "caution",
                    "example": "What's in my Downloads folder",
                },
                {
                    "id": "fs.write",
                    "label": "Write files",
                    "risk": "dangerous",
                    "example": "Save the meeting notes I dictated to ~/notes/2026-04-25.md",
                },
                {
                    "id": "shell.exec",
                    "label": "Run a shell command",
                    "risk": "dangerous",
                    "example": "Show me which processes are using more than 500 MB",
                },
                {
                    "id": "net.http",
                    "label": "Make HTTP requests",
                    "risk": "caution",
                    "example": "Check whether docs.python.org is up",
                },
                {
                    "id": "desktop.click",
                    "label": "Click on the screen",
                    "risk": "dangerous",
                    "example": "Click the Send button in my email draft",
                },
                {
                    "id": "desktop.type",
                    "label": "Type into the focused window",
                    "risk": "dangerous",
                    "example": "Type the subject line I dictated into Gmail",
                },
                {
                    "id": "desktop.read_screen",
                    "label": "Take a screenshot",
                    "risk": "caution",
                    "example": "What does the error dialog on my screen say",
                },
            ]
        }

    # ─── Skill packs ──────────────────────────────────────────
    #
    # Bundled, offline skill bundles. "Install" flips a pack on locally and
    # refreshes the live agent so its skills are immediately callable in chat +
    # the autonomous loop. No network, registry, or signature — first-party.

    def _refresh_agent_skills() -> None:
        """Reload the running agent's skill set so a just-installed pack takes
        effect without a restart. Best-effort (no agent in headless/test)."""
        if _agent is not None and hasattr(_agent, "_load_skills"):
            try:
                _agent._load_skills()
            except Exception:
                pass

    @app.get("/api/local/packs")
    async def list_packs():
        from community_member import skill_runtime

        return {"packs": skill_runtime.list_packs_for_ui()}

    @app.post("/api/local/packs/{pack_id}/install")
    async def install_pack(pack_id: str):
        from fastapi import HTTPException

        from community_member import skill_runtime

        manifests = skill_runtime.load_pack_manifests()
        if pack_id not in manifests:
            raise HTTPException(status_code=404, detail=f"unknown pack: {pack_id}")
        skill_runtime.set_pack_installed(pack_id, True)
        _refresh_agent_skills()
        return {"installed": pack_id}

    @app.post("/api/local/packs/{pack_id}/uninstall")
    async def uninstall_pack(pack_id: str):
        from fastapi import HTTPException

        from community_member import skill_runtime

        manifests = skill_runtime.load_pack_manifests()
        if pack_id not in manifests:
            raise HTTPException(status_code=404, detail=f"unknown pack: {pack_id}")
        if manifests[pack_id].get("default_installed"):
            raise HTTPException(status_code=400, detail="default packs cannot be uninstalled")
        skill_runtime.set_pack_installed(pack_id, False)
        _refresh_agent_skills()
        return {"uninstalled": pack_id}

    def _ensure_chat_store_init() -> None:
        """Lazy-init the chat history SQLite store. Idempotent —
        chat_store.init() is safe to call repeatedly. Failures are
        swallowed so a broken history file never blocks streaming."""
        try:
            from community_member import chat_store
            from community_member.config import CONFIG_DIR

            chat_store.init(CONFIG_DIR / "chat_history.db")
        except Exception:
            pass

    @app.get("/api/local/chat/history")
    async def chat_history(limit: int = 200):
        """Return the most recent chat turns (chronological order).

        The chat panel calls this on mount to rehydrate the
        conversation across browser refreshes / Electron restarts.
        Server stays stateless on the wire; persistence is purely so
        the UI can show the user where they left off.
        """
        from community_member import chat_store

        _ensure_chat_store_init()
        return {"turns": chat_store.list_recent(limit=limit)}

    @app.delete("/api/local/chat/history")
    async def chat_history_clear():
        """Wipe every persisted chat turn. Returns the deleted count.

        Audit ledger and habit data are unaffected — this only clears
        the cosmetic display history. Use the panic endpoint for the
        nuclear option.
        """
        from community_member import chat_store

        _ensure_chat_store_init()
        return {"deleted": chat_store.clear()}

    @app.post("/api/local/chat/stream")
    async def chat_stream(body: ChatRequest):
        """Stream a chat completion + tool calls through the agent's
        configured provider.

        Server-Sent Events, in the **AG-UI** protocol (https://docs.ag-ui.com)
        so the stream interoperates with the AG-UI ecosystem (see
        ``community_member.agui``). One JSON event per ``data:`` frame:
          - ``RunStarted`` / ``RunFinished`` — bracket the turn
          - ``TextMessageStart`` / ``TextMessageContent`` (delta) /
            ``TextMessageEnd`` — assistant text tokens
          - ``ToolCallStart`` / ``ToolCallArgs`` (args JSON) / ``ToolCallEnd``
            — the agent invoked a tool; ``ToolCallResult`` carries its result
            (truncated for display)
          - ``RunError`` — terminal error (rides inside the 200 SSE)

        The endpoint:
          1. Replaces any client-supplied system message with one that
             names the user, the chapter, and the local capabilities
             — without that, the LLM has no idea who it represents.
          2. Exposes :data:`AGENT_TOOLS` so the LLM can actually look
             up chapter members, submit intents, save notes, etc.
             Tool execution reuses ``LocalAgent.execute_tool`` so the
             chat panel and the autonomous think loop stay
             behaviorally identical.
          3. Loops until the model emits text instead of more tool
             calls (capped at 5 iterations to bound a runaway loop).

        Stateless on purpose: the client owns the user/assistant
        message history and sends the full array every turn.
        """
        from fastapi.responses import StreamingResponse

        async def _gen():
            from community_member import agui

            run_id = agui.new_id()
            try:
                from community_member import chat_store
                from community_member.agent import AGENT_TOOLS

                # Expose the agent's full tool set (protocol tools + loaded
                # skills) when a live agent is present, so the chat panel can
                # call skills; fall back to the module constant for the
                # agent-less case (tests, headless capture).
                chat_tools = getattr(_agent, "all_tools", None) or AGENT_TOOLS

                # Tool scoping on the INTERACTIVE path is opt-in. A person
                # mid-conversation is exactly who notices a missing capability
                # and exactly who cannot route around it, so narrowing here is
                # something a deployment turns on rather than something it
                # receives. The autonomous loops are scoped by default; a
                # 20-cycle drive produced no durable output from the full set.
                from community_member import tool_scope

                scoped = tool_scope.select(
                    chat_tools,
                    scope=tool_scope.SCOPE_CHAT if tool_scope.chat_scope_enabled() else tool_scope.SCOPE_FULL,
                )
                chat_tools = scoped.tools

                _ensure_chat_store_init()
                yield agui.encode_sse(agui.run_started(run_id=run_id, thread_id=run_id))

                # This site lowercased the provider WITHOUT stripping it, so a
                # space-padded value missed the table and resolved to OpenAI's
                # endpoint carrying the configured key. The resolver normalises
                # once and resolves nothing it does not recognise.
                from community_member import llm_runtime

                provider = getattr(_config, "provider", "") or ""
                model = getattr(_config, "model", "") or ""
                # THIS SURFACE HAS NO DETERMINISTIC FALLBACK. Every other gated
                # site serves a computed answer instead of calling; a chat stream
                # has nothing to serve. So it refuses with a readable reason
                # rather than becoming a silent POST carrying a placeholder
                # credential — which is what it did.
                try:
                    resolution = llm_runtime.resolve(provider, model=model or None)
                    client = llm_runtime.build_client(
                        resolution, api_key=getattr(_config, "api_key", ""), strict=llm_client.strict_enabled()
                    )
                except llm_runtime.LLMNotConfigured as exc:
                    yield agui.encode_sse(
                        agui.run_error(
                            run_id=run_id,
                            message=(
                                f"no LLM provider is configured, so this chat cannot run and no request was made. {exc}"
                            ),
                        )
                    )
                    return
                model = resolution.model

                # Build the identity-aware system prompt server-side.
                # The client ships a generic placeholder; we discard
                # whatever it sent so the model can't be tricked into
                # role-confusion by a malicious page that injected text.
                msgs: list[dict] = [{"role": "system", "content": _chat_system_prompt(_config)}]
                for m in body.messages:
                    d = m.model_dump()
                    if d.get("role") == "system":
                        continue
                    msgs.append(d)

                if body.images and msgs:
                    last_user_idx = next(
                        (i for i in range(len(msgs) - 1, -1, -1) if msgs[i].get("role") == "user"),
                        None,
                    )
                    if last_user_idx is not None:
                        existing = msgs[last_user_idx].get("content")
                        text = existing if isinstance(existing, str) else ""
                        blocks: list[dict] = []
                        if text:
                            blocks.append({"type": "text", "text": text})
                        for url in body.images:
                            blocks.append({"type": "image_url", "image_url": {"url": url}})
                        msgs[last_user_idx]["content"] = blocks

                # Persist the user's turn now (before streaming the
                # assistant). The UI hydrates from this on refresh.
                # Best-effort: a chat_store failure should not break
                # the stream, so swallow.
                last_user_idx = next(
                    (i for i in range(len(msgs) - 1, -1, -1) if msgs[i].get("role") == "user"),
                    None,
                )
                if last_user_idx is not None:
                    try:
                        chat_store.append("user", msgs[last_user_idx]["content"])
                    except Exception:
                        pass

                # Tool-calling loop. Each iteration: stream until the
                # model finishes; if it asked for tools, execute them,
                # append results, and let the model keep going. The
                # final assistant text (across all loops) is what we
                # persist for hydration.
                final_assistant_text = ""
                # Bounded by TOKENS SPENT, not by iterations. Five cheap
                # iterations and five expensive ones are not the same bound,
                # and the measured worst case here was five calls carrying
                # 11,469 input tokens that produced no assistant text at all.
                # A hard iteration cap stays as a backstop against a provider
                # that reports nothing and an estimator that somehow reads zero.
                from community_member import token_budget

                budget = token_budget.LoopBudget()
                HARD_LOOP_CAP = 25
                truncated_steps = 0
                while budget.iterations < HARD_LOOP_CAP:
                    if budget.exhausted:
                        budget.stopped_on_budget = True
                        break
                    budget.charge(msgs, chat_tools)
                    stream = client.chat.completions.create(
                        model=model,
                        messages=msgs,
                        tools=chat_tools,
                        stream=True,
                    )
                    assistant_text = ""
                    msg_id: str | None = None
                    # idx -> {"id", "name", "args"} accumulator
                    tool_calls: dict[int, dict] = {}
                    for chunk in stream:
                        try:
                            choice = chunk.choices[0]
                            delta = choice.delta
                        except (AttributeError, IndexError):
                            continue
                        # finish_reason == "length" means the output ceiling
                        # cut the answer off. Silent truncation reads as a
                        # model that stopped having anything to say.
                        if getattr(choice, "finish_reason", None) == "length":
                            truncated_steps += 1
                        text = getattr(delta, "content", "") or ""
                        if text:
                            if msg_id is None:
                                msg_id = agui.new_id()
                                yield agui.encode_sse(agui.text_message_start(message_id=msg_id))
                            assistant_text += text
                            yield agui.encode_sse(agui.text_message_content(message_id=msg_id, delta=text))
                        for tc in getattr(delta, "tool_calls", None) or []:
                            idx = getattr(tc, "index", 0) or 0
                            slot = tool_calls.setdefault(idx, {"id": "", "name": "", "args": ""})
                            if getattr(tc, "id", None):
                                slot["id"] = tc.id
                            fn = getattr(tc, "function", None)
                            if fn is not None:
                                if getattr(fn, "name", None):
                                    slot["name"] = fn.name
                                if getattr(fn, "arguments", None):
                                    slot["args"] += fn.arguments

                    if msg_id is not None:
                        yield agui.encode_sse(agui.text_message_end(message_id=msg_id))
                    if assistant_text:
                        final_assistant_text = assistant_text
                    if not tool_calls:
                        break  # plain text turn — done

                    # Append the assistant's tool-call message so the
                    # next loop has the matching tool_call_ids when we
                    # reply with tool results.
                    msgs.append(
                        {
                            "role": "assistant",
                            "content": assistant_text or None,
                            "tool_calls": [
                                {
                                    "id": slot["id"],
                                    "type": "function",
                                    "function": {
                                        "name": slot["name"],
                                        "arguments": slot["args"] or "{}",
                                    },
                                }
                                for slot in tool_calls.values()
                            ],
                        }
                    )

                    # Execute each tool. The agent dispatcher already
                    # routes to server API + local memory + skills,
                    # so the chat panel inherits everything the
                    # autonomous think loop can do.
                    for slot in tool_calls.values():
                        name = slot["name"]
                        raw_args = slot["args"] or "{}"
                        try:
                            args = json.loads(raw_args)
                        except json.JSONDecodeError:
                            args = {}
                        tc_id = slot["id"] or agui.new_id()
                        yield agui.encode_sse(agui.tool_call_start(tool_call_id=tc_id, tool_call_name=name))
                        yield agui.encode_sse(agui.tool_call_args(tool_call_id=tc_id, delta=raw_args))
                        yield agui.encode_sse(agui.tool_call_end(tool_call_id=tc_id))
                        try:
                            if _agent is not None:
                                result = await _agent.execute_tool(name, args)
                            else:
                                result = json.dumps({"error": "agent runtime not available"})
                        except Exception as err:
                            result = json.dumps({"error": str(err)})
                        yield agui.encode_sse(agui.tool_call_result(tool_call_id=tc_id, content=result[:2000]))
                        msgs.append(
                            {
                                "role": "tool",
                                "tool_call_id": slot["id"],
                                "content": result,
                            }
                        )

                # WHAT WAS WITHHELD OR CUT IS SAID OUT LOUD. A user who
                # cannot see why the agent declined cannot fix it, and a short
                # answer with no explanation is indistinguishable from a model
                # that had nothing more to offer.
                notices = [n for n in (scoped.summary(), budget.summary()) if n]
                if truncated_steps:
                    notices.append(f"{truncated_steps} step(s) hit the output ceiling and were cut short.")
                if notices:
                    notice_id = agui.new_id()
                    yield agui.encode_sse(agui.text_message_start(message_id=notice_id))
                    yield agui.encode_sse(
                        agui.text_message_content(message_id=notice_id, delta="\n\n" + " ".join(notices))
                    )
                    yield agui.encode_sse(agui.text_message_end(message_id=notice_id))

                # Persist the assistant turn for hydration. Best-
                # effort — never block the stream on history write.
                if final_assistant_text:
                    try:
                        chat_store.append("assistant", final_assistant_text)
                    except Exception:
                        pass

                yield agui.encode_sse(agui.run_finished(run_id=run_id))
            except Exception as err:
                yield agui.encode_sse(agui.run_error(run_id=run_id, message=str(err)))

        return StreamingResponse(
            _gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.get("/api/local/pending")
    async def get_pending():
        try:
            return _client.get_intents_pending(_config.agent_id)
        except Exception as e:
            return {"pending": [], "error": str(e)}

    @app.get("/api/local/thoughts")
    async def get_thoughts():
        return {"thoughts": list(_thought_log)}

    # ─── W5 PR1: consent / graduations / panic / duress ───────
    #
    # Lazy-initialize the consent ledger on first hit. Keystore-signed
    # when the agent_id has a private key registered; otherwise the
    # ledger still works but without the signature layer.

    def _ensure_ledger_init() -> None:
        from community_member import keystore
        from community_member.config import CONFIG_DIR
        from community_member.consent import ledger as _ledger

        priv = keystore.load_private_key(_config.agent_id) if _config and _config.agent_id else None
        try:
            _ledger.init(CONFIG_DIR / "consent.db", signing_key_b64=priv)
        except Exception:
            pass

    def _chapter_id() -> str:
        return f"local:{_config.agent_id}" if _config and _config.agent_id else "local:unknown"

    def _body_to_action_request(body: ActionRequestBody):
        from community_member.consent.gate import ActionRequest

        return ActionRequest(
            capability=body.capability,
            scope=body.scope,
            context=body.context,
            provenance=body.provenance,  # type: ignore[arg-type]
            source_ref=body.source_ref,
            rationale=body.rationale,
        )

    def _prompt_to_action_request(prompt_event_sha256: str):
        """Reconstruct the CANONICAL ActionRequest (including ``extra``) from
        our own ``consent.prompt`` ledger row.

        The client only sends the prompt hash; the action we actually execute
        comes from the server-side prompt record, NOT client input — so a
        hijacked UI cannot inject a different ``extra`` (url/path/skill args)
        to run. ``find_valid_approval`` is still the authorization guard.
        Returns ``None`` if the prompt isn't on file (e.g. aged out).
        """
        from community_member.consent import ledger as _ledger
        from community_member.consent.gate import ActionRequest

        for ev in _ledger.list_events(action="consent.prompt", limit=200):
            if ev.get("event_sha256") != prompt_event_sha256:
                continue
            det = ev.get("detail") or {}
            return ActionRequest(
                capability=det.get("capability", ""),
                scope=det.get("scope", ""),
                context=det.get("context", ""),
                provenance=det.get("provenance", "untrusted"),
                source_ref=det.get("source_ref"),
                rationale=det.get("rationale", ""),
                extra=det.get("extra") or {},
            )
        return None

    def _observe_decision_safe(req, decision: str) -> None:
        """WIRE-5: best-effort write to the habit model on user click.

        `decision` is "approved" or "denied" (HabitModel's UserDecision).
        Uses sha256 of the request's `context` field as the bucket key
        — the same shape the executor uses, so user-clicks and
        auto-graduations land in the same bucket.
        """
        if _config is None or not _config.agent_id:
            return
        try:
            import hashlib
            from datetime import UTC, datetime

            from community_member.config import CONFIG_DIR
            from community_member.habits import HabitModel

            ctx_sha = hashlib.sha256((req.context or "").encode()).hexdigest()
            HabitModel(CONFIG_DIR / "habits.db").observe(
                capability=req.capability,
                scope=req.scope,
                context_sha256=ctx_sha,
                decision=decision,
                recorded_at=datetime.now(UTC).isoformat(),
            )
        except Exception:
            pass

    def _is_resolved(prompt_sha: str, all_events: list[dict]) -> bool:
        """A prompt is resolved iff some later row references it as
        `detail.prompt_event_sha256` or the matching approval/denial
        exists in the same chain."""
        for ev in all_events:
            if ev["action"] not in (
                "consent.approved",
                "consent.reject",
                "consent.denied",
                "consent.auto_approved",
            ):
                continue
            det = ev.get("detail") or {}
            if det.get("prompt_event_sha256") == prompt_sha:
                return True
        return False

    @app.get("/api/local/profile")
    async def get_profile():
        """Return the local profile + a flag indicating whether
        signature verification would pass under the agent's pubkey.

        Lean-chapter migration: this is the canonical read path
        for the agent's profile. The chapter no longer holds the
        truth — it caches whatever this endpoint serves (via the
        Agent Card's x-nanda.profile extension).
        """
        from community_member.config import CONFIG_DIR
        from community_member.profile import load_profile

        prof = load_profile(CONFIG_DIR)
        return {
            "name": prof.name,
            "bio": prof.bio,
            "interests": list(prof.interests),
            "skills": list(prof.skills),
            "email": {"value": prof.email.value, "visible": prof.email.visible},
            "phone": {"value": prof.phone.value, "visible": prof.phone.visible},
            "socials": dict(prof.socials),
            "photo_url": prof.photo_url,
            "updated_at": prof.updated_at,
            "signed": bool(prof.signature),
        }

    @app.put("/api/local/profile")
    async def put_profile(request: Request):
        """Update the local profile + re-sign + re-publish in the
        Agent Card. Body shape mirrors GET /api/local/profile.
        Missing fields keep their current value.

        Signing uses the agent's Ed25519 private key from keystore.
        If the keystore is unavailable, the profile saves unsigned;
        chapters that fetch the card see signature=\"\" and may
        choose to render with a \"unverified\" badge.
        """
        from community_member.config import CONFIG_DIR
        from community_member.profile import (
            ProfileField,
            load_profile,
            save_profile,
        )

        body = await request.json()
        prof = load_profile(CONFIG_DIR)
        if "name" in body:
            prof.name = str(body.get("name") or "")
        if "bio" in body:
            prof.bio = str(body.get("bio") or "")
        if "interests" in body and isinstance(body["interests"], list):
            prof.interests = [str(s) for s in body["interests"]]
        if "skills" in body and isinstance(body["skills"], list):
            prof.skills = [str(s) for s in body["skills"]]
        if "email" in body and isinstance(body["email"], dict):
            prof.email = ProfileField(
                value=body["email"].get("value"),
                visible=bool(body["email"].get("visible", False)),
            )
        if "phone" in body and isinstance(body["phone"], dict):
            prof.phone = ProfileField(
                value=body["phone"].get("value"),
                visible=bool(body["phone"].get("visible", False)),
            )
        if "socials" in body and isinstance(body["socials"], dict):
            prof.socials = {str(k): str(v) for k, v in body["socials"].items()}
        if "photo_url" in body:
            prof.photo_url = body["photo_url"] or None

        # Try to sign with the agent's keystore-stored Ed25519 key.
        # If keystore is locked or unavailable we save unsigned;
        # the user can re-sign later via PUT after unlocking.
        sign_callable = None
        try:
            import base64 as _b64

            from community_member import keystore
            from community_member.crypto import ed25519_sign_message

            priv_b64 = keystore.load_private_key(_config.agent_id) if _config.agent_id else None
            if priv_b64:

                def _sign(msg: bytes) -> bytes:
                    sig_b64 = ed25519_sign_message(msg.decode("utf-8"), priv_b64)
                    return _b64.b64decode(sig_b64)

                sign_callable = _sign
        except Exception:
            sign_callable = None

        prof = save_profile(prof, CONFIG_DIR, sign=sign_callable)
        return {
            "ok": True,
            "signed": bool(prof.signature),
            "updated_at": prof.updated_at,
        }

    @app.get("/api/local/consent/pending")
    async def consent_pending():
        """Unresolved consent.prompt rows not older than 5 min TTL."""
        from datetime import UTC, datetime, timedelta

        from community_member.consent import ledger as _ledger

        _ensure_ledger_init()

        # Pull a wide window — we filter + enrich in-process.
        prompts = _ledger.list_events(action="consent.prompt", limit=200)
        all_events = _ledger.list_events(limit=1000)
        now = datetime.now(UTC)
        ttl = timedelta(minutes=5)
        out = []
        for p in prompts:
            try:
                occurred = datetime.fromisoformat(p["occurred_at"])
            except (KeyError, ValueError):
                continue
            if now - occurred > ttl:
                continue
            if _is_resolved(p["event_sha256"], all_events):
                continue
            det = p.get("detail") or {}
            out.append(
                {
                    "prompt_event_sha256": p["event_sha256"],
                    "capability": det.get("capability", ""),
                    "scope": det.get("scope", ""),
                    "context": det.get("context", ""),
                    "provenance": det.get("provenance", ""),
                    "source_ref": det.get("source_ref"),
                    "rationale": det.get("rationale", ""),
                    "occurred_at": p["occurred_at"],
                }
            )
        return {"pending": out}

    @app.get("/api/local/digest")
    async def consent_digest(hours: int = 24):
        """Rolling-window summary of the local consent ledger.

        Returns counts and samples for `consent.approved`,
        `consent.denied`, and `consent.auto_approved` rows within the
        last `hours` (default 24 — "today"). Used by the DailyDigest
        page in the dashboard so the user can see at a glance what
        their agent did while they were away.
        """
        from datetime import UTC, datetime, timedelta

        from community_member.consent import ledger as _ledger

        _ensure_ledger_init()
        hours_clamped = max(1, min(24 * 30, int(hours)))
        since = (datetime.now(UTC) - timedelta(hours=hours_clamped)).isoformat()

        def _rows(action: str) -> list[dict]:
            rows = _ledger.list_events(action=action, since=since, limit=500)
            samples = []
            for r in rows[:5]:
                det = r.get("detail") or {}
                samples.append(
                    {
                        "capability": det.get("capability", ""),
                        "scope": det.get("scope", ""),
                        "occurred_at": r.get("occurred_at", ""),
                    }
                )
            return [rows, samples]

        approved_rows, approved_samples = _rows("consent.approved")
        denied_rows, denied_samples = _rows("consent.denied")
        auto_rows, auto_samples = _rows("consent.auto_approved")

        return {
            "window_hours": hours_clamped,
            "approved": {"count": len(approved_rows), "sample": approved_samples},
            "denied": {"count": len(denied_rows), "sample": denied_samples},
            "auto_approved": {"count": len(auto_rows), "sample": auto_samples},
        }

    @app.post("/api/local/consent/approve")
    async def consent_approve(body: ConsentApproveRequest):
        """Approve a pending action AND run it now.

        Records the ``consent.approved`` row, then immediately executes the
        action through the agent's v2 runners (instead of waiting for the next
        autonomous think cycle — the "I clicked Approve, why did nothing
        happen?" gap). The approval is one-shot: ``execute_plan`` tombstones
        it (``gate.claim_approval``) BEFORE the runner fires, so a crash
        between the runner and the ledger cannot leave it live to re-fire on
        the next cycle. The ``finally`` below only tombstones an approval the
        executor never reached (an exception before the claim). The action is
        reconstructed from OUR prompt record, and only runs because
        ``find_valid_approval`` matches the row we just wrote — the gate is
        never bypassed.
        """
        import asyncio

        from community_member.consent import gate

        _ensure_ledger_init()
        # Execute the canonical action (server-side prompt record, with its
        # `extra`); fall back to the client body only to RECORD the approval
        # when the prompt has aged out (then execution is skipped).
        canonical = _prompt_to_action_request(body.prompt_event_sha256)
        req = canonical if canonical is not None else _body_to_action_request(body.request)
        try:
            approval_sha = gate.approve(
                req,
                chapter_id=_chapter_id(),
                prompt_event_sha256=body.prompt_event_sha256,
                actor_agent_id=_config.agent_id if _config else None,
            )
        except Exception as e:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail=f"approve_failed: {e}") from e

        executed: dict
        if _agent is not None and canonical is not None:
            try:
                # Sync executors (timeouts bound them) → run off the event loop.
                executed = await asyncio.to_thread(_agent.run_approved_action, req)
            except Exception as e:
                executed = {"decision": "error", "error": str(e)}
            finally:
                # One-shot: execute_plan claims (tombstones) the approval before
                # running it. If it never got that far — an exception before the
                # claim — tombstone here so the autonomous loop won't re-fire it.
                # execute_plan already observed the habit model, so we do NOT
                # call _observe_decision_safe here (avoids a double count).
                try:
                    if not gate.is_consumed(approval_sha):
                        gate.mark_consumed(
                            approval_sha,
                            chapter_id=_chapter_id(),
                            actor_agent_id=_config.agent_id if _config else None,
                        )
                except Exception:
                    pass
        else:
            # No agent runtime, or the prompt aged out — record + observe the
            # click; the autonomous loop will pick the approval up if/when it
            # re-proposes the action within the TTL (legacy behaviour).
            _observe_decision_safe(req, "approved")
            executed = {"skipped": "no_agent" if _agent is None else "prompt_expired"}

        return {"approval_event_sha256": approval_sha, "executed": executed}

    @app.post("/api/local/consent/explain")
    async def consent_explain(request: Request):
        """Use the configured LLM to translate a raw consent prompt
        into 2-sentence plain-English summary.

        The agent already has an OpenAI/xAI/Anthropic key wired
        (used by think_v2 for planning). We reuse it here to
        explain pending actions to the human:

          - What the action will do, in human terms
          - Why the agent thinks it's relevant
          - Any risk worth flagging (egress, file write, etc.)

        Body shape: ``{capability, scope, context, source_ref?,
        rationale?, extra?}`` — the ConsentInbox forwards the raw
        prompt fields. Returns ``{summary, risk_level}``.

        Failure modes: missing API key → clear error text the UI
        can show inline. LLM error → fall back to a deterministic
        rule-based summary (see ``_fallback_summary``) so the
        inbox is never blank.
        """
        try:
            body = await request.json()
        except Exception:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="invalid_json") from None

        capability = str(body.get("capability") or "")
        scope = str(body.get("scope") or "")
        rationale = str(body.get("rationale") or "")
        source_ref = body.get("source_ref")
        extra = body.get("extra") or {}

        # Try the LLM first; fall back to deterministic summary.
        summary, risk = _explain_with_llm(
            capability=capability,
            scope=scope,
            rationale=rationale,
            source_ref=source_ref,
            extra=extra,
        ) or _fallback_summary(capability, scope, rationale)
        return {"summary": summary, "risk_level": risk}

    @app.post("/api/local/consent/deny")
    async def consent_deny(body: ConsentDenyRequest):
        from community_member.consent import gate

        _ensure_ledger_init()
        req = _body_to_action_request(body.request)
        # Use gate.deny so the consent.denied row stamps the original
        # prompt_event_sha256 in detail. _is_resolved looks for that
        # field; without it the prompt never disappears from the inbox
        # even though the user clicked Deny.
        denied_sha = gate.deny(
            req,
            chapter_id=_chapter_id(),
            prompt_event_sha256=body.prompt_event_sha256,
            actor_agent_id=_config.agent_id if _config else None,
        )
        _observe_decision_safe(req, "denied")
        return {"denied_event_sha256": denied_sha}

    @app.get("/api/local/consent/suppressed")
    async def consent_suppressed():
        """Actions the user denied that are still being SUPPRESSED — the
        consent.denied rows within DENIAL_COOLDOWN that haven't been cleared.

        Deduped to one row per action (newest denial, which governs the
        expiry). Backs the suppressed-actions view: see what the agent has been
        told not to do, when each lifts, and "Allow again" to lift early.
        """
        from datetime import UTC, datetime

        from community_member.consent import gate
        from community_member.consent import ledger as _ledger

        _ensure_ledger_init()
        now = datetime.now(UTC)
        cleared = gate._cleared_denial_shas()
        seen: set[tuple] = set()
        out: list[dict] = []
        for d in _ledger.list_events(action="consent.denied", limit=200):
            if d.get("chapter_id") != _chapter_id():
                continue
            sha = d.get("event_sha256")
            if sha in cleared:
                continue
            det = d.get("detail") or {}
            key = (det.get("capability"), det.get("scope"), det.get("context"), det.get("provenance"))
            if key in seen:
                continue  # newest-first → keep only the most recent per action
            try:
                occurred = datetime.fromisoformat(d["occurred_at"])
            except (KeyError, ValueError):
                continue
            if now - occurred > gate.DENIAL_COOLDOWN:
                continue
            seen.add(key)
            out.append(
                {
                    "denial_event_sha256": sha,
                    "capability": det.get("capability", ""),
                    "scope": det.get("scope", ""),
                    "context": det.get("context", ""),
                    "provenance": det.get("provenance", ""),
                    "source_ref": det.get("source_ref"),
                    "rationale": det.get("rationale", ""),
                    "denied_at": d.get("occurred_at"),
                    "expires_at": (occurred + gate.DENIAL_COOLDOWN).isoformat(),
                }
            )
        return {"suppressed": out}

    @app.post("/api/local/consent/suppressed/clear")
    async def consent_suppressed_clear(request: Request):
        """Lift a suppression early ('Allow again') so the agent may re-propose
        the action. Clears the named denial + any other active denial of the
        same action; returns how many were cleared."""
        from fastapi import HTTPException

        from community_member.consent import gate

        _ensure_ledger_init()
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_json") from None
        sha = str((body or {}).get("denial_event_sha256") or "")
        if not sha:
            raise HTTPException(status_code=400, detail="denial_event_sha256 required")
        cleared = gate.clear_denial(
            sha,
            chapter_id=_chapter_id(),
            actor_agent_id=_config.agent_id if _config else None,
        )
        return {"cleared": cleared}

    @app.get("/api/local/graduations")
    async def graduations_list():
        """All graduation rows for this device."""
        import sqlite3

        from community_member.config import CONFIG_DIR

        db = CONFIG_DIR / "graduations.db"
        if not db.exists() or not _config or not _config.agent_id:
            return {"graduations": []}
        with sqlite3.connect(str(db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT capability, scope, context_sha256, state, "
                "graduated_at, revoked_at FROM graduations "
                "WHERE device_did = ? ORDER BY graduated_at DESC",
                (_config.agent_id,),
            ).fetchall()
        return {"graduations": [dict(r) for r in rows]}

    @app.post("/api/local/graduations/revoke")
    async def graduations_revoke(body: GraduationRevokeRequest):
        from community_member.config import CONFIG_DIR
        from community_member.graduation import GraduationStore

        if not _config or not _config.agent_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="no_agent_configured")
        store = GraduationStore(CONFIG_DIR / "graduations.db", device_did=_config.agent_id)
        revoked_at = store.revoke(
            capability=body.capability,
            scope=body.scope,
            context_sha256=body.context_sha256,
        )
        return {"revoked_at": revoked_at}

    @app.post("/api/local/panic")
    async def panic_endpoint():
        from community_member import panic

        _ensure_ledger_init()
        if not _config or not _config.agent_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="no_agent_configured")
        report = panic.execute_panic(
            chapter_id=_chapter_id(),
            agent_id=_config.agent_id,
            config=_config,
        )
        return {
            "revoked_graduations": report.revoked_graduations,
            "new_public_key": report.new_public_key,
            "key_rotated": report.key_rotated,
            "audit_event_sha256": report.audit_event_sha256,
        }

    @app.post("/api/local/duress/verify")
    async def duress_verify(body: DuressVerifyRequest):
        """Wire-indistinguishable response for normal vs duress paths.

        Both a correct normal passphrase and a correct duress passphrase
        return exactly `{"result": "unlocked"}`. Only an invalid
        passphrase returns `{"result": "invalid"}`. If an observer can
        tell normal from duress by the response, the whole S8 defense
        collapses.
        """
        from community_member import duress
        from community_member.config import CONFIG_DIR

        _ensure_ledger_init()
        store_path = CONFIG_DIR / "duress.json"
        result = duress.verify_and_handle(
            body.passphrase,
            store_path=store_path,
            chapter_id=_chapter_id(),
            actor_agent_id=_config.agent_id if _config else None,
            on_duress_wipe_habits=CONFIG_DIR / "habits.db",
            device_did=_config.agent_id if _config else None,
            graduation_db_path=CONFIG_DIR / "graduations.db",
        )
        if result == "invalid":
            return {"result": "invalid"}
        # Both "normal" and "duress" collapse to "unlocked" — the
        # observer must not be able to tell them apart.
        return {"result": "unlocked"}

    @app.get("/api/local/duress/status")
    async def duress_status():
        """Whether a passphrase pair has been registered yet.

        Used by the first-run wizard: if `{registered: false}`, the UI
        walks the user through passphrase setup; otherwise it renders
        the unlock dialog.
        """
        from community_member.config import CONFIG_DIR

        store_path = CONFIG_DIR / "duress.json"
        return {"registered": store_path.exists()}

    @app.post("/api/local/duress/register")
    async def duress_register(body: DuressRegisterRequest):
        """Register the normal + duress passphrases.

        First-run setup only. If a store already exists at
        `~/.community-member/duress.json`, this endpoint refuses with
        409 Conflict — re-registering would silently invalidate the
        user's previously-known passphrases and is almost always a
        mistake.

        The backend library enforces that normal ≠ duress and both
        non-empty.
        """
        from fastapi import HTTPException

        from community_member import duress
        from community_member.config import CONFIG_DIR

        store_path = CONFIG_DIR / "duress.json"
        if store_path.exists():
            raise HTTPException(
                status_code=409,
                detail="already_registered",
            )
        try:
            duress.register_passphrases(
                body.normal,
                body.duress,
                path=store_path,
            )
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {"registered": True}

    # ─── sm-bridge: NANDA-compatible registry routers ─────────
    # Mount /sm-bridge/{index,resolve,deltas,tools} so NANDA/NEST can read
    # this agent's canonical AgentFacts. MUST be mounted before the SPA
    # catch-all below or the /{full_path} route would shadow it.
    try:
        import os as _os

        from . import DASHBOARD_PORT as _DEFAULT_PORT
        from .sm_bridge_adapter import mount_sm_bridge_routers

        _bridge_base = (
            _os.environ.get("AGENT_PUBLIC_URL", "").strip().rstrip("/") or f"http://localhost:{_DEFAULT_PORT}"
        )
        mount_sm_bridge_routers(app, config=_config, public_url=_bridge_base)
    except Exception as _e:
        print(f"[sm_bridge] mount skipped: {_e}")

    # Headless: the agent serves its signed local API (/api/local/*) + the NANDA
    # discovery surfaces. There is no bundled web SPA — render with a client of
    # your choice (see docs/ROADMAP.md for the reference renderer).

    return app


def log_thought(text: str):
    """Add a thought to the log (called by the agent)."""
    _thought_log.append(
        {
            "text": text[:200],
            "timestamp": time.time(),
        }
    )


def _mask_key(key: str) -> str:
    """Mask an API key for display."""
    if not key or len(key) < 8:
        return "***"
    return key[:4] + "****" + key[-4:]
