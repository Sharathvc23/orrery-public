"""Generic org agent — config-driven, federation-aware, virtual sub-agents.

Naming: this module implements the Chapter Protocol for an org; the routes,
headers, tables and ids here keep the protocol noun on purpose — see
docs/ARCHITECTURE.md § Two nouns for the mapping and which surfaces are frozen.

Each chapter agent:
1. Registers itself + all member agents on NEST on startup
2. Discovers other chapter agents from NEST
3. Hosts virtual sub-agents — responds AS each member with their personality
4. Persists conversations in Postgres
5. Logs all activity to a public activity feed
6. Uses Grok to drive introductions across the federation
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import threading
import time as time_mod
import uuid
from collections import OrderedDict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from hmac import compare_digest
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field

import activity_tracker
import agent_conversations
import agent_export
import agent_scheduler
import agent_telemetry
import auth_verify
import broadcast as broadcast_mod
import chapter_helpers
import consent_gate
import digest as digest_mod
import env_flags
import event_bus
import federation_discovery
import federation_feed
import federation_intelligence
import intents
import invites as invites_mod
import member_listing
import member_runtime
import metrics
import nanda_registry
import org_home
import outcome_tracker
import projections
import rate_limit_persistence
import registry_attestation
import registry_divergence
import registry_policy
import secret_sealing
import sovereign_identity
import sovereign_runtime
import subscriptions as subscriptions_svc
import surfaces
import think_cycle
import thought_redaction
import trust_gate


# ============================================================
# SECURITY: Input sanitization + rate limiting
# ============================================================
def sanitize_text(text: str, max_length: int = 2000) -> str:
    """Strip dangerous patterns from user input."""
    if not text:
        return ""
    # Truncate
    text = text[:max_length]
    # Remove null bytes
    text = text.replace("\x00", "")
    # Strip common prompt injection markers
    for marker in ["<|system|>", "<|user|>", "<|assistant|>", "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>"]:
        text = text.replace(marker, "")
    return text.strip()


def sanitize_agent_id(agent_id: str) -> str:
    """Enforce safe agent ID format."""
    import re

    cleaned = re.sub(r"[^a-zA-Z0-9\-_@.]", "", agent_id)
    return cleaned[:64]


_rate_limit_store: OrderedDict[str, list[float]] = OrderedDict()
_rate_limit_lock = threading.Lock()
# Set at boot from the org data dir. Until then the limiter still works — it
# just keys on an unsalted-but-still-hashed id for the few requests that can
# arrive before lifespan runs, which cannot match a restored bucket and so fails
# toward an empty bucket rather than a shared one.
_rate_limit_salt: bytes = b"orrery-rate-limit-unsalted-boot"
#: Where _rate_limit_salt came from — one of rate_limit_persistence.SOURCE_*.
#: Decides whether a snapshot written by the previous process can match, which
#: is a different fact from whether the table is writable; /health reports both.
_rate_limit_salt_source: str = rate_limit_persistence.SOURCE_UNRESOLVED
#: Whether this process may persist limiter state. False when there is no
#: database, or the boot ensure could not create the table.
_rate_limit_persist_ok = False
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30  # requests per window — write methods (POST/PATCH/DELETE)
RATE_LIMIT_GET_MAX = 60  # requests per window — enumerable GET endpoints
RATE_LIMIT_KEY_CAP = 10_000  # tracked client buckets per process

# behind an edge/reverse proxy (the documented Railway deploy), the socket
# peer is the PROXY, so keying the per-IP limiter on request.client.host puts every
# user in ONE bucket — a single attacker 429s everyone and abusers aren't isolated.
# TRUSTED_PROXY_HOPS = how many trusted proxies sit between the client and this app
# (Railway/most single edge = 1). When > 0 the real client IP is read from
# X-Forwarded-For at that hop from the right (the entry the OUTERMOST TRUSTED proxy
# appended — spoofed left-prepended entries are ignored). Default 0 = direct-connect,
# trust nothing, use the socket peer (unchanged behavior; XFF is NOT trusted).
#
# ⚠️ RESOLVED ONCE, HERE, AND REPORTED ON /health AS `trusted_proxy_hops`. Changing
# the variable does not change a running process, and for as long as this setting
# has existed nothing reported it — so every live deployment ran at 0 behind an
# edge proxy, keying every member into the proxy's single bucket, and the only way
# to find out was to read the hosting platform's variables per deployment. The
# health field reports THIS object, never a fresh read of os.environ, so that an
# environment which has moved on from the process is visible rather than
# papered over.
try:
    TRUSTED_PROXY_HOPS = max(0, int(os.environ.get("TRUSTED_PROXY_HOPS", "0") or "0"))
except ValueError:
    TRUSTED_PROXY_HOPS = 0
# Passed to uvicorn so it only honors forwarded headers from a trusted peer.
FORWARDED_ALLOW_IPS = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1").strip() or "127.0.0.1"


def client_ip_for_rate_limit(request: Request) -> str:
    """The IP the per-IP rate limiter keys on.

    Direct-connect (TRUSTED_PROXY_HOPS=0): the socket peer. Behind N trusted proxies:
    the X-Forwarded-For entry N-from-the-right — the address the outermost trusted
    proxy observed. A client cannot lower another client's bucket or spoof its own by
    prepending XFF entries: only the rightmost `hops` entries (written by trusted
    proxies) are consulted, and a chain shorter than `hops` falls back to the peer."""
    if TRUSTED_PROXY_HOPS > 0:
        xff = request.headers.get("x-forwarded-for", "")
        chain = [ip.strip() for ip in xff.split(",") if ip.strip()]
        if len(chain) >= TRUSTED_PROXY_HOPS:
            return chain[-TRUSTED_PROXY_HOPS]
    return request.client.host if request.client else "unknown"


# Path-specific ceilings for expensive write operations. The
# generic 30/min POST ceiling is fine for normal writes, but a few
# endpoints do heavy work (5000-row event_log scans + LLM summary,
# in the digest case) and a runaway script could easily melt the
# LLM bill or pin a DB connection.  Keyed by exact path; matched
# BEFORE the generic ceiling.
EXPENSIVE_WRITE_LIMITS: dict[str, int] = {
    "/api/digest/build": 5,  # scans 7 days of event_log + LLM-summarises
    # M10. /api/surfaces/compose is UNAUTHENTICATED (auth_verify puts it in the
    # open POST set) and calls an LLM on every request to generate a surface from
    # free-text intent. It was not in this table, so it fell back to the generic
    # 30/min write ceiling — six times the budget of /api/digest/build, which is
    # on this table for exactly the same reason and does strictly more work per
    # call. An anonymous caller had the larger allowance on the cheaper-to-abuse
    # endpoint.
    #
    # The per-cycle LLM budget (llm_runtime.CYCLE_BUDGET) does NOT cover this:
    # it bounds the autonomous think loop and is reset by the cycle owner, while
    # this is request-driven and never enters that path.
    #
    # ⚠️ This is a RATE limit, not a SPEND cap. It slows one source; it does not
    # bound total cost, because the window is per-source and per-process. A
    # distributed caller still costs money. Saying so here rather than letting
    # the entry read as a budget.
    "/api/surfaces/compose": 5,
    # Brokered co-sign relay makes an OUTBOUND A2A call to a peer member per
    # request (cosign-companion.md §4). SSRF is already closed (relays only to
    # registered members), but a tighter ceiling stops one member from using the
    # server to hammer a peer. 20/min is ample for legitimate interaction
    # recording; bump if the openclaw brokered path (step 4) needs more.
    "/api/cosign/broker": 20,
    "/api/cosign/broker/": 20,
}

# GET path prefixes that get the per-IP rate limit even though they
# don't require auth. Pre-launch audit found these returning 200 in
# 50/50 sequential requests with no throttle — trivial enumeration
# vector for a hostile scraper. Keep the limit generous (60 req/min
# per IP per path family) so a client's polling never hits it but
# a curl-loop dies quickly.
RATE_LIMITED_GET_PREFIXES = (
    "/api/members",
    "/api/thoughts",
    "/api/agents/",  # covers both /profile and /export
    "/api/sessions",
    "/api/runtimes",
    "/api/outcomes",
    "/api/knowledge/",
    # ARP receipts — enumerable per-principal; without a limit a hostile
    # client could probe via repeated signed-fetch attempts. Auth-gated
    # so the bar is non-trivial, but still worth the throttle.
    "/api/receipts",
    # Intent enumeration — open-by-design (community-shareable) but a
    # determined scraper could pull the full intent list at default
    # ceiling. Throttle to the GET-prefix rate. Residual item closed
    # from docs/security/OPEN_SOURCE_READINESS.md.
    "/api/intents",
)


def _expensive_write_ceiling(path: str) -> int | None:
    """Return the per-IP limit for ``path`` if it's in the expensive set,
    else None (use the default RATE_LIMIT_MAX). Exact-match only — we
    don't want prefix matching to accidentally throttle a sibling path."""
    return EXPENSIVE_WRITE_LIMITS.get(path)


def check_rate_limit(client_ip: str, *, max_requests: int = RATE_LIMIT_MAX) -> bool:
    """Bounded in-memory rate limiter. Returns True if allowed.

    ``max_requests`` lets the GET path use a higher ceiling (60/min)
    than the write path (30/min) since GETs are inherently lower
    impact. Both share the same per-IP bucket so a flood across both
    methods is throttled by whichever ceiling fires first. The store is
    ordered by last admitted request. At capacity, only expired buckets
    are reclaimed; an unseen key is refused rather than evicting a live
    bucket and resetting its quota.
    """
    with _rate_limit_lock:
        now = time_mod.monotonic()
        window_start = now - RATE_LIMIT_WINDOW
        requests = _rate_limit_store.get(client_ip)

        if requests is not None:
            requests = [timestamp for timestamp in requests if timestamp > window_start]
            if len(requests) >= max_requests:
                # Updating an existing OrderedDict value does not change order.
                # A denied request is not admitted activity and must not make an
                # otherwise-old bucket harder to reclaim.
                _rate_limit_store[client_ip] = requests
                return False
            requests.append(now)
            _rate_limit_store[client_ip] = requests
            _rate_limit_store.move_to_end(client_ip)
            return True

        while len(_rate_limit_store) >= RATE_LIMIT_KEY_CAP:
            _oldest_key, oldest_requests = next(iter(_rate_limit_store.items()))
            # Admission order makes the oldest bucket decisive: if its newest
            # admitted request is live, every later bucket is live as well.
            if oldest_requests and oldest_requests[-1] > window_start:
                metrics.record_rate_limit_capacity_rejection()
                return False
            _rate_limit_store.popitem(last=False)

        requests = [now]
        _rate_limit_store[client_ip] = requests
        return True


def _rate_limit_bucket_key(client_key: str) -> str:
    """The id a client's bucket is stored under. See rate_limit_persistence."""
    return rate_limit_persistence.bucket_key(_rate_limit_salt, client_key)


async def _persist_rate_limit_buckets() -> bool:
    """Snapshot the live buckets. Best-effort by contract — never raises."""
    if not _rate_limit_persist_ok:
        return False
    with _rate_limit_lock:
        snapshot = rate_limit_persistence.snapshot_buckets(
            _rate_limit_store,
            now_monotonic=time_mod.monotonic(),
            now_wall=time_mod.time(),
            window=RATE_LIMIT_WINDOW,
        )
    try:
        return await rate_limit_persistence.save(pg_request, AGENT_ID, snapshot)
    except Exception as exc:  # noqa: BLE001 — persistence failing must never affect limiting
        print(f"[rate-limit] snapshot failed ({type(exc).__name__}: {exc})")
        return False


async def _rate_limit_persist_loop() -> None:
    """Periodic snapshot. Cancelled at shutdown, which then takes a final one."""
    while True:
        await asyncio.sleep(rate_limit_persistence.PERSIST_INTERVAL_S)
        await _persist_rate_limit_buckets()


async def _restore_rate_limit_buckets() -> int:
    """Rehydrate buckets saved by the previous process. Returns how many landed.

    A restart used to hand every client a full quota back. It now hands back at
    most one flush interval of it. Failure degrades to today's behaviour —
    empty buckets — and never blocks boot.
    """
    if not _rate_limit_persist_ok:
        return 0
    if not rate_limit_persistence.salt_durable(_rate_limit_salt_source):
        # This process minted its salt, so nothing in the table was hashed
        # under it: every restored key would be an orphan that no client can
        # ever look up. Restoring them anyway is how the deployed mesh reported
        # buckets "carried across the restart" while carrying nothing.
        print(
            f"[rate-limit] restore skipped: salt source is {_rate_limit_salt_source!r}, so the previous snapshot "
            "was written under a different salt and cannot match"
        )
        return 0
    try:
        persisted = await rate_limit_persistence.load(pg_request, AGENT_ID)
    except Exception as exc:  # noqa: BLE001 — boot must not fail on a cache row
        print(f"[rate-limit] restore skipped ({type(exc).__name__}: {exc})")
        return 0
    if not persisted:
        return 0
    restored = rate_limit_persistence.restore_buckets(
        persisted,
        now_monotonic=time_mod.monotonic(),
        now_wall=time_mod.time(),
        window=RATE_LIMIT_WINDOW,
        key_cap=RATE_LIMIT_KEY_CAP,
    )
    with _rate_limit_lock:
        _rate_limit_store.clear()
        _rate_limit_store.update(restored)
    return len(restored)


def _is_rate_limited_get_path(path: str) -> bool:
    """True iff this GET path is enumerable and should be throttled."""
    return any(path.startswith(p) for p in RATE_LIMITED_GET_PREFIXES)


load_dotenv()

# ============================================================
# A2UI — imported from a2ui_helpers.py
# Backward-compatible aliases so all existing code keeps working.
# ============================================================
import a2ui_helpers
from a2ui_helpers import (
    alert as _alert,
)
from a2ui_helpers import (
    avatar as _avatar,
)
from a2ui_helpers import (
    badge as _badge,
)
from a2ui_helpers import build_chapter_info as _build_chapter_info_base
from a2ui_helpers import build_federation_cards as _build_federation_cards_base
from a2ui_helpers import (
    build_member_cards,
)
from a2ui_helpers import build_thought_card as _build_thought_card_base
from a2ui_helpers import (
    card as _card,
)
from a2ui_helpers import (
    column as _column,
)
from a2ui_helpers import (
    divider as _divider,
)
from a2ui_helpers import (
    metric as _metric,
)
from a2ui_helpers import (
    progress as _progress,
)
from a2ui_helpers import (
    row as _row,
)
from a2ui_helpers import (
    stat as _stat,
)
from a2ui_helpers import (
    surface as _surface,
)
from a2ui_helpers import (
    text as _text_fn,
)
from a2ui_helpers import (
    toast as _toast,
)


# Wrap _text to keep the same call signature
def _text(id: str, text: str, usage_hint: str = "body") -> dict:
    return _text_fn(id, text, usage_hint)


# Wrappers that pass globals to the extracted pure functions
def build_chapter_info_a2ui() -> dict:
    return _build_chapter_info_base(
        AGENT_NAME, AGENT_DESCRIPTION, AGENT_FOCUS, AGENT_REGION, len(members), len(federation)
    )


def build_federation_a2ui() -> dict | None:
    return _build_federation_cards_base(federation)


def build_thought_card(thought_type: str, title: str, body_text: str, targets: list[dict] | None = None) -> dict:
    return _build_thought_card_base(thought_type, title, body_text, targets, AGENT_NAME)


# ============================================================
# CONFIG
# ============================================================
AGENT_ID = os.environ["AGENT_ID"]
AGENT_NAME = os.environ["AGENT_NAME"]
AGENT_DESCRIPTION = os.environ.get("AGENT_DESCRIPTION", "A self-hosted Orrery org agent")
AGENT_FOCUS = os.environ.get("AGENT_FOCUS", "General AI")
AGENT_REGION = os.environ.get("AGENT_REGION", "")


def _derive_chapter_slug(agent_id: str) -> str:
    """Derive a URL-safe slug from agent_id when CHAPTER_SLUG is unset.

    Strips the TEST- prefix and conventional `-chapter` / `-nanda-chapter`
    suffixes so transient agent_id naming does not leak into the URL.
    Examples:
        TEST-boston-chapter      -> boston
        TEST-london-chapter      -> london
        bayarea-nanda-chapter    -> bayarea
        bayarea-agent            -> bayarea
        my-custom-id             -> my-custom-id  (no recognised affixes)

    Once CHAPTER_SLUG is set explicitly via env, this fallback is unused.
    Production rollout sets CHAPTER_SLUG on every Railway service so the
    URL stays stable across any future agent_id rename.
    """
    s = agent_id.lower()
    if s.startswith("test-"):
        s = s[len("test-") :]
    for suffix in ("-nanda-chapter", "-chapter", "-agent"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    return s or agent_id


# Operator config: ORG_* is canonical; CHAPTER_* stays as a back-compat
# fallback (mirrors that change). The Python names are internal and unchanged.
CHAPTER_SLUG = (
    os.environ.get("ORG_SLUG", "").strip()
    or os.environ.get("CHAPTER_SLUG", "").strip()
    or _derive_chapter_slug(AGENT_ID)
)
CHAPTER_DISPLAY_NAME = (
    os.environ.get("ORG_DISPLAY_NAME", "").strip() or os.environ.get("CHAPTER_DISPLAY_NAME", "").strip() or AGENT_NAME
)
AGENT_LEADERS = json.loads(os.environ.get("AGENT_LEADERS", "[]"))
PORT = int(os.environ.get("PORT", "7000"))
# an explicitly-EMPTY REGISTRY_URL means "no registry", not "the live one".
# Resolved in registry_policy so every reader agrees — the heartbeat used to
# interpolate this constant directly and ignore the question entirely.
REGISTRY_URL = registry_policy.registry_url()
# Federation peer auto-discovery is OPT-IN. A fresh org stands alone — it does not
# phone the public registry and adopt its agents as "peers" on first boot. Set
# FEDERATION_AUTODISCOVER=true to auto-discover + sync peers from REGISTRY_URL.
_FEDERATION_AUTODISCOVER = env_flags.security_flag("FEDERATION_AUTODISCOVER", default=False)
# Whether a database is configured. Agent-native data access goes through
# pg_store (DATABASE_URL); when unset (e.g. unit tests that mock pg_request)
# the server runs in a no-database mode (ARP uses a local SQLite issuer log).
_HAS_DATABASE = bool(os.environ.get("DATABASE_URL"))

# Member-persist retry. The persist is fire-and-forget, so a transient
# failure — a PostgREST schema-cache warmup race on a fresh boot, a 5xx, a brief
# network blip — would silently drop the row and leave the member directory
# diverged from the in-memory bridge. Retry a few times with linear backoff; on
# final failure bump a metric so the divergence is observable.
_PERSIST_MAX_ATTEMPTS = 4
_PERSIST_RETRY_DELAY_S = 0.5

# LLM configuration — provider-agnostic (default Claude, bring-your-own-key).
# See llm_config: resolves provider/base_url/key/model from LLM_PROVIDER /
# LLM_MODEL / LLM_API_KEY (auto-detecting from whichever provider key is set,
# preferring Anthropic). A missing key no longer crashes boot.
import llm_config
import llm_runtime  # noqa: E402

DEFAULT_LLM_MODEL = llm_config.DEFAULT_MODEL
LLM_API_KEY = llm_config.API_KEY
LLM_API_BASE_URL = llm_config.BASE_URL

# Timeouts (seconds)
FEDERATION_QUERY_TIMEOUT = float(os.environ.get("FEDERATION_QUERY_TIMEOUT", "15"))

# Think cycle interval (seconds), parsed by the scheduler that owns the cadence.
#
# ⚠️ NOT ``int(os.environ.get(...))``. That raised ValueError AT IMPORT on any
# non-integer, so a typo in one environment variable produced a container that
# would not start and a traceback naming neither the variable nor the value.
# ``interval_seconds`` clamps, logs, and falls back — and it is the same parser
# the member path uses, so the two cannot drift into two disciplines.
THINK_CYCLE_INTERVAL = agent_scheduler.interval_seconds()

# Limits
MAX_CONVERSATION_MESSAGES = 100
MAX_MEMBERS = int(os.environ.get("MAX_MEMBERS", "40"))

# None when no client may be built. Under LLM_STRICT a chapter with no usable
# credential gets no client at all — which is the point of gating at
# construction: twenty-four sites use this object and four ask whether they may,
# so a client that exists is a client that gets called. Boot is NOT failed: a
# chapter serves its portal, its surfaces and its federation without a model, and
# refusing to start would turn a missing key into an outage.
try:
    llm = llm_config.build_client()
except llm_runtime.LLMNotConfigured as _exc:
    print(f"[llm] no client built: {_exc}")
    llm = None


# ============================================================
# POSTGRES DATA-ACCESS HELPER
# ============================================================
async def pg_request(
    method: str,
    table: str,
    params: dict | None = None,
    body: dict | list | None = None,
    on_conflict: list[str] | None = None,
    merge_jsonb: list[str] | None = None,
) -> dict | list | None:
    """Data access via direct Postgres (``pg_store``) — requires ``DATABASE_URL``.

    A thin wrapper over ``pg_store.pg_request`` retained as the single call site
    the server code uses (the PostgREST/Supabase transport is gone). Returns
    parsed rows (``list[dict] | dict``) or ``None`` on failure / when no database
    is configured (e.g. unit tests that mock this function).

    ``on_conflict`` names the columns a POST upserts on when the row identifies
    an existing record by a NATURAL key instead of the surrogate primary key —
    see ``pg_store.pg_request`` for why it is explicit rather than inferred.
    ``merge_jsonb`` names jsonb columns to merge rather than replace, for
    columns more than one writer contributes keys to."""
    import pg_store

    return await pg_store.pg_request(method, table, params, body, on_conflict, merge_jsonb)


# Helpers -> chapter_helpers.py, Think cycle -> think_cycle.py
from chapter_helpers import (
    ConversationStore,
    get_intelligence_context,
    load_knowledge,
    log_activity,
    log_agent_thought,
    recent_memories,
    remember,
)

conv_store = ConversationStore()

# ============================================================
# STATE
# ============================================================
# key on a member record marking that its host39 card has actually been
# published. Written only by POST /admin/api/host39/record-publication (which the
# publisher calls after a successful POST /cards) — never inferred from the org
# having ORG_HOST39_CARD_BASE configured, which is what made the catalog
# advertise 18 dead URLs.
HOST39_PUBLISHED_AT = "host39_card_published_at"

members: dict[str, dict] = {}
federation: dict[str, dict] = {}
_federation_failures: dict[str, int] = {}
PUBLIC_URL = ""
AGENT_DB_UUID = ""  # Resolved on startup


# ══════════════════════════════════════════════════════════════════════
# KEY PROVENANCE — how a member's key came to be theirs
#
# A public key carries no evidence of how it was established, and the four ways
# it can happen here are NOT equally strong. Recording which one applies is the
# difference between "this member's key" and "the key somebody claimed for this
# member and nobody has contradicted yet".
#
# Only a ROTATION is attested: `member_key_rotations` holds a signature from the
# key being superseded, which is why the loader walks that table and why
# nothing below ever sets ``attested``. The rest are first-claim-wins, including
# ordinary registration — a fact this vocabulary makes visible rather than new.
# ══════════════════════════════════════════════════════════════════════
KEY_PROVENANCE = "key_provenance"

#: Supplied at the member's FIRST registration. The pre-existing trust model:
#: nothing proved the caller was that member, only that they arrived first.
KEY_SOURCE_REGISTERED = "registered"
#: Adopted for an EXISTING member who had no key on file, from a re-registration
#: body. A PIN, not a proof — see `_pin_member_key` for the full weakness.
KEY_SOURCE_PINNED_REGISTRATION = "pinned_registration"
#: Same pin, established instead by ``X-Agent-DID-Key`` on a signed request.
#: The claimant proved they hold the private key; nothing proved they are the
#: member. Persisted so the window in which it can be replaced is one claim
#: rather than every restart, forever.
KEY_SOURCE_PINNED_TOFU_HEADER = "pinned_tofu_header"
#: An operator revoked the key. Terminal — the loader refuses to walk a rotation
#: chain past it, or a revocation would be undone by the next restart.
KEY_SOURCE_REVOKED = "revoked"
#: An operator named this key as the successor at revoke time. STRONGER than a
#: pin — a named party is accountable for it, and it forecloses the first-claim
#: race a bare revocation opens — and WEAKER than a rotation, which carries a
#: signature from the key it replaces. The server cannot verify the key
#: originated with the member (any proof-of-possession an operator relays, an
#: operator can also manufacture), so this records an assertion to be reviewed,
#: never a fact that was checked.
KEY_SOURCE_OPERATOR_VOUCHED = "operator_vouched"

#: PRECEDENCE, strongest first. The ordering is the safety property, so it is
#: written once here and asserted in `test_member_key_provenance.py`:
#:
#:   1. ROTATION      — `member_key_rotations`, signed by the superseded key.
#:                      Walked forward from whatever the row holds, so a
#:                      rotation performed FROM a vouched key supersedes the
#:                      vouch, and an operator cannot overwrite an attested key
#:                      by asserting a different one.
#:   2. OPERATOR VOUCH — on file the moment it is written, so `_pin_member_key`
#:                      declines: a first claim cannot displace it.
#:   3. FIRST-CLAIM PIN — only ever fills a vacancy, never replaces.
#:
#: Each level can only be displaced by one at least as strong. Nothing here
#: lets a weaker establishment overwrite a stronger one.


def _key_provenance(source: str) -> dict:
    """The provenance marker written alongside a key in ``agent_facts``."""
    return {
        "source": source,
        # NEVER true for anything written here, and that is the point. A
        # rotation is the only establishment with a signature behind it, and it
        # is recorded in `member_key_rotations` rather than as a marker — the
        # evidence is the chain, not a boolean somebody wrote next to the key.
        "attested": False,
        "at": datetime.now(UTC).isoformat(),
    }


async def _has_recorded_rotation(agent_id: str) -> bool | None:
    """Has this member ever rotated? ``None`` when the answer is unknown.

    Callers must treat ``None`` as "yes". A pin is only ever the RIGHT answer
    for a member with no other way to establish a key; if the rotation table
    cannot be read we do not know that, and declining to pin leaves the member
    exactly where they were rather than pinning over recoverable evidence.
    """
    if pg_request is None:
        return None
    try:
        rows = await pg_request(
            "GET",
            "member_key_rotations",
            params={
                "chapter_id": f"eq.{AGENT_ID}",
                "agent_id": f"eq.{agent_id}",
                "select": "id",
                "limit": "1",
            },
        )
    except Exception as exc:  # noqa: BLE001 — an unreadable table is unknown, not "no"
        print(f"⚠️  rotation history for {agent_id!r} unreadable ({type(exc).__name__}: {exc}) — not pinning")
        return None
    return bool(rows)


async def _pin_member_key(agent_id: str, public_key_b64: str, *, source: str) -> bool:
    """Durably adopt a key for a member who has none — TOFU at member scope.

    ⚠️ THE WEAKNESS, STATED WHERE IT IS IMPLEMENTED. This is pin-on-first-claim:
    for a member with no key on file, WHOEVER CLAIMS FIRST WINS. Nothing here
    proves the claimant is the member. It is the same trust model registration
    itself uses, so it is not a new weakness — but it is a real one, and a
    pinned key must never be read as a verified key. That is what the
    `key_provenance` marker is for.

    What it buys is the difference between "replaceable at will, by anyone, on
    every restart, forever, with no record" — which is what an empty
    ``public_key`` means, since the guard only fires on a non-empty one —
    and "claimable once, durably, with an audit row naming who claimed it and
    when". The hole shrinks from a standing invitation to a single race.

    Narrowed as far as it goes without creating a lockout. It applies ONLY to a
    member who has no key on file AND no rotation history: a member who has
    rotated has attested evidence in ``member_key_rotations`` and must recover
    from there, never from a claim. Every other refusal below leaves the
    member exactly as they were, so no path here can lock anyone out of an
    account they hold.
    """
    did_key = sovereign_identity.try_build_did_key_from_ed25519(public_key_b64) if public_key_b64 else None
    if not did_key:
        # Legacy HMAC material has no did:key form. Refusing to pin it is not a
        # gap: it could not verify an Ed25519 signature anyway, so recording it
        # would arm the guard with a value no rotation could ever match.
        return False
    if pg_request is None:
        return False

    rows = await pg_request(
        "GET", "agents", params={"agent_id": f"eq.{agent_id}", "select": "agent_id,agent_facts", "limit": "1"}
    )
    if not rows:
        # No durable row for this agent. A pin must never CREATE a member —
        # that would turn an unauthenticated claim into a registration.
        return False
    facts = rows[0].get("agent_facts")
    facts = dict(facts) if isinstance(facts, dict) else {}
    provider = dict(facts.get("provider") or {})
    if provider.get("did"):
        # Somebody already established one. A pin never displaces a key on file;
        # replacing one is a rotation and goes through the attested path.
        return False
    if await _has_recorded_rotation(agent_id) is not False:
        return False

    # A pin that follows a revocation is ALLOWED and flagged, not refused.
    # `admin_revoke_key` documents the recovery as "the agent re-registers with a
    # fresh keypair", so refusing here would break the operator's own path back
    # and leave the member permanently unguarded — a refusal with no recovery,
    # which is the thing this whole change exists to avoid. The residual is
    # inherent to that recovery rather than introduced by persisting it: after a
    # revoke the identity goes to whoever claims first, which is why the flag and
    # the audit row matter more here than anywhere else.
    after_revocation = (facts.get(KEY_PROVENANCE) or {}).get("source") == KEY_SOURCE_REVOKED

    provider["did"] = did_key
    facts["provider"] = provider
    facts[KEY_PROVENANCE] = {**_key_provenance(source), "after_revocation": after_revocation}
    updated = await pg_request("PATCH", "agents", params={"agent_id": f"eq.{agent_id}"}, body={"agent_facts": facts})
    if not updated:
        print(f"⚠️  key pin for {agent_id!r} did NOT persist — the member stays unguarded until the next claim")
        return False

    # Loud, and durable in the hash-chained ledger rather than only on stdout:
    # the operator question this must answer months later is "which members hold
    # a key nobody proved, and when was it claimed".
    print(
        f"📌 PINNED key for member {agent_id!r} [source={source}"
        f"{', AFTER REVOCATION' if after_revocation else ''}] — first claim wins, NOT an attested key"
    )
    try:
        import chapter_audit as _cau

        await _cau.record(
            chapter_id=AGENT_ID,
            action="member_key_pinned",
            actor_agent_id=agent_id,
            target_type="member",
            target_id=agent_id,
            outcome="ok",
            detail={
                "source": source,
                "did_key": did_key[:200],
                "attested": False,
                "after_revocation": after_revocation,
            },
        )
    except Exception as exc:  # noqa: BLE001 — the pin landed; the ledger write is telemetry
        print(f"⚠️  member_key_pinned audit row failed for {agent_id!r} (non-fatal): {type(exc).__name__}: {exc}")
    return True


async def _on_tofu_established(agent_id: str, headers: dict, *, method: str, path: str) -> None:
    """A signed request just bootstrapped this agent's key from its header.

    B — ``auth_verify.store_did_key`` files that key in ``_agent_keys``, which is
    in-memory and empty on every boot. Nothing wrote it down, so a member whose
    key was only ever established this way had NO durable key anywhere: the
    loader hydrated ``public_key=""``, the guard is a no-op on an empty key,
    and the identity was re-claimable by an unauthenticated POST after every
    restart, indefinitely. Persisting the key the server already accepted turns
    that standing invitation into a single first-claim race.

    It is a pin, not a proof — the claimant proved possession of a private key,
    not that they are this member — so it is recorded through the same
    `_pin_member_key` path and carries the same provenance marker.
    """
    metrics.record_tofu_bootstrap()
    did_key = headers.get("x-agent-did-key") or headers.get("X-Agent-DID-Key", "")
    # spec/0.2 §3.1 audit invariant — every TOFU bootstrap appends a row to the
    # hash-chained ledger so operators can reconstruct the bootstrap after the
    # fact. Includes the recorded did_key and the originating request signature
    # (truncated for size; the full signature is in the wire log).
    # Fire-and-forget: telemetry failure cannot wedge the request.
    try:
        import chapter_audit as _cau

        signature = headers.get("x-agent-signature") or headers.get("X-Agent-Signature", "")
        await _cau.record(
            chapter_id=AGENT_ID,
            action="tofu_register",
            actor_agent_id=agent_id,
            target_type="agent",
            target_id=agent_id,
            outcome="ok",
            detail={
                "did_key": did_key[:200],
                "signature_b64": signature[:90],  # Ed25519 sig is ~88 chars b64
                "path": path,
                "method": method,
            },
        )
    except Exception as e:  # noqa: BLE001 — telemetry must not raise
        print(f"[Auth] tofu_register audit failed (non-fatal): {e}")

    pubkey = (auth_verify.get_agent_key(agent_id) or {}).get("ed25519_pubkey", "")
    if not pubkey:
        return
    # Same fire-and-forget discipline as the registration persist: the key is
    # already live in memory, so a Postgres hiccup must not fail the request the
    # member is making. `_pin_member_key` declines by itself for an agent with no
    # row, a key already on file, or any rotation history.
    asyncio.create_task(_pin_member_key(agent_id, pubkey, source=KEY_SOURCE_PINNED_TOFU_HEADER))


async def _persist_member_to_db(agent_id: str, member: dict, origin: str, *, key_source: str | None = None) -> None:
    """Upsert a newly-registered member into Postgres ``agents``.

    Called fire-and-forget from ``register_member`` so the portal
    directory + every other surface that queries the table sees the
    member immediately. Without this, /api/members registrations live
    ONLY in the in-memory ``members`` dict until something else writes
    a row (and nothing else does in the registration path).

    Defensive: any failure is logged and swallowed. The bridge-side
    registration already succeeded; a Postgres write hiccup must not
    surface as a registration failure to the caller.

    UPSERT semantics: ``pg_request`` ships
    ``Prefer: resolution=merge-duplicates`` so this POST replaces the
    row when ``agent_id`` already exists. Re-registration is therefore
    idempotent on the Postgres side — origin is checked above and
    rejected if it would change, so the row only ever updates the
    safe fields below.
    """
    try:
        row = {
            "agent_id": agent_id,
            "name": member.get("name", agent_id),
            "description": member.get("description", ""),
            "skills": member.get("skills") or [],
            "origin": origin,
            "status": "active",
            # only these two are self-assignable, and `service` is the
            # less privileged of the two. Anything unrecognised falls back to
            # `member` rather than being rejected — an odd kind must not be a
            # way to fail a join, only a way to not get the service role.
            "chapter_role": "service" if member.get("agent_kind") == "service" else "member",
            "profile_type": "member",
            "config": {
                "parent_chapter": AGENT_ID,
                "voice": member.get("voice", "helpful"),
                "personality": member.get("personality", ""),
                "virtual": bool(member.get("virtual", False)),
                "registered_via": "api",
                # The member's A2A endpoint. Persisted here for the same reason
                # HOST39_PUBLISHED_AT and the listing consent record are: an
                # in-memory-only field is empty on EVERY boot for EVERY member,
                # and two readers degrade silently rather than failing when it
                # is. `cosign_broker.resolve_member_endpoint` returns None, so
                # every brokered co-sign falls back to a valid-but-UNCORROBORATED
                # receipt — indistinguishable from "the counterparty declined".
                # And the `@handle` A2A forward in `agent_logic` falls through to
                # the virtual sub-agent, so a message addressed to a real member
                # agent is answered by this org's LLM impersonating it. Neither
                # errors, neither logs a cause.
                "endpoint": member.get("endpoint", "") or "",
            },
            "nest_registered": False,
            "trust_score": 0,
        }
        # Persist the member's did:key into the agent_facts jsonb so
        # agent_id→did:key resolution survives a restart. The auth key store is
        # in-memory and empty on every boot; without a durable home the mapping is
        # lost on every redeploy, silently emptying reputation/standing surfaces
        # and breaking signed-request verification until re-registration.
        #
        # We use the EXISTING agent_facts column (provider.did) rather than a new
        # column: load_keys_from_members()/reload_member_keys() already read the key
        # back from provider.did, and it needs no schema migration (works on every
        # existing deployment). Only an Ed25519 key is did:key material (44-char
        # base64, '=' padded); legacy HMAC public keys are skipped.
        pubkey = member.get("public_key") or ""
        if len(pubkey) == 44 and pubkey.endswith("="):
            # try_ variant: the length heuristic doesn't prove valid base64, and
            # the strict builder raises on non-Ed25519 input (R4).
            did_key = sovereign_identity.try_build_did_key_from_ed25519(pubkey)
            if did_key:
                row["agent_facts"] = {"provider": {"did": did_key}}
                # Provenance is written ONLY when the caller says which
                # establishment this is — a re-registration passes None and must
                # not restamp the column, or a key that was PINNED would silently
                # be relabelled as registered by the member's next profile
                # update. `agent_facts` merges on conflict for the same reason:
                # this writer rebuilds the column from its own fields, so a
                # replace would delete the marker it did not supply.
                if key_source:
                    row["agent_facts"][KEY_PROVENANCE] = _key_provenance(key_source)
        # pg_request returns None when no DATABASE_URL is configured
        # are unset (local dev — nothing to retry) or on any non-2xx / transient
        # failure (the case worth retrying — e.g. a PostgREST warmup race). Retry
        # with linear backoff so a brief blip doesn't silently drop the row.
        result = None
        for attempt in range(_PERSIST_MAX_ATTEMPTS):
            # Keyed on agent_id, NOT on the surrogate `id` primary key. The row
            # never carries `id`, so the default PK target generated a fresh
            # uuid, never tripped ON CONFLICT, and every re-registration died on
            # the `agents_agent_id_key` unique violation — the write dropped,
            # outboxed, and replayed into the identical conflict on every boot.
            #
            # `config` MERGES rather than replaces, and that is not optional
            # alongside the fix above. Registration rebuilds config from its own
            # fields, so once the upsert actually lands it would delete every key
            # another writer put there — measured: a member's `listing` consent
            # and their `host39_card_published_at` / `host39_card_url`
            # publication record were all destroyed by one ordinary
            # re-registration. Repairing the upsert WITHOUT this would take a
            # defect that was masked (the write never landed) and make it
            # durable, which is strictly worse than leaving it broken.
            #
            # `agent_facts` merges for the same reason and a sharper one: the
            # key-provenance marker is written by `_pin_member_key`, a DIFFERENT
            # writer, and a replace here would erase it on the pinned member's
            # next profile update — leaving a pinned key indistinguishable from
            # a registered one, which is precisely what it must never be.
            result = await pg_request(
                "POST", "agents", body=row, on_conflict=["agent_id"], merge_jsonb=["config", "agent_facts"]
            )
            if result is not None or not _HAS_DATABASE:
                break
            if attempt < _PERSIST_MAX_ATTEMPTS - 1:
                await asyncio.sleep(_PERSIST_RETRY_DELAY_S * (attempt + 1))
        if result is None and _HAS_DATABASE:
            # don't let the member SILENTLY vanish. After retries fail, record
            # the metric AND durably outbox the upsert so it is replayed at boot
            # (rehydrate is Postgres-only). Requires a durable filesystem — mount a
            # volume on ephemeral hosts; see MEMBER_PERSIST_OUTBOX_PATH.
            metrics.record_member_persist_failure()
            _outbox_member_row(row)
            print(
                f"⚠️  Postgres upsert for member {agent_id} failed after "
                f"{_PERSIST_MAX_ATTEMPTS} attempts — OUTBOXED for boot replay"
            )
    except Exception as exc:  # noqa: BLE001 — telemetry must not crash registration
        print(f"⚠️  Failed to persist member {agent_id} to Postgres: {exc}")


# durable member-persist outbox — the last line of defence so a member whose
# Postgres row never landed (after retries) is NOT lost on restart.
_MEMBER_OUTBOX_PATH = Path(os.environ.get("MEMBER_PERSIST_OUTBOX_PATH", "member_persist_outbox.jsonl"))


def _outbox_member_row(row: dict) -> None:
    """Append a failed member upsert to the durable outbox (one JSON line), replayed
    at boot by ``replay_member_persist_outbox``. Best-effort: a write failure here is
    logged loudly but never crashes registration (the in-memory member still serves)."""
    import json as _json

    try:
        with _MEMBER_OUTBOX_PATH.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps({"table": "agents", "row": row}) + "\n")
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️  member persist OUTBOX write failed for {row.get('agent_id')}: {exc}")


async def replay_member_persist_outbox() -> int:
    """At boot, re-attempt every outboxed member upsert. Rows that persist are
    dropped from the outbox; rows that still fail are kept for the next boot. Returns
    the number re-persisted. No-op without a database or an outbox file."""
    import json as _json

    if not _HAS_DATABASE or not _MEMBER_OUTBOX_PATH.exists():
        return 0
    try:
        lines = _MEMBER_OUTBOX_PATH.read_text(encoding="utf-8").splitlines()
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️  member persist outbox read failed: {exc}")
        return 0

    still_failing: list[str] = []
    replayed = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = _json.loads(line)["row"]
        except Exception:  # noqa: BLE001 — a corrupt line is dropped (and logged), not retried forever
            print("⚠️  dropping unparseable member-persist-outbox line")
            continue
        if await pg_request("POST", "agents", body=row) is not None:
            replayed += 1
        else:
            still_failing.append(line)

    try:
        if still_failing:
            _MEMBER_OUTBOX_PATH.write_text("\n".join(still_failing) + "\n", encoding="utf-8")
        else:
            _MEMBER_OUTBOX_PATH.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️  member persist outbox rewrite failed: {exc}")
    if replayed:
        print(f"Re-persisted {replayed} outboxed member(s) from {_MEMBER_OUTBOX_PATH}")
    return replayed


# ============================================================
# MEMBER MANAGEMENT — seed from config, register on NEST
# ============================================================
def load_chapter_config() -> dict | None:
    """Load this org's config from orgs.json (legacy chapters.json still read)."""
    here = Path(__file__).parent
    config_path = here / "orgs.json"
    if not config_path.exists():
        config_path = here / "chapters.json"  # back-compat
    if not config_path.exists():
        return None
    chapters = json.loads(config_path.read_text())
    for ch in chapters:
        if ch["agent_id"] == AGENT_ID:
            return ch
    return None


def seed_members(chapter_config: dict):
    """Seed members from the chapter config into the in-memory registry."""
    for m in chapter_config.get("members", []):
        members[m["agent_id"]] = {
            "name": m["name"],
            "description": m["description"],
            "skills": m.get("skills", []),
            "personality": m.get("personality", ""),
            "voice": m.get("voice", "helpful"),
            "virtual": True,
            "endpoint": "",
            # Members flagged is_demo MUST be gated out of public-registry
            # fanout. The server keeps them locally for client rendering;
            # nanda_registry checks this flag before publishing.
            "is_demo": bool(m.get("is_demo", False)),
            "profile_type": m.get("profile_type") or "member",
        }
    print(f"Seeded {len(members)} members from config")


# DELETED: `persist_member_to_db(agent_id, member)` — a second member-writer that
# had ZERO callers repo-wide. Recorded here rather than only in git history,
# because the reason it is gone is the reason not to bring it back.
#
# It wrote a strict SUBSET of what `_persist_member_to_db` writes, and every
# omission is now load-bearing. Against what `load_persisted_members` hydrates it
# dropped `config.endpoint`, the `origin` column, and `agent_facts` (the member's
# did:key). Wiring it up would therefore have:
#
#   * emptied `endpoint` on the next boot — the co-sign, A2A-forward and
#     AI-catalog degradations the descriptor-listing fix exists to close; and
#   * left `agent_facts` absent, so `public_key` hydrates to "" and the key-change guard
#     key-change guard becomes a NO-OP again — reintroducing the unauthenticated
#     key-replacement path (measured takeover, see the descriptor-listing fix).
#
# It also had no try/except, no retry and no durable outbox, all of which the
# live writer has. There was no axis on which it was the better function.
#
# If you need to persist a member from a new call site, call
# `_persist_member_to_db` or extend it — do NOT restore this from history. A
# second writer that silently disagrees with the live one is the defect, not the
# missing helper.


async def _recorded_rotation_chains() -> dict[str, list[dict]]:
    """agent_id → this chapter's recorded rotations, oldest first.

    ``member_key_rotations`` is the only durable record of a member's key that
    the loader did not read, and it is the STRONGEST one. ``agent_facts`` holds
    whatever key registration was handed; a rotation row exists only because the
    key it supersedes signed an attestation naming this chapter, which the
    server verified before writing (``member_rotation._verify_attestation``).

    Without this, a rotation did not survive a restart. Measured: register with
    K1, rotate to K2, restart — the loader hydrated ``did(K1)`` because rotation
    never writes back to ``agent_facts``, ``reload_member_keys`` restored K1 into
    the auth store, and the member's CURRENT key then failed with
    ``key_mismatch`` while the key they revoked signed successfully. A revocation
    that the next redeploy undoes is not a revocation.

    Best-effort, and deliberately not fail-closed: an unreadable audit table
    leaves every member exactly where they were a moment ago, whereas refusing
    to hydrate any key at all would turn one unreadable table into the guard
    being a no-op for the entire org. Loud, though — a silent fallback here is
    invisible until someone cannot sign.
    """
    if pg_request is None:
        return {}
    try:
        rows = await pg_request(
            "GET",
            "member_key_rotations",
            params={
                "chapter_id": f"eq.{AGENT_ID}",
                "select": "agent_id,old_public_key,new_public_key,attestation",
                "order": "recorded_at.asc",
            },
        )
    except Exception as exc:  # noqa: BLE001 — startup must not crash on the audit table
        print(
            f"⚠️  member_key_rotations unreadable ({type(exc).__name__}: {exc}) — hydrating "
            "registration-time keys only; any member who has ROTATED will hold a REVOKED key"
        )
        return {}
    chains: dict[str, list[dict]] = {}
    for row in rows or []:
        aid = row.get("agent_id") or ""
        if aid:
            chains.setdefault(aid, []).append(row)
    return chains


def _key_after_recorded_rotations(hydrated: str, chain: list[dict], *, revoked: bool = False) -> str:
    """Walk ``chain`` forward from the registration-time key.

    Forward from ``hydrated`` rather than "take the newest row", because the two
    disagree in a case that actually happens: a re-registration with the same
    key rewrites ``agent_facts`` and writes no rotation row, so a member whose
    ``agent_facts`` is AHEAD of the audit table must keep what registration
    recorded. A key that appears nowhere in the chain is therefore left alone.

    The empty case is the exception and takes the chain's tail: there is nothing
    to walk from, and the member demonstrably held a key — one they proved
    possession of by signing the rotation.

    Each link is re-verified (``verify_recorded_link``), so a row inserted
    directly into Postgres moves nothing. ``seen`` bounds the walk: nothing stops
    a member from rotating K1→K2→K1, and a cycle must terminate rather than spin
    at boot.

    ``revoked`` stops the walk entirely, and it has to. An operator revoking a
    key clears ``provider.did`` but cannot delete the rotation history — so
    without this, the very next boot would walk the chain from its tail and hand
    the member back the key an operator had just taken away. The break-glass
    case in ``admin_revoke_key`` is "compromised key suspected", which makes a
    revocation the next restart undoes worse than no revocation at all: the
    operator was told it worked.
    """
    if revoked:
        return ""
    if not chain:
        return hydrated
    import member_rotation

    current = hydrated or (chain[-1].get("new_public_key") or "")
    if not hydrated:
        # Nothing to verify against — the tail is taken on the strength of the
        # server having accepted it, exactly as the endpoint left it in memory.
        return current
    seen = {current}
    while True:
        nxt = ""
        for row in chain:
            if row.get("old_public_key") != current:
                continue
            if not member_rotation.verify_recorded_link(row.get("attestation") or {}, current, chapter_id=AGENT_ID):
                print(
                    f"⚠️  rotation row for {row.get('agent_id')!r} failed re-verification — chain not advanced past it"
                )
                continue
            nxt = row.get("new_public_key") or ""
            break
        if not nxt or nxt in seen:
            return current
        seen.add(nxt)
        current = nxt


async def load_persisted_members():
    """Load previously spawned agents from Postgres on startup."""
    data = await pg_request(
        "GET",
        "agents",
        params={
            "status": "eq.active",
            # profile_type is carried so the community-shaped think-cycle
            # behaviours can tell an individual member from a business one
            # (think_cycle.think_event) instead of assuming everyone is a peer.
            #
            # origin + agent_facts are carried because two GUARDS in the open
            # `POST /api/members` path read them off the in-memory member record
            # and are no-ops when the field is absent — see the hydration below.
            "select": "agent_id,name,description,skills,config,profile_type,origin,agent_facts",
        },
    )
    if not data:
        return
    # One query for the whole org, not one per member: rotations are rare and
    # boot is not the place for N round trips.
    chains = await _recorded_rotation_chains()
    loaded = 0
    for row in data:
        aid = row.get("agent_id", "")
        config = row.get("config") or {}
        # Only load agents that belong to this server
        if config.get("parent_chapter") != AGENT_ID:
            continue
        # Don't overwrite config-seeded members
        if aid in members:
            continue
        members[aid] = {
            "name": row.get("name", aid),
            "description": row.get("description", ""),
            "skills": row.get("skills", []),
            "personality": config.get("personality", ""),
            "voice": config.get("voice", "helpful"),
            "virtual": config.get("virtual", True),
            # Hydrated from the config jsonb rather than hardcoded "". This was
            # `""` for every member on every boot — see the persist side in
            # `_persist_member_to_db` for the two readers that degraded silently
            # because of it.
            "endpoint": config.get("endpoint", "") or "",
            # Carry is_demo through from the Postgres config jsonb so
            # the public-registry gate in nanda_registry can refuse to
            # publish demo/synthetic members.
            "is_demo": bool(config.get("is_demo", False)),
            "profile_type": row.get("profile_type") or config.get("profile_type") or "member",
            # whether this member's host39 card was actually published. The
            # AI Catalog advertises that URL only when this is set; without
            # carrying it through the loader the record would be in-memory only
            # and the catalog would silently drop the member on the next boot.
            HOST39_PUBLISHED_AT: config.get(HOST39_PUBLISHED_AT, ""),
            # Listing consent, carried through for the same reason as the line
            # above and with a sharper consequence: without it a member who opted
            # into the Listing would silently VANISH from it on the next restart.
            # A consenting member absent from the listing is §3's presence half
            # broken, and broken quietly — the exact shape the builder raises to
            # prevent, arriving through the loader instead.
            member_listing.CONSENT_KEY: config.get(member_listing.CONSENT_KEY),
            # Origin, from the top-level column registration already writes. The
            # origin-immutability check in `register_member` reads
            # `existing.get("origin")` and is a NO-OP when the field is absent —
            # so without this line a restarted org lets an unauthenticated
            # re-registration flip a member between sovereign and openclaw, which
            # is the trust-origin downgrade that check exists to refuse.
            "origin": row.get("origin") or "",
        }
        # The member's Ed25519 public key, recovered from the did:key that
        # registration already persists in `agent_facts.provider.did`. No new
        # column and no schema migration: every existing deployment already has
        # this material (see `reload_member_keys`, which restores the same value
        # into the auth store).
        #
        # This is a SECURITY fix, not a convenience one. Two readers key off
        # `members[id]["public_key"]` and BOTH fail open when it is missing:
        #
        #   1. The key-change guard in `register_member`. `/api/members` is
        #      open-pathed, so re-registration is the one place a caller can
        #      change a stored agent's identity. The guard reads
        #      `existing.get("public_key", "")` and only fires when it is
        #      non-empty — so on a restarted org an UNAUTHENTICATED POST
        #      replaced the victim's auth key outright. Measured end to end
        #      against a real two-process restart: 403 before the restart, 200
        #      after, the attacker's key then signed as the victim, and the
        #      legitimate key got `key_mismatch`. The owner could not sign their
        #      way back.
        #   2. `cosign_broker.resolve_member_endpoint`, which matches the
        #      counterparty's did:key against this field BEFORE it ever reads
        #      `endpoint` — so persisting the endpoint alone leaves every
        #      brokered co-sign resolving to None and degrading to an
        #      uncorroborated receipt, indistinguishable from a decline.
        #
        # Only Ed25519 material yields a key here; a legacy HMAC pubkey riding
        # in provider.did returns "" (pubkey_from_provider_did), which leaves
        # the guard exactly as it was for those members rather than seeding it
        # with a value that cannot verify a signature.
        #
        # `agent_facts` is the REGISTRATION-time key, so it is the start of the
        # walk and not the end of it: a member who has rotated since has an
        # attested newer key in `member_key_rotations`, and a member who never
        # had a did:key at all may still have one there. See
        # `_key_after_recorded_rotations`.
        facts = row.get("agent_facts")
        did = ((facts.get("provider") or {}).get("did") or "") if isinstance(facts, dict) else ""
        registered_key = sovereign_identity.pubkey_from_provider_did(did) if did else ""
        provenance = (facts.get(KEY_PROVENANCE) or {}) if isinstance(facts, dict) else {}
        members[aid]["public_key"] = _key_after_recorded_rotations(
            registered_key,
            chains.get(aid, []),
            revoked=provenance.get("source") == KEY_SOURCE_REVOKED,
        )
        loaded += 1
    if loaded:
        print(f"Loaded {loaded} persisted agents from Postgres")


async def reload_member_keys() -> None:
    """Rehydrate agent_id→did:key into the auth store from Postgres.

    ``auth_verify._agent_keys`` is in-memory and empty on every boot. Registration
    persists each member's did:key in ``agent_facts.provider.did`` (see
    ``_persist_member_to_db``), so we restore the full key store from that
    column here — ``store_did_key`` parses the Ed25519 pubkey out of the did:key
    and files it in the correct slot.

    Without this, ``did_key_for_member()`` + signed-request verification fail for
    every previously-registered member after a redeploy — silently emptying
    reputation/standing surfaces and breaking signed actions until the member
    happens to re-register. Best-effort: a Postgres hiccup must not wedge startup.
    """
    if pg_request is None:
        return
    try:
        data = await pg_request(
            "GET",
            "agents",
            params={"agent_facts": "not.is.null", "select": "agent_id,agent_facts"},
        )
    except Exception as exc:  # noqa: BLE001 — startup must not crash on telemetry
        print(f"⚠️  reload_member_keys failed: {exc}")
        return
    restored = 0
    for row in data or []:
        aid = row.get("agent_id") or ""
        facts = row.get("agent_facts")
        did = ((facts.get("provider") or {}).get("did") or "") if isinstance(facts, dict) else ""
        # The member record wins when the two disagree, and they disagree for
        # exactly one reason: the loader walked this member's rotation chain and
        # `agent_facts` did not move. Reading the column unconditionally here is
        # what put the REVOKED key back into the auth store after `load_persisted_members`
        # had already resolved the current one — this function runs later, so it
        # had the last word.
        effective = (members.get(aid) or {}).get("public_key") or ""
        if aid and effective and effective != sovereign_identity.pubkey_from_provider_did(did):
            # replace_ rather than store_: the point is to overwrite, and
            # store_agent_key OR-preserves whatever is already in the slot.
            auth_verify.replace_agent_key(aid, effective)
            restored += 1
        elif aid and did.startswith("did:key:"):
            auth_verify.store_did_key(aid, did)
            restored += 1
    if restored:
        print(f"Restored {restored} member keys from Postgres")


# ============================================================
# VIRTUAL SUB-AGENT — server agent responds AS the member
# ============================================================
def build_member_system_prompt(member_id: str, member: dict) -> str:
    """Build a persona system prompt for a virtual sub-agent."""
    personality = member.get("personality", "")
    if not personality:
        skills_str = ", ".join(member.get("skills", []))
        personality = (
            f"You are {member['name']}, {member.get('description', 'an org agent')}. Your skills include: {skills_str}."
        )

    voice = member.get("voice", "helpful")
    return f"""{personality}

You are a member of {AGENT_NAME} ({AGENT_REGION}), part of an open federation.
Your agent ID is @{member_id}.{_registry_sentence()}
Tone: {voice}.
Keep responses concise (under 150 words). Stay in character."""


def _registry_sentence() -> str:
    """One sentence for the virtual-member prompt naming the registry this org
    actually publishes to — or nothing. It used to hardcode a public NANDA
    registry, so a member of an org that publishes nowhere was told it was
    registered somewhere it had never been sent."""
    if registry_policy.publication_blocked_reason(PUBLIC_URL):
        return ""
    return f" You are registered on {registry_policy.registry_url()}."


async def virtual_member_response(member_id: str, member: dict, message: str, conversation_id: str) -> str:
    """Handle a message AS a virtual sub-agent member."""
    # Load conversation history
    conv_key = f"{member_id}:{conversation_id}"
    history = await conv_store.load(conv_key)

    system_prompt = build_member_system_prompt(member_id, member)

    # Build message list
    chat_messages: list[Any] = [{"role": "system", "content": system_prompt}]
    for msg in history[-20:]:
        chat_messages.append({"role": msg["role"], "content": msg["content"]})
    chat_messages.append({"role": "user", "content": message})

    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=chat_messages,
            max_tokens=512,
        )
        reply = response.choices[0].message.content or "I couldn't generate a response."
    except Exception as e:
        reply = f"LLM error: {e}"

    # Persist conversation
    await conv_store.append(AGENT_DB_UUID, conv_key, message, reply)

    # Log activity (fire and forget)
    asyncio.create_task(log_activity(member_id, member["name"], conversation_id, message, reply))

    return reply


# ============================================================
# CHAPTER SYSTEM PROMPT
# ============================================================
def build_system_prompt() -> str:
    leaders_str = ", ".join(AGENT_LEADERS) if AGENT_LEADERS else "Not yet assigned"
    members_str = (
        json.dumps(
            [
                {"id": mid, "name": m["name"], "description": m["description"], "skills": m.get("skills", [])}
                for mid, m in members.items()
            ],
            indent=2,
        )
        if members
        else "No members registered yet."
    )

    fed_lines = []
    for fid, finfo in federation.items():
        fed_lines.append(f"  - {fid}: {finfo['name']} — {finfo.get('focus', 'General')}")
    fed_str = "\n".join(fed_lines) if fed_lines else "  No other orgs discovered yet."

    return f"""You are {AGENT_NAME}, the AI agent for the {AGENT_REGION} org.
Agent ID: {AGENT_ID}

You operate in an open ecosystem where accountable AI agents discover, communicate, and collaborate across the web — every action signed and offline-verifiable.

YOUR ORG:
- Focus: {AGENT_FOCUS}
- Region: {AGENT_REGION}
- Description: {AGENT_DESCRIPTION}
- Leaders: {leaders_str}

YOUR MEMBER AGENTS (virtual sub-agents you host):
{members_str}

When someone messages @member-id, you route it to that member's virtual personality.

FEDERATION — OTHER ORGS:
{fed_str}

YOUR CAPABILITIES:
1. ANSWER questions about your org and the agent ecosystem
2. ROUTE @member-id MESSAGES to virtual sub-agents (they respond in character)
3. CROSS-ORG INTRODUCTIONS — suggest members from other orgs when expertise is needed elsewhere
4. COMMUNITY BUILDING — welcome new members, suggest orgs for their interests

Keep responses concise (under 200 words)."""


# ============================================================
# AGENT LOGIC
# ============================================================
def _chat_payload_messages(history: list[dict]) -> list[Any]:
    """OpenAI-SDK chat payload from stored history (typed loosely on purpose —
    the payload is provider-agnostic dicts; the SDK validates at runtime)."""
    return [
        {"role": "system", "content": build_system_prompt()},
        *[{"role": m["role"], "content": m["content"]} for m in history[-20:]],
    ]


async def agent_logic(message: str, conversation_id: str) -> tuple[str, dict | None]:
    a2ui_data: dict | None
    """Process a message — route to virtual member, cross-query, or answer as chapter."""

    # 1. Route @agent-id messages
    match = re.match(r"^@([\w-]+)\s*(.*)", message, re.DOTALL)
    if match:
        target_id = match.group(1)
        forwarded = match.group(2).strip() or message

        # Check local members — virtual sub-agent response
        if target_id in members:
            member = members[target_id]
            if member.get("endpoint"):
                # Real endpoint — forward via A2A
                try:
                    async with httpx.AsyncClient() as client:
                        resp = await client.post(
                            f"{member['endpoint'].rstrip('/')}/a2a",
                            json={
                                "role": "user",
                                "content": {"type": "text", "text": forwarded},
                                "conversation_id": conversation_id,
                            },
                            timeout=15.0,
                        )
                        if resp.status_code == 200:
                            reply = resp.json().get("content", {}).get("text", "")
                            return f"[via @{target_id}] {reply}", None
                except Exception as e:
                    return f"Could not reach @{target_id}: {e}", None
            else:
                # Check if member has a sovereign session (multi-step reasoning with tools)
                sovereign_reply = await sovereign_runtime.session_respond(target_id, forwarded, conversation_id)
                if sovereign_reply:
                    return f"[@{target_id}] {sovereign_reply}", None
                # Fallback: check legacy member runtime
                member_reply = await member_runtime.member_respond(target_id, forwarded, conversation_id)
                if member_reply:
                    return f"[@{target_id}] {member_reply}", None
                # Final fallback: virtual sub-agent using server LLM
                reply = await virtual_member_response(target_id, member, forwarded, conversation_id)
                return f"[@{target_id}] {reply}", None

        # Check federation servers
        if target_id in federation:
            result = await federation_discovery.query_chapter(target_id, forwarded)
            if result:
                asyncio.create_task(log_activity(None, None, conversation_id, forwarded, result, is_cross_chapter=True))
                return f"[via @{target_id}] {result}", None
            return f"Could not reach {target_id}.", None

        return f"Unknown agent '{target_id}'. Try /api/members or /api/federation.", None

    # 2. Intent detection — "I need", "find me", "looking for", "who knows"
    intent_patterns = [
        "i need",
        "find me",
        "looking for",
        "who knows",
        "connect me with",
        "anyone who",
        "someone who",
        "help me find",
        "introduce me to someone",
    ]
    if any(p in message.lower() for p in intent_patterns):
        # Extract agent_id from conversation or use server default
        requester_id = conversation_id.split(":")[0] if ":" in conversation_id else "anonymous"

        # Use LLM to extract tags from the intent
        try:
            tag_resp = llm.chat.completions.create(
                model=DEFAULT_LLM_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "Extract 2-5 skill/topic tags from this request. Return ONLY a comma-separated list of lowercase tags, nothing else.",
                    },
                    {"role": "user", "content": message},
                ],
                max_tokens=50,
            )
            tags = [t.strip() for t in (tag_resp.choices[0].message.content or "").split(",") if t.strip()][:5]
        except Exception:
            tags = []

        intent_id = await intents.create_intent(requester_id, message, tags)
        local_result = await intents.match_intent(intent_id)
        fed_result = await intents.match_intent_federation(intent_id, federation)

        local_count = local_result.get("local_matches", 0)
        remote_count = fed_result.get("remote_matches", 0)
        total = local_count + remote_count
        matched_skills = local_result.get("matched_skills", [])

        if total > 0:
            reply = f"I found {total} potential matches across the network ({local_count} in our chapter, {remote_count} in other chapters). "
            if matched_skills:
                reply += f"Matching skills: {', '.join(matched_skills[:5])}. "
            reply += "I've sent anonymous requests to the matched agents — you'll be introduced once they accept. Your identity stays private until mutual consent."
        else:
            reply = "I couldn't find matches for that specific need right now, but I've recorded it. As new members join or skills evolve, I'll keep looking and notify you when someone matches."

        await activity_tracker.track(requester_id, "intent_submitted", {"intent": message[:100]})

        # Build A2UI showing match summary
        a2ui_data = _surface(
            "intent-result",
            [
                _card("page", "root"),
                _column("root", ["ir-title", "ir-stats", "ir-msg"]),
                _text("ir-title", "Intent Matched", "h2"),
                _row("ir-stats", ["ir-local", "ir-remote", "ir-total"]),
                _metric("ir-local", str(local_count), "Local Matches"),
                _metric("ir-remote", str(remote_count), "Federation"),
                _metric("ir-total", str(total), "Total"),
                _text("ir-msg", reply, "body"),
            ],
            "page",
        )

        await conv_store.append(AGENT_DB_UUID, f"chapter:{conversation_id}", message, reply)
        return reply, a2ui_data

    # 3. Server agent responds with Grok
    history = await conv_store.load(f"chapter:{conversation_id}")
    history.append({"role": "user", "content": message})

    try:
        response = llm.chat.completions.create(
            model=DEFAULT_LLM_MODEL,
            messages=_chat_payload_messages(history),
            max_tokens=512,
        )
        reply = response.choices[0].message.content or "I couldn't generate a response."
    except Exception as e:
        reply = f"LLM error: {e}"

    # 3. Cross-server query if Grok suggests it
    cross_match = re.search(r"\[CROSS_QUERY:([\w-]+):(.+?)\]", reply)
    if cross_match:
        target_chapter = cross_match.group(1)
        query = cross_match.group(2)
        cross_result = await federation_discovery.query_chapter(target_chapter, query)
        if cross_result:
            try:
                synth = llm.chat.completions.create(
                    model=DEFAULT_LLM_MODEL,
                    messages=[
                        {"role": "system", "content": build_system_prompt()},
                        {
                            "role": "user",
                            "content": f"You queried {target_chapter} and got: {cross_result}\n\nSynthesize a helpful answer for: {message}",
                        },
                    ],
                    max_tokens=512,
                )
                reply = synth.choices[0].message.content or reply
            except Exception:
                reply = reply.replace(cross_match.group(0), f"\n\nFrom {target_chapter}: {cross_result}")

    # Persist + log
    await conv_store.append(AGENT_DB_UUID, f"chapter:{conversation_id}", message, reply)
    asyncio.create_task(log_activity(None, None, conversation_id, message, reply))

    # 4. A2UI
    a2ui_data = None
    msg_lower = message.lower()
    if any(kw in msg_lower for kw in ["member", "who", "people", "list"]) and members:
        a2ui_data = build_member_cards(
            [
                {"name": m["name"], "description": m["description"], "skills": m.get("skills", [])}
                for m in members.values()
            ]
        )
    elif any(kw in msg_lower for kw in ["federation", "network", "other chapter"]) and federation:
        a2ui_data = build_federation_a2ui()
    elif any(kw in msg_lower for kw in ["about", "what is", "tell me about this"]):
        a2ui_data = build_chapter_info_a2ui()

    return reply, a2ui_data


# ============================================================
# FastAPI
# ============================================================
async def register_with_nest(public_url: str) -> None:
    payload = {
        "agent_id": AGENT_ID,
        "name": AGENT_NAME,
        "endpoint": public_url,
        "facts_url": f"{public_url}/agentfacts.json",
        "description": AGENT_DESCRIPTION,
        "specialization": AGENT_FOCUS,
        "capabilities": [s.strip().lower().replace(" ", "-") for s in AGENT_FOCUS.split(",")],
        "agent_type": "skill",
        "status": "running",
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{REGISTRY_URL}/api/agents", json=payload, timeout=10.0)
            if resp.status_code < 300:
                print(f"Registered on NEST: {AGENT_ID}")
            else:
                resp2 = await client.put(
                    f"{REGISTRY_URL}/api/agents/{AGENT_ID}",
                    json={"status": "running", "endpoint": public_url},
                    timeout=10.0,
                )
                print(f"NEST update: {resp2.status_code}")
    except Exception as e:
        print(f"NEST registration failed: {e}")


async def resolve_agent_uuid() -> str:
    """Get or create our agent UUID in Postgres agents table."""
    data = await pg_request("GET", "agents", params={"agent_id": f"eq.{AGENT_ID}", "select": "id", "limit": "1"})
    if data and isinstance(data, list) and len(data) > 0:
        return data[0]["id"]
    # Create a sentinel agent record
    result = await pg_request(
        "POST",
        "agents",
        body={
            "agent_id": AGENT_ID,
            "name": AGENT_NAME,
            "description": AGENT_DESCRIPTION,
            "skills": [s.strip() for s in AGENT_FOCUS.split(",")],
            "status": "active",
            "llm_provider": llm_config.PROVIDER,
            "llm_model": llm_config.DEFAULT_MODEL,
            "nest_registered": True,
        },
    )
    if result and isinstance(result, list) and len(result) > 0:
        return result[0]["id"]
    return ""


nanda_registry.registered_on_nest = set()


# Module-level memo for the chronicle date boundary check. Surfacing this
# at module scope lets the heartbeat loop survive function-local reentry
# (e.g., if the loop is restarted) without re-generating today's entries.
_last_chronicle_run_date: dict[str, str] = {}


# the org's think cadence, owned by agent_scheduler rather than a bare
# sleep. Kept here rather than inside the loop so the restart-resume read and
# the per-cycle write use one definition of the interval.
_think_delay_s: float = float(THINK_CYCLE_INTERVAL)


async def _record_think_schedule() -> None:
    """Persist the next think time and remember how long to wait for it."""
    global _think_delay_s
    import random as _random

    import agent_scheduler

    decision = agent_scheduler.after_success(
        now=datetime.now(UTC), interval_s=float(THINK_CYCLE_INTERVAL), rand=_random.random()
    )
    # after_success always sets a next run time, but Decision allows None for
    # the PAUSED case — and an unguarded subtraction there is a TypeError at
    # runtime, not merely a mypy complaint. Falling back to the configured
    # interval keeps the loop pacing instead of crashing it.
    if decision.next_run_at is None:
        _think_delay_s = float(THINK_CYCLE_INTERVAL)
    else:
        _think_delay_s = max(agent_scheduler.MIN_INTERVAL_S, (decision.next_run_at - datetime.now(UTC)).total_seconds())
    # A failed write is reported, not swallowed: the in-memory delay still
    # paces this process, but the schedule did not survive and a restart will
    # fall back to the default rather than resuming.
    if not await agent_scheduler.record(AGENT_ID, decision):
        print("[scheduler] think schedule not persisted — this restart will not resume it")


#: Consecutive think-cycle failures, and the reason the loop stopped thinking.
#: Module scope for the same reason ``_think_delay_s`` is: the loop must not
#: lose its backoff position across a function-local reentry.
_consecutive_think_failures: int = 0
_think_paused_reason: str | None = None


async def _record_think_failure(exc: BaseException) -> None:
    """Back off a retryable think failure; STOP a terminal one.

    ⚠️ THIS IS THE HALF THAT WAS WRITTEN AND NEVER CALLED.
    ``agent_scheduler.after_failure`` has had the correct terminal-vs-retryable
    verdict all along, reached through the table both trees share byte for byte.
    Nothing called it, because ``run_cycle`` returned normally on every
    exception, so the scheduler recorded a success after each failure and the
    cadence never widened. A sustained 401 therefore cost 418 org calls a day,
    forever.

    A terminal verdict sets ``_think_paused_reason`` and the loop stops calling
    ``run_cycle``. It does NOT stop the heartbeat: registration, federation and
    every surface keep running, so a bad key downgrades the chapter instead of
    silently burning quota. Clearing the pause is deliberately operator-driven —
    see ``agent_scheduler.resume`` and ``POST /api/admin/think/resume``. Anything
    that rescheduled it on a timer would be retrying by another name.
    """
    global _think_delay_s, _consecutive_think_failures, _think_paused_reason
    import random as _random

    decision = agent_scheduler.after_failure(
        exc,
        now=datetime.now(UTC),
        consecutive_failures=_consecutive_think_failures,
        rand=_random.random(),
    )
    _consecutive_think_failures = decision.consecutive_failures

    if decision.paused:
        _think_paused_reason = decision.paused_reason
        print(
            f"[scheduler] think cycle HALTED — {decision.paused_reason}. "
            "Heartbeat, federation and surfaces continue. Fix the cause, then "
            "POST /api/admin/think/resume."
        )
    else:
        _think_delay_s = max(
            agent_scheduler.MIN_INTERVAL_S,
            (decision.next_run_at - datetime.now(UTC)).total_seconds()
            if decision.next_run_at
            else THINK_CYCLE_INTERVAL,
        )
        print(
            f"[scheduler] think cycle retryable failure #{decision.consecutive_failures} "
            f"({type(exc).__name__}) — next attempt in {_think_delay_s:.0f}s"
        )

    if not await agent_scheduler.record(AGENT_ID, decision):
        print("[scheduler] failure schedule not persisted — this restart will not resume it")


def _next_think_delay() -> float:
    return _think_delay_s


async def _resume_think_schedule() -> float | None:
    """Seconds still owed on a schedule persisted before the last restart.

    This is the whole point of durability: without it every restart resets the
    cadence to "now", so a fleet redeployed together thinks in lockstep from
    that instant. Returns None when there is nothing to resume (first boot, no
    database, or the time has already passed).
    """
    import agent_scheduler

    rows = await agent_scheduler.due_agents(limit=1)
    if rows:
        return None  # already due — run now
    try:
        existing = await pg_request("GET", "agent_schedule", params={"agent_id": f"eq.{AGENT_ID}", "limit": "1"})
    except Exception:
        return None
    if not existing:
        return None
    raw = (existing[0] or {}).get("next_run_at")
    if not raw:
        return None
    try:
        when = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    remaining = (when - datetime.now(UTC)).total_seconds()
    return remaining if remaining > 0 else None


async def heartbeat_loop(public_url: str) -> None:
    # Reset on a successful cycle, so a blip followed by recovery does not leave
    # the chapter permanently slowed.
    global _consecutive_think_failures

    # decide AND announce the publication state before the startup delay.
    # This log used to sit after the sleep below, so for the first 30 seconds of
    # every boot there was no line either way — and once REGISTRY_URL defaulted
    # to empty (PR4) the common case became "no line at all". Absence is weaker
    # evidence than a statement: an operator checking whether their org
    # publishes should read the answer, not infer it from silence. Both
    # branches log, so "off" and "not yet decided" are distinguishable.
    registration_blocked = registry_policy.publication_blocked_reason(public_url)
    if registration_blocked:
        print(
            f"[registry] publication OFF: {registration_blocked}. "
            "Nothing is sent to any registry; local upkeep continues."
        )
    else:
        print(f"[registry] publication ON: this org will publish to {registry_policy.registry_url()}")

    # Loud at boot, naming the variable, because dropping the default changes
    # DISCOVERY too and that failure is silent: with no registry, federation
    # finds no peers and "no peers found" is indistinguishable from "no peers
    # exist". The per-path notices say it again where it bites; this says it once
    # where an operator upgrading will see it.
    if not registry_policy.registry_url():
        print(
            "[registry] NO REGISTRY CONFIGURED — REGISTRY_URL is unset or empty. This org "
            "publishes to no registry AND discovers no peers through one; federation peers "
            "come only from KNOWN_CHAPTER_ENDPOINTS. Nothing has failed and nothing is being "
            "sent anywhere. ⚠️ EARLIER VERSIONS SILENTLY DEFAULTED to "
            f"{registry_policy.FORMER_DEFAULT_REGISTRY_URL} — if you relied on that, set "
            "REGISTRY_URL explicitly to keep it.",
            flush=True,
        )

    # resume a schedule persisted before the last restart rather than
    # resetting the cadence to "now".
    resumed = await _resume_think_schedule()
    if resumed is not None:
        print(f"[scheduler] resuming persisted think schedule — {resumed:.0f}s remaining")
        await asyncio.sleep(resumed)
    else:
        # Initial delay before first think cycle
        await asyncio.sleep(30)

    # the heartbeat used to re-register unconditionally — independent of
    # REGISTRY_URL and of AUTO_REGISTER, which was never read by any code. That
    # is how 31 dev/CI stacks published localhost and docker-internal endpoints
    # to the PRODUCTION registry: an operator who set AUTO_REGISTER=false, or
    # emptied REGISTRY_URL, was still publishing every cycle. Decided ONCE here
    # rather than per iteration, so the reason is logged exactly once instead of
    # every heartbeat forever.

    while True:
        # Heartbeat — re-register server itself (in case NEST lost it)
        try:
            if not registration_blocked:
                async with httpx.AsyncClient() as client:
                    # Always keep our server registration alive. Re-signing the
                    # endpoint attestation here keeps its expires_at window
                    # rolling — a dead or key-rotated org stops refreshing and
                    # its registry record goes verifiably stale.
                    heartbeat_body: dict = {"status": "running", "endpoint": public_url}
                    attestation = registry_attestation.build(AGENT_ID, public_url, AGENT_ID)
                    if attestation:
                        heartbeat_body["attestation"] = attestation
                    await client.put(
                        f"{registry_policy.registry_url()}/api/agents/{AGENT_ID}",
                        json=heartbeat_body,
                        timeout=10.0,
                    )

                    # Only register members that haven't been registered yet this session
                    new_members = [mid for mid in members if mid not in nanda_registry.registered_on_nest]
                    for mid in new_members:
                        try:
                            await nanda_registry.register_member(mid, members[mid], public_url)
                            nanda_registry.registered_on_nest.add(mid)
                        except Exception:
                            pass

                # Keep the NANDA Index entry fresh too — register_on_index only
                # runs at boot, and the attestation's expires_at (24h) only rolls
                # if something re-publishes it. No-op when no index configured.
                await nanda_registry.update_index_entry(
                    AGENT_ID,
                    sovereign_identity.build_nanda_facts(
                        agent_id=AGENT_ID,
                        member={
                            "name": AGENT_NAME,
                            "description": AGENT_DESCRIPTION,
                            "skills": [s.strip() for s in AGENT_FOCUS.split(",")],
                        },
                        public_url=public_url,
                    ),
                )
        except Exception:
            pass

        # Federation re-discovery — opt-in (see FEDERATION_AUTODISCOVER).
        if _FEDERATION_AUTODISCOVER:
            await federation_discovery.discover()

        # Cross-registry divergence detector: with ≥2 registries configured
        # (NEST + NANDA Index + any federation directory), compare what
        # each claims about THIS org and its federation peers — a registry
        # that omits, re-points, or re-keys an org diverges from its siblings
        # and the event log gets the alarm. No-op with a single registry.
        # check() never raises and dedupes the url list.
        await registry_divergence.check(
            nanda_registry.configured_registries() + federation_discovery.directory_urls(),
            {AGENT_ID} | set(federation.keys()),
        )

        # auto-prune zombie peers — persisted federation_policy rows
        # whose peer is not operator-anchored, not currently live, not
        # deliberately blocked, and stale past FEDERATION_PEER_PRUNE_AFTER_S
        # (default 72h; <=0 disables). Without this, a dead legacy peer sits
        # 'degraded' in /health federation_state forever (the in-memory
        # federation dict prunes, the DB row never did).
        try:
            import federation_policy as _fed_policy_mod

            _anchored = [e.strip() for e in os.environ.get("KNOWN_CHAPTER_ENDPOINTS", "").split(",") if e.strip()]
            _prune_after = int(os.environ.get("FEDERATION_PEER_PRUNE_AFTER_S", "259200"))
            await _fed_policy_mod.prune_stale_peers(_anchored, set(federation.keys()), _prune_after)
        except Exception as e:  # noqa: BLE001 — heartbeat survives, loudly
            print(f"[federation][WARN] peer auto-prune failed ({type(e).__name__}: {e})")

        # Exchange knowledge with federation peers (every 6 minutes)
        if think_cycle.think_cycle_count % 3 == 0:
            await federation_intelligence.exchange_with_all(federation)

        # Reload runtimes (new signups may have API keys)
        if think_cycle.think_cycle_count % 5 == 0:  # Every 10 minutes
            await sovereign_runtime.load_sessions(members)
            await member_runtime.load_runtimes(members)

        # Chronicle layer — once per UTC day boundary, generate
        # yesterday's first-person Chronicle entries for every member
        # whose config.parent_chapter is this chapter. Idempotent —
        # re-running on the same day just upserts the same rows.
        try:
            from datetime import UTC, datetime, timedelta

            import chronicle as chronicle_mod

            today_utc = datetime.now(UTC).date()
            if _last_chronicle_run_date.get("d") != today_utc.isoformat():
                yesterday = today_utc - timedelta(days=1)
                written = await chronicle_mod.generate_for_all_own_members(day=yesterday, members=members)
                if written:
                    print(f"[chronicle] generated {written} entries for {yesterday}")
                _last_chronicle_run_date["d"] = today_utc.isoformat()
        except Exception:  # noqa: BLE001 — chronicle generation must never wedge heartbeat
            pass

        # Autonomous think cycle.
        #
        # the cadence is now DURABLE rather than a bare sleep. The next
        # run time is persisted, so a restart resumes the schedule instead of
        # resetting every org to "now" — which is also what kept a fleet of
        # orgs phase-locked to whatever instant they were last deployed.
        # Jittered on every decision, not once, or they re-lock immediately.
        #
        # Success and failure both route through agent_scheduler, so the
        # cadence has one owner. `run_cycle` now RAISES rather than swallowing,
        # which is what makes the failure half reachable at all — while it
        # returned normally on every exception, the scheduler recorded a success
        # after each failure and a sustained 401 never widened the interval.
        if _think_paused_reason is None:
            try:
                await think_cycle.run_cycle()
            except Exception as exc:  # noqa: BLE001 — classified, not swallowed
                await _record_think_failure(exc)
            else:
                _consecutive_think_failures = 0
                await _record_think_schedule()
        await asyncio.sleep(_next_think_delay())


def resolve_public_url() -> str:
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway_domain:
        return f"https://{railway_domain}"
    return os.environ.get("PUBLIC_URL", f"http://localhost:{PORT}")


# Operator-visible data dir (org-config, conformance badge, issuer-log, signing
# keypair). Renamed .nanda/ → .org/ for org-readiness; lifespan() migrates an
# existing .nanda/ into it on startup (non-breaking).
_ORG_DATA_DIR = Path(__file__).resolve().parent / ".org"
_CONFORMANCE_BADGE_PATH = _ORG_DATA_DIR / "conformance.json"  # served by routes/identity.py


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    global PUBLIC_URL, AGENT_DB_UUID
    PUBLIC_URL = resolve_public_url()
    print(f"Public URL: {PUBLIC_URL}")

    # Migrate the operator-visible data dir .nanda/ → .org/ once, non-breaking
    # . Constants below already point at .org; this carries over an
    # existing .nanda/ from an upgraded deployment before anything reads it.
    org_home.resolve_org_dir(_ORG_DATA_DIR.parent)

    # Admin token — system-level operator credential. Generated on first
    # startup if no env var / on-disk token exists. Printed ONCE; never
    # surfaced again. Operator captures it on first run.
    import admin as admin_mod

    admin_token, freshly_generated = admin_mod.init()
    if freshly_generated:
        print(admin_mod.format_startup_message(admin_token, public_url=PUBLIC_URL))

    # Rate-limiter durability. Optional by design: without the table the limiter
    # still limits, it just forgets across restarts — which is the behaviour
    # that existed before this. So the ensure degrades rather than raising, and
    # the salt lives outside the database — the operator's environment, or the
    # org data dir — so a dump of the snapshot table cannot be turned back into
    # client IPs. The salt's SOURCE is kept because it decides whether a
    # restart restores anything, and the table being writable does not.
    import pg_store as _rl_pg_store

    global _rate_limit_salt, _rate_limit_salt_source, _rate_limit_persist_ok
    _rate_limit_salt, _rate_limit_salt_source = rate_limit_persistence.resolve_salt(_ORG_DATA_DIR)
    print(f"Rate limiter: salt source {_rate_limit_salt_source}")
    if _rate_limit_salt_source == rate_limit_persistence.SOURCE_FILE_NEW:
        print(
            f"Rate limiter: salt file created this boot under {_ORG_DATA_DIR} — buckets are restored after a "
            f"restart only if that directory persists; on a service with no persistent volume set "
            f"{rate_limit_persistence.SALT_ENV}"
        )

    async def _rate_limit_table_usable() -> bool:
        """Whether the snapshot table is there and this role can read it.

        Consulted BEFORE any DDL. On a fresh default install init.sql created
        the table as the superuser and 0006 granted the app role DML on it, but
        Postgres refuses CREATE TABLE IF NOT EXISTS without CREATE on the
        schema even when the table exists — so the ensure used to report
        persistence unavailable on the one install every stranger runs.
        """
        rows = await pg_request("GET", rate_limit_persistence.TABLE, params={"limit": "1"})
        return isinstance(rows, list)

    _rate_limit_persist_ok = await rate_limit_persistence.ensure_schema(
        _rl_pg_store.execute_ddl,
        has_database=bool(_rl_pg_store.database_url()),
        table_usable=_rate_limit_table_usable,
    )
    if _rate_limit_persist_ok:
        carried = await _restore_rate_limit_buckets()
        print(f"Rate limiter: {carried} client bucket(s) carried across the restart")

    # Load server config and seed members
    config = load_chapter_config()
    if config:
        seed_members(config)

    # Load previously spawned agents from Postgres (survives redeploys)
    await load_persisted_members()

    print(f"Total members: {len(members)} (config + persisted)")

    # Load stored auth keys from members
    auth_verify.load_keys_from_members(members)
    # replay any members whose Postgres row failed to persist last time BEFORE
    # rehydrating keys, so a re-persisted member's did:key is picked up below.
    await replay_member_persist_outbox()
    # Rehydrate member keys from Postgres (agent_facts.provider.did) so
    # agent_id→did:key resolution + signed-request verification survive a restart
    # (the in-memory key store is empty on boot). See reload_member_keys().
    await reload_member_keys()

    # Initialize NEST registry
    # ── H6: the signing key must exist BEFORE anything registers or federates ──
    # Registration used to run ~150 lines before this, so the org published
    # itself to the registry with NO signing key — no attestation accompanied the
    # registration, and every federation call in that window would have been
    # emitted unsigned (see H4). Ordering, not configuration, so it is fixed by
    # moving the call rather than by a flag.
    sovereign_identity.init(pg_request=pg_request, agent_id=AGENT_ID)
    await sovereign_identity.ensure_chapter_keypair(
        AGENT_ID,
        # _arp_offline is derived from _HAS_DATABASE and is not computed until
        # later in lifespan; use its source directly rather than moving that
        # derivation too and widening this change.
        pg_request=None if not _HAS_DATABASE else pg_request,
        local_home=str(_ORG_DATA_DIR),
    )
    # ⚠️ AND SAY SO. A normal boot printed NOTHING when the keypair loaded — only
    # on first mint or on the seal-in-place migration — so the ordering this fix
    # establishes was UNOBSERVABLE in production, which is why it went unnoticed.
    # An invariant nothing can observe regresses silently. This line is the
    # observability half of the fix and is not decoration: it is what lets anyone
    # confirm from a log that the key was ready before registration ran.
    _kp_ready = sovereign_identity._ed25519_keypairs.get(AGENT_ID)
    if _kp_ready:
        _kp_did = sovereign_identity.build_did_key_from_ed25519(base64.b64encode(_kp_ready["public_key"]).decode())
        print(f"[identity] chapter signing key READY before registration — {_kp_did}")
    else:
        print(
            "[identity][ERROR] chapter signing key NOT available after "
            "ensure_chapter_keypair — registration and federation will be unsigned"
        )

    nanda_registry.init(REGISTRY_URL, AGENT_ID, AGENT_NAME, AGENT_DESCRIPTION, AGENT_FOCUS, members, PUBLIC_URL)
    federation_discovery.init(REGISTRY_URL, AGENT_ID, PUBLIC_URL, federation, _federation_failures)

    # Reconcile the registry — REPORT ONLY. This used to call a function that
    # issued DELETEs against the registry, keyed on an endpoint-string match, in
    # this unconditional startup path, and it fired even with AUTO_REGISTER=false.
    # Measured: two records that merely shared this org's endpoint were deleted
    # at boot and logged as "cleaned". Boot does not delete; removal is an
    # explicit operator action (reconcile_stale_agents(..., delete=True)).
    await nanda_registry.reconcile_stale_agents(PUBLIC_URL)

    # Register server on NEST + NANDA Index
    chapter_facts = sovereign_identity.build_nanda_facts(
        agent_id=AGENT_ID,
        member={
            "name": AGENT_NAME,
            "description": AGENT_DESCRIPTION,
            "skills": [s.strip() for s in AGENT_FOCUS.split(",")],
        },
        public_url=PUBLIC_URL,
    )
    await nanda_registry.register_chapter(PUBLIC_URL, facts=chapter_facts)

    # Register all members on NEST
    await nanda_registry.register_all_members(PUBLIC_URL)

    # Discover federation peers — opt-in (see FEDERATION_AUTODISCOVER).
    if _FEDERATION_AUTODISCOVER:
        await federation_discovery.discover()

    # Resolve Agent DB UUID
    AGENT_DB_UUID = await resolve_agent_uuid()
    if AGENT_DB_UUID:
        print(f"Agent DB UUID: {AGENT_DB_UUID}")
    else:
        print("Warning: Could not resolve Agent DB UUID — conversations won't persist")

    # Initialize server helpers (must be before load_knowledge)
    chapter_helpers.init(pg_request, AGENT_ID, AGENT_NAME, AGENT_DB_UUID, chapter_helpers._knowledge_cache)

    # Load knowledge models from Postgres
    await load_knowledge()

    # Initialize activity tracker
    activity_tracker.init(pg_request=pg_request, agent_id=AGENT_ID)
    await activity_tracker.load_scores()

    # Initialize outcome tracking + conversations
    outcome_tracker.init(pg_request=pg_request, agent_id=AGENT_ID)
    agent_conversations.init(pg_request=pg_request, agent_id=AGENT_ID)
    agent_export.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Event bus (EB-2 — publish primitive backed by event_log)
    event_bus.init(pg_request, AGENT_ID)

    # Subscription service (EB-3 — register/list/cancel)
    subscriptions_svc.init(pg_request, AGENT_ID)
    invites_mod.init(pg_request)

    # Trust-tier delivery gating (EB-5 — filter events at delivery
    # time using MIN_TRUST_TO_SUBSCRIBE + agents.trust_score)
    trust_gate.init(pg_request)

    # Weekly server digest builder (server.digest.weekly event source)
    digest_mod.init(pg_request, AGENT_ID, AGENT_NAME, llm=llm)

    # Server broadcasts — POST /api/broadcast + federation inbox.
    # Reads from the live ``federation`` dict so peer discovery
    # changes flow through without re-init.
    import federation_signing

    broadcast_mod.init(
        pg_request=pg_request,
        chapter_id=AGENT_ID,
        federation=federation,
        # S2S Ed25519 signing: sign the broadcast body with this chapter's
        # key. The receiver verifies against our published did.json. method/path
        # are unused — the signature binds the body via JCS canonicalization.
        sign_outbound=lambda method, path, body: federation_signing.sign_outbound(AGENT_ID, body),
    )

    # the restart-replay guard (federation_inbound_seen) is baked
    # into init.sql with no boot DDL/migration, so a DB provisioned before it
    # is missing it and _seen_persisted silently fails open. Probe it at boot
    # and, under enforcement, make a degraded guard LOUD instead of silent.
    _dedup_ok, _dedup_detail = await broadcast_mod.dedup_store_healthy()
    if not _dedup_ok:
        _msg = (
            f"[federation][{'SECURITY' if federation_signing.enforcement_enabled() else 'WARN'}] "
            f"restart-replay dedup store unavailable ({_dedup_detail}) — the persistent guard "
            "is INERT; replay protection is degraded to the broadcast freshness window only. "
            "Ensure the 'federation_inbound_seen' table exists (it is in infra/init.sql)."
        )
        print(_msg)

    # Sovereign member key rotation (Phase 2 — /api/members/rotate endpoint)
    import member_rotation

    member_rotation.init(pg_request=pg_request, chapter_id=AGENT_ID)

    # Skill attestation marketplace (Phase A)
    import attestations
    import skill_revenue

    attestations.init(pg_request=pg_request, chapter_id=AGENT_ID)
    skill_revenue.init(pg_request=pg_request, chapter_id=AGENT_ID)

    # ARP v0.1 — Agency Receipt Protocol issuer log.
    # See spec/arp/0.1/spec.md §10.2.
    import arp as arp_mod

    # Offline mode: with no Postgres configured (local dev / demo), back the
    # Issuer Log with a local SQLite store so receipts persist and are viewable
    # exactly as in production. Inert when Postgres IS configured (production).
    _arp_offline = not _HAS_DATABASE
    arp_mod.init(
        pg_request=pg_request,
        chapter_id=AGENT_ID,
        offline=_arp_offline,
        local_log_home=_ORG_DATA_DIR,
    )

    # Chronicle layer — first-person daily summaries derived from ARP.
    # The server generates Chronicle rows for its OWN members (those
    # whose config.parent_chapter == AGENT_ID) once per UTC day boundary.
    import chronicle as chronicle_mod

    chronicle_mod.init(
        pg_request=pg_request,
        chapter_id=AGENT_ID,
        chapter_name=AGENT_NAME,
        llm=llm,
    )

    # Trust-events ledger + endorsements (PR-A/B of trust-events series)
    # + daily decay/drift crons (WIRE-3)
    import endorsements as endorsements_mod
    import trust_cron as trust_cron_mod
    import trust_events as trust_events_mod

    trust_events_mod.init(pg_request, AGENT_ID)
    endorsements_mod.init(pg_request, AGENT_ID)
    trust_cron_mod.init(pg_request, AGENT_ID)

    # Initialize A2UI surfaces
    surfaces.init(
        pg_request_fn=pg_request,
        members_dict=members,
        federation_dict=federation,
        knowledge_cache=chapter_helpers._knowledge_cache,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
        get_think_count=lambda: think_cycle.think_cycle_count,
        intents_mod=intents,
        projections_mod=projections,
        outcome_tracker_mod=outcome_tracker,
        agent_conversations_module=agent_conversations,
        federation_intelligence_mod=federation_intelligence,
        activity_tracker_mod=activity_tracker,
        portal_layout_fn=_portal_layout_document,
    )
    # Surfaces show the org's configured display name (wizard), not the env default.
    surfaces.set_display_name(_org_profile()["name"])

    # conformance surface live out of the box — sign a self-attested
    # badge from a real in-process check run unless an operator badge already
    # verifies. After ensure_chapter_keypair so the signing key is durable.
    import conformance_boot

    conformance_boot.ensure_boot_badge(AGENT_ID, _CONFORMANCE_BADGE_PATH)
    await sovereign_identity.load_facts_versions()

    # sm-federation §4 — ensure the durable feed log exists, and decide from the
    # RESULT whether this node can honour the exchange. There is no runner for
    # infra/migrations (README.md says so), so an existing install would otherwise
    # never get this table; pg_store.execute_ddl was written for exactly this
    # ("schema ensure at boot, that change") and had no callers until now.
    #
    # ⚠️ Deliberately does NOT follow execute_ddl's raise-on-failure contract for
    # the permission-denied case. That contract is right for a table the runtime
    # REQUIRES; this one is optional, and plenty of self-hosted deployments run
    # the app under a least-privilege role with no DDL rights. Bricking a working
    # install to add an optional federation surface is worse than the surface
    # being absent — so a privilege refusal degrades the node to §2-only, loudly,
    # and every other DDL failure still raises.
    import pg_store as _pg_store

    async def _feed_log_readable() -> bool:
        """Whether the feed log exists and this role can read it.

        Consulted only when the DDL ensure is refused for want of privilege.
        Postgres refuses CREATE TABLE IF NOT EXISTS without CREATE on the schema
        even when the table is there, so an app role with no DDL rights — which
        is what this deployment now uses — is refused on every boot regardless.
        """
        rows = await pg_request("GET", "federation_feed_entries", params={"limit": "1"})
        return isinstance(rows, list)

    await federation_feed.ensure_schema(
        _pg_store.execute_ddl,
        has_database=bool(_pg_store.database_url()),
        db_reachable=_pg_store.db_reachable,
        feed_readable=_feed_log_readable,
    )

    # Governance — approval queue + role nominations. Must init before think_cycle
    # starts proposing introductions so governance.propose is wired.
    import governance

    governance.init(pg_request=pg_request, agent_id=AGENT_ID)

    # the scheduler shipped with a complete API and no importers, so
    # `agent_schedule` held 0 rows and restart-resume could not be tested
    # because nothing ever started it. Wired here, beside the other store-backed
    # module, so it is initialised on the same path and by the same pg_request.
    import agent_scheduler

    agent_scheduler.init(pg_request)

    # Bounded operational grants — the middle option between "approve every
    # action" and "no gate". Initialised on the same path as governance, whose
    # gate consults it.
    import bounded_grants

    bounded_grants.init(pg_request, AGENT_ID)

    # Server policy — hyperparameter store + auto-tune.
    import policy

    policy.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Federation policy — per-peer state + backoff + leader block.
    import federation_policy

    federation_policy.init(pg_request=pg_request, agent_id=AGENT_ID)

    # CRM records — org-side contacts/deals/interactions, written through the org.
    import crm_store

    crm_store.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Durable per-agent memory — cursors/dedup/notes that must survive a
    # container recreate. Storage only, no LLM; see the module docstring for
    # why it is deliberately NOT behind the record_write gate.
    import agent_memory_store

    agent_memory_store.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Agent authority scope — per-member delegation contract + rate limits.
    import authority

    authority.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Server skill registry — Ed25519-signed skill catalog.
    import skill_registry

    skill_registry.init(pg_request_fn=pg_request, chapter_id=AGENT_ID)

    # Seed the non-profit starter skills pack (idempotent; first-party convenience skills).
    import starter_pack

    await starter_pack.seed_starter_pack()

    # Agent settings store + onboarding state machine.
    # Reads go through the plain wrapper; WRITES that a caller marks strict go
    # through pg_execute_strict, which raises instead of logging and returning
    # None. Onboarding is its first production caller — the mechanism and its
    # docstring ("callers where a swallowed failure would silently lose data")
    # had been here with nothing using it.
    import pg_store
    import settings as settings_mod

    settings_mod.init(pg_request_fn=pg_request, execute_strict_fn=pg_store.pg_execute_strict)

    import onboarding

    onboarding.init(pg_request_fn=pg_request, execute_strict_fn=pg_store.pg_execute_strict)

    # Voice configuration catalogs (stateless — no init needed, just import).
    # Channel connections (Slack, email, discord, webhook).
    import channels
    import voice  # noqa: F401

    channels.init(pg_request_fn=pg_request)

    # Server enterprise primitives: SSO + audit + federation allowlist.
    import chapter_audit
    import chapter_auth

    chapter_audit.init(pg_request_fn=pg_request)
    chapter_auth.init(pg_request_fn=pg_request)

    # ── A1: sm-locp compliance VC issuer ───────────────────────────
    # Server's Ed25519 keypair is the issuer identity for any
    # ComplianceCredential the server mints. Init AFTER sovereign_identity
    # has run keygen but BEFORE any handler that might invoke
    # compliance.emit_compliance_attestation().
    try:
        import compliance as _compliance_mod

        chapter_kp = sovereign_identity._ed25519_keypairs.get(AGENT_ID)
        if chapter_kp and isinstance(chapter_kp.get("private_key"), bytes):
            private_key_b64 = base64.b64encode(chapter_kp["private_key"]).decode()
            _compliance_mod.init(chapter_id=AGENT_ID, private_key_b64=private_key_b64)
    except Exception as _compliance_init_err:  # noqa: BLE001
        # Compliance VC issuance is optional. If init fails (sm-locp missing,
        # keypair not yet resolved, etc.), the server continues to work;
        # emit_compliance_attestation becomes a no-op.
        print(f"[compliance] init skipped: {_compliance_init_err}")

    # ── A2: sm-bridge parallel peer-discovery routers ──────────────
    # Mounts sm-bridge at /sm-bridge/* alongside the server's existing
    # /.well-known/nanda-agent.json + /agentfacts.json. Federation peers
    # continue using the legacy endpoints; new consumers and forward
    # migrations use the sm-bridge shape. See chapter/sm_bridge_adapter.py
    # for the converter implementation.
    try:
        import sm_bridge_adapter

        sm_bridge_adapter.mount_sm_bridge_routers(
            application,
            agent_id=AGENT_ID,
            agent_name=AGENT_NAME,
            public_url=PUBLIC_URL,
            members=members,
        )
    except Exception as _sm_bridge_init_err:  # noqa: BLE001
        print(f"[sm-bridge] mount skipped: {_sm_bridge_init_err}")

    # Federation mesh — unified agent-facing interface to peers + federation.
    # Inited later (after projections + federation_intelligence are ready)
    # — see below near the end of lifespan.

    # Initialize privacy projections + intent matching
    projections.init(
        pg_request=pg_request,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
        api_key=LLM_API_KEY,
        api_base_url=LLM_API_BASE_URL,
    )
    intents.init(pg_request=pg_request, agent_id=AGENT_ID, agent_name=AGENT_NAME)
    consent_gate.init(pg_request=pg_request, agent_id=AGENT_ID)

    # Initialize member agent runtimes
    member_runtime.init(
        pg_request=pg_request,
        conv_store=conv_store,
        log_activity=log_activity,
        log_agent_thought=log_agent_thought,
        build_thought_card=build_thought_card,
        knowledge_cache=chapter_helpers._knowledge_cache,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
    )
    await member_runtime.load_runtimes(members)

    # Initialize sovereign agent runtime (replaces member_runtime for members with API keys)
    sovereign_runtime.init(
        pg_request=pg_request,
        conv_store=conv_store,
        log_activity=log_activity,
        log_agent_thought=log_agent_thought,
        build_thought_card=build_thought_card,
        knowledge_cache=chapter_helpers._knowledge_cache,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
    )
    await sovereign_runtime.load_sessions(members)

    # Build anonymized projections for all members
    await projections.rebuild_all_projections(members)

    # Initialize federation intelligence
    federation_intelligence.init(
        pg_request=pg_request,
        knowledge_cache=chapter_helpers._knowledge_cache,
        agent_id=AGENT_ID,
        agent_name=AGENT_NAME,
    )
    await federation_intelligence.load_cached_knowledge()

    # Publish the current intelligence, so a node that just came up has something
    # for a peer to subscribe TO. Without a producer the endpoint serves an empty
    # page forever and a subscriber cannot even obtain a cursor — the state this
    # feature exists to end, and what the feed-restart conformance work's suite caught in this PR.
    #
    # ⚠️ AFTER federation_intelligence.init(), not before. Placed earlier it built
    # an envelope from an uninitialised module — empty community_id — which
    # validate_envelope correctly rejected, and the raise took the whole boot
    # down. Content-deduped, so restarting an unchanged org appends nothing.
    await federation_feed.publish_if_changed(
        pg_request,
        sovereign_identity._ed25519_keypairs.get(AGENT_ID),
        federation_intelligence.get_our_summary(),
        generated_at=datetime.now(UTC).isoformat(),
    )

    # Federation mesh — wire now that federation_intelligence + intents are ready.
    import mesh as mesh_mod

    mesh_mod.init(
        pg_request=pg_request,
        members=members,
        federation=federation,
        agent_id=AGENT_ID,
        intents_module=intents,
        federation_intelligence_module=federation_intelligence,
        federation_discovery_module=federation_discovery,
        auth_verify_module=auth_verify,
        governance_module=governance,
    )

    # Wire think_cycle last — it depends on everything above. Without this,
    # run_cycle() crashes silently every tick on missing injected modules.
    think_cycle.init(
        pg_request=pg_request,
        members=members,
        federation=federation,
        llm=llm,
        AGENT_ID=AGENT_ID,
        AGENT_NAME=AGENT_NAME,
        AGENT_DESCRIPTION=AGENT_DESCRIPTION,
        AGENT_FOCUS=AGENT_FOCUS,
        DEFAULT_LLM_MODEL=DEFAULT_LLM_MODEL,
        remember=remember,
        recent_memories=recent_memories,
        get_intelligence_context=get_intelligence_context,
        log_activity=log_activity,
        log_agent_thought=log_agent_thought,
        conv_store=conv_store,
        build_member_system_prompt=build_member_system_prompt,
        activity_tracker=activity_tracker,
        sovereign_runtime_mod=sovereign_runtime,
        intents_mod=intents,
        outcome_tracker_mod=outcome_tracker,
        federation_discovery_mod=federation_discovery,
    )

    task = asyncio.create_task(heartbeat_loop(PUBLIC_URL))
    persist_task = asyncio.create_task(_rate_limit_persist_loop()) if _rate_limit_persist_ok else None
    yield
    task.cancel()
    if persist_task is not None:
        persist_task.cancel()
        # A graceful stop gets a final snapshot, so an orderly deploy carries
        # the buckets across exactly. A crash or SIGKILL does not reach here —
        # which is why the periodic flush, not this, is the guarantee.
        await _persist_rate_limit_buckets()


# ── Deployment profile (R7; safe-by-default that change) ───────────────────────
# ORRERY_PROFILE=prod (DEFAULT) is the safe-for-public posture: CORS is an explicit
# allowlist (empty = no foreign-origin browser access; signed server-to-server
# requests are unaffected) and the interactive /docs + /redoc + /openapi.json
# surfaces are OFF (no full API schema map handed to the public). Set
# ORRERY_PROFILE=dev locally to opt into CORS `*` + the docs surfaces for
# ergonomics. That change: the stock install (`cp .env.example .env`) must NOT expose the
# docs/schema or wildcard CORS by default. See docs/CONFIGURATION.md § Production profile.
ORRERY_PROFILE = os.environ.get("ORRERY_PROFILE", "prod").strip().lower()


def resolve_cors_origins(profile: str, raw: str | None) -> list[str]:
    """CORS allowlist for a profile. dev defaults to `*`; prod defaults to NO
    cross-origin browser access and warns if a wildcard is configured."""
    if raw is None or not raw.strip():
        raw = "" if profile == "prod" else "*"
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if profile == "prod":
        if "*" in origins:
            print(
                "[config][WARN] ORRERY_PROFILE=prod with ALLOWED_ORIGINS=* — every website "
                "a member visits may read this API from their browser; set an explicit allowlist"
            )
        elif not origins:
            print(
                "[config] prod profile: no ALLOWED_ORIGINS set — cross-origin browser access "
                "disabled (signed server-to-server requests unaffected)"
            )
    return origins


def docs_urls(profile: str) -> dict:
    """FastAPI docs-surface kwargs for a profile: prod serves none of them."""
    if profile == "prod":
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {}


app = FastAPI(
    title=AGENT_NAME,
    description=AGENT_DESCRIPTION,
    lifespan=lifespan,
    redirect_slashes=False,
    **docs_urls(ORRERY_PROFILE),
)
ALLOWED_ORIGINS = resolve_cors_origins(ORRERY_PROFILE, os.environ.get("ALLOWED_ORIGINS"))


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Authentication + rate limiting middleware.

    Checks auth headers on protected endpoints.
    Logs auth status on all requests for observability.
    """
    method = request.method
    path = request.url.path

    # Rate limiting — write methods (default 30/min, with per-path
    # tighter ceilings for expensive endpoints like /api/digest/build)
    # + enumerable GET paths (60/min). Same per-IP bucket; lowest-ceiling
    # fires first.
    # Hashed HERE, once, on the way into the limiter. The bucket store, its
    # periodic snapshot and the boot restore then all deal in the same opaque
    # id, and no client IP is ever held in a structure that gets persisted.
    client_ip = _rate_limit_bucket_key(client_ip_for_rate_limit(request))
    if method in ("POST", "PATCH", "DELETE"):
        # Per-path tight ceiling wins when set.
        tight = _expensive_write_ceiling(path) if method == "POST" else None
        ceiling = tight if tight is not None else RATE_LIMIT_MAX
        if not check_rate_limit(client_ip, max_requests=ceiling):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded.",
                    "limit_per_window": ceiling,
                    "window_seconds": RATE_LIMIT_WINDOW,
                },
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )
    elif method == "GET" and _is_rate_limited_get_path(path):
        if not check_rate_limit(client_ip, max_requests=RATE_LIMIT_GET_MAX):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded.", "retry_after_seconds": RATE_LIMIT_WINDOW},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )

    # Read auth headers FIRST — the openclaw version gate below
    # needs them even when the path is "open" (e.g. POST /api/members
    # is self-signed-open, but we still must block openclaw clients
    # below the minimum version before the registration handler runs).
    headers = dict(request.headers)
    body = ""
    if method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()
        body = body_bytes.decode("utf-8", errors="replace")

    # OpenClaw skill version gate — runs BEFORE the auth-open-path
    # short-circuit so that POST /api/members (a self-signed-open
    # endpoint) is also gated. For TOFU register we peek the body's
    # `origin` field; for everything else we use the stored origin
    # once auth resolution has run below.
    pre_auth_origin = ""
    if method == "POST" and path in ("/api/members", "/api/members/"):
        try:
            import json as _json_mod

            body_doc = _json_mod.loads(body) if body else {}
            if isinstance(body_doc, dict):
                pre_auth_origin = str(body_doc.get("origin", "")).strip()
        except (ValueError, TypeError):
            pre_auth_origin = ""
    if pre_auth_origin == "openclaw":
        gate = auth_verify.check_openclaw_version(headers, pre_auth_origin)
        if gate is not None:
            metrics.record_request(method, 426)
            return JSONResponse(status_code=426, content=gate)

    # Auth verification — open paths short-circuit here (post-gate).
    if auth_verify.is_open_path(method, path):
        # ⚠️ IDENTITY-AWARE OPEN PATHS. A few open documents serve MORE
        # to a caller who signed than to a stranger — the catalog lists members
        # only to a verified caller, and the portal layout renders its member
        # section only for one. The short-circuit above is what made that
        # impossible: it returns before verify_request runs, so
        # request.state.agent_id is never set and the handler cannot tell a
        # signed member from anyone else.
        #
        # This does NOT gate anything and must not: the result is used only to
        # POPULATE identity, never to reject. An absent, malformed or invalid
        # signature leaves the path exactly as open as it was — which is why the
        # path stays declared in OPEN_PATHS rather than being quietly removed
        # from it. Removing it would have worked, and would have made its
        # openness implicit again, which is the mistake with the reasoning
        # written down.
        if auth_verify.is_identity_aware_open_path(method, path) and auth_verify.has_signature_headers(headers):
            raw = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            ok, caller, _reason = auth_verify.verify_request(body, headers, method=method, url_path=raw)
            ok = ok and _signer_is_member(caller, path)
            if ok:
                request.state.agent_id = caller
                request.state.verified = True
                # A TOFU bootstrap can happen HERE too — `verify_request` stores
                # the header's key whatever path invoked it. The auth-gated
                # branch below has recorded and now persists that event since
                # spec/0.2 §3.1; this one recorded nothing, so the same
                # bootstrap was durable or invisible depending only on which
                # path the member's first signed request happened to hit.
                if _reason == "tofu_accepted":
                    await _on_tofu_established(caller, headers, method=method, path=path)
        response = await call_next(request)
        response.headers["X-Auth-Status"] = "open"
        return response

    # v0.3: pass method + url_path so the canonical string can bind them.
    # url_path is the request-line path including query string per
    # spec/0.3/signing.md. v0.2 / hmac requests ignore these.
    raw_path = request.url.path
    if request.url.query:
        raw_path = f"{raw_path}?{request.url.query}"
    # C4: internal mutating API requires the method-bound scheme (v0.3); the A2A
    # interop POSTs (/a2a, /run) are exempt. Policy decided on the bare path.
    require_method_binding = auth_verify.enforce_method_binding(method, request.url.path)
    valid, agent_id, reason = auth_verify.verify_request(
        body, headers, method=method, url_path=raw_path, require_method_binding=require_method_binding
    )
    # A VALID SIGNATURE IS NOT MEMBERSHIP. Outside the A2A interop surfaces a
    # verified caller is read as "this member" by every handler downstream, so
    # the id has to BE one. A key pinned by a TOFU bootstrap on /run, or a
    # member later removed, otherwise carries a working signature into the
    # gates that exist to keep non-members out.
    if valid and not _signer_is_member(agent_id, path):
        valid, reason = False, "not_a_member"
    # `not_a_member` is the operator's word (metrics, audit); on the wire it is
    # `no_stored_key`, the closed-set reason for "this org holds no member key
    # for that id" — a key pinned on the interop surfaces is not one, and a
    # removed member's is no longer one. spec/0.5/signing.md step 5 closes the
    # set of 401 reasons; a string outside it is a conformance defect and, here,
    # would also tell a stranger which ids have a key on file without being
    # members. test_wire_reasons_closed_set.py holds every reason to the set.
    wire_reason = "no_stored_key" if reason == "not_a_member" else reason

    # Propagate the VERIFIED identity to the request so handlers read the caller
    # from request.state.agent_id (set here only on a valid Ed25519 signature),
    # never from the spoofable X-Agent-ID header. _resolve_caller depends on this
    # — without it, every per-identity authorization decision trusts a header.
    if valid:
        request.state.agent_id = agent_id
        request.state.verified = True

    if auth_verify.requires_auth(method, path):
        # admin break-glass. A few admin POSTs (e.g. /api/invites) authorize
        # a valid X-Admin-Token bearer in their own _authorize_role, but the global
        # signature gate would 401 a bearer-only request before the handler runs.
        # Let a VALID bearer through for those paths; the handler still enforces
        # role. The signed path is untouched — a valid signature sets `valid` above
        # and never reaches this branch.
        _admin_bearer_ok = (
            not valid
            and auth_verify.is_admin_bearer_path(method, path)
            and auth_verify.check_admin_token_header(headers)
        )
        # operator break-glass on the auth-gated reads whose authorization
        # rule is simply "an operator of this org" (the member directory). The
        # same operator reads the same rows via GET /admin/api/members.
        _operator_read_ok = (
            not valid
            and not _admin_bearer_ok
            and auth_verify.is_operator_readable_path(method, path)
            and auth_verify.check_admin_token_header(headers)
        )
        # a signature-verified federation peer may read the member
        # directory — that is the cross-org discovery leg
        # (federation_discovery.query_chapter_members). Fail-closed: an
        # allowlisted endpoint is not enough, the peer must sign. A peer that
        # tried and failed is an operational fault, so it is logged loudly
        # rather than folded into a generic 401.
        _peer_ok = False
        _peer_readable = auth_verify.is_federation_peer_readable_path(method, path)
        if not valid and not _admin_bearer_ok and not _operator_read_ok and _peer_readable:
            import federation_signing as _fed_sig

            _peer_ok, _peer_sender, _peer_reason = await _fed_sig.verify_peer_request(
                method, raw_path, headers, federation
            )
            if not _peer_ok and _peer_reason != "missing_origin":
                print(
                    f"[federation] peer read REJECTED: {method} {path} from "
                    f"{_peer_sender or 'unknown'!r} — {_peer_reason}"
                )
        if not valid and not _admin_bearer_ok and not _operator_read_ok and not _peer_ok:
            # For DELETE, check agent_id matches path
            if method == "DELETE" and "/api/members/" in path:
                path_agent_id = path.split("/api/members/")[-1].strip("/")
                if agent_id and agent_id != path_agent_id:
                    metrics.record_request(method, 403)
                    return JSONResponse(status_code=403, content={"error": "Cannot delete another agent's membership"})
            if reason == "missing_agent_id" or reason == "missing_signature":
                metrics.record_signing_failure(reason)
                metrics.record_request(method, 401)
                return JSONResponse(status_code=401, content={"error": "Authentication required", "detail": reason})
            # spec/0.2 §3.1 — `key_mismatch` is a discrete failure mode separate
            # from invalid_signature. An attacker probing with random keypairs
            # gets the explicit reason; auditors can filter on it.
            if reason in (
                "invalid_signature",
                "expired_timestamp",
                "no_stored_key",
                "key_mismatch",
                "not_a_member",
            ):
                metrics.record_signing_failure(reason)
                if reason == "key_mismatch":
                    metrics.record_key_mismatch()
                if reason == "expired_timestamp":
                    metrics.record_replay_rejection()
                metrics.record_request(method, 401)
                return JSONResponse(status_code=401, content={"error": "Invalid authentication", "detail": wire_reason})
            # Fail CLOSED. Any OTHER non-valid reason on a require-auth path —
            # method_binding_required (C4), nonce_replay, unknown_sig_scheme,
            # missing/invalid_timestamp, missing_nonce, invalid_did_key,
            # the closed-set fallback — must reject, never fall through. A
            # `tofu_accepted` result sets valid=True and never reaches this
            # block, so there is no legitimate "invalid but continue" case; the
            # old implicit fall-through here let these reasons pass unauthenticated.
            if reason == "nonce_replay":
                metrics.record_replay_rejection()
            metrics.record_signing_failure(reason)
            metrics.record_request(method, 401)
            return JSONResponse(status_code=401, content={"error": "Invalid authentication", "detail": wire_reason})
        elif reason == "tofu_accepted":
            await _on_tofu_established(agent_id, headers, method=method, path=path)
    elif auth_verify.is_warn_path(method, path) and not valid:
        print(f"[Auth] WARN: unsigned {method} {path} from {agent_id or 'unknown'} ({reason})")

    # OpenClaw skill version gate. Block any openclaw-origin client
    # whose `X-Openclaw-Skill-Version` is missing or below the server's
    # configured minimum. This neutralizes pre-0.5.1 openclaw-skill
    # versions whose helpers carry confirmed vulnerabilities — they
    # cannot reach any server endpoint regardless of whether their
    # ed25519 signature is otherwise valid.
    #
    # Resolution of `origin`:
    #   - POST /api/members  → peek body's `origin` field (TOFU register)
    #   - Otherwise          → stored `members[agent_id]["origin"]`
    effective_origin = ""
    if method == "POST" and path in ("/api/members", "/api/members/"):
        try:
            import json as _json_mod

            body_doc = _json_mod.loads(body) if body else {}
            if isinstance(body_doc, dict):
                effective_origin = str(body_doc.get("origin", "")).strip()
        except (ValueError, TypeError):
            effective_origin = ""
    elif agent_id:
        member = members.get(agent_id) or {}
        effective_origin = str(member.get("origin", "")).strip()

    if effective_origin == "openclaw":
        gate = auth_verify.check_openclaw_version(headers, effective_origin)
        if gate is not None:
            metrics.record_request(method, 426)
            return JSONResponse(status_code=426, content=gate)

    response = await call_next(request)
    # The stamp says whether the middleware verified a signature, and no more.
    # It used to carry the failure reason (`unverified:no_stored_key` vs
    # `unverified:invalid_signature`), which on an identity-aware OPEN path —
    # where the body is the same for everyone — told an unauthenticated
    # caller whether an agent_id has a stored key. The spec's closed reason
    # set governs the 401 BODY on gated paths (spec/0.5/signing.md); response
    # headers are not part of it, so nothing is owed here. The specific
    # reason still reaches the operator through metrics.record_signing_failure.
    response.headers["X-Auth-Status"] = "verified" if valid else "unverified"
    metrics.record_request(method, response.status_code)
    return response


# CORS must be the OUTERMOST middleware: Starlette wraps in reverse
# add-order, so registering it AFTER auth_middleware means every response —
# including the 401s/403s the auth layer emits directly — passes back through
# the CORS layer and carries its headers. Registered before this move, a
# cross-origin browser saw auth rejections as opaque network errors and could
# not tell "unauthorized" from "server down". Auth semantics are unchanged;
# CORS preflights (OPTIONS) are handled by the CORS layer without auth, which
# is the spec behavior — preflights are unauthenticated by design.
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["*"], allow_headers=["*"])


# ── Public-read CORS ─────────────────────────────────────────────────
# The keyless PUBLIC GET surfaces are world-readable by design, so they carry
# Access-Control-Allow-Origin: * regardless of ORRERY_PROFILE — a browser
# dashboard on any origin can read them. Everything else keeps the restricted
# CORSMiddleware allowlist above (empty in prod). Scoped to GET/HEAD/OPTIONS so
# authenticated POSTs on a shared prefix (e.g. /api/federation/broadcast/inbox)
# never receive the wildcard; the sensitive operation is the POST, which is not
# matched here.
_PUBLIC_CORS_PATHS = frozenset({"/health", "/api/events", "/api/digest", "/agentfacts.json", "/.well-known/agent.json"})
_PUBLIC_CORS_PREFIXES = ("/api/federation", "/.well-known/")


def _is_public_cors_path(path: str) -> bool:
    return path in _PUBLIC_CORS_PATHS or any(path.startswith(p) for p in _PUBLIC_CORS_PREFIXES)


@app.middleware("http")
async def public_read_cors(request: Request, call_next):
    """Force ACAO:* on the keyless public GET surfaces (see that change). Runs
    outermost (added after CORSMiddleware), so it can answer their OPTIONS
    preflight and stamp the read response even when the profile allowlist is
    empty."""
    is_public = request.method in ("GET", "HEAD", "OPTIONS") and _is_public_cors_path(request.url.path)
    if is_public and request.method == "OPTIONS":
        # Unauthenticated preflight for a public read — answer it directly.
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": request.headers.get("access-control-request-headers", "*"),
                "Access-Control-Max-Age": "600",
            },
        )
    response = await call_next(request)
    if is_public:
        # Overrides any echo the CORSMiddleware set; * is correct for keyless,
        # credential-less reads (no Allow-Credentials is ever set here).
        response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ============================================================
# SURFACE BUILDERS — delegated to surfaces.py
# ============================================================
def _unsupported_a2ui_version_response(exc: surfaces.UnsupportedSchemaVersion) -> JSONResponse:
    """400 for an A2UI `?schema=` value this chapter cannot emit.

    Structured so a client can act on it: the version it asked for and the
    closed set it may choose from — the same set `/api/version` advertises in
    `a2ui_versions`. A 400 here is the point of the fix; the old behaviour was
    to serve the default version and let the caller discover the mismatch at
    render time, if at all.
    """
    return JSONResponse(
        status_code=400,
        content={
            "error": "unsupported_a2ui_version",
            "detail": str(exc),
            "requested": exc.requested,
            "supported": list(exc.supported),
        },
    )


@app.get("/api/surfaces/{page_id}", response_model=None)
async def get_surface_endpoint(
    page_id: str,
    request: Request,
    target: str | None = None,
    schema: str | None = None,
) -> dict | JSONResponse:
    """Universal A2UI surface endpoint — agents own every page.

    schema: optional wire-version selector, with or without the leading 'v'.
    '0.8' returns the OpenClaw Canvas-compatible envelope, '0.9' the native
    envelope with every `meta` block stripped (spec/0.4/a2ui.md §8 item 3),
    '0.10' or None the native envelope. Any other value is a 400
    `unsupported_a2ui_version` — never a silent fallback to the default, since
    a caller naming a version is saying it cannot handle the others.

    Self-scoped surfaces (``today``, ``advisor-earnings``): the caller's
    verified did:key replaces any client-supplied ``target`` so a caller cannot
    view another principal's surface. For ``today`` the middleware-level auth
    requirement is declared in auth_verify.REQUIRE_AUTH_GET_PATHS; an
    unauthenticated caller resolves to ``target=None``, which every builder in
    this set renders as its no-data prompt rather than another principal's data.
    """
    # The activity-feed PII closure residual: advisor-earnings joined this set once the three surfaces the
    # original triage left "unconfirmed" were re-examined. Its builder passes
    # ``target`` straight to skill_revenue.get_earnings_for_did, so before this an
    # unauthenticated caller supplying any did:key got that principal's all-time
    # and 7-day earnings, ledger entry count and per-role breakdown. The earlier
    # probe recorded it CLEAN because it called the route with NO target, which
    # returns only the "Pass ?target=<your did:key>" prompt.
    if page_id in ("today", "advisor-earnings"):
        caller = _resolve_caller(request)
        if not caller:
            target = None
        else:
            safe_id = sanitize_agent_id(caller)
            stored = auth_verify._agent_keys.get(safe_id, {}) if safe_id and hasattr(auth_verify, "_agent_keys") else {}
            pubkey = stored.get("ed25519_pubkey") or ""
            target = sovereign_identity.build_did_key_from_ed25519(pubkey) if pubkey else None
    # Admin-aware surfaces (approvals, authority) embed full operator detail
    # only when the request carries a valid admin token; otherwise they serve
    # the redacted safe-projection floor. The bearer check is the lightweight
    # boolean form of _authorize_admin's path 2 — no deny-flow needed, we just
    # want "is a valid admin token present". The streaming variant cannot send
    # headers, so it always gets admin_verified=False (safe-projection).
    admin_verified = auth_verify.check_admin_token_header(dict(request.headers))
    try:
        return await surfaces.get_surface(page_id, target, schema, admin_verified=admin_verified)
    except surfaces.UnsupportedSchemaVersion as exc:
        return _unsupported_a2ui_version_response(exc)


@app.get("/api/surfaces/{page_id}/stream")
async def stream_surface_endpoint(
    page_id: str,
    target: str | None = None,
    schema: str | None = None,
    interval_seconds: float = 5.0,
    max_iterations: int | None = None,
):
    """AG-UI streaming variant of `/api/surfaces/{page_id}`.

    Server-Sent Events. Wire format: AG-UI v1 — `RunStarted`,
    `StateSnapshot`, `StateDelta`, `RunFinished` events. Frontend
    consumers can patch the rendered surface in place instead of
    re-fetching on a 30 s poll.

    Query params:
      target / schema       — same as the JSON endpoint
      interval_seconds      — between fetcher cycles. Default 5 s.
                              Clamped to [1, 60].
      max_iterations        — None for an indefinite stream (closes
                              when client disconnects), else stop after
                              N cycles. Useful for tests + bounded jobs.

    Cancellation: when the consumer disconnects, FastAPI closes the
    underlying generator and the loop exits cleanly.
    """
    # Principal-private surfaces (today) are served per-caller from the
    # auth-verified did:key. SSE cannot carry an X-Agent-Signature header, so
    # there is no way to authenticate the principal here — refuse rather than
    # honor a client-supplied `target` (which would leak another principal's
    # receipts). Use GET /api/surfaces/today (signed) for the JSON form.
    if page_id in ("today",):
        return JSONResponse(
            status_code=403,
            content={
                "error": "auth_required",
                "detail": "The Today surface is principal-private and cannot be streamed; "
                "fetch GET /api/surfaces/today with a signed request.",
            },
        )

    # Validate the wire-version selector BEFORE the stream opens: once
    # StreamingResponse is returned the status line is already 200, so a bad
    # selector could only be reported as an in-band SSE error the consumer may
    # never surface. Fail as a real 400 instead.
    try:
        surfaces.normalize_schema_selector(schema)
    except surfaces.UnsupportedSchemaVersion as exc:
        return _unsupported_a2ui_version_response(exc)

    from fastapi.responses import StreamingResponse

    import agui_streaming

    interval = max(1.0, min(60.0, float(interval_seconds or 5.0)))
    cap = max_iterations if max_iterations is None else max(1, min(10000, int(max_iterations)))

    async def fetcher() -> dict:
        return await surfaces.get_surface(page_id, target, schema)

    return StreamingResponse(
        agui_streaming.stream_surface_updates(
            fetcher,
            thread_id=f"surface:{page_id}",
            interval_seconds=interval,
            max_iterations=cap,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx/Railway buffering off
            "Connection": "keep-alive",
        },
    )


# ── Surface Composer endpoint (GenUI-2) ────────────────────────────


class ComposeSurfaceRequest(BaseModel):
    """User intent + optional context items.

    `context_items` are short trusted strings (e.g. \"name: alice\",
    \"skills: python, climate\") the composer injects into the LLM
    user message. Treat them like the trusted bucket from the v2
    planner — they shape the surface but content is never executed.
    """

    intent: str
    context_items: list[str] = []
    # Optional: skip cache for this call (e.g. iterative dev).
    bypass_cache: bool = False


@app.post("/api/surfaces/compose")
async def compose_surface_endpoint(req: ComposeSurfaceRequest) -> dict:
    """Generative surface — LLM composes a custom A2UI v0.9 surface
    from `intent`. Caches by sha256(intent + sorted context_items)
    with 1h TTL so repeat asks don't burn LLM tokens.

    Wire shape:
      {
        \"surface\": <A2UI v0.9 envelope>,
        \"cache_hit\": bool,
        \"unknown_components\": [...],   // stripped by the whitelist
        \"dangling_references\": [...],  // pruned references
        \"raw_component_count\": int,
        \"final_component_count\": int
      }

    400 — empty intent or invalid input
    422 — pydantic rejects the request body

    Never 500s on an LLM hiccup: for an otherwise-valid request, an
    `sc.CompositionError` OR any LLM/network `Exception` during compose
    is caught and the endpoint returns HTTP 200 with the deterministic
    "default shell" (`sc.fallback_surface`) plus `"fallback": true` and
    a short `"reason"`. The caller always gets a renderable surface —
    that IS the "safe fallback to the default shell". Only input
    validation (empty / oversized intent) still returns 4xx.
    """
    import surface_composer as sc

    intent = (req.intent or "").strip()
    if not intent:
        raise HTTPException(status_code=400, detail="intent required")
    if len(intent) > 1000:
        raise HTTPException(status_code=400, detail="intent too long (>1000 chars)")

    context = tuple((req.context_items or [])[:10])

    def _fallback(reason: str) -> dict:
        """Graceful 200 fallback. `sc.fallback_surface` is pure and
        cannot raise, so this response is always well-formed."""
        result = sc.fallback_surface(reason)
        return {
            "surface": result.surface,
            "cache_hit": False,
            "unknown_components": list(result.unknown_components),
            "dangling_references": list(result.dangling_references),
            "raw_component_count": result.raw_component_count,
            "final_component_count": result.final_component_count,
            "fallback": True,
            "reason": reason[:200],
        }

    # No provider configured ⇒ do not call one. Provider detection falls through
    # to a default when no key is set, so the client is pointed at a real remote
    # endpoint the operator never chose; calling it would send `intent` there and
    # get a 401 back. Serving the shell here means a chapter with no key makes no
    # outbound request at all, which is what the configuration docs promise.
    if not llm_config.planner_enabled():
        return _fallback("planner_disabled: no provider key configured — no request was made")

    try:
        if req.bypass_cache:
            result = sc.compose(intent, llm=llm, model=DEFAULT_LLM_MODEL, context_items=context)
            cache_hit = False
        else:
            result, cache_hit = sc.compose_cached(
                intent,
                llm=llm,
                model=DEFAULT_LLM_MODEL,
                context_items=context,
            )
    except sc.CompositionError as e:
        return _fallback(f"composition_failed: {e}")
    except Exception as e:  # noqa: BLE001 — LLM/network errors degrade to the default shell, never 500
        return _fallback(f"llm_error: {type(e).__name__}: {e}")

    return {
        "surface": result.surface,
        "cache_hit": cache_hit,
        "unknown_components": list(result.unknown_components),
        "dangling_references": list(result.dangling_references),
        "raw_component_count": result.raw_component_count,
        "final_component_count": result.final_component_count,
    }


# ============================================================
# ENDPOINTS
# ============================================================


class A2AContent(BaseModel):
    type: str = "text"
    text: str


class A2ARequest(BaseModel):
    role: str = "user"
    content: A2AContent
    conversation_id: str = ""
    message_id: str = ""
    target_agent: str | None = None  # NANDA Adapter compatibility: explicit target


class A2AResponse(BaseModel):
    role: str = "assistant"
    content: A2AContent
    conversation_id: str
    message_id: str
    a2ui: dict | None = None


_VALID_ORIGINS = frozenset({"sovereign", "openclaw", "openclaw_sandboxed"})

# Public-listing gate.
#
# Conformance test R3 (test_register.py) deliberately registers
# `TEST-injection-*` agents to verify the server sanitizes hostile input
# without 5xx-ing. The server accepts the registration (R3 is happy with
# either accept-and-sanitize or reject), so these agents end up in the
# in-memory `members` dict. Same for `TEST-conformance-*` from R5 boundary
# tests and TEST-* seed members from orgs.json.
#
# That's fine for the server's internal state — but `GET /api/members`
# and `GET /api/thoughts` are unauthenticated public surfaces, and any
# external caller (journalist, LLM scraper, hostile dev) sees the full
# member list including the test artifacts. Pre-launch audit found the
# bayarea production server serving entries like
# `TEST-injection-DROPTABLEagents--` and `TEST-injection-scriptalert1script`
# as visible community members. Any screenshot of that ships poorly.
#
# This constant gates EVERY public listing surface (members directory,
# thoughts feed, member-card lookups). The server is free to reference
# these agents internally — federation, governance, conformance — but
# they never leak into a publicly-rendered list.
_PUBLIC_HIDDEN_PREFIXES: tuple[str, ...] = ("TEST-",)


def _hidden_from_public_listing(agent_id: str) -> bool:
    """True iff this agent_id should be filtered from public read surfaces."""
    return any(agent_id.startswith(p) for p in _PUBLIC_HIDDEN_PREFIXES)


def _member_disclosable_to(agent_id: str, request: Request | None) -> bool:
    """Whether a per-member read may answer THIS caller about THIS member.

    The rule the profile route established, stated once so the routes that
    reshape a member row cannot each decide it differently: a member is
    disclosed to a stranger only if they opted in (``member_listing.consent_of``);
    a signed caller may read any member; hidden-prefix ids are never disclosed.
    Every route that consults this answers a refusal EXACTLY as it answers an
    unknown id — otherwise the gate closes a disclosure and opens a membership
    oracle in its place. Callers must therefore branch on this predicate before
    they have said anything that distinguishes the two.
    """
    if _hidden_from_public_listing(agent_id) or agent_id not in members:
        return False
    if member_listing.consent_of(members[agent_id]) is not None:
        return True
    return bool(request is not None and _resolve_caller(request))


class MemberRegistration(BaseModel):
    agent_id: str
    name: str
    description: str = ""
    endpoint: str = ""
    skills: list[str] = []
    personality: str = ""
    voice: str = "helpful"
    virtual: bool = True
    public_key: str = ""
    # endpoint runtime type — see migration 20260428_openclaw_origin.sql
    # 'openclaw' agents get reduced trust + leader-gated actions by default
    origin: str = "sovereign"
    # Invite token, required to register under the 'invite' join policy.
    invite_token: str = ""
    # an UNATTENDED service agent declares itself so it lands in the
    # `service` role instead of `member`. Self-declaration is safe here and
    # ONLY here, because `service` is strictly LESS privileged than `member`:
    # it has no social surface, cannot attest, cannot approve, and sees only
    # the operational slice of the approval queue. A self-declared `leader` or
    # `admin` would be privilege escalation by request body; the allow-list
    # below is what keeps this to the one safe direction.
    agent_kind: str = "member"


# ── Join policy (piece 1) ─────────────────────────────────────────────
# open (default, today's behavior) | invite (valid token required) | approval
# (leader must approve; NO member/key created until then). Stored in org-config.
_VALID_JOIN_POLICIES = ("open", "invite", "approval")
# agent_ids currently being materialized from an approved member_admission —
# their internal register call must bypass the join-policy gate (it already
# cleared approval). A set, not a flag, so concurrent admissions don't race.
_approval_admitting: set[str] = set()


def _join_policy() -> str:
    """The org's join policy from org-config; defaults to 'open' (non-breaking)."""
    pol = str(_load_org_config().get("join_policy", "open")).strip().lower()
    return pol if pol in _VALID_JOIN_POLICIES else "open"


def resolve_handle(handle: str) -> tuple[str | None, str | None]:
    """Resolve a @agent_id@domain handle to (agent_id, endpoint).

    Returns (agent_id, None) for local agents, (agent_id, endpoint) for federated,
    or (None, None) if unresolvable.
    """
    handle = handle.lstrip("@")
    if "@" in handle:
        agent_id, domain = handle.split("@", 1)
        # Check if domain matches us
        from urllib.parse import urlparse

        our_domain = urlparse(PUBLIC_URL).netloc if PUBLIC_URL else ""
        if domain == our_domain or domain == "localhost":
            return agent_id, None  # Local
        # Look up in federation
        for _fid, finfo in federation.items():
            fendpoint = finfo.get("endpoint", "")
            if domain in fendpoint:
                return agent_id, fendpoint
        return agent_id, None  # Unknown domain, try local anyway
    return handle, None  # No domain, local


@app.post("/a2a")
@app.post("/a2a/")
async def a2a_endpoint(request: A2ARequest) -> A2AResponse:
    _a2a_start = time_mod.monotonic()
    conversation_id = sanitize_text(request.conversation_id, 100) or str(uuid.uuid4())
    safe_text = sanitize_text(request.content.text, 2000)

    # NANDA Adapter compatibility: route to target_agent if specified
    if request.target_agent:
        agent_id, endpoint = resolve_handle(request.target_agent)
        if endpoint:
            # Forward to federated agent
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{endpoint.rstrip('/')}/a2a",
                        json={
                            "role": "user",
                            "content": {"type": "text", "text": safe_text},
                            "conversation_id": conversation_id,
                            "target_agent": agent_id,
                        },
                        timeout=15.0,
                    )
                    data = resp.json()
                    return A2AResponse(
                        content=A2AContent(text=data.get("content", {}).get("text", "Forwarded")),
                        conversation_id=conversation_id,
                        message_id=str(uuid.uuid4()),
                    )
            except Exception as e:
                return A2AResponse(
                    content=A2AContent(text=f"Failed to forward to {request.target_agent}: {e}"),
                    conversation_id=conversation_id,
                    message_id=str(uuid.uuid4()),
                )
        elif agent_id and agent_id in members:
            safe_text = f"@{agent_id} {safe_text}"

    response_text, a2ui_data = await agent_logic(safe_text, conversation_id)
    agent_telemetry.record_request((time_mod.monotonic() - _a2a_start) * 1000)
    return A2AResponse(
        content=A2AContent(text=response_text),
        conversation_id=conversation_id,
        message_id=str(uuid.uuid4()),
        a2ui=a2ui_data,
    )


def _extract_run_text(message: dict) -> str:
    """Pull text from an A2A message's ``parts``.

    Robust to the live wire shape: the NANDA resolver/demo send parts as bare
    ``{"text": ...}`` with NO ``kind``/``type`` key; we also accept explicit
    ``kind``/``type`` == "text". Any part carrying a ``text`` string contributes;
    multiple text parts are space-joined.
    """
    if not isinstance(message, dict):
        return ""
    texts: list[str] = []
    for part in message.get("parts") or []:
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            texts.append(part["text"])
    return " ".join(t for t in texts if t).strip()


@app.post("/run")
@app.post("/run/")
async def run_endpoint(request: Request) -> JSONResponse:
    """Standard A2A invoke: ``POST <card.url>/run`` with
    ``{"message":{"role","parts":[{"text"}]}}`` → ``agent_logic`` → A2A task result.

    Auth is identical to ``/a2a``: the middleware enforces the Ed25519 signed-by-
    caller layer (``/run`` is REQUIRE in auth_verify), so unsigned→401,
    tampered→401, signed→200. The body is already read + signature-verified by
    the middleware; we re-read the cached body here to extract the prompt.
    """
    _run_start = time_mod.monotonic()
    try:
        payload = await request.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    _msg = payload.get("message")
    message = _msg if isinstance(_msg, dict) else {}
    text = sanitize_text(_extract_run_text(message), 2000)
    task_id = sanitize_text(str(payload.get("id") or ""), 100) or str(uuid.uuid4())

    response_text, _a2ui = await agent_logic(text, task_id)
    agent_telemetry.record_request((time_mod.monotonic() - _run_start) * 1000)
    return JSONResponse(
        content={
            "id": task_id,
            "status": {"state": "completed"},
            "artifacts": [{"name": "response", "parts": [{"kind": "text", "text": response_text}]}],
        }
    )


@app.post("/a2a/@{agent_handle}")
async def a2a_handle_endpoint(agent_handle: str, request: A2ARequest) -> A2AResponse:
    """NANDA Adapter compatibility: route via @handle in URL path."""
    request.target_agent = agent_handle
    return await a2a_endpoint(request)


# ── What a registrant is told about publication ─────────────────────────────
#
# `description` and `skills` are free text the registrant writes, and NOTHING
# told them where it goes. An audit put an email address and a phone
# number in a description and both came back to an UNAUTHENTICATED GET. The
# anonymous surfaces are closed as of the member-directory closure, but the field is still
# published to every signed member of the org, to federation peers, and — once
# a card is published — through the org's catalog and each member's AgentFacts,
# which are documents the org hands to crawlers.
#
# Closing a surface does not un-write what somebody already typed, so the fix
# that lasts is telling them at the point they type it. Returned on every
# successful registration rather than buried in docs: the registrant is a
# program as often as a person, and a program can act on a field.
PUBLICATION_NOTICE = {
    "published_fields": ["name", "description", "skills", "endpoint"],
    "audience": "every signed member of this org, federation peers, and any crawler that resolves this member's AgentFacts or catalog entry",
    "detail": (
        "The name, description, skills and endpoint you supplied are PUBLISHED. Do not put "
        "an email address, phone number, postal address or anything else private in them. "
        "There is no per-member opt-out today."
    ),
}


@app.post("/api/members", response_model=None)
@app.post("/api/members/", response_model=None)
async def register_member(reg: MemberRegistration) -> dict | JSONResponse:
    # Sanitize all inputs
    safe_id = sanitize_agent_id(reg.agent_id)
    safe_name = sanitize_text(reg.name, 100)
    safe_desc = sanitize_text(reg.description, 500)
    safe_personality = sanitize_text(reg.personality, 500)
    safe_skills = [sanitize_text(s, 50) for s in reg.skills[:20]]
    if not safe_id or not safe_name:
        return {"error": "agent_id and name required"}

    # Validate origin. Default is sovereign; invalid values reject rather than
    # silently coerce — we need origin integrity for governance routing.
    raw_origin = (reg.origin or "sovereign").strip().lower()
    if raw_origin not in _VALID_ORIGINS:
        return {"error": f"invalid origin: must be one of {sorted(_VALID_ORIGINS)}"}
    origin = raw_origin

    existing = members.get(safe_id)

    # Origin is immutable once set — a registered sovereign agent cannot be
    # re-registered as openclaw to downgrade trust, and vice versa. This also
    # prevents an openclaw agent from upgrading itself to sovereign by lying.
    if existing and existing.get("origin") and existing["origin"] != origin:
        return {
            "error": f"origin mismatch: agent already registered as {existing['origin']}",
            "existing_origin": existing["origin"],
        }

    # Key-change protection (account-takeover guard, P0). /api/members is
    # open-pathed — the auth middleware does NOT run for it — so re-registration
    # is the one place a caller can change a stored agent's identity. Changing
    # the public_key of an EXISTING agent is a key ROTATION and must be
    # self-signed by the OLD key: that flow is POST /api/members/rotate, which
    # verifies a rotation attestation. Plain re-registration must NOT silently
    # overwrite the auth key — that was full account takeover (an unauthenticated
    # POST swapping in an attacker's pubkey, after which they sign as the victim
    # everywhere). Same-key re-registration (idempotent profile update),
    # key-omitted updates, and first registration are all unaffected.
    existing_key = (existing or {}).get("public_key", "")
    if existing_key and reg.public_key and reg.public_key != existing_key:
        return JSONResponse(
            status_code=403,
            content={
                "error": "key_change_requires_rotation",
                "detail": (
                    "Changing a registered agent's key is a signed rotation; "
                    "use POST /api/members/rotate (attested by the current key)."
                ),
            },
        )

    # C2 — the guard above only fires on a NON-EMPTY stored key, so a member with
    # none is not protected by it at all: every re-registration could set a
    # different key, forever, silently. Pin the first one instead.
    #
    # Deliberately NOT a refusal. Refusing a key for a member whose key cannot be
    # established locks them out of their own account with no way back — they
    # cannot re-register (refused) and cannot rotate either, because
    # /api/members/rotate returns `no stored key for this agent`. The population
    # that would hit it is the one we cannot size without a read credential.
    #
    # `_pin_member_key` declines for a member with rotation history, so an
    # attested key is always recovered from `member_key_rotations` rather
    # than overwritten by a claim. It is fire-and-forget for the same reason the
    # persist below is: the in-memory key is set either way, and a Postgres
    # hiccup must not fail a registration.
    _pin_this_key = bool(existing and not existing_key and reg.public_key)

    # ── Join policy gate — only for NEW joins, never re-registration /
    # profile updates / key-omitted updates (those keep working under any policy).
    if not existing and safe_id not in _approval_admitting:
        policy = _join_policy()
        if policy == "invite":
            if not await invites_mod.consume(reg.invite_token, agent_id=safe_id):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "invite_required",
                        "detail": "This org requires a valid invite to join. Ask an admin or leader for one.",
                    },
                )
        elif policy == "approval":
            # Create NO member/key yet — a pending member with a recorded key
            # could sign before approval (the open /api/members path has no
            # active-status auth gate). Stash the claimed identity in the
            # approval; materialize on leader approve.
            from datetime import timedelta

            import governance

            appr = await governance.propose(
                "member_admission",
                proposer_agent_id=safe_id,  # the joining agent proposes its own admission
                payload={
                    "agent_id": safe_id,
                    "name": safe_name,
                    "description": safe_desc,
                    "skills": safe_skills,
                    "public_key": reg.public_key,
                    "origin": origin,
                },
                ttl=timedelta(days=7),
            )
            return {
                "status": "pending_approval",
                "approval_id": (appr or {}).get("id"),
                "detail": "Your request to join is pending a leader's approval.",
                "publication_notice": PUBLICATION_NOTICE,
            }

    # MERGED over the existing record, not replacing it — the in-memory
    # counterpart of the `config` jsonb merge in `_persist_member_to_db`, and
    # needed for the same reason. Registration owns exactly the keys written
    # below; a member record also carries keys OTHER writers own — the Listing
    # consent (`member_listing.CONSENT_KEY`), the host39 publication record,
    # `is_demo`, `profile_type`. Replacing the dict wholesale deleted all of
    # them from the running process on every re-registration, so a consenting
    # member silently dropped out of the live Listing until the next restart
    # rehydrated them. Merging fixes that window; the config merge fixes the
    # durable half. Fixing only one of the two leaves the process and the row
    # disagreeing, which is how this whole class of defect stayed invisible.
    members[safe_id] = {
        **(existing or {}),
        "name": safe_name,
        # `description` and `skills` fall back to the stored values for the same
        # reason `endpoint` and `public_key` do: the request model defaults them,
        # so a profile-only re-registration that simply does not mention them
        # used to ERASE them. That was invisible while the upsert was broken —
        # nothing was written — and became a durable loss of member-authored
        # profile data the moment it was repaired. Supplying either field still
        # replaces it; only omission preserves.
        "description": safe_desc or (existing or {}).get("description", ""),
        "skills": safe_skills or (existing or {}).get("skills", []),
        # Falls back to the stored endpoint exactly as `public_key` does two
        # lines below. Without this, a profile-only re-registration — one that
        # simply omits `endpoint`, which the model defaults to "" — WIPED the
        # member's endpoint from the running process while the durable row kept
        # it. For the window between that re-registration and the next restart
        # the member was catalog-omitted, unresolvable to the co-sign broker,
        # and A2A-impersonated by the org's LLM. The next restart then healed it
        # from Postgres.
        #
        # That heal is why no restart-based test could ever have caught this:
        # restarting is the repair. An assertion for this defect has to live
        # entirely inside ONE process — the exact inverse of the across-a-
        # restart rule, and the reason `test_reregistration_preserves_...` in
        # test_member_record_durability.py never boots anything.
        #
        # Deliberate consequence, same as `public_key`: a member cannot CLEAR
        # their endpoint by re-registering without one. Clearing a load-bearing
        # routing field must be an explicit act, not the side effect of omitting
        # a key from a profile update.
        "endpoint": sanitize_text(reg.endpoint, 200) or (existing or {}).get("endpoint", ""),
        "personality": safe_personality,
        "voice": sanitize_text(reg.voice, 20),
        "virtual": reg.virtual,
        "public_key": reg.public_key or (existing or {}).get("public_key", ""),
        "origin": origin,
        # carried through so the persisted row can select the `service`
        # role. Without this the field would exist on the request model and
        # reach nothing — the unreachability class this fix is about.
        "agent_kind": "service" if reg.agent_kind == "service" else "member",
    }

    # Store key for auth verification.
    #
    # A 44-char base64 string is almost certainly an Ed25519 32-byte
    # public key (44 = ceil(32 * 4/3) with one '=' pad). Store it under
    # BOTH the legacy HMAC slot AND the ed25519_pubkey slot so the
    # verify path (which only reads ed25519_pubkey for ed25519 /
    # ed25519+nonce schemes) can find it. Without this, a fresh
    # registration after a server restart sees the X-Agent-DID-Key
    # header and rejects with key_mismatch because the stale TOFU
    # entry doesn't match the new client. This is the "registration
    # silently doesn't update the auth store" bug surfaced 2026-05-10.
    if reg.public_key:
        looks_like_ed25519 = len(reg.public_key) == 44 and reg.public_key.endswith("=")
        if looks_like_ed25519:
            # Use replace_agent_key so the ed25519_pubkey slot is
            # overwritten rather than coalesced with any stale value.
            auth_verify.replace_agent_key(safe_id, reg.public_key)
        else:
            auth_verify.store_agent_key(safe_id, reg.public_key)

    if PUBLIC_URL:
        asyncio.create_task(nanda_registry.register_member(safe_id, members[safe_id], PUBLIC_URL))

    # Persist to Postgres `agents` so the member directory + every
    # downstream surface that reads from the table sees this member
    # immediately. Without this, registrations live ONLY in the
    # in-memory bridge — they survive server restarts via
    # load_persisted_members() only if the row is already in
    # Postgres, which it never is for /api/members registrations.
    #
    # pg_request already sets `Prefer:
    # resolution=merge-duplicates`, so this is upsert by primary key
    # (agent_id). Fire-and-forget — Postgres outage must not 5xx the
    # registration. Bridge writes are the source of truth for live
    # federation; Postgres is the snapshot store for clients.
    #
    # `key_source` is set ONLY for a first registration. A re-registration passes
    # None so the provenance marker already on the row survives — a pinned key
    # must not be relabelled `registered` by its holder's next profile update.
    _first_key = KEY_SOURCE_REGISTERED if (not existing and reg.public_key) else None

    async def _persist_and_pin() -> None:
        # SEQUENCED, not two tasks. Both writers touch `agent_facts`, and the
        # pin declines when a did is already on file — so a persist that landed
        # first would make the pin a no-op and the key would end up on the row
        # with NO provenance marker, i.e. indistinguishable from a registered
        # one. The pin runs first and the persist merges over it.
        if _pin_this_key:
            await _pin_member_key(safe_id, reg.public_key, source=KEY_SOURCE_PINNED_REGISTRATION)
        await _persist_member_to_db(safe_id, members[safe_id], origin, key_source=_first_key)

    asyncio.create_task(_persist_and_pin())

    # feed the quilt delta sync surface — /sm-bridge/deltas carried
    # nothing before this (the DeltaStore existed but no writer did).
    try:
        import sm_bridge_adapter as _smb

        _smb.record_member_delta("upsert", safe_id, members[safe_id])
    except Exception as _e:  # noqa: BLE001
        print(f"[sm-bridge][WARN] quilt delta not recorded for {safe_id!r}: {type(_e).__name__}")

    # Emit member.joined on the event bus (EB-2). Fire-and-forget — a
    # downstream telemetry failure must not 5xx the registration. Skip
    # for re-registrations (only the first time we see this agent counts
    # as a "join"; subsequent calls are usually key-rotation cleanups
    # that have their own member.left/member.joined flow if needed).
    if not existing:
        # try_ variant: reg.public_key is caller-supplied and may be legacy HMAC
        # material — the strict builder now raises on non-Ed25519 input (R4),
        # and the old fallback emitted a malformed DID into this event.
        did_key = (sovereign_identity.try_build_did_key_from_ed25519(reg.public_key) or "") if reg.public_key else ""
        asyncio.create_task(
            event_bus.safe_publish(
                "member.joined",
                {
                    "agent_id": safe_id,
                    "did_key": did_key,
                    "name": safe_name,
                    "skills": safe_skills,
                    "origin": origin,
                    "trust_score": 0.0,
                },
            )
        )

        # ── A1: emit server-signed authority_granted receipt for the
        # new member's first action scope. Per ARP spec §4.6, the server
        # is permitted to emit this on the principal's behalf during
        # onboarding in v0.1 (v0.2 will move this responsibility to the
        # SDK). The grant covers the baseline action categories a server
        # member will routinely take: intent_submitted, message_sent,
        # data_shared. Expires in 1 year unless renewed.
        #
        # The receipt establishes:
        #   - Verifiable consent record (CCPA right-to-know answer)
        #   - Authority-to-operate evidence (DoD ATO adjacent)
        #   - Scope boundary (out-of-scope actions can be flagged by
        #     strict verifiers per spec §4.5)
        #
        # Fire-and-forget — emission failure must not block registration.
        # Sovereign agents (origin=sovereign) get the grant; non-sovereign
        # (openclaw / ephemeral) currently skip — they're issuer-side
        # already, and re-granting authority to a less-trusted runtime
        # would muddle the trust model.
        if origin == "sovereign" and did_key:
            from datetime import UTC, datetime, timedelta

            async def _emit_onboarding_grant() -> None:
                try:
                    import arp as _arp_mod

                    grant_expires_at = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    receipt_id = await _arp_mod.emit_authority_grant(
                        principal_did=did_key,
                        granted_to_did=did_key,  # self-grant: SDK key acts on principal's behalf
                        granted_scope=["intent_submitted", "message_sent", "data_shared"],
                        grant_expires_at=grant_expires_at,
                        human_summary=(
                            f"On joining {AGENT_ID}, I authorize my agent to submit intents, "
                            f"send messages, and share data within the chapter for 1 year."
                        ),
                    )
                    if receipt_id:
                        print(f"  [onboarding-grant] {safe_id}: receipt_id={receipt_id[:8]}...")
                except Exception as e:  # noqa: BLE001
                    print(f"  [onboarding-grant] skipped for {safe_id}: {type(e).__name__}: {e}")

            asyncio.create_task(_emit_onboarding_grant())

    print(f"Member registered: {safe_id} [origin={origin}]" + (" (with key)" if reg.public_key else ""))
    return {
        "agent_id": safe_id,
        "registered": True,
        "chapter": AGENT_ID,
        "origin": origin,
        "publication_notice": PUBLICATION_NOTICE,
    }


class InviteGenerateRequest(BaseModel):
    max_uses: int = 1
    ttl_days: int = 7


@app.post("/api/invites")
@app.post("/api/invites/")
async def create_invite(req: InviteGenerateRequest, request: Request):
    """Generate an invite token (admin/leader). Single-use + 7-day TTL by
    default; ``max_uses>1`` makes a shareable multi-use link."""
    ok, identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    inv = await invites_mod.generate(
        identity.get("agent_id") or "operator",
        max_uses=max(1, req.max_uses),
        ttl_days=max(1, req.ttl_days),
    )
    if not inv:
        return JSONResponse(status_code=503, content={"error": "invite_store_unavailable"})
    return inv


@app.get("/api/invites")
@app.get("/api/invites/")
async def list_invites(request: Request):
    """List active invites (admin/leader)."""
    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    return {"invites": await invites_mod.list_active()}


@app.post("/api/invites/{token}/revoke")
async def revoke_invite(token: str, request: Request):
    """Revoke an invite token (admin/leader)."""
    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    return {"revoked": await invites_mod.revoke(sanitize_text(token, 128))}


@app.post("/api/members/rotate")
@app.post("/api/members/rotate/")
async def rotate_member_key(attestation: dict) -> JSONResponse:
    """Accept a signed key-rotation attestation from a sovereign member.

    Member side creates the attestation via
    community_member.auth.create_rotation_attestation (OLD key signs).
    We verify it, check replay, record to member_key_rotations, and
    update the in-memory pubkey used for request verification.

    Origin=openclaw agents cannot rotate — they don't hold their own
    keys in a sovereign way. Their rotation story is "uninstall the
    skill + reinstall" (which generates a fresh keypair and re-registers
    from scratch, losing trust-tier history — by design).
    """
    import member_rotation

    agent_id = attestation.get("agent_id") if isinstance(attestation, dict) else None
    if not agent_id or not isinstance(agent_id, str):
        return JSONResponse(status_code=400, content={"error": "agent_id required in attestation"})

    safe_id = sanitize_agent_id(agent_id)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    # Must be a known, sovereign member
    existing = members.get(safe_id)
    if not existing:
        return JSONResponse(status_code=400, content={"error": "unknown agent"})
    if existing.get("origin") == "openclaw":
        return JSONResponse(status_code=400, content={"error": "openclaw agents cannot rotate — reinstall the skill"})

    stored_key = existing.get("public_key", "")
    if not stored_key:
        # A TOFU-via-header agent (registered by signing with X-Agent-DID-Key,
        # no public_key in the body) keeps its key in the auth store, not in
        # members[][public_key]. Fall back to it so it can rotate too (e2e
        # NOTE b). The rotation attestation's old key must match this.
        stored_key = (auth_verify._agent_keys.get(safe_id) or {}).get("ed25519_pubkey", "")
    if not stored_key:
        return JSONResponse(status_code=400, content={"error": "no stored key for this agent"})

    result = await member_rotation.accept_rotation(attestation, stored_key)
    if result.get("error"):
        # A rejected attestation is an AUTH failure: the old key did not
        # prove possession. Malformed-input 400s were handled above.
        return JSONResponse(status_code=401, content=result)

    # Verified + audit row written — update in-memory state.
    # Use replace_agent_key (not store_agent_key) so the OLD ed25519_pubkey
    # is overwritten, not OR-preserved. Otherwise signing with the new key
    # fails post-rotation (bug discovered live 2026-04-22).
    new_pub = result["new_public_key_b64"]
    members[safe_id]["public_key"] = new_pub
    auth_verify.replace_agent_key(safe_id, new_pub)
    print(f"Member key rotated: {safe_id}")
    return JSONResponse(status_code=200, content={"agent_id": safe_id, "rotated": True, "new_public_key_b64": new_pub})


@app.get("/api/sessions")
@app.get("/api/sessions/")
async def list_sessions(request: Request) -> dict:
    """List active sovereign agent sessions.

    Public response is intentionally minimal: agent_id, status, and
    last_action_at only. Pre-launch audit found the unauth response
    leaked active provider+model+thought-counts per agent — useful
    operational telemetry for an attacker fingerprinting the runtime
    or budgeting an LLM-cost-exhaustion attack.

    Authenticated callers (any X-Agent-* signed request) get the full
    record including provider, model, thought_count, tool_calls. The
    chapter's own dashboard authenticates by signing the surface call
    so it sees the rich data; random scrapers see only liveness.

    ⚠️ THE TIER MUST COME FROM request.state, NEVER A HEADER. This route is
    in auth_verify.IDENTITY_AWARE_OPEN_PATHS, so the middleware verifies a
    signature when one is present and sets request.state.verified — the
    same mechanism the AI catalog and portal layout use. request.state is
    populated by the middleware before this handler runs and cannot be set
    by the caller. X-Auth-Status is not: the middleware only ever writes it
    onto the RESPONSE, after call_next returns — so reading it from
    request.headers reads whatever the CALLER sent, and any anonymous
    caller could set X-Auth-Status: verified on their own request and
    receive the tier this docstring says requires authentication. That was
    exactly this route's bug before this fix.
    """
    is_authenticated = getattr(request.state, "verified", False) is True
    return {
        "sessions": [
            (
                {
                    "agent_id": aid,
                    "status": s.status,
                    "provider": s.provider,
                    "model": s.model,
                    "thought_count": s.thought_count,
                    "tool_calls": s.tool_calls,
                    "last_action_at": s.last_action_at,
                }
                if is_authenticated
                else {
                    "agent_id": aid,
                    "status": s.status,
                    "last_action_at": s.last_action_at,
                }
            )
            for aid, s in sovereign_runtime.sessions.items()
        ],
        "total": len(sovereign_runtime.sessions),
    }


@app.get("/api/runtimes")
@app.get("/api/runtimes/")
async def list_runtimes(request: Request) -> dict:
    """List active member agent runtimes.

    Same tiering as GET /api/sessions, for the same reason: an anonymous
    response carrying provider, model, thought_count and conversation_count
    per agent is exactly the operational telemetry that route was hardened
    to hide after a pre-launch audit — this route returned it unconditionally
    until now. request.state.verified is set by the middleware (this route is
    in auth_verify.IDENTITY_AWARE_OPEN_PATHS) after a real signature check;
    never trust a header a caller could set themselves for this decision.
    """
    is_authenticated = getattr(request.state, "verified", False) is True
    return {
        "runtimes": [
            (
                {
                    "agent_id": aid,
                    "status": rt.status,
                    "provider": rt.provider,
                    "model": rt.model,
                    "thought_count": rt.thought_count,
                    "conversation_count": rt.conversation_count,
                    "last_thought_at": rt.last_thought_at,
                }
                if is_authenticated
                else {
                    "agent_id": aid,
                    "status": rt.status,
                    "last_thought_at": rt.last_thought_at,
                }
            )
            for aid, rt in member_runtime.runtimes.items()
        ],
        "total": len(member_runtime.runtimes),
    }


# ============================================================
# INTENT MATCHING ENDPOINTS
# ============================================================
class IntentSubmission(BaseModel):
    requester_agent_id: str
    intent_text: str
    intent_tags: list[str] = []


@app.post("/api/intents", response_model=None)
async def submit_intent(req: IntentSubmission, request: Request) -> dict | JSONResponse:
    # The intent is attributed to the VERIFIED caller, never the body's
    # requester_agent_id — otherwise a signed caller could submit an intent (and
    # emit receipts / activity) AS another agent (sweep, write-IDOR).
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_text = sanitize_text(req.intent_text, 500)
    safe_tags = [sanitize_text(t, 50) for t in req.intent_tags[:10]]
    safe_id = sanitize_agent_id(caller)
    if not safe_id or not safe_text:
        return {"error": "intent_text required"}
    intent_id = await intents.create_intent(safe_id, safe_text, safe_tags)
    asyncio.create_task(intents.match_intent(intent_id))
    asyncio.create_task(intents.match_intent_federation(intent_id, federation))
    await activity_tracker.track(safe_id, "intent_submitted", {"intent": safe_text[:100]})

    # Emit intent.published on the event bus (EB-2 trigger site).
    asyncio.create_task(
        event_bus.safe_publish(
            "intent.published",
            {
                "intent_id": intent_id,
                "submitter_agent_id": safe_id,
                "text": safe_text,
                "tags": safe_tags,
            },
        )
    )

    # ARP — emit a signed receipt for the intent submission. The server
    # is the issuer (it accepted the submission); the member is the
    # principal. Fire-and-forget; receipt emission must not wedge the
    # response.
    try:
        import arp as arp_mod

        principal_did = arp_mod.did_key_for_member(safe_id)
        if principal_did:
            asyncio.create_task(
                arp_mod.emit_chapter_action(
                    principal_did=principal_did,
                    category="other",
                    human_summary=f"Submitted an intent: {safe_text[:140]}",
                    machine_payload={
                        "action_type_label": "intent_submitted",
                        "intent_id": intent_id,
                        "tags": safe_tags,
                    },
                )
            )
    except Exception:  # noqa: BLE001 — telemetry must never break business logic
        pass

    return {"intent_id": intent_id, "status": "matching"}


@app.get("/api/intents", response_model=None)
async def list_intents(request: Request) -> dict | JSONResponse:
    # Scoped to the caller's OWN intents. The rows expose
    # requester_agent_id + raw intent_text + match_details and were
    # bulk-enumerable via ?agent_id unauthenticated — the 3rd unauth hole on
    # this surface (after that change). Ignore any client-supplied id; use the
    # verified caller.
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    data = await intents.get_active_intents(sanitize_agent_id(caller))
    return {"intents": data or []}


@app.get("/api/intents/{intent_id}", response_model=None)
async def get_intent_detail(intent_id: str, request: Request) -> dict | JSONResponse:
    # Full intent detail exposes requester_agent_id + raw intent_text; require a
    # verified caller and authorize them against the intent.
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    return await intents.get_intent_detail(intent_id, sanitize_agent_id(caller))


@app.post("/api/intents/match")
async def match_external_intent(req: dict) -> dict:
    """Federation endpoint — peer chapters call this to match against our projections."""
    text = sanitize_text(req.get("intent_text", ""), 500)
    tags = [sanitize_text(t, 50) for t in req.get("intent_tags", [])[:10]]
    local_matches = projections.match_intent_against_projections(text, tags)
    return {
        "chapter_id": AGENT_ID,
        "chapter_name": AGENT_NAME,
        "match_count": len(local_matches),
        "matched_skills": list(set(s for m in local_matches for s in m["matched_skills"]))[:10],
    }


@app.delete("/api/intents/{intent_id}", response_model=None)
async def cancel_intent_endpoint(intent_id: str, request: Request) -> dict | JSONResponse:
    # The owner derives from the VERIFIED caller, never the ?agent_id query
    # param — otherwise a signed caller could cancel another agent's intent by
    # passing the owner's public id (IDOR). That change
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    return await intents.cancel_intent(intent_id, sanitize_agent_id(caller))


@app.get("/api/intents/pending/{agent_id}", response_model=None)
async def get_pending_intents(agent_id: str, request: Request) -> dict | JSONResponse:
    # A principal may only read their OWN pending matches — ignore the path
    # agent_id, use the verified caller.
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    pending = await consent_gate.get_pending_for_agent(sanitize_agent_id(caller))
    return {"pending": pending}


class ConsentResponse(BaseModel):
    intent_id: str
    responder_agent_id: str
    response: str  # accept, decline, counter
    counter_text: str = ""


@app.post("/api/intents/respond", response_model=None)
async def respond_to_intent_endpoint(req: ConsentResponse, request: Request) -> dict | JSONResponse:
    # The responder is the VERIFIED caller, never the request body. The
    # body's responder_agent_id is ignored — otherwise any registered agent
    # could respond as someone else, or to an intent they were never matched
    # to, and unlock the requester's PII via check_mutual_consent.
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    responder = sanitize_agent_id(caller)

    result = await consent_gate.respond_to_intent(
        req.intent_id,
        responder,
        req.response,
        sanitize_text(req.counter_text, 500),
    )
    if result.get("mutual_consent"):
        intro = await consent_gate.check_mutual_consent(req.intent_id, responder)
        return {"mutual_consent": True, "introduction": intro}
    return result


@app.get("/api/intents/introductions/{agent_id}", response_model=None)
async def get_introductions_endpoint(agent_id: str, request: Request) -> dict | JSONResponse:
    # Introductions expose BOTH parties' identity (the PII boundary). A
    # principal may read only their OWN — ignore the path agent_id, use the
    # verified caller (same class as that change).
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    return {"introductions": await consent_gate.get_introductions(sanitize_agent_id(caller))}


# ─── EB-3: subscription endpoints ───────────────────────────────────
#
# Auth model: every subscription endpoint pulls the caller identity
# from request.state.agent_id (set by the auth middleware on a verified
# Ed25519 signature). The body is NEVER trusted to assert "I am alice"
# — only the signature is. POST /api/subscriptions and DELETE
# /api/subscriptions/{id} require auth via REQUIRE_AUTH_METHODS;
# GET /api/subscriptions is in REQUIRE_AUTH_GET_PATHS so it doesn't
# leak the subscription ledger to anonymous enumeration.


class SubscriptionRequest(BaseModel):
    topics: list[str]
    filters: dict | None = None
    delivery: str = "stream"
    webhook_url: str | None = None


# TOFU may bootstrap a key only for a REGISTERED member. Installed here, beside
# the members dict it reads, so auth_verify — which holds no membership state —
# fails closed on its own and answers `no_stored_key` for everyone else.
auth_verify.set_tofu_eligibility(lambda agent_id: agent_id in members)


def _signer_is_member(agent_id: str, path: str) -> bool:
    """Whether a signature-verified ``agent_id`` counts as authenticated on ``path``.

    On the A2A interop surfaces any self-authenticating caller does — the
    signature is accountability there. Everywhere else only a registered
    member does, because that is what every handler reads a verified caller
    as. Measured before this existed: a never-registered id with a fresh
    keypair was TOFU-accepted on GET /api/members and received the directory,
    descriptions included — the enumeration the gate exists to close, open to
    anyone willing to sign.
    """
    return agent_id in members or auth_verify.is_self_authenticating_path(path)


def _resolve_caller(request: Request) -> str:
    """Caller identity from the auth-verified ``request.state.agent_id``, set by
    the middleware ONLY after a valid Ed25519 signature. The spoofable
    ``X-Agent-ID`` header is never trusted — an unsigned or spoofed request
    yields no caller, so per-identity authorization can't be bypassed by
    asserting someone else's id in a header."""
    return getattr(request.state, "agent_id", "") or ""


def _bind_actor_to_caller(request: Request, claimed: str, *, field: str) -> str:
    """ATTRIBUTION. The identity a write RECORDS is the VERIFIED CALLER.

    Returns the caller's sanitized agent_id, which the handler must use in place
    of whatever the body said.

    Authentication is not authorization, and neither is authorship: the
    middleware proves WHO CALLED, and a handler that then copies an actor id out
    of the payload records someone else. Two audits missed this class because
    the request they examined was valid — the signature verifies, the caller is
    real, and the row still names a member who did nothing.

    ⚠️ A MISMATCH IS A 403, NOT A SILENT CORRECTION. Quietly substituting the
    caller would leave a hostile client's forgery attempt unlogged and an honest
    client believing the write it asked for happened as asked. Both deserve to
    be told.

    There is deliberately no admin override. These routes sit behind
    ``requires_auth``, which demands a signed member for every mutation, so an
    ``X-Admin-Token``-only request never reaches one; an override would be an
    unreachable branch that reads like a supported path. Operator actions on
    another member's behalf belong on ``/admin/api/*``, which carries its own
    identity and its own audit.
    """
    caller = sanitize_agent_id(_resolve_caller(request))
    if not caller:
        raise HTTPException(status_code=401, detail="auth required")
    if claimed and sanitize_agent_id(claimed) != caller:
        raise HTTPException(
            status_code=403,
            detail=(
                f"{field} must be the verified caller: signed as {caller!r}, claimed {sanitize_agent_id(claimed)!r}"
            ),
        )
    return caller


def _require_agent_owner(request: Request, aid: str, *, what: str) -> None:
    """TARGET OWNERSHIP. A member's own resource is writable by that member or
    by an operator holding the admin token.

    Distinct from ``_bind_actor_to_caller`` and the difference matters: this one
    answers "whose record is this", that one answers "whose name goes on it".
    A route can need both — ``/api/chapter/allowlist/add`` writes an entry ABOUT
    a peer and STAMPS an actor, and only the second is an attribution.
    """
    caller = _resolve_caller(request)
    if caller != aid and not auth_verify.check_admin_token_header(dict(request.headers)):
        raise HTTPException(status_code=403, detail=f"{what} are restricted to the agent or an admin")


@app.post("/api/subscriptions", response_model=None)
@app.post("/api/subscriptions/", response_model=None)
async def create_subscription_endpoint(req: SubscriptionRequest, request: Request) -> dict | JSONResponse:
    """Create a subscription on behalf of the calling agent (EB-3)."""
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    # Resolve the subscriber's did_key from the stored Ed25519 pubkey.
    # If absent (e.g. a TOFU-only HMAC member), did_key falls back to
    # empty — the row is still valid (the migration doesn't require it
    # be non-empty), but cryptographic delivery features expecting a
    # did:key won't gain anything from this subscription.
    stored = auth_verify._agent_keys.get(safe_id, {}) if hasattr(auth_verify, "_agent_keys") else {}
    pubkey = stored.get("ed25519_pubkey") or ""
    did_key = sovereign_identity.build_did_key_from_ed25519(pubkey) if pubkey else ""

    try:
        row = await subscriptions_svc.create_subscription(
            subscriber_agent_id=safe_id,
            subscriber_did_key=did_key,
            topics=req.topics,
            filters=req.filters,
            delivery=req.delivery,
            webhook_url=req.webhook_url,
        )
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    if row is None:
        return JSONResponse(status_code=503, content={"error": "subscription store unavailable"})
    return {"subscription": row}


@app.get("/api/subscriptions", response_model=None)
@app.get("/api/subscriptions/", response_model=None)
async def list_subscriptions_endpoint(request: Request) -> dict | JSONResponse:
    """List the caller's active subscriptions (EB-3)."""
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})
    rows = await subscriptions_svc.list_active_subscriptions(safe_id)
    return {"subscriptions": rows, "total": len(rows)}


# ─── Chronicle settings toggle ───────────────────────────────────────
#
# Public Chronicle visibility is an opt-in flag in the agent's
# agents.config jsonb. Defaults to false. The toggle is set by the
# authenticated agent themselves; no admin override in v1.


class ChroniclePublicRequest(BaseModel):
    public: bool


@app.post("/api/me/chronicle-public")
@app.post("/api/me/chronicle-public/")
async def set_chronicle_public_endpoint(req: ChroniclePublicRequest, request: Request) -> JSONResponse:
    """Toggle the caller's Chronicle public-visibility flag.

    The caller MUST be the agent being updated. Their X-Agent-Signature
    is verified by the standard middleware (this is a POST so it falls
    under SELF-SIGNED auth via REQUIRE_AUTH_METHODS or per-path rule).
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    existing = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe_id}", "select": "config", "limit": "1"},
    )
    if not existing:
        return JSONResponse(status_code=404, content={"error": "agent not found"})
    row = existing[0] if isinstance(existing, list) else existing
    config = row.get("config") or {}
    config["chronicle_public"] = bool(req.public)

    result = await pg_request(
        "PATCH",
        "agents",
        params={"agent_id": f"eq.{safe_id}"},
        body={"config": config},
    )
    if result is None:
        return JSONResponse(status_code=503, content={"error": "persistence failed"})

    return JSONResponse(
        status_code=200,
        content={"agent_id": safe_id, "chronicle_public": bool(req.public)},
    )


# ─── ARP v0.1 — Agency Receipt Protocol endpoints ────────────────────
#
# POST /api/receipts — issuer submits a signed receipt. The receipt's own
# Ed25519 signature is the auth (see SELF_SIGNED_POST_PATHS). The handler
# delegates verification to server.arp.emit() which runs the full
# schema + signature + hash-chain pipeline.
#
# GET /api/receipts — principal queries their own receipt log. Auth
# middleware enforces X-Agent-Signature (REQUIRE_AUTH_GET_PATHS), then
# the handler derives the principal's did:key from the authenticated
# agent's stored pubkey and queries only receipts where principal_did
# matches. A principal cannot read receipts attributed to someone else.


@app.post("/api/receipts")
@app.post("/api/receipts/")
async def submit_receipt_endpoint(request: Request) -> JSONResponse:
    """Accept a signed ARP v0.1 receipt and persist it to the Issuer Log.

    Returns:
        200 {receipt_id, chain_link} on success
        400 schema/signature/hash-chain failure (body includes stage + detail)
        409 receipt_id collision under the same issuer (idempotent re-submit)
        503 persistence backend unavailable (signature verified, write failed)
    """
    import arp as arp_mod

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "receipt MUST be a JSON object"})

    # a member may only submit receipts vouching for its OWN actions —
    # principal_did MUST equal issuer_did. Without this a member could inject
    # receipts into ANY other principal's ledger and inflate their nanda-rep/0.1
    # (default) score. Chapter-issued authority grants (issuer=chapter ≠
    # principal) never come through this HTTP path — they are emitted internally.
    result = await arp_mod.emit(body, require_principal_match=body.get("issuer_did"))
    if not result.ok:
        # Map verification stage → HTTP status. Signature + schema + chain
        # failures are all 400 (client supplied bad data); a genuine
        # persistence failure is 503; an idempotent re-submit is 409.
        if result.stage == "duplicate":
            return JSONResponse(
                status_code=409,
                content={"receipt_id": body.get("receipt_id"), "idempotent": True, "detail": result.detail},
            )
        if result.stage == "accepted" and "persistence" in result.detail:
            return JSONResponse(
                status_code=503,
                content={"error": result.detail, "stage": result.stage},
            )
        return JSONResponse(
            status_code=400,
            content={"error": result.detail, "stage": result.stage},
        )

    return JSONResponse(
        status_code=200,
        content={
            "receipt_id": body.get("receipt_id"),
            "chain_link": arp_mod.compute_chain_link(body) if hasattr(arp_mod, "compute_chain_link") else None,
        },
    )


@app.post("/api/cosign/broker")
@app.post("/api/cosign/broker/")
async def cosign_broker_endpoint(request: Request) -> JSONResponse:
    """Broker the co-sign handshake for a reduced-tier member (cosign-companion.md §4).

    The issuer (A) — typically an ``openclaw-skill`` client with no receiving A2A
    server of its own — POSTs its UNSIGNED receipt. The chapter resolves the
    counterparty named in ``action.counterparty_did`` to a registered member's
    A2A endpoint, relays the receipt to that member's ``nanda/cosignReceipt``, and
    returns the counterparty's witness entry UNCHANGED. The chapter is a transport
    relay only — it NEVER signs as the witness (the returned ``witness_did`` is the
    counterparty's own ``did:key``).

    Fail-safe (§3): an unresolvable / offline / declining counterparty yields
    ``{"witness": null}`` — a valid-but-uncorroborated outcome for the issuer,
    never an error.

    Returns:
        200 {"witness": {witness_did, signature}}  — counterparty co-signed
        200 {"witness": null}                       — decline / offline / unreachable
        400 malformed request (no receipt object, or no counterparty_did)
    """
    import cosign_broker

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON body"})

    if not isinstance(body, dict) or not isinstance(body.get("receipt"), dict):
        return JSONResponse(status_code=400, content={"error": "request MUST include a 'receipt' object"})

    receipt = body["receipt"]
    action = receipt.get("action")
    if not isinstance(action, dict) or not action.get("counterparty_did"):
        return JSONResponse(status_code=400, content={"error": "receipt.action.counterparty_did is required"})

    entry = await cosign_broker.relay_cosign(receipt, members=members)
    return JSONResponse(status_code=200, content={"witness": entry})


@app.get("/api/receipts")
@app.get("/api/receipts/")
async def list_receipts_endpoint(request: Request) -> JSONResponse:
    """Return the authenticated caller's own ARP receipts (where the
    caller is the principal).

    The caller is identified via the standard X-Agent-Signature middleware
    (REQUIRE_AUTH_GET_PATHS gates this endpoint). We derive the caller's
    did:key from their stored pubkey and look up receipts whose
    ``principal_did`` matches.

    Query parameters:
        limit — int, default 100, max 500
    """
    import arp as arp_mod

    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    # Resolve the caller's did:key from their stored Ed25519 pubkey.
    stored = auth_verify._agent_keys.get(safe_id, {}) if hasattr(auth_verify, "_agent_keys") else {}
    pubkey = stored.get("ed25519_pubkey") or ""
    if not pubkey:
        return JSONResponse(
            status_code=403,
            content={"error": "caller has no stored Ed25519 pubkey; cannot derive did:key"},
        )
    caller_did = sovereign_identity.build_did_key_from_ed25519(pubkey)

    raw_limit = request.query_params.get("limit", "100")
    try:
        limit = max(1, min(500, int(raw_limit)))
    except (TypeError, ValueError):
        limit = 100

    receipts = await arp_mod.list_for_principal(caller_did, limit=limit)
    return JSONResponse(
        status_code=200,
        content={"receipts": receipts, "total": len(receipts), "principal_did": caller_did},
    )


@app.get("/api/receipts/recent")
async def recent_receipts_endpoint(request: Request) -> JSONResponse:
    """Dev-only chapter-wide Issuer Log view (newest first).

    Returns the whole chapter's recent receipts WITHOUT per-principal auth so
    the chapter's Receipts page can render them locally. This is only available
    in OFFLINE mode (no Postgres configured) — a local-dev / demo chapter. When
    Postgres IS configured (any real deployment) it returns 404, so a production
    chapter never exposes its Issuer Log publicly. The authenticated, principal-
    scoped read at GET /api/receipts is the production surface.
    """
    import arp as arp_mod

    if not arp_mod.is_offline():
        return JSONResponse(status_code=404, content={"error": "not found"})
    raw_limit = request.query_params.get("limit", "100")
    try:
        limit = max(1, min(500, int(raw_limit)))
    except (TypeError, ValueError):
        limit = 100
    receipts = arp_mod._local_log.list_recent(limit=limit) if arp_mod._local_log else []
    return JSONResponse(
        status_code=200,
        content={"receipts": receipts, "total": len(receipts), "mode": "offline"},
    )


@app.get("/receipts", include_in_schema=False)
@app.get("/receipts/", include_in_schema=False)
async def receipts_ui():
    """Serve the static chapter Receipts viewer (renders /api/receipts/recent)."""
    import os as _os

    from fastapi.responses import FileResponse

    here = _os.path.dirname(_os.path.abspath(__file__))
    page = _os.path.join(here, "static", "receipts", "index.html")
    if not _os.path.exists(page):
        return JSONResponse(
            status_code=503,
            content={"error": "receipts UI not bundled with this chapter build"},
        )
    import csp as _csp

    return FileResponse(page, media_type="text/html", headers=_csp.document_headers(page))


def _static_page(*parts: str):
    """Serve a bundled static page with its hash-based CSP, or say it is absent.

    Mirrors the existing ``/receipts`` route rather than mounting a directory:
    the CSP header is computed per document from the inline sources it actually
    contains, which a blanket StaticFiles mount cannot do.

    Every served HTML document goes through here or through the two routes that
    call ``_csp.document_headers`` directly. A page added with a bare
    ``FileResponse`` would carry no CSP and no referrer policy.
    """
    import os as _os

    from fastapi.responses import FileResponse

    import csp as _csp

    here = _os.path.dirname(_os.path.abspath(__file__))
    page = _os.path.join(here, "static", *parts)
    if not _os.path.exists(page):
        return JSONResponse(status_code=503, content={"error": f"{parts[0]} UI not bundled with this build"})
    return FileResponse(page, media_type="text/html", headers=_csp.document_headers(page))


@app.get("/console", include_in_schema=False)
@app.get("/console/", include_in_schema=False)
async def console_ui():
    """The operator console: agents, tasks, the approval queue, receipts."""
    return _static_page("console", "index.html")


@app.get("/join", include_in_schema=False)
@app.get("/join/", include_in_schema=False)
async def join_ui():
    """The QR landing: one invite token, a runtime picker. OpenClaw and Python
    join today; an MCP option is shown and named unavailable rather than
    omitted (see server/static/ui/join.js's RUNTIMES and its own comment on
    why a missing path would teach the wrong lesson)."""
    return _static_page("join", "index.html")


@app.get("/ui/{asset}", include_in_schema=False)
async def ui_asset(asset: str):
    """The console/join ES modules.

    ⚠️ Name-allowlisted rather than path-joined. A directory mount would serve
    whatever lands in that folder, and ``asset`` comes from the URL — the
    traversal surface is not worth the convenience for five files.
    """
    import os as _os

    from fastapi.responses import FileResponse

    allowed = {
        "dom.js",
        "console.js",
        "console-boot.js",
        "join.js",
        "join-boot.js",
        "receipts.js",
        "receipts-boot.js",
    }
    if asset not in allowed:
        return JSONResponse(status_code=404, content={"error": "unknown asset"})
    here = _os.path.dirname(_os.path.abspath(__file__))
    path = _os.path.join(here, "static", "ui", asset)
    if not _os.path.exists(path):
        return JSONResponse(status_code=503, content={"error": "console UI not bundled with this build"})
    return FileResponse(path, media_type="text/javascript")


@app.get("/api/invites/{token}/qr.svg", include_in_schema=False)
async def invite_qr(token: str, request: Request):
    """A QR encoding this org's join URL for ``token``.

    ⚠️ The QR is only a CARRIER for the join URL — it grants nothing the URL does
    not, and the URL grants nothing the token does not. So it does NOT create,
    look up or validate an invite: an unknown token yields a perfectly valid QR
    pointing at a landing page that then refuses. Validating here would make the
    route an oracle for guessing tokens.

    SVG so there is no image dependency, and so a projector-sized code is not a
    resolution problem.
    """
    import qrcode
    import qrcode.image.svg
    from fastapi.responses import Response as _Response

    base = str(request.base_url).rstrip("/")
    target = f"{base}/join?invite={quote(token, safe='')}"
    img = qrcode.make(target, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return _Response(content=buf.getvalue(), media_type="image/svg+xml")


def _ordered_issuer_log() -> list:
    """The offline Issuer Log in a deterministic committed order (issued_at,
    receipt_id) — shared by the checkpoint + proof endpoints so leaves align."""
    import arp as arp_mod

    rows = arp_mod._local_log.list_recent(limit=5000) if arp_mod._local_log else []
    return sorted(rows, key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))


async def _ordered_issuer_log_any_mode() -> list:
    """The Issuer Log in committed order, offline OR production.

    The offline path reads the local SQLite mirror; production reads Postgres
    ``arp_receipts``. The ORDER MUST MATCH between publish and serve, or a proof
    built against one leaf ordering will not verify against the other — so both
    modes sort by the same (issued_at, receipt_id) key rather than trusting the
    order rows happen to arrive in.
    """
    import arp as arp_mod

    if arp_mod.is_offline():
        return _ordered_issuer_log()
    rows = await pg_request(
        "GET",
        "arp_receipts",
        params={"select": "receipt_json", "order": "issued_at.asc", "limit": "5000"},
    )
    receipts = []
    for row in rows or []:
        raw = (row or {}).get("receipt_json")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                continue
        if isinstance(raw, dict):
            receipts.append(raw)
    return sorted(receipts, key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))


class _PublishDisclosureRequest(BaseModel):
    receipt_ids: list[str] = Field(default_factory=list)
    publication_id: str = ""


@app.post("/admin/api/receipts/publish")
async def admin_publish_disclosure(req: _PublishDisclosureRequest, request: Request) -> JSONResponse:
    """Publish a disclosure bundle for named receipts this org issued.

    Explicit and opt-in: nothing becomes publicly readable except what an
    operator named here. ``/api/receipts`` stays 401 and is untouched — that
    endpoint is a member's private history and this one is the org's own
    receipts about its own actions, which is why publishing it involves no
    member's data at all.
    """
    import receipt_publication as rp

    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    receipt_ids = [r.strip() for r in req.receipt_ids if r and r.strip()]
    if not receipt_ids:
        return JSONResponse(status_code=400, content={"error": "receipt_ids is required"})
    pub_id = sanitize_agent_id(req.publication_id.strip() or "sample")
    if not pub_id:
        return JSONResponse(status_code=400, content={"error": "invalid publication_id"})

    import arp as arp_mod

    kp = arp_mod._chapter_keypair_bytes()
    if not kp:
        return JSONResponse(status_code=503, content={"error": "chapter keypair unavailable"})
    sk_bytes, issuer_did = kp

    # Build BEFORE recording, so a bundle that cannot be assembled (unknown id,
    # another issuer's receipt) never leaves a record pointing at a URL that
    # would then fail to serve.
    try:
        rp.build_bundle(
            publication_id=pub_id,
            published_at="",
            receipt_ids=receipt_ids,
            issuer_log=await _ordered_issuer_log_any_mode(),
            issuer_did=issuer_did,
            sk_bytes=sk_bytes,
        )
        record = await rp.record_publication(pg_request, AGENT_ID, pub_id, receipt_ids)
    except rp.PublicationError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    return JSONResponse(
        content={
            "publication_id": pub_id,
            "published_at": record["published_at"],
            "receipt_ids": receipt_ids,
            "url": f"{PUBLIC_URL}/.well-known/receipt-disclosure/{pub_id}.json",
        }
    )


@app.get("/.well-known/nanda-chapter-rotation.json")
async def public_rotation_chain() -> JSONResponse:
    """This org's key-rotation chain — PUBLIC, no auth, by design (spec/0.6 §8.5.2).

    Unauthenticated because a peer needs it precisely when it CANNOT verify our
    signatures: our key changed and its pin no longer matches, so any auth we
    demanded would be auth it cannot satisfy. Nothing here is secret — every
    entry is a public key plus a signature over public fields, and the security
    is that each link is signed by the key being retired.

    Ordered oldest-first. An empty list is valid and means no rotation has ever
    occurred, which is this org's state until one is performed; a peer walking
    it from a matching pin simply finds nothing to apply.
    """
    import federation_policy as fp

    return JSONResponse({"rotations": await fp.published_rotation_chain()})


@app.get("/.well-known/receipt-disclosure/{publication_id}.json")
async def public_receipt_disclosure(publication_id: str) -> JSONResponse:
    """A published disclosure bundle — PUBLIC, no auth, by design.

    Unauthenticated because the entire point is that a stranger can check us
    without an account and without our code. Only bundles an operator explicitly
    published are served; anything else is 404.
    """
    import receipt_publication as rp

    pub_id = sanitize_agent_id(publication_id)
    published = await rp.load_publications(pg_request, AGENT_ID)
    record = published.get(pub_id) if pub_id else None
    if not record:
        return JSONResponse(status_code=404, content={"error": "no such published disclosure"})

    import arp as arp_mod

    kp = arp_mod._chapter_keypair_bytes()
    if not kp:
        return JSONResponse(status_code=503, content={"error": "chapter keypair unavailable"})
    sk_bytes, issuer_did = kp
    try:
        bundle = rp.build_bundle(
            publication_id=pub_id,
            published_at=record.get("published_at", ""),
            receipt_ids=list(record.get("receipt_ids") or []),
            issuer_log=await _ordered_issuer_log_any_mode(),
            issuer_did=issuer_did,
            sk_bytes=sk_bytes,
        )
    except rp.PublicationError as exc:
        # A published receipt that can no longer be assembled is a real problem,
        # not a 404 — say so rather than implying it was never published.
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return JSONResponse(content=bundle, media_type=rp.MEDIA_TYPE)


@app.get("/.well-known/receipt-disclosure/")
async def public_receipt_disclosure_index() -> JSONResponse:
    """Which disclosure bundles this org has published — public, no auth."""
    import receipt_publication as rp

    published = await rp.load_publications(pg_request, AGENT_ID)
    return JSONResponse(
        content={
            "publications": [
                {
                    "publication_id": pid,
                    "published_at": rec.get("published_at", ""),
                    "url": f"{PUBLIC_URL}/.well-known/receipt-disclosure/{pid}.json",
                }
                for pid, rec in sorted(published.items())
            ]
        }
    )


@app.get("/api/checkpoint")
async def checkpoint_endpoint(request: Request) -> JSONResponse:
    """Dev-only signed RFC 6962 Merkle checkpoint over the Issuer Log.

    The chapter signs a commitment to the whole log by Merkle root. Offline-only
    (404 in production, same gate as the other dev endpoints).
    """
    import arp as arp_mod

    if not arp_mod.is_offline():
        return JSONResponse(status_code=404, content={"error": "not found"})
    kp = arp_mod._chapter_keypair_bytes()
    if not kp:
        # The server Ed25519 key is generated lazily; ensure it exists.
        sovereign_identity.generate_ed25519_keypair(AGENT_ID)
        kp = arp_mod._chapter_keypair_bytes()
    if not kp:
        return JSONResponse(status_code=503, content={"error": "chapter keypair unavailable"})
    sk_bytes, signer_did = kp
    checkpoint = arp_mod.build_checkpoint(_ordered_issuer_log(), sk_bytes=sk_bytes, signer_did=signer_did)
    return JSONResponse(status_code=200, content=checkpoint)


@app.get("/api/checkpoint/proof/{receipt_id}")
async def checkpoint_proof_endpoint(receipt_id: str, request: Request) -> JSONResponse:
    """Dev-only RFC 6962 inclusion proof for one receipt under the current root."""
    import arp as arp_mod
    import merkle

    if not arp_mod.is_offline():
        return JSONResponse(status_code=404, content={"error": "not found"})
    receipts = _ordered_issuer_log()
    idx = next((i for i, r in enumerate(receipts) if r.get("receipt_id") == receipt_id), None)
    if idx is None:
        return JSONResponse(status_code=404, content={"error": "receipt not in Issuer Log"})
    leaves = arp_mod.checkpoint_leaves(receipts)
    proof = merkle.inclusion_proof(leaves, idx)
    root = merkle.merkle_root(leaves)
    return JSONResponse(
        status_code=200,
        content={
            "receipt_id": receipt_id,
            "leaf_index": idx,
            "tree_size": len(receipts),
            "merkle_root": "sha256:" + root.hex(),
            "proof": [p.hex() for p in proof],
        },
    )


@app.get("/api/receipts/ledger/{principal_did}")
async def receipts_ledger_endpoint(principal_did: str, request: Request) -> JSONResponse:
    """Dev-only full VRP Receipts Ledger (inline receipts) for a principal.

    The full ledger exposes receipt contents, so it is offline-only (404 in
    production) like /api/checkpoint. Production publishes the contents-free
    verifiable_receipts facet on /agentfacts/{member_id}.json; a visibility-tiered
    public ledger (spec/vrp §9) is a follow-up.
    """
    import arp as arp_mod
    import vrp as vrp_mod

    if not arp_mod.is_offline():
        return JSONResponse(status_code=404, content={"error": "not found"})
    scoring_method = request.query_params.get("scoring_method", vrp_mod.DEFAULT_SCORING_METHOD)
    if scoring_method not in vrp_mod.SUPPORTED_SCORING_METHODS:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"unsupported scoring_method {scoring_method!r}",
                "supported": list(vrp_mod.SUPPORTED_SCORING_METHODS),
            },
        )
    ledger_uri = f"{PUBLIC_URL}/api/receipts/ledger/{principal_did}"
    ledger, _facet = await vrp_mod.build_principal_ledger(principal_did, ledger_uri=ledger_uri, method=scoring_method)
    return JSONResponse(status_code=200, content=ledger)


@app.get("/api/audit")
async def audit_endpoint(request: Request) -> JSONResponse:
    """Dev-only auditor: re-verify the entire Issuer Log and report.

    Independently re-checks every receipt (signature + schema + hash chain),
    runs the Sybil-ring topology analysis, and anchors the current Merkle root —
    the auditor's combined view over the four trust primitives. Offline-only.
    """
    import arp as arp_mod
    import merkle
    import sybil
    from _arp_verify import compute_chain_link, verify_receipt

    if not arp_mod.is_offline():
        return JSONResponse(status_code=404, content={"error": "not found"})
    receipts = _ordered_issuer_log()
    priors = {compute_chain_link(r): r for r in receipts}
    valid = 0
    invalid: list[dict] = []
    for r in receipts:
        res = verify_receipt(r, mode="strict", prior_receipts=priors)
        if res.ok:
            valid += 1
        else:
            invalid.append({"receipt_id": r.get("receipt_id"), "stage": res.stage, "detail": res.detail})
    analysis = sybil.detect_sybil_rings(receipts)
    root = merkle.merkle_root(arp_mod.checkpoint_leaves(receipts))
    return JSONResponse(
        status_code=200,
        content={
            "total_receipts": len(receipts),
            "signatures_valid": valid,
            "signatures_invalid": invalid,
            "sybil_flagged_rings": analysis.flagged_rings,
            "sybil_flagged_dids": analysis.flagged_dids,
            "merkle_root": "sha256:" + root.hex(),
            "mode": "offline",
        },
    )


_SSE_POLL_INTERVAL_S = float(os.environ.get("SSE_POLL_INTERVAL_S", "2.0"))


def _parse_last_event_id(raw: str) -> int:
    """Parse Last-Event-ID. Returns 0 on anything unparseable so a
    hostile header can't trigger a 500."""
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


@app.get("/api/subscriptions/{subscription_id}/stream")
async def stream_subscription_endpoint(subscription_id: str, request: Request):
    """SSE delivery for a subscription (EB-4).

    Three phases:
      1. Auth + ownership — caller must own the subscription.
      2. Replay — if Last-Event-ID header present, replay matching
         events from event_log where id > N.
      3. Long-poll — until disconnect, poll event_log every
         _SSE_POLL_INTERVAL_S seconds and stream new matching events.
         Keepalive comment goes out every poll regardless so proxies
         don't time out the connection on idle subscriptions.

    Per-event-type trust gating (EB-5) will filter events before yield.
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    safe_sub_id = sanitize_text(subscription_id, 64)
    if not safe_sub_id:
        return JSONResponse(status_code=400, content={"error": "subscription_id required"})

    sub = await subscriptions_svc.get_subscription_for_owner(
        subscription_id=safe_sub_id,
        subscriber_agent_id=safe_id,
    )
    if sub is None:
        # Same shape as "doesn't exist" — no oracle leak.
        return JSONResponse(status_code=404, content={"error": "subscription not found"})

    topics = sub.get("topics") or []
    last_event_id = _parse_last_event_id(request.headers.get("Last-Event-ID", "0"))

    async def event_generator():
        nonlocal last_event_id

        # EB-5: snapshot the subscriber's trust score at stream start
        # (cached, refreshed every DEFAULT_CACHE_TTL_S). A promotion
        # mid-stream applies to the next event the cache refreshes
        # past; a demotion takes effect on the same schedule.
        async def _score():
            return await trust_gate.get_subscriber_trust_score(safe_id)

        try:
            replay = await event_bus.events_since(last_event_id, topics)
        except Exception as e:  # noqa: BLE001
            print(f"SSE replay error for {safe_sub_id}: {e}")
            replay = []
        replay = trust_gate.filter_events_for_trust(replay, await _score())
        for row in replay:
            yield event_bus.format_sse_event(row)
            last_event_id = max(last_event_id, int(row.get("id") or 0))

        while True:
            if await request.is_disconnected():
                return
            try:
                new_rows = await event_bus.events_since(last_event_id, topics)
            except Exception as e:  # noqa: BLE001
                # Don't crash the stream on a transient Postgres blip —
                # send a keepalive and try again next tick.
                print(f"SSE poll error for {safe_sub_id}: {e}")
                new_rows = []
            new_rows = trust_gate.filter_events_for_trust(new_rows, await _score())
            for row in new_rows:
                yield event_bus.format_sse_event(row)
                last_event_id = max(last_event_id, int(row.get("id") or 0))
            yield ": keepalive\n\n"
            await asyncio.sleep(_SSE_POLL_INTERVAL_S)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # nginx hint — don't buffer SSE
        },
    )


class DigestBuildRequest(BaseModel):
    window_days: int = 7
    publish: bool = True


@app.post("/api/digest/build", response_model=None)
async def build_digest_endpoint(req: DigestBuildRequest, request: Request) -> dict | JSONResponse:
    """Build (optionally publish) a chapter.digest.weekly event on demand.

    GATED (audit M11): a signed member or the operator bearer. This docstring
    used to say "Open to anyone — the digest is public-tier", and the
    middleware exempted the route on the strength of that sentence. The digest
    is public-tier *among subscribers* — ``MIN_TRUST_TO_SUBSCRIBE`` is 0.0 —
    but a subscriber is a signed member; the SSE stream 401s without one. The
    route handed the same rows to a caller with no credential at all.

    What that meant, measured on a local org rather than read off the code:
    one member registered, one intent submitted, then an unauthenticated
    POST with ``publish: false``. The response carried the intent's text
    verbatim in ``top_intents[0].text`` and again in ``summary_markdown``
    (the deterministic fallback quotes the first three intents), the joiner's
    ``agent_id``, display name and skills in ``new_members[0]``, and with the
    default ``publish: true`` it appended a ``chapter.digest.weekly`` row to
    event_log attributed to the org. Intent text is member-authored prose —
    the field class the profile route was closed over — and ``new_members``
    is a seven-day membership roster, which the member directory does not
    serve anonymously.

    ``publish: false`` builds the payload without firing the event, useful
    for previewing. Otherwise emits chapter.digest.weekly on the bus and
    returns the persisted event_id alongside the payload so the caller can
    confirm subscribers will see it within the next SSE poll.

    The credential is checked HERE as well as at the middleware, on purpose.
    The middleware classification is a set literal in ``auth_verify``; adding
    one string to it reopened this route once already, and a handler that
    refuses on its own means that edit is no longer sufficient.
    """
    if not _resolve_caller(request) and not auth_verify.check_admin_token_header(dict(request.headers)):
        return JSONResponse(
            status_code=401,
            content={
                "error": "authorization required",
                "hint": "sign the request as a member (X-Agent-Signature) or present the operator X-Admin-Token",
            },
        )
    try:
        payload = await digest_mod.build_digest(window_days=req.window_days)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"error": f"build failed: {e}"})

    if not req.publish:
        return {"payload": payload, "event_id": None, "published": False}

    event_id = await event_bus.safe_publish("chapter.digest.weekly", payload)
    return {"payload": payload, "event_id": event_id, "published": event_id is not None}


class BroadcastRequest(BaseModel):
    """Body for POST /api/broadcast — fields mirror ChapterBroadcastPayload
    minus server-set fields. The chapter resolves sender_agent_id from
    the authenticated caller, so callers cannot spoof a sender."""

    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=8000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    audience: Literal["local", "federation", "all"] = "all"


@app.post("/api/broadcast", response_model=None)
async def broadcast_send_endpoint(req: BroadcastRequest, request: Request) -> dict | JSONResponse:
    """Publish a chapter broadcast — one message, many recipients.

    Three-tier governance (PR5):

    * Chapter agent (autonomous think-cycle path) — always allowed.
    * Chapter leaders (chapter_role in {leader, admin}) — direct send.
    * High-trust members (trust_score >= 75) — direct send.
    * Everyone else — 403 with pointer to POST /api/broadcast/propose.

    The caller's agent_id becomes ``sender_agent_id`` on the payload;
    spoofing is prevented because the body has no sender field.
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})

    allowed, reason = await broadcast_mod.caller_can_broadcast_directly(caller)
    if not allowed:
        return JSONResponse(
            status_code=403,
            content={
                "error": "broadcast_not_authorized",
                "reason": reason,
                "remedy": (
                    "POST /api/broadcast/propose — your broadcast will be "
                    "queued for leader approval. Direct send requires "
                    "chapter_role in {leader, admin} or trust_score >= 75."
                ),
            },
        )

    result = await broadcast_mod.send_broadcast(
        sender_agent_id=caller,
        title=req.title,
        body=req.body,
        tags=req.tags,
        audience=req.audience,
    )
    if "error" in result:
        return JSONResponse(status_code=503, content=result)
    return result


@app.post("/api/broadcast/propose", response_model=None)
async def broadcast_propose_endpoint(req: BroadcastRequest, request: Request) -> dict | JSONResponse:
    """Queue a broadcast for leader approval.

    Open path for any signed member (no role gate) — sovereignty of
    voice means every verified member can propose. The leader
    approval queue then governs whether the proposal reaches the
    chapter's collective audience.

    On approve, ``think_approvals_sweep`` calls broadcast.send_broadcast
    with the CHAPTER agent as sender_agent_id (not the proposer) —
    preserving the "the chapter broadcast this" semantics so peers
    see it as a sanctioned chapter message, not a member's voice.
    The proposer_agent_id stays on the pending_approvals row for
    audit attribution.

    Returns the approval row (with id, expires_at) so the caller can
    poll status via /api/approvals/{id}.
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})

    import governance

    row = await governance.propose(
        kind="broadcast",
        proposer_agent_id=caller,
        payload={
            "title": req.title[:200],
            "body": req.body[:8000],
            "tags": list(req.tags)[:20],
            "audience": req.audience,
        },
        # Confidence not meaningful for broadcasts; the leader judges
        # content. Pin to 0.5 so the row sorts neutrally in lists.
        confidence=0.5,
    )
    if row is None:
        return JSONResponse(status_code=503, content={"error": "propose_failed"})
    return {
        "approval": row,
        "remedy": (f"Your broadcast is queued for leader approval. Watch /api/approvals/{row.get('id')} for status."),
    }


@app.get("/api/broadcast/log", response_model=None)
async def broadcast_log_endpoint(request: Request, limit: int = 50) -> dict | JSONResponse:
    """List this chapter's recent broadcasts from broadcast_log.

    Auth-gated — caller must be a chapter member. The body of each
    broadcast lives on event_log; this surface is the per-peer
    delivery audit (which peers got it, which failed). Used by
    leader dashboards and the podcast-as-agent composer.
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    rows = await broadcast_mod.list_recent_broadcasts(limit=limit)
    return {"broadcasts": rows, "count": len(rows)}


@app.post("/api/federation/broadcast/inbox", response_model=None)
async def broadcast_inbox_endpoint(request: Request) -> dict | JSONResponse:
    """Receive a broadcast pushed from a peer chapter.

    Prototype-tier auth: caller declares its chapter via
    ``X-Chapter-Origin`` and we verify the origin appears in our
    federation registry. The payload's ``origin_chapter_id`` MUST
    match the header — a peer cannot fabricate broadcasts under
    another chapter's name (see broadcast.receive_broadcast).
    """
    sender = request.headers.get("X-Chapter-Origin") or request.headers.get("x-chapter-origin", "")
    if not sender:
        return JSONResponse(status_code=400, content={"error": "X-Chapter-Origin header required"})
    if sender not in federation and sender != AGENT_ID:
        return JSONResponse(status_code=403, content={"error": "unknown_origin", "sender": sender})

    try:
        payload_dict = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})

    # S2S signature verification (model B). When the sender has a pinned
    # or attested did:key, the verification key is derived from the DID itself
    # — no did.json fetch, so a registry-supplied endpoint can't smuggle in an
    # attacker key. Peers without a pin fall back to the did.json discovery
    # anchored to the operator-added allowlist endpoint. Always verify + log;
    # REJECT when enforcement is enabled, which is the default: the warn-then-
    # enforce cutover closed and FEDERATION_ENFORCE_SIGNED_BROADCASTS now
    # defaults on (env_flags.security_flag, federation_signing.enforcement_enabled).
    # Setting it to a recognised falsey value returns to warn-only.
    import federation_signing

    peer_endpoint = (federation.get(sender) or {}).get("endpoint", "")
    pinned_did, pin_lookup_failed = await federation_signing.pinned_did_for(sender, federation.get(sender))
    enforcing = federation_signing.enforcement_enabled()
    # F5 fail-closed: if the persistent-pin read errored we cannot tell whether a
    # pin would override the endpoint's did.json. Under enforcement, refuse the
    # broadcast (retryable) rather than silently downgrade a pinned peer to
    # endpoint trust. In warn mode the whole gate is advisory, so we log and
    # proceed with whatever fallback resolved.
    if pin_lookup_failed:
        print(f"[federation] pin lookup failed for {sender!r} (enforcement={'on' if enforcing else 'off'})")
        if enforcing:
            return JSONResponse(
                status_code=503,
                content={"error": "pin_lookup_unavailable", "reason": "pin_lookup_failed"},
            )
    # Under enforcement, demand replay protection: a legacy (no-timestamp)
    # signature is rejected, not accepted as ok_legacy.
    sig_valid, sig_reason = await federation_signing.verify_inbound(
        payload_dict,
        dict(request.headers),
        peer_endpoint,
        require_replay_protection=enforcing,
        pinned_did=pinned_did,
    )
    if not sig_valid:
        print(
            f"[federation] unverified broadcast from {sender!r}: {sig_reason} (enforcement={'on' if enforcing else 'off'})"
        )
        if enforcing:
            return JSONResponse(status_code=403, content={"error": "unverified_signature", "reason": sig_reason})

    result = await broadcast_mod.receive_broadcast(
        payload_dict=payload_dict,
        sender_chapter_id=sender,
    )

    if result.get("ok"):
        return {
            "ok": True,
            "broadcast_id": result["broadcast_id"],
            "event_id": result["event_id"],
        }

    status_map = {
        "duplicate": 409,
        "invalid_payload": 400,
        "origin_sender_mismatch": 403,
        "self_origin_via_federation": 403,
        "uninitialized": 503,
        "local_publish_failed": 503,
    }
    status = status_map.get(result.get("reason", ""), 400)
    return JSONResponse(status_code=status, content=result)


@app.delete("/api/subscriptions/{subscription_id}", response_model=None)
async def cancel_subscription_endpoint(subscription_id: str, request: Request) -> dict | JSONResponse:
    """Soft-cancel a subscription owned by the caller (EB-3)."""
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    # Light input validation — Postgres will also constrain.
    safe_sub_id = sanitize_text(subscription_id, 64)
    if not safe_sub_id:
        return JSONResponse(status_code=400, content={"error": "subscription_id required"})

    ok = await subscriptions_svc.cancel_subscription(
        subscription_id=safe_sub_id,
        subscriber_agent_id=safe_id,
    )
    if not ok:
        # Same response shape for "not yours" + "not found" — see
        # subscriptions.cancel_subscription docstring on why we don't
        # distinguish (no per-id existence oracle for the hostile case).
        return JSONResponse(status_code=404, content={"error": "subscription not found"})
    return {"subscription_id": safe_sub_id, "cancelled": True}


class FeedbackSubmission(BaseModel):
    action_id: str
    action_type: str
    signal: str  # positive, negative, rsvp, skip
    agent_id: str = ""
    detail: str = ""


@app.post("/api/feedback", response_model=None)
async def submit_feedback(req: FeedbackSubmission, request: Request) -> dict | JSONResponse:
    """Record feedback on an agent action.

    Attributed to the auth-verified caller (``request.state.agent_id``), NOT the
    body-claimed ``req.agent_id`` — otherwise any member could mint a
    chapter-signed feedback receipt in another member's ledger and skew quality
    scores (C3). An unauthenticated caller is rejected here as well as at the
    middleware, so no feedback is ever recorded with an empty actor (kept
    consistent with the projection-update gate, C6).
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    await outcome_tracker.record_feedback(
        req.action_id,
        req.action_type,
        req.signal,
        caller,
        {"detail": req.detail} if req.detail else {},
    )
    return {"recorded": True, "action_id": req.action_id, "signal": req.signal}


@app.get("/api/outcomes")
async def get_outcomes() -> dict:
    """Get quality scores for all action types."""
    return {"scores": await outcome_tracker.get_quality_scores()}


# ============================================================
# AGENT CONVERSATION ENDPOINTS
# ============================================================
class ConversationStart(BaseModel):
    from_agent_id: str
    to_agent_id: str
    message: str
    topic: str = ""


@app.post("/api/conversations")
async def start_conversation_endpoint(req: ConversationStart, request: Request) -> dict:
    safe_from = _bind_actor_to_caller(request, req.from_agent_id, field="from_agent_id")
    safe_to = sanitize_agent_id(req.to_agent_id)
    safe_msg = sanitize_text(req.message, 500)
    result = await agent_conversations.start_conversation(safe_from, safe_to, safe_msg, req.topic)
    if "error" not in result:
        # Route opening message to target agent for response
        thread_id = result.get("thread_id", "")
        import sovereign_runtime

        reply = await sovereign_runtime._route_to_agent(safe_to, safe_msg, f"conv-{thread_id}")
        if reply:
            await agent_conversations.send_message(thread_id, safe_to, reply)
            result["reply"] = reply
        await activity_tracker.track(safe_from, "agent_conversation", {"partner": safe_to, "topic": req.topic[:100]})
    return result


@app.get("/api/conversations/{agent_id}")
async def get_conversations(agent_id: str, request: Request) -> dict:
    """A participant's own conversation threads — full message bodies.

    ⚠️ USED TO ANSWER FOR ANY agent_id WITH NO PARTICIPATION CHECK, while the
    write path on the same table (agent_conversations.send_message) has always
    enforced ``from_agent_id in (thread.from_agent_id, thread.to_agent_id)``.
    A thread's ``messages`` field is the verbatim conversation body between two
    agents; this route served it to anyone who supplied either party's id. Now
    requires a signature (``/api/conversations/`` is in
    ``auth_verify.REQUIRE_AUTH_GET_PREFIXES``) and, like ``/api/settings/{id}``,
    scopes the read to the caller via ``_require_agent_owner``.
    """
    safe_id = sanitize_agent_id(agent_id)
    _require_agent_owner(request, safe_id, what="conversations")
    threads = await agent_conversations.get_threads(safe_id)
    return {"threads": threads, "total": len(threads)}


class ConversationMessage(BaseModel):
    from_agent_id: str
    text: str


@app.post("/api/conversations/{thread_id}/message")
async def send_conversation_message(thread_id: str, req: ConversationMessage, request: Request) -> dict:
    safe_from = _bind_actor_to_caller(request, req.from_agent_id, field="from_agent_id")
    safe_text = sanitize_text(req.text, 500)
    result = await agent_conversations.send_message(thread_id, safe_from, safe_text)
    if "error" not in result:
        # Route to the other agent for response
        to_agent = result.get("to", "")
        if to_agent:
            import sovereign_runtime

            reply = await sovereign_runtime._route_to_agent(to_agent, safe_text, f"conv-{thread_id}")
            if reply:
                await agent_conversations.send_message(thread_id, to_agent, reply)
                result["reply"] = reply
    return result


# ============================================================
# AGENT EXPORT/IMPORT ENDPOINTS
# ============================================================
@app.get("/api/agents/{agent_id}/export")
async def export_agent_endpoint(agent_id: str, request: Request) -> dict:
    """Export an agent's portable state as JSON.

    Restricted to the agent itself (verified caller) or an admin. The full
    export carries conversation bodies, activity, and reputation history —
    ``requires_auth`` gates the endpoint at the middleware, and this handler
    additionally enforces that the verified caller owns the id (or holds an
    admin token), closing the cross-agent IDOR.
    """
    safe_id = sanitize_agent_id(agent_id)
    caller = _resolve_caller(request)
    is_admin = auth_verify.check_admin_token_header(dict(request.headers))
    if caller != safe_id and not is_admin:
        raise HTTPException(status_code=403, detail="export is restricted to the agent or an admin")
    return await agent_export.export_agent(safe_id)


@app.get("/api/agents/{agent_id}/profile")
async def agent_profile_surface(agent_id: str) -> dict:
    """Return a consented A2UI v0.9 profile surface for ``agent_id``.

    CONSENT-GATED (L1). A member's profile is served only if they opted in
    through ``POST /api/me/listing``; a member who has not answered has no
    profile, and the route answers 404 exactly as it does for an id that was
    never registered. Default private, and there is no state in which silence
    means yes.

    WHY THE GATE EXISTS, stated because the route used to be open and the
    reasoning for that was wrong. It was accepted as returning "only fields
    already public by design (skills, trust score, did:key)". It also returned
    ``description`` — free text the MEMBER wrote — as the card subtitle. That is
    the field an audit found carrying an email address and a phone number out to
    an unauthenticated GET, and the one ``sm-listing 0.1`` §4.2 forbids in a
    published entry. ``member_listing.entry_for`` prevents that structurally by
    copying named fields from a consent record; this handler reshaped the member
    row instead, and was the last open path that did. So this route published
    MORE than the consented Listing does, with LESS consent than the Listing
    requires.

    ``description`` is gone for the same reason — consent to be listed is not
    consent to publish arbitrary prose, and the remaining fields are the ones
    the Listing's own rule permits.

    ONE CONSENT RECORD, NOT TWO. The gate reads the same
    ``agents.config.listing`` record ``member_listing.consent_of`` reads. Two
    mechanisms for one decision drift, and the member has already been asked
    this question.

    NOT gated on ``ORRERY_LISTING_ENABLED``, deliberately. That flag governs
    whether the org serves the listing DOCUMENT at
    ``/.well-known/agent-community-listing.json``; the consent endpoint accepts a
    member's opt-in regardless of it. Gating profiles on it too would conflate
    "does this org publish a directory document" with "may this member's profile
    be shown", and would let an org's choice about its own surface silently
    overrule a member's answer about theirs. Default-private already gives an org
    what it needs: no member is visible until that member says so.

    Sharing a profile URL still works without an account — for a member who
    consented. That is the trade, and it is the whole user-visible change.

    Returns 404 if the agent isn't a member of this chapter. Federated
    agents are NOT served here — only local members. The federation peer
    of the foreign agent is the right source for that profile.

    FIXED: this is now the sole survivor of a near-duplicate pair (the
    other was GET /api/member/{agent_id}/profile, retired) and inherits
    that route's hidden-prefix gate — a TEST-* agent existing in the
    in-memory ``members`` dict must 404 exactly like a nonexistent one,
    with no branch that would let a caller distinguish "doesn't exist"
    from "exists but hidden" (test_public_listing_gate.py).
    """
    safe = sanitize_agent_id(agent_id)
    if not safe:
        raise HTTPException(status_code=400, detail="invalid agent_id")
    if _hidden_from_public_listing(safe) or safe not in members:
        raise HTTPException(status_code=404, detail="agent_not_found")

    m = members[safe]

    # The consent gate. Byte-identical to the two 404s above on purpose: a
    # caller must not be able to tell "no such member" from "a member who did
    # not opt in" — otherwise the gate closes the profile and opens a membership
    # oracle in its place, which is the finding this change exists to close.
    if member_listing.consent_of(m) is None:
        raise HTTPException(status_code=404, detail="agent_not_found")

    # Trust score (best-effort; missing trust DB row is not fatal —
    # surface the agent as newcomer rather than failing the page).
    trust_score: float = 0.0
    try:
        rows = await pg_request(
            "GET",
            "agents",
            params={"agent_id": f"eq.{safe}", "select": "trust_score", "limit": "1"},
        )
        if rows:
            trust_score = float(rows[0].get("trust_score") or 0.0)
    except Exception:  # noqa: BLE001 — public profile must not fail on telemetry blip
        trust_score = 0.0

    skills = list(m.get("skills") or [])[:12]
    origin = m.get("origin") or "sovereign"
    name = m.get("name") or f"@{safe}"

    components: list[dict] = [
        a2ui_helpers.member_card(
            "profile-card",
            name=name,
            agent_id=safe,
            avatar_url=m.get("avatar_url") or "",
            role=origin,
            trust_score=trust_score,
            skills=skills,
            # NO subtitle: it carried m["description"], member-authored free
            # text. See this handler's docstring — it is the C7 vector and
            # sm-listing 0.1 §4.2 forbids member prose in a published entry.
            subtitle="",
        ),
        a2ui_helpers.trust_badge("profile-trust", trust_score, show_score=True),
    ]
    children: list[str] = ["profile-card", "profile-trust"]

    if skills:
        components.append(a2ui_helpers.text("profile-skills-label", "Skills", "h3"))
        components.append(a2ui_helpers.list_component("profile-skills-list", skills))
        children.extend(["profile-skills-label", "profile-skills-list"])

    components.append(
        a2ui_helpers.text(
            "profile-meta",
            f"Member of {AGENT_NAME}. did:key:{m.get('did_key', '')[:48]}…",
            "caption",
        )
    )
    children.append("profile-meta")

    components.append(a2ui_helpers.column("profile-root", children))
    return a2ui_helpers.surface(f"agent-profile-{safe}", components, "profile-root")


class AgentImportRequest(BaseModel):
    export_data: dict
    profile_id: str = ""


@app.post("/api/agents/import", response_model=None)
async def import_agent_endpoint(req: AgentImportRequest) -> dict | JSONResponse:
    """Import an agent from exported JSON into this chapter."""
    result = await agent_export.import_agent(req.export_data, req.profile_id)
    if result.get("imported"):
        # Register with members dict so it joins the think cycle
        aid = result["agent_id"]
        agent_data = req.export_data.get("agent", {})
        members[aid] = {
            "name": agent_data.get("name", f"@{aid}"),
            "description": agent_data.get("description", ""),
            "skills": agent_data.get("skills", []),
            "personality": "",
            "voice": "helpful",
            "virtual": True,
            "endpoint": "",
        }
        # Register on NEST
        if PUBLIC_URL:
            asyncio.create_task(nanda_registry.register_member(aid, members[aid], PUBLIC_URL))
    return result


@app.get("/api/projections", response_model=None)
async def get_projections_endpoint() -> dict | JSONResponse:
    """List all members' anonymized capability projections.

    FIXED: used to answer for anyone with no auth at all, AND to leak each
    member's real agent_id as projection_id — despite
    projections.get_projections()'s own docstring claiming "anonymized —
    no agent_ids in output". Identity is meant to be revealed only after
    bilateral consent (see the projections module docstring); projection_id
    defeated the one property this endpoint exists to provide. Now requires
    a signature (/api/projections is in auth_verify.REQUIRE_AUTH_GET_PATHS;
    not self-scoped — this is a directory of OTHER members' capabilities,
    same shape as /api/policy) and strips projection_id before returning.
    The id itself stays available internally via
    projections.get_projections_with_ids() for the intent-matching
    pipeline's own exclusion/correlation needs, which never render it to a
    caller — get_projections() itself is unchanged, only this handler's
    response is filtered.
    """
    projs = [{k: v for k, v in p.items() if k != "projection_id"} for p in projections.get_projections()]
    return {"projections": projs, "chapter": AGENT_ID}


class ProjectionUpdate(BaseModel):
    """Partial update to a member's public projection.

    Members own their projection — chapter operators do not edit it.
    The middleware enforces that the X-Agent-ID matches the body's
    ``agent_id`` so an agent can only update its own projection.
    """

    agent_id: str
    skills: list[str] | None = None
    interests: list[str] | None = None
    availability: str | None = None


@app.post("/api/projections", response_model=None)
async def update_projection_endpoint(req: ProjectionUpdate, request: Request) -> dict | JSONResponse:
    """Update the calling agent's public projection.

    Projections in this runtime are derived from the member record, so
    we update the underlying ``members[agent_id]`` fields and let the
    next ``build_projection`` call surface the change. Returns the
    new projection.
    """
    safe_id = sanitize_agent_id(req.agent_id)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "agent_id required"})

    # Authn enforcement: the signed request must come from this agent. Identity
    # comes ONLY from the middleware-verified ``request.state.agent_id`` — the
    # spoofable ``X-Agent-ID`` header is never trusted, and an empty caller is
    # rejected rather than allowed to fall through (C6).
    caller = _resolve_caller(request)
    if caller != safe_id:
        return JSONResponse(
            status_code=403,
            content={"error": "agent_id mismatch", "caller": caller, "target": safe_id},
        )

    member = members.get(safe_id)
    if not member:
        return JSONResponse(status_code=404, content={"error": f"unknown agent {safe_id!r}"})

    if req.skills is not None:
        member["skills"] = [sanitize_text(s, 50) for s in (req.skills or [])[:20]]
    if req.interests is not None:
        # Interests aren't a top-level member field today — store under
        # a side bucket so the schema stays additive.
        member["interests"] = [sanitize_text(s, 50) for s in (req.interests or [])[:20]]
    if req.availability is not None:
        member["availability"] = sanitize_text(req.availability, 30)

    return {
        "agent_id": safe_id,
        "updated": True,
        "projection": projections.build_projection(safe_id, member),
    }


# ============================================================
# A2UI ACTION ENDPOINT — interactive component callbacks
# ============================================================
class SurfaceAction(BaseModel):
    surface_id: str
    component_id: str
    action: str
    values: dict = {}  # form values, input text, selections


@app.post("/api/surfaces/action")
async def handle_surface_action(req: SurfaceAction, request: Request) -> dict:
    """Process an interactive A2UI component action and return updated surface."""
    action = req.action
    values = req.values

    # Intent submission via A2UI form. Values arrive keyed by the component id
    # of each Input in the Form — the only key a renderer has, since A2UI gives
    # an Input no name of its own — so they are read by the ids the dashboard
    # surface declares, not by a second spelling kept here.
    if action == "submit_intent":
        intent_text = str(values.get(surfaces.DASH_INTENT_INPUT, "") or "").strip()
        # Authorship comes from the verified caller, NOT the body. This
        # path is OPEN, so an unsigned form may submit — but only anonymously;
        # the body-supplied requester_agent_id is never trusted to name an
        # author, otherwise anyone could plant an intent "as" a victim and
        # pollute their activity/receipts. A non-anonymous attribution
        # requires a valid Ed25519 signature (request.state.agent_id).
        requester = _resolve_caller(request) or "anonymous"
        tags_raw = values.get(surfaces.DASH_INTENT_TAGS, "")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if isinstance(tags_raw, str) else tags_raw

        if not intent_text:
            return _surface(
                "action-error",
                [
                    _card("page", "root"),
                    _column("root", ["err"]),
                    _alert("err", "Please describe what you need.", "Missing Intent", "warning"),
                ],
                "page",
            )

        # Extract tags via LLM if none provided; a keyless org has no client
        # and files the intent untagged.
        if not tags and llm is not None:
            try:
                tag_resp = llm.chat.completions.create(
                    model=DEFAULT_LLM_MODEL,
                    messages=[
                        {
                            "role": "system",
                            "content": "Extract 2-5 skill/topic tags. Return ONLY comma-separated lowercase tags.",
                        },
                        {"role": "user", "content": intent_text},
                    ],
                    max_tokens=50,
                )
                tags = [t.strip() for t in (tag_resp.choices[0].message.content or "").split(",") if t.strip()][:5]
            except Exception:
                tags = []

        intent_id = await intents.create_intent(sanitize_agent_id(requester), sanitize_text(intent_text, 500), tags)
        local_result = await intents.match_intent(intent_id)
        fed_result = await intents.match_intent_federation(intent_id, federation)
        await activity_tracker.track(requester, "intent_submitted", {"intent": intent_text[:100]})

        local_count = local_result.get("local_matches", 0)
        remote_count = fed_result.get("remote_matches", 0)
        total = local_count + remote_count
        matched_skills = local_result.get("matched_skills", [])

        # Build result surface with match breakdown
        sections = ["ir-title", "ir-stats", "ir-div1"]
        components = [
            _text("ir-title", "Intent Matched", "h2"),
            _row("ir-stats", ["ir-local", "ir-remote", "ir-total"]),
            _metric("ir-local", str(local_count), "Local"),
            _metric("ir-remote", str(remote_count), "Federation"),
            _metric("ir-total", str(total), "Total"),
            _divider("ir-div1"),
        ]

        if total > 0:
            components.append(
                _alert(
                    "ir-status",
                    "Anonymous requests sent to matched agents. You'll be introduced after mutual consent. Your identity stays private.",
                    f"{total} Matches Found",
                    "success",
                )
            )
            sections.append("ir-status")

            # Show matched skills
            if matched_skills:
                sections.append("ir-skills-label")
                components.append(_text("ir-skills-label", "Matched Skills", "h3"))
                skill_chips = []
                for i, skill in enumerate(matched_skills[:10]):
                    cid = f"ir-skill-{i}"
                    skill_chips.append(cid)
                    components.append(_badge(cid, skill, "secondary"))
                sections.append("ir-skills-row")
                components.append(_row("ir-skills-row", skill_chips))

            # Show local match details (anonymized — server + skills only)
            local_matches_raw = projections.match_intent_against_projections(
                intent_text, tags, [p for p in projections.get_projections() if p.get("projection_id") != requester]
            )
            if local_matches_raw:
                sections.extend(["ir-div2", "ir-local-label"])
                components.extend(
                    [
                        _divider("ir-div2"),
                        _text("ir-local-label", f"Local Matches ({len(local_matches_raw)} in {AGENT_NAME})", "h3"),
                    ]
                )
                for i, m in enumerate(local_matches_raw[:8]):
                    mid = f"ir-lm-{i}"
                    sections.append(mid)
                    skills_text = ", ".join(m.get("matched_skills", [])[:5])
                    components.extend(
                        [
                            _card(mid, f"{mid}-col"),
                            _column(f"{mid}-col", [f"{mid}-skills", f"{mid}-score"]),
                            _text(f"{mid}-skills", f"Skills: {skills_text}", "body"),
                            _badge(f"{mid}-score", f"Score: {m.get('score', 0):.1f}", "outline"),
                        ]
                    )

            # Show federation match details
            fed_details = fed_result.get("details", [])
            if fed_details:
                sections.extend(["ir-div3", "ir-fed-label"])
                components.extend(
                    [
                        _divider("ir-div3"),
                        _text("ir-fed-label", "Federation Matches", "h3"),
                    ]
                )
                for i, fd in enumerate(fed_details[:5]):
                    fid = f"ir-fm-{i}"
                    sections.append(fid)
                    ch_name = fd.get("chapter_name", fd.get("chapter_id", "?"))
                    count = fd.get("match_count", 0)
                    ch_skills = ", ".join(fd.get("matched_skills", [])[:5])
                    components.extend(
                        [
                            _card(fid, f"{fid}-col"),
                            _column(f"{fid}-col", [f"{fid}-name", f"{fid}-info"]),
                            _text(f"{fid}-name", ch_name, "h4"),
                            _text(f"{fid}-info", f"{count} matches · Skills: {ch_skills}", "caption"),
                        ]
                    )
        else:
            components.append(
                _alert(
                    "ir-status",
                    "No matches yet. Your intent is recorded — I'll keep looking as new members join and skills evolve.",
                    "No Matches",
                    "default",
                )
            )
            sections.append("ir-status")

        components.insert(0, _column("root", sections))
        return _surface("intent-result", [_card("page", "root")] + components, "page")

    # Feedback on agent actions via A2UI
    if action == "submit_feedback":
        action_id = values.get("action_id", "")
        action_type = values.get("action_type", "unknown")
        signal = values.get("signal", "positive")
        agent_id = values.get("agent_id", "")
        await outcome_tracker.record_feedback(action_id, action_type, signal, agent_id)
        msg = "Thanks for the feedback!" if signal == "positive" else "Noted — we'll improve."
        return _surface(
            "feedback-ack",
            [
                _card("page", "root"),
                _column("root", ["fb-msg"]),
                _toast("fb-msg", msg, "Feedback Recorded", "success" if signal == "positive" else "default"),
            ],
            "page",
        )

    # Consent response via A2UI.
    #
    # Responding to an intent records consent AND reveals BOTH parties' identity
    # (consent_gate.check_mutual_consent — "the ONLY place where identity crosses
    # the privacy boundary"). This endpoint (/api/surfaces/action) is OPEN, so
    # there is no verified caller here and the body-supplied responder_agent_id
    # cannot be trusted — an unauthenticated caller could record a consent as a
    # victim and unlock the requester's PII (the surface-action twin of that change,
    # caught by the sweep). Consent MUST go through the signed
    # POST /api/intents/respond (verified caller + matched-responder gate); this
    # surface only directs the user there. No respond, no reveal on the open path.
    if action == "consent_respond":
        return _surface(
            "consent-auth-required",
            [
                _card("page", "root"),
                _column("root", ["cr-title", "cr-msg"]),
                _text("cr-title", "Sign in to respond", "h2"),
                _text(
                    "cr-msg",
                    "Responding to an intent reveals both parties' identities, so it "
                    "must come from your signed agent — POST /api/intents/respond.",
                    "body",
                ),
            ],
            "page",
        )

    return {"error": f"Unknown action: {action}"}


@app.get("/api/members")
@app.get("/api/members/")
async def list_members(skill: str | None = None, role: str | None = None) -> dict:
    # Enrich with Postgres profile data if available
    agent_profiles = {}
    profile_data = await pg_request(
        "GET",
        "agents",
        params={
            "select": "agent_id,profile_type,interests,availability,github_data,linkedin_url,reputation",
        },
    )
    if profile_data:
        for p in profile_data:
            agent_profiles[p.get("agent_id", "")] = p

    results = []
    for mid, m in members.items():
        if _hidden_from_public_listing(mid):
            continue  # gate: test artifacts never surface in public directory
        if skill and skill.lower() not in [s.lower() for s in m.get("skills", [])]:
            continue
        profile = agent_profiles.get(mid, {})
        profile_type = profile.get("profile_type", "member")
        if role and profile_type != role:
            continue
        is_startup = mid.startswith("STARTUP-")
        results.append(
            {
                "agent_id": mid,
                "name": m["name"],
                "description": m["description"],
                "skills": m.get("skills", []),
                "profile_type": profile_type if not is_startup else "startup_team",
                "interests": profile.get("interests", []),
                "availability": profile.get("availability", "active"),
                "github_url": (profile.get("github_data") or {}).get("url"),
                "linkedin_url": profile.get("linkedin_url"),
                "reputation": profile.get("reputation", {}),
                "virtual": m.get("virtual", False),
                "chapter": AGENT_ID,
            }
        )
    return {"members": results, "total": len(results), "chapter": AGENT_ID}


@app.get("/api/event-catalog")
async def event_catalog() -> dict:
    """The event-bus contract a subscriber needs BEFORE it renders anything.

    Deliberately not ``/api/events/catalog``: ``/api/events`` is the
    agent-proposed community events list, an unrelated surface, and nesting the
    bus catalog under it would read as a sub-resource of that list.

    Open, and it can afford to be: every value is derived from module-level
    constants in ``event_types`` — the enum, the trust tiers, and the two
    provenance tables. Nothing per-principal, nothing from a database.

    WHY THIS EXISTS. The server does not escape event text on the way out
    because it does not know the rendering context; a subscriber that renders
    the text unescaped has an XSS. What the server owes that subscriber is not
    pretending the text is safe, and a statement it can only read in our source
    is not a contract. ``text_provenance`` names, per event type, which fields
    this server authored and which arrived from a member, a peer org or a
    language model. ``test_event_text_provenance.py`` keeps it total: a payload
    field cannot be added without being classified here.
    """
    import event_types as _et

    return {
        "org": AGENT_ID,
        "escaping": (
            "This server does not escape event text: it cannot know your rendering "
            "context. Escape every field listed under text_provenance.untrusted for "
            "the context you render it into. summary_markdown is markdown WITHOUT "
            "embedded HTML — disable raw HTML in your markdown renderer for it."
        ),
        "events": {
            event_type.value: {
                "min_trust_to_subscribe": _et.MIN_TRUST_TO_SUBSCRIBE[event_type],
                "text_provenance": _et.text_provenance(event_type),
            }
            for event_type in sorted(_et.PAYLOAD_FOR, key=lambda e: e.value)
        },
    }


@app.get("/api/events")
async def list_events() -> dict:
    """List agent-proposed events.

    Keyless public by CORS design (see _PUBLIC_CORS_PATHS) — but each row's
    suggested_speakers is a member display name the event-proposal LLM was
    prompted with, so it is redacted here before serving. See
    thought_redaction.redact_suggested_speakers.
    """
    events = await pg_request(
        "GET",
        "agent_events",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
        },
    )
    event_rows = events if isinstance(events, list) else []
    event_rows = thought_redaction.redact_suggested_speakers(event_rows)
    return {"events": event_rows, "total": len(event_rows)}


@app.get("/api/digest")
async def get_digest() -> dict:
    """Get the latest chapter digest — weekly aggregate highlights.

    Keyless by design, same tier as the sibling /api/events and
    /api/federation/divergence surfaces (see that docstring). Traced:
    think_cycle.think_digest's `highlights` are aggregate counts ("N
    agent activities", "N members active", "N federated chapters"), and
    the LLM summary is prompted from those counts alone — unlike
    /api/events' prompt, which is fed real member names and needed a
    redaction. No per-member field appears anywhere in this response.
    """
    digests = await pg_request(
        "GET",
        "agent_digests",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "1",
        },
    )
    return {"digest": digests[0] if digests else None}


@app.get("/api/federation/divergence")
async def get_registry_divergence(limit: int = 50) -> dict:
    """Recent cross-registry divergence findings.

    The divergence detector (``registry_divergence.check``, run each heartbeat)
    publishes ``federation.registry.divergence`` findings to the event bus; this
    surfaces them read-only so an operator can see the detector working instead
    of it running blind. Findings are public-tier (the registry records they
    compare are already on each registry's ``/api/agents``), so this GET is
    keyless like the sibling ``/api/events`` and ``/api/digest`` surfaces.

    Each item is the finding payload as emitted — ``kind`` (omission / endpoint
    / did / unconfirmed), ``agent_id``, and the kind-specific detail — plus the
    ``observed_at`` timestamp and event id. Reverse-chronological.
    """
    n = max(1, min(500, limit))
    rows = await pg_request(
        "GET",
        "event_log",
        params={
            "event_type": "eq.federation.registry.divergence",
            "order": "id.desc",
            "limit": str(n),
            "select": "id,payload,created_at",
        },
    )
    findings = []
    for r in rows or []:
        payload = r.get("payload") or {}
        findings.append(
            {
                "event_id": r.get("id"),
                "observed_at": r.get("created_at"),
                "kind": payload.get("kind"),
                "agent_id": payload.get("agent_id"),
                # kind-specific detail, echoed as stored (omitting the envelope keys)
                "detail": {
                    k: v for k, v in payload.items() if k not in ("kind", "agent_id", "event_id", "occurred_at")
                },
            }
        )
    # The status travels WITH the findings. An empty list is ambiguous on its
    # own — it means "compared everything, found nothing" or "compared nothing" —
    # and a reader should not have to cross-reference /health to tell which.
    return {
        "findings": findings,
        "total": len(findings),
        "corroboration": registry_divergence.corroboration_status(
            nanda_registry.configured_registries() + federation_discovery.directory_urls()
        ),
    }


@app.delete("/api/members/{agent_id}")
async def remove_member(agent_id: str, request: Request) -> JSONResponse:
    """Remove a member from this chapter. Two authorized paths:

    - **Self-removal (sovereignty):** a member removes THEMSELVES,
      authorized by their own Ed25519 signature — the verified caller
      (``request.state.agent_id``, set only on a valid signature) equals the
      target. A signed member can only remove *itself* this way, never a victim.
    - **Admin removal:** an admin/leader removes another member (admin token or
      signed admin), via the admin handler — identical last-admin protection,
      durable Postgres-row removal, and audit. The canonical operator path is
      ``DELETE /admin/api/members/{agent_id}``; this alias stays for clients
      that already point at it.
    """
    caller = sanitize_agent_id(_resolve_caller(request))
    if caller and caller == sanitize_agent_id(agent_id):
        return await _self_remove_member(caller, request)
    return await admin_remove_member(agent_id, request)


async def _self_remove_member(safe_id: str, request: Request) -> JSONResponse:
    """A member leaving the org under its own signature (caller already verified
    to equal ``safe_id``). Last-admin protection still applies — the sole admin
    must promote a successor before leaving, or the org is left ungovernable."""
    current_rows = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe_id}", "select": "chapter_role"},
    )
    current_role = (current_rows[0].get("chapter_role") if current_rows else None) or "member"
    if current_role == "admin":
        admin_rows = await pg_request("GET", "agents", params={"chapter_role": "eq.admin", "select": "agent_id"})
        remaining = [r for r in (admin_rows or []) if r.get("agent_id") != safe_id]
        if not remaining:
            return JSONResponse(
                status_code=409,
                content={
                    "error": "would leave no admin",
                    "hint": "You are the last admin. Promote another member to admin (POST /admin/api/members/{id}/role) before leaving.",
                },
            )

    removed_member = members.pop(safe_id, None)
    # quilt delta feed — removal is a "delete" delta so cross-org sync
    # consumers drop the member instead of serving it forever.
    if removed_member is not None:
        try:
            import sm_bridge_adapter as _smb

            _smb.record_member_delta("delete", safe_id, removed_member)
        except Exception as _e:  # noqa: BLE001
            print(f"[sm-bridge][WARN] quilt delete-delta not recorded for {safe_id!r}: {type(_e).__name__}")
    if hasattr(auth_verify, "_agent_keys"):
        auth_verify._agent_keys.pop(safe_id, None)
    await pg_request("DELETE", "agents", params={"agent_id": f"eq.{safe_id}"})

    # Emit member.left so subscribers see departures, mirroring member.joined
    # on registration (the event type existed but was never published).
    asyncio.create_task(event_bus.safe_publish("member.left", {"agent_id": safe_id, "reason": "self_revoke"}))

    try:
        import chapter_audit

        await chapter_audit.record(
            chapter_id=AGENT_ID,
            action="member.self_remove",
            actor_agent_id=safe_id,
            target_type="agent",
            target_id=safe_id,
            outcome="ok",
            detail={"role_before": current_role, "auth_path": "self-signed"},
        )
    except Exception:  # noqa: BLE001 — audit is best-effort, never block the leave
        pass

    return JSONResponse(content={"removed": safe_id, "self": True})


@app.get("/api/federation")
async def get_federation() -> dict:
    return {
        "self": {"agent_id": AGENT_ID, "name": AGENT_NAME, "focus": AGENT_FOCUS},
        "chapters": dict(federation),
        "total": len(federation),
    }


@app.get("/api/federation/{chapter_id}/members")
async def get_federation_members(chapter_id: str) -> dict:
    if chapter_id not in federation:
        raise HTTPException(status_code=404, detail=f"Unknown chapter '{chapter_id}'")
    result = await federation_discovery.query_chapter_members(chapter_id)
    return {"chapter": chapter_id, "members": result, "total": len(result)}


@app.get("/api/knowledge/summary")
async def get_knowledge_summary() -> dict:
    """Return our chapter intelligence summary for federation exchange.

    Uses the async variant so the payload includes our policy_snapshot
    (used by peer chapters with policy.federation.enabled=true for
    federation-wide governance merge).
    """
    return await federation_intelligence.get_our_summary_async()


@app.get(federation_feed.FEED_PATH, response_model=None)
async def federation_intelligence_feed(since: int | None = None) -> JSONResponse | dict:
    """sm-federation §4 — a signed page of this org's intelligence feed.

    PUBLIC/OPEN by design, and declared so in ``auth_verify.OPEN_PATHS``. A peer
    that has never met this org discovers it through the unauthenticated node
    descriptor and follows ``feed_url`` from there; gating the feed would make the
    pointer resolve to a 401 and put us back where ``did.json`` was in the public-discovery rule. The
    payload is aggregate-only by §3 — skill graph, gaps, trends, counts — and
    carries no per-member identity, so there is nothing here that authentication
    would be protecting.

    The subscriber, not the server, decides whether to trust this: every entry is
    Ed25519-signed by the org's own key and hash-chained to its predecessor, so
    ``?since=<cursor>`` returns a run whose completeness the peer VERIFIES. That
    is the whole difference from ``GET /api/knowledge/summary``, which is an
    unsigned cursorless snapshot — the v0.1 model §4 replaced, still served for
    Orrery's own peers and deliberately NOT what ``feed_url`` points at.

    ⚠️ A subscriber continuing a subscription MUST pass back the head it last
    accepted (``expected_head`` in ``read_intelligence``). Without it a publisher
    that restarted its sequence verifies as a clean first sync — sm-federation
    0.5.0 made that normative after the conformance suite found the reference seam
    could not detect a rewind at all.
    """
    if not federation_feed.is_available():
        # 501, not 404: the surface exists in this runtime and this deployment
        # cannot serve it. The descriptor already says so — no feed_url, so no
        # federation/0.1#4 claim — and a peer should only reach this by ignoring
        # that, so the body says which of the two reasons applies.
        return JSONResponse(
            status_code=501,
            content={
                "error": "federation_feed_unavailable",
                "detail": federation_feed.unavailable_reason(),
                "hint": (
                    "This node is sm-federation §2-only. Its node descriptor omits feed_url and "
                    "does not claim federation/0.1#4; subscribe only to nodes that claim it."
                ),
            },
        )

    identity = federation_feed.feed_identity(sovereign_identity._ed25519_keypairs.get(AGENT_ID))
    if identity is None:
        # Reading a feed must never mint an identity. No key is a 503, the
        # same answer /.well-known/did.json gives, for the same reason.
        return JSONResponse(
            status_code=503,
            content={
                "error": "identity_not_initialized",
                "detail": "This org has no Ed25519 signing key yet; the feed is signed with it and is not generated on demand.",
            },
        )

    return await federation_feed.build_page(
        pg_request, identity, since=since, generated_at=datetime.now(UTC).isoformat()
    )


@app.get(member_listing.LISTING_PATH, response_model=None)
async def agent_listing() -> JSONResponse:
    """sm-listing 0.1 — the members who chose to be discoverable.

    PUBLIC, and declared so in ``auth_verify.OPEN_PATHS``. This is the document a
    stranger reads to find a member inside an org it has never met; gating it
    would defeat its only purpose, and unlike the Directory there is nothing here
    that anyone declined to publish.

    ⚠️ **NOT a filter over the member directory.** The Directory is gated and
    stays gated. This is a different resource over a different population — the
    members who opted in — and its default state is EMPTY.

    Non-consenting members are ABSENT: dropped in `member_listing`, at the layer
    that owns the preference, so this handler never sees them. No count of them
    exists anywhere, which is what makes "a count of the non-consenting is a
    census of them" enforceable rather than advisory.
    """
    if not member_listing.is_enabled():
        # §: a node that does not implement the profile MUST NOT serve this path.
        # 404, never an empty document — the path is a CLAIM. An empty listing
        # means "I run this surface and nobody has opted in", which is a
        # different and more useful fact than silence; serving one from an org
        # that never enabled the profile would say the first and mean the second.
        return JSONResponse(
            status_code=404,
            content={
                "error": "listing_profile_not_implemented",
                "detail": (
                    f"This org does not implement the member-listing profile. Set "
                    f"{member_listing.ENABLED_FLAG}=true to serve it; until then this path is "
                    "absent rather than empty, because an empty listing is a claim that the "
                    "surface exists and nobody opted in."
                ),
            },
        )
    try:
        doc = member_listing.build(members, community_id=AGENT_ID, generated_at=datetime.now(UTC).isoformat())
    except ValueError as exc:
        # §3's presence half, made loud. An entry that cannot be published is NOT
        # skipped: skipping would leave a consenting member silently absent and a
        # listing that is MORE conformant against the absence rule the less it
        # contains. 500 with the reason, so the operator sees which member and why.
        print(f"[listing][ERROR] refusing to publish an incomplete listing: {exc}", flush=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "listing_entry_unpublishable",
                "detail": str(exc),
                "hint": (
                    "A member consented to be listed but their entry cannot be published. The "
                    "listing is NOT served with that member silently omitted — fix the entry or "
                    "withdraw the consent."
                ),
            },
        )
    return JSONResponse(content=doc, media_type="application/json")


class ListingConsentRequest(BaseModel):
    listed: bool = False
    did: str | None = None
    geo: dict | None = None
    offering: list | None = None
    trade: dict | None = None


@app.post("/api/me/listing", response_model=None)
@app.post("/api/me/listing/", response_model=None)
async def set_listing_consent(req: ListingConsentRequest, request: Request) -> JSONResponse:
    """The member's own opt-in — explicit, default private, self-signed.

    Modelled on ``/api/me/chronicle-public``: the caller must BE the agent being
    updated, and their identity comes from the middleware-verified signature, not
    from a header. Default private means a member who never calls this is never
    listed; there is no state in which silence means yes.

    Per-field consent is per FIELD: omitting `geo` publishes no geo and does not
    hide the row, which is `contact_public`'s rule rather than
    `profiles.is_public`'s.
    """
    caller = _resolve_caller(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "auth required"})
    safe_id = sanitize_agent_id(caller)
    if not safe_id or safe_id not in members:
        return JSONResponse(status_code=400, content={"error": "unknown agent_id"})

    payload = {k: v for k, v in req.model_dump().items() if v is not None}
    payload["listed"] = bool(req.listed)
    if payload["listed"]:
        # Server-set, never member-supplied: it is their REGISTERED endpoint or
        # nothing. Stored in the consent record because members[id]["endpoint"]
        # is in-memory only — see member_listing.SERVER_SET_FIELDS.
        payload["agent_url"] = str(members[safe_id].get("endpoint") or "").strip()

    ok, reason = member_listing.validate_consent_request(payload, members[safe_id])
    if not ok:
        # Refused at the moment of consent rather than at publication: this keeps
        # "consenting implies publishable" true by construction, and puts the
        # error in front of the person who can fix it instead of in a 500 for a
        # stranger reading the listing.
        return JSONResponse(status_code=400, content={"error": "cannot_be_listed", "detail": reason})

    existing = await pg_request("GET", "agents", params={"agent_id": f"eq.{safe_id}", "select": "config", "limit": "1"})
    config = ((existing or [{}])[0] or {}).get("config") or {}
    config[member_listing.CONSENT_KEY] = payload if payload["listed"] else None
    await pg_request("PATCH", "agents", params={"agent_id": f"eq.{safe_id}"}, body={"config": config})
    members[safe_id][member_listing.CONSENT_KEY] = config[member_listing.CONSENT_KEY]
    # Consent is what makes a member discoverable on the sm-bridge surfaces,
    # so this is the lifecycle event the quilt delta feed carries: an opt-in
    # publishes the member, an opt-out retracts them.
    import sm_bridge_adapter as _smb

    _smb.record_member_delta("upsert" if payload["listed"] else "delete", safe_id, members[safe_id])

    return JSONResponse(
        content={
            "agent_id": safe_id,
            "listed": payload["listed"],
            "published_fields": sorted(k for k in payload if k != "listed"),
            "detail": (
                "You are now discoverable in this org's public listing at "
                f"{member_listing.LISTING_PATH}, carrying only the fields above."
                if payload["listed"]
                else "You are not listed. Nothing about you appears in the public listing."
            ),
        }
    )


@app.get("/api/knowledge/network")
async def get_network_knowledge() -> dict:
    """Return aggregated network-wide intelligence."""
    return {
        "skill_map": federation_intelligence.get_network_skill_map(),
        "trends": federation_intelligence.get_network_trends(),
        "skill_matches": federation_intelligence.find_skill_matches(),
        "chapters_with_knowledge": len(federation_intelligence.federation_knowledge),
        "our_summary": federation_intelligence.get_our_summary(),
        "peer_summaries": {
            cid: {
                "chapter_name": k.get("chapter_name", cid),
                "top_skills": k.get("top_skills", []),
                "skill_gaps": k.get("skill_gaps", []),
                "trending_topics": k.get("trending_topics", []),
                "member_count": k.get("member_count", 0),
                "fetched_at": k.get("fetched_at"),
            }
            for cid, k in federation_intelligence.federation_knowledge.items()
        },
    }


@app.get("/api/activity")
async def get_activity(limit: int = 50) -> dict:
    """Public activity feed for this chapter."""
    data = await pg_request(
        "GET",
        "agent_activity",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": str(limit),
        },
    )
    return {"activity": data or [], "chapter": AGENT_ID}


@app.get("/api/thoughts")
async def get_thoughts(limit: int = 30) -> dict:
    """Public thoughts feed for this chapter — includes A2UI surfaces.

    Keyless by design, and the REDACTION is what makes that defensible,
    not an assumption that the prose is already safe: hidden-prefix
    rows are dropped outright (a row naming a hidden fixture is never
    shown, not merely edited), the unredactable `targets` field is
    dropped from every row, and every surviving row is passed through
    thought_redaction.redact_deep, which replaces every `@handle`
    mention — in thought_text AND in the a2ui_surface's card titles —
    with a visible marker before the response is built. Nothing reaches
    an anonymous caller without going through that transform first.
    """
    # Over-fetch so the post-filter still has at least `limit` items
    # in the common case where ≤30% of rows contain test artifacts.
    raw_limit = max(limit * 2, 60)
    data = (
        await pg_request(
            "GET",
            "agent_thoughts",
            params={
                "chapter_agent_id": f"eq.{AGENT_ID}",
                "order": "created_at.desc",
                "limit": str(raw_limit),
            },
        )
        or []
    )

    def _mentions_hidden(thought: dict) -> bool:
        """Whether this row must not be shown to a public caller at all.

        ⚠️ THE PROSE CHECK IS A SUBSTRING SEARCH FOR ``"TEST-"``. It matches a
        seeded test account and nothing else — ``@priya-sharma-12`` passes it
        untouched — so this route read as filtering handles while filtering one
        prefix. The prefix tuple decides which MEMBERS are hidden, which is
        what it is for; it was never a statement about what prose contains.
        Handles are removed by redaction below, not by this predicate.
        """
        member = thought.get("member_agent_id") or ""
        if _hidden_from_public_listing(member):
            return True
        body = thought.get("thought_text") or ""
        return any(p in body for p in _PUBLIC_HIDDEN_PREFIXES)

    # Hidden members' rows are dropped; every surviving row is redacted.
    # Dropping every row that names ANY member would empty the feed, since the
    # conversation type always does — the handle is the leak, not the thought.
    #
    # redact_deep, not redact_handles on thought_text alone: this route returns
    # the WHOLE row, and a2ui_surface carries handles too (its card titles are
    # built as f"@{agent_id} thinks"). A filter reading only thought_text
    # leaves them — the same leak one column across.
    #
    # targets is dropped rather than redacted: entries are bare values
    # ({"agent_id": ..., "name": ...}), and HANDLE_RE needs a leading @ —
    # redact_deep cannot reach them. Nothing in this repo reads the field
    # back off a thought row (every read is a signing/build path, never a
    # consumer of this route), so dropping it from the anonymous response
    # is the cheap, honest fix rather than teaching redact_deep a second
    # value shape for a field nobody uses.
    visible = []
    for t in data:
        if _mentions_hidden(t):
            continue
        row = dict(t)
        row.pop("targets", None)
        visible.append(thought_redaction.redact_deep(row))
        if len(visible) >= limit:
            break
    return {"thoughts": visible, "chapter": AGENT_ID}


def _build_package_a2ui(startup: dict, phases: dict, eval_summary: dict | None, team: list) -> dict:
    """Build a rich A2UI card for the full business package."""
    title = startup.get("title", "Startup")
    status = startup.get("status", "proposed")
    grade = startup.get("avg_grade", 0) or 0
    sprint = startup.get("sprint_phase", 0) or 0
    phase_labels = {0: "Research", 1: "Spec & Plan", 2: "Build Sprint", 3: "Launch", 4: "Iterate"}

    status_color = {
        "building": "bg-blue-500/10 text-blue-700",
        "funded": "bg-green-500/10 text-green-700",
        "evaluating": "bg-yellow-500/10 text-yellow-700",
    }.get(status, "bg-muted text-muted-foreground")

    children = ["pkg-title", "pkg-header", "pkg-div1", "pkg-problem", "pkg-solution"]
    components = [
        _text("pkg-title", title, "h1"),
        _row("pkg-header", ["pkg-status", "pkg-phase", "pkg-grade-metric"]),
        _badge("pkg-status", status.title(), "secondary", status_color),
        _badge("pkg-phase", f"Sprint: {phase_labels.get(sprint, '?')}", "outline"),
        _metric(
            "pkg-grade-metric",
            f"{grade:.1f}" if grade else "—",
            "Grade",
            "/50",
            "up" if grade >= 35 else "down" if grade and grade < 25 else "neutral",
        ),
        _divider("pkg-div1"),
        _text("pkg-problem", f"Problem: {startup.get('problem', '—')}", "body"),
        _text("pkg-solution", f"Solution: {startup.get('solution', '—')}", "body"),
    ]

    # Market context
    if startup.get("market_context") or startup.get("competitors"):
        children.append("pkg-market-div")
        components.append(_divider("pkg-market-div"))
        if startup.get("market_context"):
            children.append("pkg-market")
            components.append(_stat("pkg-market", "Market", startup["market_context"][:200]))
        if startup.get("competitors"):
            children.append("pkg-competitors")
            components.append(_stat("pkg-competitors", "Competitors", startup["competitors"][:200]))

    # Team
    if team:
        children.append("pkg-team-div")
        children.append("pkg-team-label")
        components.append(_divider("pkg-team-div"))
        components.append(_text("pkg-team-label", "Team", "h3"))
        for i, t in enumerate(team[:4]):
            tid = f"pkg-t{i}"
            children.append(tid)
            components.append(_avatar(tid, t["name"], t["role"].upper()))

    # Evaluation breakdown
    if eval_summary:
        children.append("pkg-eval-div")
        children.append("pkg-eval-label")
        components.append(_divider("pkg-eval-div"))
        components.append(_text("pkg-eval-label", f"Evaluation ({eval_summary['count']} reviews)", "h3"))
        dims = [
            ("Market Viability", "market_viability"),
            ("Technical Feasibility", "technical_feasibility"),
            ("Community Fit", "community_fit"),
            ("Real-World Impact", "real_world_impact"),
            ("Execution Risk", "execution_risk"),
        ]
        for i, (label, key) in enumerate(dims):
            pid = f"pkg-eval-{i}"
            val = eval_summary["avg_scores"].get(key, 0)
            color = "green" if val >= 7 else "yellow" if val >= 4 else "red"
            children.append(pid)
            components.append(_progress(pid, val * 10, f"{label} ({val}/10)", color))

    # Phase deliverables
    phase_order = ["research", "spec", "build", "launch", "iterate"]
    phase_display = {
        "research": "Research",
        "spec": "Spec & Plan",
        "build": "Build Sprint",
        "launch": "Launch",
        "iterate": "Iterate",
    }
    role_display = {"ceo": "CEO", "cto": "CTO", "product": "Product", "marketing": "Marketing"}
    for phase_key in phase_order:
        if phase_key not in phases:
            continue
        pid_base = f"pkg-ph-{phase_key}"
        children.append(f"{pid_base}-div")
        children.append(f"{pid_base}-label")
        components.append(_divider(f"{pid_base}-div"))
        components.append(_text(f"{pid_base}-label", f"Phase: {phase_display.get(phase_key, phase_key)}", "h3"))
        for role_key, data in phases[phase_key].items():
            rid = f"{pid_base}-{role_key}"
            children.extend([rid, f"{rid}-content"])
            components.append(_badge(rid, role_display.get(role_key, role_key), "outline"))
            components.append(_text(f"{rid}-content", data["content"][:300], "body"))

    components.insert(0, _column("pkg-root", children))
    return _surface(f"package-{startup['id'][:8]}", [_card("pkg-card", "pkg-root")] + components, "pkg-card")


# ============================================================
# ORG PAGE DATA API — profile/layout data for any client (/api/portal/*)
# ============================================================
# ── Org provisioning ─────────────────────────────────────────────────────────
# The first-run wizard persists the org's display profile here; env vars are the
# defaults until then. Stored under .org/ (gitignored; mount a volume to persist).
_ORG_CONFIG_PATH = _ORG_DATA_DIR / "org-config.json"
_ORG_PROFILE_FIELDS = (
    "name",
    "description",
    "hero_heading",
    "hero_description",
    "hero_cta_label",
    "hero_cta_url",
    "hero_image_url",
    "logo_url",
    "website_url",
    "accent_color",
)


def _load_org_config() -> dict[str, Any]:
    try:
        return json.loads(_ORG_CONFIG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_org_config(cfg: dict) -> None:
    _ORG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _ORG_CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def _org_profile() -> dict:
    """Env-derived defaults overlaid with the first-run wizard config (if any)."""
    cfg = _load_org_config()
    profile = {
        "id": "a0000000-0000-0000-0000-000000000001",
        "name": AGENT_NAME,
        "slug": AGENT_ID,
        "description": AGENT_DESCRIPTION,
        "hero_heading": AGENT_NAME,
        "hero_description": AGENT_DESCRIPTION,
        "hero_cta_label": "Learn more",
        "hero_cta_url": "",
        "hero_image_url": None,
        "logo_url": None,
        "website_url": "",
        "accent_color": "",
    }
    for field in _ORG_PROFILE_FIELDS:
        if cfg.get(field):
            profile[field] = cfg[field]
    # Departments: named sub-units of the org, set at first-run.
    profile["departments"] = cfg.get("departments", [])
    return profile


@app.get("/api/portal/chapter")
async def portal_chapter() -> dict:
    profile = _org_profile()
    profile.update(
        {
            "stat_events_count": think_cycle.think_cycle_count,
            "stat_communities_count": len(federation) + 1,
            "stat_partners_count": len(members),
        }
    )
    return profile


@app.get("/api/org/config")
async def org_config_get() -> dict:
    """Report whether the org has been set up, plus the current resolved profile."""
    cfg = _load_org_config()
    return {"configured": bool(cfg.get("configured")), "profile": _org_profile()}


@app.post("/api/org/config", response_model=None)
async def org_config_set(request: Request) -> dict | JSONResponse:
    """First-run org setup, by the OPERATOR. Locked once configured (delete
    .org/org-config.json to re-run). Accepts the display-profile fields.

    Requires the admin credential — the boot-printed ``ORG_ADMIN_TOKEN`` bearer
    (or a signed admin member, once one exists). This used to be open until the
    org was configured, reasoning that nothing exists to sign with before
    provisioning. That is true of a member signature and beside the point: the
    admin token is minted and printed before the port is reachable, so it is
    exactly the credential a first-run POST can carry. Open, on a public deploy,
    the window between the process listening and the operator's first visit
    was one in which whoever reached it first named the org and chose its
    join policy. The installer never calls this route (the profile comes from
    the ORG_* variables), so an unattended first run is unchanged.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return denied or JSONResponse(status_code=401, content={"error": "auth required"})
    if _load_org_config().get("configured"):
        raise HTTPException(status_code=403, detail="org already configured")
    body = await request.json()
    cfg: dict[str, Any] = {
        field: str(body[field])
        for field in _ORG_PROFILE_FIELDS
        if isinstance(body.get(field), str) and body[field].strip()
    }
    if not cfg.get("name"):
        raise HTTPException(status_code=400, detail="org name is required")
    # Join policy: set at first-run; changeable later via POST
    # /api/org/join-policy. Defaults to 'open' when unset/invalid.
    jp = str(body.get("join_policy", "")).strip().lower()
    if jp in _VALID_JOIN_POLICIES:
        cfg["join_policy"] = jp
    # Departments — named sub-units (deduped, trimmed, capped).
    depts = body.get("departments")
    if isinstance(depts, list):
        seen: list[str] = []
        for d in depts:
            name = str(d).strip()
            if name and name not in seen:
                seen.append(name)
        cfg["departments"] = seen[:50]
    cfg["configured"] = True
    _save_org_config(cfg)
    surfaces.set_display_name(_org_profile()["name"])
    return {"ok": True, "configured": True, "profile": _org_profile()}


class JoinPolicyRequest(BaseModel):
    policy: str


@app.get("/api/org/join-policy")
async def get_join_policy() -> dict:
    """The org's current join policy: open | invite | approval.

    Keyless by design: the /join landing page (static/ui/join-boot.js,
    join.js) reads this BEFORE a visitor has any credential, to decide
    what the page shows — a visitor arriving with an invite link cannot
    be signed in yet, so anything the page needs at that point must be
    answerable without one. The response is a single value from a
    closed vocabulary (_join_policy, one of _VALID_JOIN_POLICIES),
    org-wide rather than per-member, and says nothing about any
    particular invite (join.js's own comment: "the org's join policy,
    which is org-wide, already public... and says nothing about any
    particular token").
    """
    return {"join_policy": _join_policy()}


@app.post("/api/org/join-policy")
async def set_join_policy(req: JoinPolicyRequest, request: Request):
    """Change the org join policy (admin only — governance-sensitive). Unlike
    first-run setup, this is changeable any time."""
    ok, _identity, denied = await _authorize_role(request, allowed_roles={"admin"})
    if not ok:
        return denied
    policy = req.policy.strip().lower()
    if policy not in _VALID_JOIN_POLICIES:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_policy", "valid": list(_VALID_JOIN_POLICIES)},
        )
    cfg = _load_org_config()
    cfg["join_policy"] = policy
    _save_org_config(cfg)
    return {"join_policy": policy}


@app.get("/api/portal/layout")
async def portal_layout(request: Request) -> dict:
    """Route wrapper: decide from the VERIFIED caller, then build.

    Split from the builder because FastAPI cannot accept ``Request | None`` as a
    route parameter, and the builder needs to be callable with no request at all
    — ``surfaces.build_chapter_surface`` renders this same document inside a page
    that is already gated to verified callers.
    """
    return await _portal_layout_document(include_members=bool(_resolve_caller(request)))


async def _portal_layout_document(*, include_members: bool) -> dict:
    """Serve the entire chapter page as A2UI v0.9 — the agent owns its UI.

    PUBLIC, but the MEMBER SECTION requires a verified caller. The document is
    an org's landing page: its hero, leaders, federation peers and the org's own
    recent thoughts are things the org publishes about ITSELF, and a stranger
    loading the page is the normal case. The member list is not — anonymously it
    returned every member's handle, display name, free-text description and
    skills, which is the same population `GET /api/members` is gated for.

    So the ARRAY is gated rather than the DOCUMENT: gating the whole
    layout would break the public page for a reason that only applies to one of
    its sections, and an operator whose site renders this would lose the org's
    own content to protect data the org never meant to publish.
    """
    from a2ui_helpers import (
        badge,
        card,
        column,
        divider,
        heading,
        stat_group,
        surface,
        text,
    )

    components: list[dict] = []
    sections: list[str] = []

    # --- Hero ---
    sections.append("hero-section")
    components.extend(
        [
            column("hero-section", ["hero-title", "hero-desc", "hero-region", "hero-divider"]),
            heading("hero-title", 1, AGENT_NAME),
            text("hero-desc", AGENT_DESCRIPTION, "body"),
            text("hero-region", f"Region: {AGENT_REGION} | Focus: {AGENT_FOCUS}", "caption"),
            divider("hero-divider"),
        ]
    )

    # --- Leaders ---
    if AGENT_LEADERS:
        sections.append("leaders-section")
        leader_ids = []
        components.append(heading("leaders-title", 2, "Org Leaders"))
        for i, name in enumerate(AGENT_LEADERS):
            lid = f"leader-{i}"
            leader_ids.append(lid)
            components.append(text(lid, name, "body"))
        components.append(column("leaders-section", ["leaders-title"] + leader_ids))

    # --- Federation ---
    if federation:
        sections.append("fed-section")
        fed_ids = ["fed-title"]
        components.append(heading("fed-title", 2, f"Federation — {len(federation)} Orgs Online"))
        for i, (fid, finfo) in enumerate(list(federation.items())[:8]):
            cid = f"fed-{i}"
            fed_ids.append(f"{cid}-card")
            components.extend(
                [
                    card(f"{cid}-card", f"{cid}-col"),
                    column(f"{cid}-col", [f"{cid}-name", f"{cid}-focus"]),
                    heading(f"{cid}-name", 4, finfo.get("name", fid)),
                    text(f"{cid}-focus", finfo.get("focus", "General"), "caption"),
                ]
            )
        components.append(column("fed-section", fed_ids))

    # --- Members (verified callers only) ---
    # `_resolve_caller` reads request.state.agent_id, which the auth middleware
    # sets ONLY after a valid Ed25519 signature — the spoofable X-Agent-ID
    # header is never trusted, so this cannot be bypassed by asserting an id.
    # The caller decides, and there is no default: over HTTP the route wrapper
    # passes the verified-caller answer, and the one internal caller
    # (surfaces.build_chapter_surface, itself gated) passes True. Making this a
    # required keyword means a future caller has to state which it is rather than
    # inheriting whichever default happened to be safe when it was written.
    if members and include_members:
        sections.append("members-section")
        mem_ids = ["members-title"]
        components.append(heading("members-title", 2, f"Agents — {len(members)} Members"))
        for i, (mid, m) in enumerate(list(members.items())[:12]):
            cid = f"mem-{i}"
            mem_ids.append(f"{cid}-card")
            skills = ", ".join(m.get("skills", [])[:3])
            components.extend(
                [
                    card(f"{cid}-card", f"{cid}-col"),
                    column(f"{cid}-col", [f"{cid}-name", f"{cid}-desc", f"{cid}-skills"]),
                    heading(f"{cid}-name", 4, f"@{mid} — {m['name']}"),
                    text(f"{cid}-desc", m.get("description", ""), "body"),
                    text(f"{cid}-skills", skills, "caption"),
                ]
            )
        components.append(column("members-section", mem_ids))

    # --- Recent Thoughts ---
    recent_thoughts = await pg_request(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "4",
        },
    )
    if recent_thoughts:
        sections.append("thoughts-section")
        thought_ids = ["thoughts-title"]
        components.append(heading("thoughts-title", 2, "Agent Minds — Recent Thoughts"))
        for i, t in enumerate(recent_thoughts):
            tid = f"thought-{i}"
            thought_ids.append(f"{tid}-card")
            components.extend(
                [
                    card(f"{tid}-card", f"{tid}-col"),
                    column(f"{tid}-col", [f"{tid}-type", f"{tid}-text"]),
                    badge(f"{tid}-type", t.get("thought_type", "?"), "outline"),
                    text(f"{tid}-text", t.get("thought_text", "")[:150], "body"),
                ]
            )
        components.append(column("thoughts-section", thought_ids))

    # --- NEST Info ---
    sections.append("nest-section")
    components.extend(
        [
            column("nest-section", ["nest-title", "nest-stats", "nest-facts"]),
            heading("nest-title", 2, "Agent Info"),
            stat_group(
                "nest-stats",
                [
                    {"label": "Agent ID", "value": AGENT_ID},
                    {"label": "Endpoint", "value": PUBLIC_URL},
                ],
            ),
            text("nest-facts", f"AgentFacts: {PUBLIC_URL}/agentfacts.json", "caption"),
        ]
    )

    # --- Root layout ---
    components.insert(0, column("page-root", sections))

    return surface(f"portal-{AGENT_ID}", components, "page-root")


# ═══════════════════════════════════════════════════════════════
# Governance — approval queue + role nominations
# ═══════════════════════════════════════════════════════════════


class ApprovalDecision(BaseModel):
    # Kept for backward compatibility but IGNORED for authorization — the
    # approver is the auth-verified caller, not a body claim (anti-forgery).
    approver_agent_id: str = ""
    reason: str = ""


@app.get("/api/approvals")
async def list_approvals(request: Request, kind: str | None = None, limit: int = 100):
    """List pending approvals for this chapter (leader/advisor/mentor/admin
    visibility, or the break-glass bearer). The queue is governance data — the
    old ``requester_agent_id`` query param skipped the check entirely when
    omitted, so the queue was readable unauthenticated."""
    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "advisor", "mentor", "admin"})
    if not ok:
        return denied
    import governance

    items = await governance.list_pending(kind=kind, limit=min(limit, 500))
    return {"pending": items, "count": len(items)}


@app.get("/api/approvals/kinds")
async def approval_kinds():
    """The approval vocabulary this org actually has.

    ⚠️ DERIVED FROM ``governance``, never a second list. The console renders
    whatever this returns instead of enumerating kinds in the browser — a
    hard-coded UI list is the ``INDIVIDUAL_PROFILE_TYPES`` bug waiting to
    happen: an inclusion allowlist that silently drops every value nobody
    remembered to add. That one shipped, excluded six of seven legal values, and
    was caught in deploy verification rather than by a test.

    ⚠️ NO ``getattr`` FALLBACK. An earlier draft read the operational set via
    ``getattr(governance, ..., set())`` to stay forward-compatible with PR1 —
    and guessed the symbol name wrong. The console would then have reported
    "nothing here is gated" forever, with every test passing, because a default
    turns a missing symbol into a plausible answer. If ``governance`` stops
    exporting this, the import fails loudly instead.

    ``operational`` is the subset an UNATTENDED agent can trigger — sends,
    record writes, external fetches. It is intersected with the live vocabulary
    so a kind marked operational but not approvable is never advertised as a
    gate that exists.
    """
    from governance import APPROVAL_KINDS, OPERATIONAL_KINDS

    kinds = sorted(APPROVAL_KINDS)
    operational = sorted(OPERATIONAL_KINDS & APPROVAL_KINDS)
    return {"kinds": kinds, "operational": operational, "count": len(kinds)}


@app.get("/api/approvals/dashboard")
async def approvals_dashboard():
    """Aggregate counts for leader dashboard (counts only — no identifying data)."""
    import governance

    return await governance.get_dashboard()


def _approver_from(identity: dict) -> str:
    """Who to record as having made an oversight decision.

    A signed caller is named. The break-glass bearer authenticates a secret and
    carries no identity, so it is recorded as unattributed rather than falling
    back to this org's own id — a record naming the org for a decision nobody at
    the org is accountable for looks complete and is false, which is worse for
    an auditor than one that says plainly it cannot name a person.
    """
    named = sanitize_agent_id(identity.get("agent_id") or "")
    if named:
        return named
    import governance

    return governance.BREAK_GLASS_APPROVER


@app.post("/api/approvals/{approval_id}/approve")
async def approve_approval(approval_id: str, decision: ApprovalDecision, request: Request):
    """Leader approves a pending proposal. TTL still applies — expired items stay expired.

    The approver is the AUTH-VERIFIED caller (a signed leader/admin, or the
    break-glass bearer) — NEVER the body-claimed ``approver_agent_id``. Trusting
    the body let any signed member approve by naming a leader.
    """
    ok, identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    import governance

    aid = sanitize_agent_id(approval_id)[:64]
    approver = _approver_from(identity)
    result = await governance.approve(aid, approver, pre_authorized=True)
    if result and result.get("error") == "not_authorized":
        raise HTTPException(status_code=403, detail="not_authorized")
    if not result:
        raise HTTPException(status_code=404, detail="not_found_or_not_pending")
    # materialize an admitted member on leader-approve (approval join
    # policy). Done HERE, not in governance, so the approval engine stays
    # decoupled from membership.
    if result.get("kind") == "member_admission":
        await _materialize_admitted_member(result.get("payload") or {})
    return result


async def _materialize_admitted_member(payload: dict) -> None:
    """Create a member from an approved member_admission payload. Routes
    through register_member with the join-policy gate bypassed (approval already
    cleared) so the in-memory + Postgres + auth-key writes stay in one place."""
    safe_id = sanitize_agent_id(payload.get("agent_id", ""))
    if not safe_id:
        return
    _approval_admitting.add(safe_id)
    try:
        await register_member(
            MemberRegistration(
                agent_id=safe_id,
                name=payload.get("name") or safe_id,
                description=payload.get("description", ""),
                skills=payload.get("skills") or [],
                public_key=payload.get("public_key", ""),
                origin=payload.get("origin", "sovereign"),
            )
        )
    finally:
        _approval_admitting.discard(safe_id)


@app.post("/api/approvals/{approval_id}/reject")
async def reject_approval(approval_id: str, decision: ApprovalDecision, request: Request):
    """Reject a pending proposal. Approver = the auth-verified caller, never the
    body claim (same anti-forgery binding as approve)."""
    ok, identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    import governance

    aid = sanitize_agent_id(approval_id)[:64]
    approver = _approver_from(identity)
    result = await governance.reject(aid, approver, decision.reason, pre_authorized=True)
    if result and result.get("error") == "not_authorized":
        raise HTTPException(status_code=403, detail="not_authorized")
    if not result:
        raise HTTPException(status_code=404, detail="not_found_or_not_pending")
    return result


# ═══════════════════════════════════════════════════════════════
# Agent Authority Scope — delegation contract + rate limits
# ═══════════════════════════════════════════════════════════════


class AuthorityUpdate(BaseModel):
    agent_id: str  # which agent's scope is being changed
    action_kind: str
    allowed: bool
    constraints: dict = {}
    updated_by: str = "self"  # 'self' | admin agent_id


@app.get("/api/authority/{agent_id}")
async def get_authority(agent_id: str, request: Request):
    """List an agent's authority scope — all action kinds.

    ⚠️ USED TO ANSWER FOR ANY agent_id WITH NO AUTH AT ALL, while the write
    side on this same path (POST, below) has always scoped to the caller's
    own id or an admin. Now requires a signature (/api/authority/ is in
    auth_verify.REQUIRE_AUTH_GET_PREFIXES) and, like the POST, is scoped to
    the caller via _require_agent_owner.
    """
    import authority as auth_mod

    aid = sanitize_agent_id(agent_id)
    _require_agent_owner(request, aid, what="authority")
    rows = await auth_mod.list_scope_for(aid)
    return {"agent_id": aid, "scope": rows, "count": len(rows)}


@app.post("/api/authority/{agent_id}")
async def update_authority(agent_id: str, req: AuthorityUpdate, request: Request):
    """Update an agent's authority scope.

    A member can update their OWN scope; an admin can update anyone's scope for
    safety overrides; anyone else is rejected. The actor is the AUTH-VERIFIED
    caller (request.state.agent_id, set by the middleware only on a valid
    Ed25519 signature) — NOT the body-claimed ``updated_by``. Trusting the body
    let any signed member edit ANY agent's scope by sending updated_by="self".
    """
    import authority as auth_mod
    import governance

    aid = sanitize_agent_id(agent_id)
    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")

    if actor != aid:
        role = await governance.get_chapter_role(actor)
        if role != "admin":
            raise HTTPException(status_code=403, detail="not_authorized")

    result = await auth_mod.set_scope(
        agent_id=aid,
        action_kind=req.action_kind,
        allowed=req.allowed,
        constraints=req.constraints or {},
        updated_by=actor,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ═══════════════════════════════════════════════════════════════
# Federation Policy — per-peer state + leader block/unblock
# ═══════════════════════════════════════════════════════════════


class PeerBlock(BaseModel):
    actor_agent_id: str
    reason: str = ""


@app.get("/api/federation/peers")
async def list_federation_peers():
    """Live per-peer state for the leader dashboard.

    This endpoint is now in REQUIRE_AUTH_GET_PATHS — middleware
    rejects unauth GET. The handler just emits the full row set
    because every caller is authenticated by the time they reach
    here. (Pre-launch audit found this returning 200 unauth with
    full per-peer backoff history, consecutive-failure counts, and
    blocking metadata — operational details that helped attackers
    map federation health.)
    """
    import federation_policy as fed_mod

    rows = await fed_mod.list_policies()
    return {"peers": rows, "count": len(rows)}


@app.get("/api/federation/peers/{peer_id}/history")
async def peer_history(peer_id: str, limit: int = 50):
    import federation_policy as fed_mod

    hist = await fed_mod.history_for(sanitize_agent_id(peer_id), limit=limit)
    return {"history": hist, "count": len(hist)}


@app.post("/api/federation/peers/{peer_id}/forget")
async def forget_peer_endpoint(peer_id: str, req: PeerBlock, request: Request):
    """Leader: FORGET a dead/legacy peer — its policy row is deleted, so it
    stops haunting /health federation_state and the federation gauges.
    block is the reversible deny; forget is removal. History keeps the audit."""
    import federation_policy as fed_mod
    import governance

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await fed_mod.forget_peer(sanitize_agent_id(peer_id), actor, reason=req.reason)
    if result.get("error"):
        code = 404 if result["error"] == "not_found" else 400
        raise HTTPException(status_code=code, detail=result["error"])
    return result


@app.post("/api/federation/peers/{peer_id}/block")
async def block_peer(peer_id: str, req: PeerBlock, request: Request):
    """Leader: permanently block a peer chapter from our federation."""
    import federation_policy as fed_mod
    import governance

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await fed_mod.block_peer(sanitize_agent_id(peer_id), actor, reason=req.reason)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/federation/peers/{peer_id}/unblock")
async def unblock_peer(peer_id: str, req: PeerBlock, request: Request):
    import federation_policy as fed_mod
    import governance

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await fed_mod.unblock_peer(sanitize_agent_id(peer_id), actor)
    if result.get("error") in ("not_found", "not_blocked"):
        raise HTTPException(status_code=404, detail=result["error"])
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/federation/peers/{peer_id}/unpin-did")
async def unpin_peer_did(peer_id: str, req: PeerBlock, request: Request):
    """Leader: clear a peer's pinned DID to accept a legitimate key rotation.
    The peer's next attested discovery sighting re-pins (trust-on-first-use).
    Deliberately manual — a registry record must never rotate a peer's
    identity on its own."""
    import federation_policy as fed_mod
    import governance

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await fed_mod.clear_did_pin(sanitize_agent_id(peer_id), actor)
    if result.get("error") in ("not_found", "not_pinned"):
        raise HTTPException(status_code=404, detail=result["error"])
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ═══════════════════════════════════════════════════════════════
# Server Policy — hyperparameters with auto-tune + pin overrides
# ═══════════════════════════════════════════════════════════════


class PolicyPin(BaseModel):
    actor_agent_id: str
    reason: str = ""


class PolicyOverride(BaseModel):
    actor_agent_id: str
    new_value: object
    reason: str = ""


@app.get("/api/policy")
async def list_policy():
    """Read the live hyperparameter table for this chapter."""
    import policy as policy_mod

    rows = await policy_mod.list_all()
    return {"policy": rows, "count": len(rows)}


@app.get("/api/policy/{key}/history")
async def get_policy_history(key: str, limit: int = 50):
    import policy as policy_mod

    hist = await policy_mod.history_for(key[:100], limit=limit)
    return {"history": hist, "count": len(hist)}


@app.post("/api/policy/{key}/pin")
async def pin_policy(key: str, req: PolicyPin, request: Request):
    """Leader freezes a key — auto-tune skips it until unpinned."""
    import governance
    import policy as policy_mod

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await policy_mod.pin(key[:100], actor, reason=req.reason)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=result["error"])
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/policy/{key}/unpin")
async def unpin_policy(key: str, req: PolicyPin, request: Request):
    import governance
    import policy as policy_mod

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    if not await governance.can_approve(actor):
        raise HTTPException(status_code=403, detail="not_authorized")
    result = await policy_mod.unpin(key[:100], actor)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=result["error"])
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/policy/{key}/override")
async def override_policy(key: str, req: PolicyOverride, request: Request):
    """Admin-only manual override. Goes to history with reason='admin_override'."""
    import governance
    import policy as policy_mod

    actor = _resolve_caller(request)
    if not actor:
        raise HTTPException(status_code=401, detail="authentication required")
    role = await governance.get_chapter_role(actor)
    if role != "admin":
        raise HTTPException(status_code=403, detail="admin_only")
    result = await policy_mod.override(key[:100], req.new_value, actor, reason=req.reason)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=result["error"])
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ═══════════════════════════════════════════════════════════════
# Server Calls — trust-gated member-posted requests
# ═══════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════
# Server skill registry — Ed25519-signed skill catalog
# ═══════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════
# Skill attestation marketplace — Phase A
# ═══════════════════════════════════════════════════════════════════


class SkillAttestRequest(BaseModel):
    attestor_agent_id: str
    attestor_did: str
    attestor_public_key_b64: str
    attestation_sig_b64: str
    created_unix: int
    note_markdown: str = ""


# ── Endorsements (PR-B of trust-events series) ──────────────────────


class TrustEndorsementRequest(BaseModel):
    """Signed endorsement of `endorsee_agent_id` by the endorser.

    Canonical signed string (see endorsements.create_endorsement_signature):
      ENDORSE:{chapter_id}:{endorser_did}:{endorsee_agent_id}:{created_unix}
    """

    endorser_agent_id: str
    endorser_did: str
    endorser_pubkey_b64: str
    endorsee_agent_id: str
    signature_b64: str
    created_unix: int
    note_markdown: str | None = None


class TrustEndorsementRevokeRequest(BaseModel):
    endorser_agent_id: str
    endorsee_agent_id: str
    revocation_reason: str = ""


@app.post("/api/endorsements")
async def create_endorsement(req: TrustEndorsementRequest) -> dict:
    """Record a signed endorsement. Mints a `trust_event(endorsement_received,
    +0.5)` for the endorsee on first write; refreshes the row idempotently
    on re-write. Endorser must have `trust_score >= 20`.

    400 — invalid signature or self-endorsement
    403 — endorser_trust_below_floor
    """
    import endorsements as endorsements_mod

    endorser = sanitize_agent_id(req.endorser_agent_id)
    endorsee = sanitize_agent_id(req.endorsee_agent_id)
    if not endorser or not endorsee:
        raise HTTPException(status_code=400, detail="invalid agent_id")

    result = await endorsements_mod.record_endorsement(
        endorser_agent_id=endorser,
        endorser_did=req.endorser_did,
        endorsee_agent_id=endorsee,
        endorser_pubkey_b64=req.endorser_pubkey_b64,
        signature_b64=req.signature_b64,
        created_unix=req.created_unix,
        note_markdown=req.note_markdown,
    )
    if "error" in result:
        err = result["error"]
        status = 400
        if err.startswith("endorser_trust_below_floor"):
            status = 403
        if err == "self-endorsement rejected":
            status = 400
        raise HTTPException(status_code=status, detail=err)
    return result


@app.post("/api/endorsements/revoke")
async def revoke_endorsement(req: TrustEndorsementRevokeRequest) -> dict:
    """Revoke a prior endorsement. Soft-delete + emits a compensating
    `revocation_received` trust event (-1.0) for the endorsee.
    """
    import endorsements as endorsements_mod

    endorser = sanitize_agent_id(req.endorser_agent_id)
    endorsee = sanitize_agent_id(req.endorsee_agent_id)
    if not endorser or not endorsee:
        raise HTTPException(status_code=400, detail="invalid agent_id")

    result = await endorsements_mod.revoke_endorsement(
        endorser_agent_id=endorser,
        endorsee_agent_id=endorsee,
        revocation_reason=req.revocation_reason,
    )
    if "error" in result:
        err = result["error"]
        status = 404 if err == "not_found" else 400
        raise HTTPException(status_code=status, detail=err)
    return result


@app.get("/api/agents/{agent_id}/endorsements")
async def list_agent_endorsements(agent_id: str, include_revoked: bool = False, limit: int = 50) -> dict:
    """List endorsements an agent has received.

    FIXED: docstring used to say "Public read", but each row carries
    endorser_agent_id and endorser_did — a THIRD PARTY's identity, not
    just the subject's — plus free-text note_markdown, which together
    build a who-endorsed-whom social graph for anyone with no auth at
    all. Now requires a signature (see the /api/agents/*/endorsements
    check in auth_verify.requires_auth, same startswith/endswith idiom
    as /api/agents/{id}/export); not self-scoped — reading another
    agent's received endorsements to evaluate them is the endorsement
    feature's whole purpose, any signed member may do it.
    """
    import endorsements as endorsements_mod

    safe = sanitize_agent_id(agent_id)
    if not safe:
        raise HTTPException(status_code=400, detail="invalid agent_id")
    rows = await endorsements_mod.list_endorsements_received(
        safe,
        include_revoked=include_revoked,
        limit=max(1, min(200, int(limit or 50))),
    )
    return {"endorsee_agent_id": safe, "endorsements": rows}


# ── Trust admin: decay sweep + drift detector (PR-C) ────────────────


@app.post("/api/admin/trust/decay-sweep", response_model=None)
async def trust_decay_sweep(request: Request, limit: int = 5000) -> dict | JSONResponse:
    """Walk all agents; emit a `inactive_decay (-1.0)` for any agent
    inactive >60 days whose score is above the floor. Idempotent at
    the ISO-week level (one decay row per agent per week).

    The automatic sweep runs inside the think cycle (trust_cron); this
    HTTP endpoint is a manual admin trigger and requires admin authz.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    import trust_events as _trust

    rows = (
        await pg_request(
            "GET",
            "agents",
            params={"select": "agent_id", "limit": max(1, min(10000, int(limit or 5000)))},
        )
        or []
    )
    fired = 0
    for r in rows:
        aid = r.get("agent_id")
        if not aid:
            continue
        try:
            if await _trust.apply_inactivity_decay_for_agent(agent_id=aid):
                fired += 1
        except Exception:  # noqa: S112,BLE001 — sweep is best-effort per agent
            continue
    return {"swept": len(rows), "decay_emitted": fired}


@app.get("/api/admin/trust/drift", response_model=None)
async def trust_drift_report(request: Request) -> dict | JSONResponse:
    """Compare trigger-maintained `agents.trust_score` against
    `SUM(delta)` replay over `trust_events`. Any non-empty result is
    a P1 alert: governance overrides bypassed the ledger.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    import trust_events as _trust

    drifts = await _trust.detect_score_drift()
    return {"drifts": drifts, "drift_count": len(drifts)}


@app.post("/api/admin/think/resume", response_model=None)
async def think_resume(request: Request) -> dict | JSONResponse:
    """Clear a terminal think-cycle halt so the chapter thinks again.

    ⚠️ OPERATOR-DRIVEN ON PURPOSE, AND THAT IS THE WHOLE POINT. A terminal
    failure is one no delay can fix — a revoked key, a model that does not
    exist. Anything that resumed it on a timer would be retrying by another
    name, which is exactly the loop this halt exists to stop. A human confirms
    the cause is fixed; only then does the cadence come back.

    Reports whether the chapter was actually halted, so "resume" against a
    healthy chapter is a no-op that says so rather than a silent success.
    """
    global _think_paused_reason, _consecutive_think_failures

    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    was = _think_paused_reason
    persisted = await agent_scheduler.resume(AGENT_ID)
    _think_paused_reason = None
    _consecutive_think_failures = 0
    return {
        "was_halted": was is not None,
        "previous_reason": was,
        "persisted": persisted,
        "detail": ("think cycle resumed" if was else "the think cycle was not halted; nothing to resume"),
    }


@app.get("/api/admin/llm/spend", response_model=None)
async def llm_spend_report(request: Request) -> dict | JSONResponse:
    """What this chapter's LLM calls actually cost in tokens, per principal.

    RECORD-ONLY. Every figure is an OBSERVATION — what a provider reported in
    ``response.usage`` — never a tokenizer estimate and never a ``max_tokens``
    ceiling, which is what every LLM number in this repo was before the meter.
    ``llm_calls_without_usage`` counts calls whose provider reported nothing;
    they add no tokens, so a reader can tell how much of the total is covered
    rather than reading a sum that merely looks complete.

    Keyed per principal from the start. ``member_runtime.think()`` has no caller
    today, but wired on a 245-member chapter it is a per-member multiplier — an
    unkeyed meter would let that land looking like ordinary growth.

    ``resolved`` names the provider and model the chapter actually executes
    with, so a spend figure is never read against the wrong price.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    import agent_telemetry as _telemetry
    import settings as _settings

    return {**_telemetry.get_llm_spend(), "resolved": _settings.resolved_llm()}


@app.get("/api/trust/drift-status", response_model=None)
async def trust_drift_status() -> dict:
    """Public, read-only view of the replay-determinism invariant
    (spec/0.2 §9.4): does ``agents.trust_score`` still equal
    ``SUM(delta) FROM trust_events``?

    Returns ``{drift_count, drifts}`` so a conformance verifier (or any
    auditor) can check ``drift_count == 0`` WITHOUT admin credentials — a
    chapter cannot hide trust drift behind an admin gate. Same computation as
    the admin ``/api/admin/trust/drift`` endpoint, which stays gated for the
    full operator view + any future drift actions. On a conformant chapter the
    list is empty, so this exposes nothing; a non-empty list is exactly the
    public integrity signal it is meant to be.
    """
    import trust_events as _trust

    drifts = await _trust.detect_score_drift()
    return {"drift_count": len(drifts), "drifts": drifts}


@app.get("/api/agents/{agent_id}/aae-events")
async def agent_aae_events(agent_id: str, request: Request, limit: int = 50) -> dict:
    """Return the agent's ARP receipts as AAE-shaped AttestationEvents.

    Consumer: ``@sharathvc/sm-attest-viewer`` React component renders this
    JSON directly. The chapter's ARP receipts are converted to the AAE
    wire envelope shape per ``chapter/aae_export.py``; ARP-specific
    fields (counterparty, jurisdiction, accessibility, hash chain) ride
    in ``payload`` per the chapter's documented convention.

    Visibility: classification is 'public' iff the agent has opted into
    the public Chronicle (``agents.config.chronicle_public = true``). When
    it has NOT, the receipts are 'internal' and the endpoint enforces that
    the verified caller owns the id (or holds an admin token) — otherwise a
    third party could read another member's private action log by guessing
    the id. A public Chronicle stays open (that is the opt-in).

    Limit clamped to [1, 200]. Reverse-chronological order.
    """
    import aae_export

    safe = sanitize_agent_id(agent_id)
    if not safe:
        raise HTTPException(status_code=400, detail="invalid agent_id")

    # Resolve the agent's did:key (the receipts' principal_did)
    import arp as arp_mod

    principal_did = arp_mod.did_key_for_member(safe)
    if not principal_did:
        # Unknown agent or no Ed25519 key on file — return empty rather
        # than 404 so callers can display "no events yet" gracefully.
        return {"events": [], "total": 0, "agent_id": safe}

    # Check chronicle visibility flag for classification
    rows = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe}", "select": "config", "limit": "1"},
    )
    cfg = (rows[0].get("config") or {}) if rows else {}
    public = bool(cfg.get("chronicle_public", False))

    # An 'internal' chronicle is the agent's private action log — only the
    # agent itself (or an admin) may read it. A 'public' chronicle is an
    # explicit opt-in and stays open to any caller.
    if not public:
        caller = _resolve_caller(request)
        is_admin = auth_verify.check_admin_token_header(dict(request.headers))
        if caller != safe and not is_admin:
            # BYTE-IDENTICAL to the unknown-agent response above. This used to
            # be a 403 naming the chronicle as internal — which told a stranger
            # that the id exists and has a chronicle, while an unknown id got
            # 200 and an empty list. A private log is not disclosed to a third
            # party, and neither is the fact that there is one.
            return {"events": [], "total": 0, "agent_id": safe}

    # Fetch receipts where this agent is the principal
    capped = max(1, min(200, int(limit)))
    receipts = await pg_request(
        "GET",
        "arp_receipts",
        params={
            "principal_did": f"eq.{principal_did}",
            "order": "issued_at.desc",
            "limit": str(capped),
            "select": "receipt_json",
        },
    )
    # Each row stores the full receipt under receipt_json
    raw_receipts = [r.get("receipt_json") for r in (receipts or []) if isinstance(r.get("receipt_json"), dict)]
    events = aae_export.arp_receipts_to_aae_events(raw_receipts, tenant=AGENT_ID, public=public)
    return {
        "events": events,
        "total": len(events),
        "agent_id": safe,
        "principal_did": principal_did,
        "classification": "public" if public else "internal",
    }


async def _redact_trust_history(history: list[dict]) -> list[dict]:
    """Redact `source_agent_id`/`reason` to `endorser_role`-grain.

    FIXED: agent_trust_summary's docstring has claimed this redaction
    happens since before this function existed, but trust_events.list_history
    returns source_agent_id, source_event_id and reason verbatim — and both
    endorsements.py call sites that mint a trust event put the endorser's raw
    agent_id directly into `reason` (e.g. f"endorsed by {endorser_agent_id}"),
    so redacting source_agent_id alone would not have closed it. source_event_id
    is dropped too even though the docstring didn't name it: it is built the
    same way (f"endorsement:{endorser_agent_id}:{endorsee_agent_id}") and
    carries the identical identity.

    Coarsened to the endorser's chapter_role rather than dropped outright —
    "an admin vouched for this agent" is a materially different signal than
    "a peer member did", which a bare count or omission would lose. `None`
    for system-generated events (tenure milestones, inactive_decay) that
    carry no source_agent_id at all.
    """
    import governance as gov

    unique_sources: set[str] = {sid for row in history if (sid := row.get("source_agent_id"))}
    roles: dict[str, str] = {sid: await gov.get_chapter_role(sid) for sid in unique_sources}
    return [
        {
            "event_type": row.get("event_type"),
            "delta": row.get("delta"),
            "occurred_at": row.get("occurred_at"),
            "endorser_role": roles.get(sid) if (sid := row.get("source_agent_id")) else None,
        }
        for row in history
    ]


@app.get("/api/agents/{agent_id}/trust")
async def agent_trust_summary(agent_id: str, request: Request) -> dict:
    """Per-agent trust dossier: current score, tier, last 20 events,
    30-day projection, days to next tier.

    Anyone SIGNED can see another agent's score — the score is a transparent
    reputation — and a stranger can see it for a member who opted into the
    listing, exactly as the profile route serves them. A stranger asking about
    a member who did not opt in gets the 404 an unknown id gets, byte for byte:
    this route answered 200 for every member and 404 for every non-member with
    no credential at all, which is the membership oracle the profile gate
    closed, reopened one path over. The underlying events have
    `source_agent_id` and `reason` redacted to `endorser_role`-grain to avoid
    leaking internal call IDs to the UI consumer.
    """
    import trust_events as _trust

    safe = sanitize_agent_id(agent_id)
    if not safe:
        raise HTTPException(status_code=400, detail="invalid agent_id")
    if not _member_disclosable_to(safe, request):
        raise HTTPException(status_code=404, detail="agent_not_found")

    # Score (trigger-maintained on agents row)
    rows = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe}", "select": "trust_score", "limit": 1},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="agent_not_found")
    score = float(rows[0].get("trust_score") or 0.0)

    tier = _trust.tier_for(score)
    history = await _redact_trust_history(await _trust.list_history(safe, limit=20))
    projection = await _trust.projection_30d(safe)

    # Days-to-next-tier — naive: at the current 30d rate, when does
    # `score + (rate * days/30)` cross the next tier minimum?
    next_tier_min = None
    for t_min in _trust.TRUST_TIERS:
        if t_min > score:
            next_tier_min = t_min
            break
    days_to_next: float | None = None
    if next_tier_min is not None:
        rate_30d = float(projection["projected_30d"] or 0.0)
        if rate_30d > 0:
            days_to_next = (next_tier_min - score) / (rate_30d / 30.0)

    return {
        "agent_id": safe,
        "score": round(score, 3),
        "tier": tier,
        "next_tier_min": next_tier_min,
        "days_to_next_tier": round(days_to_next, 1) if days_to_next is not None else None,
        "projection": projection,
        "history": history,
    }


@app.post("/api/skills/{skill_id}/attest")
@app.post("/api/skills/{skill_id}/attest/")
async def attest_skill(skill_id: str, req: SkillAttestRequest, request: Request) -> dict:
    """Trusted-tier member co-signs an attestation on a published skill.

    Gates:
      - Skill must exist and not be revoked
      - Caller's chapter_role in {advisor, mentor, leader, admin} via governance
      - Self-attestation rejected (author_did != attestor_did)
      - Signature verifies against the canonical string + attestor public key
    """
    import attestations
    import governance as gov
    import skill_registry as sr

    # The attestor IS the auth-verified caller — never the body-claimed
    # attestor_agent_id. Otherwise a non-trusted member bypasses the trust-tier
    # gate by naming a trusted member's id (while signing with their own key).
    # attestor_did / attestor_public_key_b64 stay as the signature mechanism.
    # Auth is the first gate — fail fast before any registry lookup.
    attestor = _resolve_caller(request)
    if not attestor:
        raise HTTPException(status_code=401, detail="authentication required")
    attestor = sanitize_agent_id(attestor)
    if not attestor:
        raise HTTPException(status_code=400, detail="invalid attestor_agent_id")

    safe_id = sanitize_text(skill_id, max_length=128)
    skill = await sr.get_skill(safe_id)
    if not skill:
        raise HTTPException(status_code=404, detail="skill_not_found")
    if skill.get("revoked_at"):
        raise HTTPException(status_code=400, detail="skill is revoked")

    # Trust-tier gate (maps chapter_role → trusted/leader label or rejects)
    eligible, reason, tier = await gov.require_trusted_tier(attestor)
    if not eligible:
        raise HTTPException(status_code=403, detail=reason)

    result = await attestations.record_attestation(
        skill_id=safe_id,
        skill_version=skill.get("version", ""),
        content_sha256=skill.get("content_sha256", ""),
        attestor_did=req.attestor_did,
        attestor_agent_id=attestor,
        attestor_public_key_b64=req.attestor_public_key_b64,
        trust_tier_at_attest=tier or "trusted",
        attestation_sig_b64=req.attestation_sig_b64,
        created_unix=req.created_unix,
        note_markdown=req.note_markdown,
        author_did=skill.get("author_did", ""),
    )
    if result.get("error"):
        # "self-attestation" is a 403 (authz), everything else is a 400
        status = 403 if "self-attestation" in result["error"] else 400
        raise HTTPException(status_code=status, detail=result["error"])
    return result


class SkillRevokeAttestationRequest(BaseModel):
    attestor_agent_id: str
    revocation_reason: str = ""


@app.post("/api/skills/{skill_id}/attestations/{attestor_did_path:path}/revoke")
async def revoke_skill_attestation(
    skill_id: str, attestor_did_path: str, req: SkillRevokeAttestationRequest, request: Request
) -> dict:
    """Revoke an attestation. Author cannot revoke (they don't own the attestation).

    Attestor can revoke their own. Leader/admin can revoke any. The requester is
    the AUTH-VERIFIED caller, never the body-claimed ``attestor_agent_id`` —
    otherwise any signed member could revoke any attestation by naming a leader.
    """
    import attestations
    import skill_registry as sr

    requester = _resolve_caller(request)
    if not requester:
        raise HTTPException(status_code=401, detail="authentication required")

    safe_id = sanitize_text(skill_id, max_length=128)
    skill = await sr.get_skill(safe_id)
    if not skill:
        raise HTTPException(status_code=404, detail="skill_not_found")

    requester = sanitize_agent_id(requester)
    requester_member = members.get(requester) or {}
    is_leader = requester_member.get("chapter_role") in ("leader", "admin")
    is_self = requester_member.get("did") == attestor_did_path
    if not (is_leader or is_self):
        raise HTTPException(status_code=403, detail="only the attestor or a chapter leader may revoke")

    result = await attestations.revoke_attestation(
        skill_id=safe_id,
        skill_version=skill.get("version", ""),
        attestor_did=attestor_did_path,
        revocation_reason=sanitize_text(req.revocation_reason, max_length=500),
    )
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


class SkillUseRequest(BaseModel):
    skill_version: str
    used_by_agent_id: str
    used_by_did: str = ""
    tool_name: str
    idempotency_key: str
    gross_cents: int = 100
    success: bool = True
    duration_ms: int | None = None


@app.post("/api/skills/{skill_id}/use")
@app.post("/api/skills/{skill_id}/use/")
async def record_skill_use_endpoint(skill_id: str, req: SkillUseRequest, request: Request) -> dict:
    """Record an attested-skill tool invocation + mint the revenue ledger split.

    Unattested skills return {"billed": false, "reason": "no_attestations"}.
    Duplicate idempotency_keys return {"billed": false, "reason": "duplicate"}.

    The using agent IS the auth-verified caller — never the body-claimed
    ``used_by_agent_id`` (accepted-but-ignored). Every agent self-reports its own
    usage; otherwise revenue attribution could be spoofed onto another agent.
    """
    import skill_revenue

    agent = _resolve_caller(request)
    if not agent:
        raise HTTPException(status_code=401, detail="authentication required")

    safe_id = sanitize_text(skill_id, max_length=128)
    agent = sanitize_agent_id(agent)
    if not agent:
        raise HTTPException(status_code=400, detail="invalid used_by_agent_id")

    result = await skill_revenue.record_skill_use(
        skill_id=safe_id,
        skill_version=sanitize_text(req.skill_version, max_length=32),
        used_by_agent_id=agent,
        used_by_did=sanitize_text(req.used_by_did, max_length=200),
        tool_name=sanitize_text(req.tool_name, max_length=100),
        idempotency_key=sanitize_text(req.idempotency_key, max_length=256),
        gross_cents=int(req.gross_cents),
        success=bool(req.success),
        duration_ms=req.duration_ms,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/ledger/earnings", response_model=None)
async def ledger_earnings(request: Request, did: str | None = None, since: str | None = None) -> dict | JSONResponse:
    """Rolled-up earnings for the CALLER's own DID.

    ⚠️ `did` USED TO BE A PLAIN, UNVERIFIED QUERY PARAMETER. The docstring said
    "caller should pass their own did:key", but nothing checked that — any
    caller could read any DID's earnings by supplying it, including a DID
    belonging to a different org. Same class of bug the self-scoped surfaces
    (today, advisor-earnings; see get_surface_endpoint) were fixed for first:
    the verified caller's OWN did:key replaces any client-supplied target,
    it is never taken from the request as-is.

    The `chapter:<id>` form is this chapter's own aggregate share, not a
    member's — it stays reachable only for this chapter's own signed caller
    or a valid admin bearer, everything else resolves to the caller's own
    did:key regardless of what `did` was sent.
    """
    import skill_revenue

    caller = _resolve_caller(request)
    requested = sanitize_text(did, max_length=300) if did else ""

    if requested.startswith("chapter:"):
        # The admin-bearer path carries no member signature at all, so this
        # branch must not require a resolved caller first — an admin-only
        # request would 401 before ever reaching the check it should pass.
        safe_id = sanitize_agent_id(caller) if caller else ""
        is_this_chapter = bool(safe_id) and safe_id == AGENT_ID
        is_admin = auth_verify.check_admin_token_header(dict(request.headers))
        if not (is_this_chapter or is_admin):
            return JSONResponse(
                status_code=403,
                content={"error": "chapter earnings require this chapter's own signed caller or an admin token"},
            )
        target_did = requested
    else:
        if not caller:
            return JSONResponse(status_code=401, content={"error": "auth required"})
        safe_id = sanitize_agent_id(caller)
        # Resolve the caller's did:key from their stored Ed25519 pubkey —
        # same idiom as get_surface_endpoint's self-scoped surfaces.
        stored = auth_verify._agent_keys.get(safe_id, {}) if hasattr(auth_verify, "_agent_keys") else {}
        pubkey = stored.get("ed25519_pubkey") or ""
        if not pubkey:
            return JSONResponse(
                status_code=403,
                content={"error": "caller has no stored Ed25519 pubkey; cannot derive did:key"},
            )
        target_did = sovereign_identity.build_did_key_from_ed25519(pubkey)

    return await skill_revenue.get_earnings_for_did(target_did, since_iso=since)


# ═══════════════════════════════════════════════════════════════════
# Onboarding + settings endpoints
# ═══════════════════════════════════════════════════════════════════


class OnboardingAdvanceRequest(BaseModel):
    agent_id: str
    step: int
    values: dict = {}


class SettingsUpdateRequest(BaseModel):
    agent_id: str
    patch: dict


@app.get("/api/onboarding/{agent_id}")
async def onboarding_state(agent_id: str, request: Request):
    """⚠️ USED TO ANSWER FOR ANY agent_id WITH NO AUTH AT ALL, while the write
    side (POST /api/onboarding/advance) has always used _require_agent_owner.
    Now requires a signature (/api/onboarding/ is in
    auth_verify.REQUIRE_AUTH_GET_PREFIXES) and is scoped the same way.
    """
    import onboarding as onb

    aid = sanitize_agent_id(agent_id)
    _require_agent_owner(request, aid, what="onboarding state")
    step = await onb.get_step(aid)
    spec = onb.step_spec(step)
    total = onb.total_steps()
    return {"agent_id": aid, "step": step, "total": total, "spec": spec}


async def store_onboarding_secret(pg_request, agent_id: str, key_name: str, value: str) -> None:
    """Persist an onboarding secret, SEALED, in the member's private memory.

    ⚠️ IT WAS WRITTEN IN THE CLEAR. This is the same database that holds the
    chapter's signing key and members' provider keys, and both of those are
    sealed with ``secret_sealing`` (AES-256-GCM under ``ORRERY_KEY_SECRET``)
    precisely because a dump or a backup is enough to read a plaintext row. The
    value arriving here is an operator's provider credential; it belongs under
    the same mechanism rather than beside it in plaintext.

    No new failure mode: the chapter already refuses to start when sealing is
    required and no secret is configured, so a chapter that is running can
    always seal. An operator who deliberately opted out gets the same logged
    plaintext fallback they get for every other secret.

    Module level, not a closure in the route, so the sealing can be driven
    directly — a test that re-implements this write would be asserting its own
    copy of the behaviour rather than the one that ships.
    """
    # sovereign_identity.py already writes to agent_private_memory with
    # memory_type='identity'. We reuse the same table with memory_type='secret'.
    await pg_request(
        "POST",
        "agent_private_memory",
        body={
            "agent_id": agent_id,
            "owner_id": agent_id,  # member owns their own secrets
            "memory_type": "secret",
            "memory_key": key_name,
            "memory_value": {"value": secret_sealing.seal(value, subject=f"the onboarding secret {key_name!r}")},
        },
    )


@app.post("/api/onboarding/advance")
async def onboarding_advance(req: OnboardingAdvanceRequest, request: Request):
    import onboarding as onb
    import pg_store as pg_store_mod
    import settings as settings_mod

    aid = sanitize_agent_id(req.agent_id)
    _require_agent_owner(request, aid, what="onboarding state")
    # Store LLM keys under private memory when step 2 provides one.
    # In MVP we stash under agent_config private memory via pg_request —
    # reuse existing helper if present, otherwise write to a dedicated table.

    async def store_secret(agent_id: str, key_name: str, value: str) -> None:
        await store_onboarding_secret(pg_request, agent_id, key_name, value)

    try:
        result = await onb.advance(
            agent_id=aid,
            step=int(req.step),
            values={k: sanitize_text(str(v), max_length=1000) for k, v in (req.values or {}).items()},
            store_secret=store_secret,
            settings_module=settings_mod,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except onb.StepPartiallyApplied as e:
        # ⚠️ "NOTHING WAS RECORDED" WAS FALSE, AND IT USED TO BE THIS MESSAGE.
        # These writes are not atomic, so a refusal part way through leaves the
        # earlier ones applied. Telling the operator nothing landed is the same
        # defect as telling them everything did, mirrored — and it is the more
        # dangerous direction, because it invites them to assume a clean slate
        # that is not there.
        #
        # So the detail says what DID land, and that resubmitting is safe. It
        # is safe: every write in a step is idempotent, so a resubmit re-applies
        # what landed and retries what did not.
        saved = ", ".join(e.saved) if e.saved else "nothing"
        raise HTTPException(
            status_code=503,
            detail=(
                f"onboarding step {req.step} did not finish: {e.failed} was refused. "
                f"Already saved: {saved}. Submit the same step again — resubmitting is safe."
            ),
        ) from e
    except (onb.OnboardingWriteFailed, settings_mod.SettingsWriteFailed, pg_store_mod.DatabaseError) as e:
        # A refusal from OUTSIDE the recorded sequence — nothing in the step had
        # run yet, so there is genuinely nothing to have landed.
        raise HTTPException(
            status_code=503,
            detail=f"onboarding step {req.step} was not saved: {e}. Nothing was recorded; retry.",
        ) from e
    return result


@app.post("/api/onboarding/{agent_id}/reset")
async def onboarding_reset(agent_id: str, request: Request):
    import onboarding as onb
    import pg_store as pg_store_mod

    aid = sanitize_agent_id(agent_id)
    _require_agent_owner(request, aid, what="onboarding state")
    try:
        await onb.reset(aid)
    except (onb.OnboardingWriteFailed, pg_store_mod.DatabaseError) as e:
        # The success body below is a constant, so a refused write here would
        # report a wizard reset that did not happen.
        raise HTTPException(status_code=503, detail=f"onboarding reset was not saved: {e}") from e
    return {"agent_id": aid, "step": 0}


def _require_settings_owner(request: Request, aid: str) -> None:
    """A member's settings bag is private. The middleware already requires a
    valid signature on these routes; here we bind the target id to the
    verified caller (or an admin token), so a signed member can only touch
    their OWN settings — never another agent's by passing a different id.

    Delegates to ``_require_agent_owner``: this rule was correct here and absent
    from ``/api/voice/config``, which writes the SAME ``agent_settings`` row.
    One implementation, so the next route that needs it cannot get a subtly
    different one."""
    _require_agent_owner(request, aid, what="settings")


@app.get("/api/settings/{agent_id}")
async def settings_get(agent_id: str, request: Request):
    import settings as settings_mod

    aid = sanitize_agent_id(agent_id)
    _require_settings_owner(request, aid)
    return {"agent_id": aid, "settings": await settings_mod.get_settings(aid)}


@app.post("/api/settings/update")
async def settings_update(req: SettingsUpdateRequest, request: Request):
    import settings as settings_mod

    aid = sanitize_agent_id(req.agent_id)
    _require_settings_owner(request, aid)
    try:
        new_settings = await settings_mod.update_settings(aid, req.patch or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"agent_id": aid, "settings": new_settings}


@app.post("/api/settings/{agent_id}/reset")
async def settings_reset(agent_id: str, request: Request):
    import settings as settings_mod

    aid = sanitize_agent_id(agent_id)
    _require_settings_owner(request, aid)
    return {"agent_id": aid, "settings": await settings_mod.reset_settings(aid)}


# ═══════════════════════════════════════════════════════════════════
# Voice configuration endpoints
# ═══════════════════════════════════════════════════════════════════


class VoiceConfigRequest(BaseModel):
    agent_id: str
    config: dict


@app.get("/api/voice/providers")
async def voice_providers():
    """Return the STT + TTS provider catalog the A2UI surface renders."""
    import voice as voice_mod

    return {
        "stt": voice_mod.stt_providers(),
        "tts": voice_mod.tts_providers(),
    }


@app.get("/api/voice/voices")
async def voice_voices(tts_provider: str):
    """Return voice_id options for a given TTS provider."""
    import voice as voice_mod

    return {"voices": voice_mod.voice_options_for(tts_provider[:64])}


@app.post("/api/voice/config")
async def voice_config_update(req: VoiceConfigRequest, request: Request):
    """Apply a validated voice config patch via the settings store.

    Same ownership rule as ``/api/settings/update`` because it writes the same
    ``agent_settings`` row — that route was gated and this one was not, so a
    signed member could rewrite any other member's voice config through the
    unbolted door beside the bolted one."""
    import settings as settings_mod
    import voice as voice_mod

    aid = sanitize_agent_id(req.agent_id)
    _require_agent_owner(request, aid, what="voice settings")
    ok, reason = voice_mod.validate_config(req.config or {})
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    try:
        new = await settings_mod.update_settings(aid, {"voice": req.config or {}})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"agent_id": aid, "voice": new.get("voice", {})}


# ═══════════════════════════════════════════════════════════════════
# Channel connection endpoints
# ═══════════════════════════════════════════════════════════════════


class ChannelConnectRequest(BaseModel):
    agent_id: str
    kind: str
    remote_id: str
    display_name: str = ""
    config: dict = {}


class ChannelDisconnectRequest(BaseModel):
    agent_id: str


@app.get("/api/channels/{agent_id}")
async def channels_list(agent_id: str, request: Request, kind: str | None = None):
    """⚠️ USED TO ANSWER FOR ANY agent_id WITH NO AUTH AT ALL, while the write
    side (POST /api/channels/connect) has always used _require_agent_owner.
    Now requires a signature (/api/channels/ is in
    auth_verify.REQUIRE_AUTH_GET_PREFIXES) and is scoped the same way.
    """
    import channels as channels_mod

    aid = sanitize_agent_id(agent_id)
    _require_agent_owner(request, aid, what="channel connections")
    safe_kind = sanitize_text(kind, max_length=32) if kind else None
    conns = await channels_mod.list_connections(aid, kind=safe_kind)
    return {"agent_id": aid, "connections": conns}


@app.post("/api/channels/connect")
async def channels_connect(req: ChannelConnectRequest, request: Request):
    import channels as channels_mod

    aid = sanitize_agent_id(req.agent_id)
    _require_agent_owner(request, aid, what="channel connections")
    try:
        conn = await channels_mod.connect(
            agent_id=aid,
            kind=sanitize_text(req.kind, max_length=32),
            remote_id=sanitize_text(req.remote_id, max_length=256),
            display_name=sanitize_text(req.display_name, max_length=120),
            config=req.config or {},
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"connection": conn}


@app.post("/api/channels/{connection_id}/disconnect")
async def channels_disconnect(connection_id: str, req: ChannelDisconnectRequest, request: Request):
    import channels as channels_mod

    safe_id = sanitize_text(connection_id, max_length=64)
    _require_agent_owner(request, sanitize_agent_id(req.agent_id), what="channel connections")
    try:
        result = await channels_mod.disconnect(
            connection_id=safe_id,
            agent_id=sanitize_agent_id(req.agent_id),
        )
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg) from e
        raise HTTPException(status_code=403, detail=msg) from e
    return result


@app.post("/api/channels/{connection_id}/test")
async def channels_test(connection_id: str):
    import channels as channels_mod

    safe_id = sanitize_text(connection_id, max_length=64)
    try:
        return await channels_mod.test(safe_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


# ═══════════════════════════════════════════════════════════════════
# Mesh endpoints — unified peers + intent + send
# ═══════════════════════════════════════════════════════════════════


class MeshSendRequest(BaseModel):
    sender_agent_id: str
    target_agent_id: str
    text: str
    intent_id: str | None = None


class MeshIntentRequest(BaseModel):
    requester_agent_id: str
    text: str
    tags: list[str] = []


@app.get("/api/mesh/state")
async def mesh_state(target: str | None = None):
    """Mesh overview summary for the /page/mesh surface.

    Traced: mesh.get_mesh_state returns aggregate counts only
    (members_here, peers_online, peers_offline, chapter_id) plus
    `opportunities` (chapter-level skill-gap matches: gap, source/
    matching chapter name, matching_skills, member_count — no
    individual agent). The one per-principal field, `my_trust` (present
    only when `target` is supplied), is `mesh.my_trust`'s
    {agent_id, trust_score, tier} for that id — the identical shape
    already open at GET /api/agents/{agent_id}/trust's score/tier, just
    reached through a second path; not a new disclosure.
    """
    import mesh as mesh_mod

    aid = sanitize_agent_id(target) if target else None
    return await mesh_mod.get_mesh_state(agent_id=aid)


@app.get("/api/mesh/peers")
async def mesh_peers(
    query: str | None = None,
    skills: str | None = None,  # comma-separated
    chapter_id: str | None = None,
    limit: int = 50,
):
    import mesh as mesh_mod

    skills_list = [sanitize_text(s, max_length=64) for s in skills.split(",") if s.strip()] if skills else None
    peers = await mesh_mod.list_peers(
        query=sanitize_text(query, max_length=200) if query else None,
        skills=skills_list,
        chapter_id=sanitize_text(chapter_id, max_length=64) if chapter_id else None,
        limit=min(max(int(limit), 1), 200),
    )
    return {"peers": peers, "count": len(peers)}


@app.post("/api/mesh/send")
async def mesh_send(req: MeshSendRequest, request: Request):
    import mesh as mesh_mod

    sender = _bind_actor_to_caller(request, req.sender_agent_id, field="sender_agent_id")
    try:
        return await mesh_mod.send_to_peer(
            sender_agent_id=sender,
            target_agent_id=sanitize_agent_id(req.target_agent_id),
            text=sanitize_text(req.text, max_length=16000),
            intent_id=sanitize_text(req.intent_id, max_length=64) if req.intent_id else None,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/api/mesh/intent")
async def mesh_intent(req: MeshIntentRequest, request: Request):
    import mesh as mesh_mod

    requester = _bind_actor_to_caller(request, req.requester_agent_id, field="requester_agent_id")
    try:
        return await mesh_mod.submit_intent(
            requester_agent_id=requester,
            text=sanitize_text(req.text, max_length=2000),
            tags=[sanitize_text(t, max_length=64) for t in (req.tags or [])][:20],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/mesh/trust/{agent_id}")
async def mesh_trust(agent_id: str):
    """An agent's trust score/tier via the mesh path.

    mesh.my_trust returns {agent_id, trust_score, tier} for any id —
    the identical shape and sensitivity already open at GET
    /api/agents/{agent_id}/trust's score/tier fields (that route's
    history is what needed redacting, not its score). This is the same
    data reached through a second, mesh-namespaced path, not a new
    disclosure.
    """
    import mesh as mesh_mod

    return await mesh_mod.my_trust(sanitize_agent_id(agent_id))


# ═══════════════════════════════════════════════════════════════════
# Surface telemetry — W7
# ═══════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════
# Server enterprise endpoints — SSO, audit, federation allowlist
# ═══════════════════════════════════════════════════════════════════


class SSOConfigRequest(BaseModel):
    chapter_id: str
    provider: str
    issuer_url: str
    client_id: str
    enforce_sso: bool = False
    metadata: dict = {}


class AllowlistEntryRequest(BaseModel):
    chapter_id: str
    peer_chapter_id: str
    added_by_agent_id: str
    reason: str = ""


class AuditRecordRequest(BaseModel):
    chapter_id: str
    action: str
    actor_agent_id: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    outcome: str = "ok"
    detail: dict = {}


@app.get("/api/chapter/sso/{chapter_id}")
async def chapter_sso_get(chapter_id: str, request: Request):
    """This org's SSO configuration. Leader or admin only, and this org only.

    An identity-provider binding names the party that decides who may
    authenticate. Reading it discloses the issuer, the client id and whether
    enforcement is claimed, which is what a caller would need to aim a
    replacement at it.
    """
    import chapter_auth

    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    if sanitize_text(chapter_id, max_length=128) != AGENT_ID:
        raise HTTPException(status_code=403, detail="sso config is scoped to this org")
    return {"sso": await chapter_auth.get_sso_config(AGENT_ID)}


@app.post("/api/chapter/sso")
async def chapter_sso_set(req: SSOConfigRequest, request: Request):
    """Bind this org to an identity provider. Leader or admin only, this org only.

    ``chapter_id`` is this org, taken from ``AGENT_ID``. The handler took it from
    the request body and accepted any caller with a member signature, so a member
    of one org could point another org at an issuer of their choosing.
    """
    import chapter_audit
    import chapter_auth

    ok, identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    chapter_id = AGENT_ID
    try:
        result = await chapter_auth.set_sso_config(
            chapter_id=chapter_id,
            provider=sanitize_text(req.provider, max_length=32),
            issuer_url=sanitize_text(req.issuer_url, max_length=500),
            client_id=sanitize_text(req.client_id, max_length=256),
            enforce_sso=bool(req.enforce_sso),
            metadata=req.metadata or {},
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    # Audit: SSO config change is always logged.
    await chapter_audit.record(
        chapter_id=chapter_id,
        action="sso.configure",
        actor_agent_id=identity.get("agent_id") or None,
        target_type="sso_config",
        target_id=req.provider,
        detail={"issuer_url": req.issuer_url, "enforce_sso": req.enforce_sso},
    )
    return {"sso": result}


@app.delete("/api/chapter/sso/{chapter_id}")
async def chapter_sso_clear(chapter_id: str, request: Request):
    """Remove this org's identity-provider binding. Leader or admin, this org only."""
    import chapter_audit
    import chapter_auth

    ok, identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    if sanitize_text(chapter_id, max_length=128) != AGENT_ID:
        raise HTTPException(status_code=403, detail="sso config is scoped to this org")
    await chapter_auth.clear_sso_config(AGENT_ID)
    await chapter_audit.record(
        chapter_id=AGENT_ID,
        action="sso.disable",
        actor_agent_id=identity.get("agent_id") or None,
        target_type="sso_config",
    )
    return {"ok": True}


@app.get("/api/chapter/allowlist/{chapter_id}")
async def chapter_allowlist_get(chapter_id: str, request: Request):
    """This org's federation allowlist — which peers it will federate with.

    ⚠️ USED TO ANSWER FOR AN ARBITRARY chapter_id WITH NO AUTH AT ALL, while
    the write routes on the same resource (allowlist/add, allowlist/remove)
    have always required leader-or-admin and hardcode ``chapter_id=AGENT_ID``
    — "a request cannot name an org it is not" (see their docstrings). The
    read side got neither protection. Now requires leader-or-admin and is
    scoped to this org the same way.
    """
    import chapter_auth

    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    safe_chapter = sanitize_text(chapter_id, max_length=128)
    if safe_chapter != AGENT_ID:
        raise HTTPException(status_code=403, detail="allowlist reads are scoped to this org")
    return {"allowlist": await chapter_auth.list_federation_allowlist(safe_chapter)}


@app.post("/api/chapter/allowlist/add")
async def chapter_allowlist_add(req: AllowlistEntryRequest, request: Request):
    """Add a peer to this org's federation allowlist.

    Leader or admin only. The allowlist is a federation trust decision: an
    allowlist with any entries is default-deny for every peer not on it, so a
    single entry decides which peers this org will federate with at all.

    ``chapter_id`` is this org, taken from ``AGENT_ID`` rather than the request.
    A request cannot name an org it is not.
    """
    import chapter_audit
    import chapter_auth

    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    actor = _bind_actor_to_caller(request, req.added_by_agent_id, field="added_by_agent_id")
    chapter_id = sanitize_text(AGENT_ID, max_length=128)
    try:
        result = await chapter_auth.add_federation_peer(
            chapter_id=chapter_id,
            peer_chapter_id=sanitize_text(req.peer_chapter_id, max_length=128),
            added_by_agent_id=actor,
            reason=sanitize_text(req.reason, max_length=500),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    await chapter_audit.record(
        chapter_id=chapter_id,
        action="allowlist.add",
        actor_agent_id=actor,
        target_type="chapter",
        target_id=req.peer_chapter_id,
        detail={"reason": req.reason},
    )
    return {"entry": result}


@app.post("/api/chapter/allowlist/remove")
async def chapter_allowlist_remove(req: AllowlistEntryRequest, request: Request):
    """Remove a peer from this org's federation allowlist.

    Leader or admin only, and scoped to this org, for the same reasons as the
    add path. Removal is the more direct denial of the two: taking the last
    remaining peer off a populated allowlist leaves the org federating with
    nobody.
    """
    import chapter_audit
    import chapter_auth

    ok, _identity, denied = await _authorize_role(request, allowed_roles={"leader", "admin"})
    if not ok:
        return denied
    actor = _bind_actor_to_caller(request, req.added_by_agent_id, field="added_by_agent_id")
    safe_chapter = sanitize_text(AGENT_ID, max_length=128)
    safe_peer = sanitize_text(req.peer_chapter_id, max_length=128)
    result = await chapter_auth.remove_federation_peer(safe_chapter, safe_peer)
    await chapter_audit.record(
        chapter_id=safe_chapter,
        action="allowlist.remove",
        actor_agent_id=actor,
        target_type="chapter",
        target_id=safe_peer,
    )
    return result


@app.post("/api/chapter/audit/record")
async def chapter_audit_record(req: AuditRecordRequest, request: Request):
    """Append an event to the chapter's hash-chained audit ledger.

    ⚠️ ``actor_agent_id`` is the VERIFIED CALLER, never the body. This handler
    took no ``Request`` at all until the actor-binding change, so it could not consult the caller
    even in principle: any signed member could append a chain-linked row naming
    any other member as the actor. The chain proves append-ORDER, never
    AUTHORSHIP, so a forged entry was indistinguishable from a real one to
    everything that reads the ledger as evidence."""
    import chapter_audit

    actor = _bind_actor_to_caller(request, req.actor_agent_id or "", field="actor_agent_id")
    # The ledger written to is this org's. The actor was already bound to the
    # verified caller; chapter_id was still taken from the body, so a member
    # could append a correctly-attributed row to a DIFFERENT org's ledger.
    try:
        result = await chapter_audit.record(
            chapter_id=AGENT_ID,
            action=sanitize_text(req.action, max_length=64),
            actor_agent_id=actor,
            target_type=sanitize_text(req.target_type, max_length=64) if req.target_type else None,
            target_id=sanitize_text(req.target_id, max_length=128) if req.target_id else None,
            outcome=sanitize_text(req.outcome, max_length=16),
            detail=req.detail or {},
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"event": result}


@app.get("/api/chapter/audit/{chapter_id}")
async def chapter_audit_list(
    chapter_id: str,
    request: Request,
    action: str | None = None,
    actor_agent_id: str | None = None,
    since: str | None = None,
    limit: int = 100,
):
    """⚠️ USED TO ANSWER FOR AN ARBITRARY chapter_id WITH NO AUTH AT ALL — the
    same audit ledger the admin-gated /admin/api/audit twin already serves,
    correctly gated and hardcoded to ``chapter_id=AGENT_ID``. Now requires
    admin and is scoped to this org the same way.
    """
    import chapter_audit

    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_chapter = sanitize_text(chapter_id, max_length=128)
    if safe_chapter != AGENT_ID:
        raise HTTPException(status_code=403, detail="audit reads are scoped to this org")
    events = await chapter_audit.list_events(
        chapter_id=safe_chapter,
        action=sanitize_text(action, max_length=64) if action else None,
        actor_agent_id=sanitize_agent_id(actor_agent_id) if actor_agent_id else None,
        since=sanitize_text(since, max_length=40) if since else None,
        limit=min(max(int(limit), 1), 1000),
    )
    return {"events": events, "count": len(events)}


@app.get("/api/chapter/audit/{chapter_id}/verify")
async def chapter_audit_verify(chapter_id: str, request: Request):
    """Same fix as chapter_audit_list: admin-gated twin of /admin/api/audit/verify."""
    import chapter_audit

    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_chapter = sanitize_text(chapter_id, max_length=128)
    if safe_chapter != AGENT_ID:
        raise HTTPException(status_code=403, detail="audit reads are scoped to this org")
    return await chapter_audit.verify_chain(safe_chapter)


@app.get("/api/chapter/audit/{chapter_id}/export.jsonl")
async def chapter_audit_export(chapter_id: str, request: Request, since: str | None = None):
    """Same fix as chapter_audit_list: admin-gated twin of /admin/api/audit/export."""
    from fastapi.responses import PlainTextResponse

    import chapter_audit

    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_chapter = sanitize_text(chapter_id, max_length=128)
    if safe_chapter != AGENT_ID:
        raise HTTPException(status_code=403, detail="audit reads are scoped to this org")
    lines = await chapter_audit.export_jsonl(
        chapter_id=safe_chapter,
        since=sanitize_text(since, max_length=40) if since else None,
    )
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""), media_type="application/x-ndjson")


@app.get("/api/chapter/providers")
async def chapter_providers():
    """SSO provider catalog for the admin surface's Select."""
    import chapter_auth

    return {"providers": chapter_auth.valid_providers()}


@app.get("/health/surfaces")
async def health_surfaces():
    """Per-surface cache + latency telemetry. Fast, in-memory only."""
    import surface_cache

    return {
        "surfaces": surface_cache.stats(),
        "cache_enabled": True,
        "ttl_seconds": surface_cache.DEFAULT_TTL_SECONDS,
    }


@app.post("/health/surfaces/reset")
async def health_surfaces_reset():
    """Clear surface cache + stats. Ops endpoint for cache busts."""
    import time as _time

    import surface_cache

    surface_cache.reset()
    return {"ok": True, "reset_at_ms": int(_time.time() * 1000)}


@app.get("/")
async def root_landing() -> dict:
    """Friendly hostname-only landing.

    Anyone hitting the bare chapter URL (developer probing it for the
    first time, share-card crawler, monitoring smoke test) used to see a
    raw FastAPI ``{"detail": "Not Found"}``. Pre-launch audit flagged
    this as a "broken service" first impression. Replace with a tiny JSON
    pointer to the discoverable surfaces:

      - ``/health``           liveness + slug + member count
      - ``/ready``            readiness — proves the DB round-trips (503 if not)
      - ``/api/version``      protocol + A2UI version negotiation
      - ``/agentfacts.json``  AgentFacts JSON-LD card
      - ``/.well-known/nanda-agent.json``  well-known discovery doc
      - ``/docs``             Swagger UI (FastAPI default)
      - ``/openapi.json``     full OpenAPI spec
      - ``/api/surfaces/dashboard``  the chapter's own A2UI surface

    Unauthenticated by design — this is the bootstrap document for any
    visitor who only knows the hostname.
    """
    return {
        "name": AGENT_NAME,
        "agent_id": AGENT_ID,
        "slug": CHAPTER_SLUG,
        "kind": "nanda-chapter",
        "spec": "https://github.com/Sharathvc23/orrery",
        "endpoints": {
            "health": "/health",
            "ready": "/ready",
            "version": "/api/version",
            "agentfacts": "/agentfacts.json",
            "well_known": "/.well-known/nanda-agent.json",
            "docs": "/docs",
            "openapi": "/openapi.json",
            "dashboard_surface": "/api/surfaces/dashboard",
            "members": "/api/members",
            "thoughts": "/api/thoughts",
        },
    }


@app.head("/health")
async def health_head() -> Response:
    """HEAD /health for load-balancer probes that don't follow GET semantics.

    Pre-launch audit flagged that HEAD /health returned 405 with
    ``Allow: GET`` — common HTTP probes (HAProxy, nginx upstream
    health checks, k8s liveness probes when configured for HEAD) get
    misled into reporting the chapter as down. FastAPI doesn't auto-add
    HEAD handlers; declare an empty 200 explicitly.
    """
    return Response(status_code=200)


@app.get("/api/docs")
async def api_docs_redirect():
    """Redirect /api/docs → /docs.

    The docs UI lives at the FastAPI default path (``/docs``), but
    several developers reflexively try ``/api/docs`` because the rest of
    the surface is namespaced under ``/api/``. Redirect rather than 404.
    """
    return RedirectResponse(url="/docs", status_code=308)


@app.get("/api/version")
async def api_version() -> dict:
    """Protocol-version advertisement.

    A version-capable chapter MUST advertise the versions it accepts here plus
    the A2UI versions it can emit. Clients probe this before signing so they can
    pick a scheme the server supports. Unauthenticated by design — the bootstrap
    document a client reads before signing.

    Returns:
      - ``chapter_id`` (canonical agent id)
      - ``protocol_versions`` (closed set of accepted spec majors; backward
        compat per §14 means "0.2" and "0.3" stay listed)
      - ``preferred_version`` (the latest spec major the chapter
        speaks fluently — clients SHOULD prefer this)
      - ``signature_scheme_scope`` (**this org is a v0.5 chapter**: the legacy
        ``ed25519`` v0.2 scheme is accepted on reads and the A2A interop
        surface, and REJECTED on mutating requests with 401
        ``method_binding_required``. ``protocol_versions`` carries no
        per-method scope — the spec says so plainly — so a v0.2-only client
        would otherwise read "0.2", conclude its writes are fine, and find out
        at request time. This block is that missing signal, served at
        negotiation time.)
      - ``a2ui_versions`` (closed set of A2UI envelope versions the
        chapter can emit on demand via ``?schema=v0.X``)
      - ``preferred_a2ui_version`` (the default A2UI version on
        unqualified surface requests)
    """
    # protocol v0.4 added an optional `meta` block on A2UI components; signing
    # is unchanged from v0.3 so v0.4 requests verify verbatim. v0.5 changes
    # exactly one rule on top of that — the scope in which the legacy
    # `ed25519` scheme is honoured — which this org already enforces (C4), so
    # `preferred_version` is "0.5".
    #
    # A2UI: default emit is v0.10 (additive minor over v0.9 — same envelope
    # shape, optional `meta` block per component). Clients that request
    # `?schema=v0.9` get the same surface byte-equivalent with the `meta`
    # block stripped, per spec/0.4/a2ui.md §10.2.
    return {
        "chapter_id": os.environ.get("AGENT_ID", "unknown"),
        # 0.5 is what this org actually implements: it rejects v0.2-signed
        # MUTATIONS (spec/0.5/signing.md §"v0.2 scope"), which is the one
        # normative delta from 0.4. 0.2/0.3/0.4 stay listed because v0.5 keeps
        # accepting them within the scope described below — dropping them would
        # break §14 backward compat and tell clients something false.
        "protocol_versions": ["0.2", "0.3", "0.4", "0.5"],
        "preferred_version": "0.5",
        "signature_scheme_scope": {
            "ed25519+nonce": "all requests",
            "ed25519": "reads and the A2A interop surface only; "
            "mutating requests are rejected with 401 method_binding_required",
            "spec": "spec/0.5/signing.md#v02-scope--the-one-change-in-v05",
        },
        "a2ui_versions": ["0.8", "0.9", "0.10"],
        "preferred_a2ui_version": "0.10",
        # ARP receipt-envelope versions this server accepts on POST /api/receipts.
        # 0.2 is accepted alongside 0.1 for the migration window (spec/arp/0.2 §0.2);
        # the server's own emitted receipts stay 0.1 until enforcement is flipped.
        "arp_versions": ["0.1", "0.2"],
        "preferred_arp_version": "0.2",
    }


_BUILD_INFO_CACHE: dict[str, str] | None = None


def _local_git(*args: str) -> str:
    """`git <args>` in the repo checkout — LOCAL DEV ONLY. Returns "" (never
    raises) unless a real ``.git`` is present next to the source; in a deployed
    ``railway up`` upload ``.git`` is excluded, so this yields "" and the caller
    degrades honestly instead of reporting a wrong value."""
    import subprocess
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parents[1]
    if not (repo_root / ".git").exists():
        return ""
    try:
        out = subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _resolve_build_info() -> dict[str, str]:
    """Resolve the running build's commit / branch / timestamp — the SAME
    provenance for /version AND /health (so the stale-deploy signal exists
    where orchestrators poll).

    Resolution order, freshest DEPLOY-TIME source first. A source that is absent
    degrades to the next; an exhausted chain ends at an honest ``"unknown"`` —
    NEVER a stale hardcoded value.

      1. ``APP_GIT_COMMIT`` / ``APP_GIT_BRANCH`` / ``APP_BUILD_TIMESTAMP`` env —
         set FRESH at every deploy (``railway variables --set
         APP_GIT_COMMIT=$(git rev-parse HEAD)`` then ``railway up``). This is the
         authoritative source for ``railway up`` LOCAL uploads, where ``.git`` is
         excluded and ``RAILWAY_GIT_COMMIT_SHA`` is NOT populated — the exact hole
         that left the live mesh reporting a stale commit.
      2. ``_version.json`` baked into the upload before ``railway up``.
      3. ``GIT_COMMIT`` / ``GIT_BRANCH`` / ``BUILD_TIMESTAMP`` env (docker
         ``--build-arg``: CI, compose, plain ``docker build``).
      4. ``RAILWAY_GIT_COMMIT_SHA`` / ``RAILWAY_GIT_BRANCH`` — github-connected
         Railway deploys only; empty for local uploads.
      5. ``git rev-parse HEAD`` — LOCAL DEV ONLY (a real ``.git`` checkout).
      6. ``"unknown"`` — honest degraded.

    Cached: env/file/checkout don't change within a process, and /health is
    polled hot.
    """
    global _BUILD_INFO_CACHE
    if _BUILD_INFO_CACHE is not None:
        return _BUILD_INFO_CACHE

    import json as _json
    import os as _os
    from pathlib import Path as _Path

    def _env(*names: str) -> str:
        for n in names:
            v = _os.environ.get(n, "").strip()
            if v:
                return v
        return ""

    # 1. deploy-time-injected (freshest; the railway-up fix)
    commit = _env("APP_GIT_COMMIT")
    branch = _env("APP_GIT_BRANCH")
    build_ts = _env("APP_BUILD_TIMESTAMP")

    # 2. baked _version.json (written into the upload pre-`railway up`)
    if not (commit and branch and build_ts):
        version_file = _Path(__file__).resolve().parent / "_version.json"
        if version_file.exists():
            try:
                data = _json.loads(version_file.read_text(encoding="utf-8"))
            except (ValueError, OSError) as e:
                # Honest degradation, LOUD — not a silent swallow into a stale value.
                print(f"[build-info] _version.json present but unreadable ({e!r}); degrading to the next source")
                data = {}
            commit = commit or str(data.get("git_commit", "")).strip()
            branch = branch or str(data.get("git_branch", "")).strip()
            build_ts = build_ts or str(data.get("build_timestamp", "")).strip()

    # 3. docker --build-arg env
    commit = commit or _env("GIT_COMMIT")
    branch = branch or _env("GIT_BRANCH")
    build_ts = build_ts or _env("BUILD_TIMESTAMP")

    # 4. platform provenance — github-connected Railway deploys only
    if not commit:
        rw_sha = _env("RAILWAY_GIT_COMMIT_SHA")
        commit = rw_sha[:7] if rw_sha else ""
    branch = branch or _env("RAILWAY_GIT_BRANCH")

    # 5. LOCAL DEV ONLY — a real checkout, so `/health` is accurate without wiring
    if not commit:
        commit = _local_git("rev-parse", "--short", "HEAD")
    if not branch:
        branch = _local_git("rev-parse", "--abbrev-ref", "HEAD")

    # 6. honest degraded — never a stale hardcoded SHA
    _BUILD_INFO_CACHE = {
        "git_commit": commit or "unknown",
        "git_branch": branch or "unknown",
        "build_timestamp": build_ts or "unknown",
    }
    return _BUILD_INFO_CACHE


@app.get("/version")
async def version() -> dict:
    """Build version + git commit + deploy timestamp.

    Operators + smoke-tests use this to confirm a deploy actually
    landed the expected code. Catches the failure mode where a deploy
    fails silently and the previous container keeps serving — see PR incident postmortem where production ran 2 weeks of stale
    code without obvious signal.

    Resolution order (highest priority first):

      1. ``_version.json`` baked into the source archive by
         ``chapter/scripts/deploy_production.sh`` — the canonical
         path for any deploy that runs ``railway up`` or a similar
         uploader. Survives any base image / build system.
      2. ``GIT_COMMIT`` / ``GIT_BRANCH`` / ``BUILD_TIMESTAMP`` env
         vars — set by build systems that pass Docker ``--build-arg``
         (GitHub Actions, Fly, plain ``docker build``).
      3. ``"unknown"`` — legitimate for local dev when neither path
         was wired.

    Endpoint is open (no auth) — version info is non-sensitive and
    operators MUST be able to read it from external smoke-test
    scripts that don't hold admin credentials.
    """
    info = _resolve_build_info()
    return {
        "agent_id": AGENT_ID,
        "agent_name": AGENT_NAME,
        "git_commit": info["git_commit"],
        "git_branch": info["git_branch"],
        "build_timestamp": info["build_timestamp"],
        "protocol_version": "0.3",
        "arp_version": "0.1",
    }


@app.get("/ready", response_model=None)
async def ready() -> JSONResponse:
    """Readiness — actively PROVES the loops. Distinct from ``/health``, which
    is cheap liveness (the process serves). ``/ready`` round-trips the database
    (``SELECT 1``). Returns **503** with per-check detail when a *configured*
    dependency is not ready, so a load balancer / orchestrator never routes DB
    traffic to a DB-blind chapter (the "liveness masquerading as readiness" gap
    this closes).

    When no ``DATABASE_URL`` is configured (dev / in-memory mode) there is no backing
    loop to prove, so the chapter is ready by definition."""
    checks: dict[str, str] = {}
    ready_ok = True

    if _HAS_DATABASE:
        import pg_store

        db_ok = await pg_store.db_ping()
        checks["database"] = "up" if db_ok else "down"
        if not db_ok:
            ready_ok = False
    else:
        checks["database"] = "not_configured"

    return JSONResponse(
        status_code=200 if ready_ok else 503,
        content={
            "status": "ready" if ready_ok else "not_ready",
            "checks": checks,
            "agent_id": AGENT_ID,
            "git_commit": _resolve_build_info()["git_commit"],
        },
    )


def _db_tls_available_safe() -> bool | None:
    """pg_store.db_tls_available(), or None when there is no database at all.

    pg_store is imported lazily throughout this module (offline deployments have
    no Postgres), so /health must not assume it is in scope.
    """
    if not _HAS_DATABASE:
        return None
    try:
        import pg_store

        return pg_store.db_tls_available()
    except Exception:  # noqa: BLE001 — a diagnostic must never break /health
        return None


@app.get("/health")
async def health() -> dict:
    """Liveness — the process is up and serving (cheap, no backing-store I/O so load
    balancers can poll it hot). It deliberately does NOT prove the database or
    backing store; readiness lives at ``/ready``, which round-trips the
    DB and 503s when a configured dependency is down. ``status`` here is always
    ``ok`` for a serving process — do not read it as readiness."""
    # Compact per-peer federation state — useful for ops + leader dashboards
    federation_state: list[dict] = []
    try:
        import federation_policy as fed_mod

        for p in await fed_mod.list_policies():
            federation_state.append(
                {
                    "peer": p.get("peer_chapter_id"),
                    "state": p.get("state"),
                    "failures": p.get("consecutive_failures"),
                    "backoff_seconds": p.get("backoff_seconds"),
                    "blocked_by": p.get("blocked_by"),
                    "last_success_at": p.get("last_success_at"),
                }
            )
            # Mirror federation state into Prometheus gauges.
            metrics.set_federation_state(p.get("peer_chapter_id") or "unknown", p.get("state") or "offline")
    except Exception:  # noqa: BLE001 — health probe must never raise
        pass

    # Mirror member count into Prometheus gauge.
    metrics.set_members_total(len(members))

    return {
        "status": "ok",
        "agent_id": AGENT_ID,
        "slug": CHAPTER_SLUG,
        "display_name": CHAPTER_DISPLAY_NAME,
        # Build provenance: the same commit /version resolves, surfaced
        # here so smoke-tests/orchestrators that poll /health can detect a
        # stale deploy. "unknown" in local dev when nothing was baked.
        "git_commit": _resolve_build_info()["git_commit"],
        "members": len(members),
        "federation": len(federation),
        "federation_state": federation_state,
        "registries": nanda_registry.get_registry_status(),
        # Whether the cross-registry divergence detector can actually run. It
        # returns [] both when it compared everything and found nothing wrong,
        # and when it had nothing to compare — this is what tells those apart.
        # regentix ran with one registry for weeks and looked identical to a
        # clean result until someone read /health org by org.
        "corroboration": registry_divergence.corroboration_status(
            nanda_registry.configured_registries() + federation_discovery.directory_urls()
        ),
        # ⚠️ THE HOP COUNT THE RATE LIMITER IS ACTUALLY USING — the module
        # constant `client_ip_for_rate_limit` consults, NOT a fresh read of the
        # environment. The distinction is the whole reason this field exists.
        #
        # TRUSTED_PROXY_HOPS is resolved ONCE at import. An operator who changes
        # the variable does not change the running process, so a field that
        # re-read os.environ here would print the NEW value while the limiter
        # went on keying with the OLD one — a surface that reports the
        # configuration back to the person who just wrote it, and agrees with
        # them precisely when they most need to be contradicted. Measured on a
        # sibling service: `railway variables` read back the new value while the
        # process used the old one through eighteen consecutive polls.
        #
        # WHAT THIS FIELD IS FOR. Left unset, the limiter keys on the edge
        # proxy's address rather than the caller's, so every member shares one
        # bucket and one caller can 429 everyone — the failure the startup
        # comment describes in its own words. That was the deployed state of
        # this setting for as long as it has existed, and nobody saw it, because
        # the only way to check was to read the platform's variables per
        # deployment. `0` here on a proxied deployment IS that failure, visible.
        #
        # PUBLISHED ON AN UNAUTHENTICATED ENDPOINT DELIBERATELY. A wrong hop
        # count is marginally easier to exploit when it is stated, but the
        # bucketing is discoverable anyway — vary the prepended X-Forwarded-For
        # and observe whether buckets separate — so concealment buys an attacker
        # little and costs the operator the one signal that would have caught
        # this. The misconfiguration is the vulnerability; the disclosure is not.
        # Same posture as db.tls_available below: reported, never enforced.
        #
        # Named for the variable an operator sets (TRUSTED_PROXY_HOPS) rather
        # than for the sibling service's flat `trusted_proxies`, because the
        # check this exists to make possible is "does the process agree with
        # what I just set", and that comparison should not need a translation
        # step. It is a COUNT of hops, not a list of proxies.
        #
        # Reading an already-computed int costs nothing and cannot raise, which
        # is what keeps the promise in this handler's docstring: no
        # backing-store I/O, so a load balancer can poll it hot.
        "trusted_proxy_hops": TRUSTED_PROXY_HOPS,
        # Whether limiter buckets actually survive a restart on THIS process.
        # Reported for the same reason trusted_proxy_hops is: the boot ensure
        # degrades silently by design, and an application role has no CREATE on
        # schema public (0006 withholds it deliberately), so an existing
        # least-privilege install runs with persistence OFF until an operator
        # applies 0008 as superuser. Without this field the only way to find out
        # is to read the boot log of a process that has since been replaced —
        # which is precisely how TRUSTED_PROXY_HOPS stayed wrong in production
        # for the life of the setting.
        "rate_limit_persistence": _rate_limit_persist_ok,
        # THE OTHER HALF of "do limiter buckets survive a restart", and it is a
        # separate fact. The flag above says the snapshot TABLE is writable.
        # Restore matches by equality of an HMAC under a salt kept outside the
        # database, so a restart restores something only if the next process
        # hashes with the SAME salt — and on a service with no persistent
        # volume the salt file is minted fresh on every boot. Measured on the
        # deployed mesh: all three processes read persistence true, all three
        # mounted no volume, and every restart booted the limiter empty.
        # `source` names where the salt came from (rate_limit_persistence
        # SOURCE_*); `durable` is whether that source survives a boot. Not
        # folded into the flag above, because a single boolean is exactly what
        # read true while the property it named did not hold.
        "rate_limit_salt": {
            "source": _rate_limit_salt_source,
            "durable": rate_limit_persistence.salt_durable(_rate_limit_salt_source),
        },
        # C3 residual: whether this Postgres accepts TLS on the hop this server
        # actually uses. Reported, never enforced — see pg_store._probe_tls_capability.
        # null until the pool is first created (or if the probe could not run).
        "db": {"tls_available": _db_tls_available_safe()},
    }


# ═══════════════════════════════════════════════════════════════════════
# /admin/api/* — system-level operator endpoints.
#
# Auth is TWO-PATH, tried in order:
#
#   1. PRIMARY: X-Agent-Signature from a member whose chapter_role
#      is 'admin'. Same auth scheme as every other endpoint — Ed25519
#      over the canonical signing string, did:key derived from the
#      stored pubkey. Audit trail shows WHICH human took each admin
#      action. This is what sovereign-SDK and member-signed scripts
#      use.
#
#   2. FALLBACK: X-Admin-Token bearer credential. For bootstrap (the
#      first admin needs to promote themselves), break-glass (the
#      admin lost their key), and browser-UI ops (the static admin UI
#      at /admin/ cannot hold a private key safely).
#
# The static admin UI at /admin/ + /admin/index.html is served below
# without auth so the operator can paste credentials; the API surface
# at /admin/api/* requires successful auth via one of the two paths
# on every call.
# ═══════════════════════════════════════════════════════════════════════


async def _authorize_role(
    request: Request,
    allowed_roles: set[str],
) -> tuple[bool, dict, JSONResponse | None]:
    """Generalized org-level role authorization gate (HTTP layer).

    A request is authorized iff EITHER:
      - it carries a valid ``X-Agent-Signature`` from a member whose
        ``chapter_role`` is in ``allowed_roles``, OR
      - it carries a valid ``X-Admin-Token`` bearer — the system-operator
        break-glass credential, which satisfies ANY administrative gate
        (it is how an operator recovers if signed-admin ever breaks).

    This is the request-layer adapter: it resolves identity, renders the
    401/403 JSONResponses, and looks up the role via ``governance``. The
    role *predicates* themselves (``is_leader``, ``can_approve``) live in
    ``governance`` at the ``agent_id → bool`` layer — keep that split.

    Returns ``(authorized, identity, response_if_denied)``:
      authorized — True iff one of the two paths succeeded.
      identity   — {"path": "did_key", "agent_id": <id>, "chapter_role": <role>}
                   or {"path": "bearer"}; {} when authorized=False.
      response_if_denied — pre-built denial JSONResponse (handler returns it
                           directly) when authorized=False, else None.

    ``_authorize_admin`` is the ``allowed_roles={"admin"}`` specialization;
    new gates pass e.g. ``{"leader", "admin"}``.
    """
    headers = dict(request.headers)
    roles_label = ", ".join(sorted(allowed_roles))

    # ── Path 1: X-Agent-Signature with an allowed chapter_role ──────
    if auth_verify._header(headers, "X-Agent-Signature"):
        # ⚠️ CONSUME THE MIDDLEWARE'S RESULT; DO NOT VERIFY AGAIN.
        #
        # Verification is not idempotent: `verify_request` spends the request's
        # (agent_id, nonce) in the replay store. On a middleware-gated route the
        # middleware has already verified and already spent it, so a second call
        # here saw ITS OWN nonce and returned `nonce_replay` — a legitimately
        # signed admin was told its request was a replay of itself. Eight
        # mutating routes were affected (invites, invite revoke, both approval
        # decisions, dsar delete, join-policy, trust decay-sweep, and the admin
        # branch of DELETE /api/members/{id}); the signed did:key path — the
        # documented PRIMARY one — was unusable on every one of them, leaving
        # only the shared static X-Admin-Token. The replay guard is correct and
        # the second verification was the bug, so the nonce is NOT exempted.
        #
        # The middleware records its verification as TWO things: the flag
        # `request.state.verified` and the identity `request.state.agent_id`.
        # Both are required here, and the identity must be a non-empty STRING —
        # this is an authorization decision reading mutable request state, so it
        # accepts the declared shape rather than anything merely truthy. (A test
        # double whose auto-created attribute is truthy took this branch and
        # authorized a mock; production only ever sets a str, but an auth path
        # should not depend on that being the only writer.) Anything else falls
        # through to a real verification below.
        verified_caller = _resolve_caller(request)
        middleware_verified = getattr(request.state, "verified", False) is True
        if middleware_verified and isinstance(verified_caller, str) and verified_caller:
            valid, agent_id, reason = True, verified_caller, "ok"
        else:
            # No middleware verification for this path: /admin/api/* is an open
            # path at the gate precisely so its handler can do this itself. Here
            # the nonce is unspent and this is the FIRST and ONLY verification.
            try:
                body_bytes = await request.body()
                body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
            except Exception:
                body_str = ""
            valid, agent_id, reason = auth_verify.verify_request(
                body=body_str,
                headers=headers,
                method=request.method,
                url_path=request.url.path,
            )
        if valid and agent_id:
            import governance as _governance

            role = await _governance.get_chapter_role(agent_id)
            if role in allowed_roles:
                return True, {"path": "did_key", "agent_id": agent_id, "chapter_role": role}, None
            # Signed but role not permitted — explicit refusal so the
            # operator sees "your member identity is fine but lacks the
            # required role" rather than the generic 401 for no signature.
            return (
                False,
                {},
                JSONResponse(
                    status_code=403,
                    content={
                        # Phrasing keeps the admin-case strings stable
                        # ("admin role required") for existing callers/tests
                        # while reading naturally for multi-role gates.
                        "error": f"{roles_label} role required",
                        "hint": f"agent_id={agent_id} has chapter_role={role!r}; needs one of [{roles_label}]",
                        "remediation": "ask an existing admin to promote you via POST /admin/api/members/{your_id}/role",
                    },
                ),
            )
        # Sig present but invalid — surface the reason so the operator
        # can debug their canonical-string construction or replay window.
        return (
            False,
            {},
            JSONResponse(
                status_code=401,
                content={
                    "error": "X-Agent-Signature verification failed",
                    "reason": reason,
                },
            ),
        )

    # ── Path 2: X-Admin-Token bearer (operator break-glass) ─────────
    if auth_verify.check_admin_token_header(headers):
        return True, {"path": "bearer"}, None

    # ── Neither path supplied / matched ─────────────────────────────
    return (
        False,
        {},
        JSONResponse(
            status_code=401,
            content={
                "error": "authorization required",
                "hint": (
                    f"use X-Agent-Signature (member with chapter_role={roles_label}) "
                    "or X-Admin-Token (break-glass / bootstrap)"
                ),
            },
        ),
    )


def _deny_fallback(denied: JSONResponse | None) -> JSONResponse:
    """The deny response from _authorize_admin — with a fail-closed 403 if the
    not-ok-implies-denied invariant ever breaks (previously 12 call sites
    papered over this with `type: ignore[return-value]`; that change)."""
    return denied if denied is not None else JSONResponse(status_code=403, content={"error": "forbidden"})


async def _authorize_admin(request: Request) -> tuple[bool, dict, JSONResponse | None]:
    """Admin-only authorization — the ``allowed_roles={"admin"}``
    specialization of :func:`_authorize_role`. Kept as a named wrapper
    because ~6 admin endpoints call it directly. See that function for the
    two-path (signed-admin / bearer) semantics and return shape.
    """
    return await _authorize_role(request, {"admin"})


# Backward-compat alias retained for existing endpoints. New endpoints
# should call _authorize_admin directly to get the identity dict.
async def _require_admin(request: Request) -> JSONResponse | None:
    _ok, _ident, denied = await _authorize_admin(request)
    return denied


async def _require_role(request: Request, allowed_roles: set[str]) -> JSONResponse | None:
    """Convenience for endpoints that only need the denial-or-None: returns
    the pre-built denial :class:`JSONResponse` when the caller's role is not
    in ``allowed_roles`` (and no valid bearer), else ``None``."""
    _ok, _ident, denied = await _authorize_role(request, allowed_roles)
    return denied


class _AdminRoleChangeRequest(BaseModel):
    role: str  # member | advisor | mentor | leader | admin


@app.get("/admin/api/status")
async def admin_status(request: Request) -> JSONResponse:
    """Chapter status snapshot for operator dashboards."""
    if (denied := await _require_admin(request)) is not None:
        return denied
    return JSONResponse(
        content={
            "agent_id": AGENT_ID,
            "agent_name": AGENT_NAME,
            "slug": CHAPTER_SLUG,
            "public_url": PUBLIC_URL,
            "members_total": len(members),
            "federation_peers": len(federation),
            "version": {
                "protocol": ["0.2", "0.3"],
                "arp": "0.1",
            },
        }
    )


@app.get("/admin/api/audit")
async def admin_audit_list(
    request: Request,
    action: str | None = None,
    actor_agent_id: str | None = None,
    since: str | None = None,
    limit: int = 100,
) -> JSONResponse:
    """Query the chapter_audit_events ledger.

    Surfaces the hash-chained admin audit log that PR started
    populating + that PR began enriching with W3C ComplianceCredential
    detail. Before this endpoint, operators had to go direct to Postgres
    to read their own audit trail — a real friction point surfaced in
    today's verification pass.

    Query filters (all optional; combined with AND):
      - action       : substring of audit event action (e.g., 'admin.role.change')
      - actor_agent_id: filter by who performed the action
      - since        : ISO-8601 timestamp; only events occurred_at >= since
      - limit        : 1-1000, default 100

    Response shape:
      {
        "events": [
          {
            "id": "...",
            "occurred_at": "...",
            "action": "admin.role.change",
            "actor_agent_id": "...",
            "target_type": "agent",
            "target_id": "...",
            "outcome": "ok",
            "detail": { ..., "compliance_credential": {...optional W3C VC...} },
            "prev_hash": "sha256:...",
            "hash": "sha256:..."
          },
          ...
        ],
        "total_returned": N,
        "limit": N
      }

    Admin-gated (signed did:key OR bearer). The audit log is operator-
    sensitive — exposing it to non-admins would reveal who has been doing
    what to the chapter's governance state.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    capped = max(1, min(1000, int(limit)))
    try:
        import chapter_audit

        events = await chapter_audit.list_events(
            chapter_id=AGENT_ID,
            action=action,
            actor_agent_id=actor_agent_id,
            since=since,
            limit=capped,
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"error": "audit query failed", "detail": str(e)[:200]},
        )

    return JSONResponse(
        content={
            "events": events,
            "total_returned": len(events),
            "limit": capped,
            "filters": {
                "action": action,
                "actor_agent_id": actor_agent_id,
                "since": since,
            },
        }
    )


@app.get("/admin/api/audit/verify")
async def admin_audit_verify(request: Request) -> JSONResponse:
    """Verify the hash chain of chapter_audit_events.

    Walks the audit ledger and confirms each row's prev_hash matches the
    sha256 of the previous row. A break in the chain indicates either
    storage tampering OR a bug in chapter_audit.record's chaining logic.
    Returns the position of the first break, or success.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    try:
        import chapter_audit

        result = await chapter_audit.verify_chain(chapter_id=AGENT_ID)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"error": "chain verify failed", "detail": str(e)[:200]},
        )

    return JSONResponse(content=result)


@app.get("/admin/api/audit/export")
async def admin_audit_export(
    request: Request,
    action: str | None = None,
    actor_agent_id: str | None = None,
    since: str | None = None,
    limit: int = 1000,
) -> Response:
    """Download the chapter_audit_events ledger as NDJSON.

    Same filter shape and admin gate as ``/admin/api/audit`` — the export
    is the read endpoint with a download wrapper. SIEM consumers prefer
    NDJSON (every line is an independently-parseable JSON object) over
    a JSON array because they can stream-process without loading the full
    payload. ``since`` doubles as a SIEM watermark for incremental ingest:
    repeated calls with the last seen ``occurred_at`` advance the cursor.

    Scope (MVP): NDJSON only, max 1000 rows per call (same cap as the
    read endpoint). CSV format, chain-integrity headers, and an ``until``
    filter are deferred — see A3.2b if appetite emerges.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    try:
        capped = max(1, min(1000, int(limit)))
    except (TypeError, ValueError, OverflowError):
        capped = 1000

    try:
        import chapter_audit

        events = await chapter_audit.list_events(
            chapter_id=AGENT_ID,
            action=action,
            actor_agent_id=actor_agent_id,
            since=since,
            limit=capped,
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"error": "audit export failed", "detail": str(e)[:200]},
        )

    body = "\n".join(json.dumps(e, default=str) for e in events)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"audit-{AGENT_ID}-{timestamp}.ndjson"
    return Response(
        content=body,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/admin/api/index-v2/register")
async def admin_register_index_v2(request: Request) -> JSONResponse:
    """Operator-gated trigger: register this org on the configured NANDA
    Index v2 (``hosting_path=registry``, JWT signup + email-verify).

    Admin-gated (signed did:key OR bearer). This is the EXPLICIT trigger — Index
    v2 registration never auto-fires on startup, so there are no surprise
    network calls. Returns the registration status; ``pending`` means the
    operator must still click the verification email to activate the org.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    result = await nanda_registry.register_on_index_v2()
    return JSONResponse(content=result)


@app.post("/admin/api/grants")
async def admin_issue_grant(request: Request) -> JSONResponse:
    """Issue a BOUNDED operational grant — the middle option between approving
    every action and having no gate.

    Body: ``kind``, ``scope``, ``cap``, ``expires_at`` (ISO-8601, tz-aware).
    All four are REQUIRED. A bounded grant with an optional cap is an unbounded
    grant with extra steps, so an omission is a 400, never a generous default.

    Admin-gated: issuing a grant IS the operator decision, so it must be made
    by an operator and attributed to one.
    """
    ok, identity, denied = await _authorize_admin(request)
    if not ok:
        return denied or JSONResponse(status_code=403, content={"error": "forbidden"})
    import bounded_grants

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})

    raw_expiry = str((body or {}).get("expires_at") or "")
    try:
        expires_at = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00")) if raw_expiry else None
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "expires_at is not ISO-8601"})

    try:
        row = await bounded_grants.issue(
            kind=str((body or {}).get("kind") or ""),
            scope=(body or {}).get("scope"),
            cap=(body or {}).get("cap"),
            expires_at=expires_at,
            created_by=str(identity or "admin"),
        )
    except bounded_grants.GrantRefused as exc:
        # The refusal reason is the useful part — it names which bound was
        # missing, so an operator fixes it rather than guessing.
        return JSONResponse(status_code=400, content={"error": "grant_refused", "detail": str(exc)})
    return JSONResponse(content={"ok": True, "grant": row})


@app.get("/admin/api/grants")
async def admin_list_grants(request: Request) -> JSONResponse:
    """Live bounded grants — what this org is currently exposed to."""
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return denied or JSONResponse(status_code=403, content={"error": "forbidden"})
    import bounded_grants

    return JSONResponse(content={"grants": await bounded_grants.list_live()})


@app.delete("/admin/api/grants/{grant_id}")
async def admin_revoke_grant(request: Request, grant_id: str) -> JSONResponse:
    """Revoke a grant before either bound is reached.

    The third thing that makes a bound safe: an operator who changes their mind
    must not have to wait for the cap to fill or the clock to run out.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return denied or JSONResponse(status_code=403, content={"error": "forbidden"})
    import bounded_grants

    if not await bounded_grants.revoke(grant_id):
        return JSONResponse(status_code=409, content={"error": "not_revoked", "grant_id": grant_id})
    return JSONResponse(content={"ok": True, "grant_id": grant_id})


@app.get("/admin/api/grants/{grant_id}/consumptions")
async def admin_grant_consumptions(request: Request, grant_id: str) -> JSONResponse:
    """The per-consumption audit trail: which action, when, charged or not, and
    how many remained. Uncharged retries appear too — a retry storm that costs
    nothing is still something an operator should be able to see."""
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return denied or JSONResponse(status_code=403, content={"error": "forbidden"})
    import bounded_grants

    return JSONResponse(content={"consumptions": await bounded_grants.consumptions(grant_id)})


@app.post("/admin/api/audit/attest")
async def admin_audit_attest(request: Request) -> JSONResponse:
    """Issue a chapter-signed Signed Tree Head over the audit chain (A3.3).

    Computes the chain's current state — tip sha256, length, occurred_at
    window — and emits an ARP receipt with ``category="audit.chain.snapshot"``
    that cryptographically commits the chapter to that state at the
    snapshot moment. The receipt is self-attesting (issuer == principal ==
    the chapter's own did:key); verifiers trust the signature and judge
    the claim by comparing successive snapshots over time.

    Returns the signed ARP receipt as JSON. The admin chooses where to
    publish it — peer chapters, compliance officer's archive, a public
    transparency log — federation/publication mechanics are out of scope
    for A3.3.

    Admin-gated (signed did:key OR bearer).
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)

    try:
        import chapter_audit

        tip = await chapter_audit.chain_tip(AGENT_ID)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"error": "chain tip read failed", "detail": str(e)[:200]},
        )

    snapshot_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        import arp

        receipt = await arp.emit_audit_chain_snapshot(
            tip_sha256=tip.get("tip_sha256", ""),
            chain_length=tip.get("length", 0),
            snapshot_at=snapshot_at,
            first_occurred_at=tip.get("first_occurred_at"),
            last_occurred_at=tip.get("last_occurred_at"),
        )
    except arp.AttestationRefused as refused:
        # name the ACTUAL failure. The old 503 said "keypair unavailable OR
        # persistence failed" and told you which neither time — and the real
        # cause (a schema-invalid action category) went unreported for the whole
        # life of the endpoint.
        return JSONResponse(
            status_code=503,
            content={
                "error": "attestation refused",
                "stage": refused.stage,
                "detail": refused.detail[:300],
            },
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={"error": "attestation emit failed", "detail": str(e)[:200]},
        )

    if receipt is None or not receipt.get("signature"):
        # Either the server has no Ed25519 keypair loaded (boot ordering,
        # test isolation) or persistence failed. Either way, refuse to
        # return an unsigned blob — auditors trust the signature.
        return JSONResponse(
            status_code=503,
            content={"error": "cannot sign attestation — chapter keypair unavailable or persistence failed"},
        )

    return JSONResponse(content=receipt)


@app.get("/admin/api/members")
async def admin_members_list(request: Request, limit: int = 200) -> JSONResponse:
    """List every member known to this chapter (in-memory + persisted)."""
    if (denied := await _require_admin(request)) is not None:
        return denied
    capped = max(1, min(500, int(limit)))
    out: list[dict] = []
    for agent_id, m in list(members.items())[:capped]:
        out.append(
            {
                "agent_id": agent_id,
                "name": m.get("name", agent_id),
                "description": (m.get("description") or "")[:200],
                "skills": list(m.get("skills") or [])[:10],
                "chapter_role": m.get("chapter_role", "member"),
                "virtual": bool(m.get("virtual", False)),
                "is_demo": bool(m.get("is_demo", False)),
            }
        )
    return JSONResponse(content={"members": out, "total": len(members)})


class _Host39PublicationRecord(BaseModel):
    card_url: str = ""


@app.post("/admin/api/host39/record-publication/{agent_id}")
async def admin_record_host39_publication(
    agent_id: str, req: _Host39PublicationRecord, request: Request
) -> JSONResponse:
    """Record that a member's host39 card has actually been published.

    The AI Catalog advertises a member's host39 card URL only when this record
    exists. It used to emit one for EVERY member whenever ORG_HOST39_CARD_BASE
    was set — but publishing a card is an explicit operator trigger that
    registration deliberately does not fire, so the catalog advertised
    URLs for members whose cards were never created. Measured live on the
    astrocity org 2026-08-02: 24 entries, 6 resolved, 18 returned 404.

    "The org has a card base configured" is a fact about the ORG. Whether THIS
    member's card exists is a different fact, and this endpoint is where it is
    written. ``scripts/publish_host39_card.py --record-on-org`` calls it right
    after a successful POST /cards, so the record cannot drift ahead of the
    publication it describes.

    Admin-gated: it changes what the org advertises publicly.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_id = sanitize_agent_id(agent_id)
    if not safe_id or safe_id not in members:
        return JSONResponse(status_code=404, content={"error": "member not found"})

    published_at = datetime.now(UTC).isoformat()
    members[safe_id][HOST39_PUBLISHED_AT] = published_at

    # Persist into the member's config jsonb so the record survives a restart —
    # an in-memory-only flag would silently revert the catalog to omitting this
    # member on the next boot, which is the failure mode this endpoint exists to
    # remove.
    rows = await pg_request("GET", "agents", params={"agent_id": f"eq.{safe_id}", "select": "config"})
    config = ((rows or [{}])[0] or {}).get("config") or {}
    config[HOST39_PUBLISHED_AT] = published_at
    if req.card_url.strip():
        config["host39_card_url"] = req.card_url.strip()
    stored = await pg_request("PATCH", "agents", params={"agent_id": f"eq.{safe_id}"}, body={"config": config})
    if stored is None:
        print(
            f"[host39][ERROR] recorded publication for {safe_id} in memory but the DB write "
            f"FAILED — the catalog will drop this member again on the next restart."
        )
        return JSONResponse(
            status_code=502,
            content={"error": "publication recorded in memory only; database write failed"},
        )
    return JSONResponse(content={"agent_id": safe_id, "published_at": published_at})


@app.post("/admin/api/members/{agent_id}/role")
async def admin_set_role(agent_id: str, req: _AdminRoleChangeRequest, request: Request) -> JSONResponse:
    """Change a member's chapter_role via direct Postgres write.

    Last-admin protection (E2): refuses to demote the only `chapter_role='admin'`
    member via the signed path. Bearer path can override with `?force=true`
    (because bearer IS the break-glass credential for exactly this scenario —
    if you lock yourself out via signed demotion, the bearer is your way back in).

    Audit (E1): every role change writes to chapter_audit_events with
    actor identity, target, and before/after roles. Hash-chained per
    chapter_audit's existing primitive.
    """
    ok, identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_id = sanitize_agent_id(agent_id)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})
    role = (req.role or "").strip().lower()
    if role not in {"member", "advisor", "mentor", "leader", "admin"}:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid role", "allowed": ["member", "advisor", "mentor", "leader", "admin"]},
        )

    # ── E2: last-admin protection ────────────────────────────────────
    # Look up the current role. If demoting away from 'admin' AND this
    # would be the last admin, refuse — unless bearer force=true.
    current_rows = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe_id}", "select": "chapter_role"},
    )
    current_role = (current_rows[0].get("chapter_role") if current_rows else None) or "member"
    force = request.query_params.get("force", "").lower() in ("1", "true", "yes")

    if current_role == "admin" and role != "admin":
        # Count remaining admins
        admin_rows = await pg_request(
            "GET",
            "agents",
            params={"chapter_role": "eq.admin", "select": "agent_id"},
        )
        remaining = [r for r in (admin_rows or []) if r.get("agent_id") != safe_id]
        if not remaining:
            # Would leave the server with no admin.
            if identity.get("path") != "bearer" or not force:
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": "would leave no admin",
                        "hint": (
                            "Demoting the last admin would lock the signed-admin path. "
                            "If you have intentional access to the bearer token, retry "
                            "with ?force=true (bearer-only)."
                        ),
                        "current_role": current_role,
                        "requested_role": role,
                    },
                )

    # ── Perform the update ──────────────────────────────────────────
    result = await pg_request(
        "PATCH",
        "agents",
        params={"agent_id": f"eq.{safe_id}"},
        body={"chapter_role": role},
    )
    if result is None:
        return JSONResponse(status_code=503, content={"error": "persistence unavailable"})

    # Keep the in-memory roster consistent with the DB write — reads like
    # GET /admin/api/members and in-process role checks serve from `members`,
    # so a DB-only write would show the stale role until the next restart.
    if safe_id in members:
        members[safe_id]["chapter_role"] = role

    # ── E1: audit log write + W3C ComplianceCredential (fire-and-forget) ──
    try:
        import chapter_audit
        import compliance as _compliance_mod

        # Mint a ComplianceCredential for this access-control change.
        # Maps to NIST 800-171 §3.1.5 (least-privilege enforcement) and
        # CCPA §1798.135 (right to know who can access subject data).
        # The VC embeds in the audit detail; auditors can verify the
        # signature without re-querying the source database.
        compliance_vc = _compliance_mod.emit_compliance_attestation(
            subject_did=safe_id,
            rule_id="nist-800-171:3.1.5",
            status="compliant",
            confidence=1.0,
            evaluation_state={
                "control": "AC-3 / 3.1.5",
                "decision": "access-rights changed",
                "from_role": current_role,
                "to_role": role,
                "auth_path": identity.get("path"),
            },
            agency="NIST",
            cfr_reference="NIST SP 800-171",
        )

        await chapter_audit.record(
            chapter_id=AGENT_ID,
            action="admin.role.change",
            actor_agent_id=identity.get("agent_id") or "bearer",
            target_type="agent",
            target_id=safe_id,
            outcome="ok",
            detail={
                "role_before": current_role,
                "role_after": role,
                "auth_path": identity.get("path"),
                "force_override": force,
                "compliance_credential": compliance_vc if compliance_vc else None,
            },
        )
    except Exception:  # noqa: BLE001 — audit MUST never break business logic
        pass

    return JSONResponse(content={"agent_id": safe_id, "chapter_role": role})


@app.post("/admin/api/keys/revoke/{agent_id}")
async def admin_revoke_key(agent_id: str, request: Request, body: dict | None = None) -> JSONResponse:
    """E3: Revoke an agent's Ed25519 pubkey, optionally naming its successor.

    Clears the agent's pubkey in memory AND durably (``agent_facts.provider.did``
    — see the write below for what that used to do instead). The agent must
    re-register via TOFU on its next signed request to come back.

    Use cases:
      - Sovereign admin lost their key (break-glass scenario): revoke the
        old key, the agent re-registers with a fresh keypair.
      - Compromised key suspected: immediate revocation.
      - Decommissioning an agent: revoke first, then optionally
        DELETE /admin/api/members/{id}.

    The chapter_role + member row STAY. Only the cryptographic identity
    is invalidated. To remove the member entirely, DELETE the member.

    ── ``{"successor_public_key": "<base64 Ed25519>"}`` ──────────────────────
    Revoke AND pre-authorise in one act, which closes the window the plain
    revoke opens. Without it the member's identity is unclaimed until somebody
    takes it, and the first-claim pin pins the FIRST claim — so after a revocation the
    legitimate member is racing anyone else who is watching. Naming the
    successor means there is nothing to race for: the key is already on file, so
    the guard refuses every other claimant from the first moment.

    ⚠️ WHY THIS IS NOT AN ESCALATION, MEASURED RATHER THAN ASSUMED. It lets an
    operator INSTALL a key, and an operator who holds that key can sign AS the
    member — which is impersonation, not the denial a plain revoke gives. That
    would be a new power if the operator did not already have it. They do, by
    three paths, each measured end to end across a restart:

      A. revoke, then claim the vacancy with ``X-Agent-DID-Key`` (TOFU)
      B. revoke, then claim it with an open ``POST /api/members`` (the first-claim pin's pin)
      C. ``DELETE /admin/api/members/{id}``, then register the id afresh

    All three need only the admin token plus the open registration path — no
    database credential — and all three end with the operator's key in the auth
    store after a reboot. This endpoint adds no capability; it makes the same act
    ATOMIC, LABELLED and AUDITED instead of a race an operator wins by being
    first. A capability that exists only as a three-step sequence is not more
    restricted than one with a name, it is only harder to review.

    ⚠️ AND WHAT IT CANNOT DO, because it was proposed as a safeguard: the server
    CANNOT verify that the successor key originated with the member. Any
    proof-of-possession the member could supply, an operator can equally produce
    for a keypair they generated themselves — a signature proves someone holds
    the private key, never which someone. "The operator only relays the member's
    key" is a procedural control, not a mechanical one, and the provenance value
    is written so it can be reviewed as such rather than trusted as verified.
    """
    ok, identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_id = sanitize_agent_id(agent_id)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    successor = str((body or {}).get("successor_public_key") or "").strip()
    successor_did = sovereign_identity.try_build_did_key_from_ed25519(successor) if successor else None
    if successor and not successor_did:
        # A refusal to the OPERATOR, which the recovery-path rule does not
        # forbid — they retry with a well-formed key and nothing about the
        # member changed. Refusing here is what keeps a typo from installing a
        # key nobody holds, which WOULD strand the member.
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid successor_public_key",
                "detail": "must be a base64 Ed25519 public key (44 chars, '='-padded)",
            },
        )

    # Clear from in-memory auth keys
    if hasattr(auth_verify, "_agent_keys"):
        auth_verify._agent_keys.pop(safe_id, None)
        # Also clear from the member's in-memory record so nothing stale
        # is exposed via /api/agents/{id}/profile.
        if safe_id in members:
            m = members[safe_id]
            for stale in ("public_key", "signing_secret", "ed25519_pubkey"):
                m.pop(stale, None)

    # Clear from the Postgres row — and this used to clear NOTHING.
    #
    # It nulled `ed25519_pubkey`, `public_key` and `signing_secret`, three
    # columns that do not exist on `agents` (check `infra/init.sql`). The UPDATE
    # failed and `pg_request` swallowed it, so the endpoint returned success
    # while the durable key sat untouched in `agent_facts.provider.did` — where
    # the loader and `reload_member_keys` both read it. The next redeploy handed
    # the member back the key an operator had just revoked, and the docstring's
    # first use case is "compromised key suspected".
    #
    # A revocation that the next restart undoes is worse than none, because the
    # operator was told it worked. `key_provenance.source` records it so the
    # rotation-chain walk stops here too (would otherwise re-derive the key
    # from history that a revoke cannot delete), and so a later unauthenticated
    # claim cannot quietly pin a replacement.
    rows = await pg_request(
        "GET", "agents", params={"agent_id": f"eq.{safe_id}", "select": "agent_facts", "limit": "1"}
    )
    facts = (rows[0].get("agent_facts") if rows else None) or {}
    facts = dict(facts) if isinstance(facts, dict) else {}
    provider = dict(facts.get("provider") or {})
    provider.pop("did", None)
    facts["provider"] = provider
    facts[KEY_PROVENANCE] = _key_provenance(KEY_SOURCE_REVOKED)
    if successor_did:
        # The successor goes in the SAME write as the revocation. Two writes
        # would leave a window between them in which the member is unclaimed —
        # the very window this exists to close, reintroduced by the
        # implementation of the thing that closes it.
        provider["did"] = successor_did
        facts["provider"] = provider
        facts[KEY_PROVENANCE] = {
            **_key_provenance(KEY_SOURCE_OPERATOR_VOUCHED),
            # WHO vouched, so the assertion can be reviewed rather than merely
            # trusted. `attested` stays false: an operator's word is not the
            # superseded key's signature, and only a rotation is that.
            "vouched_by": identity.get("agent_id") or identity.get("path") or "operator",
        }
    cleared = await pg_request("PATCH", "agents", params={"agent_id": f"eq.{safe_id}"}, body={"agent_facts": facts})
    if not cleared:
        # Loud, and reported to the caller below: an in-memory-only revocation
        # lasts until the next restart, which is exactly the failure this fixes.
        print(f"⚠️  key revocation for {safe_id!r} did NOT persist — it will NOT survive a restart")
    elif successor_did:
        # In-memory too, so the guard protects the successor from THIS request
        # onward rather than from the next boot. The durable row is what makes
        # it survive; this is what makes it immediate.
        members.setdefault(safe_id, {})["public_key"] = successor
        auth_verify.replace_agent_key(safe_id, successor)
        print(f"🔑 pre-authorised successor key for {safe_id!r} [vouched_by={identity.get('agent_id') or 'operator'}]")

    # Audit (E1) + ComplianceCredential — key revocation is a NIST
    # 800-171 §3.5.2 (authenticator management) event AND CCPA §1798.105
    # right-to-delete adjacent (revoked key = subject can no longer be
    # impersonated).
    try:
        import chapter_audit
        import compliance as _compliance_mod

        compliance_vc = _compliance_mod.emit_compliance_attestation(
            subject_did=safe_id,
            rule_id="nist-800-171:3.5.2",
            status="compliant",
            confidence=1.0,
            evaluation_state={
                "control": "IA-5 / 3.5.2",
                "decision": "credential revoked",
                "auth_path": identity.get("path"),
                "tofu_remediation": "available",
            },
            agency="NIST",
            cfr_reference="NIST SP 800-171",
        )

        await chapter_audit.record(
            chapter_id=AGENT_ID,
            action="admin.key.revoke",
            actor_agent_id=identity.get("agent_id") or "bearer",
            target_type="agent",
            target_id=safe_id,
            outcome="ok",
            detail={
                "auth_path": identity.get("path"),
                "compliance_credential": compliance_vc if compliance_vc else None,
                "successor_preauthorized": bool(successor_did),
            },
        )
        if successor_did:
            # BOTH HALVES, as two rows. To the operator this was one call; to
            # anyone reading the ledger afterwards it is two different facts —
            # a key stopped being valid, and a specific other key was installed
            # by a named party. Folding the second into the first would make
            # "who installed this key" answerable only by inference.
            await chapter_audit.record(
                chapter_id=AGENT_ID,
                action="admin.key.preauthorize",
                actor_agent_id=identity.get("agent_id") or "bearer",
                target_type="agent",
                target_id=safe_id,
                outcome="ok",
                detail={
                    "auth_path": identity.get("path"),
                    "successor_did": successor_did[:200],
                    "attested": False,
                    "note": "operator-vouched: the server cannot verify this key originated with the member",
                },
            )
    except Exception:  # noqa: BLE001
        pass

    return JSONResponse(
        content={
            "agent_id": safe_id,
            "revoked": True,
            # Reported rather than assumed. The in-memory clear always happens;
            # whether it OUTLIVES the process is the part an operator acting on a
            # suspected compromise needs to know, and the old response asserted
            # success for a write that never landed.
            "durable": bool(cleared),
            "successor_preauthorized": bool(successor_did and cleared),
            "hint": (
                "Successor key is on file; only that key can now claim this member"
                if successor_did and cleared
                else "Member must re-register via TOFU on next signed request to restore identity"
            ),
        }
    )


@app.delete("/admin/api/members/{agent_id}")
async def admin_remove_member(agent_id: str, request: Request) -> JSONResponse:
    """Hard-remove a member from this chapter's in-memory registry +
    Postgres row + auth keys. Federation peers will NOT be notified —
    they retain their own view of the member until their next sync.

    Last-admin protection (E2): refuses to remove the only admin via
    the signed path. Bearer can force with `?force=true`.
    """
    ok, identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_id = sanitize_agent_id(agent_id)
    if not safe_id:
        return JSONResponse(status_code=400, content={"error": "invalid agent_id"})

    # ── E2: last-admin protection on removal too ────────────────────
    current_rows = await pg_request(
        "GET",
        "agents",
        params={"agent_id": f"eq.{safe_id}", "select": "chapter_role"},
    )
    current_role = (current_rows[0].get("chapter_role") if current_rows else None) or "member"
    force = request.query_params.get("force", "").lower() in ("1", "true", "yes")

    if current_role == "admin":
        admin_rows = await pg_request(
            "GET",
            "agents",
            params={"chapter_role": "eq.admin", "select": "agent_id"},
        )
        remaining = [r for r in (admin_rows or []) if r.get("agent_id") != safe_id]
        if not remaining and (identity.get("path") != "bearer" or not force):
            return JSONResponse(
                status_code=409,
                content={
                    "error": "would leave no admin",
                    "hint": "Removing the last admin via signed path is refused. Retry with ?force=true (bearer-only) if intentional.",
                },
            )

    members.pop(safe_id, None)
    if hasattr(auth_verify, "_agent_keys"):
        auth_verify._agent_keys.pop(safe_id, None)
    await pg_request(
        "DELETE",
        "agents",
        params={"agent_id": f"eq.{safe_id}"},
    )

    # Emit member.left (leader_remove) so subscribers see the departure.
    asyncio.create_task(event_bus.safe_publish("member.left", {"agent_id": safe_id, "reason": "leader_remove"}))

    # Audit (E1)
    try:
        import chapter_audit

        await chapter_audit.record(
            chapter_id=AGENT_ID,
            action="admin.member.remove",
            actor_agent_id=identity.get("agent_id") or "bearer",
            target_type="agent",
            target_id=safe_id,
            outcome="ok",
            detail={"role_before": current_role, "auth_path": identity.get("path"), "force_override": force},
        )
    except Exception:  # noqa: BLE001
        pass

    return JSONResponse(content={"removed": safe_id})


@app.get("/api/dsar/export")
async def dsar_export(subject_did: str, request: Request) -> JSONResponse:
    """Data Subject Access Request — export every record the chapter
    holds about the given data subject.

    CCPA/CPRA right-to-know: a consumer can request access to all
    personal information a business has about them. The chapter's
    response is bounded but complete to the catalogued inventory in
    chapter/dsar.py.

    Admin-gated — random callers cannot dump arbitrary subjects'
    data. Subjects requesting their OWN data should go through a
    chapter-operator-mediated process per the operator's privacy
    policy.
    """
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_did = (subject_did or "").strip()
    if not safe_did.startswith("did:key:"):
        return JSONResponse(
            status_code=400,
            content={"error": "subject_did must start with did:key:"},
        )

    import dsar

    archive = await dsar.export_subject_data(pg_request, safe_did)
    return JSONResponse(content=archive)


@app.post("/api/dsar/delete")
async def dsar_delete(subject_did: str, request: Request, confirm: bool = False) -> JSONResponse:
    """Data Subject Deletion Request — cascading deletion across every
    catalogued table.

    CCPA/CPRA right-to-delete: irreversible. Requires explicit
    ``confirm=true`` query param to prevent misclick. Admin-gated.

    Operator is responsible for emitting an authority_revoked receipt
    after the deletion completes if the subject had previously been
    granted authority — the deletion itself is an evidenced event
    per the chapter's audit ledger discipline.
    """
    ok, identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    safe_did = (subject_did or "").strip()
    if not safe_did.startswith("did:key:"):
        return JSONResponse(
            status_code=400,
            content={"error": "subject_did must start with did:key:"},
        )
    if not confirm:
        return JSONResponse(
            status_code=400,
            content={
                "error": "confirm=true required",
                "hint": "DSAR deletion is irreversible. Pass ?confirm=true to proceed.",
            },
        )

    import dsar

    result = await dsar.delete_subject_data(pg_request, safe_did)

    # Audit + ComplianceCredential — DSAR delete is THE canonical
    # CCPA §1798.105 (right-to-delete) regulatory event. Embeds a W3C
    # ComplianceCredential alongside the audit row so auditors can
    # verify the deletion was performed under explicit authority
    # without re-querying the DB.
    try:
        import chapter_audit
        import compliance as _compliance_mod

        compliance_vc = _compliance_mod.emit_compliance_attestation(
            subject_did=safe_did,
            rule_id="ccpa:1798.105",
            status="compliant",
            confidence=1.0,
            evaluation_state={
                "regulation": "CCPA right-to-delete",
                "decision": "subject data erased",
                "auth_path": identity.get("path"),
                "tables_swept": len(result["tables"]),
                "rows_deleted": result["total_deleted"],
            },
            agency="CA-AG",
            cfr_reference="Cal Civ Code §1798.105",
        )

        await chapter_audit.record(
            chapter_id=AGENT_ID,
            action="admin.dsar.delete",
            actor_agent_id=identity.get("agent_id") or "bearer",
            target_type="data_subject",
            target_id=safe_did,
            outcome="ok",
            detail={
                "auth_path": identity.get("path"),
                "total_deleted": result["total_deleted"],
                "per_table_summary": {
                    t: {"deleted": v["deleted"], "errored": bool(v["error"])} for t, v in result["tables"].items()
                },
                "compliance_credential": compliance_vc if compliance_vc else None,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return JSONResponse(content=result)


@app.get("/api/dsar/inventory")
async def dsar_inventory_endpoint(request: Request) -> JSONResponse:
    """Public-ish catalog of which tables/fields are scoped to data
    subjects. Useful for the operator to draft a Privacy Policy that
    matches reality. Admin-gated because the inventory is operationally
    sensitive (reveals chapter's data shape)."""
    ok, _identity, denied = await _authorize_admin(request)
    if not ok:
        return _deny_fallback(denied)
    import dsar

    return JSONResponse(content={"inventory": dsar.inventory()})


@app.get("/admin", include_in_schema=False)
@app.get("/admin/", include_in_schema=False)
@app.get("/admin/index.html", include_in_schema=False)
async def admin_ui_index():
    """Serve the static admin UI. No auth — the UI itself prompts for
    the X-Admin-Token, stores it in localStorage, attaches it to every
    /admin/api/* call from the page."""
    import os as _os

    from fastapi.responses import FileResponse

    here = _os.path.dirname(_os.path.abspath(__file__))
    index_path = _os.path.join(here, "static", "admin", "index.html")
    if not _os.path.exists(index_path):
        return JSONResponse(
            status_code=503,
            content={"error": "admin UI not bundled with this chapter build"},
        )
    import csp as _csp

    return FileResponse(index_path, media_type="text/html", headers=_csp.document_headers(index_path))


# ---------------------------------------------------------------------------
# /metrics — Prometheus exposition. Auth-gated by METRICS_BEARER_TOKEN env;
# if the env var is unset, the endpoint is open (dev/test convenience). In
# production set the token so external scrapers must authenticate.
# ---------------------------------------------------------------------------


@app.get("/metrics")
async def metrics_endpoint(request: Request):
    """Prometheus text exposition.

    Auth model:
      - If env ``METRICS_BEARER_TOKEN`` is set, callers MUST supply
        ``Authorization: Bearer <token>``. Wrong/missing token → 401.
      - If unset, the endpoint is open (matches /health behavior — useful
        for local dev and same-host scrapes).

    Counters never reset within a process lifetime. Gauges (members,
    federation peer state) are refreshed on every /health hit; if a
    chapter goes long enough without /health traffic the gauges may be
    stale, but Railway's healthchecks make this hypothetical.
    """
    import os as _os

    from fastapi.responses import PlainTextResponse

    expected = _os.environ.get("METRICS_BEARER_TOKEN", "").strip()
    if expected:
        auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        presented = auth[7:].strip() if auth.startswith("Bearer ") else ""
        # compare_digest, as admin.verify_admin_token and auth_verify already use
        # for the same job. Encoded to bytes because the str path raises
        # TypeError on non-ASCII input, and a bad token must return 401 rather
        # than raise. The scheme prefix is checked separately: it is not secret,
        # so it does not need a constant-time comparison.
        if not presented or not compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
            return PlainTextResponse(
                status_code=401,
                content="metrics: bearer token required\n",
            )

    body = metrics.render(chapter_id=AGENT_ID)
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


# ── Mounted route adapters (extracted from this module — see routes/) ──
# Run as `python chapter_agent.py`, this module is "__main__" — but the route
# adapters' `ca` proxy resolves chapter_agent from sys.modules["chapter_agent"].
# Alias self under that name so the proxy works under BOTH __main__ and import
# (pytest imports it as "chapter_agent", so this gap only surfaced at runtime).
import sys as _sys  # noqa: E402

_sys.modules.setdefault("chapter_agent", _sys.modules[__name__])

from routes import identity  # noqa: E402  (mounted after globals + app exist)

app.include_router(identity.router)
from routes import skills  # noqa: E402

app.include_router(skills.router)
from routes import crm  # noqa: E402

app.include_router(crm.router)
from routes import external_send as external_send_routes  # noqa: E402

app.include_router(external_send_routes.router)


if __name__ == "__main__":
    print(f"Starting {AGENT_NAME} ({AGENT_ID}) on port {PORT}")
    # trust forwarded headers only from the edge (FORWARDED_ALLOW_IPS) so
    # uvicorn resolves request.client to the real peer behind the proxy. The per-IP
    # rate limiter keys on client_ip_for_rate_limit(), which reads the real client
    # from X-Forwarded-For per TRUSTED_PROXY_HOPS — so one attacker can't 429 everyone
    # by sharing the proxy's IP bucket.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        proxy_headers=True,
        forwarded_allow_ips=FORWARDED_ALLOW_IPS,
    )
