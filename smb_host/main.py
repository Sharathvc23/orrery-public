"""SMB Host — a multi-tenant, no-infra runtime host for sovereign SMB agents.

Milestone B2b-1. The SMB demo hinges on a service a non-technical small business
can hit ONCE to get a live agent — no keys to manage, no server to run, no DNS.
This is that service. A single ``POST /provision`` mints an isolated sovereign
identity for the business and serves the resulting A2A agent card at a stable
per-tenant URL. It returns exactly what a downstream operator (host39) needs to
register the agent on the NANDA Index itself — ``{tenant_id, endpoint, did,
recovery_phrase}``. This host does NOT register anyone on any index: there is one
NANDA Index (api.nandaindex.org) and registering the agent there is host39's job,
out of scope for this runtime. This host's only roles are minting an isolated
identity and serving the agent (card + booking receipts).

Isolation is the whole game: the host runs many businesses in one process, so
each tenant is an :class:`~community_member.tenant.AgentContext` (B2a) pinned to
its own on-disk home under ``SMB_HOST_DATA_DIR``. Distinct home → distinct
keystore vault → distinct did:key → distinct card. A restart rehydrates every
tenant from disk (the identity lives in the tenant's vault; only the one-time
recovery phrase is never persisted).

Pre-warm pool (B4): a live on-stage ``POST /provision`` must feel instant, but a
cold provision does CPU (mint an Ed25519 identity) on the request path. So a
background warmer keeps ``SMB_HOST_POOL_SIZE`` ready tenants hot — each fully
minted before any request arrives. ``POST /provision`` then CLAIMS one and
returns it instantly (only a fast local business_name label update), falling back
to the cold path when the pool is drained (correctness over latency).
``SMB_HOST_POOL_SIZE=0`` ⇒ pure cold-provision (the original behavior). The
warmer is bound to the app lifespan, so it runs under uvicorn but stays dormant
for a bare ``TestClient(app)``.

CONSENT GUARDRAIL (hard rule): this service performs NO consent-gated action.
The consent-ledger singleton is process-global and therefore unsafe on a
concurrent multi-tenant path — so it is never activated here.
``AgentContext.activate_consent`` is intentionally never called. Provisioning
and card serving are the only things this host does.

Reuses, never reinvents:
* identity / isolation  → ``community_member.tenant.AgentContext``      (B2a)
* agent card shape      → ``community_member.a2a_card.build_agent_card``
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import shutil
import tempfile
import threading
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import community_member
from community_member import recovery
from community_member.a2a_card import build_agent_card
from community_member.builtin_skills.booking.skill import BookingStoreUnreadable
from community_member.sm_bridge_adapter import build_self_agentfacts
from community_member.tenant import AgentContext
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── configuration (env-resolved at app build; overridable per deployment) ────────

_PUBLIC_URL_ENV = "HOST_PUBLIC_URL"
_DATA_DIR_ENV = "SMB_HOST_DATA_DIR"
# The funnel (smb_funnel/) is a static browser app served from a different origin
# than this host, so provision/book/card must be reachable cross-origin. The API
# is a public, no-credential provisioning surface (a barber's onboarding funnel),
# so allowing any origin is correct — there is no cookie/auth to protect, and
# receipts are self-certifying (verified client-side against the issuer did:key).
# Override with a comma-separated allowlist for a locked-down deployment.
_CORS_ORIGINS_ENV = "SMB_HOST_CORS_ORIGINS"

# Shared secret gating POST /provision. Provisioning mints an Ed25519 identity
# and writes a tenant home to disk, so an open one lets anybody who finds the
# host mint identities in someone else's business name.
#
# NO "OPEN WHEN UNSET" DEFAULT, and the reason is the same one that removed the
# HOST_PUBLIC_URL default: a default that is correct in one deployment shape and
# wrong in another is not a default, it is a trap that fires in whichever shape
# the operator did not test. So the unset case is decided by the address the
# operator has already stated:
#
#   set                       -> Authorization: Bearer <token> required, 401 otherwise
#   unset + loopback URL      -> open (the development and CI shape, unchanged)
#   unset + any other URL     -> provisioning refused with 503 naming this variable
#
# An operator who has stated a public address and configured no token has
# described a host that mints identities for strangers; the third branch refuses
# to be that host rather than becoming it silently.
_PROVISION_TOKEN_ENV = "SMB_HOST_PROVISION_TOKEN"

# Total tenant cap. UNCONDITIONALLY required — unlike HOST_PUBLIC_URL/the token,
# there is no loopback carve-out, because the thing this bounds (identities
# minted and vaults written, with no delete route anywhere in this host) is a
# resource-exhaustion concern regardless of who can reach the port. Measured on
# the deployed host before this existed: tenant count went 23 -> 68 with nothing
# recording who provisioned the other 45, because the token was the only bound
# and a token bounds WHO may call, never HOW MUCH. Mirrors smb_signup's own
# SMB_SIGNUP_TENANT_CAP, which already refuses unconfigured rather than serving
# an unbounded front door — this closes the same gap one layer down, on the
# host a caller holding the token can reach directly.
_TENANT_CAP_ENV = "SMB_HOST_TENANT_CAP"

# How many trusted proxy hops sit in front of this host, for attributing a
# provision to a caller. Mirrors smb_signup's SMB_SIGNUP_TRUSTED_PROXIES: an
# unset default of 0 trusts nothing and records the raw socket peer, because
# X-Forwarded-For is client-supplied unless something in front of this host
# rewrites it — trusting it by default would let one caller attribute every
# provision to a forged address of its choosing.
_TRUSTED_PROXIES_ENV = "SMB_HOST_TRUSTED_PROXIES"

# What a provision is recorded as when no usable caller signal exists. Never a
# default like "0.0.0.0" or "unknown" that could be mistaken for a real,
# resolved value — this string is deliberately not a valid IP or address, so it
# cannot be confused with an attribution that succeeded.
_UNATTRIBUTABLE = "unattributable"

# ── H14: bounds on the unauthenticated booking path ──────────────────────────
# POST /t/{tenant_id}/book takes no credential and does persistent work. Three
# separate bounds, because they fail differently and only one of them is a cap:
#
#   _MAX_BOOKING_FIELD / _MAX_BOOKING_NOTES  bound what can be STORED, per
#       request, unconditionally. These are the load-bearing ones.
#   _MAX_BODY_BYTES                          bounds what is READ into memory
#       before parsing. Evadable by a chunked sender with no Content-Length,
#       which is why it is not the storage bound.
#   SMB_HOST_BOOK_RATE_PER_HOUR              slows one source down. It is NOT a
#       cap: the window is in-process, a restart empties it, and a distributed
#       source never fills it. Saying which control is load-bearing matters —
#       smb_signup's limiter carries the same warning for the same reason.
_MAX_BOOKING_FIELD = 500
_MAX_BOOKING_NOTES = 4000
_MAX_BODY_BYTES_ENV = "SMB_HOST_MAX_BODY_BYTES"
_DEFAULT_MAX_BODY_BYTES = 64 * 1024
_BOOK_RATE_ENV = "SMB_HOST_BOOK_RATE_PER_HOUR"
_DEFAULT_BOOK_RATE_PER_HOUR = 120

# B4 pre-warm pool: how many ready tenants to keep hot. 0 ⇒ pure cold-provision
# (today's behavior), so the feature is opt-out and fully backward compatible.
_POOL_SIZE_ENV = "SMB_HOST_POOL_SIZE"
_DEFAULT_POOL_SIZE = 3
# The warmer's idle backstop poll — it normally reacts immediately to a claim
# (via a wake event); this only bounds retry latency after an Index outage.
_POOL_POLL_INTERVAL_S = 2.0
# Placeholder display name carried by an un-claimed pool tenant. Replaced with
# the caller's business_name the instant it is claimed.
_POOL_PLACEHOLDER_NAME = "(unclaimed)"
# Prefix of every tenant_id the warmer mints. Shared by the minter and the
# reclaim predicate below so the two cannot drift: a predicate that decides
# whether a home may be re-keyed must recognise exactly the ids the warmer
# produces, and nothing else.
_POOL_ID_PREFIX = "smb-pool-"

# NO DEFAULT PUBLIC URL, deliberately.
#
# This used to be "http://localhost:8080", which tracked neither the bind host
# nor the port: running on any other port returned an `endpoint` in the provision
# response that refused connection, while the real address served the card
# normally. That field is the one thing a business hands onward — to a card host,
# to a customer, to an index — and a wrong value is indistinguishable from a
# right one at the moment it is issued. The business finds out when someone
# cannot reach them.
#
# So the host provisions only when an operator has SAID where it is publicly
# reachable. Booting without it is allowed — health, and the card and booking
# routes for tenants already on disk, do not depend on knowing the public
# address — but minting a NEW tenant does, because that is when the address is
# baked into a card and returned to a caller.
_PUBLIC_URL_UNSET = ""


# A container-shaped path that does not exist on a normal machine, and this is
# resolved at import: `create_app()` called `mkdir` on it, so importing the
# module as any ordinary user died with
# `PermissionError: [Errno 13] Permission denied: '/data'` before any route
# existed. The default is now a user-writable location; the image sets
# SMB_HOST_DATA_DIR to its own volume path explicitly, which is where a fixed
# absolute path belongs.
def _default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "orrery-smb-host" / "tenants"


logger = logging.getLogger("smb_host")

# The per-tenant marker file. A tenant is "provisioned" iff its home holds this
# file — written LAST, only after the identity is fully minted, so a failed
# provision never leaves a half-built orphan and rehydration only ever picks up
# fully-minted tenants.
_META_FILE = "smb_tenant.json"


# ── provisioning authority ───────────────────────────────────────────────────────


def _provision_token() -> str:
    """The configured provisioning secret, or "" when the operator set none."""
    return os.environ.get(_PROVISION_TOKEN_ENV, "").strip()


def _is_loopback(public_url: str) -> bool:
    """True when ``public_url``'s host is this machine and nothing else.

    Decided from the parsed host, not a substring: "http://127.0.0.1.evil.test/"
    contains "127.0.0.1" and is not loopback. ``urlparse`` unwraps IPv6 brackets
    and lowercases, so "http://[::1]:8080" resolves to "::1". Any host that is
    not a literal loopback address and not "localhost" is treated as public —
    the safe direction, since the consequence of being wrong here is refusing to
    provision rather than provisioning for strangers.
    """
    host = (urlparse(public_url).hostname or "").strip()
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _provision_config_error(public_url: str, token: str, tenant_cap: int | None) -> str | None:
    """Why provisioning is refused under this configuration, or None if allowed.

    Called by BOTH ``POST /provision`` and the pool warmer's lifespan so the two
    cannot diverge. The warmer mints tenants BEFORE any request arrives and
    writes them to disk, where a later rehydrate picks them up as fully
    provisioned — so gating the route alone would still leave an ungated host
    producing identities.
    """
    if not public_url:
        # Refuse rather than guess. The response's `endpoint` is the address the
        # business hands onward, and an address nobody stated is a guess that
        # looks exactly like a fact.
        return (
            f"{_PUBLIC_URL_ENV} is not set, so this host does not know the address to put in "
            f"the agent's card. Set it to the URL this host is reachable at "
            f"(for example {_PUBLIC_URL_ENV}=https://smb.example.com, or "
            f"{_PUBLIC_URL_ENV}=http://127.0.0.1:8080 when running locally) and restart."
        )
    if not token and not _is_loopback(public_url):
        return (
            f"{_PROVISION_TOKEN_ENV} is not set and {_PUBLIC_URL_ENV} is {public_url!r}, which is not "
            f"a loopback address. Provisioning mints an identity and writes a tenant home, so an "
            f"un-gated host reachable off this machine mints identities for anyone who finds it. "
            f"Set {_PROVISION_TOKEN_ENV} to a shared secret and send it as "
            f"'Authorization: Bearer <token>', or bind this host to loopback, and restart."
        )
    if tenant_cap is None:
        # Unconditional — no loopback carve-out. The token bounds WHO may call;
        # this bounds HOW MANY identities exist. Both are needed, and a host
        # that mints without limit is the failure this variable exists to
        # remove regardless of who can reach it.
        return (
            f"{_TENANT_CAP_ENV} is not set to a positive integer. Provisioning mints an Ed25519 "
            f"identity and writes a tenant vault to disk, and this host has no delete route — "
            f"an unbounded cap means unlimited identities accumulating with no way to remove them. "
            f"Set {_TENANT_CAP_ENV} to the maximum number of tenants this host should ever hold "
            f"and restart."
        )
    return None


def _positive_int(name: str) -> int | None:
    """A configured positive integer, or None when unset, empty or unusable.

    None is never treated as "unlimited" by any caller here — a typo in a bound
    must not silently disable it.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _resolve_tenant_cap() -> int | None:
    """The configured total tenant cap, or None when unconfigured."""
    return _positive_int(_TENANT_CAP_ENV)


def _resolve_trusted_proxies() -> int:
    """How many proxy hops in front of this host to trust for attribution.

    Unlike the bounds above, 0 IS the meaningful default (trust nothing), not
    an error — there is nothing to refuse provisioning over here.
    """
    raw = os.environ.get(_TRUSTED_PROXIES_ENV, "").strip()
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _capacity_status(state: HostState) -> tuple[int, int | None]:
    """(used, cap). ``used`` counts every tenant this host holds — claimed or a
    not-yet-claimed pool slot — the same count ``/health`` reports as
    ``tenants``, so the cap and the observable headroom agree on what "used"
    means. ``cap`` is None only when unconfigured, in which case
    ``_provision_config_error`` has already refused all provisioning.
    """
    cap = _resolve_tenant_cap()
    with state.lock:
        used = len(state.tenants)
    return used, cap


def _at_capacity(state: HostState) -> bool:
    used, cap = _capacity_status(state)
    return cap is not None and used >= cap


def _caller_discriminator(request: Request, trusted_proxies: int) -> str:
    """Best-effort "who called this", for ATTRIBUTION rather than authorization.

    Mirrors smb_signup's own ``client_source``: ``X-Forwarded-For`` is
    client-supplied unless something in front of this host rewrites it, so it is
    trusted only for the configured number of hops. The default trusts nothing
    and records the raw socket peer — which, behind an unconfigured proxy, is
    that proxy's own address. That is a real, honest limit on what this records,
    not a bug: it is why the field is attribution, not identity, and why an
    operator who wants the real source must say how many hops it is behind.

    Returns "" when nothing usable is available. This function never invents a
    default — the caller decides what "nothing usable" becomes on the record.
    """
    if trusted_proxies > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(chain) >= trusted_proxies:
            return chain[-trusted_proxies]
    return request.client.host if request.client else ""


class _BookRateLimiter:
    """A per-source sliding hour window over the unauthenticated booking path.

    ⚠️ **THIS IS NOT THE CAP, AND CALLING IT ONE WOULD BE THE MISTAKE.** The
    window lives in this process: a restart empties it, and a source distributed
    across addresses never fills it. What actually bounds damage is the per-field
    length cap, which applies to every accepted request regardless of rate. This
    limiter only slows a single source down. ``smb_signup.RateLimiter`` carries
    the same warning for the same reason, and the two are deliberately worded
    alike so an operator reading either one draws the same conclusion.

    Keyed on :func:`_caller_discriminator` — the SAME attribution this host
    already records for provisioning — so the limiter and the audit trail cannot
    disagree about who a caller was. With ``SMB_HOST_TRUSTED_PROXIES`` unset that
    resolves to the socket peer, which behind a proxy is the proxy: every request
    then shares one bucket and the limit becomes global. That is more restrictive
    rather than less, which is the direction an unconfigured deployment should
    err in, and it is why the hop count is worth setting.
    """

    def __init__(self, per_hour: int) -> None:
        self.per_hour = per_hour
        self._seen: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, source: str, now: float | None = None) -> int:
        """Return 0 if allowed, else the seconds to wait before retrying."""
        if self.per_hour <= 0:
            return 0
        now = time.time() if now is None else now
        window = 3600.0
        with self._lock:
            hits = self._seen.setdefault(source, deque())
            while hits and now - hits[0] >= window:
                hits.popleft()
            if len(hits) >= self.per_hour:
                return max(1, int(window - (now - hits[0])) + 1)
            hits.append(now)
            return 0


def _book_rate_per_hour() -> int:
    """Bookings per source per hour. 0 disables, which an operator must choose."""
    raw = os.environ.get(_BOOK_RATE_ENV, "").strip()
    if not raw:
        return _DEFAULT_BOOK_RATE_PER_HOUR
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_BOOK_RATE_PER_HOUR


def _max_body_bytes() -> int:
    raw = os.environ.get(_MAX_BODY_BYTES_ENV, "").strip()
    if not raw:
        return _DEFAULT_MAX_BODY_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_MAX_BODY_BYTES


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _authorize_provision(token: str, authorization: str | None) -> None:
    """Raise 401 unless ``authorization`` carries the configured bearer token.

    No-op when no token is configured — whether that is allowed at all is
    ``_provision_config_error``'s decision, not this one.

    The refusal is identical for a missing header, a wrong scheme and a wrong
    secret, and carries nothing derived from the supplied value: this endpoint
    is the one an unauthenticated caller can reach, so anything it varies on is
    something it can be asked about.
    """
    if not token:
        return
    supplied = ""
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            supplied = value.strip()
    # compare_digest over bytes: the str form raises TypeError on a non-ASCII
    # header, which an unauthenticated caller controls.
    if not hmac.compare_digest(supplied.encode("utf-8"), token.encode("utf-8")):
        raise HTTPException(
            status_code=401,
            detail=f"provisioning on this host requires 'Authorization: Bearer <token>' ({_PROVISION_TOKEN_ENV}).",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _claimed_tenant_named(state: HostState, business_name: str) -> Tenant | None:
    """The already-provisioned tenant holding this business name, or None.

    DERIVED from ``tenants`` rather than kept in a second index, so it cannot
    drift out of sync with the tenant table — including across a restart, where
    ``_rehydrate`` rebuilds ``tenants`` from disk and this answer rebuilds with
    it. A pre-minted pool tenant that nobody has claimed carries a placeholder
    display name, so ``claimed`` is what makes a name taken, not existence.
    """
    slug = _slugify(business_name)
    if not slug:
        return None
    with state.lock:
        for tenant in state.tenants.values():
            if tenant.claimed and _slugify(tenant.business_name) == slug:
                return tenant
    return None


def _contact_for(tenant: Tenant) -> Any:
    """The delivery channel for this tenant, or None if it has none.

    None is reachable for a tenant provisioned before the contact field existed:
    it rehydrates with an empty contact, and its bookings then report
    undelivered by name rather than appearing to have reached anyone.
    """
    from community_member.builtin_skills.booking import notify

    if not tenant.contact:
        return None
    try:
        return notify.parse_contact(tenant.contact)
    except notify.ContactError:
        # Stored contacts are validated at the claim call, so this is a tenant
        # whose stored value predates that check. Undeliverable is reported, not
        # raised: the booking and its receipt still stand.
        return None


def _reject_unusable_contact(contact: str) -> None:
    """Refuse a contact that names no channel a booking can be delivered on.

    Checked at the claim call, where a human is present to correct it, rather
    than at the first booking, where the customer is the one who finds out. The
    classification is the booking skill's own, so the host cannot accept a
    contact the delivery path would then reject.
    """
    from community_member.builtin_skills.booking import notify

    try:
        notify.parse_contact(contact)
    except notify.ContactError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _reject_unusable_business_name(state: HostState, business_name: str) -> None:
    """Raise the 400/409 a business name earns, or return.

    ONE implementation, called from both provisioning paths. It used to live
    inside ``_cold_provision`` only, and the pool claim — which is the DEFAULT,
    since ``SMB_HOST_POOL_SIZE`` is 3 — took a pre-minted id without consulting
    the name, so neither check ran on the configuration operators actually run.
    Measured at ebb0aeb: the same business_name three times returned 201 three
    times, three did:keys, three cards all reading the same name; and a name of
    only punctuation returned 201 rather than the documented 400.

    The refusal is decided by the business name, not by which path serves the
    request. A refusal whose presence depends on a performance setting is worse
    than either having it or not having it, because the operator cannot tell
    which behaviour they have.

    WHAT THIS DOES NOT DO: it refuses names that reduce to the SAME SLUG, and
    that is not name ownership. _slugify lowercases and collapses every
    non-alphanumeric run to a hyphen, so "CORNER BAKERY", "Corner-Bakery",
    "corner  bakery" and "Corner Bakery." all collide with "Corner Bakery" and
    are refused — but "Corner Bakery Ltd" and "Corner Bakery NYC" are different
    slugs and still provision alongside it. The tenant URL does not identify a
    business and this does not make it one.

    CONCURRENCY LIMIT, stated rather than implied: on the pool path the check and
    the claim are both taken under ``state.lock``, so two simultaneous requests
    for one name cannot both succeed. On the cold path the check happens before a
    mint that takes seconds and is deliberately NOT holding the lock across it —
    serialising every cold provision to close that window is a worse trade at
    this scale. Two concurrent cold provisions of the same name can therefore
    still both land; that race is unchanged from before this function existed.
    """
    if not _slugify(business_name):
        raise HTTPException(
            status_code=400,
            detail="business_name must contain at least one alphanumeric character",
        )
    if _claimed_tenant_named(state, business_name) is not None:
        # The refusal names what the CALLER supplied, never the existing
        # tenant's id. The previous message interpolated that id, which on the
        # cold path is only the slug of the name the caller just sent — but on
        # the pool path it is a random id belonging to somebody else's live
        # tenant, and /t/<id> is that tenant's endpoint, card and booking route.
        # Provisioning is open on the loopback shape, so a refusal that hands an
        # anonymous caller a live tenant's id turns a duplicate-name probe into
        # a directory of every business on the host.
        raise HTTPException(
            status_code=409,
            detail=f"a business is already provisioned under the name {business_name!r}",
        )


def _slugify(business_name: str) -> str:
    """A URL-safe, stable tenant_id from a business name.

    Lowercase, non-alphanumeric runs collapse to a single hyphen, ends trimmed.
    Empty result (e.g. a name of only punctuation) is rejected by the caller.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", business_name.strip().lower()).strip("-")
    return slug


def _tenant_description(business_name: str) -> str:
    """The description served on both the A2A card and AgentFacts for a
    claimed tenant. NOT "sovereign": the tenant does not hold its own key —
    one operator passphrase decrypts every tenant on this host, and the
    tenant's process is this host's process (docs/OPERATIONS.md's own
    "separation of state, not a boundary" limit). Single source so the card
    and AgentFacts cannot describe the same tenant differently, and so a
    cold-provisioned tenant is described the same way a pool-claimed one is.

    KEPT LOCAL rather than imported from its sibling copy in the registration
    module, even though the two must say the same thing: a guard elsewhere in
    this suite asserts the registration module's name appears nowhere in this
    file's source, because that module is the write-capable half of the SMB
    registration path, reaching a network client this host never touches, and
    this host makes no outbound calls of that kind. Equivalence with the
    sibling copy is enforced by test_served_claims.py instead of by a shared
    import.
    """
    return f"Agent for {business_name}, hosted on this service"


def _operator_identity(public_url: str) -> tuple[str, str]:
    """(organization, url) for the provider block — who actually runs this agent.

    Derived from the host's own public address rather than the tenant's
    name or slug: the tenant is what is being run, not who is running it,
    and the domain a caller is already talking to is a fact this host can
    state without inventing a verified operator identity it does not have.

    THE ONE SOURCE OF TRUTH for the provider on BOTH served documents — the A2A
    card (``_build_tenant_card``) and the canonical AgentFacts (``agent_facts``).
    They used to disagree: the card named this host while AgentFacts fell back to
    ``config.name``, i.e. the tenant, so a consumer resolving both documents for
    one business was told two different things about who operates the endpoint.
    The host is the correct answer, and the reasoning is recorded here because
    the next hardening pass will otherwise reverse it:

    * sm-bridge documents ``SmProvider`` as "the organization running the agent",
      and A2A's ``provider`` likewise. That is this host. One operator passphrase
      decrypts every tenant, every tenant route is served from this process, and
      the tenant runs nothing (``OPERATIONS.md``: separation of state, not a
      boundary).
    * The tenant is not absent from the document if we decline to name it here —
      ``label``, ``agent_name`` and ``handle`` already carry it. Putting the
      business in ``provider`` too would not add information; it would replace
      the only field that says who is accountable for the endpoint with a
      second copy of who is being hosted.
    * ``business_name`` is a display label nobody verified (README, and the
      CLAIMS.md scope note). Promoting an unverified string into the field a
      directory reads as the operator is the worse half of the same mistake.
    """
    netloc = urlparse(public_url).netloc or public_url
    return netloc, public_url


# ── request / response models ───────────────────────────────────────────────────


class ProvisionRequest(BaseModel):
    business_name: str = Field(..., min_length=1, description="The SMB's display name")
    service_type: str | None = Field(None, description="Optional service category, e.g. 'barber'")
    # REQUIRED, and the reasoning is worth keeping next to the field. This host
    # takes bookings on the business's behalf; a business that cannot be reached
    # cannot receive one, and the customer still leaves holding a signed receipt
    # saying the appointment was made. An optional contact would ship exactly
    # that outcome, so the claim call refuses without one rather than
    # provisioning an agent that can accept bookings and deliver none.
    #
    # It is captured here rather than at mint time because a pool tenant is
    # minted before anyone claims it, so this is the first moment a business
    # exists to have a contact.
    contact: str = Field(
        ...,
        min_length=1,
        description="Where this business receives bookings: an https webhook URL or an email address",
    )


class ProvisionResponse(BaseModel):
    """What ``POST /provision`` returns — exactly what host39 needs to register
    the agent on the NANDA Index itself. No ``urn`` (that was an index concept)."""

    tenant_id: str
    endpoint: str
    recovery_phrase: str
    did: str


class ProvisionSource(BaseModel):
    """One recorded caller and what it provisioned.

    ``source`` is whatever ``_caller_discriminator`` resolved at the claim call —
    an address, and explicitly not an identity (see that function). It is
    reported verbatim rather than re-interpreted here: this surface says what is
    on the record, and a reader who wants to know how much that address is worth
    reads ``SMB_HOST_TRUSTED_PROXIES``.
    """

    source: str
    count: int
    first_provisioned_at: str | None
    last_provisioned_at: str | None


class ProvisionSummary(BaseModel):
    """The aggregate answer to "who provisioned the tenants on this host".

    AGGREGATE, NOT A ROSTER, and that is the whole design decision. The question
    this exists to answer is a distribution — how many provisions came from
    where, and when — which an aggregate answers completely. A per-tenant
    listing would answer it too and would additionally hand its reader every
    tenant_id on the host, which is the enumeration surface removed from the
    409 duplicate-name refusal when it stopped naming an existing tenant's id
    to an anonymous caller. Requiring a bearer
    does not make it safe to rebuild: a leaked provisioning token would then
    yield the roster as well as the ability to mint, and nothing about the
    growth question needs a tenant named to answer it.

    FOUR BUCKETS, and the distinctions between them are the point:

    * ``recorded`` — a claim whose caller signal resolved. The answer to "who".
    * ``unattributable`` — a claim that WAS attributed and whose signal did not
      resolve, recorded under the ``_UNATTRIBUTABLE`` sentinel. Attribution was
      attempted and failed.
    * ``unrecorded`` — a claimed tenant carrying no ``provisioned_by`` key at
      all, i.e. one provisioned before the field existed. Nothing was ever
      attempted.
    * ``unclaimed_pool_slots`` — a pre-minted pool tenant nobody has claimed. It
      is not a provision at all and has no attribution state; folding it into
      ``unrecorded`` would report the host's own warmer output as unattributed
      demand, which is exactly how 15 warmer mints were read as 15 businesses.

    ``unattributable`` and ``unrecorded`` are never defaulted to one another,
    and both accounting identities below hold on every response, so a reader can
    check that no tenant was dropped or double-counted:

        tenants == claimed + unclaimed_pool_slots
        claimed == sum(r.count for r in recorded) + unattributable + unrecorded
    """

    tenants: int
    claimed: int
    unclaimed_pool_slots: int
    recorded: list[ProvisionSource]
    unattributable: int
    unrecorded: int


class BookRequest(BaseModel):
    """A booking request. Fields are declared optional so a missing required
    field is surfaced as a clean 400 (a client error we own) rather than
    FastAPI's default 422 — the booking action itself has NO consent gate, so
    the only rejection here is a malformed body.

    Field lengths are bounded. They were not, and POST /t/{id}/book is
    unauthenticated: a single anonymous request carrying a 2 MB ``notes`` field
    returned 200 and grew the tenant store by 4,015,349 bytes — roughly twice the
    input, because the caller's text is persisted in the booking store AND again
    inside the signed ARP receipt. This host has no delete route, so that growth
    was permanent (H14).

    These caps bound STORAGE and they do it unconditionally, independent of
    transfer encoding and of whether the request carries a Content-Length. That
    matters: the body-size middleware below can be evaded by a chunked sender,
    and these cannot."""

    service: str | None = Field(None, max_length=_MAX_BOOKING_FIELD, description="What is being booked, e.g. 'haircut'")
    provider: str | None = Field(None, max_length=_MAX_BOOKING_FIELD, description="Who it is with (business or person)")
    datetime: str | None = Field(None, max_length=_MAX_BOOKING_FIELD, description="When, e.g. an ISO-8601 timestamp")
    notes: str | None = Field(None, max_length=_MAX_BOOKING_NOTES, description="Optional free-form notes")


# The fields POST /t/{tenant_id}/book rejects a body for omitting. Module-level so
# the doc guard in test_main.py can assert the README's booking example sends this
# exact set: a run page naming a field the route does not require produces a 400
# the reader cannot attribute to the page rather than to the service.
_BOOKING_REQUIRED_FIELDS = ("service", "provider", "datetime")


# ── in-process tenant registry ───────────────────────────────────────────────────


@dataclass
class Tenant:
    """One provisioned SMB: its isolated context + the public facts about it."""

    tenant_id: str
    business_name: str
    service_type: str | None
    ctx: AgentContext
    did: str
    endpoint: str
    # B4 pool bookkeeping. ``claimed`` is False for a hot, un-handed-out pool
    # tenant and flips True the instant a caller claims it. ``recovery_phrase``
    # is the one-time mnemonic held IN MEMORY only for an un-claimed pool tenant
    # (never persisted, exactly like the cold path) so the claim can return the
    # pool tenant's REAL phrase; it is cleared to None on claim.
    claimed: bool = True
    recovery_phrase: str | None = None
    # Where this business receives its bookings. Empty on an un-claimed pool
    # tenant, which has no business yet; set from the claim call and persisted,
    # so a restart does not leave a claimed tenant unreachable.
    contact: str = ""
    # ATTRIBUTION, set at the CLAIM call (cold-provision or pool-claim) — not at
    # mint time, since a pool tenant's mint is this host's own background job
    # and is never attributable to an external caller. None means "no claim
    # attribution recorded": either a not-yet-claimed pool slot, or a tenant
    # provisioned before this field existed — the two are NOT backfilled with a
    # guess. A claimed tenant with no usable caller signal carries the literal
    # string in _UNATTRIBUTABLE instead, which IS a recorded outcome and is
    # never confused with "not recorded at all".
    provisioned_at: str | None = None
    provisioned_by: str | None = None
    # Whether this tenant's id is sitting in the pool queue right now. IN-MEMORY
    # ONLY and deliberately absent from ``meta()``: the queue is in-memory, so a
    # rehydrated tenant is by definition not in it. It exists so the warmer can
    # tell a slot it has already made ready from one still waiting to be
    # reclaimed — without it, a reclaimed slot still satisfies every other
    # condition in ``_is_reclaimable_pool_slot`` and would be re-keyed on every
    # tick forever.
    queued: bool = False

    def meta(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "business_name": self.business_name,
            "service_type": self.service_type,
            "did": self.did,
            "endpoint": self.endpoint,
            "claimed": self.claimed,
            "contact": self.contact,
            "provisioned_at": self.provisioned_at,
            "provisioned_by": self.provisioned_by,
        }


@dataclass
class HostState:
    """Per-app configuration + the live tenant table. Lives on ``app.state`` so
    two app instances (e.g. a restart in a test) never share a registry."""

    public_url: str
    data_dir: Path
    tenants: dict[str, Tenant] = field(default_factory=dict)

    # ── B4 pre-warm pool ─────────────────────────────────────────────────────
    # ``pool_size`` == 0 disables the pool entirely (pure cold-provision). The
    # ``pool`` queue holds the tenant_ids of ready, pre-minted, not-yet-claimed
    # tenants (the Tenant objects themselves live in ``tenants``). All
    # mutation of ``tenants`` crosses a request thread and the warmer thread, so
    # it is guarded by ``lock``. ``pool_wake`` lets a claim nudge the warmer to
    # top up immediately; ``pool_stop`` tears the warmer down on shutdown.
    pool_size: int = 0
    pool: queue.Queue[str] = field(default_factory=queue.Queue)
    lock: threading.RLock = field(default_factory=threading.RLock)
    pool_wake: threading.Event = field(default_factory=threading.Event)
    pool_stop: threading.Event = field(default_factory=threading.Event)
    pool_thread: threading.Thread | None = None


def _write_meta(home: Path, tenant: Tenant) -> None:
    """Persist the tenant's meta record atomically: write a sibling temp file,
    fsync it, then ``rename`` it over the real one.

    The meta file is what a restart rehydrates a tenant from, and every field
    the pool-reclaim predicate reads comes from it. A plain ``write_text``
    truncates first and writes second, so a crash between the two leaves a
    torn file: the tenant fails to rehydrate at the next boot — on a claimed
    tenant, a business that was there is not. ``rename`` is atomic on POSIX,
    so a reader sees either the previous record or the new one, never a
    partial one.
    """
    target = home / _META_FILE
    payload = json.dumps(tenant.meta(), indent=2)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{_META_FILE}.", suffix=".tmp", dir=home)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _endpoint_for(public_url: str, tenant_id: str) -> str:
    return f"{public_url.rstrip('/')}/t/{tenant_id}"


def _load_tenant_from_home(home: Path, public_url: str) -> Tenant | None:
    """Rehydrate one tenant from its on-disk home, or None if it is not a
    fully-provisioned tenant. Identity is reloaded from the tenant's own vault;
    the recovery phrase is (correctly) unrecoverable."""
    meta_path = home / _META_FILE
    if not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text())
    tenant_id = str(meta["tenant_id"])
    ctx = AgentContext.load(home)
    # Reuses the stored key (idempotent): ensure_identity finds the vaulted seed
    # under this home and rebinds it rather than minting a new one.
    did = ctx.ensure_identity(tenant_id)
    # The endpoint is recomputed from the CURRENT public URL so a redeployed host
    # under a new base URL serves the tenant's card at the right address.
    endpoint = _endpoint_for(public_url, tenant_id)
    return Tenant(
        tenant_id=tenant_id,
        business_name=str(meta.get("business_name") or tenant_id),
        service_type=meta.get("service_type"),
        ctx=ctx,
        did=did,
        endpoint=endpoint,
        # A rehydrated tenant is a live tenant, not a pool slot: its one-time
        # recovery phrase is (correctly) unrecoverable, so it is never re-enqueued
        # for claim. The pool queue is fed ONLY by freshly-warmed in-memory
        # tenants that still hold their mnemonic.
        claimed=bool(meta.get("claimed", True)),
        recovery_phrase=None,
        contact=str(meta.get("contact") or ""),
        # .get, not .get(..., default): a tenant provisioned before this field
        # existed has no key at all, and that must rehydrate as None (not
        # recorded) rather than as _UNATTRIBUTABLE (recorded, and known not to
        # resolve) — the two are different facts and this is the one place that
        # could conflate them.
        provisioned_at=meta.get("provisioned_at"),
        provisioned_by=meta.get("provisioned_by"),
    )


def _rehydrate(state: HostState) -> None:
    """Load every previously-provisioned tenant under ``data_dir`` into memory."""
    if not state.data_dir.is_dir():
        return
    for child in sorted(state.data_dir.iterdir()):
        if not child.is_dir():
            continue
        tenant = _load_tenant_from_home(child, state.public_url)
        if tenant is not None:
            state.tenants[tenant.tenant_id] = tenant


# ── what a tenant can actually be asked to do ───────────────────────────────
#
# Every tenant-scoped ACTION route this host serves, and the A2A tool it
# exposes. The card is built FROM this table, so the card cannot advertise a
# capability the host does not serve, and
# `test_the_card_declares_every_action_route_the_host_serves` walks the app's
# own route table and fails if a route is added without an entry here — so it
# cannot drift the other way either.
#
# Routes that are metadata rather than actions (the card itself, AgentFacts)
# belong in _TENANT_METADATA_ROUTES below, not here: they describe the agent
# instead of doing something for a caller.
#
# The card previously passed `tools=None` and served `"skills": []`, so a client
# that resolved a tenant could not tell it takes bookings — while POST /book
# answered 200 with a signed receipt.
TENANT_ACTION_TOOLS: dict[str, dict[str, Any]] = {
    "/t/{tenant_id}/book": {
        "type": "function",
        "function": {
            "name": "book_appointment",
            "description": (
                # Not "with this business": README says business_name is a
                # display label nobody verified, and this description used to
                # imply the noun the label is not.
                "Book an appointment. Returns a signed receipt for the booking, "
                "verifiable offline under the agent's did:key."
            ),
        },
    },
}

# Tenant-scoped routes that describe the agent rather than act for a caller.
# Listed so the divergence guard can account for every tenant route as either an
# action or metadata, and never by ignoring what it does not recognise.
_TENANT_METADATA_ROUTES: frozenset[str] = frozenset(
    {
        "/t/{tenant_id}/.well-known/agent.json",
        "/t/{tenant_id}/agentfacts.json",
    }
)


def tenant_action_skill_names() -> list[str]:
    """The capability names behind the tenant action routes, for AgentFacts.

    AgentFacts names skills as free text rather than as A2A tool objects, so the
    tool name is turned into a phrase here. Derived from the same table as the
    card so a capability cannot appear on one document and not the other.
    """
    return [t["function"]["name"].replace("_", " ") for t in TENANT_ACTION_TOOLS.values()]


def _build_tenant_card(tenant: Tenant, version: str, public_url: str) -> dict[str, Any]:
    """The tenant's A2A agent card as a JSON-ready dict, via the canonical
    ``build_agent_card`` (same shape the community-member runtime serves) —
    name, did:key, endpoint, credential.

    Every capability this card advertises must be one this host actually
    enforces or implements — see the per-surface overrides below, each
    with the check that justifies it:
    * no ``streaming``: this host mounts plain REST routes, no JSON-RPC
      ``tasks/sendSubscribe`` anywhere in it.
    * no ``authentication`` scheme: ``/t/{id}/book`` and every tenant route
      have no auth dependency — only ``/provision`` is gated, and that is a
      host-level admin credential, not a per-request caller scheme.
    * ``provider`` names the host's own address, not the tenant: the tenant
      does not run itself, and the actual operator's identity is otherwise
      absent from this document entirely.
    * the topical skill does not claim discovery ranking: this host
      registers on no index and imports nothing from the ranking code that
      lives in ``server/``.
    """
    skills_declared = [tenant.service_type] if tenant.service_type else None
    organization, provider_url = _operator_identity(public_url)
    card = build_agent_card(
        agent_id=tenant.tenant_id,
        display_name=tenant.business_name,
        description=_tenant_description(tenant.business_name),
        version=version,
        base_url=tenant.endpoint,
        chapter_url=None,
        did=tenant.did,
        skills_declared=skills_declared,
        tools=list(TENANT_ACTION_TOOLS.values()),
        supports_streaming=False,
        authentication_schemes=[],
        provider_organization=organization,
        provider_url=provider_url,
        topical_skills_are_ranked=False,
    )
    payload: dict[str, Any] = card.model_dump(mode="json", by_alias=True, exclude_none=True)
    return payload


# ── provisioning primitive (shared by the cold path AND the pool warmer) ─────────


def _provision_tenant(
    state: HostState,
    tenant_id: str,
    business_name: str,
    service_type: str | None,
    contact: str = "",
) -> tuple[Tenant, str]:
    """Mint an isolated sovereign identity for ``tenant_id`` and publish it into
    the live registry. Returns the ``(Tenant, recovery_phrase)`` pair.

    This is the ONE place a tenant is minted — the cold ``POST /provision`` path
    and the background pool warmer both call it, so the two never drift. This host
    registers the agent on NO index; making it discoverable on the NANDA Index is
    host39's job, downstream of the ``{tenant_id, endpoint, did, recovery_phrase}``
    this returns. The registry is only mutated on full success.
    """
    home = state.data_dir / tenant_id
    if home.exists():
        # Residue from a prior failed/partial provision — clear it so this
        # attempt starts clean.
        shutil.rmtree(home)

    # Mint an isolated identity from a fresh recovery phrase, so the phrase we
    # hand back actually recovers this exact key. Persist into THIS tenant's
    # home vault, then ensure_identity (idempotent) rebinds it → did:key.
    ctx = AgentContext.load(home)
    material = recovery.generate_recovery()
    ctx.config.agent_id = tenant_id
    ctx.config.name = business_name
    ctx.config.private_key = material.private_key_b64
    ctx.config.public_key = material.public_key_b64
    if service_type:
        ctx.config.skills = [service_type]
    ctx.config.save()
    did = ctx.ensure_identity(tenant_id)

    endpoint = _endpoint_for(state.public_url, tenant_id)

    # Minted → serveable. Record the marker LAST (so rehydration only ever sees
    # fully-minted tenants) and publish into the live registry.
    tenant = Tenant(
        tenant_id=tenant_id,
        business_name=business_name,
        service_type=service_type,
        contact=contact,
        ctx=ctx,
        did=did,
        endpoint=endpoint,
        claimed=False,
        recovery_phrase=material.mnemonic,
    )
    _write_meta(home, tenant)
    with state.lock:
        state.tenants[tenant_id] = tenant
    return tenant, material.mnemonic


def _cold_provision(state: HostState, req: ProvisionRequest, caller: str) -> ProvisionResponse:
    """The original synchronous provision path: slug the business name and mint an
    identity, all on the request thread. Used when the pool is disabled OR drained
    (graceful fallback — correctness over latency).

    Kept as a named module-level function specifically so the pool-claim path can
    be proven to NOT call it (see the B4 structural-proof test).

    Checked BEFORE the request-shape validation below, not after: a host that is
    completely out of capacity has nothing to say about whether this particular
    name or contact would have been acceptable, and this is the ONE path that
    actually mints — the pool-claim path never does, so it carries no capacity
    check (see ``_claim_from_pool``).
    """
    if _at_capacity(state):
        used, cap = _capacity_status(state)
        raise HTTPException(
            status_code=507,
            detail=(
                f"this host has issued its full allocation of tenants ({used} of {cap}). "
                f"No further provisioning until an operator raises {_TENANT_CAP_ENV}."
            ),
        )
    _reject_unusable_business_name(state, req.business_name)
    _reject_unusable_contact(req.contact)
    tenant_id = _slugify(req.business_name)

    tenant, mnemonic = _provision_tenant(state, tenant_id, req.business_name, req.service_type, req.contact)

    # A cold tenant is claimed on creation (it is not a pool slot).
    tenant.claimed = True
    tenant.recovery_phrase = None
    tenant.provisioned_at = _now_iso()
    tenant.provisioned_by = caller or _UNATTRIBUTABLE
    # Without this, config.description stays unset on the cold path (unlike
    # the pool-claim path, which sets it) and AgentFacts falls back to
    # sm_bridge_adapter's own default — a second, DIFFERENT description of
    # the same tenant that the card never shows.
    tenant.ctx.config.description = _tenant_description(req.business_name)
    tenant.ctx.config.save()
    _write_meta(state.data_dir / tenant_id, tenant)
    return ProvisionResponse(
        tenant_id=tenant_id,
        endpoint=tenant.endpoint,
        recovery_phrase=mnemonic,
        did=tenant.did,
    )


# ── B4 pre-warm pool: warmer + claim + background label push ──────────────────────


def _new_pool_id() -> str:
    """A fresh, collision-resistant tenant_id for a pool slot. Distinct from a
    business-name slug (which the cold path derives), so a pool tenant never
    shadows a would-be cold tenant."""
    return f"{_POOL_ID_PREFIX}{secrets.token_hex(6)}"


def _is_reclaimable_pool_slot(tenant: Tenant) -> bool:
    """True when this home is a pool slot nobody has ever been handed, and the
    warmer may therefore re-key it in place instead of minting a new home.

    ⚠️ THIS PREDICATE GUARDS A DESTRUCTIVE OPERATION. Re-keying replaces the
    Ed25519 seed in the tenant's vault. On an un-claimed slot that costs nothing
    — its one-time recovery phrase is handed out AT CLAIM, so nobody has ever
    seen the phrase for a slot that was never claimed, and its did:key appears
    in no card anyone was given. On a CLAIMED tenant the same operation destroys
    a business's signing identity, recoverable only from a phrase its owner saw
    once. So the two cases must never be confused, and the asymmetry decides how
    this is written: an over-strict predicate leaves a home stranded, which is
    the behaviour that exists today; an under-strict one destroys a business.

    Every condition below is a POSITIVE property the warmer itself writes at
    mint time and that a claim overwrites — not the absence of a marker. They
    are required to hold TOGETHER, so no single corrupted or missing field can
    make a claimed home look reclaimable:

    * ``claimed`` is explicitly False. ``_load_tenant_from_home`` reads this as
      ``meta.get("claimed", True)``, so a home whose meta lacks the key at all
      rehydrates as CLAIMED and is excluded here — the safe direction, and the
      one that keeps a tenant provisioned before the field existed out of reach.
    * ``queued`` is False. A slot already in the pool queue is ready, not
      stranded; without this it would satisfy every other condition and be
      re-keyed on every warmer tick forever.
    * the id carries the warmer's own prefix. A cold-provisioned tenant's id is
      the slug of its business name.
    * the display name is still the placeholder. A claim replaces it with the
      business name, in the same locked block that sets ``claimed``.
    * no contact is stored. A claim requires one and refuses without it.
    * no attribution is recorded. A claim writes ``provisioned_at`` and
      ``provisioned_by`` together with ``claimed``; a slot nobody claimed has
      neither. This one does not discriminate against a tenant provisioned
      before attribution existed — that tenant also has neither — which is why
      it is one condition among several rather than the test.
    """
    return (
        not tenant.claimed
        and not tenant.queued
        and tenant.tenant_id.startswith(_POOL_ID_PREFIX)
        and tenant.business_name == _POOL_PLACEHOLDER_NAME
        and not tenant.contact
        and tenant.provisioned_at is None
        and tenant.provisioned_by is None
    )


def _next_reclaimable_slot_id(state: HostState) -> str | None:
    """The id of one stranded pool slot the warmer may re-key, or None.

    ``_load_tenant_from_home`` deliberately never re-enqueues a rehydrated pool
    tenant — its one-time recovery phrase is unrecoverable, so handing it to a
    claim would return an empty phrase, a silent downgrade of the one secret
    that recovers the business's key. The consequence was that every restart
    stranded the previous boot's un-claimed slots and the warmer minted a fresh
    set beside them: tenant count rose by ``SMB_HOST_POOL_SIZE`` per boot with
    no provision involved, and the stranded homes could never be handed to
    anyone. Measured on the deployed host: 26 of 58 container boots ran the
    warmer, which accounts for 78 of its 83 tenant homes; the other 5 are the
    only provisions it has ever served.

    Re-keying is what makes such a home usable again: a fresh recovery phrase is
    generated for it, so the phrase handed out at claim really does recover that
    tenant's key. Sorted so the choice is deterministic rather than dict order.
    """
    with state.lock:
        candidates = sorted(t.tenant_id for t in state.tenants.values() if _is_reclaimable_pool_slot(t))
    return candidates[0] if candidates else None


def reclaimable_slot_count(state: HostState) -> int:
    """How many stranded pool homes are waiting to be re-keyed into the pool.

    Reported on ``/health`` so the backlog is observable rather than inferred
    from a tenant count that does not move. On a host with a backlog the warmer
    consumes it before it mints anything new, so this number falling while
    ``tenants`` stays flat is the fix working.
    """
    with state.lock:
        return sum(1 for t in state.tenants.values() if _is_reclaimable_pool_slot(t))


def _warm_one(state: HostState, reclaim_id: str | None = None) -> None:
    """Make one ready tenant available in the pool.

    ``reclaim_id`` re-keys an existing stranded slot in place instead of minting
    a new home; ``None`` mints a new one. ``_provision_tenant`` already clears a
    pre-existing home before minting into it, so both cases go through the one
    mint primitive and no second deletion path is introduced anywhere in this
    module.
    """
    tenant_id = reclaim_id if reclaim_id is not None else _new_pool_id()
    _provision_tenant(state, tenant_id, _POOL_PLACEHOLDER_NAME, None)
    with state.lock:
        tenant = state.tenants.get(tenant_id)
        if tenant is not None:
            tenant.queued = True
        state.pool.put(tenant_id)
    logger.info(
        "pool: %s %s (ready=%d/%d)",
        "reclaimed" if reclaim_id is not None else "warmed",
        tenant_id,
        state.pool.qsize(),
        state.pool_size,
    )


def _pool_worker(state: HostState) -> None:
    """Background warmer: keep the pool topped up to ``pool_size``. Reacts to a
    claim immediately (via ``pool_wake``); if a pre-mint fails it logs loud and
    retries on the next tick rather than crashing the host thread.

    THIS IS THE PATH THAT ACTUALLY GROWS TENANT COUNT under the default
    (pool-enabled) configuration: a claim never mints, it only relabels an
    already-minted slot, so it is this loop's replenishment mint — not the
    request that triggered it — that the total cap has to stop. Capacity is
    re-checked on every attempted warm (not once per wake), so raising the cap
    at runtime is picked up without a restart.

    A STRANDED SLOT IS SPENT BEFORE A NEW HOME IS MINTED. Every boot starts with
    an empty queue, so before this loop existed in this form a restart minted
    ``pool_size`` fresh homes beside the ones the previous boot had left
    un-claimed and unreachable. It now re-keys those first and only mints when
    none is left, which is what makes the tenant count stable across restarts
    rather than rising by ``pool_size`` per boot.

    THE CAPACITY CHECK GATES MINTING ONLY, and that is deliberate rather than an
    oversight: re-keying an existing home creates no new home and moves the
    count by nothing, so a host sitting at its cap with stranded slots must
    still be able to make them usable. Refusing there would leave a full host
    permanently unable to serve anyone while holding homes nobody can reach.
    """
    logger.info("pool: warmer starting (target=%d)", state.pool_size)
    capacity_logged = False
    while not state.pool_stop.is_set():
        try:
            while state.pool.qsize() < state.pool_size and not state.pool_stop.is_set():
                reclaim_id = _next_reclaimable_slot_id(state)
                if reclaim_id is None and _at_capacity(state):
                    if not capacity_logged:
                        used, cap = _capacity_status(state)
                        logger.info("pool: at capacity (%d of %s=%s), not warming further", used, _TENANT_CAP_ENV, cap)
                        capacity_logged = True
                    break
                capacity_logged = False
                _warm_one(state, reclaim_id)
        except Exception as e:
            # Non-fatal for the warmer: the pool simply stays short and the cold
            # path covers provisions meanwhile. Loud, never silent.
            logger.warning("pool: warm failed, will retry: %s", e)
        state.pool_wake.wait(timeout=_POOL_POLL_INTERVAL_S)
        state.pool_wake.clear()
    logger.info("pool: warmer stopped")


def _claim_from_pool(state: HostState, req: ProvisionRequest, caller: str) -> ProvisionResponse | None:
    """Claim a ready tenant from the pool and return it INSTANTLY — no identity
    mint on the request path. Returns None if the pool is disabled or drained, so
    the caller can fall back to the cold path.

    Applying the business_name is a fast local update (display label + a disk
    meta write); the served card immediately reflects it.

    NO CAPACITY CHECK HERE, deliberately. This path never mints — the tenant it
    hands out was already minted (and already counted against the cap) by the
    warmer or an earlier cold provision — so claiming it cannot push the host
    over its cap. The cap is enforced where minting actually happens: the
    warmer (see ``_pool_worker``) and the cold path (see ``_cold_provision``).
    """
    if state.pool_size <= 0:
        return None

    # The name check and the claim are taken under ONE acquisition of the lock,
    # so two simultaneous requests for the same business name cannot both be
    # served: the second sees the first's tenant already marked claimed. The
    # queue read is inside it too — a slot must not be taken off the queue for a
    # request that is about to be refused, which would drain the pool by one on
    # every rejected duplicate.
    with state.lock:
        _reject_unusable_business_name(state, req.business_name)
        _reject_unusable_contact(req.contact)
        try:
            tenant_id = state.pool.get_nowait()
        except queue.Empty:
            return None

        tenant = state.tenants.get(tenant_id)
        if tenant is None:
            # A queued id with no live tenant should be impossible; treat as a
            # drained slot and fall back rather than hand back a broken response.
            logger.warning("pool: queued id %s had no live tenant; falling back to cold path", tenant_id)
            return None
        # Off the queue, so it is no longer a ready slot. Cleared before the
        # claim below rather than after, so the flag is never left set on a
        # tenant the queue no longer holds even if the claim raises.
        tenant.queued = False
        tenant.business_name = req.business_name
        if req.service_type:
            tenant.service_type = req.service_type
        tenant.contact = req.contact
        tenant.claimed = True

        # Apply the claim to the tenant's OWN config as well, not only to this
        # dataclass. The A2A card is built from the fields above; AgentFacts is
        # built from ``ctx.config`` by build_self_agentfacts. Claiming used to
        # update the first and not the second, so a provisioned business served a
        # card reading "Moon Bakery" beside an AgentFacts reading
        # label "(unclaimed)", provider.name "(unclaimed)", agent_name the pool
        # id, and no mention of the business anywhere in the document.
        #
        # That is the NANDA-facing half — the one a card host hands onward to
        # register the business at api.nandaindex.org (see
        # docs/integrations/SMB_NANDA_HANDSHAKE.md). A record labelled
        # "(unclaimed)" describes no business to anyone searching for one.
        #
        # These are exactly the assignments _provision_tenant makes at mint time,
        # where the name is already known; the pool path just learns it later.
        tenant.ctx.config.name = req.business_name
        tenant.ctx.config.description = _tenant_description(req.business_name)
        if req.service_type:
            tenant.ctx.config.skills = [req.service_type]
        tenant.ctx.config.save()
        mnemonic = tenant.recovery_phrase or ""
        tenant.recovery_phrase = None  # a one-time secret; drop it after handing it back
        tenant.provisioned_at = _now_iso()
        tenant.provisioned_by = caller or _UNATTRIBUTABLE
        _write_meta(state.data_dir / tenant_id, tenant)

    # Nudge the warmer to refill the slot we just took (off the request path).
    state.pool_wake.set()

    return ProvisionResponse(
        tenant_id=tenant.tenant_id,
        endpoint=tenant.endpoint,
        recovery_phrase=mnemonic,
        did=tenant.did,
    )


def _resolve_pool_size() -> int:
    """The configured pool size (``SMB_HOST_POOL_SIZE``), clamped to >= 0.
    Default :data:`_DEFAULT_POOL_SIZE`; 0 ⇒ pool disabled (pure cold-provision)."""
    raw = os.environ.get(_POOL_SIZE_ENV, "").strip()
    if not raw:
        return _DEFAULT_POOL_SIZE
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning("pool: invalid %s=%r, using default %d", _POOL_SIZE_ENV, raw, _DEFAULT_POOL_SIZE)
        return _DEFAULT_POOL_SIZE


# ── provisioning attribution (read) ─────────────────────────────────────────────


def _summarize_provisions(state: HostState) -> ProvisionSummary:
    """Aggregate the per-tenant attribution records into a reportable shape.

    Recording a provision (``provisioned_by`` / ``provisioned_at`` per tenant)
    landed without a reader, so the host held the answer to "who provisioned
    these" and could only be asked by shelling into its volume. This is the read
    half.

    The bucketing is decided by two independent facts, in this order, and never
    by defaulting one to another — see :class:`ProvisionSummary` for why each
    distinction is load-bearing:

    1. ``claimed`` — is this a provision at all, or a pool slot nobody took?
    2. ``provisioned_by`` — absent (never attempted), the ``_UNATTRIBUTABLE``
       sentinel (attempted, unresolved), or a resolved source.

    A stored source is grouped VERBATIM. This function does not normalise,
    canonicalise or discard an odd value: it reports what is on the record, and
    a value no write path in this host can produce is a fact about the record
    that a reader needs to see rather than one this function should hide.
    """
    with state.lock:
        tenants = list(state.tenants.values())

    claimed = [t for t in tenants if t.claimed]
    unclaimed = len(tenants) - len(claimed)

    sources: dict[str, list[str | None]] = {}
    unattributable = 0
    unrecorded = 0
    for tenant in claimed:
        who = tenant.provisioned_by
        if who is None:
            unrecorded += 1
        elif who == _UNATTRIBUTABLE:
            unattributable += 1
        else:
            sources.setdefault(who, []).append(tenant.provisioned_at)

    recorded = []
    for source, stamps in sources.items():
        seen = sorted(s for s in stamps if s)
        recorded.append(
            ProvisionSource(
                source=source,
                count=len(stamps),
                first_provisioned_at=seen[0] if seen else None,
                last_provisioned_at=seen[-1] if seen else None,
            )
        )
    # Busiest caller first, then by source, so two hosts holding the same
    # records produce the same document and a diff between two reads is a real
    # change rather than dict ordering.
    recorded.sort(key=lambda r: (-r.count, r.source))

    return ProvisionSummary(
        tenants=len(tenants),
        claimed=len(claimed),
        unclaimed_pool_slots=unclaimed,
        recorded=recorded,
        unattributable=unattributable,
        unrecorded=unrecorded,
    )


# ── app factory ──────────────────────────────────────────────────────────────────


def create_app() -> FastAPI:
    """Build the SMB host app, reading its config from the environment and
    rehydrating any tenants already on disk.

    A factory (not a module-global mutable app) so a test can stand up a fresh
    host — or simulate a restart against the same ``SMB_HOST_DATA_DIR`` — with an
    independent in-memory registry.
    """
    # No-infra default: an isolated per-tenant file vault. Dir-isolated by each
    # tenant's home, so it is the right backend for a many-tenants-one-container
    # host. setdefault so an operator can still override via env.
    os.environ.setdefault("COMMUNITY_MEMBER_KEYSTORE", "device")

    configured_dir = os.environ.get(_DATA_DIR_ENV, "").strip()
    data_dir = (Path(configured_dir) if configured_dir else _default_data_dir()).expanduser().resolve()
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # Name the variable and the path. The bare PermissionError traceback this
        # replaces named neither, so the fix was not discoverable from the error.
        raise RuntimeError(
            f"cannot create the tenant data directory {str(data_dir)!r}: {exc}. Set {_DATA_DIR_ENV} to a writable path."
        ) from exc

    state = HostState(
        public_url=os.environ.get(_PUBLIC_URL_ENV, _PUBLIC_URL_UNSET).strip().rstrip("/"),
        data_dir=data_dir,
        pool_size=_resolve_pool_size(),
    )
    _rehydrate(state)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Start the background pool warmer on boot and tear it down on shutdown.

        Bound to the app lifespan (uvicorn fires it on real startup; a test fires
        it via ``with TestClient(app) as client``). When ``pool_size`` is 0 the
        warmer never starts — pure cold-provision, today's behavior verbatim.
        """
        warmer_refusal = _provision_config_error(state.public_url, _provision_token(), _resolve_tenant_cap())
        if state.pool_size > 0 and warmer_refusal is not None:
            # The warmer mints tenants BEFORE any request arrives and writes them
            # to disk, where a later rehydrate picks them up as fully
            # provisioned. Refusing at /provision alone would not prevent that,
            # so it is gated on exactly the same condition — the message names
            # the variable to set, and never the token's value.
            logger.warning("pool warmer not started: %s", warmer_refusal)
        elif state.pool_size > 0:
            state.pool_stop.clear()
            state.pool_thread = threading.Thread(
                target=_pool_worker, args=(state,), daemon=True, name="smb-pool-warmer"
            )
            state.pool_thread.start()
        try:
            yield
        finally:
            state.pool_stop.set()
            state.pool_wake.set()  # wake the warmer so it observes the stop promptly
            if state.pool_thread is not None:
                state.pool_thread.join(timeout=5)

    app = FastAPI(title="smb-host", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.host = state
    max_body = _max_body_bytes()
    book_limiter = _BookRateLimiter(_book_rate_per_hour())

    @app.middleware("http")
    async def _bound_request_body(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Refuse a body larger than the cap before it is parsed.

        ⚠️ **HONEST LIMIT:** this reads ``Content-Length``. A chunked sender that
        omits it is not bounded here, which is exactly why it is not the storage
        bound — the per-field ``max_length`` on BookRequest is, and that applies
        whatever the transfer encoding. This bounds memory during parse; the
        field caps bound what can be written.
        """
        if max_body:
            declared = request.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_body:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            f"request body of {int(declared)} bytes exceeds the "
                            f"{max_body}-byte limit ({_MAX_BODY_BYTES_ENV})."
                        )
                    },
                )
        return await call_next(request)

    # Cross-origin access for the browser funnel. Default "*" (public API, no
    # credentials); a deployment can pin an allowlist via the env var.
    #
    # ⚠️ "Authorization" IS LOAD-BEARING HERE. Provisioning is gated on a bearer
    # token, and the funnel is served from another origin, so its POST /provision
    # is preceded by a preflight naming that header. A preflight the middleware
    # does not allow is answered 400 "Disallowed CORS headers", and the browser
    # then never sends the request at all — the page sees an opaque network
    # failure rather than this host's 401 or its 201. Omitting it does not make
    # provisioning stricter; it makes the gated host unreachable from a browser
    # in BOTH directions, with and without a valid token.
    #
    # `allow_credentials` stays False: a bearer header is not a cookie, and "*"
    # origins with credentials is a combination browsers reject outright.
    raw_origins = os.environ.get(_CORS_ORIGINS_ENV, "*").strip()
    allow_origins = ["*"] if raw_origins in ("", "*") else [o.strip() for o in raw_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept", "Authorization"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        # ⚠️ HEADROOM MUST BE VISIBLE BEFORE IT IS EXHAUSTED, next to the counts
        # it is computed from, or exhaustion is discovered by a real business
        # failing to sign up rather than from this endpoint.
        used, cap = _capacity_status(state)
        return {
            "status": "ok",
            "service": "smb-host",
            "tenants": used,
            "pool_target": state.pool_size,
            "pool_ready": state.pool.qsize(),
            # Stranded pool homes waiting to be re-keyed back into the pool.
            # Reported because a backlog is otherwise invisible: `tenants`
            # includes them and does not move, and before the warmer learned to
            # spend them they were homes nobody could ever be handed. This
            # falling while `tenants` stays flat is the reclaim working.
            "pool_reclaimable": reclaimable_slot_count(state),
            "tenant_cap": cap,
            "headroom": (cap - used) if cap is not None else None,
            "at_capacity": cap is not None and used >= cap,
            # ⚠️ HOW MANY PROXY HOPS THIS HOST TRUSTS FOR ATTRIBUTION, READABLE
            # FROM OUTSIDE. `smb_signup` states one caller per provision in a
            # single-entry X-Forwarded-For, and this host ignores that header
            # entirely while this number is 0 — which is the correct default and
            # also the configuration in which the front door's forwarding does
            # nothing at all. Both services are individually right there and the
            # pair silently records the façade's own address, so the number that
            # decides it must not be knowable only from the environment of a
            # container nobody is looking at.
            "trusted_proxies": _resolve_trusted_proxies(),
        }

    def _gate_attribution_read(authorization: Annotated[str | None, Header()] = None) -> None:
        """Decide whether this caller may read the attribution summary.

        THE SAME CREDENTIAL AS PROVISIONING, and deliberately only its
        AUTHORIZATION half — not ``_provision_config_error``. That second check
        refuses when the host is configured such that it must not MINT, and the
        state this endpoint exists to explain is exactly one of those: the
        deployed host has ``SMB_HOST_TENANT_CAP`` unset, so ``POST /provision``
        answers 503 and its warmer never starts. Gating the read on the same
        condition would make the diagnostic unavailable in precisely the
        configuration it was built to diagnose.

        There is no separate read credential because there is no separate reader:
        the operator who holds the provisioning token is the party this answers
        to. Adding a second secret would be one more value to rotate for no
        change in who can see what.
        """
        _authorize_provision(_provision_token(), authorization)

    @app.get(
        "/provisions/summary",
        response_model=ProvisionSummary,
        dependencies=[Depends(_gate_attribution_read)],
    )
    def provisions_summary() -> ProvisionSummary:
        """Who provisioned the tenants on this host, when, and from where.

        Authenticated: the tenant population is not public, and an attribution
        listing is a better enumeration surface than the duplicate-name 409,
        which stopped naming an existing tenant's id to an anonymous caller.
        Aggregate rather than per-tenant for the same reason — see :class:`ProvisionSummary`.
        """
        return _summarize_provisions(state)

    def _gate_provisioning(authorization: Annotated[str | None, Header()] = None) -> None:
        """Decide whether this caller may provision, BEFORE the body is read.

        A route-level dependency rather than a check inside the handler: FastAPI
        resolves dependencies before validating body parameters, so the 401 is
        reached without the business name ever being looked at. That matters
        because the cold path answers a name that is already taken with a 409
        naming the tenant_id — an oracle an unauthenticated caller must not be
        able to consult. The refusal is identical whether or not the name would
        have collided, because the name is not read to produce it.
        """
        _authorize_provision(_provision_token(), authorization)
        # Authorization first: a caller who has not proved authority is told
        # nothing about how this host is configured.
        config_error = _provision_config_error(state.public_url, _provision_token(), _resolve_tenant_cap())
        if config_error is not None:
            raise HTTPException(status_code=503, detail=config_error)

    @app.post(
        "/provision",
        response_model=ProvisionResponse,
        status_code=201,
        dependencies=[Depends(_gate_provisioning)],
    )
    def provision(req: ProvisionRequest, request: Request) -> ProvisionResponse:
        # ATTRIBUTION, resolved once per request and threaded into whichever
        # path serves it — best-effort, and recorded as such (see
        # ``_caller_discriminator``); never used to authorize or refuse.
        caller = _caller_discriminator(request, _resolve_trusted_proxies())

        # FAST PATH (B4): claim a pre-warmed tenant — already minted before this
        # request arrived, so the request path does NO synchronous identity-mint.
        claimed = _claim_from_pool(state, req, caller)
        if claimed is not None:
            return claimed

        # GRACEFUL FALLBACK: pool disabled or drained → cold-provision on the
        # request thread (correctness over latency; never fail on a drained pool).
        return _cold_provision(state, req, caller)

    @app.get("/t/{tenant_id}/.well-known/agent.json")
    def agent_card(tenant_id: str) -> dict[str, Any]:
        tenant = state.tenants.get(tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail=f"no tenant {tenant_id!r}")
        return _build_tenant_card(tenant, community_member.__version__, state.public_url)

    @app.get("/t/{tenant_id}/agentfacts.json")
    def agent_facts(tenant_id: str) -> dict[str, Any]:
        """Canonical NANDA AgentFacts for this tenant.

        The A2A card's ``x-nanda`` bag advertises ``<endpoint>/agentfacts.json``
        whenever a did is present, which for a provisioned tenant is always. The
        host did not mount the route, so the one link from a published card to
        the agent's AgentFacts resolved to a 404 — and host39's
        ``check_agentfacts_pointer`` already probes exactly that URL, so the
        pointer was checked and the target was missing.

        Built by the same ``build_self_agentfacts`` the agent runtime serves at
        its own ``/agentfacts.json``, from THIS tenant's config, so the two
        surfaces cannot describe the same agent differently.

        ``supports_streaming=False`` / ``authentication_methods=["none"]`` /
        ``provider_*``: the same three overrides ``_build_tenant_card`` passes
        to the A2A card, from the same sources — this host mounts plain REST
        routes with no JSON-RPC streaming and no auth dependency on any tenant
        route, and it, not the tenant, operates the endpoint. Without them a
        consumer that reads AgentFacts instead of the card would see the two
        capability claims the card no longer makes, and would be told a
        different operator than the card names.
        """
        tenant = state.tenants.get(tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail=f"no tenant {tenant_id!r}")

        organization, provider_url = _operator_identity(state.public_url)
        facts = build_self_agentfacts(
            tenant.ctx.config,
            tenant.endpoint,
            # From the same table the card is built from, so the two documents
            # cannot name different capabilities for one tenant.
            exposed_skills=tenant_action_skill_names(),
            supports_streaming=False,
            authentication_methods=["none"],
            # From the same function the card is built from, for the same
            # reason — see _operator_identity for why the host, not the tenant.
            provider_organization=organization,
            provider_url=provider_url,
        )
        if facts is None:
            # sm-bridge is a hard dependency of the agent package this host
            # requires, so None means a broken install rather than a supported
            # configuration. Say that, instead of serving a thinner document
            # that would look like the real thing to a resolving client.
            raise HTTPException(
                status_code=503,
                detail="AgentFacts unavailable: sm-bridge is not installed in this host's environment",
            )
        result: dict[str, Any] = facts.model_dump(mode="json", exclude_none=True)
        return result

    @app.post("/t/{tenant_id}/book")
    def book(tenant_id: str, req: BookRequest, request: Request) -> dict[str, Any]:
        """Take a booking for a provisioned tenant and return a VERIFIABLE
        signed receipt.

        The booking is performed through THIS tenant's isolated
        :class:`AgentContext`, so the booking row and the signed
        ``appointment_booked`` ARP receipt land only under that tenant's home
        and the receipt is signed by that tenant's did:key. The full signed
        receipt is returned verbatim (exactly as persisted in the tenant's
        Agency Log), so a client can verify it offline with
        ``arp.verify_receipt`` — no trust in this server required.

        CONSENT GUARDRAIL: booking is a no-consent action (capabilities: []).
        This path never calls ``AgentContext.activate_consent`` and therefore
        never touches the process-global consent-ledger singleton — safe on a
        concurrent multi-tenant request path.
        """
        # Rate check BEFORE the tenant lookup, so probing for valid tenant ids
        # costs the prober the same as booking against a real one. Checking after
        # would leak existence through the differing status codes.
        retry_after = book_limiter.check(_caller_discriminator(request, _resolve_trusted_proxies()) or _UNATTRIBUTABLE)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail=(f"too many bookings from this source; retry in {retry_after}s ({_BOOK_RATE_ENV})."),
                headers={"Retry-After": str(retry_after)},
            )

        tenant = state.tenants.get(tenant_id)
        if tenant is None:
            raise HTTPException(status_code=404, detail=f"no tenant {tenant_id!r}")

        # A malformed body is the only client-side rejection here — booking has
        # no consent gate. Required fields are validated the same way the booking
        # skill does, but surfaced as a 400.
        service = (req.service or "").strip()
        provider = (req.provider or "").strip()
        datetime_ = (req.datetime or "").strip()
        supplied = {"service": service, "provider": provider, "datetime": datetime_}
        missing = [k for k in _BOOKING_REQUIRED_FIELDS if not supplied[k]]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"missing required field(s): {', '.join(missing)}",
            )

        # Book through the tenant's isolated context: the booking + the signed
        # receipt land under THIS tenant's home only, signed by THIS tenant's key.
        #
        # A failure here means the receipt could not be persisted, and since the
        # receipt is written BEFORE the booking is recorded, nothing was stored.
        # That is worth saying: the previous behaviour let the exception escape
        # to FastAPI's generic handler, so the caller got a bare "Internal Server
        # Error" and the operator got no indication which tenant failed or why.
        # The exception TYPE is reported, not its message — the endpoint is
        # unauthenticated, and the detail belongs in the log, not the response.
        try:
            result = tenant.ctx.book_appointment(
                service=service,
                provider=provider,
                datetime=datetime_,
                notes=(req.notes or "").strip(),
                contact=_contact_for(tenant),
                business_name=tenant.business_name,
            )
        except BookingStoreUnreadable as exc:
            # Separated from the transient case deliberately: retrying a damaged
            # store cannot succeed, and telling a caller to retry would have them
            # hammer a tenant that needs an operator. The store is left intact.
            logger.exception("book: tenant %s has an unreadable booking store", tenant_id)
            raise HTTPException(
                status_code=500,
                detail=(
                    f"tenant {tenant_id!r} has an unreadable booking store; no booking was "
                    f"stored and retrying will not help until an operator looks at it"
                ),
            ) from exc
        except Exception as exc:
            logger.exception("book: tenant %s could not record a booking", tenant_id)
            raise HTTPException(
                status_code=500,
                detail=(
                    f"tenant {tenant_id!r} could not record the booking "
                    f"({type(exc).__name__}); no booking was stored — safe to retry"
                ),
            ) from exc

        # A slot already taken is refused before anything is signed or stored, so
        # this is a client error and not a failure: nothing was written, and the
        # caller can retry at another time. Reported as 409 for the same reason a
        # duplicate business name is — the request is well formed and conflicts
        # with state that already exists.
        if result.get("error"):
            raise HTTPException(status_code=409, detail=result["error"])

        receipt_id = result.get("receipt_id")
        if not receipt_id:
            # A provisioned tenant always holds a valid Ed25519 key, so a missing
            # receipt means the signing path failed — a host-side fault, loud not
            # silent. (Keyless tenants cannot exist on this host.)
            #
            # The skill writes the attempt, then the booking, then the receipt.
            # Reaching here means the booking IS stored and the receipt stage
            # failed after it: the caller must be told the slot is held and not
            # to retry — a retry is refused as a duplicate — and which attempt
            # in the tenant's Agency Log is owed the receipt. The "no booking
            # was stored — safe to retry" branch above is for a failure BEFORE
            # the store write, and this one must not borrow its wording.
            note = result.get("receipt_note", "unknown reason")
            booking_id = (result.get("booked") or {}).get("id")
            raise HTTPException(
                status_code=500,
                detail=(
                    f"tenant {tenant_id!r} stored booking {booking_id} but could not record its "
                    f"receipt: {note}. The slot is held; do not retry — the receipt is owed against "
                    f"attempt {result.get('attempt_id')} in the tenant's Agency Log."
                ),
            )

        # Re-read the receipt exactly as persisted in the tenant's Agency Log, so
        # the object we hand back is byte-for-byte the signed receipt (its
        # signature re-canonicalizes and verifies offline under issuer_did).
        receipt = tenant.ctx.agency_log.get(receipt_id)
        if receipt is None:
            raise HTTPException(
                status_code=500,
                detail=f"receipt {receipt_id!r} was signed but not found in tenant {tenant_id!r} Agency Log",
            )

        booking = dict(result["booked"])
        # "recorded", not "confirmed": there is no acceptance step anywhere in
        # this path, and set here — before delivery is even consulted below —
        # so it ships alongside delivered: false in the same response.
        # "confirmed" told a reader the business had agreed to something;
        # "recorded" says what actually happened. Shared with smb_funnel via
        # smb_funnel/tests/host_contract.json's book_success.booking_status,
        # which both suites are held to.
        booking["status"] = "recorded"
        booking["tenant_id"] = tenant_id

        response: dict[str, Any] = {"booking": booking, "receipt_id": receipt_id, "receipt": receipt}
        # The delivery outcome travels with the booking rather than only into a
        # log. The booking is real and receipted either way, so this is not an
        # error — but a caller that is told nothing cannot tell a delivered
        # booking from one the business will never see.
        response["delivered"] = bool(result.get("delivered"))
        response["delivery_channel"] = result.get("delivery_channel", "none")
        if not result.get("delivered"):
            response["delivery_note"] = result.get("delivery_note", "delivery was not attempted")
            logger.warning(
                "book: tenant %s booking %s was not delivered: %s",
                tenant_id,
                booking.get("id"),
                response["delivery_note"],
            )
        return response

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
