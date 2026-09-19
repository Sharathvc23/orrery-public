"""smb_signup — the public front door: it serves the funnel and it BOUNDS signup.

⚠️ WHY THIS IS NOT "HIDE THE TOKEN". `smb_host` gates `POST /provision` on a
shared secret, and `smb_funnel` is a static bundle that cannot hold one — so the
obvious move is a server-side component that keeps the secret and forwards the
call. **That component, on its own, is exactly as open as publishing the token.**
One extra hop, same openness: anyone who can reach it can mint identities.

Measured on the deployed shape before this service existed: nothing else bounds
provisioning. There is no rate limiting in `smb_host`, `SMB_HOST_POOL_SIZE`
bounds pre-warming rather than the total, the cold path mints on demand with no
cap, and there is no expiry or per-source accounting. Driven at `origin/main`
c920702 with a valid token, a loop provisioned **60 tenants in 3.7 s and was never
refused** — about 20 KB of key material each. The token was the only bound there
has ever been, so removing it without replacing it opens the door rather than
widening it.

WHAT IS ACTUALLY AT RISK: each provision mints an Ed25519 keypair, writes an
encrypted vault to a persistent volume, and creates a permanent tenant. Unbounded
means unlimited identities issued under this operator's vouching, on a disk
filling with key material nobody can attribute. The cost is identity issuance and
storage, not CPU, so the bound is sized against tenants and disk rather than
requests per second.

SO THE BOUND IS THE UNIT. Two of them, and the service REFUSES TO PROVISION AT ALL
unless they are configured — the façade cannot exist without them:

  * a per-source rate limit (`SMB_SIGNUP_RATE_PER_HOUR`), and
  * a total tenant cap (`SMB_SIGNUP_TENANT_CAP`), counted from the host's own
    authoritative tenant count rather than from anything this process remembers,
    so a redeploy of this service does not reset the bound.

Both are observable: `GET /health` reports the cap, the count and the headroom, so
exhaustion is visible before a business is turned away rather than after. It also
reports `caller_attribution`, for the reason given below.

WHY A FAÇADE OF THE WHOLE CONTRACT rather than one signup route: the funnel then
needs no new configuration switch. This service SERVES the bundle, so the page a
visitor is handed is already talking to its own origin and needs no `API_BASE` at
all — and it speaks the contract it already speaks. Pointing a SEPARATELY-SERVED
page at this origin is not a supported shape: no CORS middleware is mounted here,
deliberately (see `test_the_facade_answers_no_cross_origin_caller` and
`smb_funnel/src/config.js`). Card reads and bookings are relayed untouched and
only `POST /provision` is bounded and re-credentialed. An `Authorization` header
supplied by a browser is DISCARDED here, never forwarded — the credential on the
wire to the host is this service's, or there is none.

⚠️ AND THE CALLER IS STATED TO THE HOST, BECAUSE A RELAY DESTROYS ATTRIBUTION BY
DEFAULT. `smb_host` records `provisioned_by` from the caller it can see. Every
request it sees from here arrives on THIS service's socket, so before this
service forwarded anything the host recorded its own peer — measured: three
distinct public visitors through the front door and one operator calling the host
directly, all four recorded as `127.0.0.1`. The cap still said HOW MANY had been
issued; nothing said BY WHOM, on exactly the deployment where by-whom starts to
matter.

WHICH SERVICE IS AUTHORITATIVE, AND WHY IT IS THIS ONE. This service terminates
the visitor's connection, so it is the only party that sees the socket the
request actually arrived on, and it ALREADY has to decide who the caller is in
order to rate-limit them. Attribution therefore reuses that decision rather than
making a second one: `client_source` is called ONCE per provision and the value
it returns is both the rate-limit bucket and the address forwarded to the host.
Two determinations could disagree about who a caller is, and a bound that counted
one address while the record named another would be worse than no record.

WHAT GOES ON THE WIRE, IN BOTH CONFIGURATIONS. A SINGLE-ENTRY `X-Forwarded-For`
carrying that one resolved address, REPLACING whatever the caller sent — never
appending to it:

  * not behind a trusted proxy (`SMB_SIGNUP_TRUSTED_PROXIES` unset or 0): the
    resolved address is this service's socket peer and any inbound
    `X-Forwarded-For` is discarded unread, so a caller cannot write its own
    attribution.
  * behind N trusted hops: the resolved address is the Nth-from-the-right entry
    of the real proxy chain — the same entry the rate limit counts against. An
    address a caller prepends sits to the LEFT of what the real proxy appended
    and is never selected.

Appending instead of replacing is the version that must not be written: it hands
the caller a plausible forged address on the record, which is strictly worse than
`127.0.0.1`, because a single obviously-wrong value is visibly wrong and a
plausible one is not.

WHAT THE HOST DOES WITH IT is the host's own decision and it is the fail-closed
one: `smb_host` ignores `X-Forwarded-For` entirely unless `SMB_HOST_TRUSTED_PROXIES`
is at least 1, because a header from a peer it was not told to trust is exactly
what it must not believe. So the two halves are separately correct and the pair
is silently useless when the host half is unset — which is why `GET /health`
reports whether the host is configured to record what this service states.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ── configuration ────────────────────────────────────────────────────────────
#
# Every one of these follows the same rule the rest of this tree uses: UNSET and
# EMPTY are the same thing, and neither is a permissive default. A bound that
# defaults to "no bound" is not a bound.

_HOST_URL_ENV = "SMB_SIGNUP_HOST_URL"
_TOKEN_ENV = "SMB_HOST_PROVISION_TOKEN"
_CAP_ENV = "SMB_SIGNUP_TENANT_CAP"
_RATE_ENV = "SMB_SIGNUP_RATE_PER_HOUR"
_TRUST_PROXIES_ENV = "SMB_SIGNUP_TRUSTED_PROXIES"

# What ``client_source`` returns when no caller signal is usable at all. It has
# to be a non-empty string because it is a rate-limit BUCKET KEY, and it is
# deliberately not an address so that it can never be mistaken for one on a
# record downstream — nothing that looks resolved is ever forwarded.
_UNRESOLVED_SOURCE = "unknown"

_BUNDLE = Path(__file__).resolve().parent.parent / "smb_funnel"


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _positive_int(name: str) -> int | None:
    """A configured positive integer, or None when unset, empty or unusable.

    None is never treated as "unlimited" by any caller here — it is treated as
    "not configured", which refuses. A typo in a bound must not disable it.
    """
    raw = _env(name)
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


class SignupRequest(BaseModel):
    """The shape the host expects, mirrored so a malformed request stops here.

    ⚠️ THE SHAPE IS MIRRORED; THE CONTACT'S MEANING IS NOT RE-JUDGED. `contact` is
    required because the host requires it — a business that cannot be reached
    cannot receive a booking, so provisioning without one ships the outcome the
    booking work removed. But WHAT counts as a usable contact is the host's rule,
    derived from what its delivery path can actually deliver on, and a second
    opinion here could accept something the host would refuse or refuse something
    it would take. Same reasoning as leaving confusable names to the host: a check
    that does not own the thing it checks lets two services disagree.
    """

    business_name: str = Field(..., min_length=1)
    service_type: str | None = None
    contact: str = Field(..., min_length=1)


# ── per-source rate limiting ─────────────────────────────────────────────────


class RateLimiter:
    """A fixed-size sliding window of request times per source.

    Deliberately in-process and deliberately not the total bound. It slows a
    single source down; it is the tenant cap that bounds the damage, because a
    process restart empties this and a distributed source never fills it. Saying
    which of the two is load-bearing matters: a rate limit alone would be a
    control that looks like a cap and is not one.
    """

    def __init__(self, per_hour: int) -> None:
        self.per_hour = per_hour
        self._seen: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, source: str, now: float | None = None) -> int:
        """Return 0 if allowed, else the seconds to wait before retrying."""
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


def client_source(request: Request, trusted_proxies: int) -> str:
    """Which source a request is attributed to, given N trusted proxies.

    ⚠️ `X-Forwarded-For` IS CLIENT-SUPPLIED unless something in front rewrites it,
    so trusting it by default would let one caller mint a fresh identity per
    request and defeat the per-source limit entirely. The default is therefore to
    trust nothing and use the socket peer.

    Behind a load balancer that means every request shares one source and the
    limit becomes global — more restrictive, not less, which is the direction an
    unconfigured deployment should err in. Set `SMB_SIGNUP_TRUSTED_PROXIES` to the
    number of hops you actually run and the Nth-from-the-right entry is used.
    """
    if trusted_proxies > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(chain) >= trusted_proxies:
            return chain[-trusted_proxies]
    return request.client.host if request.client else _UNRESOLVED_SOURCE


def caller_forwarding_headers(source: str) -> dict[str, str]:
    """The attribution this service STATES to the host about one caller.

    ⚠️ A SINGLE ENTRY, REPLACING WHATEVER ARRIVED. ``source`` is what
    ``client_source`` resolved under this service's own declared hop count, so an
    ``X-Forwarded-For`` the caller supplied has already been either discarded
    (no trusted hops) or overridden by the real proxy's appended entry. Emitting
    exactly one entry means the host reads a deterministic chain: with
    ``SMB_HOST_TRUSTED_PROXIES=1`` the rightmost entry is this value and nothing
    else can appear to its right.

    ⚠️ NOTHING IS FORWARDED WHEN NOTHING WAS RESOLVED. The sentinel is a bucket
    key, not an address; sending it would put a token that is not an address into
    a header whose entries are read as addresses, and the host would store it as
    though attribution had succeeded. Omitting the header instead leaves the host
    on its own socket peer — which is this service, an honest and checkable
    answer — rather than on a word that looks like a resolution and is not.
    """
    if source == _UNRESOLVED_SOURCE:
        return {}
    return {"X-Forwarded-For": source}


# ── is the attribution this service states actually recorded? ────────────────

_ATTRIBUTION_RECORDED = "recorded"
_ATTRIBUTION_DISCARDED = "discarded-by-host"
_ATTRIBUTION_UNKNOWN = "unknown"


def _attribution_state(host_health_body: dict[str, Any]) -> str:
    """Whether the caller this service forwards actually lands on the record.

    ⚠️ FORWARDING IS HALF A CONTROL, AND THE OTHER HALF IS ON A DIFFERENT
    SERVICE. This service states one caller per provision; ``smb_host`` records
    it only while ``SMB_HOST_TRUSTED_PROXIES`` is at least 1, because a header
    from a peer it was not told to trust is precisely what it must ignore. Both
    halves are right on their own and the pair does nothing when the host half is
    unset: provisions still succeed, the record still fills in, and every row
    says this service's own socket address. That is the defect this work exists
    to remove, wearing the appearance of a fix.

    So the mismatch is READ OFF ``/health`` rather than discovered later from a
    directory of identical attributions. ``unknown`` when the host cannot be
    reached or is too old to report its hop count — never guessed, for the same
    reason ``headroom`` is not.
    """
    hops = host_health_body.get("trusted_proxies")
    if not isinstance(hops, int) or isinstance(hops, bool):
        return _ATTRIBUTION_UNKNOWN
    return _ATTRIBUTION_RECORDED if hops >= 1 else _ATTRIBUTION_DISCARDED


# ── the app ──────────────────────────────────────────────────────────────────


def create_app() -> FastAPI:
    app = FastAPI(title="smb-signup", docs_url=None, redoc_url=None)
    limiter_box: dict[str, RateLimiter] = {}

    def host_url() -> str:
        return _env(_HOST_URL_ENV).rstrip("/")

    def configuration_error() -> str | None:
        """Why this service cannot provision, or None if it can.

        ⚠️ THE ORDER IS NOT ARBITRARY. The bounds are checked as sternly as the
        credential, because a façade with a token and no bound is the failure this
        service exists to prevent — it would look like a control and be an open
        door with extra latency.
        """
        if not host_url():
            return f"{_HOST_URL_ENV} is not set, so this service does not know which host to provision on."
        if not _env(_TOKEN_ENV):
            return (
                f"{_TOKEN_ENV} is not set. This service exists to hold that credential on behalf of a "
                f"static page; without it there is nothing to hold and provisioning would be unauthenticated."
            )
        if _positive_int(_CAP_ENV) is None:
            return (
                f"{_CAP_ENV} is not set to a positive integer. Provisioning mints a keypair and writes a "
                f"vault to disk, and this service is the only thing bounding how many. Refusing rather "
                f"than serving an unbounded front door."
            )
        if _positive_int(_RATE_ENV) is None:
            return f"{_RATE_ENV} is not set to a positive integer, so no per-source limit would apply."
        return None

    def limiter() -> RateLimiter:
        per_hour = _positive_int(_RATE_ENV) or 0
        current = limiter_box.get("l")
        if current is None or current.per_hour != per_hour:
            current = RateLimiter(per_hour)
            limiter_box["l"] = current
        return current

    async def host_health(client: httpx.AsyncClient) -> dict[str, Any]:
        """The host's own health body — the authority on its own state."""
        resp = await client.get(f"{host_url()}/health", timeout=10.0)
        resp.raise_for_status()
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def host_tenant_count(client: httpx.AsyncClient) -> int:
        """The host's own tenant count — the authority on how full the disk is.

        Read from the host rather than counted here on purpose: a redeploy of this
        service would reset an in-process tally, and a cap that resets is not a
        cap. It also counts tenants provisioned by the operator path, which occupy
        the same disk.
        """
        return int((await host_health(client)).get("tenants", 0))

    @app.get("/health")
    async def health() -> dict[str, Any]:
        """Headroom, readable without provisioning anything.

        ⚠️ THE CAP IS ONLY A CONTROL IF SOMEONE CAN SEE IT COMING. Reported here
        so a canary or an operator learns the front door is nearly full before a
        business is turned away, rather than from the first refusal.
        """
        cap = _positive_int(_CAP_ENV)
        body: dict[str, Any] = {
            "status": "ok",
            "service": "smb-signup",
            "configured": configuration_error() is None,
            "tenant_cap": cap,
            "rate_per_hour": _positive_int(_RATE_ENV),
        }
        if cap is not None and host_url():
            try:
                async with httpx.AsyncClient() as client:
                    host_body = await host_health(client)
                used = int(host_body.get("tenants", 0))
                body["tenants"] = used
                body["headroom"] = max(0, cap - used)
                body["at_capacity"] = used >= cap
                body["caller_attribution"] = _attribution_state(host_body)
            except Exception as exc:
                # Unreachable host is reported, never guessed at. A health surface
                # that invents a headroom is worse than one that admits ignorance.
                body["headroom"] = None
                body["caller_attribution"] = _ATTRIBUTION_UNKNOWN
                body["host_unreachable"] = str(exc)[:200]
        return body

    @app.post("/provision", status_code=201)
    async def provision(
        req: SignupRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        # ⚠️ A BROWSER-SUPPLIED CREDENTIAL IS DISCARDED, NOT FORWARDED. The
        # credential on the wire to the host is this service's or there is none;
        # `authorization` is accepted as a parameter only so that it cannot be
        # passed through by accident later.
        del authorization

        problem = configuration_error()
        if problem is not None:
            raise HTTPException(status_code=503, detail=problem)

        # ⚠️ RESOLVED ONCE, USED TWICE, ON PURPOSE. This single value is both the
        # rate-limit bucket and the address forwarded to the host, so the record
        # cannot name a caller the bound did not count. Two calls would be two
        # determinations that could drift apart under a later edit to either.
        source = client_source(request, _positive_int(_TRUST_PROXIES_ENV) or 0)

        wait = limiter().check(source)
        if wait:
            raise HTTPException(
                status_code=429,
                detail=(
                    "too many signups from this connection in the last hour. "
                    f"Try again in about {wait // 60 + 1} minute(s)."
                ),
                headers={"Retry-After": str(wait)},
            )

        cap = _positive_int(_CAP_ENV) or 0

        # ⚠️ FAIL CLOSED, AND THE GUARD COVERS OPENING THE CONNECTION TOO. Not
        # knowing the headroom is not permission to ignore the cap. An earlier
        # version put only the request inside the try, so a client that could not
        # be constructed escaped as a 500 rather than refusing — a bound that
        # disappears exactly when the thing it depends on is broken.
        try:
            async with httpx.AsyncClient() as client:
                used = await host_tenant_count(client)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"could not read the host's tenant count, so the cap cannot be honoured: {exc}",
            ) from exc

        # Raised OUTSIDE any try, so the refusal cannot be swallowed by a handler
        # written for a different failure.
        if used >= cap:
            raise HTTPException(
                status_code=507,
                detail=(
                    f"this service has issued its full allocation of agents ({used} of {cap}). "
                    f"No further signups until an operator raises the cap."
                ),
            )

        try:
            async with httpx.AsyncClient() as client:
                upstream = await client.post(
                    f"{host_url()}/provision",
                    json={
                        "business_name": req.business_name,
                        "service_type": req.service_type,
                        "contact": req.contact,
                    },
                    # ⚠️ THE CALLER IS STATED, NOT RELAYED. `caller_forwarding_headers`
                    # emits one entry — the address resolved above — replacing
                    # anything the caller sent, so a request cannot choose the
                    # attribution the host writes down. See the module docstring
                    # for what each configuration puts on this wire.
                    headers={
                        "Authorization": f"Bearer {_env(_TOKEN_ENV)}",
                        **caller_forwarding_headers(source),
                    },
                    timeout=60.0,
                )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"the host could not be reached: {exc}") from exc
        return JSONResponse(status_code=upstream.status_code, content=upstream.json())

    # ── relayed, unbounded on purpose: reading a card and making a booking mint
    # nothing and write no key material, so they carry no credential and no cap.
    @app.get("/t/{tenant_id}/.well-known/agent.json")
    async def card(tenant_id: str) -> JSONResponse:
        return await _relay("GET", f"/t/{tenant_id}/.well-known/agent.json", None)

    @app.post("/t/{tenant_id}/book")
    async def book(tenant_id: str, body: dict[str, Any]) -> JSONResponse:
        return await _relay("POST", f"/t/{tenant_id}/book", body)

    async def _relay(method: str, path: str, body: dict[str, Any] | None) -> JSONResponse:
        if not host_url():
            raise HTTPException(status_code=503, detail=f"{_HOST_URL_ENV} is not set.")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.request(method, f"{host_url()}{path}", json=body, timeout=60.0)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"the host could not be reached: {exc}") from exc
        return JSONResponse(status_code=resp.status_code, content=resp.json())

    # ── the funnel bundle, served from this origin ───────────────────────────
    if _BUNDLE.is_dir():
        @app.get("/")
        async def index() -> FileResponse:
            return FileResponse(_BUNDLE / "index.html")

        app.mount("/src", StaticFiles(directory=_BUNDLE / "src"), name="src")
        app.mount("/", StaticFiles(directory=_BUNDLE), name="bundle")

    return app


app = create_app()
