"""Authentication for the local agent API.

The dashboard app serves the agent's control surface: the consent gate's
settings, the approval and denial records the gate enforces on, the LLM
provider and key, the profile the org sees. Every route requires a token
unless it is listed in :data:`OPEN_ROUTES`.

The default is deny. A route added to ``server.py`` is protected because
nobody did anything; exposing it takes an explicit entry in the list below,
which is why the list carries a reason per entry rather than a pattern.
``tests/test_local_api_auth_guard.py`` fails the build if a route is neither
protected nor declared, and if a declaration names a route that no longer
exists or has since been protected.

The token travels in a header — ``Authorization: Bearer <token>`` or
``X-Orrery-Local-Token``. It is deliberately not read from the query string
(it would land in logs, history and Referer headers) and not from a cookie
(a cookie is attached by the browser to cross-site requests, which would make
every state-changing route reachable from any page the user visits).

A caller that cannot set a header therefore cannot authenticate. That applies
to ``EventSource``, which the SSE routes below use: a browser page consuming
them needs a fetch-based reader with an explicit header, not a query-string
token. No page in this repository consumes them today.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

__all__ = [
    "OPEN_ROUTES",
    "LocalAuthMiddleware",
    "TOKEN_FILENAME",
    "is_open",
    "load_or_create_token",
    "read_request_token",
    "was_generated_this_process",
]

TOKEN_FILENAME = ".local-token"

# Overrides the file, for tests and for an operator who manages the secret
# elsewhere. Blank or unset means the file is authoritative.
TOKEN_ENV_VAR = "COMMUNITY_MEMBER_LOCAL_TOKEN"

# Set by load_or_create_token when it writes a new token; read by the CLI so
# the file's location is printed once rather than on every start.
_was_generated_this_process: bool = False

# Routes reachable without the local token, each with the reason it is open.
# Keyed by (method, path) because opening a path for GET must not also open it
# for POST. Every entry is an exact path; none of the open routes takes a path
# parameter.
OPEN_ROUTES: dict[tuple[str, str], str] = {
    # ── The agent's public identity. A peer or resolver fetches these
    # before it can know how to sign anything, so requiring a credential
    # would make the agent undiscoverable.
    ("GET", "/.well-known/agent.json"): (
        "A2A AgentCard. A resolver fetches it unauthenticated to learn how to address this agent."
    ),
    ("GET", "/.well-known/agent-card.json"): (
        "The same A2A AgentCard at the path a current A2A client fetches. Open for the same "
        "reason as the line above, and the omission is not academic: before it was listed "
        "here the route answered 401 rather than 404, so a stock client's discovery failed "
        "on the credential rather than on the path."
    ),
    ("GET", "/.well-known/agent-lifecycle.json"): (
        "Lifecycle state a peer reads to decide whether this agent is still transacting."
    ),
    ("GET", "/.well-known/conformance.json"): (
        "Signed conformance badge. Offline-verifiable against the embedded did:key; "
        "gating a public proof defeats its purpose."
    ),
    ("GET", "/.well-known/reputation.json"): "Published reputation credential, verifiable by its signature.",
    ("GET", "/agentfacts.json"): "AgentFacts document the Index and peers resolve.",
    # ── Liveness.
    ("GET", "/api/health"): "Liveness probe. Reports no agent state; the Compose healthcheck calls it.",
    # ── Protocol and platform surfaces whose callers hold no local token.
    ("POST", "/"): (
        "A2A JSON-RPC endpoint. The caller is a peer agent, which has no local token, so a "
        "local-token check is the wrong credential here and would refuse every legitimate peer. "
        "This endpoint performs no caller authentication of its own — that is a separate open "
        "question about the A2A surface, not something this middleware can close without "
        "breaking the protocol."
    ),
    ("POST", "/webhooks/platform/{platform}/uninstall"): (
        "Commerce-platform uninstall callback. The caller is a platform with no agent "
        "credentials. Open by route, closed by signature: the handler requires a valid HMAC "
        "over a configured per-platform secret and refuses every request when no secret is set."
    ),
}


def load_or_create_token(home: Path) -> str:
    """Return the local API token, generating and persisting one if absent.

    The file is created with mode 0600 at open() time rather than chmod'ed
    afterwards, so it is never briefly world-readable. An install that predates
    this file gets a token on next start with no operator action.

    Sets :func:`was_generated_this_process` when it writes a new token, so a
    caller can tell the operator where the file is exactly once — the same
    split server/admin.py uses for the org admin token.
    """
    global _was_generated_this_process

    override = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if override:
        _was_generated_this_process = False
        return override

    path = Path(home) / TOKEN_FILENAME
    try:
        existing = path.read_text().strip()
    except (FileNotFoundError, NotADirectoryError):
        existing = ""
    if existing:
        _was_generated_this_process = False
        return existing

    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    # O_CREAT honours the mode only when it creates the file; a pre-existing
    # empty file keeps whatever mode it had.
    os.chmod(path, 0o600)
    _was_generated_this_process = True
    return token


def was_generated_this_process() -> bool:
    """True iff the most recent :func:`load_or_create_token` wrote a new token.

    The operator needs the file's location once, when the thing comes into
    existence and they have to go find it. Printing it on every start puts it
    into every scrollback, log capture and screen share for no further benefit.
    """
    return _was_generated_this_process


def is_open(method: str, path: str) -> bool:
    """True iff (method, path) is declared in :data:`OPEN_ROUTES`."""
    return (method.upper(), path) in OPEN_ROUTES


def read_request_token(request: Request) -> str:
    """Extract the presented token from the request headers.

    Header only. See the module docstring for why the query string and cookies
    are not consulted.
    """
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (request.headers.get("x-orrery-local-token") or "").strip()


class LocalAuthMiddleware(BaseHTTPMiddleware):
    """Require the local token on every route not in :data:`OPEN_ROUTES`."""

    def __init__(self, app, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()

        # CORS preflight carries no credentials by definition and reveals no
        # agent state; refusing it would break the browser before the real
        # request is ever sent.
        if method == "OPTIONS":
            return await call_next(request)

        # Match on the matched route template, not the concrete path, so a
        # declaration cannot be sidestepped by a path parameter.
        path = _route_template(request) or request.url.path
        if is_open(method, path):
            return await call_next(request)

        presented = read_request_token(request)
        if not presented or not hmac.compare_digest(
            presented.encode("utf-8"),
            self._token.encode("utf-8"),
        ):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "local_token_required",
                    "detail": (
                        "This endpoint controls the local agent. Send the token from "
                        f"~/.community-member/{TOKEN_FILENAME} as 'Authorization: Bearer <token>'."
                    ),
                },
            )
        return await call_next(request)


def _route_template(request: Request) -> str | None:
    """The path template of the route this request matches, e.g.
    ``/api/local/memory/{index}``. None when no route matches."""
    from starlette.routing import Match

    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            return getattr(route, "path", None)
    return None
