"""Publish an Orrery agent's **A2A agent card** to a host39 card host (Leg B).

WHICH ARTIFACT — read this before touching the code
===================================================
Orrery has two descriptor artifacts and they are NOT interchangeable:

* **A2A agent card** — :func:`community_member.a2a_card.build_agent_card`.
  Fields: ``name / description / url / version / provider / capabilities /
  authentication{schemes,credentials} / skills`` (+ an ``x-nanda`` extension bag).
* **canonical NANDA AgentFacts** — :func:`community_member.sm_bridge_adapter.
  build_self_agentfacts`, sm-bridge's ``SmAgentFacts``, served at
  ``GET /agentfacts.json``. Fields: ``id / agent_name / handle / label /
  endpoints / capabilities{modalities,skills,authentication} / skills``.

**host39 accepts the A2A card, not AgentFacts.** This is settled by host39's own
OpenAPI (``GET /docs/json``): ``POST /cards`` declares
``additionalProperties: false`` over exactly

    slug, display_name, description, runtime_url, version, capabilities,
    authentication, skills, provider_name, provider_url, is_public,
    monitoring_enabled

which is the A2A card flattened (``provider`` split into ``provider_name`` /
``provider_url``, ``url`` renamed ``runtime_url``, plus a host39-local ``slug``).
None of AgentFacts' distinctive fields (``id``, ``agent_name``, ``handle``,
``label``, ``endpoints``) exist in that schema, and ``additionalProperties:
false`` means a request carrying them is rejected outright rather than
truncated. host39 then serves the result as ``application/a2a-agent-card+json``.

So: **AgentFacts needs its own home, and already has one** — the agent runtime's
``GET /agentfacts.json``. The card published here only *points back* at it, via
the ``x-nanda`` bag (see ``include_nanda_extension`` on
:func:`a2a_card_to_host39_body` for how, and why it cannot ride at top level).

FAIL CLOSED: EMPTY IS NOT "CONFIGURED WITH NOTHING"
===================================================
An **empty** env var is treated identically to an **unset** one, and neither
falls through to a default or to an unauthenticated call. Specifically:

* :data:`BASE_URL_ENV` has **no default**. There is deliberately no fallback to
  the live ``agentcards.host39.org`` — an operator who has not named a target
  publishes nowhere. (``REGISTRY_URL=`` once meant LIVE PRODUCTION in this repo
  and put 31 phantom records into a public registry. Not again.)
* :class:`Host39Client` refuses to exist without a non-empty bearer token, so
  there is no code path on which a request leaves this module unauthenticated.
* Nothing here runs on import, on app startup, or on ``POST /provision``.
  Publishing is an explicit operator call (see ``scripts/publish_host39_card.py``).

Secrets never appear in an exception message, a log line, or a ``repr`` — errors
name the **env var**, never its value.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

# ── env contract ────────────────────────────────────────────────────────────────
# Read from the environment ONLY. Credentials are never read from a file by this
# module and never written to one.
BASE_URL_ENV = "HOST39_BASE_URL"
TOKEN_ENV = "HOST39_TOKEN"
EMAIL_ENV = "HOST39_EMAIL"
PASSWORD_ENV = "HOST39_PASSWORD"

#: What host39 serves a published card as.
CARD_MEDIA_TYPE = "application/a2a-agent-card+json"

#: host39's own slug pattern + length cap (from its OpenAPI schema), mirrored so a
#: bad slug fails locally with a clear message instead of as a remote 400.
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SLUG_MAX_LEN = 64

# Remaining host39 maxLength caps we mirror. Overflow raises — never silently
# truncates, because a truncated display_name or runtime_url publishes a subtly
# WRONG card, which is worse than a refused one.
_MAX_LENS = {
    "display_name": 255,
    "runtime_url": 512,
    "version": 32,
    "provider_name": 255,
    "provider_url": 512,
}

_DEFAULT_TIMEOUT = 20.0


class Host39Error(RuntimeError):
    """Base class for every failure raised by this module."""


class Host39ConfigError(Host39Error):
    """Configuration is missing or incomplete. Names the env var, never its value."""


class Host39AuthError(Host39Error):
    """No usable credential, or host39 rejected the one supplied."""


class Host39PublishError(Host39Error):
    """host39 refused the card, or the published card failed verification."""


# ── the fail-closed env primitive ───────────────────────────────────────────────


def env_or_none(name: str) -> str | None:
    """The value of ``name``, or None if it is unset, empty, or whitespace-only.

    This is the ONE place the unset-vs-empty question is answered, so every
    caller inherits the same answer: **they are identical**. A variable set to
    ``""`` is not "configured with a blank value" — it is not configured.
    """
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def resolve_base_url() -> str | None:
    """The configured host39 base URL, or None.

    **No default.** Returning None means "publish nowhere", not "publish to the
    live host". Callers must treat None as a refusal.
    """
    value = env_or_none(BASE_URL_ENV)
    return value.rstrip("/") if value else None


def resolve_token() -> str | None:
    """A pre-minted host39 JWT from the environment, or None."""
    return env_or_none(TOKEN_ENV)


def resolve_login() -> tuple[str, str] | None:
    """``(email, password)`` from the environment, or None if either is absent.

    A half-set login (email but no password) is *not* configured — it must not
    degrade into an anonymous call.
    """
    email = env_or_none(EMAIL_ENV)
    password = env_or_none(PASSWORD_ENV)
    if email and password:
        return email, password
    return None


def publishing_configured() -> bool:
    """True only when a target AND a credential are both explicitly present.

    Use this to decide whether to attempt anything at all. It is False for every
    unset-or-empty combination, which is why no code path here can auto-fire.
    """
    return resolve_base_url() is not None and (resolve_token() is not None or resolve_login() is not None)


def missing_config() -> list[str]:
    """The env var names an operator still has to set, for a clear error/skip
    message. Names only — this never touches a value."""
    missing: list[str] = []
    if resolve_base_url() is None:
        missing.append(BASE_URL_ENV)
    if resolve_token() is None and resolve_login() is None:
        missing.append(f"{TOKEN_ENV} (or {EMAIL_ENV}+{PASSWORD_ENV})")
    return missing


# ── card mapping: A2A card → host39 POST /cards body ────────────────────────────


def _require_str(body: dict[str, Any], key: str, *, where: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise Host39PublishError(f"{where}: missing required field {key!r}")
    return value.strip()


def validate_slug(slug: str) -> str:
    """host39's slug rules, enforced locally."""
    candidate = (slug or "").strip()
    if not candidate:
        raise Host39PublishError("slug is required and must be non-empty")
    if len(candidate) > SLUG_MAX_LEN:
        raise Host39PublishError(f"slug {candidate!r} exceeds host39's {SLUG_MAX_LEN}-character limit")
    if not SLUG_PATTERN.match(candidate):
        raise Host39PublishError(
            f"slug {candidate!r} does not match host39's pattern {SLUG_PATTERN.pattern!r} "
            "(lowercase alphanumerics and hyphens, must not start with a hyphen)"
        )
    return candidate


def a2a_card_to_host39_body(
    card: dict[str, Any],
    *,
    slug: str,
    is_public: bool = True,
    include_nanda_extension: bool = True,
    require_runtime_url: bool = True,
    require_credentials: bool = True,
) -> dict[str, Any]:
    """Flatten an A2A agent card into host39's ``POST /cards`` body.

    ``card`` is the JSON-ready dict form of
    :func:`community_member.a2a_card.build_agent_card` — i.e. exactly what
    ``smb_host`` already serves at ``/t/<tenant>/.well-known/agent.json``, so the
    card host39 publishes and the card the runtime serves cannot drift.

    The mapping, field by field::

        A2A card                     →  host39 POST /cards
        ─────────────────────────────────────────────────────
        (n/a — host39-local)         →  slug
        name                         →  display_name
        description                  →  description
        url                          →  runtime_url      ← the live Orrery endpoint
        version                      →  version
        capabilities                 →  capabilities
        authentication{schemes,      →  authentication   ← credentials carries the did
                       credentials}
        skills                       →  skills
        provider.organization        →  provider_name
        provider.url                 →  provider_url
        (caller's choice)            →  is_public

    ``x-nanda`` has no top-level home: host39's schema is
    ``additionalProperties: false``, so sending it would get the whole request
    rejected. With ``include_nanda_extension`` (default True) the bag is carried
    inside the free-form ``capabilities`` object under the same ``x-nanda`` key,
    which preserves the two things a NANDA-aware reader wants — ``did`` and
    ``agentfacts_url`` (the pointer to canonical AgentFacts on the runtime) —
    while a plain A2A client ignores an unknown capabilities key. This is the one
    place this module departs from a literal field-for-field copy; pass
    ``include_nanda_extension=False`` for a strictly-declared body.

    Raises Host39PublishError on anything that would publish a wrong card: a
    missing runtime URL, a missing did credential, or a field over host39's
    length caps (overflow is never truncated).
    """
    where = "a2a_card_to_host39_body"
    body: dict[str, Any] = {
        "slug": validate_slug(slug),
        "display_name": _require_str(card, "name", where=where),
        "is_public": bool(is_public),
    }

    description = card.get("description")
    if isinstance(description, str) and description.strip():
        body["description"] = description.strip()

    runtime_url = card.get("url")
    if isinstance(runtime_url, str) and runtime_url.strip():
        body["runtime_url"] = runtime_url.strip()
    elif require_runtime_url:
        raise Host39PublishError(
            f"{where}: the A2A card has no 'url', so runtime_url would be null and the "
            "published card would point nowhere. host39 permits a null runtime_url; this "
            "publisher does not."
        )

    version = card.get("version")
    if isinstance(version, str) and version.strip():
        body["version"] = version.strip()

    capabilities = dict(card.get("capabilities") or {})

    authentication = dict(card.get("authentication") or {})
    credentials = authentication.get("credentials")
    if not (isinstance(credentials, str) and credentials.strip()):
        if require_credentials:
            raise Host39PublishError(
                f"{where}: authentication.credentials is empty, so the published card would "
                "carry no did. The whole point of Leg B is a card whose credentials name the "
                "tenant's did:key."
            )
    if authentication:
        body["authentication"] = authentication

    skills = card.get("skills")
    if isinstance(skills, list) and skills:
        body["skills"] = skills

    provider = card.get("provider") or {}
    if isinstance(provider, dict):
        organization = provider.get("organization")
        if isinstance(organization, str) and organization.strip():
            body["provider_name"] = organization.strip()
        provider_url = provider.get("url")
        if isinstance(provider_url, str) and provider_url.strip():
            body["provider_url"] = provider_url.strip()

    if include_nanda_extension:
        nanda = card.get("x-nanda")
        if isinstance(nanda, dict) and nanda:
            capabilities["x-nanda"] = nanda

    if capabilities:
        body["capabilities"] = capabilities

    for field, cap in _MAX_LENS.items():
        value = body.get(field)
        if isinstance(value, str) and len(value) > cap:
            raise Host39PublishError(
                f"{where}: {field} is {len(value)} characters, over host39's {cap}-character "
                f"limit. Refusing to truncate — a truncated {field} publishes a wrong card."
            )

    return body


def advertised_agentfacts_url(body: dict[str, Any]) -> str | None:
    """The canonical-AgentFacts URL a mapped body advertises, if any.

    host39 stores no AgentFacts of its own, so this pointer is the ONLY link from
    a published card back to the runtime's ``GET /agentfacts.json``.
    """
    capabilities = body.get("capabilities")
    nanda = capabilities.get("x-nanda") if isinstance(capabilities, dict) else None
    url = nanda.get("agentfacts_url") if isinstance(nanda, dict) else None
    return url.strip() if isinstance(url, str) and url.strip() else None


def check_agentfacts_pointer(body: dict[str, Any], *, timeout: float = _DEFAULT_TIMEOUT) -> str | None:
    """Warn if the card advertises an ``agentfacts_url`` that does not resolve.

    :func:`community_member.a2a_card.build_agent_card` sets ``agentfacts_url``
    unconditionally whenever a did is present, but a host only serves it if it
    actually mounts the AgentFacts route. ``smb_host`` currently does **not**, so
    a tenant card advertises a pointer that 404s. Publishing that to host39 would
    ship a dead link — loud, not silent. Returns None when the pointer resolves
    or when the card advertises none.
    """
    url = advertised_agentfacts_url(body)
    if not url:
        return None
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError as exc:
        return f"advertised agentfacts_url {url} is unreachable ({type(exc).__name__})"
    if response.status_code != 200:
        return (
            f"advertised agentfacts_url {url} returns HTTP {response.status_code} — the published "
            "card would point at AgentFacts that are not served. host39 stores no AgentFacts of "
            "its own, so this pointer is the only link to them."
        )
    return None


def published_card_url(
    base_url: str,
    *,
    slug: str,
    identity_type: str | None,
    handle: str | None,
    domain: str | None,
) -> str:
    """Where host39 will serve the card, derived from the account's own identity.

    Taken from ``GET /auth/me`` rather than guessed, so a domain account and a
    personal (email-identity) account each get the route host39 actually
    registers: ``/{domain}/{slug}.json`` vs ``/personal/{handle}/{slug}.json``.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise Host39ConfigError(f"{BASE_URL_ENV} is unset or empty; no card URL can be derived")
    safe_slug = validate_slug(slug)
    safe_domain = (domain or "").strip()
    safe_handle = (handle or "").strip()
    if (identity_type or "").strip().lower() == "domain":
        if not safe_domain:
            raise Host39PublishError(
                "account identity_type is 'domain' but the account carries no domain; "
                "host39 cannot serve a domain card without one"
            )
        return f"{base}/{safe_domain}/{safe_slug}.json"
    if not safe_handle:
        raise Host39PublishError("account has no handle; a personal card URL cannot be derived")
    return f"{base}/personal/{safe_handle}/{safe_slug}.json"


# ── public, unauthenticated probe ───────────────────────────────────────────────


@dataclass(frozen=True)
class FetchedCard:
    """The result of an **unauthenticated** GET of a published card URL.

    Unauthenticated on purpose: a 2xx from ``POST /cards`` proves only that
    host39 accepted a row. Fetching the public URL with no bearer token is what
    proves the card is actually *published*.
    """

    url: str
    status_code: int
    content_type: str
    body: dict[str, Any] | None
    raw: str

    @property
    def is_a2a_media_type(self) -> bool:
        return self.content_type.split(";")[0].strip().lower() == CARD_MEDIA_TYPE


def fetch_published_card(url: str, *, timeout: float = _DEFAULT_TIMEOUT) -> FetchedCard:
    """GET a published card URL with no credentials at all."""
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    raw = response.text
    parsed: dict[str, Any] | None
    try:
        candidate = response.json()
        parsed = candidate if isinstance(candidate, dict) else None
    except ValueError:
        parsed = None
    return FetchedCard(
        url=url,
        status_code=response.status_code,
        content_type=response.headers.get("content-type", ""),
        body=parsed,
        raw=raw,
    )


def verify_published_card(
    fetched: FetchedCard,
    *,
    expected_runtime_url: str,
    expected_did: str,
) -> list[str]:
    """Check a fetched card against what Leg B promises. Returns a list of
    problems — empty means it passed.

    Deliberately returns findings instead of raising on the first one, so an
    operator sees every mismatch in a single run.
    """
    problems: list[str] = []
    if fetched.status_code != 200:
        problems.append(f"GET {fetched.url} returned {fetched.status_code}, expected 200")
        return problems
    if not fetched.is_a2a_media_type:
        problems.append(f"content-type is {fetched.content_type!r}, expected {CARD_MEDIA_TYPE!r}")
    body = fetched.body
    if body is None:
        problems.append("response body is not a JSON object")
        return problems

    # host39 may serve the runtime URL either flattened (its own storage shape)
    # or re-expanded into the A2A 'url' field. Accept whichever it emits.
    served_runtime = body.get("runtime_url") or body.get("url")
    if served_runtime != expected_runtime_url:
        problems.append(f"runtime_url is {served_runtime!r}, expected {expected_runtime_url!r}")

    auth = body.get("authentication")
    served_did = auth.get("credentials") if isinstance(auth, dict) else None
    if served_did != expected_did:
        problems.append(f"authentication.credentials is {served_did!r}, expected the tenant did {expected_did!r}")
    return problems


# ── authenticated client ────────────────────────────────────────────────────────


def login(base_url: str, email: str, password: str, *, timeout: float = _DEFAULT_TIMEOUT) -> str:
    """Exchange email+password for a host39 JWT via ``POST /auth/login``.

    Raises Host39AuthError on rejection. The password is never echoed, and the
    returned token is never logged by this module.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise Host39ConfigError(f"{BASE_URL_ENV} is unset or empty; refusing to log in to an unnamed host")
    if not (email or "").strip() or not (password or "").strip():
        raise Host39AuthError(f"{EMAIL_ENV} and {PASSWORD_ENV} must both be set and non-empty to log in")
    response = httpx.post(
        f"{base}/auth/login",
        json={"email": email.strip(), "password": password},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise Host39AuthError(
            f"host39 login failed with {response.status_code} "
            f"(check {EMAIL_ENV} / {PASSWORD_ENV}; the values are not shown here)"
        )
    token = ""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            token = str(payload.get("token") or "")
    except ValueError:
        token = ""
    if not token.strip():
        raise Host39AuthError("host39 login returned 200 but no token")
    return token.strip()


@dataclass(frozen=True)
class PublishResult:
    """Everything an operator needs to believe the card is live."""

    card_id: str | None
    slug: str
    card_url: str
    runtime_url: str
    did: str
    status: str | None
    fetched: FetchedCard
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


class Host39Client:
    """An authenticated host39 client. **Cannot be built without a token.**"""

    def __init__(self, base_url: str, token: str, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        base = (base_url or "").strip().rstrip("/")
        if not base:
            raise Host39ConfigError(
                f"{BASE_URL_ENV} is unset or empty. There is no default host39 target — "
                "an unnamed target means publish nowhere, never publish to production."
            )
        # The fail-closed hinge: an empty token cannot become an anonymous call.
        cleaned = (token or "").strip()
        if not cleaned:
            raise Host39AuthError(
                f"refusing to build a host39 client without a bearer token: set {TOKEN_ENV} "
                f"(or {EMAIL_ENV}+{PASSWORD_ENV}). An empty token is treated as no token."
            )
        self.base_url = base
        self._token = cleaned
        self._timeout = timeout

    def __repr__(self) -> str:  # pragma: no cover - trivial, but must not leak
        return f"Host39Client(base_url={self.base_url!r}, token=<redacted>)"

    @classmethod
    def from_env(cls, *, timeout: float = _DEFAULT_TIMEOUT) -> Host39Client:
        """Build from the environment, or raise naming what is missing.

        Prefers :data:`TOKEN_ENV`; falls back to a login with
        :data:`EMAIL_ENV`/:data:`PASSWORD_ENV`. Never falls back to anonymous.
        """
        base_url = resolve_base_url()
        if base_url is None:
            raise Host39ConfigError(
                f"{BASE_URL_ENV} is unset or empty (the two are identical here). "
                "Set it explicitly to the host39 base URL you intend to publish to."
            )
        token = resolve_token()
        if token is None:
            credentials = resolve_login()
            if credentials is None:
                raise Host39ConfigError(
                    f"no host39 credential: set {TOKEN_ENV}, or both {EMAIL_ENV} and "
                    f"{PASSWORD_ENV}. Unset and empty are treated identically."
                )
            token = login(base_url, credentials[0], credentials[1], timeout=timeout)
        return cls(base_url, token, timeout=timeout)

    # ── internals ──────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        # Re-assert the invariant at the point of use, so no future refactor can
        # ship a request without a credential.
        if not self._token:
            raise Host39AuthError("host39 client has no bearer token; refusing to send a request")
        return {"authorization": f"Bearer {self._token}", "content-type": "application/json"}

    def _request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> httpx.Response:
        return httpx.request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(),
            json=json_body,
            timeout=self._timeout,
        )

    # ── API surface ────────────────────────────────────────────────────────────

    def me(self) -> dict[str, Any]:
        """``GET /auth/me`` — the account's handle / identity_type / domain."""
        response = self._request("GET", "/auth/me")
        if response.status_code == 401:
            raise Host39AuthError(f"host39 rejected the credential from {TOKEN_ENV} (401)")
        if response.status_code != 200:
            raise Host39Error(f"GET /auth/me returned {response.status_code}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise Host39Error("GET /auth/me did not return an object")
        return payload

    def create_card(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /cards``. Raises Host39PublishError with host39's own reason."""
        response = self._request("POST", "/cards", json_body=body)
        if response.status_code == 401:
            raise Host39AuthError("host39 rejected the credential on POST /cards (401)")
        if response.status_code not in (200, 201):
            raise Host39PublishError(f"POST /cards returned {response.status_code}: {response.text[:400]}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise Host39PublishError("POST /cards did not return an object")
        return payload

    def update_card(self, card_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """``PUT /cards/{id}`` — used to make a re-publish idempotent."""
        response = self._request("PUT", f"/cards/{card_id}", json_body=body)
        if response.status_code == 401:
            raise Host39AuthError("host39 rejected the credential on PUT /cards/{id} (401)")
        if response.status_code not in (200, 201):
            raise Host39PublishError(f"PUT /cards/{card_id} returned {response.status_code}: {response.text[:400]}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise Host39PublishError("PUT /cards/{id} did not return an object")
        return payload

    def list_cards(self) -> list[dict[str, Any]]:
        """``GET /cards`` — this account's cards."""
        response = self._request("GET", "/cards")
        if response.status_code == 401:
            raise Host39AuthError("host39 rejected the credential on GET /cards (401)")
        if response.status_code != 200:
            raise Host39Error(f"GET /cards returned {response.status_code}")
        payload = response.json()
        if isinstance(payload, dict):
            items = payload.get("cards") or payload.get("items") or []
            return [i for i in items if isinstance(i, dict)]
        if isinstance(payload, list):
            return [i for i in payload if isinstance(i, dict)]
        return []

    def find_card_by_slug(self, slug: str) -> dict[str, Any] | None:
        for card in self.list_cards():
            if card.get("slug") == slug:
                return card
        return None

    # ── the Leg B operation ────────────────────────────────────────────────────

    def publish_a2a_card(
        self,
        card: dict[str, Any],
        *,
        slug: str,
        is_public: bool = True,
        include_nanda_extension: bool = True,
        replace_existing: bool = True,
    ) -> PublishResult:
        """Publish ``card`` and then PROVE it is fetchable.

        The proof is a second, unauthenticated GET of the public card URL — a 2xx
        from ``POST /cards`` alone is not treated as success.
        """
        body = a2a_card_to_host39_body(
            card,
            slug=slug,
            is_public=is_public,
            include_nanda_extension=include_nanda_extension,
        )
        account = self.me()

        existing = self.find_card_by_slug(body["slug"]) if replace_existing else None
        if existing and existing.get("id"):
            created = self.update_card(str(existing["id"]), body)
        else:
            created = self.create_card(body)

        url = published_card_url(
            self.base_url,
            slug=body["slug"],
            identity_type=account.get("identity_type"),
            handle=account.get("handle"),
            domain=account.get("domain"),
        )
        runtime_url = str(body.get("runtime_url") or "")
        did = str((body.get("authentication") or {}).get("credentials") or "")
        fetched = fetch_published_card(url, timeout=self._timeout)
        problems = verify_published_card(fetched, expected_runtime_url=runtime_url, expected_did=did)
        return PublishResult(
            card_id=str(created.get("id")) if created.get("id") else None,
            slug=body["slug"],
            card_url=url,
            runtime_url=runtime_url,
            did=did,
            status=str(created.get("status")) if created.get("status") else None,
            fetched=fetched,
            problems=problems,
        )


__all__ = [
    "BASE_URL_ENV",
    "CARD_MEDIA_TYPE",
    "EMAIL_ENV",
    "FetchedCard",
    "Host39AuthError",
    "Host39Client",
    "Host39ConfigError",
    "Host39Error",
    "Host39PublishError",
    "PASSWORD_ENV",
    "PublishResult",
    "SLUG_MAX_LEN",
    "SLUG_PATTERN",
    "TOKEN_ENV",
    "a2a_card_to_host39_body",
    "env_or_none",
    "fetch_published_card",
    "login",
    "missing_config",
    "published_card_url",
    "publishing_configured",
    "resolve_base_url",
    "resolve_login",
    "resolve_token",
    "verify_published_card",
]
