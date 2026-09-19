"""Offline tests for the host39 card publisher (Leg B).

Nothing here touches the network. The live drive lives in
``test_host39_live.py`` and SKIPS when no credential is present.

Two things this suite exists to nail down:

1. **Fail closed: set-but-empty is not configured.** ``HOST39_BASE_URL=`` (set but empty) must
   behave *identically* to unset, and neither may fall through to a default
   target or to an unauthenticated call. Every env var is tested BY NAME in both
   the unset and the empty case, because "empty means production" is exactly the
   bug that put 31 phantom records into a public registry.
2. **The artifact question.** host39's ``POST /cards`` is
   ``additionalProperties: false`` over a flattened *A2A card* field set. The
   mapping test asserts the produced body's keys are a subset of that declared
   set, so a future edit that starts smuggling AgentFacts fields (``agent_name``,
   ``handle``, ``label``, ``endpoints``, ``id``) fails here rather than as an
   opaque remote 400.
"""

from __future__ import annotations

import json

import httpx
import pytest

from community_member import host39
from community_member.a2a_card import build_agent_card

# The exact property set host39 declares for POST /cards, transcribed from its
# OpenAPI (GET /docs/json) where the schema is additionalProperties: false.
HOST39_DECLARED_CARD_FIELDS = {
    "slug",
    "display_name",
    "description",
    "runtime_url",
    "version",
    "capabilities",
    "authentication",
    "skills",
    "provider_name",
    "provider_url",
    "is_public",
    "monitoring_enabled",
}

# Fields that would mean somebody sent canonical NANDA AgentFacts by mistake.
AGENTFACTS_ONLY_FIELDS = {"id", "agent_name", "handle", "label", "endpoints"}

TENANT_DID = "did:key:z6MkfakeTenantKeyForTestsOnly1234567890"
TENANT_ENDPOINT = "https://smb-host.example.org/t/bobs-barbers"

ALL_HOST39_ENV = (
    host39.BASE_URL_ENV,
    host39.TOKEN_ENV,
    host39.EMAIL_ENV,
    host39.PASSWORD_ENV,
)


@pytest.fixture(autouse=True)
def _clean_host39_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts from a fully unset host39 environment, so a real
    operator credential in the ambient shell cannot influence a result."""
    for name in ALL_HOST39_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any accidental HTTP call in this module a loud failure.

    This is also the auto-fire guard: it proves that merely importing the module
    and asking it about its configuration performs no request.
    """

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline test attempted a network call")

    for attr in ("get", "post", "put", "request"):
        monkeypatch.setattr(httpx, attr, _explode)


def _tenant_card() -> dict:
    """The card shape ``smb_host`` actually serves, built through the same
    canonical builder so this suite cannot drift from the runtime."""
    card = build_agent_card(
        agent_id="bobs-barbers",
        display_name="Bob's Barbers",
        description="Sovereign SMB agent for Bob's Barbers",
        version="0.2.0",
        base_url=TENANT_ENDPOINT,
        chapter_url=None,
        did=TENANT_DID,
        skills_declared=["barber"],
        tools=None,
    )
    return card.model_dump(mode="json", by_alias=True, exclude_none=True)


# ── 1. fail closed: unset ≡ empty, tested by name ───────────────────────────────


@pytest.mark.parametrize("name", ALL_HOST39_ENV)
def test_unset_and_empty_env_are_identical(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """``env_or_none`` is the single place unset-vs-empty is decided."""
    monkeypatch.delenv(name, raising=False)
    unset = host39.env_or_none(name)
    monkeypatch.setenv(name, "")
    empty = host39.env_or_none(name)
    monkeypatch.setenv(name, "   ")
    whitespace = host39.env_or_none(name)
    assert unset is None
    assert empty is None, f"{name}= (empty) must behave like unset"
    assert whitespace is None, f"{name}=<whitespace> must behave like unset"
    assert unset == empty == whitespace


def test_base_url_has_no_default_when_unset() -> None:
    """No fallback to the live host. Unnamed target ⇒ publish nowhere."""
    assert host39.resolve_base_url() is None


def test_base_url_empty_does_not_fall_through_to_a_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(host39.BASE_URL_ENV, "")
    assert host39.resolve_base_url() is None


def test_base_url_whitespace_does_not_fall_through_to_a_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(host39.BASE_URL_ENV, "   ")
    assert host39.resolve_base_url() is None


def test_no_live_host_appears_as_a_default_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """Belt-and-braces: with the environment empty, nothing resolves to a host."""
    for name in ALL_HOST39_ENV:
        monkeypatch.setenv(name, "")
    assert host39.resolve_base_url() is None
    assert host39.resolve_token() is None
    assert host39.resolve_login() is None
    assert host39.publishing_configured() is False


@pytest.mark.parametrize(
    "env",
    [
        {},
        {host39.BASE_URL_ENV: ""},
        {host39.BASE_URL_ENV: "https://cards.example.org"},  # target, no credential
        {host39.TOKEN_ENV: "tok"},  # credential, no target
        {host39.BASE_URL_ENV: "https://cards.example.org", host39.TOKEN_ENV: ""},
        {host39.BASE_URL_ENV: "", host39.TOKEN_ENV: "tok"},
        # a half-set login is not a login
        {host39.BASE_URL_ENV: "https://cards.example.org", host39.EMAIL_ENV: "a@b.test"},
        {host39.BASE_URL_ENV: "https://cards.example.org", host39.PASSWORD_ENV: "pw"},
        {
            host39.BASE_URL_ENV: "https://cards.example.org",
            host39.EMAIL_ENV: "a@b.test",
            host39.PASSWORD_ENV: "",
        },
    ],
)
def test_publishing_not_configured_for_every_partial_env(env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert host39.publishing_configured() is False


def test_publishing_configured_only_when_target_and_credential_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(host39.BASE_URL_ENV, "https://cards.example.org")
    monkeypatch.setenv(host39.TOKEN_ENV, "tok")
    assert host39.publishing_configured() is True


def test_login_pair_requires_both_halves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(host39.EMAIL_ENV, "a@b.test")
    assert host39.resolve_login() is None
    monkeypatch.setenv(host39.PASSWORD_ENV, "")
    assert host39.resolve_login() is None, "empty password must not complete a login pair"
    monkeypatch.setenv(host39.PASSWORD_ENV, "pw")
    assert host39.resolve_login() == ("a@b.test", "pw")


# ── 2. fail closed: no unauthenticated call is reachable ────────────────────────


@pytest.mark.parametrize("token", ["", "   "])
def test_client_refuses_empty_token(token: str) -> None:
    with pytest.raises(host39.Host39AuthError):
        host39.Host39Client("https://cards.example.org", token)


@pytest.mark.parametrize("base", ["", "   "])
def test_client_refuses_empty_base_url(base: str) -> None:
    with pytest.raises(host39.Host39ConfigError):
        host39.Host39Client(base, "tok")


def test_from_env_raises_naming_the_missing_base_url() -> None:
    with pytest.raises(host39.Host39ConfigError) as excinfo:
        host39.Host39Client.from_env()
    assert host39.BASE_URL_ENV in str(excinfo.value)


def test_from_env_empty_base_url_raises_naming_the_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(host39.BASE_URL_ENV, "")
    monkeypatch.setenv(host39.TOKEN_ENV, "tok")
    with pytest.raises(host39.Host39ConfigError) as excinfo:
        host39.Host39Client.from_env()
    assert host39.BASE_URL_ENV in str(excinfo.value)


def test_from_env_empty_token_raises_and_does_not_call_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty token must not degrade into an anonymous request. The autouse
    ``_no_network`` guard turns any attempted call into a failure, so reaching
    the Host39ConfigError proves nothing left the process."""
    monkeypatch.setenv(host39.BASE_URL_ENV, "https://cards.example.org")
    monkeypatch.setenv(host39.TOKEN_ENV, "")
    with pytest.raises(host39.Host39ConfigError) as excinfo:
        host39.Host39Client.from_env()
    message = str(excinfo.value)
    assert host39.TOKEN_ENV in message
    assert host39.EMAIL_ENV in message


def test_missing_config_names_vars_only() -> None:
    missing = host39.missing_config()
    assert host39.BASE_URL_ENV in missing
    assert any(host39.TOKEN_ENV in entry for entry in missing)


def test_login_refuses_empty_credentials() -> None:
    with pytest.raises(host39.Host39AuthError):
        host39.login("https://cards.example.org", "", "pw")
    with pytest.raises(host39.Host39AuthError):
        host39.login("https://cards.example.org", "a@b.test", "")


def test_login_refuses_empty_base_url() -> None:
    with pytest.raises(host39.Host39ConfigError):
        host39.login("", "a@b.test", "pw")


# ── 3. secret hygiene ───────────────────────────────────────────────────────────


def test_client_repr_redacts_the_token() -> None:
    client = host39.Host39Client("https://cards.example.org", "super-secret-token")
    assert "super-secret-token" not in repr(client)
    assert "redacted" in repr(client)


def test_module_source_contains_no_credential_literals() -> None:
    """The publisher reads credentials from the environment only — it must not
    read a credentials FILE or carry a baked-in value."""
    import inspect

    source = inspect.getsource(host39)
    assert "host39-accounts.env" not in source
    assert "host39-railway-secrets.env" not in source
    assert "JWT_SECRET" not in source


# ── 4. the artifact question: A2A card → host39 body ────────────────────────────


def test_body_uses_only_fields_host39_declares() -> None:
    """host39's POST /cards is additionalProperties:false. Any extra key is a
    rejected request, so the mapping must stay inside the declared set."""
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    extra = set(body) - HOST39_DECLARED_CARD_FIELDS
    assert not extra, f"body carries fields host39 does not declare: {sorted(extra)}"


def test_body_carries_no_agentfacts_only_fields() -> None:
    """host39 takes the A2A card, NOT canonical NANDA AgentFacts."""
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert not (set(body) & AGENTFACTS_ONLY_FIELDS)


def test_runtime_url_is_the_live_agent_endpoint() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert body["runtime_url"] == TENANT_ENDPOINT


def test_credentials_carries_the_tenant_did() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert body["authentication"]["credentials"] == TENANT_DID
    assert "ed25519" in body["authentication"]["schemes"]


def test_provider_is_split_into_name_and_url() -> None:
    card = _tenant_card()
    card["provider"] = {"organization": "Bob's Barbers Ltd", "url": "https://bobs.example.org"}
    body = host39.a2a_card_to_host39_body(card, slug="bobs-barbers")
    assert body["provider_name"] == "Bob's Barbers Ltd"
    assert body["provider_url"] == "https://bobs.example.org"
    assert "provider" not in body


def test_nanda_extension_rides_inside_capabilities_not_top_level() -> None:
    """``x-nanda`` cannot be a top-level key (additionalProperties:false), so it
    is carried in the free-form ``capabilities`` object — preserving the pointer
    to canonical AgentFacts on the runtime."""
    card = _tenant_card()
    assert "x-nanda" in card, "the builder should emit x-nanda when a did is present"
    body = host39.a2a_card_to_host39_body(card, slug="bobs-barbers")
    assert "x-nanda" not in body
    nanda = body["capabilities"]["x-nanda"]
    assert nanda["did"] == TENANT_DID
    assert nanda["agentfacts_url"] == f"{TENANT_ENDPOINT}/agentfacts.json"


def test_nanda_extension_can_be_omitted_for_a_strict_body() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers", include_nanda_extension=False)
    assert "x-nanda" not in json.dumps(body)


def test_capabilities_survive_the_mapping() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert body["capabilities"]["streaming"] is True


def test_missing_runtime_url_is_refused() -> None:
    card = _tenant_card()
    card.pop("url")
    with pytest.raises(host39.Host39PublishError, match="runtime_url"):
        host39.a2a_card_to_host39_body(card, slug="bobs-barbers")


def test_missing_did_credential_is_refused() -> None:
    card = _tenant_card()
    card["authentication"]["credentials"] = ""
    with pytest.raises(host39.Host39PublishError, match="credentials"):
        host39.a2a_card_to_host39_body(card, slug="bobs-barbers")


def test_missing_display_name_is_refused() -> None:
    card = _tenant_card()
    card.pop("name")
    with pytest.raises(host39.Host39PublishError, match="name"):
        host39.a2a_card_to_host39_body(card, slug="bobs-barbers")


@pytest.mark.parametrize("slug", ["", "-leading-hyphen", "Has Capitals", "under_score", "a b"])
def test_bad_slugs_are_refused_locally(slug: str) -> None:
    with pytest.raises(host39.Host39PublishError):
        host39.a2a_card_to_host39_body(_tenant_card(), slug=slug)


def test_overlong_slug_is_refused() -> None:
    with pytest.raises(host39.Host39PublishError, match="limit"):
        host39.a2a_card_to_host39_body(_tenant_card(), slug="a" * (host39.SLUG_MAX_LEN + 1))


def test_overlong_field_is_refused_not_truncated() -> None:
    """A truncated runtime_url publishes a card that points somewhere wrong."""
    card = _tenant_card()
    card["url"] = "https://example.org/t/" + "x" * 600
    with pytest.raises(host39.Host39PublishError, match="Refusing to truncate"):
        host39.a2a_card_to_host39_body(card, slug="bobs-barbers")


def test_is_public_is_explicit() -> None:
    assert host39.a2a_card_to_host39_body(_tenant_card(), slug="s")["is_public"] is True
    assert host39.a2a_card_to_host39_body(_tenant_card(), slug="s", is_public=False)["is_public"] is False


# ── 5. published URL derivation ─────────────────────────────────────────────────


def test_domain_identity_url() -> None:
    url = host39.published_card_url(
        "https://cards.example.org/",
        slug="ceo",
        identity_type="domain",
        handle="regentix",
        domain="regentix.ai",
    )
    assert url == "https://cards.example.org/regentix.ai/ceo.json"


def test_personal_identity_url() -> None:
    url = host39.published_card_url(
        "https://cards.example.org",
        slug="bobs-barbers",
        identity_type="email",
        handle="bob",
        domain=None,
    )
    assert url == "https://cards.example.org/personal/bob/bobs-barbers.json"


def test_domain_identity_without_domain_is_refused() -> None:
    with pytest.raises(host39.Host39PublishError, match="domain"):
        host39.published_card_url(
            "https://cards.example.org",
            slug="ceo",
            identity_type="domain",
            handle="regentix",
            domain=None,
        )


def test_personal_identity_without_handle_is_refused() -> None:
    with pytest.raises(host39.Host39PublishError, match="handle"):
        host39.published_card_url(
            "https://cards.example.org", slug="ceo", identity_type="email", handle="", domain=None
        )


def test_card_url_requires_a_base_url() -> None:
    with pytest.raises(host39.Host39ConfigError):
        host39.published_card_url("", slug="ceo", identity_type="email", handle="bob", domain=None)


# ── 6. verification of a fetched card ───────────────────────────────────────────


def _fetched(status: int = 200, content_type: str = host39.CARD_MEDIA_TYPE, **body: object) -> host39.FetchedCard:
    payload = {"runtime_url": TENANT_ENDPOINT, "authentication": {"credentials": TENANT_DID}}
    payload.update(body)
    return host39.FetchedCard(
        url="https://cards.example.org/personal/bob/x.json",
        status_code=status,
        content_type=content_type,
        body=payload,
        raw=json.dumps(payload),
    )


def test_verify_passes_on_a_good_card() -> None:
    problems = host39.verify_published_card(_fetched(), expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID)
    assert problems == []


def test_verify_accepts_the_a2a_media_type_with_charset() -> None:
    fetched = _fetched(content_type=f"{host39.CARD_MEDIA_TYPE}; charset=utf-8")
    assert fetched.is_a2a_media_type
    assert host39.verify_published_card(fetched, expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID) == []


def test_verify_flags_a_plain_json_content_type() -> None:
    problems = host39.verify_published_card(
        _fetched(content_type="application/json"),
        expected_runtime_url=TENANT_ENDPOINT,
        expected_did=TENANT_DID,
    )
    assert any("content-type" in p for p in problems)


def test_verify_flags_a_non_200() -> None:
    problems = host39.verify_published_card(
        _fetched(status=404), expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID
    )
    assert any("404" in p for p in problems)


def test_verify_flags_a_wrong_runtime_url() -> None:
    problems = host39.verify_published_card(
        _fetched(runtime_url="https://somewhere.else/t/x"),
        expected_runtime_url=TENANT_ENDPOINT,
        expected_did=TENANT_DID,
    )
    assert any("runtime_url" in p for p in problems)


def test_verify_flags_a_missing_did() -> None:
    problems = host39.verify_published_card(
        _fetched(authentication={}), expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID
    )
    assert any("credentials" in p for p in problems)


def test_verify_accepts_the_card_re_expanded_as_a2a_url() -> None:
    """host39 may serve the endpoint back as the A2A ``url`` field rather than
    its own flattened ``runtime_url``; both are the same fact."""
    payload = {"url": TENANT_ENDPOINT, "authentication": {"credentials": TENANT_DID}}
    fetched = host39.FetchedCard(
        url="https://cards.example.org/personal/bob/x.json",
        status_code=200,
        content_type=host39.CARD_MEDIA_TYPE,
        body=payload,
        raw=json.dumps(payload),
    )
    assert host39.verify_published_card(fetched, expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID) == []


# ── 7. no index call, ever ──────────────────────────────────────────────────────


def test_publisher_never_references_the_index() -> None:
    """Leg B stops at host39. Registering on api.nandaindex.org is Leg C and has
    an unresolved architecture question."""
    import inspect

    source = inspect.getsource(host39)
    assert "nandaindex.org" not in source
    assert "/api/v1/orgs" not in source


# ── 8. the client and the publish orchestration, offline ────────────────────────
#
# The HTTP-doing paths are exercised against a stubbed httpx so they are covered
# without a host39 account — the live drive in test_host39_live.py then proves the
# same code against the real service. Requests are recorded so the tests can
# assert that every one of them carried a bearer token.


class _StubHttp:
    """Records requests and replays canned responses keyed by ``METHOD path``."""

    def __init__(self, routes: dict[str, tuple[int, object]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, str], object]] = []

    def _respond(self, method: str, url: str, headers: dict[str, str] | None, body: object) -> httpx.Response:
        self.calls.append((method, url, dict(headers or {}), body))
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        key = f"{method} /{path}"
        if key not in self.routes:
            raise AssertionError(f"stub has no route for {key!r}; known: {sorted(self.routes)}")
        status, payload = self.routes[key]
        return httpx.Response(
            status,
            json=payload,
            headers={"content-type": host39.CARD_MEDIA_TYPE},
            request=httpx.Request(method, url),
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> _StubHttp:
        monkeypatch.setattr(httpx, "get", lambda url, **kw: self._respond("GET", url, kw.get("headers"), None))
        monkeypatch.setattr(
            httpx,
            "post",
            lambda url, **kw: self._respond("POST", url, kw.get("headers"), kw.get("json")),
        )
        monkeypatch.setattr(
            httpx,
            "request",
            lambda method, url, **kw: self._respond(method, url, kw.get("headers"), kw.get("json")),
        )
        return self

    @property
    def bodies(self) -> list[object]:
        return [body for _, _, _, body in self.calls if body is not None]


ACCOUNT_PERSONAL = {"user_id": "u1", "email": "a@b.test", "handle": "bob", "identity_type": "email", "domain": None}
ACCOUNT_DOMAIN = {
    "user_id": "u2",
    "email": "c@d.test",
    "handle": "regentix",
    "identity_type": "domain",
    "domain": "regentix.ai",
}
BASE = "https://cards.example.org"


def _published_body() -> dict:
    return {"runtime_url": TENANT_ENDPOINT, "authentication": {"credentials": TENANT_DID}}


def test_login_returns_a_token_and_never_echoes_the_password(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = _StubHttp({"POST /auth/login": (200, {"token": "jwt-value"})}).install(monkeypatch)
    assert host39.login(BASE, "a@b.test", "the-password") == "jwt-value"
    assert stub.bodies == [{"email": "a@b.test", "password": "the-password"}]


def test_login_rejection_message_hides_the_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp({"POST /auth/login": (401, {"error": "bad_credentials"})}).install(monkeypatch)
    with pytest.raises(host39.Host39AuthError) as excinfo:
        host39.login(BASE, "a@b.test", "the-password")
    message = str(excinfo.value)
    assert "the-password" not in message
    assert host39.PASSWORD_ENV in message


def test_login_200_without_a_token_is_an_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp({"POST /auth/login": (200, {})}).install(monkeypatch)
    with pytest.raises(host39.Host39AuthError, match="no token"):
        host39.login(BASE, "a@b.test", "pw")


def test_from_env_logs_in_when_only_email_and_password_are_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(host39.BASE_URL_ENV, BASE)
    monkeypatch.setenv(host39.EMAIL_ENV, "a@b.test")
    monkeypatch.setenv(host39.PASSWORD_ENV, "pw")
    _StubHttp({"POST /auth/login": (200, {"token": "jwt-value"})}).install(monkeypatch)
    client = host39.Host39Client.from_env()
    assert client.base_url == BASE
    assert "jwt-value" not in repr(client)


def test_every_client_request_carries_a_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_PERSONAL),
            "GET /cards": (200, []),
        }
    ).install(monkeypatch)
    client = host39.Host39Client(BASE, "jwt-value")
    client.me()
    client.list_cards()
    assert stub.calls, "no request was made"
    for method, url, headers, _ in stub.calls:
        assert headers.get("authorization") == "Bearer jwt-value", f"{method} {url} went out unauthenticated"


def test_me_maps_401_to_an_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp({"GET /auth/me": (401, {"error": "unauthorized"})}).install(monkeypatch)
    with pytest.raises(host39.Host39AuthError, match=host39.TOKEN_ENV):
        host39.Host39Client(BASE, "jwt-value").me()


def test_create_card_surfaces_host39s_own_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp({"POST /cards": (400, {"error": "bad_request", "detail": "slug taken"})}).install(monkeypatch)
    with pytest.raises(host39.Host39PublishError, match="400"):
        host39.Host39Client(BASE, "jwt-value").create_card({"slug": "x", "display_name": "X"})


def test_list_cards_accepts_a_wrapped_or_bare_array(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp({"GET /cards": (200, {"cards": [{"slug": "a"}, {"slug": "b"}]})}).install(monkeypatch)
    assert [c["slug"] for c in host39.Host39Client(BASE, "t").list_cards()] == ["a", "b"]
    _StubHttp({"GET /cards": (200, [{"slug": "c"}])}).install(monkeypatch)
    assert host39.Host39Client(BASE, "t").find_card_by_slug("c") == {"slug": "c"}
    assert host39.Host39Client(BASE, "t").find_card_by_slug("nope") is None


def test_publish_creates_then_proves_fetchable_for_a_personal_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_PERSONAL),
            "GET /cards": (200, []),
            "POST /cards": (201, {"id": "card-1", "status": "active", "slug": "bobs-barbers"}),
            "GET /personal/bob/bobs-barbers.json": (200, _published_body()),
        }
    ).install(monkeypatch)
    result = host39.Host39Client(BASE, "jwt-value").publish_a2a_card(_tenant_card(), slug="bobs-barbers")

    assert result.ok, result.problems
    assert result.card_id == "card-1"
    assert result.status == "active"
    assert result.card_url == f"{BASE}/personal/bob/bobs-barbers.json"
    assert result.runtime_url == TENANT_ENDPOINT
    assert result.did == TENANT_DID
    assert result.fetched.status_code == 200
    assert result.fetched.is_a2a_media_type
    # The proof fetch is UNAUTHENTICATED — a card only a bearer token can read is
    # not published.
    probe = [c for c in stub.calls if c[1].endswith("/personal/bob/bobs-barbers.json")]
    assert probe and "authorization" not in {k.lower() for k in probe[-1][2]}


def test_publish_uses_the_domain_route_for_a_domain_account(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_DOMAIN),
            "GET /cards": (200, []),
            "POST /cards": (201, {"id": "card-2", "status": "active"}),
            "GET /regentix.ai/bobs-barbers.json": (200, _published_body()),
        }
    ).install(monkeypatch)
    result = host39.Host39Client(BASE, "t").publish_a2a_card(_tenant_card(), slug="bobs-barbers")
    assert result.card_url == f"{BASE}/regentix.ai/bobs-barbers.json"
    assert result.ok, result.problems


def test_republish_updates_the_existing_card_instead_of_conflicting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second run must be idempotent: host39 409s a duplicate slug, so an
    existing card is PUT, not POSTed."""
    stub = _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_PERSONAL),
            "GET /cards": (200, [{"id": "card-1", "slug": "bobs-barbers"}]),
            "PUT /cards/card-1": (200, {"id": "card-1", "status": "active"}),
            "GET /personal/bob/bobs-barbers.json": (200, _published_body()),
        }
    ).install(monkeypatch)
    result = host39.Host39Client(BASE, "t").publish_a2a_card(_tenant_card(), slug="bobs-barbers")
    assert result.ok, result.problems
    assert any(method == "PUT" for method, _, _, _ in stub.calls)
    assert not any(method == "POST" for method, _, _, _ in stub.calls)


def test_publish_reports_problems_when_the_served_card_is_wrong(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 201 from POST /cards is NOT success. If the public URL serves something
    that does not match, the result carries the problems and ``ok`` is False."""
    _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_PERSONAL),
            "GET /cards": (200, []),
            "POST /cards": (201, {"id": "card-1", "status": "active"}),
            "GET /personal/bob/bobs-barbers.json": (
                200,
                {"runtime_url": "https://wrong.example/t/x", "authentication": {}},
            ),
        }
    ).install(monkeypatch)
    result = host39.Host39Client(BASE, "t").publish_a2a_card(_tenant_card(), slug="bobs-barbers")
    assert not result.ok
    assert any("runtime_url" in p for p in result.problems)
    assert any("credentials" in p for p in result.problems)


def test_publish_fails_loudly_when_the_card_is_not_fetchable(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubHttp(
        {
            "GET /auth/me": (200, ACCOUNT_PERSONAL),
            "GET /cards": (200, []),
            "POST /cards": (201, {"id": "card-1", "status": "pending"}),
            "GET /personal/bob/bobs-barbers.json": (404, {"error": "not_found"}),
        }
    ).install(monkeypatch)
    result = host39.Host39Client(BASE, "t").publish_a2a_card(_tenant_card(), slug="bobs-barbers")
    assert not result.ok
    assert any("404" in p for p in result.problems)


def test_fetch_published_card_handles_a_non_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def _text(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            200, text="not json", headers={"content-type": "text/html"}, request=httpx.Request("GET", url)
        )

    monkeypatch.setattr(httpx, "get", _text)
    fetched = host39.fetch_published_card(f"{BASE}/personal/bob/x.json")
    assert fetched.body is None
    assert not fetched.is_a2a_media_type
    problems = host39.verify_published_card(fetched, expected_runtime_url=TENANT_ENDPOINT, expected_did=TENANT_DID)
    assert any("not a JSON object" in p for p in problems)


# ── 9. the AgentFacts pointer must not be a dead link ───────────────────────────


def test_advertised_agentfacts_url_is_read_from_the_body() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert host39.advertised_agentfacts_url(body) == f"{TENANT_ENDPOINT}/agentfacts.json"


def test_no_agentfacts_url_when_the_extension_is_omitted() -> None:
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers", include_nanda_extension=False)
    assert host39.advertised_agentfacts_url(body) is None
    assert host39.check_agentfacts_pointer(body) is None


def test_dead_agentfacts_pointer_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """smb_host does not currently serve /agentfacts.json for a tenant, so the
    pointer the card carries 404s. That must surface, never pass silently."""

    def _not_found(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Not Found"}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", _not_found)
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    warning = host39.check_agentfacts_pointer(body)
    assert warning is not None
    assert "404" in warning
    assert "agentfacts.json" in warning


def test_live_agentfacts_pointer_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    def _ok(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(200, json={"id": TENANT_DID}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", _ok)
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    assert host39.check_agentfacts_pointer(body) is None


def test_unreachable_agentfacts_pointer_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(url: str, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", _boom)
    body = host39.a2a_card_to_host39_body(_tenant_card(), slug="bobs-barbers")
    warning = host39.check_agentfacts_pointer(body)
    assert warning is not None and "unreachable" in warning
