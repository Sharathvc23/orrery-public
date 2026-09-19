"""Domain control, bound to the owner key.

⚠️ THE PROPERTY THIS FILE EXISTS FOR. nanda-connect's ``make_challenge_validator``
reads ``key_authorization`` from CALLER-SUPPLIED CLAIMS and only checks the domain
publishes that same string; ``DomainControlVerifier.verify`` then checks only
``attested["domain"] == anchor["id"]``. Nothing binds either to ``grantor_did``.

That is worse than the optional-OIDC-nonce case, because the value an attacker
needs is PUBLISHED ON PURPOSE — an HTTP-01 response lives at a deliberately
world-readable URL and DNS-01 is a public TXT record. So a passive observer of a
legitimate challenge can copy it into their own envelope, name their own DID as
grantor, and be VERIFIED as the owner of someone else's domain. Filed upstream as
an upstream issue filed against the NANDA Connect library.

The fix is RFC 8555's, applied to the owner key: ``keyAuthorization = token ||
"." || base64url(JWK_Thumbprint(ownerKey))``, computed locally and never accepted
as input. ``test_a_challenge_served_for_owner_A_is_refused_for_owner_B`` is the
assertion that makes this path real rather than merely shaped correctly — the
same role the nonce test plays for OIDC.

HTTP-01 runs against a REAL local http.server; DNS-01 against a stub resolver
(there is no local DNS to stand up). Neither mocks the validator itself, which
would test nothing.
"""

import base64
import hashlib
import http.server
import json
import threading

import pytest

from community_member import owner
from community_member.crypto import build_did_key

AGENT_DID = build_did_key(base64.b64encode(b"\x01" * 32).decode())
DOMAIN = "moonbakery.com"


@pytest.fixture
def owner_a():
    return owner.mint_owner_identity()


@pytest.fixture
def owner_b():
    return owner.mint_owner_identity()


def _served(challenge: owner.DomainChallenge):
    """An http_get_text that serves exactly what a correctly-configured domain
    would serve for this challenge, and nothing else."""
    url = owner.http_challenge_url(challenge.domain, challenge.token)
    return lambda u: challenge.key_authorization if u == url else None


# ── the thumbprint and the key authorization ─────────────────────────────────


def test_jwk_thumbprint_matches_rfc7638_over_the_rfc8037_okp_form():
    """Computed independently here rather than re-calling the implementation —
    a test that recomputes with the same helper proves only that it is
    deterministic."""
    identity = owner.mint_owner_identity()
    x = base64.urlsafe_b64encode(base64.b64decode(identity.public_key_b64)).decode().rstrip("=")
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")
    assert owner.jwk_thumbprint(identity.public_key_b64) == expected


def test_thumbprint_from_did_agrees_with_thumbprint_from_the_public_key():
    identity = owner.mint_owner_identity()
    assert owner.jwk_thumbprint_from_did(identity.did) == owner.jwk_thumbprint(identity.public_key_b64)


def test_thumbprint_differs_per_owner(owner_a, owner_b):
    assert owner.jwk_thumbprint_from_did(owner_a.did) != owner.jwk_thumbprint_from_did(owner_b.did)


def test_key_authorization_is_token_dot_thumbprint(owner_a):
    ka = owner.key_authorization("tok123", owner_a.did)
    assert ka == f"tok123.{owner.jwk_thumbprint_from_did(owner_a.did)}"
    assert ka.count(".") == 1


def test_key_authorization_refuses_empty_inputs(owner_a):
    with pytest.raises(ValueError, match="token is required"):
        owner.key_authorization("", owner_a.did)
    with pytest.raises(ValueError, match="unbound challenge proves nothing"):
        owner.key_authorization("tok", "")


def test_challenge_tokens_are_unique():
    assert len({owner.new_challenge_token() for _ in range(50)}) == 50


# ── ⚠️ THE BINDING TEST ──────────────────────────────────────────────────────


def _unbound_validator_the_way_nanda_connect_does_it(http_get_text):
    """nanda-connect's ``make_challenge_validator``, reproduced faithfully.

    NOT production code and never imported by any — it exists so the test below
    can DEMONSTRATE the vulnerability rather than assert it in a comment. The
    only difference from the real one is that this is 8 lines instead of 20;
    the load-bearing behaviour is identical: ``key_authorization`` comes from
    the caller's claims and the domain is merely checked to publish that string.
    """

    def validate(claims):
        domain, method = claims.get("domain"), claims.get("method")
        token, key_auth = claims.get("token"), claims.get("key_authorization")
        if not (isinstance(domain, str) and isinstance(key_auth, str) and isinstance(token, str)):
            return None
        body = http_get_text(owner.http_challenge_url(domain, token))
        if body is None or body.strip() != key_auth:
            return None
        return {"domain": domain, "method": method}

    return validate


def test_the_unbound_validator_IS_vulnerable_so_the_binding_test_is_not_vacuous(owner_a, owner_b):
    """⚠️ The differential that makes the next test mean something.

    A test that only shows "our validator refuses B" is consistent with our
    validator refusing everything. This shows the SAME replay, against a
    validator built the way nanda-connect builds one, SUCCEEDS — B is attested
    as controlling A's domain. That is an upstream issue filed against the NANDA Connect library, reproduced.
    """
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    fetch = _served(challenge)
    unbound = _unbound_validator_the_way_nanda_connect_does_it(fetch)

    # B submits A's published values verbatim — everything here is world-readable.
    replayed_claims = {
        "domain": DOMAIN,
        "method": owner.HTTP_01,
        "token": challenge.token,
        "key_authorization": challenge.key_authorization,
    }
    assert unbound(replayed_claims) == {"domain": DOMAIN, "method": owner.HTTP_01}, (
        "the unbound validator was expected to be fooled — if this fails, upstream changed "
        "and the local binding may no longer be the only thing preventing the replay"
    )

    # The bound validator, handed the identical claims for B, refuses.
    bound_for_b = owner.make_bound_challenge_validator(owner_b.did, http_get_text=fetch)
    assert bound_for_b(replayed_claims) is None


def test_a_challenge_served_for_owner_A_is_refused_for_owner_B(owner_a, owner_b):
    """⚠️ an upstream issue filed against the NANDA Connect library, asserted.

    The domain GENUINELY serves A's value — this is a real, correctly-published
    proof, not a forgery. B copies it verbatim, which anyone can do because the
    URL is world-readable by design. B must still be refused.
    """
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    fetch = _served(challenge)

    # A succeeds against its own challenge.
    assert owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=fetch).domain == DOMAIN

    # B replays the SAME published value, naming itself.
    stolen = owner.DomainChallenge(
        domain=challenge.domain,
        method=challenge.method,
        token=challenge.token,
        key_authorization=challenge.key_authorization,
    )
    with pytest.raises(ValueError, match="not proven"):
        owner.verify_domain_challenge(stolen, owner_b.did, http_get_text=fetch)


def test_the_same_replay_is_refused_at_the_gate_too(owner_a, owner_b):
    """Defence in depth: even if a validator somewhere accepted the replay, the
    listing gate recomputes the expected value from the envelope's own owner did
    and refuses."""
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    anchor = {"method": "domain", "issuer": owner.HTTP_01, "id": DOMAIN}
    envelope_b = {
        "grantor_did": owner_b.did,
        "anchor": anchor,
        "evidence": [
            {
                "type": "domain_control",
                "claims": {
                    "domain": DOMAIN,
                    "method": owner.HTTP_01,
                    "token": challenge.token,
                    "key_authorization": challenge.key_authorization,  # A's, copied
                },
            }
        ],
    }
    binding = {
        "owner_did": owner_b.did,
        "subject": DOMAIN,
        "anchor": anchor,
        "evidence": envelope_b,
        "grant": owner.build_listing_grant(owner=owner_b, agent_did=AGENT_DID),
    }
    verdict = owner.listing_grant_verdict(binding, AGENT_DID)
    assert verdict.ok is False
    assert verdict.reason == "evidence_challenge_unbound"


def test_the_verifier_refuses_before_performing_the_challenge(owner_a, owner_b):
    """A mismatched grantor must not cause a network call.

    Otherwise the verifier is a lookup oracle: anyone could make it probe an
    arbitrary domain by submitting an envelope naming it.
    """
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        return None

    verifier = owner.make_bound_domain_control_verifier(owner_a.did, http_get_text=fetch)
    verdict = verifier.verify(
        {"type": "domain_control", "claims": {"domain": DOMAIN, "method": owner.HTTP_01, "token": "t"}},
        {"grantor_did": owner_b.did, "anchor": {"id": DOMAIN}},
    )
    assert verdict.status == "REFUTED"
    assert verdict.reason == "grantor_not_bound_to_challenge"
    assert calls == [], "the challenge was performed for an envelope that was not about this owner"


def test_build_domain_evidence_refuses_an_unbound_assertion(owner_a, owner_b):
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    with pytest.raises(ValueError, match="not bound to this owner key"):
        owner.build_domain_evidence(owner=owner_b, assertion=assertion)


def test_key_authorization_is_never_read_from_claims(owner_a, owner_b):
    """The structural version of the binding property.

    The validator is handed claims carrying B's key_authorization while the
    domain serves A's. If the validator trusted the claim it would compare B's
    value to B's value via the served body and could be steered; it must instead
    recompute from (token, owner_did) and compare against what is actually
    served.
    """
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    validator = owner.make_bound_challenge_validator(owner_a.did, http_get_text=_served(challenge))
    # Claims lie about key_authorization; validation must ignore the lie entirely.
    assert validator(
        {
            "domain": DOMAIN,
            "method": owner.HTTP_01,
            "token": challenge.token,
            "key_authorization": owner.key_authorization(challenge.token, owner_b.did),
        }
    ) == {"domain": DOMAIN, "method": owner.HTTP_01}


def test_the_validator_source_never_reads_the_claim():
    """Belt and braces on the above: the string is absent from the read path.

    A future edit that reintroduces ``claims.get("key_authorization")`` fails
    here and is told why, rather than silently reopening an upstream issue filed against the NANDA Connect library.
    """
    import inspect

    source = inspect.getsource(owner.make_bound_challenge_validator)
    assert 'claims.get("key_authorization")' not in source
    assert "key_authorization" not in source.split("def validate")[1]


# ── HTTP-01 against a REAL local server ──────────────────────────────────────


class _ChallengeServer:
    """A real HTTP server that publishes one challenge, exactly as a domain would."""

    def __init__(self, body: str | None, path: str):
        self.body, self.path, self.hits = body, path, []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits.append(self.path)
                if outer.body is None or self.path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = outer.body.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _plain_http_fetcher():
    """The real fetcher shape, over http:// so a local server can answer.

    ``owner.httpx_text_fetcher`` builds https:// URLs (correctly — a challenge
    over plaintext proves nothing to a network attacker), so these tests fetch
    the same way against 127.0.0.1.

    The live tests also construct ``DomainChallenge`` directly with a
    ``host:port`` "domain", bypassing ``validate_domain`` (which rightly refuses
    a port). That is the one concession to running a server locally; the
    validator and URL construction under test are otherwise the real ones.
    """
    import httpx

    def fetch(url: str) -> str | None:
        try:
            resp = httpx.get(url.replace("https://", "http://"), timeout=5.0, follow_redirects=False)
            return resp.text if resp.status_code == 200 else None
        except Exception:  # noqa: BLE001
            return None

    return fetch


def test_http_01_end_to_end_against_a_real_server(owner_a):
    challenge = owner.build_domain_challenge("127.0.0.1.nip.io", owner.HTTP_01, owner_a.did)
    path = f"{owner.DOMAIN_CHALLENGE_HTTP_PATH}{challenge.token}"
    with _ChallengeServer(challenge.key_authorization, path) as server:
        domain = f"127.0.0.1:{server.port}"
        live = owner.DomainChallenge(
            domain=domain,
            method=owner.HTTP_01,
            token=challenge.token,
            key_authorization=challenge.key_authorization,
        )
        assertion = owner.verify_domain_challenge(live, owner_a.did, http_get_text=_plain_http_fetcher())
    assert assertion.domain == domain
    assert assertion.method == owner.HTTP_01
    assert server.hits == [path], "the validator did not fetch exactly the challenge path"


def test_http_01_fails_when_the_server_publishes_the_wrong_value(owner_a):
    challenge = owner.build_domain_challenge("example.com", owner.HTTP_01, owner_a.did)
    path = f"{owner.DOMAIN_CHALLENGE_HTTP_PATH}{challenge.token}"
    with _ChallengeServer("some other text", path) as server:
        live = owner.DomainChallenge(
            domain=f"127.0.0.1:{server.port}",
            method=owner.HTTP_01,
            token=challenge.token,
            key_authorization=challenge.key_authorization,
        )
        with pytest.raises(ValueError, match="not proven"):
            owner.verify_domain_challenge(live, owner_a.did, http_get_text=_plain_http_fetcher())


def test_http_01_fails_when_nothing_is_published(owner_a):
    challenge = owner.build_domain_challenge("example.com", owner.HTTP_01, owner_a.did)
    with _ChallengeServer(None, "/nothing") as server:
        live = owner.DomainChallenge(
            domain=f"127.0.0.1:{server.port}",
            method=owner.HTTP_01,
            token=challenge.token,
            key_authorization=challenge.key_authorization,
        )
        with pytest.raises(ValueError, match="not proven"):
            owner.verify_domain_challenge(live, owner_a.did, http_get_text=_plain_http_fetcher())


def test_http_01_trailing_whitespace_in_the_served_body_is_tolerated(owner_a):
    """Editors add a trailing newline; the proof is the value, not the bytes."""
    challenge = owner.build_domain_challenge("example.com", owner.HTTP_01, owner_a.did)
    path = f"{owner.DOMAIN_CHALLENGE_HTTP_PATH}{challenge.token}"
    with _ChallengeServer(challenge.key_authorization + "\n", path) as server:
        live = owner.DomainChallenge(
            domain=f"127.0.0.1:{server.port}",
            method=owner.HTTP_01,
            token=challenge.token,
            key_authorization=challenge.key_authorization,
        )
        assert owner.verify_domain_challenge(live, owner_a.did, http_get_text=_plain_http_fetcher())


def test_the_real_fetcher_builds_an_https_url_and_refuses_redirects():
    """A challenge fetched over plaintext, or followed through a redirect, would
    let a domain that does not serve the proof point at one that does."""
    import inspect

    assert owner.http_challenge_url("x.com", "t").startswith("https://")
    source = inspect.getsource(owner.httpx_text_fetcher)
    assert "follow_redirects=False" in source


# ── DNS-01 against a stub resolver ───────────────────────────────────────────


def test_dns_01_end_to_end_against_a_stub_resolver(owner_a):
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    looked_up: list[str] = []

    def dns_txt(name):
        looked_up.append(name)
        return ["unrelated-verification=abc", challenge.key_authorization]

    assertion = owner.verify_domain_challenge(challenge, owner_a.did, dns_txt=dns_txt)
    assert assertion.method == owner.DNS_01
    assert looked_up == [f"{owner.DOMAIN_CHALLENGE_DNS_NAME}.{DOMAIN}"]


def test_dns_01_strips_the_quoting_a_resolver_may_return(owner_a):
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    assert owner.verify_domain_challenge(
        challenge, owner_a.did, dns_txt=lambda _n: [f'"{challenge.key_authorization}"']
    )


def test_dns_01_refuses_owner_B_against_owner_A_s_published_record(owner_a, owner_b):
    """The same replay, over the other challenge type — a public TXT record is
    if anything easier to copy than a URL."""
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    published = lambda _n: [challenge.key_authorization]  # noqa: E731
    assert owner.verify_domain_challenge(challenge, owner_a.did, dns_txt=published)
    with pytest.raises(ValueError, match="not proven"):
        owner.verify_domain_challenge(challenge, owner_b.did, dns_txt=published)


def test_dns_01_fails_on_no_records(owner_a):
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    with pytest.raises(ValueError, match="not proven"):
        owner.verify_domain_challenge(challenge, owner_a.did, dns_txt=lambda _n: [])


# ── fail closed ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_empty_domain_is_the_same_error_as_a_missing_one(blank):
    """⚠️ Unset and empty are one error — a blank value is not a configured one."""
    with pytest.raises(owner.OwnerConfigError, match="domain is required"):
        owner.validate_domain(blank)
    with pytest.raises(owner.OwnerConfigError, match="domain is required"):
        owner.validate_domain(None)


@pytest.mark.parametrize(
    "bad",
    [
        "https://moonbakery.com",
        "moonbakery.com/path",
        "moonbakery.com:8443",
        "*.moonbakery.com",
        "localhost",
        "moon bakery.com",
        ".moonbakery.com",
        "moonbakery..com",
        "-bad.com",
    ],
)
def test_domains_that_are_not_bare_hostnames_are_refused(bad):
    with pytest.raises(owner.OwnerConfigError):
        owner.validate_domain(bad)


def test_domain_is_normalised_not_merely_accepted():
    assert owner.validate_domain("  MoonBakery.COM. ") == "moonbakery.com"


def test_unknown_challenge_method_is_refused(owner_a):
    with pytest.raises(owner.OwnerConfigError, match="method must be one of"):
        owner.build_domain_challenge(DOMAIN, "email", owner_a.did)


def test_a_missing_transport_fails_closed_rather_than_passing(owner_a):
    """No fetcher for HTTP-01 (or no resolver for DNS-01) must be "not proven",
    never "nothing to check, so fine"."""
    http_challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    with pytest.raises(ValueError, match="not proven"):
        owner.verify_domain_challenge(http_challenge, owner_a.did, http_get_text=None)
    dns_challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    with pytest.raises(ValueError, match="not proven"):
        owner.verify_domain_challenge(dns_challenge, owner_a.did, dns_txt=None)


def test_a_raising_fetcher_is_indeterminate_not_verified(owner_a):
    def boom(_url):
        raise RuntimeError("network on fire")

    verifier = owner.make_bound_domain_control_verifier(owner_a.did, http_get_text=boom)
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    verdict = verifier.verify(
        {"claims": {"domain": DOMAIN, "method": owner.HTTP_01, "token": challenge.token}},
        {"grantor_did": owner_a.did, "anchor": {"id": DOMAIN}},
    )
    assert verdict.status == "INDETERMINATE"


def test_building_a_challenge_publishes_nothing(owner_a, monkeypatch):
    """Nothing auto-fires: minting a challenge performs no I/O at all. The owner
    publishes it as a deliberate, separate step.

    Asserted by making the network itself explode rather than by counting calls
    into a list nothing could ever append to — an empty-list assertion here would
    read like coverage and check nothing.
    """
    import httpx

    def explode(*_a, **_k):
        raise AssertionError("build_domain_challenge touched the network")

    monkeypatch.setattr(httpx, "get", explode)
    monkeypatch.setattr(httpx, "post", explode)

    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did, token="fixed-token")
    assert challenge.key_authorization == owner.key_authorization("fixed-token", owner_a.did)
    assert challenge.location == owner.http_challenge_url(DOMAIN, "fixed-token")


# ── the REAL transports, exercised rather than described ─────────────────────


def test_httpx_text_fetcher_returns_the_body_on_200():
    with _ChallengeServer("the-proof-value", "/probe") as server:
        assert owner.httpx_text_fetcher()(f"http://127.0.0.1:{server.port}/probe") == "the-proof-value"


def test_httpx_text_fetcher_returns_none_on_404():
    with _ChallengeServer(None, "/nothing") as server:
        assert owner.httpx_text_fetcher()(f"http://127.0.0.1:{server.port}/missing") is None


def test_httpx_text_fetcher_returns_none_when_unreachable():
    """Unreachable is "not proven", never an exception that a caller might
    mistake for a different failure — and never a pass."""
    assert owner.httpx_text_fetcher(timeout=0.5)("http://127.0.0.1:9/anything") is None


def test_httpx_text_fetcher_does_not_follow_a_redirect():
    """A redirect would let a domain that does not serve the proof point at one
    that does, which is the whole attack in a different costume."""

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.example/proof")
            self.end_headers()

        def log_message(self, *_a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        assert owner.httpx_text_fetcher()(f"http://127.0.0.1:{port}/probe") is None
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_dnspython_txt_lookup_joins_the_strings_of_a_record(monkeypatch):
    class _Rec:
        strings = (b"first-half", b"second-half")

    class _Resolver:
        lifetime = 0

        def resolve(self, name, rtype):
            assert rtype == "TXT"
            return [_Rec()]

    import dns.resolver

    monkeypatch.setattr(dns.resolver, "Resolver", _Resolver)
    assert owner.dnspython_txt_lookup()("_x.example.com") == ["first-halfsecond-half"]


def test_dnspython_txt_lookup_returns_empty_on_nxdomain(monkeypatch):
    class _Resolver:
        lifetime = 0

        def resolve(self, *_a):
            raise RuntimeError("NXDOMAIN")

    import dns.resolver

    monkeypatch.setattr(dns.resolver, "Resolver", _Resolver)
    assert owner.dnspython_txt_lookup()("_x.example.com") == []


def test_dnspython_txt_lookup_names_the_alternative_when_dnspython_is_absent(monkeypatch):
    """⚠️ Missing resolver and missing record are DIFFERENT answers.

    Collapsing them would report an unprovable challenge as a failed one, which
    tells the user to fix their DNS when the real fix is an install.
    """
    import builtins

    real_import = builtins.__import__

    def no_dns(name, *args, **kwargs):
        if name.startswith("dns"):
            raise ImportError("no dnspython")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_dns)
    with pytest.raises(owner.OwnerConfigError, match="use HTTP-01 instead"):
        owner.dnspython_txt_lookup()


def test_dns_01_challenge_location_names_the_txt_record(owner_a):
    challenge = owner.build_domain_challenge(DOMAIN, owner.DNS_01, owner_a.did)
    assert challenge.location == f"TXT {owner.DOMAIN_CHALLENGE_DNS_NAME}.{DOMAIN}"


def test_jwk_thumbprint_refuses_a_key_of_the_wrong_length():
    with pytest.raises(ValueError, match="32 bytes"):
        owner.jwk_thumbprint(base64.b64encode(b"short").decode())


def test_verifier_refuses_when_the_attested_domain_is_not_the_anchored_one(owner_a):
    """The check nanda-connect's verifier does make, kept — the binding check is
    additional to it, not a replacement for it."""
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    verifier = owner.make_bound_domain_control_verifier(owner_a.did, http_get_text=_served(challenge))
    verdict = verifier.verify(
        {"claims": {"domain": DOMAIN, "method": owner.HTTP_01, "token": challenge.token}},
        {"grantor_did": owner_a.did, "anchor": {"id": "a-different-domain.com"}},
    )
    assert verdict.status == "REFUTED"
    assert verdict.reason == "anchor_mismatch"


@pytest.mark.parametrize(
    "claims",
    [
        {"method": "http-01", "token": "t"},  # no domain
        {"domain": DOMAIN, "method": "http-01"},  # no token
        {"domain": DOMAIN, "method": "carrier-pigeon", "token": "t"},
        {"domain": "", "method": "http-01", "token": "t"},
    ],
)
def test_the_bound_validator_returns_none_on_unusable_claims(owner_a, claims):
    validator = owner.make_bound_challenge_validator(owner_a.did, http_get_text=lambda _u: "anything")
    assert validator(claims) is None


# ── the seam, and the shared machinery ───────────────────────────────────────


def test_the_verifier_conforms_to_sm_authority_s_evidence_verifier_protocol(owner_a):
    """The seam the brief pointed at is ``make_domain_control_verifier``'s
    injected-validator argument in nanda-connect. That package is not on PyPI and
    not importable here, so this implements ``sm_authority``'s runtime-checkable
    ``EvidenceVerifier`` Protocol — the public contract that seam is defined
    against — rather than forking or vendoring anything. Asserted mechanically so
    the claim is checked, not just written down."""
    from sm_authority.verify import EvidenceVerifier

    assert isinstance(owner.make_bound_domain_control_verifier(owner_a.did), EvidenceVerifier)


def test_nanda_connect_is_still_not_importable():
    """Pins the reason for the above. If this ever fails, nanda-connect became a
    real dependency and the verifier should move to its injection seam."""
    with pytest.raises(ImportError):
        import nanda_connect  # noqa: F401


def test_the_domain_path_reuses_the_dat_grant_and_the_listing_gate(owner_a):
    """Same owner key, same consent artifact, same gate as the OIDC path — only
    the evidence type and the anchor differ."""
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    binding = {
        "owner_did": owner_a.did,
        "subject": assertion.domain,
        "anchor": assertion.anchor,
        "evidence": owner.build_domain_evidence(owner=owner_a, assertion=assertion),
        "grant": owner.build_listing_grant(owner=owner_a, agent_did=AGENT_DID),
    }
    verdict = owner.listing_grant_verdict(binding, AGENT_DID)
    assert verdict.ok is True, verdict
    assert binding["grant"]["grantor_did"] == owner_a.did
    assert binding["grant"]["grantee_did"] == AGENT_DID
    assert binding["grant"]["scope"]["action_categories"] == [owner.LISTING_ACTION_CATEGORY]
    # The anchor is the domain itself — durable, unlike the OIDC path's email.
    assert binding["anchor"] == {"method": "domain", "issuer": owner.HTTP_01, "id": DOMAIN}


def test_the_domain_envelope_signature_verifies(owner_a):
    from sm_authority import verify_envelope_signature

    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    assert verify_envelope_signature(owner.build_domain_evidence(owner=owner_a, assertion=assertion)) is True


def test_a_self_granted_domain_consent_is_still_refused(owner_a):
    """The self-grant refusal is shared, not re-implemented per evidence type."""
    from community_member._dat import build_dat

    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    binding = {
        "owner_did": owner_a.did,
        "subject": DOMAIN,
        "anchor": assertion.anchor,
        "evidence": owner.build_domain_evidence(owner=owner_a, assertion=assertion),
        "grant": build_dat(
            grantor_sk_bytes=owner_a.signing_key_bytes(),
            grantor_did=owner_a.did,
            grantee_did=owner_a.did,
            action_categories=[owner.LISTING_ACTION_CATEGORY],
            not_after="2099-01-01T00:00:00Z",
        ),
    }
    assert owner.listing_grant_verdict(binding, owner_a.did).reason == "self_grant"


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda c: c.pop("token"), "evidence_challenge_incomplete"),
        (lambda c: c.pop("domain"), "evidence_challenge_incomplete"),
        (lambda c: c.update(method="email"), "evidence_challenge_method"),
        (lambda c: c.update(key_authorization="anything-else"), "evidence_challenge_unbound"),
        (lambda c: c.pop("key_authorization"), "evidence_challenge_unbound"),
    ],
)
def test_gate_refusals_for_malformed_domain_evidence(owner_a, mutate, expected):
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    envelope = owner.build_domain_evidence(owner=owner_a, assertion=assertion)
    mutate(envelope["evidence"][0]["claims"])
    binding = {
        "owner_did": owner_a.did,
        "subject": DOMAIN,
        "anchor": assertion.anchor,
        "evidence": envelope,
        "grant": owner.build_listing_grant(owner=owner_a, agent_did=AGENT_DID),
    }
    assert owner.listing_grant_verdict(binding, AGENT_DID).reason == expected


def test_gate_refuses_a_domain_that_is_not_the_anchored_one(owner_a):
    challenge = owner.build_domain_challenge(DOMAIN, owner.HTTP_01, owner_a.did)
    assertion = owner.verify_domain_challenge(challenge, owner_a.did, http_get_text=_served(challenge))
    envelope = owner.build_domain_evidence(owner=owner_a, assertion=assertion)
    envelope["anchor"] = {"method": "domain", "issuer": owner.HTTP_01, "id": "someone-else.com"}
    binding = {
        "owner_did": owner_a.did,
        "subject": DOMAIN,
        "anchor": envelope["anchor"],
        "evidence": envelope,
        "grant": owner.build_listing_grant(owner=owner_a, agent_did=AGENT_DID),
    }
    assert owner.listing_grant_verdict(binding, AGENT_DID).reason == "evidence_anchor_mismatch"
