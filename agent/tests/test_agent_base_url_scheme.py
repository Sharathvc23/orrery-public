"""The A2A card must advertise the scheme the CLIENT used, not our last hop.

``_agent_base_url`` built the card's ``url`` from ``request.url.scheme``.
Behind a TLS-terminating proxy the application leg is plain HTTP, so that
reports ``http`` for a request the client made over HTTPS.

Measured live 2026-10-25: all six astrocity agent services served
``url: http://<domain>`` in their agent cards while ``AGENT_PUBLIC_URL`` was
correctly ``https://<domain>``. A non-``https`` URL is dropped outright by the
NANDA Index's entry sanitizer, so the card advertised an address the index
would refuse — and nothing local could show it, because locally there is no
proxy and the scheme is right by accident.

The second defect was duplication: ``registry.public_endpoint`` already
resolved ``AGENT_PUBLIC_URL`` for the endpoint registered on the org, and this
function ignored it. One fact, two derivations, free to disagree — which is
exactly what they did. ``test_card_url_and_registered_endpoint_agree`` is the
guard that matters: it asserts the two cannot drift apart again.
"""

from __future__ import annotations

import pytest

from community_member import registry, server


class _FakeURL:
    def __init__(self, scheme: str) -> None:
        self.scheme = scheme


class _FakeRequest:
    """Just the surface ``_agent_base_url`` reads."""

    def __init__(self, host: str | None, scheme: str, headers: dict | None = None) -> None:
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        if host is not None:
            self.headers["host"] = host
        self.url = _FakeURL(scheme)


@pytest.fixture(autouse=True)
def _no_ambient_public_url(monkeypatch):
    monkeypatch.delenv("AGENT_PUBLIC_URL", raising=False)


# ── the defect ────────────────────────────────────────────────────────────────


def test_a_proxied_https_request_does_not_advertise_http():
    """THE REGRESSION GUARD. The proxy's internal leg is plain HTTP; the card
    must still say https, because that is what the client used."""
    req = _FakeRequest(
        host="agent-7.example.net",  # a fixture host, not a live deployment
        scheme="http",  # what the app sees behind the proxy
        headers={"X-Forwarded-Proto": "https"},
    )
    assert server._agent_base_url(req) == "https://agent-7.example.net"


def test_the_first_entry_of_a_forwarded_chain_is_the_client():
    """X-Forwarded-Proto accumulates across hops; the originating client is first."""
    req = _FakeRequest(host="agent.example", scheme="http", headers={"X-Forwarded-Proto": "https, http"})
    assert server._agent_base_url(req) == "https://agent.example"


def test_an_unproxied_request_keeps_its_own_scheme():
    """No forwarding header — a direct http request is genuinely http, and must
    not be upgraded on a guess."""
    req = _FakeRequest(host="localhost:7777", scheme="http")
    assert server._agent_base_url(req) == "http://localhost:7777"


def test_a_direct_https_request_is_still_https():
    req = _FakeRequest(host="agent.example", scheme="https")
    assert server._agent_base_url(req) == "https://agent.example"


@pytest.mark.parametrize("bogus", ["", "   ", "gopher", "HTTPS;DROP", "javascript"])
def test_an_unusable_forwarded_proto_falls_back_rather_than_being_echoed(bogus):
    """The header is attacker-settable, so an unrecognised value must not reach
    the advertised URL — it falls back to the request's own scheme."""
    req = _FakeRequest(host="agent.example", scheme="http", headers={"X-Forwarded-Proto": bogus})
    assert server._agent_base_url(req) == "http://agent.example"


def test_a_capitalised_forwarded_proto_is_honoured():
    req = _FakeRequest(host="agent.example", scheme="http", headers={"X-Forwarded-Proto": "HTTPS"})
    assert server._agent_base_url(req) == "https://agent.example"


# ── one derivation, not two ───────────────────────────────────────────────────


def test_agent_public_url_wins_over_the_request(monkeypatch):
    """The operator's declaration beats anything inferred from a request."""
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://agent.example.org/")
    req = _FakeRequest(host="internal-hostname.railway.internal", scheme="http")
    assert server._agent_base_url(req) == "https://agent.example.org"


def test_card_url_and_registered_endpoint_agree(monkeypatch):
    """THE GUARD THAT MATTERS. The card's url and the endpoint registered on
    the org must come from one derivation. They disagreed in production: the
    card said http, the registered endpoint said https."""
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://agent.example.org")
    req = _FakeRequest(host="whatever.internal", scheme="http")
    card_url = server._agent_base_url(req)
    registered = registry.public_endpoint("http://localhost:7777")
    assert card_url == registered == "https://agent.example.org"


def test_base_url_resolution_routes_through_public_endpoint():
    """A source guard: re-reading AGENT_PUBLIC_URL here instead of delegating is
    how the two values came apart, so the delegation is asserted, not assumed."""
    import inspect

    src = inspect.getsource(server._agent_base_url)
    # The docstring names the variable on purpose; only the CODE must not read it.
    body = src.replace(server._agent_base_url.__doc__ or "", "")
    assert "registry.public_endpoint" in body, "no longer shares the derivation"
    assert "AGENT_PUBLIC_URL" not in body, "re-reads the env instead of delegating"


# ── no request at all ─────────────────────────────────────────────────────────


def test_no_host_header_falls_back_to_the_local_dashboard():
    from community_member import DASHBOARD_PORT

    req = _FakeRequest(host=None, scheme="http")
    assert server._agent_base_url(req) == f"http://localhost:{DASHBOARD_PORT}"


def test_a_missing_request_does_not_raise():
    from community_member import DASHBOARD_PORT

    assert server._agent_base_url(None) == f"http://localhost:{DASHBOARD_PORT}"
