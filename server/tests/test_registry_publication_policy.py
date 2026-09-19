"""The empty-vs-unset fix — a dev stack must not publish itself to the production registry.

Not theoretical. The live NEST registry accumulated **31 non-routable records**
— 27 advertising `http://localhost:…` (ports 7000/7100/7300/7400/7500/7600/7700/
7777/7799/7800/7900/6500) and 4 advertising docker-internal names (`http://agent:8080`,
`http://server2:7000`). Roughly a third of that registry was our own dev and CI
stacks, and the names read like a tour of this test suite: Demo Org, Skill Org,
E2E Probe Bot, TEST Conformance CI, Restart Probe. Every record advertises an
endpoint no consumer can reach.

Three independent failures produced it, and each gets its own test here because
each could recur alone:

  * **`REGISTRY_URL=` meant LIVE** (P1-P2). compose read
    `${REGISTRY_URL:-https://nest.projectnanda.org}` and shell `:-` substitutes
    the default for an *empty* value too, so the natural way to say "no
    registry" resolved to production.
  * **`AUTO_REGISTER=false` did nothing** (P3-P4). Documented in two docs files,
    passed by compose, written by the setup wizard, referenced by a CI comment —
    and never read by a single line of server code. An off-switch that is
    documented but unwired is worse than none: operators believe they opted out.
  * **Nothing checked what was being advertised** (E1-E7). The other two are
    configuration mistakes, and configuration mistakes recur. The endpoint guard
    does not depend on anyone configuring anything correctly, and it alone would
    have stopped all 31.

Publishing by default is deliberately preserved (`docs/PRODUCT.md` lists
auto-publish as a feature). H1-H2 pin that a real deployment still publishes —
a fix that quietly stopped legitimate registration would trade a visible problem
for an invisible one.

Classification: ADVERSARIAL (P1-P4, E1-E5), HAPPY (H1-H2), EDGE (E6-E7).
"""

from __future__ import annotations

import pytest

import registry_policy


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    monkeypatch.delenv("AUTO_REGISTER", raising=False)


# ---------------------------------------------------------------------------
# P1-P2 — an explicitly empty REGISTRY_URL means "no registry"
# ---------------------------------------------------------------------------


def test_P1_empty_registry_url_disables_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE FOOT-GUN. `REGISTRY_URL=` is how anyone would say "don't publish"."""
    monkeypatch.setenv("REGISTRY_URL", "")

    assert registry_policy.registry_url() == ""
    assert registry_policy.publication_blocked_reason("https://real.example.com") is not None


def test_P2_whitespace_registry_url_also_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    """`REGISTRY_URL=" "` from a sloppy .env is the same intent."""
    monkeypatch.setenv("REGISTRY_URL", "   ")

    assert registry_policy.registry_url() == ""


def test_P3_unset_registry_url_means_NO_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """REVERSED by that change, on a human ruling. This asserted publish-BY-DEFAULT:
    an unset REGISTRY_URL resolved to https://nest.projectnanda.org.

    The reason it changed is not tidiness. That default was reached by paths that
    do not consult AUTO_REGISTER — the boot reconcile and federation discovery —
    so an org that had explicitly opted out of publishing still contacted a
    registry run by somebody else. A default that points a stranger's deployment
    at a third party is an assumption about who they federate with.

    The empty-vs-unset fix's unset-vs-empty distinction is moot for the VALUE now (both mean none),
    but its reasoning still holds and is why the default had to go from the CODE:
    compose's ``${VAR:-default}`` substitutes for an empty value too.
    """
    monkeypatch.delenv("REGISTRY_URL", raising=False)

    assert registry_policy.registry_url() == ""
    assert registry_policy.registry_url() != registry_policy.FORMER_DEFAULT_REGISTRY_URL


# ---------------------------------------------------------------------------
# P4-P5 — AUTO_REGISTER is finally wired
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["false", "False", "0", "no", "off", ""])
def test_P4_auto_register_false_disables_publication(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """This flag was documented, shipped in compose, written by the setup
    wizard — and read by NO server code. Every falsey spelling an operator might
    reach for now works."""
    monkeypatch.setenv("AUTO_REGISTER", value)

    assert registry_policy.auto_register_enabled() is False
    assert registry_policy.publication_blocked_reason("https://real.example.com") == "AUTO_REGISTER is false"


def test_P5_auto_register_unset_or_true_permits_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    assert registry_policy.auto_register_enabled() is True
    monkeypatch.setenv("AUTO_REGISTER", "true")
    assert registry_policy.auto_register_enabled() is True


# ---------------------------------------------------------------------------
# E1-E7 — the guard that needed no configuration to work
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        # every shape actually found polluting the live registry
        "http://localhost:7000",
        "http://localhost:7100",
        "http://localhost:7799",
        "http://localhost:6500",
        "http://agent:8080",
        "http://server2:7000",
    ],
)
def test_E1_the_endpoints_that_polluted_production_are_refused(endpoint: str) -> None:
    ok, reason = registry_policy.is_publishable_endpoint(endpoint)

    assert ok is False, f"{endpoint} would have been published again"
    assert reason, "a refusal must say why"


@pytest.mark.parametrize(
    "endpoint",
    ["http://127.0.0.1:7000", "http://[::1]:7000", "http://0.0.0.0:7000"],
)
def test_E2_loopback_and_unspecified_addresses_are_refused(endpoint: str) -> None:
    assert registry_policy.is_publishable_endpoint(endpoint)[0] is False


@pytest.mark.parametrize(
    "endpoint",
    ["http://10.0.0.5:7000", "http://192.168.1.20:7000", "http://172.16.4.4:7000", "http://169.254.1.1:7000"],
)
def test_E3_private_and_link_local_ranges_are_refused(endpoint: str) -> None:
    """These have dots, so a naive "must contain a dot" rule would pass them —
    and they are just as unreachable for a registry consumer."""
    assert registry_policy.is_publishable_endpoint(endpoint)[0] is False


def test_E4_the_guard_ignores_configuration_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    """The point of the guard: it holds even when every switch says publish.
    Configuration mistakes recur; this one does not depend on configuration."""
    monkeypatch.setenv("REGISTRY_URL", "https://nest.projectnanda.org")
    monkeypatch.setenv("AUTO_REGISTER", "true")

    reason = registry_policy.publication_blocked_reason("http://localhost:7000")

    assert reason is not None
    assert "loopback" in reason


def test_E5_a_missing_endpoint_is_refused() -> None:
    for endpoint in ("", "   ", "not-a-url"):
        assert registry_policy.is_publishable_endpoint(endpoint)[0] is False


def test_E6_public_hostnames_and_ips_are_publishable() -> None:
    """The guard must not be so broad it blocks real deployments."""
    for endpoint in (
        "https://agent.example.com",
        "https://org.example.com",
        "http://8.8.8.8:7000",
    ):
        ok, reason = registry_policy.is_publishable_endpoint(endpoint)
        assert ok is True, f"{endpoint} must remain publishable: {reason}"


def test_E6b_reserved_documentation_ranges_are_refused() -> None:
    """Caught by writing E6: `203.0.113.10` (RFC 5737 TEST-NET-3) reads like a
    public IP and has dots, but Python classifies the documentation ranges as
    private — and they are indeed unroutable. Worth its own assertion, because
    the guard being stricter than "contains a dot" is the property that makes it
    useful."""
    for endpoint in ("http://203.0.113.10:7000", "http://192.0.2.5:7000", "http://198.51.100.7:7000"):
        assert registry_policy.is_publishable_endpoint(endpoint)[0] is False


def test_E7_localhost_subdomains_are_refused() -> None:
    assert registry_policy.is_publishable_endpoint("http://org.localhost:7000")[0] is False


# ---------------------------------------------------------------------------
# H1-H2 — a real deployment still publishes
# ---------------------------------------------------------------------------


def test_H1_a_real_deployment_is_not_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-publish stays the default. A fix that silently stopped legitimate
    registration would swap a visible problem (noise) for an invisible one (an
    org nobody can discover)."""
    monkeypatch.setenv("REGISTRY_URL", "https://nest.projectnanda.org")

    assert registry_policy.publication_blocked_reason("https://agent.example.com") is None


def test_H2_realistic_deployment_hostnames_all_pass_the_guard() -> None:
    """The shapes a real deployment actually uses are not blocked.

    These are fixture hostnames on RFC 2606's reserved documentation domain, and
    that is the point: the guard reasons about loopback, private and reserved IP
    ranges, never about who operates a host. It used to enumerate the operator's
    own live deployment URLs, which taught a reader nothing the guard depends on
    while publishing running infrastructure into a repository strangers read —
    and four of those hosts were not even this project's to name. A test
    asserting policy needs a hostname, not somebody's production.
    """
    for host in (
        "agent.example.com",
        "multi.label.example.com",
        "hyphen-ated.example.org",
        "deep.sub.domain.example.net",
    ):
        assert registry_policy.is_publishable_endpoint(f"https://{host}")[0] is True
