"""An org that configures no registry talks to no registry — and says so.

`REGISTRY_URL` unset used to resolve to `https://nest.projectnanda.org`, so a
deployment that configured nothing contacted a registry run by somebody else.
Not only to publish: `reconcile_stale_agents` queried it at boot and
`federation_discovery` queried it every cycle, and **neither consults
`AUTO_REGISTER`** — a self-hoster who had explicitly opted out still reached out.

⚠️ **THE KNOWN COST IS WHY THE NOTICES EXIST.** Dropping the default also stops
peer discovery, and that failure is quiet: *"no peers found"* is
indistinguishable from *"no peers exist"*. A boot line alone scrolls past once
and every later cycle is silent, so each path that would have queried says so at
the point it declines — rate-limited, because discovery runs on a timer and a
warning per cycle is noise.

`Z1` is the acceptance criterion: **zero** outbound attempts to any registry
across a real boot and a discovery cycle. It is a number, driven, not a claim —
"the paths are all gated on truthiness" was reported once and was false in three
of four places.
"""

from __future__ import annotations

import importlib
import sys

import pytest

import federation_discovery
import nanda_registry
import registry_policy


class Recorder:
    """Every attempted URL, and nothing leaves the machine."""

    def __init__(self):
        self.attempts: list[str] = []

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def _record(self, method, url, **k):
        import httpx

        self.attempts.append(f"{method} {url}")
        raise httpx.ConnectError("blocked by the recorder", request=None)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Recorder({self.attempts!r})"

    async def get(self, u, **k):
        return await self._record("GET", u, **k)

    async def post(self, u, **k):
        return await self._record("POST", u, **k)

    async def delete(self, u, **k):
        return await self._record("DELETE", u, **k)


class _HttpxShim:
    """A stand-in for the `httpx` MODULE, installed on the modules under test.

    Not a global `httpx.AsyncClient` patch: `openai` subclasses that class at ITS
    import time, so replacing it globally after openai has loaded raises
    `TypeError: Recorder.__init__() takes 1 positional argument`. Patching the
    module reference held by `nanda_registry` and `federation_discovery` scopes
    the recorder to the code whose outbound calls are the subject.
    """

    def __init__(self, recorder):
        import httpx as _real

        self.AsyncClient = recorder
        self.ConnectError = _real.ConnectError
        self.TimeoutException = _real.TimeoutException


def _install_recorder(monkeypatch) -> Recorder:
    rec = Recorder()
    for mod in (nanda_registry, federation_discovery):
        monkeypatch.setattr(mod, "httpx", _HttpxShim(rec))
    return rec


@pytest.fixture
def no_registry(monkeypatch):
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    monkeypatch.delenv("NANDA_INDEX_URL", raising=False)
    registry_policy.reset_decline_notices()
    yield
    registry_policy.reset_decline_notices()


# ---------------------------------------------------------------------------
# The value
# ---------------------------------------------------------------------------


def test_V1_an_unset_registry_url_is_empty_not_a_default(no_registry) -> None:
    assert registry_policy.registry_url() == ""


def test_V2_an_explicitly_empty_one_is_also_empty(monkeypatch) -> None:
    """The empty-vs-unset fix's unset-vs-empty distinction is moot for the VALUE now — both mean
    "none" — but the reason it existed is not: compose's `${VAR:-default}`
    substitutes for an empty value too, which is exactly why the default had to
    go from the CODE rather than from the compose file."""
    monkeypatch.setenv("REGISTRY_URL", "")
    assert registry_policy.registry_url() == ""
    monkeypatch.setenv("REGISTRY_URL", "   ")
    assert registry_policy.registry_url() == ""


def test_V3_a_configured_one_is_used_verbatim(monkeypatch) -> None:
    """Both directions. Asserting only the empty cases would be satisfied by a
    function that always returned "" — which would silently disable a registry an
    operator DID configure."""
    monkeypatch.setenv("REGISTRY_URL", " https://registry.example ")
    assert registry_policy.registry_url() == "https://registry.example"


def test_V4_the_former_default_is_kept_only_to_be_named(no_registry) -> None:
    """It survives as a constant so the notices can tell an upgrading operator
    what they used to inherit. It must never be RETURNED as a value."""
    assert registry_policy.FORMER_DEFAULT_REGISTRY_URL == "https://nest.projectnanda.org"
    assert registry_policy.registry_url() != registry_policy.FORMER_DEFAULT_REGISTRY_URL


# ---------------------------------------------------------------------------
# Z1 — the acceptance criterion, driven
# ---------------------------------------------------------------------------


async def test_Z1_zero_outbound_attempts_across_boot_and_a_discovery_cycle(no_registry, monkeypatch) -> None:
    """THE NUMBER. Boot the real app and run a discovery cycle with no registry
    configured; every outbound attempt is recorded and the total must be zero.

    Driven rather than asserted from the guards, because "the three paths are all
    gated on truthiness" was reported once and was FALSE in three of four places:
    `federation_discovery.discover`, `get_agent_count` and (before that change)
    `clean_stale_agents` all built a URL from an empty base and attempted the
    resulting RELATIVE path. Reading a guard two functions away from the call is
    how that was missed.
    """
    rec = _install_recorder(monkeypatch)
    monkeypatch.setenv("AGENT_ID", "TEST-zero-org")
    monkeypatch.setenv("AGENT_NAME", "Zero Org")
    monkeypatch.setenv("PUBLIC_URL", "https://zero.example")

    async def _stub_pg(method, table, params=None, body=None):
        return []

    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")
    monkeypatch.setattr(ca, "pg_request", _stub_pg)

    from fastapi.testclient import TestClient

    with TestClient(ca.app):
        pass
    boot = list(rec.attempts)
    rec.attempts.clear()

    federation_discovery.init("", "TEST-zero-org", "https://zero.example", {}, {})
    nanda_registry.init("", "TEST-zero-org", "Zero Org", "d", "f", {}, "https://zero.example")
    await federation_discovery.discover()
    await nanda_registry.reconcile_stale_agents("https://zero.example")
    await nanda_registry.get_agent_count()
    cycle = list(rec.attempts)

    assert boot == [], f"boot contacted a registry with none configured: {boot}"
    assert cycle == [], f"a discovery cycle contacted a registry with none configured: {cycle}"


# ---------------------------------------------------------------------------
# The notices — the mitigation IS the work
# ---------------------------------------------------------------------------


async def test_N1_every_declining_path_says_so(no_registry, monkeypatch, capsys) -> None:
    """Each path that WOULD have queried announces that it did not, at the point
    it declines. A boot line alone scrolls past once; discovery runs forever."""
    _install_recorder(monkeypatch)
    federation_discovery.init("", "org", "https://zero.example", {}, {})
    nanda_registry.init("", "org", "Org", "d", "f", {}, "https://zero.example")

    await federation_discovery.discover()
    await nanda_registry.reconcile_stale_agents("https://zero.example")
    await nanda_registry.get_agent_count()
    await nanda_registry._register_on_nest("org", {"endpoint": "https://zero.example"})

    out = capsys.readouterr().out
    for where in ("federation discovery", "registry reconcile", "registry agent count", "registry publication"):
        assert where in out, f"{where} declined silently — indistinguishable from having looked and found nothing"
    assert registry_policy.FORMER_DEFAULT_REGISTRY_URL in out, (
        "the notice must name what an upgrading operator used to inherit, or they cannot restore it"
    )


def test_N2_the_notice_is_rate_limited_but_returns(no_registry) -> None:
    """Discovery runs on a timer, so a notice per cycle is noise — and noise is
    how a real warning stops being read. It still RETURNS whether it printed, so
    a caller (and this test) can tell suppression from silence; a notice that
    could not report its own suppression would be untestable."""
    assert registry_policy.note_declined("probe", "thing", now=0.0) is True
    assert registry_policy.note_declined("probe", "thing", now=10.0) is False
    assert registry_policy.note_declined("probe", "thing", now=registry_policy.DECLINE_NOTICE_INTERVAL_S + 1) is True
    assert registry_policy.note_declined("other-path", "thing", now=10.0) is True, (
        "the rate limit is per path — one chatty path must not silence a different one"
    )


async def test_N3_boot_names_the_variable_and_the_discovery_consequence(no_registry, monkeypatch, capsys) -> None:
    """An operator upgrading needs to know the name of the thing to set AND that
    federation went quiet — the second is the part that is otherwise invisible."""
    _install_recorder(monkeypatch)
    monkeypatch.setenv("AGENT_ID", "TEST-boot-notice")
    monkeypatch.setenv("AGENT_NAME", "Boot Notice")

    async def _stub_pg(method, table, params=None, body=None):
        return []

    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")
    monkeypatch.setattr(ca, "pg_request", _stub_pg)

    from fastapi.testclient import TestClient

    with TestClient(ca.app):
        pass

    out = capsys.readouterr().out
    assert "NO REGISTRY CONFIGURED" in out
    assert "REGISTRY_URL" in out, "the operator must be told the name of the variable to set"
    assert "discovers no peers" in out, "the discovery consequence is the silent half and must be named"


# ---------------------------------------------------------------------------
# What the org tells its own members about where they are listed
# ---------------------------------------------------------------------------


def test_M1_a_virtual_member_is_not_told_it_is_registered_somewhere_it_was_never_sent(no_registry, monkeypatch) -> None:
    """The virtual-member system prompt used to hardcode "You are registered on
    NEST (nest.projectnanda.org)" — a member of an org that publishes nowhere
    was told, in every conversation, that it was listed on a directory the org
    had never contacted. With no registry the sentence is absent; with one it
    names the registry actually configured."""
    sys.modules.pop("chapter_agent", None)
    ca = importlib.import_module("chapter_agent")
    member = {"name": "Ada", "description": "a test member", "skills": ["rust"]}

    prompt = ca.build_member_system_prompt("ada", member)
    assert "registered on" not in prompt
    assert "projectnanda" not in prompt

    monkeypatch.setenv("REGISTRY_URL", "https://registry.example")
    monkeypatch.setattr(ca, "PUBLIC_URL", "https://real-org.example.com")
    prompt = ca.build_member_system_prompt("ada", member)
    assert "You are registered on https://registry.example." in prompt
