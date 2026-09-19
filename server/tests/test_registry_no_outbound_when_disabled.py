"""The empty-vs-unset fix — the switches actually stop outbound traffic, at the publish paths.

`test_registry_publication_policy.py` pins the decision. This pins the
*consequence*: that no HTTP request leaves the process. They are different
claims, and only the second one is what polluted the registry — a correct policy
that some path forgets to consult buys nothing.

So every test here installs a tripwire over `httpx.AsyncClient` and asserts on
the requests that were actually attempted, rather than on a return value.

Classification: ADVERSARIAL — each case is a configuration an operator believed
meant "do not publish", while the process published anyway.
"""

from __future__ import annotations

import httpx
import pytest

import nanda_registry


class _Tripwire:
    """Records every request instead of making one."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    async def __aenter__(self) -> _Tripwire:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def _record(self, method: str, url: str, **kwargs: object):
        self.requests.append((method, url))
        raise AssertionError(f"outbound {method} {url} — nothing should have been published")

    async def post(self, url: str, **kwargs: object):
        return await self._record("POST", url)

    async def put(self, url: str, **kwargs: object):
        return await self._record("PUT", url)

    async def get(self, url: str, **kwargs: object):
        return await self._record("GET", url)


@pytest.fixture
def tripwire(monkeypatch: pytest.MonkeyPatch) -> _Tripwire:
    wire = _Tripwire()
    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", lambda *a, **k: wire)
    return wire


@pytest.fixture(autouse=True)
def _wired(monkeypatch: pytest.MonkeyPatch):
    """Wire the module, and RESTORE its globals afterwards.

    `nanda_registry` keeps its configuration in module globals, so a test that
    sets one and walks away changes the world for every test that runs later —
    which is exactly what an earlier draft of this file did: `_registry_url = ""`
    leaked and broke 14 pre-existing tests in test_nanda_registry.py that share
    module state across cases. Saved and restored explicitly rather than trusting
    each test to clean up after itself."""
    saved = (nanda_registry._registry_url, nanda_registry._public_url)
    monkeypatch.delenv("AUTO_REGISTER", raising=False)
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    nanda_registry.init(
        "https://nest.projectnanda.org",
        "TEST-395-org",
        "TEST 395 Org",
        "probe",
        "general",
        {},
        "https://real-org.example.com",
    )
    yield
    nanda_registry._registry_url, nanda_registry._public_url = saved


async def test_N1_empty_registry_url_sends_nothing(tripwire, monkeypatch: pytest.MonkeyPatch) -> None:
    """`REGISTRY_URL=` — the config that used to resolve to production."""
    monkeypatch.setenv("REGISTRY_URL", "")
    nanda_registry._registry_url = ""  # as init() would compute it now

    await nanda_registry.register_chapter("https://real-org.example.com")

    assert tripwire.requests == []


async def test_N2_auto_register_false_sends_nothing(tripwire, monkeypatch: pytest.MonkeyPatch) -> None:
    """The flag that was documented, shipped, and never read."""
    monkeypatch.setenv("AUTO_REGISTER", "false")

    await nanda_registry.register_chapter("https://real-org.example.com")

    assert tripwire.requests == []


async def test_N2b_auto_register_false_also_stops_the_index_refresh(tripwire, monkeypatch: pytest.MonkeyPatch) -> None:
    """The heartbeat's index refresh re-publishes the record. Before this it
    checked only that an index was configured — a caller that skipped the
    heartbeat's own guard would have PUT to the index with AUTO_REGISTER=false."""
    monkeypatch.setenv("AUTO_REGISTER", "false")
    monkeypatch.setattr(nanda_registry, "_index_urls", ["https://index.example"])

    ok = await nanda_registry.update_index_entry("TEST-395-org", {"endpoints": {"static": ["https://real-org.example.com"]}})

    assert ok is False
    assert tripwire.requests == []


async def test_N2d_auto_register_false_stops_the_boot_index_registration_too(tripwire, monkeypatch: pytest.MonkeyPatch) -> None:
    """register_on_index is the boot-time index publish. N1/N2 reach it only
    through register_chapter(facts=None), which never calls it — so the gate
    on this path was asserted by nothing. Called directly, with an index
    configured and full facts, AUTO_REGISTER=false must send nothing."""
    monkeypatch.setenv("AUTO_REGISTER", "false")
    monkeypatch.setattr(nanda_registry, "_index_urls", ["https://index.example"])

    ok = await nanda_registry.register_on_index("TEST-395-org", {"endpoints": {"static": ["https://real-org.example.com"]}})

    assert ok is False
    assert tripwire.requests == []


async def test_N2c_index_refresh_still_runs_when_permitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate must not turn the refresh off for everyone — with publication
    permitted and an index configured, the PUT goes out."""

    class _Recorder:
        requests: list[tuple[str, str]] = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def put(self, url, **kw):
            _Recorder.requests.append(("PUT", url))
            return httpx.Response(200)

    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", lambda *a, **k: _Recorder())
    monkeypatch.setattr(nanda_registry, "_index_urls", ["https://index.example"])
    # The one gate reads REGISTRY_URL for every publish path, index included —
    # the same rule register_on_index already lives under.
    monkeypatch.setenv("REGISTRY_URL", "https://registry.example")

    ok = await nanda_registry.update_index_entry("TEST-395-org", {"endpoints": {"static": ["https://real-org.example.com"]}})

    assert ok is True
    assert _Recorder.requests == [("PUT", "https://index.example/api/agents/TEST-395-org")]


async def test_N3_a_localhost_endpoint_sends_nothing(tripwire, monkeypatch: pytest.MonkeyPatch) -> None:
    """THE ONE THAT WOULD HAVE PREVENTED ALL 31. Every switch says publish; the
    endpoint is unreachable, so the record would be dead on arrival."""
    monkeypatch.setenv("REGISTRY_URL", "https://nest.projectnanda.org")
    monkeypatch.setenv("AUTO_REGISTER", "true")

    await nanda_registry.register_chapter("http://localhost:7000")

    assert tripwire.requests == []


async def test_N4_a_docker_internal_endpoint_sends_nothing(tripwire) -> None:
    """`http://agent:8080` — four live records looked exactly like this."""
    await nanda_registry.register_chapter("http://agent:8080")

    assert tripwire.requests == []


async def test_N5_the_refusal_is_logged_loudly(tripwire, monkeypatch, capsys: pytest.CaptureFixture[str]) -> None:
    """A silent refusal would be its own bug: an operator who expected to be
    published needs to know why they are not.

    A registry is configured explicitly here. Since that change an unset
    REGISTRY_URL means NO registry, and that check fires first — so without this
    the test would assert the endpoint guard's message while the empty-registry
    guard was the one that spoke. It would still have "passed" on the first
    assertion, which is why the second names the specific reason.
    """
    monkeypatch.setenv("REGISTRY_URL", "https://registry.test.invalid")
    await nanda_registry.register_chapter("http://localhost:7000")

    out = capsys.readouterr().out
    assert "NOT publishing" in out
    assert "loopback" in out


async def test_N6_a_real_deployment_still_publishes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must not have quietly disabled the documented feature. Here the
    tripwire is inverted: a request SHOULD be attempted."""
    attempted: list[str] = []

    class _Recorder(_Tripwire):
        async def _record(self, method: str, url: str, **kwargs: object):
            attempted.append(f"{method} {url}")
            raise RuntimeError("stop after the attempt")

    wire = _Recorder()
    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", lambda *a, **k: wire)
    monkeypatch.setenv("REGISTRY_URL", "https://nest.projectnanda.org")

    await nanda_registry.register_chapter("https://agent.example.com")

    assert attempted, "a routable endpoint with registration enabled must still publish"
    assert "nest.projectnanda.org" in attempted[0]
