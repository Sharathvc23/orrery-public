"""/health reports the proxy-hop count the RATE LIMITER IS USING, not the environment.

⚠️ WHY THIS FIELD EXISTS AT ALL. ``client_ip_for_rate_limit`` keys the per-IP
limiter on ``TRUSTED_PROXY_HOPS``. Left at 0 behind an edge proxy it keys on the
proxy's address instead of the caller's, so every member shares one bucket and a
single caller can 429 everyone — which is exactly what the startup comment in
``chapter_agent`` says the setting prevents. That was the deployed state of this
setting for as long as it has existed, on every live deployment, and nobody saw
it: nothing reported the value, so the only way to check was to read the hosting
platform's variables per deployment. A control that cannot be observed is
indistinguishable from one that was never switched on.

⚠️ AND WHY IT MUST NOT BE A FRESH READ OF os.environ. ``TRUSTED_PROXY_HOPS`` is
resolved ONCE at import. A field that re-read the environment in the handler
would print the value an operator just SET while the limiter went on keying with
the value it was IMPORTED with — a surface that agrees with the person reading it
precisely when they most need to be contradicted. That is not hypothetical: on a
sibling service the platform's variable listing read back the new value while the
running process used the old one through eighteen consecutive polls.

So the load-bearing test here is ``test_ADVERSARIAL_...environment_disagrees``:
it makes the environment and the process disagree and requires the endpoint to
side with the process. Every mirror implementation fails it, including a
carefully written one that reproduces the parsing rules exactly — because the
defect being guarded is not bad parsing, it is reading the wrong source.

Classification: ADVERSARIAL (the mirror) + EDGE (unusable inputs) + HAPPY.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-hops-chapter")
os.environ.setdefault("AGENT_NAME", "Test Hops Chapter")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from ._admin_fixtures import reset_chapter_agent_module  # noqa: E402

FIELD = "trusted_proxy_hops"


def _chapter(monkeypatch, raw: str | None):
    """A chapter process imported with TRUSTED_PROXY_HOPS set to ``raw``.

    ``raw=None`` means the variable is genuinely absent, which is a different
    input from the empty string and is one of the cases below.
    """
    if raw is None:
        monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    else:
        monkeypatch.setenv("TRUSTED_PROXY_HOPS", raw)
    return reset_chapter_agent_module(monkeypatch, agent_id="test-hops-chapter", agent_name="Test Hops Chapter")


def _health(mod) -> dict:
    r = TestClient(mod.app).get("/health")
    assert r.status_code == 200, r.text
    return r.json()


# ── the guard: the reported value tracks the resolver, not the environment ──


def test_ADVERSARIAL_health_reports_the_running_value_when_the_environment_disagrees(monkeypatch):
    """⚠️ THE GUARD (G1). Change the variable AFTER import and the endpoint must
    still report what the limiter is using.

    This is the shape of the real failure: an operator sets the variable, the
    platform reads it back, and the process — which resolved it once at import —
    is still keying on the old value. A field that answers from os.environ would
    confirm the operator's change and be wrong about the running system, which is
    worse than reporting nothing at all.

    Any mirror fails here, however carefully it parses, because the defect is the
    SOURCE and not the parsing.
    """
    mod = _chapter(monkeypatch, "2")
    assert mod.TRUSTED_PROXY_HOPS == 2, "the fixture did not produce the process this test needs"

    # The operator "sets" it — in the environment only. Nothing re-imports.
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "9")

    reported = _health(mod)[FIELD]
    assert reported == 2, (
        f"/health reported {reported!r}, the value in the ENVIRONMENT, while the limiter "
        f"is keying with {mod.TRUSTED_PROXY_HOPS!r}"
    )
    # And it is the very object the limiter consults, not a coincidentally equal one.
    assert reported == mod.TRUSTED_PROXY_HOPS


def test_ADVERSARIAL_the_limiter_and_the_report_cannot_be_made_to_disagree(monkeypatch):
    """The other direction: move the RESOLVER and the report must follow it.

    ``client_ip_for_rate_limit`` reads the module global at call time, so patching
    it is how the existing limiter suite drives this setting. Both the limiter's
    behaviour and the reported number are asserted from the same patch, so a
    report wired to anything other than that global — a copy taken at import, a
    second parse, the environment — separates them here.
    """
    mod = _chapter(monkeypatch, "0")

    class _Req:
        def __init__(self, peer, xff):
            self.client = type("C", (), {"host": peer})()
            self.headers = {"x-forwarded-for": xff}

    monkeypatch.setattr(mod, "TRUSTED_PROXY_HOPS", 1)
    assert mod.client_ip_for_rate_limit(_Req("10.0.0.1", "203.0.113.7")) == "203.0.113.7"
    assert _health(mod)[FIELD] == 1, "the limiter used 1 hop and /health said otherwise"

    monkeypatch.setattr(mod, "TRUSTED_PROXY_HOPS", 0)
    assert mod.client_ip_for_rate_limit(_Req("10.0.0.1", "203.0.113.7")) == "10.0.0.1"
    assert _health(mod)[FIELD] == 0, "the limiter fell back to the peer and /health said otherwise"


# ── the three inputs where a re-read and the resolver genuinely differ ──────


@pytest.mark.parametrize(
    ("raw", "expected", "why"),
    [
        (None, 0, "unset — the default, and a raw mirror would report the string '0' or nothing"),
        ("abc", 0, "non-integer — 0 via the ValueError path; a mirror reports 'abc' or raises"),
        ("-3", 0, "negative — 0 via max(); a mirror reports -3, a hop count that cannot exist"),
        ("", 0, "empty — the `or '0'` path, which unset and empty share deliberately"),
        ("1", 1, "the value a single-edge deployment actually runs"),
    ],
)
def test_EDGE_health_reports_the_resolved_value_on_every_input(monkeypatch, raw, expected, why):
    """The resolver's answer, exactly — including its TYPE.

    ⚠️ THE TYPE ASSERTION IS NOT DECORATION. The simplest mirror is
    ``os.environ.get("TRUSTED_PROXY_HOPS", "0")``, which agrees with the resolver
    on the unset case in value and disagrees in type: `"0"` is not `0`, and a
    consumer comparing against a number gets a silent false. Asserting the number
    alone would let that mirror through on the one input operators see most.
    """
    mod = _chapter(monkeypatch, raw)

    reported = _health(mod)[FIELD]
    assert reported == expected, f"{why}: reported {reported!r}"
    assert isinstance(reported, int) and not isinstance(reported, bool), (
        f"{why}: reported {type(reported).__name__} {reported!r}, not an int"
    )
    assert reported == mod.TRUSTED_PROXY_HOPS


# ── the field cannot break the probe, and the probe stays cheap ─────────────


def test_EDGE_an_unusable_setting_does_not_make_the_health_probe_raise(monkeypatch):
    """⚠️ G2. A health endpoint that 500s on a malformed setting is worse than one
    that omits the field: a load balancer reads the 500 as a dead process and
    takes a serving org out of rotation over a typo in an unrelated variable.

    ``'abc'`` is the input that catches the natural mirror — ``int('abc')`` raises,
    and an unguarded re-read inside the handler turns a diagnostic into an
    outage. The module's own parse already swallowed it at import; the handler
    reads that result and can add no new way to fail.
    """
    mod = _chapter(monkeypatch, "abc")

    r = TestClient(mod.app).get("/health")
    assert r.status_code == 200, f"a malformed hop count broke the health probe: {r.status_code} {r.text}"
    assert r.json()[FIELD] == 0
    assert r.json()["status"] == "ok"


def test_HAPPY_the_new_field_costs_no_backing_store_contact(monkeypatch):
    """⚠️ G2, second half. The handler's docstring promises no backing-store I/O so
    a load balancer can poll it hot, and this field must not spend that.

    ⚠️ ASSERTED BY RECORDING THE CONTACTS, NOT BY MAKING ONE EXPLODE. A first
    draft raised ``AssertionError`` from the stub — which
    ``_db_tls_available_safe`` catches, along with every other ``Exception``, and
    returns ``None``. That test passed whether or not the endpoint touched the
    store, which is the same class of defect as the field it was written to
    guard. Recording the attribute names is the version that can fail.

    The one contact is the PRE-EXISTING TLS probe. If reading the hop count ever
    grows a store lookup, this list grows with it.
    """
    import sys  # noqa: PLC0415

    mod = _chapter(monkeypatch, "1")
    touched: list[str] = []

    class _Recording:
        def __getattr__(self, name):
            # Dunders are the import machinery probing the stub (`__spec__`),
            # not this endpoint asking the store anything.
            if not name.startswith("__"):
                touched.append(name)
            raise RuntimeError("no database is reachable in this test")

    monkeypatch.setattr(mod, "_HAS_DATABASE", True)
    monkeypatch.setitem(sys.modules, "pg_store", _Recording())

    body = _health(mod)
    assert body[FIELD] == 1
    assert touched == ["db_tls_available"], (
        f"/health made backing-store contact beyond the pre-existing TLS probe: {touched}"
    )
    # The store was unreachable, so the diagnostic that DOES consult it reports its
    # own ignorance rather than a value — the existing contract, unchanged.
    assert body["db"]["tls_available"] is None


# ── additive: nothing that was on /health left ─────────────────────────────


def test_HAPPY_the_new_field_is_additive_and_renames_nothing(monkeypatch):
    """⚠️ G3. Deliberately a SUPERSET assertion, not a frozen key list.

    Nothing pinned this endpoint's key set before, and freezing it here would make
    every future addition — the kind this very change is — fail a test that has
    no opinion about it. What must not happen is a key going missing or changing
    name under a consumer that already reads it, so that is what is asserted:
    every key the endpoint carried before this change is still present, and the
    new one is present too.
    """
    mod = _chapter(monkeypatch, "1")
    body = _health(mod)

    before = {
        "status",
        "agent_id",
        "slug",
        "display_name",
        "git_commit",
        "members",
        "federation",
        "federation_state",
        "registries",
        "db",
    }
    missing = before - set(body)
    assert not missing, f"/health lost or renamed keys a consumer already reads: {sorted(missing)}"
    assert FIELD in body
