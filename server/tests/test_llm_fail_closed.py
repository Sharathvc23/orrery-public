"""A keyless process calls nobody — and ships able to prove it before it does.

THE DEFECT THIS CLOSES, reproduced before changing anything. With every provider
key unset, the chapter still built a client:

    PROVIDER       : anthropic
    BASE_URL       : https://api.anthropic.com/v1
    API_KEY        : ''
    planner_enabled: False
    client base_url: https://api.anthropic.com/v1/
    client api_key : 'MISSING'

``planner_enabled()`` was already False — the gate existed and was correct. What
did not exist was any reason for a call site to consult it: twenty-four sites use
that client and four ask. The twenty that do not posted member names, skill lists
and federation peer names under ``Authorization: Bearer MISSING`` while
docs/CONFIGURATION.md promised the org "makes no request, so there is nothing for
a firewall or an egress policy to block".

Gating at CONSTRUCTION is what makes the promise structural: under LLM_STRICT
there is no client, so there is nothing to bypass and no twenty-first site can be
added that forgets to ask.

SHIPS AT LLM_STRICT=0. Off is today's behaviour exactly, plus a log line per
construction saying what On would have refused. That is deliberate: eighteen
services change behaviour at once otherwise, and the report-only release is what
the flip is read from.
"""

from __future__ import annotations

import logging

import pytest

import env_flags
import llm_runtime


@pytest.fixture(autouse=True)
def _no_ambient_keys(monkeypatch):
    """This workstation has real provider keys. Remove them, or the test asserts
    the behaviour of a configured box rather than a keyless one."""
    for name in (
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "GROQ_API_KEY",
        "LLM_API_KEY",
        "LLM_STRICT",
        "LLM_AUTODETECT",
        "LLM_PROVIDER",
        "LLM_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)


# ── the gate ─────────────────────────────────────────────────────────────────


def test_an_absent_key_refuses_whether_or_not_strict_is_on():
    """⚠️ LLM_STRICT WIDENS THIS REFUSAL; IT DOES NOT INTRODUCE IT.

    An absent key has raised since the resolver landed, and the call sites have
    used the resolver since the migration. Making that conditional on a flag
    would LOOSEN a guarantee that already shipped — which the first version of
    this change did, and the resolver's own suite caught.
    """
    resolution = llm_runtime.resolve("anthropic")
    for strict in (True, False):
        with pytest.raises(llm_runtime.LLMNotConfigured) as caught:
            llm_runtime.build_client(resolution, strict=strict)
        assert "ANTHROPIC_API_KEY" in str(caught.value), "the refusal does not name what to set"


def test_strict_refuses_the_placeholder_a_caller_substituted():
    """What the flag actually adds.

    The empty case never reached a provider. What did reach one was a caller
    substituting a string so the client would construct — the chapter's config
    passed "MISSING", member_runtime passed "no-key-configured" — and that string
    then travelled in an Authorization header.
    """
    resolution = llm_runtime.resolve("anthropic")
    with pytest.raises(llm_runtime.LLMNotConfigured) as caught:
        llm_runtime.build_client(resolution, api_key="MISSING", strict=True)

    message = str(caught.value)
    assert "MISSING" in message, "the refusal does not name the placeholder it caught"
    assert "ANTHROPIC_API_KEY" in message, "the refusal does not name what to set"


@pytest.mark.parametrize("placeholder", ["MISSING", "missing", "local", "no-key-configured", "none"])
def test_a_placeholder_is_not_a_credential(placeholder):
    """'MISSING' is the exact string the chapter substituted for an absent key,
    so it travelled in an Authorization header to a real provider. 'local' is the
    placeholder a local endpoint ignores and must never reach a remote one."""
    with pytest.raises(llm_runtime.LLMNotConfigured):
        llm_runtime.build_client(llm_runtime.resolve("anthropic"), api_key=placeholder, strict=True)


def test_a_real_key_still_builds_under_strict():
    client = llm_runtime.build_client(
        llm_runtime.resolve("anthropic"), api_key="sk-a-real-looking-key", strict=True
    )
    assert client.api_key == "sk-a-real-looking-key"


# ── a deliberate local endpoint is never gated off ───────────────────────────


@pytest.mark.parametrize("provider", sorted(llm_runtime.LOCAL_PROVIDERS))
def test_strict_does_not_gate_off_a_local_endpoint(provider):
    """⚠️ A chapter pointed at an unkeyed LOCAL model is correctly configured.

    This is the case strict mode must not break, and it is checked for every
    local provider rather than for ollama alone.
    """
    client = llm_runtime.build_client(llm_runtime.resolve(provider), strict=True)
    assert client is not None
    assert "localhost" in str(client.base_url) or "127.0.0.1" in str(client.base_url)


def test_locality_is_read_off_the_url_not_resolved():
    """Preserved verbatim from planner_enabled's existing check.

    The question is what the operator configured. A name that happens to resolve
    to loopback today is not a promise about tomorrow, and a hostname that merely
    CONTAINS a loopback address is a different host.
    """
    import llm_config

    assert llm_config._is_local("http://localhost:11434/v1") is True
    assert llm_config._is_local("http://127.0.0.1:8080/v1") is True
    assert llm_config._is_local("https://api.anthropic.com/v1") is False
    assert llm_config._is_local("https://127.0.0.1.attacker.example/v1") is False


# ── report-only is the shipped state ─────────────────────────────────────────


def test_it_ships_off(monkeypatch):
    """LLM_STRICT unset must be OFF. Shipping it on flips eighteen services at
    once with no report to read first."""
    import llm_config

    assert llm_config.strict_enabled() is False
    monkeypatch.setenv("LLM_STRICT", "1")
    assert llm_config.strict_enabled() is True
    monkeypatch.setenv("LLM_STRICT", "0")
    assert llm_config.strict_enabled() is False, "0 must be the rollback, with no code revert"


def test_off_behaves_exactly_as_today_and_says_what_on_would_do(caplog):
    """The report-only release: same client, plus the line the flip is read from."""
    with caplog.at_level(logging.WARNING, logger="llm_runtime"):
        # "MISSING" is what llm_config substitutes, so this is the exact call the
        # chapter makes with no key configured.
        client = llm_runtime.build_client(
            llm_runtime.resolve("anthropic"), api_key="MISSING", strict=False
        )

    assert client.api_key == "MISSING", "off must be today's behaviour, unchanged"
    assert "api.anthropic.com" in str(client.base_url)

    said = " ".join(r.getMessage() for r in caplog.records)
    assert "LLM_STRICT" in said, "nothing told the operator what strict would have done"
    assert "would refuse" in said


def test_the_report_line_carries_no_key(caplog):
    """It runs on the path about to send a request, so it must not log the key."""
    with caplog.at_level(logging.WARNING, logger="llm_runtime"):
        llm_runtime.build_client(
            llm_runtime.resolve("anthropic"), api_key="sk-secret-value-here", strict=False
        )
    assert "sk-secret-value-here" not in " ".join(r.getMessage() for r in caplog.records)


# ── autodetect ───────────────────────────────────────────────────────────────


def test_autodetect_ships_on_and_can_be_turned_off(monkeypatch):
    import llm_config

    assert llm_config.autodetect_enabled() is True, "off would change resolution on every server"
    monkeypatch.setenv("LLM_AUTODETECT", "0")
    assert llm_config.autodetect_enabled() is False


def test_autodetect_off_ignores_an_ambient_key(monkeypatch):
    """With detection off, a stray key no longer decides which third party this
    org is pointed at."""
    monkeypatch.setenv("XAI_API_KEY", "sk-a-stray-key")
    import llm_config

    # _resolve() reads the environment when it is called, so the flag can be
    # exercised without reloading the module. An earlier version of this test did
    # reload it, which rebound the module's constants process-wide and made two
    # unrelated suites fail depending on execution order — a test that breaks its
    # neighbours is worse than the one it is guarding.
    monkeypatch.setenv("LLM_AUTODETECT", "1")
    assert llm_config._resolve()[0] == "xai", "detection is on; the ambient key should select"

    monkeypatch.setenv("LLM_AUTODETECT", "0")
    assert llm_config._resolve()[0] == "anthropic", "an ambient key selected the provider with detection off"


# ── both flags are declared as security gates ────────────────────────────────


def test_both_flags_go_through_security_flag():
    """They decide whether member names, skills and federation topology leave the
    box, so the direction they fail when nobody set them is written at the call
    site rather than emerging from a parsing expression."""
    import inspect

    import llm_config

    source = inspect.getsource(llm_config)
    assert 'env_flags.security_flag("LLM_STRICT", default=False)' in source
    assert 'env_flags.security_flag("LLM_AUTODETECT", default=True)' in source
    assert env_flags.security_flag("LLM_STRICT", default=False) is False


# ── the compose allowlist ────────────────────────────────────────────────────


def test_the_compose_allowlist_carries_both_flags():
    """A variable not listed there never reaches the container, silently.

    That already happened to LLM_PROVIDER, LLM_MODEL and LLM_BASE_URL, and the
    configuration doc records it — so a security flag a stock install cannot set
    is a flag that does not exist for most operators.
    """
    from pathlib import Path

    compose = (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
    assert "LLM_STRICT: ${LLM_STRICT:-false}" in compose, "LLM_STRICT cannot be set on a stock install"
    assert "LLM_AUTODETECT: ${LLM_AUTODETECT:-true}" in compose


def test_the_documentation_no_longer_promises_what_was_not_true():
    """The doc claimed a keyless org makes no request. It did make requests."""
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[2] / "docs" / "CONFIGURATION.md").read_text()
    assert "LLM_STRICT" in doc, "the flag that makes the promise true is undocumented"
    assert "Bearer MISSING" in doc, "the doc does not record what actually happened"
    assert "ships as `false`" in doc, "the doc does not say the promise is not yet in force"


def test_the_shipped_state_is_report_only_through_the_chapter_shim(caplog, monkeypatch):
    """⚠️ THE FLIP GATE, asserted on the path the chapter actually uses.

    build_client behaving correctly is not enough: llm_config substitutes
    "MISSING" for an absent key before calling it, so what ships depends on the
    shim as much as on the factory. An earlier version of this change had the
    shim pass the empty key instead, which made a keyless chapter refuse at
    construction with the flag OFF — the right end state in the wrong release.

    With LLM_STRICT unset the chapter must build exactly what it builds today,
    and say what On would have refused.
    """
    import llm_config

    # API_KEY is bound at IMPORT, so clearing the environment in a fixture does
    # not clear it — on a workstation with a real provider key the module already
    # holds one, and this test would assert the behaviour of a configured box.
    # Pinned explicitly so the case under test is the keyless one wherever it runs.
    monkeypatch.setattr(llm_config, "API_KEY", "")

    with caplog.at_level(logging.WARNING, logger="llm_runtime"):
        client = llm_config.build_client()

    assert client is not None, "the shipped state refused; that is the flip, not the release"
    assert client.api_key == "MISSING"
    said = " ".join(r.getMessage() for r in caplog.records)
    assert "LLM_STRICT" in said and "would refuse" in said


def test_the_flip_refuses_through_the_same_shim(monkeypatch):
    """And setting the flag is the whole change — no code revert either way."""
    import llm_config

    monkeypatch.setattr(llm_config, "API_KEY", "")
    monkeypatch.setenv("LLM_STRICT", "1")
    with pytest.raises(llm_runtime.LLMNotConfigured) as caught:
        llm_config.build_client()
    assert "MISSING" in str(caught.value)

    monkeypatch.setenv("LLM_STRICT", "0")
    assert llm_config.build_client() is not None, "0 did not restore today's behaviour"
