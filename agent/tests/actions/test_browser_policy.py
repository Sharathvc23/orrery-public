"""Consent and policy are both required for a navigation, and neither is the other.

Consent authorises one action at one origin. The policy says which origins this
install may reach at all. A navigation needs both, and the two refusals are
distinguishable in the outcome so an operator can tell which bound stopped it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.actions.browser import BrowserExecutor
from community_member.actions.browser_page import PageGotoResult
from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.sandbox import Policy, parse_policy

CHAPTER = "local:policy"
URL = "https://docs.example.com/a"
ORIGIN = "https://docs.example.com"


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    ledger.init(tmp_path / "consent.db")
    return tmp_path


def _driver(calls: list[str]):
    def _goto(state_dir, url, timeout_ms):
        calls.append(url)
        return PageGotoResult(final_url=url, title="t", html_sha256="0" * 64, status=200, content_length=0)

    return _goto


def _executor(home: Path, policy: Policy, calls: list[str]) -> BrowserExecutor:
    return BrowserExecutor(
        chapter_id=CHAPTER,
        policy=policy,
        grants_file=home / "grants.policy",
        browser_state_root=home / "browser-state",
        page_goto=_driver(calls),
    )


def _approve() -> str:
    req = ActionRequest(
        capability="browser.navigate",
        scope=ORIGIN,
        context="c",
        provenance="trusted",
        extra={"url": URL},
    )
    return gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")


def test_consent_alone_is_not_enough(home):
    """The reproduction: an approved navigation to an ungranted origin."""
    calls: list[str] = []
    approval = _approve()
    result = _executor(home, Policy(grants=()), calls).navigate(URL, context="c", approval_event_sha256=approval)

    assert not calls, "the driver was reached for an ungranted origin"
    assert result.outcome == "denied"
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_a_policy_refusal_is_distinguishable_from_a_gate_refusal(home):
    """Both refuse, and an operator can tell which one did."""
    calls: list[str] = []
    granted = parse_policy(f"browser.navigate:{ORIGIN}")

    # No approval on file: the gate refuses.
    gate_refusal = _executor(home, granted, calls).navigate(URL, context="c", approval_event_sha256="nope")
    # Approval on file, no grant: the policy refuses.
    approval = _approve()
    policy_refusal = _executor(home, Policy(grants=()), calls).navigate(
        URL, context="c", approval_event_sha256=approval
    )

    assert not calls
    assert gate_refusal.extra["reason"] == "approval_not_found_or_expired"
    assert policy_refusal.extra["reason"] == "sandbox_policy_deny"
    assert gate_refusal.extra["reason"] != policy_refusal.extra["reason"]


def test_the_policy_refusal_names_the_grant_and_the_file(home):
    """A denial that does not carry its own fix is how deny-by-default gets reverted."""
    approval = _approve()
    result = _executor(home, Policy(grants=()), []).navigate(URL, context="c", approval_event_sha256=approval)

    assert result.extra["required_grant"] == f"browser.navigate:{ORIGIN}"
    remedy = result.extra["remedy"]
    assert f"browser.navigate:{ORIGIN}" in remedy
    assert str(home / "grants.policy") in remedy


def test_both_bounds_cleared_navigates(home):
    calls: list[str] = []
    approval = _approve()
    granted = parse_policy(f"# operator's grants\nbrowser.navigate:{ORIGIN}\n")
    result = _executor(home, granted, calls).navigate(URL, context="c", approval_event_sha256=approval)

    assert calls == [URL]
    assert result.outcome == "ok"


def test_a_grant_for_another_origin_does_not_permit_this_one(home):
    calls: list[str] = []
    approval = _approve()
    other = parse_policy("browser.navigate:https://elsewhere.example")
    result = _executor(home, other, calls).navigate(URL, context="c", approval_event_sha256=approval)

    assert not calls
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_a_grant_does_not_cross_schemes(home):
    """The cookie-jar argument, asserted: an https grant must not admit http.

    This capability drives a persistent profile carrying the agent's cookies,
    so a grant that spanned schemes would put them on the wire in clear.
    """
    calls: list[str] = []
    cleartext = "http://docs.example.com/a"
    req = ActionRequest(
        capability="browser.navigate",
        scope="http://docs.example.com",
        context="c",
        provenance="trusted",
        extra={"url": cleartext},
    )
    approval = gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256="click")
    https_only = parse_policy(f"browser.navigate:{ORIGIN}")
    result = _executor(home, https_only, calls).navigate(cleartext, context="c", approval_event_sha256=approval)

    assert not calls
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_the_policy_is_checked_before_the_driver_is_touched(home):
    """An ungranted origin is never contacted, so no cookie leaves the machine."""
    calls: list[str] = []

    def _explode(state_dir, url, timeout_ms):  # pragma: no cover - must not run
        raise AssertionError("the browser was launched for an ungranted origin")

    approval = _approve()
    ex = BrowserExecutor(
        chapter_id=CHAPTER,
        policy=Policy(grants=()),
        browser_state_root=home / "browser-state",
        page_goto=_explode,
    )
    assert ex.navigate(URL, context="c", approval_event_sha256=approval).outcome == "denied"
    assert not calls


def test_the_refusal_is_recorded_in_the_ledger(home):
    approval = _approve()
    _executor(home, Policy(grants=()), []).navigate(URL, context="c", approval_event_sha256=approval)

    rejects = [e for e in ledger.list_events(action="consent.reject", limit=10) if e["chapter_id"] == CHAPTER]
    assert rejects
    assert rejects[0]["detail"]["decision_reason"] == "sandbox_policy_deny"
