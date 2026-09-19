"""Every capability runner pins provenance itself.

`gate.find_valid_approval` matches on (capability, scope, context,
provenance). A runner that takes provenance from the ActionRequest lets the
planner's own label decide which approval its proposal matches, so a proposal
labelled semi-trusted can be satisfied by a semi-trusted approval and reach a
driver. A runner that rebuilds it as "trusted" fails closed instead: the
approval minted for a non-trusted proposal does not match.

The runner set is derived from `LocalAgent.build_runners`, so a capability
added later is covered without editing this file.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path

import pytest

from community_member.consent.gate import ActionRequest
from community_member.executor import KNOWN_CAPABILITIES

ACTIONS_DIR = Path(__file__).resolve().parents[1] / "community_member" / "actions"


@pytest.fixture
def runners(tmp_path, monkeypatch):
    """The real runner map, built the way the think loop builds it."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config(home=tmp_path)
    cfg.agent_id = "provenance-guard"
    cfg.provider = ""
    cfg.api_key = ""
    return LocalAgent(cfg).build_runners("local:provenance-guard")


def test_the_runner_map_is_not_empty(runners):
    """Guards against a build_runners refactor silently emptying this suite."""
    assert set(runners) <= KNOWN_CAPABILITIES
    assert len(runners) >= 8


def test_no_runner_forwards_the_request_provenance(runners):
    """Read each runner's source: none may pass provenance to its executor.

    Checked at the call site rather than by driving the runner, because a
    runner that denies for an unrelated reason would hide the forward.
    """
    forwarding: list[str] = []
    for capability, runner in sorted(runners.items()):
        src = textwrap.dedent(inspect.getsource(runner))
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "provenance":
                    continue
                # `provenance=<anything but a literal>` means the value came
                # from the request rather than from the runner.
                if not isinstance(kw.value, ast.Constant):
                    forwarding.append(f"{capability}: provenance={ast.unparse(kw.value)}")
    assert not forwarding, f"runners forwarding a caller-supplied provenance: {forwarding}"


def test_every_action_executor_pins_provenance_trusted():
    """The other half of the same property, at the executor.

    Each `actions/*.py` execute-path builds its own ActionRequest. Every
    ActionRequest constructed with capability= and provenance= must pin
    provenance to a literal, never to a name.
    """
    # `propose_*` legitimately carries the planner's label INTO the gate — that
    # is the gate's input, and the label is what evaluate() rejects on.
    # `_build_request` is a parameterised helper; its callers do the pinning.
    # Everything else builds a request to MATCH an approval, and must pin.
    exempt = {"_build_request"}
    offenders: list[str] = []
    for path in sorted(ACTIONS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if fn.name.startswith("propose") or fn.name in exempt:
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if name not in ("ActionRequest", "_build_request"):
                    continue
                for kw in node.keywords:
                    if kw.arg == "provenance" and not isinstance(kw.value, ast.Constant):
                        offenders.append(f"{path.name}:{fn.name}:{node.lineno} provenance={ast.unparse(kw.value)}")
    assert not offenders, f"execute paths taking provenance from a caller: {offenders}"


def test_a_semi_trusted_approval_does_not_satisfy_a_navigation(tmp_path, monkeypatch):
    """The reproduction from the sweep, run against this build.

    A proposal labelled semi_trusted is auto-approved by the executor's trust
    path, which mints an approval carrying provenance="semi_trusted". The
    runner rebuilds the request as "trusted", so that approval no longer
    matches and the navigation is refused before the driver is reached.
    """
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.actions.browser import BrowserExecutor
    from community_member.consent import gate, ledger

    ledger.init(tmp_path / "consent.db")
    chapter_id = "local:provenance-guard"
    url = "https://marker.invalid/probe"

    semi = ActionRequest(
        capability="browser.navigate",
        scope="https://marker.invalid",
        context="cycle",
        provenance="semi_trusted",
        extra={"url": url},
    )
    approval = gate.approve(semi, chapter_id=chapter_id, prompt_event_sha256="trust_threshold")

    drove: list[str] = []

    def _never(state_dir, target, timeout_ms):  # pragma: no cover - must not run
        drove.append(target)
        raise AssertionError("the driver was reached with a semi-trusted approval")

    result = BrowserExecutor(
        chapter_id=chapter_id, page_goto=_never, browser_state_root=tmp_path / "browser-state"
    ).navigate(
        url,
        context="cycle",
        approval_event_sha256=approval,
    )

    assert not drove
    assert result.outcome == "denied"
    assert result.extra["reason"] == "approval_not_found_or_expired"


def test_a_trusted_approval_still_navigates(tmp_path, monkeypatch):
    """The fix must not close the legitimate path with the illegitimate one."""
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    from community_member.actions.browser import BrowserExecutor
    from community_member.actions.browser_page import PageGotoResult
    from community_member.consent import gate, ledger

    ledger.init(tmp_path / "consent.db")
    chapter_id = "local:provenance-guard"
    url = "https://marker.invalid/probe"

    trusted = ActionRequest(
        capability="browser.navigate",
        scope="https://marker.invalid",
        context="cycle",
        provenance="trusted",
        extra={"url": url},
    )
    approval = gate.approve(trusted, chapter_id=chapter_id, prompt_event_sha256="click")

    def _ok(state_dir, target, timeout_ms):
        return PageGotoResult(final_url=target, title="probe", html_sha256="0" * 64, status=200, content_length=0)

    # Navigation also needs a policy grant for the origin; this test is about
    # provenance, so the origin is granted.
    from community_member.sandbox import parse_policy

    result = BrowserExecutor(
        chapter_id=chapter_id,
        page_goto=_ok,
        policy=parse_policy("browser.navigate:https://marker.invalid"),
        browser_state_root=tmp_path / "browser-state",
    ).navigate(
        url,
        context="cycle",
        approval_event_sha256=approval,
    )
    assert result.outcome == "ok"


def test_navigate_does_not_accept_a_provenance_argument():
    """Pinning it inside the body is undone by a caller that can pass one."""
    from community_member.actions.browser import BrowserExecutor

    assert "provenance" not in inspect.signature(BrowserExecutor.navigate).parameters


def test_the_real_runner_refuses_a_semi_trusted_proposal(runners, tmp_path):
    """End to end through the runner the think loop actually calls.

    The two tests above read source; this one drives the wired runner with the
    proposal shape the planner emits, so a forward reintroduced either in the
    runner or in the executor is caught by behaviour rather than by parsing.
    """
    from community_member.consent import gate, ledger

    ledger.init(tmp_path / "consent.db")
    chapter_id = "local:provenance-guard"
    url = "https://marker.invalid/probe"

    proposal = ActionRequest(
        capability="browser.navigate",
        scope="https://marker.invalid",
        context="cycle",
        provenance="semi_trusted",
        extra={"url": url},
    )
    # What the executor's trust path mints for an auto-approved proposal.
    gate.approve(proposal, chapter_id=chapter_id, prompt_event_sha256="trust_threshold")

    output = runners["browser.navigate"](proposal)
    assert output.outcome != "ok"
    # The refusal reason names the approval mismatch, so this cannot pass for
    # an unrelated failure (a missing driver, a bad URL).
    assert output.extra["reason"] in ("no_valid_approval_at_runner", "approval_not_found_or_expired")
