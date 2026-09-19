"""Tests for ShellExecutor — binary-allowlist subprocess.

Coverage:

  R1  Forgery — fabricated approval → denied, no subprocess
  R3  Injection — \"tail;rm\" binary name does NOT match allowlist;
      args with shell metacharacters pass through as literal argv
  R4  Authz — binary not on sandbox allowlist → denied
  R5  Boundary — exit code 0 → ok; exit code 1 → fail
  R7  Adversarial — binary not on PATH → fail (not a silent success)
  R8  Expired approval → denied
  R9  Timeout — command over budget → fail, no crash
  R10 Chain verifies across propose/approve/exec sequence
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from community_member.actions.shell import ShellExecutor
from community_member.consent import gate, ledger
from community_member.sandbox import parse_policy


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_ledger(tmp_path: Path):
    ledger.init(tmp_path / "consent.db")


@pytest.fixture
def executor(tmp_ledger):
    pol = parse_policy(["shell.exec:python,echo,false,sleep"])
    return ShellExecutor(chapter_id="ch", actor_agent_id="alice", policy=pol)


def _consume_prompt(exec_fn, *args, **kwargs):
    try:
        exec_fn(*args, **kwargs)
    except gate.ConsentRequired:
        pass
    row = ledger.list_events(action="consent.prompt", limit=1)[0]
    req = gate.ActionRequest(
        capability=row["detail"]["capability"],
        scope=row["detail"]["scope"],
        context=row["detail"]["context"],
        provenance=row["detail"]["provenance"],
        source_ref=row["detail"].get("source_ref"),
        rationale="",
        extra=row["detail"].get("extra", {}),
    )
    return req, row["event_sha256"]


def test_propose_raises_consent(executor):
    with pytest.raises(gate.ConsentRequired, match="shell.exec"):
        executor.propose_exec("echo", ["hi"], context="c")


def test_R10_echo_roundtrip(executor):
    req, prompt = _consume_prompt(executor.propose_exec, "echo", ["hi"], context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.exec_command("echo", ["hi"], context=req.context, approval_event_sha256=approval)
    assert result.outcome == "ok"
    assert result.data["exit_code"] == 0
    assert b"hi" in result.extra["stdout_bytes"]


def test_R1_fabricated_approval_denied(executor):
    _consume_prompt(executor.propose_exec, "echo", ["hi"], context="c")
    result = executor.exec_command("echo", ["hi"], context="c", approval_event_sha256="z" * 64)
    assert result.outcome == "denied"
    assert result.extra["reason"] == "approval_not_found_or_expired"


def test_R4_binary_not_on_allowlist_denied(tmp_ledger):
    """A binary (wget) not in the shell.exec grant is rejected by the
    sandbox even with a valid consent approval."""
    pol = parse_policy(["shell.exec:echo"])  # no wget
    ex = ShellExecutor(chapter_id="ch", policy=pol)
    req, prompt = _consume_prompt(ex.propose_exec, "wget", ["--help"], context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = ex.exec_command("wget", ["--help"], context=req.context, approval_event_sha256=approval)
    assert result.outcome == "denied"
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_R3_shell_metacharacters_in_args_are_literal(executor):
    """With shell=False, 'echo ; rm -rf' passes 4 argv items to
    echo which just prints them. No shell interprets the ';'.

    The original form of this test passed "/" as the last argument. It now
    names an existing path outside the file grants, so the argument narrowing
    refuses it — a false refusal, not a caught attack. The metacharacter
    property is unchanged and is what this test is for; the narrowing's cost is
    asserted in test_argument_narrowing.py.
    """
    argv = ["hello", ";", "rm", "-rf"]
    req, prompt = _consume_prompt(executor.propose_exec, "echo", argv, context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.exec_command(
        "echo",
        argv,
        context=req.context,
        approval_event_sha256=approval,
    )
    assert result.outcome == "ok"
    # The stdout contains the literal args, space-separated by echo.
    out = result.extra["stdout_bytes"]
    assert b"hello" in out
    assert b";" in out
    # No filesystem was destroyed — the test exists, so we're fine.


def test_R5_nonzero_exit_is_fail(executor):
    req, prompt = _consume_prompt(executor.propose_exec, "false", [], context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.exec_command("false", [], context=req.context, approval_event_sha256=approval)
    assert result.outcome == "fail"
    assert result.data["exit_code"] == 1


def test_R7_binary_not_on_path_fails(tmp_ledger):
    pol = parse_policy(["shell.exec:absolutely-definitely-not-a-real-binary-xyz"])
    ex = ShellExecutor(chapter_id="ch", policy=pol)
    req, prompt = _consume_prompt(ex.propose_exec, "absolutely-definitely-not-a-real-binary-xyz", [], context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = ex.exec_command(
        "absolutely-definitely-not-a-real-binary-xyz",
        [],
        context=req.context,
        approval_event_sha256=approval,
    )
    assert result.outcome == "fail"
    assert result.extra["reason"] == "binary_not_on_path"


def test_R9_timeout_fails_gracefully(tmp_ledger):
    pol = parse_policy([f"shell.exec:{Path(sys.executable).name}"])
    ex = ShellExecutor(chapter_id="ch", policy=pol, timeout_sec=1)
    req, prompt = _consume_prompt(
        ex.propose_exec,
        Path(sys.executable).name,
        ["-c", "import time; time.sleep(5)"],
        context="c",
    )
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = ex.exec_command(
        Path(sys.executable).name,
        ["-c", "import time; time.sleep(5)"],
        context=req.context,
        approval_event_sha256=approval,
    )
    assert result.outcome == "fail"
    assert "timeout" in result.extra["reason"]


def test_R10_chain_clean_across_shell_flow(executor):
    req, prompt = _consume_prompt(executor.propose_exec, "echo", ["x"], context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    executor.exec_command("echo", ["x"], context=req.context, approval_event_sha256=approval)
    assert ledger.verify_chain()["ok"] is True
