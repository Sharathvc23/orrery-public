"""Approving a pending action runs it immediately (and once).

Closes the "I clicked Approve, why did nothing happen?" gap: the consent-approve
endpoint now records the approval AND executes the action through the agent's v2
runners, then tombstones the approval so it is one-shot (it can't also auto-fire
on the next autonomous think cycle within the TTL).

Exercised end-to-end with the side-effect-free built-in `datetime` skill so the
real runner + skill_runtime path runs without touching the network/filesystem.

  GATE    mark_consumed → find_valid_approval skips the approval (one-shot)
  AGENT   run_approved_action runs a real approved skill.invoke
  SERVER  POST /consent/approve executes + consumes; a second find_valid_approval
          returns None (the autonomous loop won't re-fire it)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import keystore
from community_member.config import Config
from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.server import create_app


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    keystore.reset_for_tests()
    yield
    ledger._reset_for_tests()
    keystore.reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    from community_member import config as config_mod

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    return tmp_path


@pytest.fixture
def cfg(tmp_env) -> Config:
    c = Config()
    c.agent_id = "alice"
    c.name = "Alice"
    c.provider = "ollama"
    c.model = "test"
    return c


def _datetime_req() -> ActionRequest:
    return ActionRequest(
        capability="skill.invoke",
        scope="datetime@1.0.0::now::test",
        context="time",
        provenance="trusted",
        extra={"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {}},
    )


# ── Gate: one-shot consumption ────────────────────────────────────


def test_mark_consumed_makes_find_valid_approval_skip(tmp_env):
    req = _datetime_req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    sha = gate.approve(
        req,
        chapter_id="local:alice",
        prompt_event_sha256=first.event_sha256,
        actor_agent_id="alice",
    )

    # Before consumption: the approval is found.
    assert gate.find_valid_approval(req, chapter_id="local:alice") is not None

    gate.mark_consumed(sha, chapter_id="local:alice", actor_agent_id="alice")

    # After consumption: gone — even though the TTL is still live.
    assert gate.find_valid_approval(req, chapter_id="local:alice") is None


def test_consumed_approval_does_not_double_fire_next_cycle(tmp_env):
    """The literal guarantee: once an approval has fired and been consumed,
    a later execute_plan (the next autonomous cycle re-proposing it) re-PROMPTS
    instead of re-running the runner."""
    from community_member.executor import ToolOutput, execute_plan
    from community_member.planner import Plan

    calls: list = []

    def runner(req):
        calls.append(req)
        return ToolOutput(capability=req.capability, scope=req.scope, outcome="ok", provenance="untrusted")

    req = _datetime_req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    sha = gate.approve(req, chapter_id="local:alice", prompt_event_sha256=first.event_sha256, actor_agent_id="alice")

    runners = {"skill.invoke": runner}
    r1 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r1[0].decision.state == "approved"
    assert len(calls) == 1  # fired once

    gate.mark_consumed(sha, chapter_id="local:alice", actor_agent_id="alice")

    gate.mark_consumed(sha, chapter_id="local:alice", actor_agent_id="alice")

    r2 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r2[0].decision.state == "prompt"  # re-prompts
    assert len(calls) == 1  # runner NOT called a second time


def test_G2_executor_consumes_approval_without_http_path(tmp_env):
    """G2: the AUTONOMOUS executor must tombstone a user approval when it fires
    it — WITHOUT any HTTP-path mark_consumed. A second cycle re-prompts and does
    not re-run the runner within the approval's TTL."""
    from community_member.executor import ToolOutput, execute_plan
    from community_member.planner import Plan

    calls: list = []

    def runner(req):
        calls.append(req)
        return ToolOutput(capability=req.capability, scope=req.scope, outcome="ok")

    req = _datetime_req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    gate.approve(
        req,
        chapter_id="local:alice",
        prompt_event_sha256=first.event_sha256,
        actor_agent_id="alice",
    )
    runners = {"skill.invoke": runner}

    # First cycle fires the approval.
    r1 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r1[0].decision.state == "approved"
    assert len(calls) == 1

    # Second cycle — NO manual mark_consumed. The executor must have consumed
    # the approval itself, so this re-prompts and the runner is NOT called again.
    r2 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r2[0].decision.state == "prompt"
    assert len(calls) == 1


def test_G2_consume_retries_transient_failure(tmp_env, monkeypatch):
    """G2 robustness: a transient mark_consumed failure (e.g. SQLite BUSY that
    clears) must be RETRIED, not swallowed on the first error. The tombstone is
    now written BEFORE the runner (gate.claim_approval), so a failure here means
    the action does not run this cycle rather than running un-tombstoned; the
    retry is what keeps a millisecond BUSY from costing the user a cycle."""
    from community_member.consent import gate as gate_mod
    from community_member.executor import ToolOutput, execute_plan
    from community_member.planner import Plan

    calls: list = []

    def runner(req):
        calls.append(req)
        return ToolOutput(capability=req.capability, scope=req.scope, outcome="ok")

    req = _datetime_req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    gate.approve(req, chapter_id="local:alice", prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    runners = {"skill.invoke": runner}

    # First call raises (transient), the retry succeeds → tombstone persists.
    real_mark = gate_mod.mark_consumed
    state = {"n": 0}

    def flaky_mark(*a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("database is locked")
        return real_mark(*a, **k)

    monkeypatch.setattr(gate_mod, "mark_consumed", flaky_mark)
    r1 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r1[0].decision.state == "approved"
    assert len(calls) == 1
    assert state["n"] >= 2, "the transient consume failure was not retried"

    # The retry persisted the tombstone (via the REAL mark_consumed), so the
    # next cycle re-prompts and does not re-fire — no double-execution.
    monkeypatch.setattr(gate_mod, "mark_consumed", real_mark)
    r2 = execute_plan(Plan(proposals=(req,)), runners, chapter_id="local:alice")
    assert r2[0].decision.state == "prompt"
    assert len(calls) == 1


# ── Agent: run_approved_action executes a real approved action ────


def test_run_approved_action_runs_datetime_skill(cfg):
    from community_member.agent import LocalAgent

    agent = LocalAgent(cfg)
    req = _datetime_req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    gate.approve(
        req,
        chapter_id="local:alice",
        prompt_event_sha256=first.event_sha256,
        actor_agent_id="alice",
    )

    out = agent.run_approved_action(req)
    assert out["decision"] == "approved"
    assert out["outcome"] == "ok"
    assert "UTC" in out["content"]  # datetime.now() tool output


def test_run_approved_action_without_approval_is_denied(cfg):
    from community_member.agent import LocalAgent

    agent = LocalAgent(cfg)
    # No approval recorded → the runner finds none → denied, not executed.
    out = agent.run_approved_action(_datetime_req())
    assert out["outcome"] != "ok"


# ── Server: approve endpoint executes + consumes ──────────────────


@pytest.fixture
def client(cfg) -> TestClient:
    from community_member.agent import LocalAgent

    return TestClient(create_app(cfg, agent=LocalAgent(cfg)))


def test_approve_endpoint_executes_and_consumes(client):
    req = _datetime_req()
    prompt = gate.check_and_record(req, chapter_id="local:alice")

    body = {
        "prompt_event_sha256": prompt.event_sha256,
        "request": {
            "capability": req.capability,
            "scope": req.scope,
            "context": req.context,
            "provenance": req.provenance,
            "source_ref": None,
            "rationale": "",
        },
    }
    resp = client.post("/api/local/consent/approve", json=body)
    assert resp.status_code == 200
    data = resp.json()

    # It ran, right now.
    assert data["executed"]["outcome"] == "ok"
    assert "UTC" in data["executed"]["content"]

    # And it's one-shot: the autonomous loop won't re-fire it.
    assert gate.find_valid_approval(req, chapter_id="local:alice") is None
