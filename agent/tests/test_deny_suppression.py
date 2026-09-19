"""Denying an action suppresses it from being re-proposed for a cooldown.

When the user clicks Deny, the prompt drops from the queue — but the planner
doesn't remember it asked, so it re-proposes the same action on the next cycle
and the prompt comes right back. This wires a denial to SUPPRESS re-prompting:
``find_recent_denial`` is the negative mirror of ``find_valid_approval``, and
the executor rejects a recently-denied proposal before any prompt/auto-approve.

  GATE      find_recent_denial matches within the cooldown, expires after it,
            and is scoped to the exact action
  EXECUTOR  a recently-denied proposal is rejected (not re-prompted), the
            denial overrides trust auto-approve, and an unrelated denial does
            not suppress a different action
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from community_member.consent import gate, ledger
from community_member.consent.gate import DENIAL_COOLDOWN, ActionRequest
from community_member.executor import ToolOutput, execute_plan
from community_member.planner import Plan


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_ledger(tmp_path: Path) -> None:
    ledger.init(tmp_path / "consent.db")


def _req(
    *,
    capability="net.http",
    scope="https://evil.example",
    context="ctx",
    provenance="trusted",
) -> ActionRequest:
    return ActionRequest(
        capability=capability,
        scope=scope,
        context=context,
        provenance=provenance,
        extra={"url": scope},
    )


def _deny(req: ActionRequest, chapter_id="ch") -> None:
    prompt = gate.check_and_record(req, chapter_id=chapter_id)
    gate.deny(
        req,
        chapter_id=chapter_id,
        prompt_event_sha256=prompt.event_sha256,
        actor_agent_id="alice",
    )


# ── Gate: find_recent_denial ──────────────────────────────────────


def test_find_recent_denial_matches_within_cooldown(tmp_ledger):
    req = _req()
    _deny(req)
    assert gate.find_recent_denial(req, chapter_id="ch") is not None


def test_find_recent_denial_expires_after_cooldown(tmp_ledger):
    req = _req()
    _deny(req)
    # Look from a point past the cooldown window → no longer suppressing.
    future = datetime.now(UTC) + DENIAL_COOLDOWN + timedelta(minutes=1)
    assert gate.find_recent_denial(req, chapter_id="ch", now=future) is None


def test_find_recent_denial_is_scoped_to_the_action(tmp_ledger):
    _deny(_req(scope="https://evil.example"))
    # A different scope (the user did NOT deny this) must not match.
    assert gate.find_recent_denial(_req(scope="https://good.example"), chapter_id="ch") is None


# ── Executor: suppression ─────────────────────────────────────────


def _runner_collecting(calls: list):
    def runner(req):
        calls.append(req)
        return ToolOutput(
            capability=req.capability,
            scope=req.scope,
            outcome="ok",
            provenance="untrusted",
        )

    return runner


def test_denied_action_is_suppressed_not_reprompted(tmp_ledger):
    req = _req()
    calls: list = []
    runners = {"net.http": _runner_collecting(calls)}

    # Sanity: with no denial, a trusted proposal goes to the prompt path.
    fresh = execute_plan(Plan(proposals=(req,)), runners, chapter_id="ch")
    assert fresh[0].decision.state == "prompt"
    assert calls == []

    # User denies it; now the same proposal is suppressed (rejected), not
    # re-prompted, and the runner is never reached.
    _deny(req)
    after = execute_plan(Plan(proposals=(req,)), runners, chapter_id="ch")
    assert after[0].decision.state == "reject"
    assert after[0].decision.reason == "recently_denied"
    assert calls == []


def test_denial_overrides_trust_auto_approve(tmp_ledger):
    """A recent 'no' beats graduation/trust for the cooldown: even a trusted
    proposal at max trust (which would auto-approve) is suppressed."""
    req = _req()
    _deny(req)
    res = execute_plan(Plan(proposals=(req,)), {}, chapter_id="ch", local_trust=90, chapter_trust=90)
    assert res[0].decision.state == "reject"
    assert res[0].decision.reason == "recently_denied"


def test_unrelated_denial_does_not_suppress(tmp_ledger):
    _deny(_req(scope="https://evil.example"))
    other = _req(scope="https://good.example")
    res = execute_plan(Plan(proposals=(other,)), {}, chapter_id="ch")
    # Different action → not suppressed → normal prompt path.
    assert res[0].decision.state == "prompt"


# ── Gate: clear_denial (lift suppression early) ───────────────────


def test_clear_denial_lifts_suppression(tmp_ledger):
    req = _req()
    _deny(req)
    denial = gate.find_recent_denial(req, chapter_id="ch")
    assert denial is not None

    n = gate.clear_denial(denial["event_sha256"], chapter_id="ch", actor_agent_id="alice")
    assert n >= 1
    # Suppression lifted → the action can be proposed/prompted again.
    assert gate.find_recent_denial(req, chapter_id="ch") is None
    res = execute_plan(Plan(proposals=(req,)), {}, chapter_id="ch")
    assert res[0].decision.state == "prompt"


def test_clear_denial_unknown_sha_is_noop(tmp_ledger):
    assert gate.clear_denial("not-a-real-sha", chapter_id="ch") == 0


# ── Server: /consent/suppressed list + clear ──────────────────────


def test_suppressed_endpoint_lists_and_clears(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from community_member import config as config_mod
    from community_member import keystore
    from community_member.config import Config
    from community_member.server import create_app

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    cfg = Config()
    cfg.agent_id = "alice"
    client = TestClient(create_app(cfg, agent=None))

    req = _req()
    _deny(req, chapter_id="local:alice")  # _chapter_id() == local:alice

    listed = client.get("/api/local/consent/suppressed").json()["suppressed"]
    assert len(listed) == 1
    assert listed[0]["scope"] == "https://evil.example"
    assert listed[0]["expires_at"] and listed[0]["denied_at"]
    sha = listed[0]["denial_event_sha256"]

    resp = client.post("/api/local/consent/suppressed/clear", json={"denial_event_sha256": sha})
    assert resp.status_code == 200 and resp.json()["cleared"] >= 1

    # Now empty + suppression actually lifted.
    assert client.get("/api/local/consent/suppressed").json()["suppressed"] == []
    assert gate.find_recent_denial(req, chapter_id="local:alice") is None
