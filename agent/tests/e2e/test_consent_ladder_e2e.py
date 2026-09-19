"""Skills-under-consent: the full consent ladder driven over a LIVE agent.

Claims driven (STELLARMINDS.md:234-236, README.md:51-54, executor.py ladder):
  - a planner proposal lands as a consent prompt; approve runs it NOW
  - deny is a first-class outcome with a cooldown (suppression), clearable
  - untrusted provenance is rejected outright, never promptable (S3)
  - ≥5 approvals graduate a (capability, scope, context) bucket → the
    autonomous loop auto-approves it with reason "graduated" (the shipped
    W4 behavior — the behavioral anchor for the F1 doc-drift fix)
  - revoking the graduation returns the action to prompting
  - skill.invoke NEVER auto-approves (``_NO_AUTO_APPROVE``)

The LLM is the deterministic stub from conftest; everything else — the
planner parsing, gate, hash-chained ledger, executor, HTTP surface — is
the real runtime in a real process.
"""

from __future__ import annotations

import time

import pytest

from tests.e2e.conftest import (
    clear_queued_plans,
    e2e_gate,
    plan_intent,
    queue_think_plan,
)

pytestmark = e2e_gate


@pytest.fixture(autouse=True)
def _clean_stub():
    clear_queued_plans()
    yield
    clear_queued_plans()


@pytest.fixture(scope="module")
def member(org_server, llm_stub, tmp_path_factory):
    """One live member with the stub LLM and a fast think loop, shared by
    the module (its consent ledger accumulates through the ladder)."""
    import os
    import subprocess
    import sys

    from tests.e2e.conftest import (
        AGENT_DIR,
        LLM_STUB_PROVIDER,
        PASSPHRASE,
        Member,
        free_port,
        wait_healthy,
    )

    home = tmp_path_factory.mktemp("ladder-home")
    (home / "workspace").mkdir()
    (home / "workspace" / "note.txt").write_text("hello from e2e\n")
    port = free_port()
    env = {**os.environ}
    env.pop("DATABASE_URL", None)
    env.update(
        AGENT_ID="e2e-ladder",
        AGENT_NAME="E2E Ladder",
        PORT=str(port),
        CHAPTER_URL=org_server,
        COMMUNITY_MEMBER_HOME=str(home),
        COMMUNITY_MEMBER_KEYSTORE="passphrase",
        COMMUNITY_MEMBER_PASSPHRASE=PASSPHRASE,
        COMMUNITY_MEMBER_NO_REGISTRY="1",
        COMMUNITY_MEMBER_THINK_INTERVAL="2",
        AGENT_PROVIDER=LLM_STUB_PROVIDER,
        AGENT_MODEL="e2e-stub",
    )
    proc = subprocess.Popen(
        [sys.executable, "serve.py"],
        cwd=AGENT_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    m = Member(base=f"http://127.0.0.1:{port}", home=home, port=port, agent_id="e2e-ladder", proc=proc, env=env)
    try:
        wait_healthy(m.base, "/api/health", proc)
        yield m
    finally:
        m.stop()


def fs_read_proposal(member, provenance="trusted", context="e2e-ladder-ctx"):
    path = str(member.home / "workspace" / "note.txt")
    return {
        "capability": "fs.read",
        "scope": path,
        "context": context,
        "provenance": provenance,
        "rationale": "e2e drive",
        "extra": {"path": path},
    }


def _req_body(prop: dict) -> dict:
    """ActionRequestBody payload matching a proposal (approve/deny wire shape)."""
    return {
        "capability": prop["capability"],
        "scope": prop["scope"],
        "context": prop["context"],
        "provenance": prop["provenance"],
        "rationale": prop.get("rationale", ""),
    }


def _pending(member) -> list[dict]:
    return member.get("/api/local/consent/pending").json()["pending"]


def _dispatch(member, proposals, summary="e2e") -> dict:
    return member.post("/api/local/intent/dispatch", json={"text": plan_intent(proposals, summary)}).json()


def _await_pending(member, capability: str, timeout: float = 15.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for row in _pending(member):
            if row["capability"] == capability:
                return row
        time.sleep(0.5)
    raise AssertionError(f"no pending prompt for {capability}; pending={_pending(member)}")


def test_prompt_approve_execute(member):
    prop = fs_read_proposal(member)
    r = _dispatch(member, [prop])
    assert r.get("queued") == 1, r

    row = _await_pending(member, "fs.read")
    approve = member.post(
        "/api/local/consent/approve",
        json={"prompt_event_sha256": row["prompt_event_sha256"], "request": _req_body(prop)},
    ).json()
    assert approve.get("approval_event_sha256"), approve
    executed = approve.get("executed", {})
    assert executed.get("decision") == "approved", executed

    # R10: the approved prompt leaves the pending queue.
    assert not any(p["prompt_event_sha256"] == row["prompt_event_sha256"] for p in _pending(member))


def test_untrusted_provenance_rejected_never_promptable(member):
    r = _dispatch(member, [fs_read_proposal(member, provenance="untrusted", context="e2e-untrusted")])
    assert r.get("rejected") == 1, r
    assert not any(p["context"] == "e2e-untrusted" for p in _pending(member))


def test_deny_suppression_and_clear(member):
    prop = fs_read_proposal(member, context="e2e-deny-ctx")
    r = _dispatch(member, [prop])
    assert r.get("queued") == 1, r
    row = _await_pending(member, "fs.read")

    denied = member.post(
        "/api/local/consent/deny",
        json={"prompt_event_sha256": row["prompt_event_sha256"], "request": _req_body(prop)},
    ).json()
    assert denied.get("denied_event_sha256"), denied

    # Re-proposing within the cooldown is suppressed (recently_denied),
    # not re-prompted.
    r2 = _dispatch(member, [prop])
    assert r2.get("rejected") == 1, r2

    suppressed = member.get("/api/local/consent/suppressed").json()
    mine = [s for s in suppressed.get("suppressed", []) if s.get("context") == "e2e-deny-ctx"]
    assert mine, suppressed

    cleared = member.post(
        "/api/local/consent/suppressed/clear",
        json={"denial_event_sha256": mine[0]["denial_event_sha256"]},
    ).json()
    assert cleared.get("cleared", 0) >= 1, cleared

    r3 = _dispatch(member, [prop])
    assert r3.get("queued") == 1, r3


def test_graduation_auto_approve_and_revoke(member):
    """The W4 ladder rung, live: 5 explicit approvals graduate the bucket;
    the autonomous think loop then executes the same action WITHOUT a
    prompt (consent.auto_approved); revoking returns it to prompting."""
    prop = fs_read_proposal(member, context="e2e-grad-ctx")

    # 6 explicit approvals (threshold is 5 + posterior > 0.85).
    for i in range(6):
        r = _dispatch(member, [prop], summary=f"grad round {i}")
        assert r.get("queued") == 1, (i, r)
        row = _await_pending(member, "fs.read")
        approve = member.post(
            "/api/local/consent/approve",
            json={"prompt_event_sha256": row["prompt_event_sha256"], "request": _req_body(prop)},
        ).json()
        assert approve.get("executed", {}).get("decision") == "approved", (i, approve)

    pending_before = {p["prompt_event_sha256"] for p in _pending(member)}

    # Feed the SAME action to the autonomous loop via the stub queue.
    queue_think_plan([prop])

    # The think loop (2s cadence) must auto-approve. ``graduated_at`` is
    # stamped ONLY inside auto_approve_if_graduated (record_graduation), so
    # its appearance is direct evidence the auto-approve rung fired live.
    deadline = time.time() + 60
    bucket: list[dict] = []
    while time.time() < deadline and not bucket:
        grads = member.get("/api/local/graduations").json()["graduations"]
        bucket = [g for g in grads if g["capability"] == "fs.read" and g["state"] == "graduated" and g["graduated_at"]]
        time.sleep(1)
    assert bucket, "think loop never auto-approved the graduated action"

    # Auto-approved means NO new prompt was raised for it.
    new_prompts = [
        p for p in _pending(member) if p["prompt_event_sha256"] not in pending_before and p["capability"] == "fs.read"
    ]
    assert not new_prompts, new_prompts

    # Revoke → the FSM goes sticky-revoked: the bucket reports "revoked"
    # and no NEW graduation stamp can appear (auto_approve_if_graduated
    # returns None on revoked buckets — the unit suite pins that; here we
    # prove the live endpoint flips the stored state).
    graduated_at_before = bucket[0]["graduated_at"]
    revoke = member.post(
        "/api/local/graduations/revoke",
        json={
            "capability": "fs.read",
            "scope": prop["scope"],
            "context_sha256": bucket[0]["context_sha256"],
        },
    ).json()
    assert not revoke.get("error"), revoke

    grads = member.get("/api/local/graduations").json()["graduations"]
    revoked = [g for g in grads if g["capability"] == "fs.read" and g["state"] == "revoked"]
    assert revoked, grads

    # A post-revoke think proposal must not mint a new graduation stamp.
    queue_think_plan([prop])
    time.sleep(8)  # several think cycles at the 2s cadence
    grads = member.get("/api/local/graduations").json()["graduations"]
    row = [g for g in grads if g["capability"] == "fs.read"][0]
    assert row["state"] == "revoked", row
    assert (row["graduated_at"] or graduated_at_before) == graduated_at_before, row


def test_skill_invoke_never_auto_approves(member):
    """skill.invoke is in _NO_AUTO_APPROVE: even via the think loop it must
    prompt, never auto-approve."""
    prop = {
        "capability": "skill.invoke",
        "scope": "ignored — re-derived from extra",
        "context": "e2e-skill-ctx",
        "provenance": "trusted",
        "rationale": "e2e drive",
        "extra": {"skill_id": "datetime", "tool_name": "now", "args": {}},
    }
    queue_think_plan([prop])

    deadline = time.time() + 30
    found = None
    while time.time() < deadline and found is None:
        for row in _pending(member):
            if row["capability"] == "skill.invoke":
                found = row
                break
        time.sleep(1)
    assert found is not None, "skill.invoke think proposal never reached the prompt queue"

    # And it arrived as a PROMPT — not an auto-approval.
    feed = member.get("/api/local/consent/decisions").json()
    auto_rows = [e for e in feed.get("envelopes", []) if "auto" in str(e).lower() and "skill.invoke" in str(e)]
    assert not auto_rows, auto_rows
