"""An action that happened always leaves a trace; an approval never fires twice.

Two orderings on the agent's execution path were wrong in the same direction,
and both are held here with the failure planted the way it happens in
production — a process that dies, not a mock that returns.

F1  ``send_task_recorded`` ran the external call, THEN built/signed/persisted
    the receipt. A kill, a raise in the receipt stage, or a timeout after the
    counterparty had already acted left an action that HAPPENED with no record
    at all. Now the Agency Log takes a ``pending`` attempt BEFORE the call and
    finalizes it ``succeeded`` / ``failed`` / ``unknown`` after; a process that
    dies in between leaves the ``pending`` row, and ``reconcile_orphans`` marks
    it ``unknown`` at the next start. The wire receipt is unchanged and is
    still emitted only for an observed success.

F2  ``execute_plan`` fired the runner, THEN tombstoned the one-shot approval.
    A crash between the two left the approval valid inside its TTL, and the
    next cycle fired the action again. Now the approval is consumed BEFORE the
    runner (``gate.claim_approval``); the outcome is a separate
    ``consent.executed`` row, and an approval whose runner never reported
    stays spent with its outcome unknown.

The five named tests the change had to make red first:

  T1  kill between the call returning and the receipt write → on restart the
      log holds an UNKNOWN attempt for that action, not nothing
  T2  raise in the receipt stage after the call returned → an attempt that
      says the action succeeded and a receipt is owed, not nothing
  T3  crash after the runner fires, before the tombstone → the next cycle
      does NOT re-fire the approval
  T4  the same approval presented twice in one cycle executes once — even
      when the runner raises after firing
  T5  a retry does not produce two receipts (or two calls) for one action

Every kill here is ``os._exit`` in a child process: no ``finally``, no flush,
the way a SIGKILL or an OOM ends a process. The parent then reads the same
SQLite files the child wrote, which is exactly what a restarted agent does.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import community_member
from community_member import arp
from community_member.a2a_client_v2 import ActionSucceededUnreceipted, GoogleA2AClient, classify_send_failure
from community_member.arp import AgencyLog, DuplicateActionError, did_from_private_key
from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.executor import ToolOutput, execute_plan
from community_member.planner import Plan

AGENT_DIR = str(Path(community_member.__file__).resolve().parents[1])
CHAPTER = "local:alice"


def _key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _child_env(tmp_path: Path) -> dict[str, str]:
    # The venv editable-installs the SHARED checkout; the child must import
    # THIS tree, so it goes first on PYTHONPATH.
    env = dict(os.environ)
    env["PYTHONPATH"] = AGENT_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["COMMUNITY_MEMBER_HOME"] = str(tmp_path)
    return env


def _run_child(tmp_path: Path, source: str) -> subprocess.CompletedProcess:
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(source))
    return subprocess.run(
        [sys.executable, str(script)], env=_child_env(tmp_path), capture_output=True, text=True, timeout=60
    )


# ── a counterparty that counts what it executed ─────────────────────


class _Counterparty:
    """A minimal A2A JSON-RPC endpoint. ``executed`` is the ground truth the
    receipt is supposed to attest — what the OTHER side did."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        outer = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                if body.get("method") == "tasks/send":
                    outer.executed.append(body["params"]["id"])
                    result = {"id": body["params"]["id"], "status": {"state": "completed"}}
                else:
                    result = {}
                payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self) -> None:
        self.srv.shutdown()


@pytest.fixture
def counterparty():
    cp = _Counterparty()
    yield cp
    cp.close()


# ── T1: kill between the call returning and the receipt write ───────


def test_T1_kill_after_call_before_receipt_write_surfaces_UNKNOWN_on_restart(tmp_path, counterparty):
    """The child performs a real A2A call and dies (``os._exit``) the instant
    the call returns, before anything after it runs. The counterparty executed
    the task; a restarted agent reading the same log must see that an action
    of unknown outcome was attempted — not an empty log."""
    seed = _key()
    (tmp_path / "seed").write_bytes(seed)
    child = _run_child(
        tmp_path,
        f"""
        import os
        from pathlib import Path
        from community_member import arp
        from community_member.a2a_client_v2 import GoogleA2AClient
        # The kill point: the call has RETURNED from the wire and nothing after
        # it runs — the process dies as _rpc hands the result back, before
        # send_task_recorded gets to write anything.
        _real_rpc = GoogleA2AClient._rpc
        def _rpc_then_die(self, method, params):
            result = _real_rpc(self, method, params)
            os._exit(9)
        GoogleA2AClient._rpc = _rpc_then_die
        log = arp.AgencyLog(home=Path({str(tmp_path / "agency")!r}))
        client = GoogleA2AClient({counterparty.url!r})
        client.send_task_recorded(
            "book", {{"slot": "10:00"}}, counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop", sk_bytes=Path({str(tmp_path / "seed")!r}).read_bytes(),
            agency_log=log, cosign=False, task_id="task-T1",
        )
        print("UNREACHABLE")
        """,
    )
    assert child.returncode == 9, child.stderr
    assert "UNREACHABLE" not in child.stdout
    assert counterparty.executed == ["task-T1"], "the external action must have happened"

    # The restart: a fresh process (this one) opens the same log.
    log = AgencyLog(home=tmp_path / "agency")
    assert log.list_recent(limit=10) == [], "no receipt was written — the kill was before the write"
    orphans = log.reconcile_orphans()
    assert [a["action_ref"] for a in orphans] == ["task-T1"], "the attempted action left no trace"
    after = log.latest_attempt("task-T1")
    assert after["state"] == "unknown"
    assert after["detail"]["unknown_reason"] == "process_died_before_finalize"
    assert [a["attempt_id"] for a in log.unresolved_actions()] == [after["attempt_id"]]
    # Never auto-retried: a second attempt with the same ref is refused before it is sent.
    with pytest.raises(DuplicateActionError):
        log.begin_action(
            issuer_did=did_from_private_key(seed), category="message_sent", summary="x", action_ref="task-T1"
        )
    assert counterparty.executed == ["task-T1"]


# ── T2: raise in the receipt stage after the call returned ──────────


def test_T2_raise_in_receipt_stage_after_call_returned_leaves_an_owed_receipt(tmp_path, monkeypatch):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = GoogleA2AClient("http://svc.test", agent_id="me")
    calls: list[str] = []

    def fake_send_task(tool, args, **kw):
        calls.append(kw.get("task_id") or "?")
        return {"id": kw.get("task_id"), "status": {"state": "completed"}}

    monkeypatch.setattr(client, "send_task", fake_send_task)

    def unwritable(self, receipt):
        raise OSError("disk full")

    monkeypatch.setattr(AgencyLog, "append", unwritable)

    with pytest.raises(ActionSucceededUnreceipted) as exc:
        client.send_task_recorded(
            "book",
            {},
            counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop",
            sk_bytes=sk,
            agency_log=log,
            cosign=False,
            task_id="task-T2",
        )
    client.close()
    assert calls == ["task-T2"]
    assert exc.value.result["status"]["state"] == "completed", "the caller still gets what the call returned"

    attempt = log.latest_attempt("task-T2")
    assert attempt is not None, "the attempted action left no trace"
    assert attempt["state"] == "succeeded" and attempt["receipt_id"] is None
    assert "disk full" in attempt["detail"]["receipt_error"]
    assert [a["attempt_id"] for a in log.unresolved_actions()] == [attempt["attempt_id"]]


# ── T3: crash after the runner fires, before the tombstone ──────────


def _consent_req() -> ActionRequest:
    return ActionRequest(
        capability="skill.invoke",
        scope="datetime@1.0.0::now::test",
        context="time",
        provenance="trusted",
        extra={"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {}},
    )


@pytest.fixture
def consent_db(tmp_path: Path):
    ledger._reset_for_tests()
    gate._reset_in_flight_for_tests()
    ledger.init(tmp_path / "consent.db")
    yield tmp_path / "consent.db"
    ledger._reset_for_tests()
    gate._reset_in_flight_for_tests()


def test_T3_process_killed_after_runner_fires_does_not_refire_next_cycle(tmp_path, consent_db):
    """The child records a prompt + a user approval and runs the plan with a
    runner that performs its side effect and dies. The parent — the restarted
    agent — runs the same plan against the same ledger: the runner must NOT be
    invoked again."""
    fired = tmp_path / "fired"
    child = _run_child(
        tmp_path,
        f"""
        import os
        from pathlib import Path
        from community_member.consent import gate, ledger
        from community_member.consent.gate import ActionRequest
        from community_member.executor import execute_plan
        from community_member.planner import Plan
        ledger.init(Path({str(consent_db)!r}))
        req = ActionRequest(
            capability="skill.invoke", scope="datetime@1.0.0::now::test", context="time", provenance="trusted",
            extra={{"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {{}}}},
        )
        first = gate.check_and_record(req, chapter_id={CHAPTER!r})
        gate.approve(req, chapter_id={CHAPTER!r}, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
        def runner(r):
            Path({str(fired)!r}).write_text("fired")   # the external side effect
            os._exit(9)                                 # dies before it can report
        execute_plan(Plan(proposals=(req,)), {{"skill.invoke": runner}}, chapter_id={CHAPTER!r})
        print("UNREACHABLE")
        """,
    )
    assert child.returncode == 9, child.stderr
    assert fired.read_text() == "fired", "the runner must have fired in the child"

    calls: list = []

    def runner(r):
        calls.append(r)
        return ToolOutput(capability=r.capability, scope=r.scope, outcome="ok")

    ledger._reset_for_tests()
    ledger.init(consent_db)
    r2 = execute_plan(Plan(proposals=(_consent_req(),)), {"skill.invoke": runner}, chapter_id=CHAPTER)
    assert calls == [], "the approval re-fired after a crash: duplicate external action"
    assert r2[0].decision.state == "prompt"
    # The ledger says: consumed, outcome unknown (no executed row).
    consumed = ledger.list_events(action="consent.consumed", limit=10)
    assert len(consumed) == 1 and consumed[0]["detail"]["execution"] == "unknown"
    assert ledger.list_events(action="consent.executed", limit=10) == []


class _Crash(BaseException):
    """A non-Exception escaping the runner — what a KeyboardInterrupt or a
    SystemExit looks like from the executor's side."""


def test_T3b_in_process_crash_after_runner_fires_does_not_refire(consent_db):
    req = _consent_req()
    first = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    calls: list = []

    def crashing(r):
        calls.append("fired")
        raise _Crash()

    with pytest.raises(_Crash):
        execute_plan(Plan(proposals=(req,)), {"skill.invoke": crashing}, chapter_id=CHAPTER)
    assert calls == ["fired"]

    def runner(r):
        calls.append("again")
        return ToolOutput(capability=r.capability, scope=r.scope, outcome="ok")

    r2 = execute_plan(Plan(proposals=(req,)), {"skill.invoke": runner}, chapter_id=CHAPTER)
    assert calls == ["fired"], "the approval re-fired after the runner crashed"
    assert r2[0].decision.state == "prompt"


# ── T4: the same approval twice in one cycle ────────────────────────


@pytest.mark.parametrize("runner_raises", [False, True], ids=["runner-returns", "runner-raises-after-firing"])
def test_T4_same_approval_presented_twice_in_one_cycle_executes_once(consent_db, runner_raises):
    req = _consent_req()
    first = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    calls: list = []

    def runner(r):
        calls.append("fired")
        if runner_raises:
            raise RuntimeError("counterparty hung up after acting")
        return ToolOutput(capability=r.capability, scope=r.scope, outcome="ok")

    results = execute_plan(Plan(proposals=(req, req)), {"skill.invoke": runner}, chapter_id=CHAPTER)
    assert calls == ["fired"], "one approval executed twice in one cycle"
    assert results[0].decision.state == "approved"
    assert results[1].decision.state == "prompt"
    executed = ledger.list_events(action="consent.executed", limit=10)
    assert len(executed) == 1
    assert executed[0]["detail"]["execution"] == ("error" if runner_raises else "ok")


# ── T5: a retry never yields two receipts for one action ────────────


def test_T5_retry_after_unreceipted_success_is_refused_before_it_is_sent(tmp_path, monkeypatch):
    """Attempt 1's receipt stage fails after the call returned. A caller that
    retries with the same task id must be stopped BEFORE the second call: one
    external call, at most one receipt."""
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = GoogleA2AClient("http://svc.test", agent_id="me")
    calls: list[str] = []
    monkeypatch.setattr(client, "send_task", lambda tool, args, **kw: calls.append(kw["task_id"]) or {"ok": True})
    real_append = AgencyLog.append
    monkeypatch.setattr(AgencyLog, "append", lambda self, r: (_ for _ in ()).throw(OSError("disk full")))
    kw = dict(
        counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        counterparty_label="the-shop",
        sk_bytes=sk,
        agency_log=log,
        cosign=False,
        task_id="task-T5",
    )
    with pytest.raises(ActionSucceededUnreceipted):
        client.send_task_recorded("book", {}, **kw)
    monkeypatch.setattr(AgencyLog, "append", real_append)  # the disk is back
    with pytest.raises(DuplicateActionError):
        client.send_task_recorded("book", {}, **kw)
    client.close()
    assert calls == ["task-T5"], "the retry performed the action a second time"
    assert log.count() <= 1
    assert len(log.list_attempts(action_ref="task-T5")) == 1


def test_T5b_retry_after_a_failed_call_yields_exactly_one_receipt(tmp_path, monkeypatch):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = GoogleA2AClient("http://svc.test", agent_id="me")
    n = {"calls": 0}

    def flaky(tool, args, **kw):
        n["calls"] += 1
        if n["calls"] == 1:
            raise httpx.ConnectError("connection refused")
        return {"ok": True}

    monkeypatch.setattr(client, "send_task", flaky)
    kw = dict(
        counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        counterparty_label="the-shop",
        sk_bytes=sk,
        agency_log=log,
        cosign=False,
        task_id="task-T5b",
    )
    with pytest.raises(httpx.ConnectError):
        client.send_task_recorded("book", {}, **kw)
    assert log.latest_attempt("task-T5b")["state"] == "failed"
    client.send_task_recorded("book", {}, **kw)
    client.close()
    attempts = log.list_attempts(action_ref="task-T5b")
    assert [a["state"] for a in attempts] == ["succeeded", "failed"]
    assert log.count() == 1
    assert attempts[0]["receipt_id"] == log.list_recent(limit=1)[0]["receipt_id"]
    assert log.unresolved_actions() == []


# ── the classification a raised call gets ───────────────────────────


@pytest.mark.parametrize(
    ("exc", "state"),
    [
        (httpx.ConnectError("refused"), "failed"),
        (httpx.ConnectTimeout("no route"), "failed"),
        (httpx.ReadTimeout("after the request left"), "unknown"),
        (httpx.RemoteProtocolError("connection closed mid-response"), "unknown"),
        (RuntimeError("anything else"), "unknown"),
    ],
)
def test_a_raised_call_is_failed_only_when_the_request_never_left(exc, state):
    assert classify_send_failure(exc) == state


def test_an_http_error_status_is_unknown_not_failed():
    req = httpx.Request("POST", "http://svc.test/")
    exc = httpx.HTTPStatusError("502", request=req, response=httpx.Response(502, request=req))
    assert classify_send_failure(exc) == "unknown"


def test_a_timeout_after_the_request_left_is_recorded_unknown(tmp_path, monkeypatch):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = GoogleA2AClient("http://svc.test", agent_id="me")
    monkeypatch.setattr(client, "send_task", lambda *a, **k: (_ for _ in ()).throw(httpx.ReadTimeout("late")))
    with pytest.raises(httpx.ReadTimeout):
        client.send_task_recorded(
            "book",
            {},
            counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop",
            sk_bytes=sk,
            agency_log=log,
            cosign=False,
            task_id="task-timeout",
        )
    client.close()
    a = log.latest_attempt("task-timeout")
    assert a["state"] == "unknown" and "ReadTimeout" in a["detail"]["error"]
    assert log.list_recent(limit=5) == [], "no receipt may claim an outcome nobody observed"
    assert [x["attempt_id"] for x in log.unresolved_actions()] == [a["attempt_id"]]


# ── the happy path still receipts, and links the attempt to it ──────


def test_success_finalizes_the_attempt_with_the_receipt_id(tmp_path, counterparty):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    with GoogleA2AClient(counterparty.url) as client:
        client.send_task_recorded(
            "book",
            {},
            counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop",
            sk_bytes=sk,
            agency_log=log,
            cosign=False,
            task_id="task-ok",
        )
    a = log.latest_attempt("task-ok")
    receipt = log.list_recent(limit=1)[0]
    assert a["state"] == "succeeded" and a["receipt_id"] == receipt["receipt_id"]
    assert receipt["action"]["outcome"] == "completed"
    assert log.unresolved_actions() == []
    assert counterparty.executed == ["task-ok"]


@pytest.mark.asyncio
async def test_async_client_has_the_same_ordering(tmp_path, monkeypatch):
    from community_member.a2a_client_v2 import AsyncGoogleA2AClient

    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = AsyncGoogleA2AClient("http://svc.test", agent_id="me")

    async def boom(tool, args, **kw):
        raise httpx.ReadTimeout("late")

    monkeypatch.setattr(client, "send_task", boom)
    with pytest.raises(httpx.ReadTimeout):
        await client.send_task_recorded(
            "book",
            {},
            counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop",
            sk_bytes=sk,
            agency_log=log,
            cosign=False,
            task_id="task-async",
        )
    await client.aclose()
    assert log.latest_attempt("task-async")["state"] == "unknown"


# ── an unwritable log refuses BEFORE the call ───────────────────────


def test_an_unwritable_log_refuses_before_the_external_call(tmp_path, monkeypatch, counterparty):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    monkeypatch.setattr(AgencyLog, "begin_action", lambda self, **kw: (_ for _ in ()).throw(OSError("read-only")))
    with GoogleA2AClient(counterparty.url) as client, pytest.raises(OSError):
        client.send_task_recorded(
            "book",
            {},
            counterparty_did="did:key:z6MkcounterpartyXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            counterparty_label="the-shop",
            sk_bytes=sk,
            agency_log=log,
            cosign=False,
        )
    assert counterparty.executed == [], "the call went out with no way to record it"


# ── the executor's ledger rows ──────────────────────────────────────


def test_claim_writes_the_tombstone_before_the_runner_runs(consent_db):
    req = _consent_req()
    first = gate.check_and_record(req, chapter_id=CHAPTER)
    sha = gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    seen: dict = {}

    def runner(r):
        seen["consumed_at_run"] = gate.is_consumed(sha)
        # The runner's own re-check must still honour the approval it is executing.
        seen["runner_recheck"] = gate.find_valid_approval(r, chapter_id=CHAPTER)
        return ToolOutput(capability=r.capability, scope=r.scope, outcome="ok")

    execute_plan(Plan(proposals=(req,)), {"skill.invoke": runner}, chapter_id=CHAPTER)
    assert seen["consumed_at_run"] is True, "the tombstone was written after the runner, not before"
    assert seen["runner_recheck"]["event_sha256"] == sha
    assert gate.find_valid_approval(req, chapter_id=CHAPTER) is None, "still admitted after the execution ended"
    executed = ledger.list_events(action="consent.executed", limit=5)
    assert executed[0]["detail"] == {"approval_event_sha256": sha, "execution": "ok"}


def test_a_claim_with_no_runner_leaves_a_spent_approval_and_an_error_row(consent_db):
    req = _consent_req()
    first = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    r = execute_plan(Plan(proposals=(req,)), {}, chapter_id=CHAPTER)
    assert r[0].error and "no runner" in r[0].error
    assert gate.find_valid_approval(req, chapter_id=CHAPTER) is None, "spent-but-unexecuted is the safe direction"
    assert ledger.list_events(action="consent.executed", limit=5)[0]["detail"]["execution"] == "error"


def test_two_threads_cannot_both_claim_one_approval(consent_db):
    import concurrent.futures as cf

    req = _consent_req()
    first = gate.check_and_record(req, chapter_id=CHAPTER)
    gate.approve(req, chapter_id=CHAPTER, prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    with cf.ThreadPoolExecutor(8) as pool:
        got = list(pool.map(lambda _: gate.claim_approval(req, chapter_id=CHAPTER), range(8)))
    assert sum(1 for g in got if g is not None) == 1


# ── restart reconciliation ──────────────────────────────────────────


def _begun_by_a_dead_process(log: AgencyLog, **kw) -> str:
    """Write a ``pending`` attempt stamped with another process's token."""
    mine = arp._PROCESS_TOKEN
    arp._PROCESS_TOKEN = "a-process-that-died"
    try:
        return log.begin_action(**kw)
    finally:
        arp._PROCESS_TOKEN = mine


def test_reconcile_marks_only_other_processes_pending_rows(tmp_path):
    log = AgencyLog(home=tmp_path / "agency")
    did = did_from_private_key(_key())
    mine = log.begin_action(issuer_did=did, category="message_sent", summary="mine, still running")
    theirs = _begun_by_a_dead_process(log, issuer_did=did, category="message_sent", summary="theirs, orphaned")
    assert [a["attempt_id"] for a in log.orphaned_actions()] == [theirs]
    reconciled = log.reconcile_orphans()
    assert [a["attempt_id"] for a in reconciled] == [theirs]
    assert log.get_attempt(theirs)["state"] == "unknown"
    assert log.get_attempt(mine)["state"] == "pending", "an attempt this process is still running was clobbered"
    assert log.reconcile_orphans() == []


def test_agent_start_reports_orphans_and_owed_receipts(tmp_path, monkeypatch, capsys):
    from community_member import config as cm_config
    from community_member.agent import LocalAgent
    from community_member.config import Config

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path)
    log = AgencyLog(home=tmp_path)
    did = did_from_private_key(_key())
    orphan = _begun_by_a_dead_process(
        log, issuer_did=did, category="message_sent", summary="sent to the-shop", action_ref="t-1"
    )
    owed = log.begin_action(issuer_did=did, category="message_sent", summary="also sent", action_ref="t-2")
    log.finalize_action(owed, "succeeded", receipt_id=None, detail={"receipt_error": "OSError: disk full"})

    cfg = Config()
    cfg.agent_id = ""
    cfg.provider = ""
    LocalAgent(cfg)
    out = capsys.readouterr().out
    assert "[agency-log][UNKNOWN] message_sent" in out and orphan in out
    assert "[agency-log][RECEIPT OWED]" in out and owed in out
    assert log.get_attempt(orphan)["state"] == "unknown"


def test_unresolved_surface_lists_attempts_not_receipts(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from community_member import config as cm_config
    from community_member.config import Config
    from community_member.server import create_app

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path)
    log = AgencyLog(home=tmp_path)
    did = did_from_private_key(_key())
    a = log.begin_action(issuer_did=did, category="message_sent", summary="sent", action_ref="t-x")
    log.finalize_action(a, "unknown", detail={"error": "ReadTimeout"})
    ok = log.begin_action(issuer_did=did, category="message_sent", summary="fine", action_ref="t-y")
    log.finalize_action(ok, "succeeded", receipt_id="r-1")

    cfg = Config()
    cfg.agent_id = "alice"
    client = TestClient(create_app(cfg))
    body = client.get("/api/agency-log/unresolved").json()
    assert [x["attempt_id"] for x in body["attempts"]] == [a]
    assert body["attempts"][0]["state"] == "unknown"
