"""Two consent-path escapes found by inspection, each confirmed by a
measurement before it was closed.

REDIRECT  ``net.http``'s host check ran once, on the URL the user approved,
          and the default fetcher then followed redirects. Measured: a grant
          for ``localhost`` fetched a body from ``127.0.0.1`` through one
          302. The fetcher no longer follows; a 3xx is reported with its
          ``Location`` and is not a success, so the planner has to propose
          the new host and that proposal meets the gate and the policy.

PANIC     ``execute_panic`` revoked graduations and rotated the key, and
          left every user approval inside its TTL live and the trust dial
          where it was — so the action a user had just clicked Approve on
          still ran on the next cycle after panic, and a dial at 100 kept
          auto-approving. Panic now spends every live approval
          (``execution="revoked_by_panic"``) and resets both trust signals.
"""

from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from community_member import identity_trust, keystore, panic
from community_member.actions.net import NetExecutor, _default_fetcher
from community_member.config import Config
from community_member.consent import gate, ledger
from community_member.consent.gate import ActionRequest
from community_member.executor import ToolOutput, execute_plan
from community_member.planner import Plan
from community_member.sandbox import parse_policy


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    gate._reset_in_flight_for_tests()
    keystore.reset_for_tests()
    yield
    ledger._reset_for_tests()
    gate._reset_in_flight_for_tests()
    keystore.reset_for_tests()


# ── net.http: a redirect must not leave the approved host ───────────


class _Server:
    def __init__(self, handler_cls):
        self.srv = HTTPServer(("127.0.0.1", 0), handler_cls)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def redirecting_pair():
    """An allowlisted origin that 302s to a host outside the grant."""
    hits: list[str] = []

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            hits.append("target")
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"secret")

    target = _Server(Target)

    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):
            hits.append("allowlisted")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.port}/")
            self.send_header("Content-Length", "0")
            self.end_headers()

    redirector = _Server(Redirector)
    yield f"http://localhost:{redirector.port}/", hits
    redirector.close()
    target.close()


def test_default_fetcher_does_not_follow_a_redirect(redirecting_pair):
    url, hits = redirecting_pair
    status, body, location = _default_fetcher(url, 5)
    assert status == 302 and body == b""
    assert location.startswith("http://127.0.0.1:")
    assert hits == ["allowlisted"], "the fetcher reached a host the policy never checked"


def test_net_http_reports_a_redirect_as_not_ok_and_does_not_fetch_the_target(tmp_path, redirecting_pair):
    url, hits = redirecting_pair
    ledger.init(tmp_path / "consent.db")
    ex = NetExecutor(chapter_id="ch", policy=parse_policy(["net.http:localhost"]))
    with pytest.raises(gate.ConsentRequired):
        ex.propose_get(url, context="c")
    row = ledger.list_events(action="consent.prompt", limit=1)[0]
    req = ActionRequest(
        capability="net.http",
        scope=row["detail"]["scope"],
        context=row["detail"]["context"],
        provenance=row["detail"]["provenance"],
        source_ref=row["detail"].get("source_ref"),
        extra=row["detail"].get("extra", {}),
    )
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=row["event_sha256"])
    result = ex.http_get(url, context="c", approval_event_sha256=approval)
    assert result.outcome == "fail", "a redirect was reported as a successful fetch"
    assert result.data["redirect_not_followed"] is True
    assert result.data["location"].startswith("http://127.0.0.1:")
    assert result.extra["body_bytes"] == b""
    assert hits == ["allowlisted"], "the approved host redirected and the fetch followed it off the allowlist"


def test_an_injected_two_tuple_fetcher_still_works(tmp_path):
    """Tests inject ``(status, body)`` fetchers; the seam keeps that shape."""
    ledger.init(tmp_path / "consent.db")
    ex = NetExecutor(chapter_id="ch", policy=parse_policy(["net.http:docs.example"]))
    with pytest.raises(gate.ConsentRequired):
        ex.propose_get("https://docs.example/x", context="c")
    row = ledger.list_events(action="consent.prompt", limit=1)[0]
    req = ActionRequest(
        capability="net.http",
        scope=row["detail"]["scope"],
        context=row["detail"]["context"],
        provenance=row["detail"]["provenance"],
        extra=row["detail"].get("extra", {}),
    )
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=row["event_sha256"])
    result = ex.http_get(
        "https://docs.example/x", context="c", approval_event_sha256=approval, fetcher=lambda u, t: (200, b"ok")
    )
    assert result.outcome == "ok" and "redirect_not_followed" not in result.data


# ── panic: nothing approved before it may run after it ──────────────


@pytest.fixture
def agent_home(tmp_path: Path, monkeypatch):
    from community_member import config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    cfg = Config()
    cfg.agent_id = "alice"
    cfg.private_key = base64.b64encode(b"X" * 32).decode()
    cfg.public_key = base64.b64encode(b"Y" * 32).decode()
    cfg.save()
    return tmp_path, cfg


def _req() -> ActionRequest:
    return ActionRequest(
        capability="skill.invoke",
        scope="datetime@1.0.0::now::test",
        context="time",
        provenance="trusted",
        extra={"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {}},
    )


def test_panic_spends_a_live_user_approval(agent_home):
    _home, cfg = agent_home
    req = _req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    sha = gate.approve(req, chapter_id="local:alice", prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    assert gate.find_valid_approval(req, chapter_id="local:alice") is not None

    report = panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=cfg, rotate_key=False)
    assert report.revoked_approvals == 1

    calls: list = []

    def runner(r):
        calls.append(r)
        return ToolOutput(capability=r.capability, scope=r.scope, outcome="ok")

    res = execute_plan(Plan(proposals=(req,)), {"skill.invoke": runner}, chapter_id="local:alice")
    assert calls == [], "an approval clicked before panic still ran after it"
    assert res[0].decision.state == "prompt"
    tomb = [
        e
        for e in ledger.list_events(action="consent.consumed", limit=10)
        if e["detail"]["approval_event_sha256"] == sha
    ]
    assert tomb and tomb[0]["detail"]["execution"] == "revoked_by_panic"


def test_panic_resets_the_trust_dial_so_nothing_auto_approves(agent_home):
    home, cfg = agent_home
    identity_trust.save_local_trust(home, 100)
    identity_trust.save_chapter_trust(home, 95)
    req = _req()

    # Before panic: the dial alone auto-approves a trusted proposal.
    assert identity_trust.auto_approve_if_trusted(req, chapter_id="local:alice", local_trust=100, chapter_trust=0)

    report = panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=cfg, rotate_key=False)
    assert report.trust_reset is True
    snap = identity_trust.snapshot(home)
    assert snap.local == identity_trust.DEFAULT_LOCAL_TRUST and snap.chapter == 0
    assert snap.effective < identity_trust.AUTO_APPROVE_THRESHOLD
    assert (
        identity_trust.auto_approve_if_trusted(
            req, chapter_id="local:alice", local_trust=snap.local, chapter_trust=snap.chapter
        )
        is None
    )


def test_panic_is_still_idempotent_with_the_new_steps(agent_home):
    _home, cfg = agent_home
    req = _req()
    first = gate.check_and_record(req, chapter_id="local:alice")
    gate.approve(req, chapter_id="local:alice", prompt_event_sha256=first.event_sha256, actor_agent_id="alice")
    first_report = panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=cfg, rotate_key=False)
    second_report = panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=cfg, rotate_key=False)
    assert (first_report.revoked_approvals, second_report.revoked_approvals) == (1, 0)
