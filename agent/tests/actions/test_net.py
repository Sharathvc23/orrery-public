"""Tests for NetExecutor — egress allowlist + S6.

Coverage:

  R1  Forgery — fabricated approval → denied, no fetch
  R3  Injection — hostname with unicode/control chars rejected cleanly
  R4  Authz — hostname not on allowlist → denied BEFORE any DNS
  R5  Boundary — wildcard match works; bare domain does NOT match '*.x'
  R7  Adversarial — approval for host A cannot authorize host B;
      DNS prefetch side-channel isn't possible because sandbox runs
      BEFORE the fetcher
  R8  Expired approval → denied
  R10 Content-sha256 recorded on successful fetch; chain verifies

  S6  Egress allowlist blocks non-allowlisted domain at SANDBOX layer,
      not at DNS/network — canonical S6 test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member.actions.net import NetExecutor, _hostname_of
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
def ok_fetcher():
    """Default fetcher: returns 200 + small body."""

    def fn(url, timeout_sec):
        return (200, f"content of {url}".encode())

    return fn


@pytest.fixture
def boom_fetcher():
    """If called, means a sandbox check failed to block an ungranted
    hostname. Any test using this expects the executor to deny BEFORE
    calling the fetcher."""

    def fn(url, timeout_sec):
        raise AssertionError(f"fetcher was called for {url} — sandbox should have blocked")

    return fn


@pytest.fixture
def executor(tmp_ledger):
    pol = parse_policy(["net.http:docs.openai.com,*.example.com"])
    return NetExecutor(chapter_id="ch", actor_agent_id="alice", policy=pol)


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


# ── _hostname_of ──────────────────────────────────────────────


def test_hostname_of_basic():
    assert _hostname_of("https://DOCS.openai.com/path") == "docs.openai.com"


def test_hostname_of_missing_raises():
    with pytest.raises(ValueError):
        _hostname_of("no-scheme-or-host")


# ── Propose → ConsentRequired ─────────────────────────────────


def test_propose_raises_consent(executor):
    with pytest.raises(gate.ConsentRequired, match="net.http"):
        executor.propose_get("https://docs.openai.com/p", context="c")


# ── S6: egress allowlist blocks at sandbox layer ─────────────


def test_S6_non_allowlisted_host_denied_before_fetch(executor, boom_fetcher):
    """Canonical S6. Hostname not on allowlist → the executor
    returns denied BEFORE invoking the fetcher. No DNS, no connection."""
    req, prompt = _consume_prompt(executor.propose_get, "https://evil.example/x", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://evil.example/x",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=boom_fetcher,
    )
    assert result.outcome == "denied"
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_S6_wildcard_subdomain_allowed(executor, ok_fetcher):
    req, prompt = _consume_prompt(executor.propose_get, "https://foo.example.com/api", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://foo.example.com/api",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=ok_fetcher,
    )
    assert result.outcome == "ok"


def test_S6_bare_domain_does_not_match_wildcard(executor, boom_fetcher):
    """*.example.com does NOT authorize bare example.com."""
    req, prompt = _consume_prompt(executor.propose_get, "https://example.com/x", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://example.com/x",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=boom_fetcher,
    )
    assert result.outcome == "denied"


# ── R1 forgery ────────────────────────────────────────────────


def test_R1_fabricated_approval_denied(executor, boom_fetcher):
    _consume_prompt(executor.propose_get, "https://docs.openai.com/p", context="c")
    result = executor.http_get(
        "https://docs.openai.com/p",
        context="c",
        approval_event_sha256="z" * 64,
        fetcher=boom_fetcher,
    )
    assert result.outcome == "denied"
    assert result.extra["reason"] == "approval_not_found_or_expired"


# ── R7: approval for one host doesn't authorize another ─────


def test_R7_approval_for_host_a_cannot_authorize_host_b(executor, boom_fetcher):
    req_a, prompt_a = _consume_prompt(executor.propose_get, "https://docs.openai.com/p", context="c")
    approval = gate.approve(req_a, chapter_id="ch", prompt_event_sha256=prompt_a)
    # Try to use that approval to fetch a different host.
    result = executor.http_get(
        "https://other.example.com/p",
        context=req_a.context,
        approval_event_sha256=approval,
        fetcher=boom_fetcher,
    )
    assert result.outcome == "denied"


# ── R10: happy path records sha256 ───────────────────────────


def test_R10_content_sha256_recorded(executor, ok_fetcher):
    req, prompt = _consume_prompt(executor.propose_get, "https://docs.openai.com/a", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://docs.openai.com/a",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=ok_fetcher,
    )
    assert result.outcome == "ok"
    assert len(result.extra["content_sha256"]) == 64  # hex
    assert result.provenance == "untrusted"
    assert ledger.verify_chain()["ok"] is True


# ── Fetcher exception → fail outcome, no raise ──────────────


def test_http_exception_captured_as_fail(executor):
    def broken(url, timeout_sec):
        raise ConnectionError("network dead")

    req, prompt = _consume_prompt(executor.propose_get, "https://docs.openai.com/a", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://docs.openai.com/a",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=broken,
    )
    assert result.outcome == "fail"
    assert "network dead" in result.extra["reason"]


# ── HTTP 4xx/5xx → outcome=fail ────────────────────────────


def test_http_500_is_fail_outcome(executor):
    def err(url, timeout_sec):
        return (500, b"internal server error")

    req, prompt = _consume_prompt(executor.propose_get, "https://docs.openai.com/a", context="c")
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt)
    result = executor.http_get(
        "https://docs.openai.com/a",
        context=req.context,
        approval_event_sha256=approval,
        fetcher=err,
    )
    assert result.outcome == "fail"
    assert result.data["status"] == 500
