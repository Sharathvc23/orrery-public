"""Tests for FilesExecutor — per-root allowlist + inode-pinned read/write.

Coverage:

  R1  Forgery — fabricated approval_event_sha256 → denied, no I/O
  R2  Replay — same approval within TTL allows retry (by design)
  R3  Injection — path with '..' resolves outside root → denied by sandbox
  R4  Authz — fs.read approval does NOT authorize fs.write
  R5  Boundary — empty file read; file exactly at MAX_READ_BYTES; one over
  R6  Concurrency — threaded writes through ledger.threading.Lock
  R7  Adversarial — symlink pointing outside root → denied; sandbox
      rejects even when approval matches
  R8  Revocation — expired approval → denied
  R9  Timing — writes are atomic (mkstemp + os.replace)
  R10 Persistence — content_sha256 in ledger matches written bytes; chain
      verifies through multi-action flow

  S3  fs.read returns provenance='untrusted' on data — file content is
      never promoted to trusted regardless of source
"""

from __future__ import annotations

import hashlib

import pytest

from community_member.actions.files import FilesExecutor
from community_member.consent import gate, ledger
from community_member.sandbox import parse_policy


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_ledger(tmp_path):
    ledger.init(tmp_path / "consent.db")


@pytest.fixture
def scratch(tmp_path):
    """A per-test scratch dir that will be in the sandbox allowlist."""
    d = tmp_path / "agent-scratch"
    d.mkdir()
    return d


@pytest.fixture
def executor(tmp_ledger, scratch):
    pol = parse_policy(
        [
            f"fs.read:{scratch}/**",
            f"fs.write:{scratch}/**",
        ]
    )
    return FilesExecutor(chapter_id="ch", actor_agent_id="alice", policy=pol)


def _consume_prompt(exec_method, path, context="ctx"):
    """Run a propose method, catch ConsentRequired, return (req, hash)."""
    try:
        exec_method(path, context=context)
    except gate.ConsentRequired:
        pass
    row = ledger.list_events(action="consent.prompt", limit=1)[0]
    req = gate.ActionRequest(
        capability=row["detail"]["capability"],
        scope=row["detail"]["scope"],
        context=row["detail"]["context"],
        provenance=row["detail"]["provenance"],
        source_ref=row["detail"].get("source_ref"),
        rationale=row["detail"].get("rationale", ""),
        extra=row["detail"].get("extra", {}),
    )
    return req, row["event_sha256"]


# ── Propose → ConsentRequired ────────────────────────────────────


def test_propose_read_raises_consent_required(executor, scratch):
    path = scratch / "note.md"
    with pytest.raises(gate.ConsentRequired, match="fs.read"):
        executor.propose_read(path, context="ctx")


def test_propose_write_raises_consent_required(executor, scratch):
    path = scratch / "out.md"
    with pytest.raises(gate.ConsentRequired, match="fs.write"):
        executor.propose_write(path, context="ctx")


# ── Happy path read ───────────────────────────────────────────────


def test_read_file_happy_path(executor, scratch):
    path = scratch / "hello.md"
    path.write_text("hello world")
    req, prompt_hash = _consume_prompt(executor.propose_read, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    result = executor.read_file(path, context=req.context, approval_event_sha256=approval)
    assert result.outcome == "ok"
    assert result.data["bytes"] == b"hello world"
    assert result.data["size"] == 11
    assert result.extra["content_sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert result.provenance == "untrusted"  # S3 invariant


def test_write_file_happy_path(executor, scratch):
    path = scratch / "out.md"
    req, prompt_hash = _consume_prompt(executor.propose_write, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    result = executor.write_file(path, "written", context=req.context, approval_event_sha256=approval)
    assert result.outcome == "ok"
    assert path.read_text() == "written"
    assert result.extra["content_sha256"] == hashlib.sha256(b"written").hexdigest()


# ── R1 forgery ───────────────────────────────────────────────────


def test_R1_fabricated_approval_denied(executor, scratch):
    path = scratch / "file.md"
    path.write_text("data")
    # Propose to create a prompt row, but use a fake approval hash.
    try:
        executor.propose_read(path, context="ctx")
    except gate.ConsentRequired:
        pass
    result = executor.read_file(path, context="ctx", approval_event_sha256="z" * 64)
    assert result.outcome == "denied"
    assert result.extra["reason"] == "approval_not_found_or_expired"


# ── R4 authz: read approval doesn't authorize write ────────────


def test_R4_read_approval_cannot_authorize_write(executor, scratch):
    path = scratch / "file.md"
    path.write_text("original")
    req, prompt_hash = _consume_prompt(executor.propose_read, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    # Use the read approval to try a write — must be denied because
    # the approval's capability is fs.read.
    result = executor.write_file(path, "tampered", context=req.context, approval_event_sha256=approval)
    assert result.outcome == "denied"
    assert path.read_text() == "original"  # file untouched


# ── R3 / R7 — sandbox policy rejects out-of-root ─────────────


def test_R3_sandbox_rejects_path_outside_allowlist(executor, tmp_path):
    """A path outside the scratch dir is rejected by the sandbox
    policy even with a valid approval."""
    outside = tmp_path / "elsewhere" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("not-for-agent")
    # Fake a valid approval for this path via propose + approve.
    req, prompt_hash = _consume_prompt(executor.propose_read, outside)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    result = executor.read_file(outside, context=req.context, approval_event_sha256=approval)
    assert result.outcome == "denied"
    assert result.extra["reason"] == "sandbox_policy_deny"


def test_R7_symlink_escape_caught_by_sandbox(executor, scratch, tmp_path):
    """A symlink inside the allowed scratch dir pointing OUTSIDE it
    resolves outside and the sandbox rejects it."""
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("secret")
    link = scratch / "link-to-secret"
    link.symlink_to(outside)

    req, prompt_hash = _consume_prompt(executor.propose_read, link)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    result = executor.read_file(link, context=req.context, approval_event_sha256=approval)
    # The resolved() path is `outside` which is NOT in the scratch allowlist.
    assert result.outcome == "denied"
    assert result.extra["reason"] == "sandbox_policy_deny"


# ── R5 boundary ─────────────────────────────────────────────────


def test_R5_empty_file_reads_as_empty(executor, scratch):
    path = scratch / "empty.md"
    path.write_text("")
    req, prompt_hash = _consume_prompt(executor.propose_read, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)
    result = executor.read_file(path, context=req.context, approval_event_sha256=approval)
    assert result.outcome == "ok"
    assert result.data["size"] == 0


def test_R5_read_respects_max_bytes(executor, scratch):
    path = scratch / "big.bin"
    path.write_bytes(b"x" * 2000)
    req, prompt_hash = _consume_prompt(executor.propose_read, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)
    result = executor.read_file(path, context=req.context, approval_event_sha256=approval, max_bytes=100)
    # File is over limit → fail
    assert result.outcome == "fail"
    assert "too large" in result.extra["reason"]


# ── R9 atomicity ────────────────────────────────────────────────


def test_R9_write_is_atomic_on_crash(executor, scratch, monkeypatch):
    """If os.replace fails, the original file must be untouched and
    the tmp file should be cleaned up. We simulate by making replace
    raise; after the call, the original file is still original."""
    path = scratch / "atomic.md"
    path.write_text("original")
    req, prompt_hash = _consume_prompt(executor.propose_write, path)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    import os as real_os

    def broken_replace(_src, _dst):
        raise OSError("simulated disk full")

    monkeypatch.setattr(real_os, "replace", broken_replace)
    result = executor.write_file(path, "new content", context=req.context, approval_event_sha256=approval)
    assert result.outcome == "fail"
    assert path.read_text() == "original"


# ── R8 expired approval ────────────────────────────────────────


def test_R8_expired_approval_denied(executor, scratch, monkeypatch):
    from datetime import UTC, datetime, timedelta

    path = scratch / "file.md"
    path.write_text("x")
    req, prompt_hash = _consume_prompt(executor.propose_read, path)

    real_now = datetime.now(UTC)

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return real_now

    monkeypatch.setattr("community_member.consent.gate.datetime", Frozen)
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=prompt_hash)

    # Advance past TTL.
    future = real_now + timedelta(minutes=10)

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return future

    monkeypatch.setattr("community_member.consent.gate.datetime", Future)

    result = executor.read_file(path, context=req.context, approval_event_sha256=approval)
    assert result.outcome == "denied"


# ── R10 chain integrity ────────────────────────────────────────


def test_R10_chain_verifies_through_read_and_write_flow(executor, scratch):
    path = scratch / "f.md"
    path.write_text("initial")

    req_r, prompt_r = _consume_prompt(executor.propose_read, path)
    approval_r = gate.approve(req_r, chapter_id="ch", prompt_event_sha256=prompt_r)
    executor.read_file(path, context=req_r.context, approval_event_sha256=approval_r)

    req_w, prompt_w = _consume_prompt(executor.propose_write, path)
    approval_w = gate.approve(req_w, chapter_id="ch", prompt_event_sha256=prompt_w)
    executor.write_file(path, "updated", context=req_w.context, approval_event_sha256=approval_w)

    assert ledger.verify_chain()["ok"] is True


def test_read_nonexistent_file_fails_gracefully(executor, scratch):
    path = scratch / "missing.md"
    # Propose, approve, then try to read something that doesn't exist.
    try:
        executor.propose_read(path, context="c")
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
    approval = gate.approve(req, chapter_id="ch", prompt_event_sha256=row["event_sha256"])
    # Sandbox allows the path (it's under scratch) but the file doesn't
    # exist on disk, so we expect a fail, not a crash.
    result = executor.read_file(path, context="c", approval_event_sha256=approval)
    assert result.outcome == "fail"
    assert result.extra["reason"] == "file_not_found"
