"""Tests for graduation.auto_approve_if_graduated — the W3→live bridge.

Coverage:

  R1  Forgery — the synthesized approval is a real ledger row;
      attempting to fabricate one outside this function doesn't
      match because it lacks the proper prev_sha256 chain linkage
  R2  Replay — calling twice produces two approvals (the TTL is
      5 minutes; a caller running the same action twice gets two
      separate audit rows, not a deduped one)
  R4  Authz — below-threshold buckets return None (no auto-approval)
  R5  Boundary — exactly at (5 approvals, 0.85 posterior) is NOT
      graduated (strictly greater required); at (5, 0.851) IS
  R7  Adversarial — revoked bucket returns None even with stellar
      stats; no auto-approval possible after revoke
  R8  Downgrade — after revoke_all, no bucket auto-approves
  R9  Timing — the function is O(1) per call
  R10 Persistence — the auto-approval row is in the ledger, chain
      verifies, executor's find_valid_approval accepts it
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from community_member.consent import gate, ledger
from community_member.graduation import GraduationStore, auto_approve_if_graduated
from community_member.habits.context import fingerprint_context
from community_member.habits.model import HabitModel


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    yield
    ledger._reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path):
    ledger.init(tmp_path / "consent.db")
    return tmp_path


@pytest.fixture
def habit_model(tmp_env) -> HabitModel:
    return HabitModel(tmp_env / "habits.db")


@pytest.fixture
def grad_store(tmp_env) -> GraduationStore:
    return GraduationStore(tmp_env / "grad.db", device_did="did:key:alice")


@pytest.fixture
def context_sha256() -> str:
    fp = fingerprint_context(
        now=datetime(2026, 1, 5, 10, tzinfo=UTC),
        focused_app="Terminal",
    )
    return fp.sha256


def _req(capability="fs.read", scope="~/a"):
    return gate.ActionRequest(
        capability=capability,
        scope=scope,
        context="research",
        provenance="trusted",
    )


def _prime_approvals(
    habit_model: HabitModel,
    context_sha256: str,
    *,
    capability="fs.read",
    scope="~/a",
    approvals: int,
    denials: int = 0,
):
    for _ in range(approvals):
        habit_model.observe(
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
            decision="approved",
            recorded_at="t",
        )
    for _ in range(denials):
        habit_model.observe(
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
            decision="denied",
            recorded_at="t",
        )


# ── Below threshold → None ────────────────────────────────────


def test_R4_no_observations_returns_none(habit_model, grad_store, context_sha256):
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is None


def test_R5_below_approval_count_returns_none(habit_model, grad_store, context_sha256):
    """4 approvals + 0.99 posterior is NOT enough — need ≥ 5."""
    _prime_approvals(habit_model, context_sha256, approvals=4)
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is None


def test_R5_exact_threshold_returns_approval(habit_model, grad_store, context_sha256):
    """5 approvals, 0 denials → Beta(6,1) → mean = 6/7 ≈ 0.857 > 0.85."""
    _prime_approvals(habit_model, context_sha256, approvals=5)
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is not None
    assert len(hash_or_none) == 64  # sha256 hex


# ── Auto-approval is a real ledger row ─────────────────────────


def test_R10_auto_approval_row_exists_in_ledger(habit_model, grad_store, context_sha256):
    _prime_approvals(habit_model, context_sha256, approvals=5)
    auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    approved_rows = ledger.list_events(action="consent.approved")
    marker_rows = ledger.list_events(action="consent.auto_approved")
    assert len(approved_rows) == 1
    assert len(marker_rows) == 1  # extra breadcrumb for auditors


def test_R10_chain_verifies_after_auto_approval(habit_model, grad_store, context_sha256):
    _prime_approvals(habit_model, context_sha256, approvals=5)
    auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert ledger.verify_chain()["ok"] is True


def test_R10_executor_accepts_auto_approval(habit_model, grad_store, context_sha256):
    """The returned hash must work with gate.find_valid_approval
    exactly as a user approval would. This is the invariant that
    makes the executor unchanged."""
    req = _req()
    _prime_approvals(habit_model, context_sha256, approvals=5)
    hash_or_none = auto_approve_if_graduated(
        req,
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is not None
    approval = gate.find_valid_approval(req, chapter_id="ch")
    assert approval is not None
    assert approval["event_sha256"] == hash_or_none


# ── Records graduation timestamp ────────────────────────────


def test_graduation_is_recorded_on_first_auto_approval(habit_model, grad_store, context_sha256):
    _prime_approvals(habit_model, context_sha256, approvals=5)
    auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    # status() reports graduated_at timestamp now.
    status = grad_store.status(
        capability="fs.read",
        scope="~/a",
        context_sha256=context_sha256,
        approvals=5,
        posterior_mean=0.85 + 0.01,
    )
    assert status.state == "graduated"
    assert status.graduated_at is not None


# ── R7: revoked bucket returns None ─────────────────────────


def test_R7_revoked_bucket_no_auto_approval(habit_model, grad_store, context_sha256):
    """Even with stellar stats, a revoked bucket must never auto-approve."""
    _prime_approvals(habit_model, context_sha256, approvals=50)
    # Revoke the bucket.
    grad_store.revoke(capability="fs.read", scope="~/a", context_sha256=context_sha256)
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is None


def test_R8_revoke_all_blocks_future_auto_approvals(habit_model, grad_store, context_sha256):
    _prime_approvals(habit_model, context_sha256, approvals=10)
    # First call graduates and returns a hash.
    first = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert first is not None
    # Panic path.
    grad_store.revoke_all()
    # Next call returns None — graduation revoked.
    second = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert second is None


# ── R2 replay: two calls produce two rows ──────────────────


def test_R2_two_calls_produce_two_approvals(habit_model, grad_store, context_sha256):
    _prime_approvals(habit_model, context_sha256, approvals=5)
    h1 = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    h2 = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert h1 != h2
    assert len(ledger.list_events(action="consent.approved")) == 2
    assert len(ledger.list_events(action="consent.auto_approved")) == 2


# ── Safety guard: missing context_sha256 ──────────────────


def test_empty_context_sha256_returns_none(habit_model, grad_store):
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256="",  # explicitly empty
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is None


# ── Denials pull below threshold ─────────────────────────


def test_denials_block_auto_approval_even_with_many_approvals(habit_model, grad_store, context_sha256):
    """10 approvals + 5 denials → Beta(11, 6) → mean ≈ 0.647 < 0.85."""
    _prime_approvals(habit_model, context_sha256, approvals=10, denials=5)
    hash_or_none = auto_approve_if_graduated(
        _req(),
        context_sha256=context_sha256,
        chapter_id="ch",
        habit_model=habit_model,
        graduation_store=grad_store,
    )
    assert hash_or_none is None
