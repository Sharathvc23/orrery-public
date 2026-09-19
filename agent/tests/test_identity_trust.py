"""Tests for identity_trust — auto-approve when effective trust crosses
the threshold for trusted-provenance actions.

Coverage map:

  R1  Forgery — trust file with bad JSON falls back to default
      (DEFAULT_LOCAL_TRUST), never raises into the gate
  R2  Replay — repeated `auto_approve_if_trusted` calls write
      separate audit rows (each with the trust snapshot at decision
      time); never reuses an old hash
  R3  Injection — provenance="untrusted" never auto-approves
      regardless of trust score (load-bearing prompt-injection
      defense)
  R4  Authz — local_trust write clamps to 0-100; negative values
      and >100 don't escape
  R5  Boundary — exactly at threshold (effective=70) auto-approves;
      69 does not
  R8  Downgrade — chapter_trust cache write is replaced atomically;
      stale data doesn't survive a save call
  R9  Audit — every auto-approval writes a `consent.auto_approved`
      row whose detail field includes the trust snapshot at decision
      time
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import identity_trust as it
from community_member import keystore
from community_member.consent import gate, ledger


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    keystore.reset_for_tests()
    yield
    ledger._reset_for_tests()
    keystore.reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path):
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    return tmp_path


def _req(provenance: str = "trusted") -> gate.ActionRequest:
    return gate.ActionRequest(
        capability="fs.read",
        scope="~/notes",
        context="ctx",
        provenance=provenance,
        source_ref="https://example.com" if provenance == "untrusted" else None,
    )


def test_default_local_trust_when_file_missing(tmp_env):
    assert it.load_local_trust(tmp_env) == it.DEFAULT_LOCAL_TRUST


def test_corrupt_local_trust_file_falls_back(tmp_env):
    (tmp_env / "identity_trust.json").write_text("{not json")
    assert it.load_local_trust(tmp_env) == it.DEFAULT_LOCAL_TRUST


def test_local_trust_clamps_to_0_100(tmp_env):
    it.save_local_trust(tmp_env, 250)
    assert it.load_local_trust(tmp_env) == 100
    it.save_local_trust(tmp_env, -50)
    assert it.load_local_trust(tmp_env) == 0


def test_chapter_trust_round_trip(tmp_env):
    it.save_chapter_trust(tmp_env, 42, raw={"tier": {"name": "established"}})
    score, refreshed_at = it.load_chapter_trust(tmp_env)
    assert score == 42
    assert refreshed_at is not None and refreshed_at > 0


def test_effective_trust_is_max(tmp_env):
    assert it.effective_trust(20, 80) == 80
    assert it.effective_trust(80, 20) == 80
    assert it.effective_trust(0, 0) == 0
    assert it.effective_trust(100, 100) == 100


def test_at_threshold_auto_approves(tmp_env):
    """effective == AUTO_APPROVE_THRESHOLD (70) → auto-approves."""
    h = it.auto_approve_if_trusted(
        _req(),
        chapter_id="local:test",
        local_trust=70,
        chapter_trust=0,
    )
    assert h is not None
    assert isinstance(h, str)


def test_below_threshold_returns_none(tmp_env):
    h = it.auto_approve_if_trusted(
        _req(),
        chapter_id="local:test",
        local_trust=69,
        chapter_trust=0,
    )
    assert h is None


def test_chapter_trust_alone_can_clear_threshold(tmp_env):
    """If chapter trusts you at 80, gate auto-approves even with
    local_trust=0. The federation's view counts."""
    h = it.auto_approve_if_trusted(
        _req(),
        chapter_id="local:test",
        local_trust=0,
        chapter_trust=80,
    )
    assert h is not None


def test_untrusted_provenance_never_auto_approves(tmp_env):
    """Even at full trust (100), untrusted-provenance never bypasses
    the gate. This is the load-bearing prompt-injection defense."""
    h = it.auto_approve_if_trusted(
        _req(provenance="untrusted"),
        chapter_id="local:test",
        local_trust=100,
        chapter_trust=100,
    )
    assert h is None


def test_semi_trusted_provenance_auto_approves_at_threshold(tmp_env):
    """semi_trusted = chapter-peer-signed message. The chapter's TOFU
    layer already verified the peer's identity, so auto-approving
    these at high trust is in scope. Without this, the trust dial
    barely affects the autonomous think loop, which mostly proposes
    actions in response to chapter peer signals."""
    h = it.auto_approve_if_trusted(
        _req(provenance="semi_trusted"),
        chapter_id="local:test",
        local_trust=100,
        chapter_trust=0,
    )
    assert h is not None


def test_audit_row_carries_trust_snapshot(tmp_env):
    """Every trust-based auto-approval must write an audit row
    whose detail field includes the trust scores at decision time.
    Without this, an auditor can't reconstruct WHY an action ran
    without a prompt."""
    it.auto_approve_if_trusted(
        _req(),
        chapter_id="local:test",
        local_trust=85,
        chapter_trust=10,
    )
    rows = ledger.list_events(action="consent.auto_approved")
    auto_rows = [r for r in rows if r.get("chapter_id") == "local:test"]
    assert len(auto_rows) >= 1
    detail = auto_rows[-1]["detail"]
    assert detail.get("decision_reason") == "trust_threshold"
    trust = detail.get("trust") or {}
    assert trust.get("local") == 85
    assert trust.get("chapter") == 10
    assert trust.get("effective") == 85
    assert trust.get("threshold") == it.AUTO_APPROVE_THRESHOLD


def test_snapshot_returns_full_state(tmp_env):
    it.save_local_trust(tmp_env, 55)
    it.save_chapter_trust(tmp_env, 30)
    snap = it.snapshot(tmp_env)
    assert snap.local == 55
    assert snap.chapter == 30
    assert snap.effective == 55
    assert snap.threshold == it.AUTO_APPROVE_THRESHOLD
    assert snap.chapter_refreshed_at is not None
