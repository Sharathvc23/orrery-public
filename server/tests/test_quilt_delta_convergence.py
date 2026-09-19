"""That change regression: /sm-bridge/deltas survives a restart.

The quilt reality audit found the in-memory DeltaStore loses all
state on restart — a delta-only consumer saw an EMPTY feed even though /index
had members (never converged), and next_seq regressed (5→1), so a consumer
whose cursor was ahead silently skipped every post-restart registration.
seed_delta_store re-delivers the persisted membership above a monotonic base
seq. These tests exercise that directly, simulating restarts by re-mounting a
fresh store against the same members dict.

Classification: HAPPY / ADVERSARIAL (convergence + monotonicity).
"""

import pytest

import sm_bridge_adapter as smb

# The feed carries the members the index would — those who opted into the
# listing. These tests are about convergence and cursors, so every member here
# is eligible; admission is asserted in test_quilt_delta_wiring.py.
LISTED = {"listed": True, "agent_url": "https://quilt.example"}


@pytest.fixture
def members():
    return {
        "quilt-agent": {"name": "Quilt Agent", "skills": ["x"], "listing": LISTED},
        "q-alpha": {"name": "Q alpha", "skills": ["y"], "listing": LISTED},
        "q-bravo": {"name": "Q bravo", "listing": LISTED},
    }


def _fresh_mount(members):
    """Simulate a process (re)start: a brand-new in-memory DeltaStore bound to
    the same converter/members, exactly as mount_sm_bridge_routers does."""
    from sm_bridge import DeltaStore

    converter = smb.make_chapter_converter(
        agent_id="quilt-org", agent_name="Quilt Org", public_url="http://quilt.test", members=members
    )
    smb._mounted_delta_store = DeltaStore()
    smb._mounted_converter = converter
    return smb._mounted_delta_store


def test_delta_only_consumer_converges_after_restart(members):
    """HAPPY: a fresh consumer at since=0 sees the full membership from
    the feed alone — no need to also pull /index."""
    store = _fresh_mount(members)
    smb.seed_delta_store(members, base_seq=1000)
    delivered = store.since(0)
    ids = {d.agent.id.rsplit(":", 1)[-1] for d in delivered}
    assert ids == set(members), f"delta feed did not converge to the membership: {ids}"


def test_next_seq_is_monotonic_across_restart(members):
    """ADVERSARIAL: a later boot's base always exceeds the prior boot's
    highest seq, so a consumer's cursor can never end up ahead of the server."""
    store1 = _fresh_mount(members)
    smb.seed_delta_store(members, base_seq=1000)
    high1 = store1.next_seq  # a consumer that caught up holds cursor = high1 - 1

    store2 = _fresh_mount(members)  # restart
    smb.seed_delta_store(members, base_seq=2000)  # a later wall-clock base
    assert store2.next_seq > high1, "seq regressed across restart — cursors would go stale"

    # a consumer with the pre-restart cursor still converges (re-delivered)
    reconverged = store2.since(high1 - 1)
    ids = {d.agent.id.rsplit(":", 1)[-1] for d in reconverged}
    assert ids == set(members)


def test_post_restart_registration_is_delivered_above_a_stale_cursor(members):
    """ADVERSARIAL: the exact silent-loss case — a member registered
    after the restart must land ABOVE a cursor left over from before it."""
    store1 = _fresh_mount(members)
    smb.seed_delta_store(members, base_seq=1000)
    stale_cursor = store1.next_seq - 1

    store2 = _fresh_mount(members)  # restart with a higher base
    smb.seed_delta_store(members, base_seq=5000)
    smb.record_member_delta("upsert", "q-new", {"name": "Q new", "listing": LISTED})

    seen = {d.agent.id.rsplit(":", 1)[-1] for d in store2.since(stale_cursor)}
    assert "q-new" in seen, "a post-restart registration was skipped past a stale cursor"


def test_seed_is_idempotent_noop_without_mount(monkeypatch):
    """EDGE: seeding before/without a mount is a quiet no-op, never a crash."""
    monkeypatch.setattr(smb, "_mounted_delta_store", None)
    monkeypatch.setattr(smb, "_mounted_converter", None)
    assert smb.seed_delta_store({"a": {"name": "A"}}, base_seq=1) == 0


def test_base_seq_never_lowers_an_already_higher_counter(members):
    """EDGE: seed_delta_store clamps to max(base, current) — a base below the
    live counter (clock skew) can't rewind an in-flight store."""
    store = _fresh_mount(members)
    smb.record_member_delta("upsert", "live", {"name": "Live"})  # counter now 1
    smb.seed_delta_store(members, base_seq=0)  # a backwards base
    assert store.next_seq > 1
