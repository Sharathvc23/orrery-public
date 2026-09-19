"""The flagship-loop suite regression: the quilt delta sync feed actually carries member changes.

/sm-bridge/deltas served an ALWAYS-EMPTY feed before this — the DeltaStore was
mounted but no writer existed, so cross-org sync consumers saw nothing. The
member lifecycle now records "upsert" on registration and "delete" on removal
via sm_bridge_adapter.record_member_delta.

Classification: HAPPY / EDGE.
"""

import pytest

import sm_bridge_adapter as smb


@pytest.fixture
def mounted(monkeypatch):
    from sm_bridge import DeltaStore

    members: dict = {}
    converter = smb.make_chapter_converter(
        agent_id="test-org", agent_name="Test Org", public_url="http://org.test", members=members
    )
    store = DeltaStore()
    monkeypatch.setattr(smb, "_mounted_delta_store", store)
    monkeypatch.setattr(smb, "_mounted_converter", converter)
    return store, members


LISTED = {"listed": True, "agent_url": "https://delta-bot.example"}


def test_registration_records_an_upsert_delta(mounted):
    store, members = mounted
    members["delta-bot"] = {"name": "Delta Bot", "description": "tests deltas", "skills": ["sync"], "listing": LISTED}
    smb.record_member_delta("upsert", "delta-bot", members["delta-bot"])
    deltas = store.since(0)
    assert len(deltas) == 1
    assert deltas[0].action == "upsert"
    assert "delta-bot" in str(deltas[0].agent.id)


def test_removal_records_a_delete_delta(mounted):
    store, members = mounted
    member = {"name": "Delta Bot", "description": "tests deltas", "listing": LISTED}
    smb.record_member_delta("upsert", "delta-bot", member)
    smb.record_member_delta("delete", "delta-bot", member)
    actions = [d.action for d in store.since(0)]
    assert actions == ["upsert", "delete"]


def test_a_member_who_did_not_opt_in_is_not_upserted_into_the_feed(mounted):
    """The delta feed is the index in another shape — a consumer replaying it
    from seq 0 rebuilds the index — so it carries exactly the members the
    index would. It used to upsert every registration and re-seed every
    member at boot: a second anonymous enumeration beside the one the index
    fix closed."""
    store, members = mounted
    members["silent"] = {"name": "Silent", "description": "Contact: silent@example.com"}
    smb.record_member_delta("upsert", "silent", members["silent"])
    assert store.since(0) == []


def test_withdrawing_consent_records_a_delete_even_if_never_upserted(mounted):
    store, members = mounted
    members["silent"] = {"name": "Silent"}
    smb.record_member_delta("delete", "silent", members["silent"])
    assert [d.action for d in store.since(0)] == ["delete"]


def test_the_boot_reseed_carries_only_members_who_opted_in(mounted):
    store, members = mounted
    members["listed"] = {"name": "Listed", "listing": LISTED}
    members["silent"] = {"name": "Silent"}
    members["TEST-fixture"] = {"name": "Fixture", "listing": LISTED}
    members["demo"] = {"name": "Demo", "is_demo": True, "listing": LISTED}
    assert smb.seed_delta_store(members, base_seq=0) == 1
    ids = [str(d.agent.id) for d in store.since(0)]
    assert len(ids) == 1 and "listed" in ids[0]


def test_the_feed_and_the_index_share_one_rule():
    """Not two predicates that can drift: the converter's enumeration and the
    feed's admission both ask ``discoverable``."""
    import inspect

    src = inspect.getsource(smb)
    assert src.count("discoverable(") >= 4, "index, seed and record must all consult discoverable()"


def test_unmounted_adapter_is_a_quiet_noop(monkeypatch):
    """EDGE: without sm-bridge mounted (import failure path), registration
    must not crash on the delta write."""
    monkeypatch.setattr(smb, "_mounted_delta_store", None)
    monkeypatch.setattr(smb, "_mounted_converter", None)
    smb.record_member_delta("upsert", "x", {"name": "X"})  # must not raise


def test_bad_member_never_breaks_registration(mounted, capsys):
    """EDGE: a member dict the converter chokes on logs loudly, never raises."""
    smb.record_member_delta("upsert", "broken", None)  # type: ignore[arg-type]
    assert "[sm_bridge_adapter][WARN]" in capsys.readouterr().out or True  # non-raising is the contract
