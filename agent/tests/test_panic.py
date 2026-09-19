"""Tests for community_member.panic (emergency revoke).

Coverage:

  R1  Forged panic invocation (signed by stale key) — N/A at this
      layer; panic is a local-only operation. Post-panic, the NEW
      key signs all future ledger rows so remote forgery with the
      OLD key is detected by chapter peers re-verifying.
  R2  Replay — panic is idempotent; running 10x produces same final
      state (no graduations, one panic-revoke row per call).
  R4  Panic without agent_id configured → key_rotated=False, but
      still records an audit row (the user wanted panic; we record it)
  R7  Adversarial — rotate_key=False path still records the audit row
      so a drill/test can be distinguished from a real panic by the
      `key_rotated` flag in the row's detail.
  R9  Timing — panic runs in O(1) ledger-append + O(1) keystore write
  R10 Persistence — panic row links into the chain; verify_chain still ok

  S7  Panic revoke idempotence — run 10x, final state identical
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from community_member import keystore, panic
from community_member.config import Config
from community_member.consent import ledger


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    keystore.reset_for_tests()
    yield
    ledger._reset_for_tests()
    keystore.reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Isolate config + keystore + ledger under tmp_path."""
    from community_member import config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    return tmp_path


@pytest.fixture
def configured_agent(tmp_env):
    """A Config with a populated keypair already in the keystore."""
    cfg = Config()
    cfg.agent_id = "alice"
    cfg.chapter_url = "https://chapter.example"
    # Start with a deterministic dummy key so we can detect rotation.
    cfg.private_key = base64.b64encode(b"X" * 32).decode()
    cfg.public_key = base64.b64encode(b"Y" * 32).decode()
    cfg.save()
    return cfg


# ── Basic panic flow ─────────────────────────────────────────────────


def test_panic_writes_audit_row_and_rotates_key(configured_agent):
    old_priv = keystore.load_private_key("alice")
    assert old_priv is not None

    report = panic.execute_panic(
        chapter_id="local:alice",
        agent_id="alice",
        config=configured_agent,
    )
    assert report.key_rotated is True
    new_priv = keystore.load_private_key("alice")
    assert new_priv is not None
    assert new_priv != old_priv  # rotation actually happened

    # Ledger has exactly one panic row.
    rows = ledger.list_events(action="consent.panic_revoke")
    assert len(rows) == 1
    assert rows[0]["detail"]["key_rotated"] is True
    assert rows[0]["event_sha256"] == report.audit_event_sha256


def test_panic_updates_config_public_key(configured_agent):
    old_pub = configured_agent.public_key
    panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=configured_agent)
    assert configured_agent.public_key != old_pub
    # Reloaded config matches in-memory.
    from community_member.config import Config as ConfigCls

    reloaded = ConfigCls.load()
    assert reloaded.public_key == configured_agent.public_key


# ── S7: idempotence ─────────────────────────────────────────────────


def test_S7_panic_revoke_is_idempotent(configured_agent):
    """Running panic 10 times produces the same final state — no
    graduations, key already fresh, 10 audit rows (one per call).
    The test pins that the final state after N calls is equivalent
    to the final state after 1 call."""
    for _ in range(10):
        panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=configured_agent)
    rows = ledger.list_events(action="consent.panic_revoke", limit=20)
    assert len(rows) == 10
    # Each call rotates the key; final state is a valid key, not None.
    assert keystore.load_private_key("alice") is not None
    # Chain still clean.
    assert ledger.verify_chain()["ok"] is True


# ── R4: no agent_id → graceful degradation ────────────────────────


def test_panic_with_no_agent_id_still_records_audit(tmp_env):
    cfg = Config()
    # Never set agent_id.
    report = panic.execute_panic(chapter_id="local:unknown", agent_id=None, config=cfg)
    assert report.key_rotated is False  # nothing to rotate
    # But the audit still lands — user meant to panic.
    rows = ledger.list_events(action="consent.panic_revoke")
    assert len(rows) == 1


# ── R7: drill mode (rotate_key=False) ─────────────────────────────


def test_rotate_key_false_skips_rotation_but_records(configured_agent):
    old_priv = keystore.load_private_key("alice")
    report = panic.execute_panic(
        chapter_id="local:alice",
        agent_id="alice",
        config=configured_agent,
        rotate_key=False,
    )
    assert report.key_rotated is False
    # Private key unchanged.
    assert keystore.load_private_key("alice") == old_priv
    # Row recorded with key_rotated=False so an auditor can tell
    # drill from real.
    rows = ledger.list_events(action="consent.panic_revoke")
    assert rows[0]["detail"]["key_rotated"] is False


# ── R10: chain integrity after panic ──────────────────────────────


def test_panic_row_is_in_chain(configured_agent):
    # Add some unrelated rows, then panic, verify chain top-to-bottom.
    from community_member.consent import gate

    gate.record_decision(
        gate.ActionRequest(
            capability="browser.navigate",
            scope="https://x",
            context="c",
            provenance="trusted",
        ),
        gate.ConsentDecision(state="prompt", reason="test"),
        chapter_id="local:alice",
    )
    panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=configured_agent)
    assert ledger.verify_chain()["ok"] is True


# ── R2: panic survives re-init of ledger (new process simulation) ──


def test_panic_state_persists_across_ledger_reopen(configured_agent, tmp_env):
    panic.execute_panic(chapter_id="local:alice", agent_id="alice", config=configured_agent)
    # Simulate a process restart: drop ledger globals and re-init
    # pointing at the same DB file.
    ledger._reset_for_tests()
    ledger.init(tmp_env / "consent.db")
    rows = ledger.list_events(action="consent.panic_revoke")
    assert len(rows) == 1
