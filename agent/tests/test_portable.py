"""Adversarial coverage for portable.py — the cross-device state bundle.

This module ships the agent's FULL local state — including the Ed25519
private key, the hash-chained consent ledger, learned habits, and
graduated capabilities — as one file, and restores it on another machine.
It had ZERO tests despite being the highest-risk CLI surface. These lock
down:

  * round-trip fidelity (identity, memory, consent chain, habits,
    graduations all restored) — build_bundle → restore_bundle
  * format_version rejection (a v2 bundle must not silently half-restore)
  * the api_key is never in the bundle (secret stays on the origin box)
  * restored on-disk state files are 0600
  * S10 device-binding: a restored graduation stamp minted under identity
    A is NOT inherited by identity B — B reading the same graduations.db
    with its own (fresh) stats sees "observing", because the stored row is
    keyed by device_did. (Both graduations.db and habits.db travel in the
    bundle by design, so a faithful restore of the SAME identity keeps its
    learned approvals; the boundary this pins is cross-IDENTITY inheritance,
    matching tests/graduation/test_state.py::test_S10_*.)
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from community_member import config as config_mod
from community_member import keystore, portable
from community_member.config import Config


@pytest.fixture(autouse=True)
def _reset():
    keystore.reset_for_tests()
    yield
    keystore.reset_for_tests()


def _point_config_dir(monkeypatch, path: Path) -> None:
    """Rebind the module-level CONFIG_DIR that portable + config read."""
    path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config_mod, "CONFIG_DIR", path)
    monkeypatch.setattr(portable, "CONFIG_DIR", path)
    keystore.reset_for_tests(dir_override=path)


def _seed_agent(home: Path, agent_id: str = "alice") -> Config:
    """A populated CONFIG_DIR: identity + memory + consent + habits + a
    graduated bucket, all keyed to ``agent_id``."""
    from community_member import crypto
    from community_member.consent import ledger
    from community_member.graduation import GraduationStore
    from community_member.habits import HabitModel

    kp = crypto.generate_ed25519_keypair()
    keystore.store_private_key(agent_id, kp["private_key"])

    cfg = Config()
    cfg.agent_id = agent_id
    cfg.name = "Alice"
    cfg.provider = "xai"
    cfg.api_key = "super-secret-key"
    cfg.public_key = kp["public_key"]
    cfg.private_key = kp["private_key"]
    cfg.save()

    (home / "memory.json").write_text(json.dumps([{"key": "note", "value": "remember me"}]))

    ledger.init(home / "consent.db", signing_key_b64=kp["private_key"])
    ledger.record(chapter_id=f"local:{agent_id}", action="consent.prompt", detail={"capability": "fs.read"})
    ledger.record(chapter_id=f"local:{agent_id}", action="consent.approved", detail={"capability": "fs.read"})

    ctx = hashlib.sha256(b"portable-test-ctx").hexdigest()
    habits = HabitModel(home / "habits.db")
    for _ in range(6):
        habits.observe(
            capability="fs.read",
            scope="/tmp/x",
            context_sha256=ctx,
            decision="approved",
            recorded_at="2026-07-12T00:00:00+00:00",
        )
    grad = GraduationStore(home / "graduations.db", device_did=agent_id)
    grad.record_graduation(capability="fs.read", scope="/tmp/x", context_sha256=ctx)
    return cfg


def test_round_trip_restores_full_state(tmp_path, monkeypatch):
    src, dst = tmp_path / "src", tmp_path / "dst"

    _point_config_dir(monkeypatch, src)
    cfg = _seed_agent(src)
    bundle = portable.build_bundle(cfg)

    # Fresh machine.
    _point_config_dir(monkeypatch, dst)
    restored = portable.restore_bundle(bundle)

    assert restored.agent_id == "alice"
    assert restored.public_key == cfg.public_key
    # Identity: the private key is recoverable on the new box.
    assert keystore.load_private_key("alice") == cfg.private_key
    # State files restored.
    assert json.loads((dst / "memory.json").read_text())[0]["value"] == "remember me"
    assert (dst / "consent.db").exists()
    assert (dst / "habits.db").exists()
    assert (dst / "graduations.db").exists()
    # Consent chain survived intact.
    from community_member.consent import ledger

    ledger.init(dst / "consent.db")
    verify = ledger.verify_chain()
    assert verify["ok"] is True, verify


def test_api_key_never_in_bundle(tmp_path, monkeypatch):
    _point_config_dir(monkeypatch, tmp_path / "src")
    cfg = _seed_agent(tmp_path / "src")
    bundle = portable.build_bundle(cfg)
    blob = json.dumps(bundle)
    assert "super-secret-key" not in blob
    assert "api_key" not in bundle.get("config", {})


def test_format_version_mismatch_rejected(tmp_path, monkeypatch):
    _point_config_dir(monkeypatch, tmp_path / "src")
    cfg = _seed_agent(tmp_path / "src")
    bundle = portable.build_bundle(cfg)
    bundle["format_version"] = 999

    _point_config_dir(monkeypatch, tmp_path / "dst")
    with pytest.raises(ValueError, match="format_version"):
        portable.restore_bundle(bundle)


def test_restored_state_files_are_0600(tmp_path, monkeypatch):
    _point_config_dir(monkeypatch, tmp_path / "src")
    cfg = _seed_agent(tmp_path / "src")
    bundle = portable.build_bundle(cfg)

    _point_config_dir(monkeypatch, tmp_path / "dst")
    portable.restore_bundle(bundle)
    for name in ("consent.db", "habits.db", "graduations.db", "memory.json"):
        mode = stat.S_IMODE((tmp_path / "dst" / name).stat().st_mode)
        assert mode == 0o600, f"{name} is {oct(mode)}, expected 0o600"


def test_s10_graduation_not_inherited_across_identity(tmp_path, monkeypatch):
    """A restored graduation stamp (minted under 'alice') is not inherited by a
    different identity ('mallory') reading the same restored graduations.db with
    its own fresh stats. The (device_did, …) key is the boundary — the exact
    guarantee tests/graduation/test_state.py::test_S10_* pins."""
    from community_member.graduation import GraduationStore

    _point_config_dir(monkeypatch, tmp_path / "src")
    cfg = _seed_agent(tmp_path / "src", agent_id="alice")
    bundle = portable.build_bundle(cfg)
    ctx = hashlib.sha256(b"portable-test-ctx").hexdigest()

    _point_config_dir(monkeypatch, tmp_path / "dst")
    portable.restore_bundle(bundle)
    db = tmp_path / "dst" / "graduations.db"

    # Same identity → its own stamp is honored (sanity; alice's stats travelled).
    grad_same = GraduationStore(db, device_did="alice")
    status_same = grad_same.status(
        capability="fs.read", scope="/tmp/x", context_sha256=ctx, approvals=6, posterior_mean=0.99
    )
    assert status_same.state == "graduated"

    # A different identity, reading with ITS OWN (empty) stats, does not inherit
    # alice's graduation — no stored row for device_did="mallory".
    grad_other = GraduationStore(db, device_did="mallory")
    status_other = grad_other.status(
        capability="fs.read", scope="/tmp/x", context_sha256=ctx, approvals=0, posterior_mean=0.5
    )
    assert status_other.state == "observing", status_other
