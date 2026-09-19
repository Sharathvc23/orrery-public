"""Prosecution-grade tests for community_member.keystore.

Coverage map to the v2 threat model (S4 key-at-rest):

  R1 forgery      — tampering the encrypted vault → decrypt fails loud
  R2 replay       — storing the same key twice is idempotent (last write wins)
  R3 injection    — agent_id containing path-like characters is safe; the
                    keystore never interprets it as a path
  R4 authz        — empty agent_id / empty key rejected
  R5 boundary     — first-ever store creates the vault; deleting the last
                    entry removes the vault file cleanly
  R6 concurrency  — tested via ledger's threading.Lock pattern (keystore is
                    a last-writer-wins vault, concurrent writes may lose
                    entries; documented behavior, not a bug here)
  R7 adversarial  — vault copied to a "different machine" (fingerprint
                    changed) cannot be decrypted
  R8 downgrade    — migrating a plaintext key → keystore has the key, and
                    re-migrating is a no-op (does not overwrite)
  R9 timing       — current_backend() is memoized; _device_fingerprint()
                    is deterministic for a given host
  R10 persistence — store → new-process → load round-trips

  S4 key at rest  — config.json never contains the plaintext key after
                    load/save; the key survives only in the keystore
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from community_member import keystore


@pytest.fixture
def tmp_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect the keystore to a temp dir + pin the device backend.

    Pinning ``COMMUNITY_MEMBER_KEYSTORE=device`` makes the test
    deterministic regardless of whether the host has a usable OS
    keyring or an interactive tty (which would otherwise trigger the
    passphrase backend's getpass prompt). The keyring path is probed
    in ``test_keyring_backend_probe`` and the passphrase path in
    ``test_passphrase_backend_*``.
    """
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    keystore.reset_for_tests(dir_override=tmp_path)
    with patch.object(keystore, "_probe_keyring", return_value=False):
        yield tmp_path
    keystore.reset_for_tests()


# ── R10: round-trip ─────────────────────────────────────────────────


def test_R10_store_load_roundtrip(tmp_keystore):
    keystore.store_private_key("alice", "key-alice-b64")
    assert keystore.load_private_key("alice") == "key-alice-b64"


def test_R10_load_missing_returns_none(tmp_keystore):
    assert keystore.load_private_key("nobody") is None


def test_R10_has_private_key_matches_presence(tmp_keystore):
    assert keystore.has_private_key("alice") is False
    keystore.store_private_key("alice", "k")
    assert keystore.has_private_key("alice") is True


# ── R2: idempotence ─────────────────────────────────────────────────


def test_R2_store_twice_last_write_wins(tmp_keystore):
    keystore.store_private_key("alice", "v1")
    keystore.store_private_key("alice", "v2")
    assert keystore.load_private_key("alice") == "v2"


# ── R4: validation ──────────────────────────────────────────────────


def test_R4_empty_agent_id_rejected(tmp_keystore):
    with pytest.raises(ValueError, match="agent_id"):
        keystore.store_private_key("", "key")


def test_R4_empty_key_rejected(tmp_keystore):
    with pytest.raises(ValueError, match="private_key_b64"):
        keystore.store_private_key("alice", "")


def test_R4_load_empty_agent_id_returns_none(tmp_keystore):
    assert keystore.load_private_key("") is None


# ── R5: vault lifecycle ─────────────────────────────────────────────


def test_R5_first_store_creates_vault_file(tmp_keystore):
    assert not (tmp_keystore / "keystore.enc").exists()
    keystore.store_private_key("alice", "k")
    assert (tmp_keystore / "keystore.enc").exists()


def test_R5_delete_last_entry_removes_vault_file(tmp_keystore):
    keystore.store_private_key("alice", "k")
    assert (tmp_keystore / "keystore.enc").exists()
    keystore.delete_private_key("alice")
    assert not (tmp_keystore / "keystore.enc").exists()


def test_R5_delete_one_of_two_keeps_vault(tmp_keystore):
    keystore.store_private_key("alice", "k1")
    keystore.store_private_key("bob", "k2")
    keystore.delete_private_key("alice")
    assert (tmp_keystore / "keystore.enc").exists()
    assert keystore.load_private_key("bob") == "k2"
    assert keystore.load_private_key("alice") is None


def test_R5_delete_missing_is_safe(tmp_keystore):
    # No raise, no side effects.
    keystore.delete_private_key("nobody")


# ── R3: agent_id with path-like characters ──────────────────────────


def test_R3_agent_id_with_slashes_is_safe(tmp_keystore):
    """The keystore keys into a dict by agent_id string — there is no
    path-like interpretation. A malicious agent_id like '../etc/passwd'
    cannot traverse the filesystem."""
    keystore.store_private_key("../etc/passwd", "k")
    assert keystore.load_private_key("../etc/passwd") == "k"
    # Only the vault file was written; no traversal happened.
    created = list(tmp_keystore.iterdir())
    assert all(p.name in {"keystore.enc", "keystore.meta.json"} for p in created)


# ── R7: device-fingerprint binding ──────────────────────────────────


def test_R7_fingerprint_change_breaks_decryption(tmp_keystore):
    """A vault encrypted under fingerprint F1 cannot be read under F2.
    This is the rsync/backup leakage defense. We simulate by patching
    _device_fingerprint to return a different string."""
    keystore.store_private_key("alice", "secret-key")
    # Simulate copying the vault to a different host.
    with patch.object(keystore, "_device_fingerprint", return_value="other-host"), pytest.raises(ValueError):
        keystore.load_private_key("alice")


def test_R9_device_fingerprint_deterministic():
    f1 = keystore._device_fingerprint()
    f2 = keystore._device_fingerprint()
    assert f1 == f2
    assert len(f1) > 0


# ── R1: vault tamper detection ─────────────────────────────────────


def test_R1_vault_ciphertext_tamper_rejected(tmp_keystore):
    keystore.store_private_key("alice", "real-key")
    vault_path = tmp_keystore / "keystore.enc"
    payload = json.loads(vault_path.read_text())
    # Flip a byte in the ciphertext. crypto.decrypt_value verifies an
    # HMAC tag, so tampering raises.
    import base64

    ct = bytearray(base64.b64decode(payload["ciphertext"]))
    ct[0] ^= 0xFF
    payload["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    vault_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        keystore.load_private_key("alice")


# ── R8: migration from plaintext ───────────────────────────────────


def test_R8_migrate_plaintext_first_time(tmp_keystore):
    assert keystore.migrate_plaintext_key("alice", "old-key") is True
    assert keystore.load_private_key("alice") == "old-key"


def test_R8_migrate_is_idempotent(tmp_keystore):
    keystore.store_private_key("alice", "current")
    # Re-migrating does NOT overwrite existing key.
    assert keystore.migrate_plaintext_key("alice", "old-from-disk") is False
    assert keystore.load_private_key("alice") == "current"


# ── R9: backend memoization ────────────────────────────────────────


def test_R9_backend_is_memoized(tmp_keystore):
    """The backend probe is cached for the process lifetime so probe
    failures don't cause mid-run inconsistency."""
    assert keystore.current_backend() == "device"
    # Probe is not re-run; cached value returned.
    with patch.object(keystore, "_probe_keyring", return_value=True):
        # Still encrypted_file because memoized.
        assert keystore.current_backend() == "device"


# ── meta file observability ─────────────────────────────────────────


def test_meta_file_records_backend(tmp_keystore):
    keystore.store_private_key("alice", "k")
    meta = json.loads((tmp_keystore / "keystore.meta.json").read_text())
    assert meta["current_backend"] == "device"
    assert meta["agents"]["alice"]["backend"] == "device"


def test_meta_file_survives_multiple_agents(tmp_keystore):
    keystore.store_private_key("alice", "k1")
    keystore.store_private_key("bob", "k2")
    meta = json.loads((tmp_keystore / "keystore.meta.json").read_text())
    assert "alice" in meta["agents"]
    assert "bob" in meta["agents"]


# ── S4: plaintext never persists across load/save round-trip ──────


def test_S4_config_save_never_writes_plaintext_key(tmp_keystore, monkeypatch):
    """After save(), config.json must not contain the plaintext key.
    This is the canonical S4 test — the key lives only in the keystore."""
    from community_member import config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_keystore)

    cfg = config.Config()
    cfg.agent_id = "alice"
    cfg.chapter_url = "https://chapter.example"
    cfg.private_key = "SECRET-KEY-B64"
    cfg.public_key = "PUB"
    cfg.save()

    # The on-disk config.json has an empty `private_key` field.
    on_disk = json.loads((tmp_keystore / "config.json").read_text())
    assert on_disk["private_key"] == ""
    # And the keystore actually has it.
    assert keystore.load_private_key("alice") == "SECRET-KEY-B64"


def test_S4_config_load_migrates_legacy_plaintext(tmp_keystore, monkeypatch):
    """A pre-keystore config.json with a plaintext private_key is
    migrated on first load — and the plaintext is cleared from the
    file before any other code can read it."""
    from community_member import config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_keystore)

    # Simulate a legacy config on disk.
    (tmp_keystore / "config.json").write_text(
        json.dumps(
            {
                "agent_id": "alice",
                "chapter_url": "https://chapter.example",
                "provider": "xai",
                "private_key": "LEGACY-PLAINTEXT",
                "public_key": "PUB",
            }
        )
    )

    cfg = config.Config.load()
    assert cfg.private_key == "LEGACY-PLAINTEXT"  # in memory, from keystore
    # Config.json plaintext is GONE.
    on_disk = json.loads((tmp_keystore / "config.json").read_text())
    assert on_disk["private_key"] == ""
    # Keystore has it.
    assert keystore.load_private_key("alice") == "LEGACY-PLAINTEXT"


def test_S4_config_load_prefers_keystore_over_config_plaintext(tmp_keystore, monkeypatch):
    """If both a keystore entry AND a plaintext config.json value
    exist (pathological state after a partial migration), the
    keystore wins — never trust a plaintext value we already migrated."""
    from community_member import config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_keystore)

    keystore.store_private_key("alice", "KEYSTORE-WINS")
    (tmp_keystore / "config.json").write_text(
        json.dumps(
            {
                "agent_id": "alice",
                "chapter_url": "https://chapter.example",
                "private_key": "STALE-PLAINTEXT",
                "public_key": "PUB",
            }
        )
    )

    cfg = config.Config.load()
    assert cfg.private_key == "KEYSTORE-WINS"


# ── BACKEND_PASSPHRASE — Tier 1 user-passphrase backend ─────────────


@pytest.fixture
def tmp_passphrase_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Pin BACKEND_PASSPHRASE and seed the cache so getpass is never invoked.

    Seeding via ``set_passphrase_for_tests`` is the test entry point that
    bypasses the interactive prompt. Production code MUST NOT call this.
    """
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    keystore.reset_for_tests(dir_override=tmp_path)
    with patch.object(keystore, "_probe_keyring", return_value=False):
        keystore.set_passphrase_for_tests("test-passphrase-12345")
        yield tmp_path
    keystore.reset_for_tests()


def test_passphrase_backend_round_trip(tmp_passphrase_keystore):
    """HAPPY: store + load under BACKEND_PASSPHRASE preserves the key."""
    backend = keystore.store_private_key("alice", "ed25519-key-bytes-b64")
    assert backend == keystore.BACKEND_PASSPHRASE
    assert keystore.load_private_key("alice") == "ed25519-key-bytes-b64"


def test_passphrase_backend_writes_encrypted_vault(tmp_passphrase_keystore):
    """ADVERSARIAL: vault file does not contain the key in plaintext."""
    keystore.store_private_key("alice", "PLAIN-MARKER-XYZ")
    vault_text = (tmp_passphrase_keystore / "keystore.enc").read_text()
    assert "PLAIN-MARKER-XYZ" not in vault_text
    assert "ciphertext" in vault_text  # AES/HMAC blob shape


def test_passphrase_backend_isolates_per_keystore_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Two keystores (different KEYSTORE_DIR) cache passphrases independently."""
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")

    with patch.object(keystore, "_probe_keyring", return_value=False):
        keystore.reset_for_tests(dir_override=dir_a)
        keystore.set_passphrase_for_tests("passphrase-A")
        keystore.store_private_key("alice", "key-A")

        keystore.reset_for_tests(dir_override=dir_b)
        keystore.set_passphrase_for_tests("passphrase-B")
        keystore.store_private_key("alice", "key-B")
        assert keystore.load_private_key("alice") == "key-B"

        keystore.reset_for_tests(dir_override=dir_a)
        keystore.set_passphrase_for_tests("passphrase-A")
        # The same keystore name in dir_a must still hold the original key —
        # cross-keystore bleed would mean two agents on one box could
        # accidentally use each other's vaults.
        assert keystore.load_private_key("alice") == "key-A"

    keystore.reset_for_tests()


def test_passphrase_backend_wrong_passphrase_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """ADVERSARIAL: wrong passphrase fails the auth tag → ValueError, not silent garbage."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
    keystore.reset_for_tests(dir_override=tmp_path)

    with patch.object(keystore, "_probe_keyring", return_value=False):
        keystore.set_passphrase_for_tests("correct-passphrase-1")
        keystore.store_private_key("alice", "secret-key")

        # Simulate a fresh process: clear the cache, try to read with the wrong passphrase.
        keystore.clear_passphrase_cache()
        keystore.set_passphrase_for_tests("wrong-passphrase-1")

        with pytest.raises(ValueError):
            keystore.load_private_key("alice")

    keystore.reset_for_tests()


def test_clear_passphrase_cache_forces_reprompt_path(tmp_passphrase_keystore, monkeypatch: pytest.MonkeyPatch):
    """clear_passphrase_cache wipes the in-RAM cache; subsequent calls
    that don't seed the cache go through the unlock prompt — which we
    stub to verify the path is hit."""
    keystore.store_private_key("alice", "key-1")
    keystore.clear_passphrase_cache()

    prompts = []
    monkeypatch.setattr(
        keystore,
        "_prompt_for_unlock_passphrase",
        lambda: (prompts.append(1), "test-passphrase-12345")[1],
    )
    val = keystore.load_private_key("alice")
    assert val == "key-1"
    assert len(prompts) == 1, "expected exactly one unlock prompt after cache clear"


# ── rotate_backend — migration between backends ─────────────────────


def test_rotate_backend_device_to_passphrase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """HAPPY: device-fingerprint vault migrates to passphrase, keys preserved."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    keystore.reset_for_tests(dir_override=tmp_path)

    with patch.object(keystore, "_probe_keyring", return_value=False):
        keystore.store_private_key("alice", "key-alice")
        keystore.store_private_key("bob", "key-bob")
        assert keystore.current_backend() == keystore.BACKEND_DEVICE

        # rotate_backend(passphrase) requires the new passphrase as a
        # parameter — the wizard collects it interactively before calling.
        monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "passphrase")
        result = keystore.rotate_backend(
            keystore.BACKEND_PASSPHRASE,
            new_passphrase="new-passphrase-9876",
        )

    assert result["migrated"] == 2
    assert result["source"] == keystore.BACKEND_DEVICE
    assert result["target"] == keystore.BACKEND_PASSPHRASE
    assert keystore.load_private_key("alice") == "key-alice"
    assert keystore.load_private_key("bob") == "key-bob"

    keystore.reset_for_tests()


def test_rotate_backend_noop_when_target_matches_source(tmp_passphrase_keystore):
    """EDGE: rotating to the current backend is a no-op, returns noop=True."""
    keystore.store_private_key("alice", "key")
    result = keystore.rotate_backend(keystore.BACKEND_PASSPHRASE)
    assert result["noop"] is True
    assert result["migrated"] == 0


def test_rotate_backend_rejects_unknown_target(tmp_passphrase_keystore):
    """FAILURE: bogus target name raises ValueError with a helpful message."""
    with pytest.raises(ValueError, match="unknown target backend"):
        keystore.rotate_backend("aether")


def test_rotate_backend_to_keyring_fails_when_unavailable(tmp_passphrase_keystore):
    """FAILURE: requesting keyring on a host without one raises RuntimeError."""
    with pytest.raises(RuntimeError, match="keyring backend requested"):
        keystore.rotate_backend(keystore.BACKEND_KEYRING)


# ── Backend selection logic ─────────────────────────────────────────


def test_env_override_takes_precedence_over_persisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Env COMMUNITY_MEMBER_KEYSTORE wins over keystore.meta.json."""
    keystore.reset_for_tests(dir_override=tmp_path)
    # Persist a "passphrase" preference, then override to "device" via env.
    (tmp_path / "keystore.meta.json").write_text(json.dumps({"current_backend": "passphrase"}))
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    keystore.reset_for_tests(dir_override=tmp_path)

    with patch.object(keystore, "_probe_keyring", return_value=False):
        assert keystore.current_backend() == keystore.BACKEND_DEVICE

    keystore.reset_for_tests()


def test_legacy_encrypted_file_meta_resolves_to_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Vaults written before the device/passphrase split recorded
    ``current_backend: encrypted_file``. The new resolver maps that
    to BACKEND_DEVICE for backward compatibility — old vaults remain
    readable without a manual migration step."""
    monkeypatch.delenv("COMMUNITY_MEMBER_KEYSTORE", raising=False)
    keystore.reset_for_tests(dir_override=tmp_path)
    (tmp_path / "keystore.meta.json").write_text(json.dumps({"current_backend": "encrypted_file"}))
    keystore.reset_for_tests(dir_override=tmp_path)

    with patch.object(keystore, "_probe_keyring", return_value=False):
        assert keystore.current_backend() == keystore.BACKEND_DEVICE

    keystore.reset_for_tests()


def test_unknown_env_value_falls_through_to_auto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """ADVERSARIAL: a typoed env value is ignored (with a stderr warning)
    rather than silently selecting an unintended backend."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "lockbox")
    keystore.reset_for_tests(dir_override=tmp_path)

    with patch.object(keystore, "_probe_keyring", return_value=False):
        # tty detection picks passphrase or device; we just need the env
        # value to NOT be honored as "lockbox" (which doesn't exist).
        backend = keystore.current_backend()
        assert backend in (keystore.BACKEND_PASSPHRASE, keystore.BACKEND_DEVICE)

    err = capsys.readouterr().err
    assert "lockbox" in err

    keystore.reset_for_tests()


# ── S2 stage 2: legacy vault migrates to the versioned blob on open ──


def _legacy_vault_blob(vault: dict, passphrase: str) -> dict:
    """Seal ``vault`` exactly as legacy code did: the same cipher, but a
    version-less {ciphertext, salt, nonce, tag} envelope at the frozen cost."""
    import base64
    import hashlib
    import hmac
    import os as _os
    import struct

    from community_member import crypto

    plaintext = json.dumps(vault, sort_keys=True).encode()
    salt, nonce = _os.urandom(32), _os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, crypto.LEGACY_PBKDF2_ITERATIONS)
    enc_key, mac_key = key[:16], key[16:]
    ct = bytearray(len(plaintext))
    for i in range(0, len(plaintext), 32):
        block = hmac.new(enc_key, nonce + struct.pack(">I", i // 32), hashlib.sha256).digest()
        for j in range(min(32, len(plaintext) - i)):
            ct[i + j] = plaintext[i + j] ^ block[j]
    tag = hmac.new(mac_key, nonce + bytes(ct), hashlib.sha256).digest()
    return {
        "ciphertext": base64.b64encode(bytes(ct)).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def test_S2_legacy_vault_migrates_to_v2_on_first_open(tmp_keystore):
    """A legacy (version-less) vault file opens fine AND is re-encrypted as
    a v2 blob on that first successful open; the data survives."""
    passphrase = keystore._passphrase_for_backend(keystore.BACKEND_DEVICE)
    legacy = _legacy_vault_blob({"alice": "key-alice-b64"}, passphrase)
    keystore.KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    keystore._vault_path().write_text(json.dumps(legacy))

    assert keystore.load_private_key("alice") == "key-alice-b64"

    on_disk = json.loads(keystore._vault_path().read_text())
    assert on_disk.get("v") == 2, "vault was not migrated to the versioned format"
    assert on_disk["kdf"]["name"] == "pbkdf2-sha256"
    # And it still opens (now through the v2 path).
    assert keystore.load_private_key("alice") == "key-alice-b64"


def test_S2_v2_vault_is_not_rewritten_on_open(tmp_keystore):
    """Migration fires once: opening an already-v2 vault leaves the file
    byte-identical (no gratuitous re-encryption per read)."""
    keystore.store_private_key("alice", "key-alice-b64")
    before = keystore._vault_path().read_text()
    assert keystore.load_private_key("alice") == "key-alice-b64"
    assert keystore._vault_path().read_text() == before


def test_S2_corrupt_legacy_vault_is_not_migrated(tmp_keystore):
    """A legacy vault that fails to decrypt raises (hard failure) and the file
    is left untouched for recovery — migration only follows a SUCCESSFUL open."""
    passphrase = keystore._passphrase_for_backend(keystore.BACKEND_DEVICE)
    legacy = _legacy_vault_blob({"alice": "key-alice-b64"}, passphrase)
    legacy["tag"] = legacy["tag"][:-4] + "AAA="  # corrupt the MAC
    keystore.KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    keystore._vault_path().write_text(json.dumps(legacy))

    with pytest.raises(ValueError):
        keystore.load_private_key("alice")
    assert json.loads(keystore._vault_path().read_text()) == legacy  # untouched


# ── an unreadable vault is not an absent one ─────────────────────────────────
#
# The distinction is the difference between a crash and permanent identity loss.
# `_read_vault` returns {} for a vault that is not there, and a caller reads that
# as a fresh agent and mints a new did:key. If an UNREADABLE vault took the same
# path, a permissions problem would silently orphan every registration the old
# identity holds — which is exactly the state fourteen deployed agents' volumes
# were in when the image went non-root.
#
# Established by running it rather than by reading pathlib: `Path.exists()` does
# not swallow EACCES, so both the unreadable-file and the untraversable-directory
# cases raise instead of reporting absence.


def _skip_if_root():
    if os.geteuid() == 0:
        pytest.skip("running as root, which bypasses the permission bits under test")


def test_an_absent_vault_reads_as_empty(tmp_path):
    """The baseline the other two are distinguished from."""
    assert keystore._read_vault("passphrase", tmp_path) == {}


def test_an_unreadable_vault_raises_instead_of_reading_as_absent(tmp_path):
    """A vault the process cannot read must not present as a fresh agent."""
    _skip_if_root()
    vault = tmp_path / "keystore.enc"
    vault.write_text('{"v": 2}')
    os.chmod(vault, 0o000)
    try:
        with pytest.raises(PermissionError):
            keystore._read_vault("passphrase", tmp_path)
    finally:
        os.chmod(vault, 0o600)


def test_an_untraversable_home_raises_instead_of_reading_as_absent(tmp_path):
    """The more dangerous half: the directory, not the file.

    `_read_vault` starts with `if not path.exists()`, and a directory the process
    cannot traverse is where "does this file exist" could plausibly answer no.
    It does not — it raises — and that is what keeps a permissions problem from
    becoming a new identity.
    """
    _skip_if_root()
    home = tmp_path / "home"
    home.mkdir()
    (home / "keystore.enc").write_text('{"v": 2}')
    os.chmod(home, 0o000)
    try:
        with pytest.raises(PermissionError):
            keystore._read_vault("passphrase", home)
    finally:
        os.chmod(home, 0o700)
