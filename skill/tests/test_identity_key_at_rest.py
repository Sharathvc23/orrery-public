"""Identity private key encrypted at rest (AUDIT_HARSH H3).

``$OPENCLAW_HOME/skills/orrery-org/identity.json`` stored the skill's Ed25519
private key as a plaintext PKCS8 PEM at mode 0600. ``ORRERY_SKILL_KEY_PASSPHRASE``
now encrypts it (PBES2/AES), and an existing plaintext key is re-encrypted in
place on the next run without changing the key.

What these tests do NOT claim: they do not cover the threat
``skill/SECURITY.md`` lists as out of scope — a process with the same uid, or
root, can read the passphrase from the environment. What is closed is the key
appearing in the clear in a disk image, filesystem backup or host snapshot.

``sign_request`` resolves ``OPENCLAW_HOME`` at import and refuses paths outside
the calling user's home, so these tests point the module-level identity paths at
``tmp_path`` rather than moving the env var.
"""

from __future__ import annotations

import json
import os

import pytest
import sign_request as sr
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PASSPHRASE_ENV = "ORRERY_SKILL_KEY_PASSPHRASE"


@pytest.fixture
def identity_at(tmp_path, monkeypatch):
    """Point the module's identity paths at tmp_path; start with no passphrase."""
    monkeypatch.setattr(sr, "IDENTITY_DIR", tmp_path)
    monkeypatch.setattr(sr, "IDENTITY_FILE", tmp_path / "identity.json")
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    return tmp_path / "identity.json"


def _write_plaintext_identity(path) -> tuple[Ed25519PrivateKey, str]:
    """Write an identity file in the pre-H3 format: unencrypted PKCS8 PEM."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    did = sr._build_did_key(pub)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    path.write_text(json.dumps({"did_key": did, "private_key_pem": pem, "created_at": 0}))
    return priv, did


def test_H3_default_is_unchanged_plaintext(identity_at):
    """No passphrase set: behaviour is exactly as before — opt-in, not a flag day."""
    _, _, did = sr._load_or_create_identity()
    stored = json.loads(identity_at.read_text())
    assert "BEGIN PRIVATE KEY" in stored["private_key_pem"]
    assert stored["did_key"] == did


def test_H3_new_identity_is_encrypted_when_a_passphrase_is_set(identity_at, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")
    _, _, did = sr._load_or_create_identity()

    stored = json.loads(identity_at.read_text())
    assert "BEGIN ENCRYPTED PRIVATE KEY" in stored["private_key_pem"]
    assert "BEGIN PRIVATE KEY" not in stored["private_key_pem"]
    # And it reloads to the same identity.
    _, _, did_again = sr._load_or_create_identity()
    assert did_again == did


def test_H3_new_identity_file_is_0600(identity_at, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")
    sr._load_or_create_identity()
    assert os.stat(identity_at).st_mode & 0o777 == 0o600


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_H3_empty_passphrase_is_treated_as_unset(identity_at, monkeypatch, value):
    """An exported-but-empty env var must not produce a key encrypted under ""."""
    monkeypatch.setenv(PASSPHRASE_ENV, value)
    sr._load_or_create_identity()
    stored = json.loads(identity_at.read_text())
    assert "BEGIN PRIVATE KEY" in stored["private_key_pem"]


# ── Migration: keys created before H3 ─────────────────────────────────────────


def test_H3_existing_plaintext_key_is_encrypted_in_place(identity_at, monkeypatch):
    """MIGRATION: encrypting only NEW identities would leave every existing key
    in the clear behind code that reads as fixed."""
    _, did = _write_plaintext_identity(identity_at)
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")

    _, _, loaded_did = sr._load_or_create_identity()

    stored = json.loads(identity_at.read_text())
    assert "BEGIN ENCRYPTED PRIVATE KEY" in stored["private_key_pem"]
    assert loaded_did == did  # same key — did:key unchanged, no re-registration


def test_H3_migration_preserves_the_key_bytes(identity_at, monkeypatch):
    """The re-encode must not rotate: the agent's did:key is what orgs bound it to."""
    priv, did = _write_plaintext_identity(identity_at)
    original_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")

    loaded, _, loaded_did = sr._load_or_create_identity()
    assert loaded_did == did
    assert (
        loaded.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        == original_raw
    )


def test_H3_migration_forces_0600_on_a_loosely_permissioned_file(identity_at, monkeypatch):
    """A key file from a build predating the 0600 change is tightened by the rewrite.

    ``O_CREAT``'s mode argument is ignored for an existing file, so the rewrite
    has to chmod explicitly or the migration would leave the old mode in place.
    """
    _write_plaintext_identity(identity_at)
    os.chmod(identity_at, 0o644)
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")

    sr._load_or_create_identity()
    assert os.stat(identity_at).st_mode & 0o777 == 0o600


def test_H3_already_encrypted_file_is_not_rewritten(identity_at, monkeypatch):
    """One-shot: a later run leaves the file byte-identical."""
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")
    sr._load_or_create_identity()
    before = identity_at.read_bytes()
    sr._load_or_create_identity()
    assert identity_at.read_bytes() == before


def test_H3_tampered_file_is_not_rewritten(identity_at, monkeypatch):
    """The migration runs only AFTER the did_key cross-check.

    Rewriting first would overwrite the evidence that the file was tampered with.
    """
    _write_plaintext_identity(identity_at)
    data = json.loads(identity_at.read_text())
    data["did_key"] = "did:key:zNotTheRealOne"
    identity_at.write_text(json.dumps(data))
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")

    with pytest.raises(ValueError, match="tampered"):
        sr._load_or_create_identity()
    assert "BEGIN PRIVATE KEY" in json.loads(identity_at.read_text())["private_key_pem"]


# ── Failure modes ─────────────────────────────────────────────────────────────


def test_H3_encrypted_key_without_the_passphrase_fails_clearly(identity_at, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")
    sr._load_or_create_identity()
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)

    with pytest.raises(ValueError, match=PASSPHRASE_ENV):
        sr._load_or_create_identity()


def test_H3_wrong_passphrase_fails(identity_at, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a-real-passphrase")
    sr._load_or_create_identity()
    monkeypatch.setenv(PASSPHRASE_ENV, "a-different-passphrase")

    with pytest.raises(ValueError):
        sr._load_or_create_identity()
