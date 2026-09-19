"""secret_sealing — the at-rest primitive shared by C11 (signing key) and C1 (LLM keys).

The behaviour under test is the DIRECTION the mechanism fails when nobody
configured it. Before that change that direction was "store plaintext and keep going",
which is why the org signing key sat unsealed in three production databases while
the module docstring described it as identity-forgery material.
"""

from __future__ import annotations

import pytest

import secret_sealing as ss


def test_round_trip(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "correct horse battery staple")
    sealed = ss.seal("plaintext-value", subject="a test secret")
    assert ss.is_sealed(sealed)
    assert "plaintext-value" not in sealed
    assert ss.unseal(sealed) == "plaintext-value"


def test_seal_is_randomised(monkeypatch):
    """Two seals of the same input differ — fresh salt and nonce per call.

    A deterministic ciphertext would let anyone with the table tell which members
    share a provider key.
    """
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek")
    assert ss.seal("same", subject="t") != ss.seal("same", subject="t")


def test_legacy_plaintext_passes_through(monkeypatch):
    """Unmarked values read as-is — this is what makes seal-in-place possible
    instead of forcing a key rotation."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek")
    assert ss.unseal("legacy-plaintext") == "legacy-plaintext"
    assert not ss.is_sealed("legacy-plaintext")


def test_sealed_value_needs_the_same_secret(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-A")
    sealed = ss.seal("v", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-B")
    with pytest.raises(Exception):  # noqa: B017 — AEAD tag failure, cryptography's own type
        ss.unseal(sealed)


def test_sealed_value_without_any_secret_raises(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-A")
    sealed = ss.seal("v", subject="t")
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    with pytest.raises(ss.SealingNotConfigured, match="ORRERY_KEY_SECRET"):
        ss.unseal(sealed)


def test_tamper_is_rejected(monkeypatch):
    """AES-GCM authenticates: a flipped ciphertext byte fails rather than decrypting."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek")
    sealed = ss.seal("v", subject="t")
    tampered = sealed[:-2] + ("AA" if sealed[-2:] != "AA" else "BB")
    with pytest.raises(Exception):  # noqa: B017
        ss.unseal(tampered)


# ── The fail direction ────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_empty_secret_is_treated_as_unset(monkeypatch, value):
    """``ORRERY_KEY_SECRET=`` is what .env.example shipped: present, decides nothing."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", value)
    assert ss.key_encryption_secret() == ""
    with pytest.raises(ss.SealingNotConfigured):
        ss.seal("v", subject="t")


def test_sealing_required_by_default(monkeypatch):
    monkeypatch.delenv("ORRERY_REQUIRE_SEALED_SECRETS", raising=False)
    assert ss.sealing_required() is True


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "FALSE"])
def test_explicit_opt_out_is_honoured(monkeypatch, value):
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    monkeypatch.setenv("ORRERY_REQUIRE_SEALED_SECRETS", value)
    assert ss.sealing_required() is False
    assert ss.seal("v", subject="t") == "v"


@pytest.mark.parametrize("value", ["flase", "nope", "  ", "1.5"])
def test_unrecognised_opt_out_still_requires_sealing(monkeypatch, value):
    """A typo is not a decision to disable — env_flags.security_flag's rule."""
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    monkeypatch.setenv("ORRERY_REQUIRE_SEALED_SECRETS", value)
    assert ss.sealing_required() is True
    with pytest.raises(ss.SealingNotConfigured):
        ss.seal("v", subject="t")


def test_error_names_the_secret_and_both_env_vars(monkeypatch):
    """The refusal has to be actionable: an operator hitting it at deploy time must
    be able to fix it without reading the source."""
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    with pytest.raises(ss.SealingNotConfigured) as e:
        ss.require_sealing_configured("the chapter's Ed25519 signing key")
    msg = str(e.value)
    assert "the chapter's Ed25519 signing key" in msg
    assert "ORRERY_KEY_SECRET" in msg
    assert "ORRERY_REQUIRE_SEALED_SECRETS=false" in msg
    assert "openssl rand -hex 32" in msg


def test_require_is_a_no_op_once_configured(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek")
    ss.require_sealing_configured("anything")  # does not raise


# ── Migration eligibility ─────────────────────────────────────────────────────


def test_needs_migration_only_for_plaintext_with_a_secret(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek")
    assert ss.needs_migration("legacy-plaintext") is True
    assert ss.needs_migration(ss.seal("v", subject="t")) is False
    assert ss.needs_migration("") is False


def test_needs_migration_is_false_without_a_secret(monkeypatch):
    """Nothing to seal under — leave the row alone rather than fail the read."""
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    assert ss.needs_migration("legacy-plaintext") is False


# ── M3: raising PBKDF2 iterations without stranding sealed rows ───────────────
# The iteration count is NOT stored inside the blob, so it cannot be recovered
# from the ciphertext — the format prefix carries it. Bumping PBKDF2_ITERS in
# place would have re-derived a different key for every already-written value and
# made every sealed secret in the database permanently undecryptable.


def _forge_v1(kek: str, plaintext: str) -> str:
    """A value sealed exactly as the pre-M3 code wrote it: enc.v1 at 200K."""
    import base64
    import hashlib
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, nonce = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", kek.encode(), salt, 200_000)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return "enc.v1:" + base64.b64encode(salt + nonce + ct).decode()


def test_v1_values_sealed_at_200k_still_decrypt(monkeypatch):
    """ADVERSARIAL: the migration hazard. A row written before M3 must still open."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-test")
    stored = _forge_v1("kek-for-test", "legacy-secret")
    assert ss.is_sealed(stored), "a v1 value must not be mistaken for legacy plaintext"
    assert ss.unseal(stored) == "legacy-secret"


def test_new_values_are_written_at_the_raised_iteration_count(monkeypatch):
    """HAPPY: M3's actual requirement — new seals use 600K."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-test")
    sealed = ss.seal("new-secret", subject="probe")
    assert sealed.startswith("enc.v2:")
    assert ss.PBKDF2_ITERS == 600_000
    assert ss.unseal(sealed) == "new-secret"


def test_each_version_derives_with_its_own_iteration_count():
    """EDGE: the prefix table is the source of truth and v1 stays frozen.

    Changing the v1 value here would silently strand every row already sealed
    under it, which is the failure this whole versioning exists to prevent.
    """
    assert ss._ITERS_BY_PREFIX["enc.v1:"] == 200_000
    assert ss._ITERS_BY_PREFIX["enc.v2:"] == 600_000


def test_legacy_plaintext_still_passes_through(monkeypatch):
    """EDGE: the seal-in-place migration path is unaffected by versioning."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-test")
    assert ss.unseal("not-sealed-at-all") == "not-sealed-at-all"


# ── rotating the key-encryption secret ───────────────────────────────
#
# Before ORRERY_KEY_SECRET_PREVIOUS existed, changing ORRERY_KEY_SECRET made
# every sealed row permanently undecryptable — the signing key first — so a
# leaked key-encryption secret could only be rotated by re-keying the org and
# having every federated peer re-pin its did:key. The deploy guide said as much
# ("never rotate it casually") and offered no procedure, because none existed.


def test_a_value_sealed_under_the_previous_secret_still_unseals(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-old")
    sealed = ss.seal("the signing key", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-new")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-old")
    assert ss.unseal(sealed) == "the signing key"


def test_the_previous_secret_is_read_only_and_never_sealed_under(monkeypatch):
    """Whatever is written during a rotation is written under the NEW secret,
    so the previous one can be dropped once the migrations have run."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-new")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-old")
    sealed = ss.seal("v", subject="t")
    monkeypatch.delenv("ORRERY_KEY_SECRET_PREVIOUS")
    assert ss.unseal(sealed) == "v"
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-old")
    with pytest.raises(Exception):  # noqa: B017 — AEAD tag failure: not sealed under the old one
        ss.unseal(sealed)


def test_a_value_sealed_under_the_previous_secret_needs_migration(monkeypatch):
    """This is what completes a rotation: every boot-time seal-in-place path
    asks needs_migration, and a row sealed under the outgoing secret answers
    yes, so it is rewritten under the current one."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-old")
    sealed_old = ss.seal("v", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-new")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-old")
    assert ss.needs_migration(sealed_old) is True
    assert ss.sealed_under_previous_secret(sealed_old) is True
    resealed = ss.seal(ss.unseal(sealed_old), subject="t")
    assert ss.needs_migration(resealed) is False, "once resealed under the current secret, nothing to do"
    monkeypatch.delenv("ORRERY_KEY_SECRET_PREVIOUS")
    assert ss.unseal(resealed) == "v", "the previous secret can be dropped after the reseal"


def test_a_value_sealed_under_the_current_secret_is_not_migrated_just_because_a_previous_is_set(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-new")
    sealed = ss.seal("v", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-old")
    assert ss.needs_migration(sealed) is False
    assert ss.sealed_under_previous_secret(sealed) is False


def test_neither_secret_opens_it_is_still_a_failure(monkeypatch):
    """A previous secret widens what can be READ; it does not soften a wrong key."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-A")
    sealed = ss.seal("v", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-B")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-C")
    with pytest.raises(Exception):  # noqa: B017 — AEAD tag failure under both
        ss.unseal(sealed)
    assert ss.needs_migration(sealed) is False, "an unreadable value is not something to rewrite"


async def test_the_chapter_signing_key_row_is_resealed_under_the_new_secret_at_boot(monkeypatch):
    """Through the real migration path, not a copy of it: sovereign_identity's
    seal-in-place sees a chapter_keys row sealed under the outgoing secret and
    PATCHes it with a value only the current secret opens."""
    import sovereign_identity as si

    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-old")
    sealed_old = ss.seal("c2VjcmV0", subject="t")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-new")
    monkeypatch.setenv("ORRERY_KEY_SECRET_PREVIOUS", "kek-old")

    patches: list[dict] = []

    async def _pg(method, table, params=None, body=None, **_kw):
        assert (method, table) == ("PATCH", "chapter_keys")
        patches.append(body)
        return [body]

    await si._migrate_plaintext_row("org-1", sealed_old, _pg)
    assert len(patches) == 1, "the row sealed under the previous secret must be rewritten"
    rewritten = patches[0]["secret_b64"]
    assert rewritten != sealed_old
    monkeypatch.delenv("ORRERY_KEY_SECRET_PREVIOUS")
    assert ss.unseal(rewritten) == "c2VjcmV0", "the rewritten row opens under the current secret alone"
