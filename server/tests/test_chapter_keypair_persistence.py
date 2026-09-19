"""sovereign_identity.ensure_chapter_keypair — durable chapter signing key.

The chapter's Ed25519 key must exist at startup and survive restarts/replicas, or
ARP receipt signing + the VRP AgentFacts Attestation silently no-op. These prove the
Postgres-backed path (mint→persist→reload) and the offline-file fallback.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import secret_sealing
import sovereign_identity as si

_CID = "test-chapter-keypersist"


@pytest.fixture(autouse=True)
def _clean_keystore():
    si._ed25519_keypairs.pop(_CID, None)
    yield
    si._ed25519_keypairs.pop(_CID, None)


class _FakePostgres:
    """Minimal in-memory stand-in for the chapter's async pg_request, scoped
    to the chapter_keys table. ``fail_writes`` simulates a missing/unreachable table."""

    def __init__(self, fail_writes: bool = False) -> None:
        self.rows: list[dict] = []
        self.fail_writes = fail_writes
        self.calls: list[str] = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append(f"{method} {table}")
        assert table == "chapter_keys"
        if method == "GET":
            cid = params["chapter_id"].removeprefix("eq.")
            return [r for r in self.rows if r["chapter_id"] == cid]
        if method == "POST":
            if self.fail_writes:
                return None
            self.rows.append(dict(body))
            return [dict(body)]
        if method == "PATCH":
            if self.fail_writes:
                return None
            cid = params["chapter_id"].removeprefix("eq.")
            hit = [r for r in self.rows if r["chapter_id"] == cid]
            for r in hit:
                r.update(body)
            return [dict(r) for r in hit]
        raise AssertionError(f"unexpected {method}")


async def test_supabase_first_boot_mints_and_persists():
    """HAPPY: empty store → mint a key, put it in memory AND persist it."""
    fake = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert _CID in si._ed25519_keypairs
    assert len(fake.rows) == 1 and fake.rows[0]["chapter_id"] == _CID
    assert "secret_b64" in fake.rows[0] and "public_b64" in fake.rows[0]


async def test_supabase_stable_across_restart():
    """C4: the key SURVIVES a restart — clear memory, re-run, identical key loads."""
    fake = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    first = si._ed25519_keypairs[_CID]["private_key"]

    si._ed25519_keypairs.pop(_CID)  # simulate process restart
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert si._ed25519_keypairs[_CID]["private_key"] == first  # SAME key, not a new mint
    assert sum(1 for c in fake.calls if c.startswith("POST")) == 1  # persisted once, never re-minted


async def test_supabase_loads_existing_row_exactly():
    """The bytes loaded from the store are exactly what was stored."""
    fake = _FakePostgres()
    kp = si.generate_ed25519_keypair("seed-only")
    fake.rows.append({"chapter_id": _CID, "secret_b64": kp["private_key"], "public_b64": kp["public_key"]})
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert base64.b64encode(si._ed25519_keypairs[_CID]["private_key"]).decode() == kp["private_key"]
    assert base64.b64encode(si._ed25519_keypairs[_CID]["public_key"]).decode() == kp["public_key"]


async def test_persist_failure_is_ephemeral_and_loud(capsys):
    """FAILURE: table missing/unreachable → key still usable in-memory, but LOUD."""
    fake = _FakePostgres(fail_writes=True)
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert _CID in si._ed25519_keypairs  # degrades to ephemeral, does not crash
    assert "EPHEMERAL" in capsys.readouterr().out


async def test_idempotent_skips_store_when_already_loaded():
    """Idempotent: an already-loaded key is never re-fetched or re-minted."""
    si.generate_ed25519_keypair(_CID)
    existing = si._ed25519_keypairs[_CID]["private_key"]
    fake = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert si._ed25519_keypairs[_CID]["private_key"] == existing
    assert fake.calls == []  # store untouched


async def test_offline_local_file_stable_across_restart(tmp_path):
    """Offline/dev: file-backed key survives a 'restart' just like Postgres."""
    await si.ensure_chapter_keypair(_CID, local_home=str(tmp_path))
    first = si._ed25519_keypairs[_CID]["private_key"]
    assert (tmp_path / "chapter_ed25519.json").exists()

    si._ed25519_keypairs.pop(_CID)
    await si.ensure_chapter_keypair(_CID, local_home=str(tmp_path))
    assert si._ed25519_keypairs[_CID]["private_key"] == first


async def test_loaded_key_signs_and_verifies():
    """C7: the persisted+reloaded key is a real, usable Ed25519 signing key."""
    fake = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    kp = si._ed25519_keypairs[_CID]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    msg = b"chapter-attestation-payload"
    sig = Ed25519PrivateKey.from_private_bytes(kp["private_key"]).sign(msg)
    Ed25519PublicKey.from_public_bytes(kp["public_key"]).verify(sig, msg)  # raises if invalid


# ── S1: chapter signing-key encryption at rest ────────────────────


def test_S1_seal_unseal_round_trip(monkeypatch):
    """With ORRERY_KEY_SECRET set, a sealed secret round-trips and its wire form
    is opaque (prefixed, not the raw base64)."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "correct horse battery staple")
    plaintext = base64.b64encode(b"x" * 32).decode()
    sealed = si._seal_secret(plaintext)
    assert secret_sealing.is_sealed(sealed)  # sealed at rest; version-agnostic by design
    assert plaintext not in sealed
    assert si._unseal_secret(sealed) == plaintext


def test_S1_legacy_plaintext_passthrough(monkeypatch):
    """A legacy (unprefixed) value is returned unchanged — non-breaking read."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "whatever")
    legacy = base64.b64encode(b"y" * 32).decode()
    assert si._unseal_secret(legacy) == legacy


def test_S1_sealed_without_secret_raises(monkeypatch):
    """A sealed value cannot be read without the key-encryption secret."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-A")
    sealed = si._seal_secret(base64.b64encode(b"z" * 32).decode())
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="ORRERY_KEY_SECRET"):
        si._unseal_secret(sealed)


def test_C11_no_secret_refuses_to_store_plaintext(monkeypatch):
    """C11: without the secret, sealing RAISES instead of storing plaintext.

    This test previously asserted the opposite — that ``_seal_secret`` returned the
    plaintext unchanged so a deploy with no ``ORRERY_KEY_SECRET`` kept working. That
    behaviour is the finding: absent configuration selected the branch that wrote the
    org's signing key in the clear.
    """
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    plaintext = base64.b64encode(b"w" * 32).decode()
    with pytest.raises(secret_sealing.SealingNotConfigured, match="ORRERY_KEY_SECRET"):
        si._seal_secret(plaintext)


def test_C11_empty_secret_is_identical_to_unset(monkeypatch):
    """C11: unset and empty/whitespace behave the same.

    ``ORRERY_KEY_SECRET=`` is what ``.env.example`` shipped, so an operator who
    copied it had an env var that was present but decided nothing. It must not read
    as a configured secret.
    """
    plaintext = base64.b64encode(b"v" * 32).decode()
    for value in ("", "   ", "\t\n"):
        monkeypatch.setenv("ORRERY_KEY_SECRET", value)
        with pytest.raises(secret_sealing.SealingNotConfigured, match="ORRERY_KEY_SECRET"):
            si._seal_secret(plaintext)


def test_C11_opt_out_stores_plaintext_loudly(monkeypatch, capsys):
    """The plaintext path still exists, but only as an explicit env decision."""
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    monkeypatch.setenv("ORRERY_REQUIRE_SEALED_SECRETS", "false")
    plaintext = base64.b64encode(b"u" * 32).decode()
    assert si._seal_secret(plaintext) == plaintext
    assert "UNENCRYPTED" in capsys.readouterr().out


def test_C11_unrecognised_require_flag_still_requires(monkeypatch):
    """A typo in the opt-out is not an opt-out (env_flags.security_flag)."""
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    monkeypatch.setenv("ORRERY_REQUIRE_SEALED_SECRETS", "flase")
    with pytest.raises(secret_sealing.SealingNotConfigured):
        si._seal_secret(base64.b64encode(b"t" * 32).decode())


async def test_C11_boot_refuses_when_secret_missing(monkeypatch):
    """C11: startup REFUSES rather than minting a plaintext key.

    ``ensure_chapter_keypair`` runs in the FastAPI lifespan, so raising here is the
    process failing to start — the difference between an operator finding out at
    deploy time and finding out from a database dump.
    """
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    fake = _FakePostgres()
    with pytest.raises(secret_sealing.SealingNotConfigured, match="ORRERY_KEY_SECRET"):
        await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert fake.calls == []  # refused BEFORE touching the store — nothing minted, nothing written
    assert _CID not in si._ed25519_keypairs


async def test_C11_boot_refuses_on_an_existing_plaintext_row(monkeypatch):
    """The refusal covers a RESTART on an already-plaintext row, not just a first boot.

    Gating only the mint path would leave the three live orgs — whose rows are already
    plaintext — booting happily and reporting healthy while the key stayed in the clear.
    """
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    kp = si.generate_ed25519_keypair("seed-only")
    fake = _FakePostgres()
    fake.rows.append({"chapter_id": _CID, "secret_b64": kp["private_key"], "public_b64": kp["public_key"]})
    with pytest.raises(secret_sealing.SealingNotConfigured):
        await si.ensure_chapter_keypair(_CID, pg_request=fake)


# ── C11 migration: existing plaintext rows are sealed IN PLACE ────────────────
# Sealing only new writes would leave every key minted before this change readable
# to anyone with database access, behind code that reads as fixed.


async def test_C11_existing_plaintext_row_is_sealed_in_place(monkeypatch, capsys):
    """A legacy plaintext row is re-stored sealed on the next boot that has the secret."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-migration")
    kp = si.generate_ed25519_keypair("seed-only")
    fake = _FakePostgres()
    fake.rows.append({"chapter_id": _CID, "secret_b64": kp["private_key"], "public_b64": kp["public_key"]})

    await si.ensure_chapter_keypair(_CID, pg_request=fake)

    assert secret_sealing.is_sealed(fake.rows[0]["secret_b64"])  # sealed at rest now
    assert kp["private_key"] not in fake.rows[0]["secret_b64"]
    assert "sealed in place" in capsys.readouterr().out


async def test_C11_migration_preserves_the_key_so_did_key_is_unchanged(monkeypatch):
    """The migration re-ENCODES the same bytes; it does not rotate.

    A rotation would change the org's did:key and break every peer that pinned it,
    so the migration must be byte-preserving. Asserted on the public key, which is
    what did:key is derived from.
    """
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-migration")
    kp = si.generate_ed25519_keypair("seed-only")
    fake = _FakePostgres()
    fake.rows.append({"chapter_id": _CID, "secret_b64": kp["private_key"], "public_b64": kp["public_key"]})

    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    loaded = si._ed25519_keypairs[_CID]
    assert base64.b64encode(loaded["private_key"]).decode() == kp["private_key"]
    assert base64.b64encode(loaded["public_key"]).decode() == kp["public_key"]
    assert fake.rows[0]["public_b64"] == kp["public_key"]  # untouched by the UPDATE

    # And the sealed row reloads to the same key in a fresh process.
    si._ed25519_keypairs.pop(_CID)
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert base64.b64encode(si._ed25519_keypairs[_CID]["private_key"]).decode() == kp["private_key"]


async def test_C11_already_sealed_row_is_not_rewritten(monkeypatch):
    """The migration is a one-shot: a sealed row triggers no UPDATE on later boots."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-migration")
    fake = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=fake)  # first boot mints sealed
    si._ed25519_keypairs.pop(_CID)
    await si.ensure_chapter_keypair(_CID, pg_request=fake)
    assert [c for c in fake.calls if c.startswith("PATCH")] == []


async def test_C11_failed_migration_is_loud_and_does_not_stop_startup(monkeypatch, capsys):
    """A failed seal-in-place UPDATE logs the still-plaintext state and keeps serving.

    The key is already loaded and usable; what is unresolved is its at-rest form, so
    the right response is a retry next boot, not an outage.
    """
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-migration")
    kp = si.generate_ed25519_keypair("seed-only")
    fake = _FakePostgres(fail_writes=True)
    fake.rows.append({"chapter_id": _CID, "secret_b64": kp["private_key"], "public_b64": kp["public_key"]})

    await si.ensure_chapter_keypair(_CID, pg_request=fake)

    assert _CID in si._ed25519_keypairs  # still serving
    out = capsys.readouterr().out
    assert "PLAINTEXT" in out and "Retrying on next boot" in out


async def test_C11_offline_plaintext_file_is_sealed_in_place(monkeypatch, tmp_path):
    """Same migration for the offline file-backed key, at 0600."""
    import json
    import os as _os

    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-migration")
    kp = si.generate_ed25519_keypair("seed-only")
    path = tmp_path / "chapter_ed25519.json"
    path.write_text(json.dumps({"secret_b64": kp["private_key"], "public_b64": kp["public_key"]}))

    await si.ensure_chapter_keypair(_CID, local_home=str(tmp_path))

    on_disk = json.loads(path.read_text())
    assert secret_sealing.is_sealed(on_disk["secret_b64"])
    assert kp["private_key"] not in on_disk["secret_b64"]
    assert on_disk["public_b64"] == kp["public_key"]  # key unchanged, only its encoding
    assert _os.stat(path).st_mode & 0o777 == 0o600
    assert base64.b64encode(si._ed25519_keypairs[_CID]["private_key"]).decode() == kp["private_key"]


async def test_S1_db_key_sealed_at_rest_and_reloads(monkeypatch):
    """SECURITY (S1): with the secret set, the chapter key persisted to the DB is
    sealed (not plaintext base64) and still reloads into a working keypair."""
    monkeypatch.setenv("ORRERY_KEY_SECRET", "a-long-random-kek-value")
    pg = _FakePostgres()
    await si.ensure_chapter_keypair(_CID, pg_request=pg)

    stored = pg.rows[0]["secret_b64"]
    assert secret_sealing.is_sealed(stored)  # sealed at rest, not plaintext
    plain = base64.b64encode(si._ed25519_keypairs[_CID]["private_key"]).decode()
    assert plain not in stored

    # Reload from the sealed row into a fresh process.
    si._ed25519_keypairs.pop(_CID, None)
    await si.ensure_chapter_keypair(_CID, pg_request=pg)
    kp = si._ed25519_keypairs[_CID]
    msg = b"m"
    sig = Ed25519PrivateKey_import().from_private_bytes(kp["private_key"]).sign(msg)
    Ed25519PublicKey.from_public_bytes(kp["public_key"]).verify(sig, msg)


def Ed25519PrivateKey_import():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey
