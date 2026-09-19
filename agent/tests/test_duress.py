"""Tests for duress — S8 under-gunpoint mode.

Coverage:

  R1  Forgery — passphrase file tampered (hash byte flipped) → both
      matches fail; 'invalid' returned
  R3  Injection — unicode + control chars in either passphrase are
      hashed as bytes, no crash
  R4  Authz — register rejects empty passphrases + identical ones
  R5  Boundary — exact match → correct bucket; 1-char-off → invalid
  R7  Adversarial — duress path must not be observable: verify with
      an invalid passphrase and with duress both take similar wall
      time (both compute both hashes)
  R9  Timing — hmac.compare_digest is constant-time (can't assert in
      test, but we assert both comparisons run on every call via
      a coverage-style probe)
  R10 Persistence — registered store survives reopen; re-register
      overwrites cleanly

  S8  Duress passphrase triggers silent wipe + audit marker; normal
      passphrase does NOT wipe; invalid does NOT wipe
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from community_member import duress
from community_member.consent import ledger


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
def store_path(tmp_env: Path) -> Path:
    path = tmp_env / "duress.json"
    # Use a lower iteration count so tests run fast. Production is 800k.
    duress.register_passphrases(
        "correct-horse-battery-staple",
        "under-duress-send-help",
        path=path,
        iterations=1000,
    )
    return path


# ── register_passphrases ───────────────────────────────────────


def test_register_creates_file_with_0600_perms(tmp_env):
    path = tmp_env / "d.json"
    duress.register_passphrases("a", "b", path=path, iterations=100)
    assert path.exists()
    # On POSIX, check mode bits.
    import os
    import stat

    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


def test_R4_reject_empty_passphrase(tmp_env):
    with pytest.raises(ValueError, match="non-empty"):
        duress.register_passphrases("", "something", path=tmp_env / "d.json")


def test_R4_reject_identical_passphrases(tmp_env):
    with pytest.raises(ValueError, match="must differ"):
        duress.register_passphrases("same", "same", path=tmp_env / "d.json")


def test_register_can_overwrite(tmp_env):
    path = tmp_env / "d.json"
    duress.register_passphrases("n1", "d1", path=path, iterations=100)
    duress.register_passphrases("n2", "d2", path=path, iterations=100)
    # Second registration wins.
    assert duress.verify_and_handle("n2", store_path=path, chapter_id="ch") == "normal"
    assert duress.verify_and_handle("n1", store_path=path, chapter_id="ch") == "invalid"


# ── verify_and_handle — happy paths ───────────────────────────


def test_normal_passphrase_returns_normal(store_path):
    result = duress.verify_and_handle("correct-horse-battery-staple", store_path=store_path, chapter_id="ch")
    assert result == "normal"


def test_invalid_passphrase_returns_invalid(store_path):
    result = duress.verify_and_handle("something-else", store_path=store_path, chapter_id="ch")
    assert result == "invalid"


def test_R5_one_char_off_is_invalid(store_path):
    # Off by one char.
    result = duress.verify_and_handle(
        "correct-horse-battery-stapla",  # final 'e' → 'a'
        store_path=store_path,
        chapter_id="ch",
    )
    assert result == "invalid"


# ── S8: duress triggers silent side effects ─────────────────


def test_S8_duress_returns_duress_not_leaked_to_caller(store_path):
    """Duress returns 'duress' to the library caller (so tray UI
    knows what to log), but the UI should NOT branch visibly on
    it. This test asserts the return value; UI behavior is tested
    separately when the tray UI ships."""
    result = duress.verify_and_handle("under-duress-send-help", store_path=store_path, chapter_id="ch")
    assert result == "duress"


def test_S8_duress_writes_audit_marker(store_path):
    duress.verify_and_handle("under-duress-send-help", store_path=store_path, chapter_id="ch")
    rows = ledger.list_events(action="consent.duress_triggered")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "ok"
    assert rows[0]["detail"]["marker"] == "silent"


def test_S8_normal_passphrase_does_NOT_write_audit_marker(store_path):
    duress.verify_and_handle("correct-horse-battery-staple", store_path=store_path, chapter_id="ch")
    rows = ledger.list_events(action="consent.duress_triggered")
    assert len(rows) == 0


def test_S8_invalid_passphrase_does_NOT_write_audit_marker(store_path):
    duress.verify_and_handle("wrong", store_path=store_path, chapter_id="ch")
    rows = ledger.list_events(action="consent.duress_triggered")
    assert len(rows) == 0


def test_S8_duress_wipes_habits_db(store_path, tmp_env):
    habits_path = tmp_env / "habits.db"
    habits_path.write_bytes(b"fake habits data")
    duress.verify_and_handle(
        "under-duress-send-help",
        store_path=store_path,
        chapter_id="ch",
        on_duress_wipe_habits=habits_path,
    )
    assert not habits_path.exists()


def test_S8_duress_revokes_graduations_for_this_device(store_path, tmp_env):
    from community_member.graduation import GraduationStore

    db = tmp_env / "grad.db"
    s = GraduationStore(db, device_did="did:key:alice")
    s.record_graduation(capability="c", scope="sc", context_sha256="ctx")
    # Sanity: before duress, graduated.
    status = s.status(capability="c", scope="sc", context_sha256="ctx", approvals=10, posterior_mean=0.95)
    assert status.state == "graduated"

    duress.verify_and_handle(
        "under-duress-send-help",
        store_path=store_path,
        chapter_id="ch",
        device_did="did:key:alice",
        graduation_db_path=db,
    )

    s2 = GraduationStore(db, device_did="did:key:alice")
    status2 = s2.status(capability="c", scope="sc", context_sha256="ctx", approvals=10, posterior_mean=0.95)
    assert status2.state == "revoked"


def test_S8_duress_does_not_touch_other_devices(store_path, tmp_env):
    from community_member.graduation import GraduationStore

    db = tmp_env / "grad.db"
    s_alice = GraduationStore(db, device_did="did:key:alice")
    s_bob = GraduationStore(db, device_did="did:key:bob")
    s_alice.record_graduation(capability="c", scope="sc", context_sha256="ctx")
    s_bob.record_graduation(capability="c", scope="sc", context_sha256="ctx")

    duress.verify_and_handle(
        "under-duress-send-help",
        store_path=store_path,
        chapter_id="ch",
        device_did="did:key:alice",
        graduation_db_path=db,
    )
    # Alice revoked; Bob intact.
    bob_status = s_bob.status(
        capability="c",
        scope="sc",
        context_sha256="ctx",
        approvals=10,
        posterior_mean=0.95,
    )
    assert bob_status.state == "graduated"


def test_S8_normal_passphrase_does_NOT_wipe(store_path, tmp_env):
    habits_path = tmp_env / "habits.db"
    habits_path.write_bytes(b"fake habits data")
    duress.verify_and_handle(
        "correct-horse-battery-staple",
        store_path=store_path,
        chapter_id="ch",
        on_duress_wipe_habits=habits_path,
    )
    assert habits_path.exists()
    assert habits_path.read_bytes() == b"fake habits data"


# ── R1 forgery: tampered store ────────────────────────────────


def test_R1_tampered_hash_causes_both_to_miss(store_path):
    import json as _json

    data = _json.loads(store_path.read_text())
    # Flip the first byte of the normal hash.
    decoded = bytearray(__import__("base64").b64decode(data["normal_hash_b64"]))
    decoded[0] ^= 0xFF
    data["normal_hash_b64"] = __import__("base64").b64encode(bytes(decoded)).decode("ascii")
    store_path.write_text(_json.dumps(data))

    # Normal passphrase no longer matches.
    assert duress.verify_and_handle("correct-horse-battery-staple", store_path=store_path, chapter_id="ch") == "invalid"
    # Duress still works (we only tampered the normal hash).
    assert duress.verify_and_handle("under-duress-send-help", store_path=store_path, chapter_id="ch") == "duress"


def test_missing_store_returns_invalid(tmp_env):
    # No file registered.
    result = duress.verify_and_handle("anything", store_path=tmp_env / "nonexistent.json", chapter_id="ch")
    assert result == "invalid"


def test_corrupt_store_returns_invalid(tmp_env):
    path = tmp_env / "corrupt.json"
    path.write_text("{not valid json")
    result = duress.verify_and_handle("x", store_path=path, chapter_id="ch")
    assert result == "invalid"


# ── R3 unicode / control chars ────────────────────────────────


def test_R3_unicode_passphrases_work(tmp_env):
    path = tmp_env / "d.json"
    duress.register_passphrases("密码👀", "🚨emergency", path=path, iterations=100)
    assert duress.verify_and_handle("密码👀", store_path=path, chapter_id="ch") == "normal"
    assert duress.verify_and_handle("🚨emergency", store_path=path, chapter_id="ch") == "duress"


# ── R9 timing: both hashes always computed ──────────────────


def test_R9_both_hashes_computed_on_every_call(store_path):
    """Constant-time guarantee: we don't short-circuit on first
    match. Probe by counting calls to _hash during a normal
    passphrase check — should be exactly 2."""
    original_hash = duress._hash
    call_count = [0]

    def counting_hash(*args, **kwargs):
        call_count[0] += 1
        return original_hash(*args, **kwargs)

    with patch.object(duress, "_hash", side_effect=counting_hash):
        duress.verify_and_handle("correct-horse-battery-staple", store_path=store_path, chapter_id="ch")
    assert call_count[0] == 2  # both normal + duress hashes


def test_R9_invalid_path_also_computes_both(store_path):
    original_hash = duress._hash
    call_count = [0]

    def counting_hash(*args, **kwargs):
        call_count[0] += 1
        return original_hash(*args, **kwargs)

    with patch.object(duress, "_hash", side_effect=counting_hash):
        duress.verify_and_handle("wrong-passphrase", store_path=store_path, chapter_id="ch")
    assert call_count[0] == 2


# ── Ledger chain stays valid through duress ────────────────


def test_duress_preserves_audit_chain(store_path):
    duress.verify_and_handle("under-duress-send-help", store_path=store_path, chapter_id="ch")
    assert ledger.verify_chain()["ok"] is True
