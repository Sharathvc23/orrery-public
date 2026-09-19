"""R1-R10 tests for chapter.admin — system-level operator credential.

R1  Forgery     — empty / wrong / garbage tokens reject
R2  Replay      — same valid token accepted on repeat calls (no nonce)
R3  Injection   — token containing shell / SQL / null bytes never crashes
                  the verifier (constant-time compare doesn't barf)
R4  Authz       — admin token cannot impersonate a member (verify_admin_token
                  is namespace-distinct from member auth)
R5  Boundary    — empty stored token never authenticates anything,
                  even empty provided token
R7  Adversarial — constant-time compare resists timing oracle (smoke test
                  only — not a real timing-side-channel statistical test)
R8  Rotation    — force_regenerate invalidates the old token immediately
R10 Persistence — round-trip generate → write to disk → re-init in fresh
                  process state → token verifies
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import importlib

import pytest

import admin as admin_mod


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """Each test starts with no admin token in env and a clean token file
    location under tmp_path so tests don't stomp on each other or the
    chapter dir's real token."""
    monkeypatch.delenv("CHAPTER_ADMIN_TOKEN", raising=False)
    monkeypatch.setenv("CHAPTER_HOME", str(tmp_path))
    # Reset module-level state — every test should look like a fresh import.
    importlib.reload(admin_mod)
    return tmp_path


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_wrong_token_rejected(clean_env):
    admin_mod.init()
    assert admin_mod.verify_admin_token("a" * 64) is False
    assert admin_mod.verify_admin_token("totally-wrong") is False
    assert admin_mod.verify_admin_token("") is False


def test_R1_forgery_unset_admin_never_authenticates(clean_env):
    # Don't init() — admin token never resolved
    assert admin_mod.verify_admin_token("") is False
    assert admin_mod.verify_admin_token("a" * 64) is False


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay (valid token accepted on repeat — no nonce required)
# ══════════════════════════════════════════════════════════════════════


def test_R2_replay_valid_token_accepted_repeatedly(clean_env):
    token, _ = admin_mod.init()
    for _ in range(10):
        assert admin_mod.verify_admin_token(token) is True


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_garbage_tokens_dont_crash(clean_env):
    admin_mod.init()
    nasty = [
        "'; DROP TABLE agents; --",
        "<script>alert(1)</script>",
        "\x00\x00\x00",
        "✓ valid? — no",
        "\n\n\n",
        "x" * 10_000,
    ]
    for n in nasty:
        # Must return False, must not raise
        assert admin_mod.verify_admin_token(n) is False


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: admin token namespace is distinct from member auth
# ══════════════════════════════════════════════════════════════════════


def test_R4_admin_token_does_not_resolve_to_a_member(clean_env):
    """verify_admin_token returns a bool. There is no agent_id surface
    on it — it cannot accidentally be wired up as member auth. This is
    a structural assertion."""
    token, _ = admin_mod.init()
    result = admin_mod.verify_admin_token(token)
    assert isinstance(result, bool)
    # No "agent_id" / "did_key" / "identity" leakage — admin auth is
    # explicitly NOT a member identity.
    assert not hasattr(admin_mod, "resolve_admin_to_agent_id")


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: empty stored token never authenticates
# ══════════════════════════════════════════════════════════════════════


def test_R5_empty_stored_token_refuses_everything(clean_env):
    # Don't init — _admin_token stays empty
    assert admin_mod.verify_admin_token("") is False
    assert admin_mod.verify_admin_token("anything") is False
    # Even the empty-vs-empty case must refuse — otherwise misconfigured
    # deploys would silently expose the admin surface.
    assert admin_mod.is_initialized() is False


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: constant-time compare (smoke test)
# ══════════════════════════════════════════════════════════════════════


def test_R7_compare_uses_hmac_compare_digest():
    """Smoke-test that verify_admin_token uses compare_digest, not ==.

    A real timing-oracle test requires statistical analysis; this is
    structural — assert the source path uses compare_digest."""
    import inspect

    src = inspect.getsource(admin_mod.verify_admin_token)
    assert "compare_digest" in src


# ══════════════════════════════════════════════════════════════════════
# R8 — Rotation: force_regenerate invalidates the old token
# ══════════════════════════════════════════════════════════════════════


def test_R8_rotation_invalidates_old_token(clean_env):
    old_token, _ = admin_mod.init()
    assert admin_mod.verify_admin_token(old_token) is True

    new_token, freshly = admin_mod.init(force_regenerate=True)
    assert freshly is True
    assert new_token != old_token
    assert admin_mod.verify_admin_token(new_token) is True
    assert admin_mod.verify_admin_token(old_token) is False


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: round-trip
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_token_survives_reload(clean_env):
    token1, freshly = admin_mod.init()
    assert freshly is True

    # Simulate process restart: reload the module, re-init.
    importlib.reload(admin_mod)
    token2, freshly2 = admin_mod.init()
    assert freshly2 is False  # NOT freshly generated; loaded from disk
    assert token2 == token1


def test_R10_env_wins_over_file(clean_env, monkeypatch):
    """If CHAPTER_ADMIN_TOKEN env is set, it takes precedence over the
    file. Operator who pastes a token into Railway env vars expects
    that to be authoritative."""
    file_token, _ = admin_mod.init()
    env_token = "b" * 64
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", env_token)
    importlib.reload(admin_mod)
    resolved, freshly = admin_mod.init()
    assert freshly is False
    assert resolved == env_token
    # The file-token is now stale; env is the authority.
    assert admin_mod.verify_admin_token(env_token) is True
    assert admin_mod.verify_admin_token(file_token) is False


def test_R10_token_file_mode_0600(clean_env):
    """Token file must be mode 0600 — no group or world access."""
    admin_mod.init()
    p = admin_mod.token_file_path()
    assert p is not None and p.exists()
    mode = oct(p.stat().st_mode)[-3:]
    assert mode == "600", f"expected 0600, got {mode}"


# ══════════════════════════════════════════════════════════════════════
# Token shape
# ══════════════════════════════════════════════════════════════════════


def test_token_is_64_hex_characters(clean_env):
    token, _ = admin_mod.init()
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token), "non-hex char in token"


def test_two_generations_produce_distinct_tokens():
    t1 = admin_mod.generate_token()
    t2 = admin_mod.generate_token()
    assert t1 != t2
    assert len(t1) == 64
    assert len(t2) == 64
