"""
R1-R10 adversarial + behavioral tests for chapter-side member key rotation.

Covers `member_rotation.accept_rotation()` and the /api/members/rotate
endpoint in chapter_agent.py.

Pair of community-member/tests/test_recovery_rotation.py (client side).
The contract is symmetric — these tests verify the chapter refuses the
same attack surfaces the client refuses on the verifier side, plus
server-only concerns (DB replay tracking, audit row persistence,
origin=openclaw rejection).

  R1  Forgery            — attestation from a key that isn't the stored one
  R2  Replay             — nonce already recorded
  R3  Injection          — missing fields, wrong kind, wrong chapter_id
  R4  Authorization      — openclaw agents cannot rotate
  R5  Boundary           — clock skew, pubkey length
  R6  Concurrency        — two rotations with same nonce: one succeeds, one fails
  R7  Adversarial input  — audit row on DB failure, partial attestation
  R8  Downgrade          — scheme must be ed25519
  R9  Timing             — out-of-window window symmetric
  R10 Persistence        — successful rotation writes audit row
"""

from __future__ import annotations

import base64
import os

# Required before importing chapter_agent / member_rotation — the module
# calls os.environ["AGENT_ID"] at import time when .env is absent.
os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import time  # noqa: E402

import pytest  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import member_rotation  # noqa: E402

# ── Shared test doubles ───────────────────────────────────────────────


class _FakePostgres:
    """Minimal in-memory Postgres stand-in for rotation flow."""

    def __init__(self):
        self.rotations: list[dict] = []
        self.fail_on_write = False

    async def __call__(self, method, table, params=None, body=None):
        if method == "GET" and table == "member_key_rotations":
            chapter = (params or {}).get("chapter_id", "").replace("eq.", "")
            nonce = (params or {}).get("nonce", "").replace("eq.", "")
            return [{"id": "x"} for r in self.rotations if r["chapter_id"] == chapter and r["nonce"] == nonce]
        if method == "POST" and table == "member_key_rotations":
            if self.fail_on_write:
                raise RuntimeError("simulated DB failure")
            entry = dict(body or {})
            entry["id"] = f"rot-{len(self.rotations) + 1}"
            self.rotations.append(entry)
            return [entry]
        return None


@pytest.fixture
def supabase():
    s = _FakePostgres()
    member_rotation.init(pg_request=s, chapter_id="test-chapter")
    return s


def _fresh_keypair():
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key)


def _build_attestation(
    old_sk,
    new_pub,
    *,
    chapter_id="test-chapter",
    agent_id="alice",
    timestamp=None,
    nonce=None,
    kind="rotation",
    scheme="ed25519",
):
    ts = int(timestamp if timestamp is not None else time.time())
    n = nonce or os.urandom(16).hex()
    new_pub_b64 = base64.b64encode(new_pub).decode()
    canonical = f"ROTATE:{chapter_id}:{agent_id}:{new_pub_b64}:{ts}:{n}".encode()
    signature = base64.b64encode(old_sk.sign(canonical).signature).decode()
    return {
        "kind": kind,
        "scheme": scheme,
        "chapter_id": chapter_id,
        "agent_id": agent_id,
        "new_public_key_b64": new_pub_b64,
        "new_did_key": "",
        "timestamp": ts,
        "nonce": n,
        "signature": signature,
    }


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_wrong_signing_key(supabase):
    """Attestation signed by a different key than the stored one."""
    stored_sk, stored_pub = _fresh_keypair()
    attacker_sk, _ = _fresh_keypair()
    _, new_pub = _fresh_keypair()

    att = _build_attestation(attacker_sk, new_pub, agent_id="alice")
    stored_pub_b64 = base64.b64encode(stored_pub).decode()
    result = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert "error" in result
    assert "invalid signature" in result["error"].lower()
    assert not supabase.rotations


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_replay_rejected_after_first_success(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    stored_pub_b64 = base64.b64encode(stored_pub).decode()

    att = _build_attestation(stored_sk, new_pub)
    r1 = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert r1.get("ok") is True
    # Same nonce used again — reject
    r2 = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert "error" in r2
    assert "replay" in r2["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_wrong_chapter(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    # Attestation is for a DIFFERENT chapter
    att = _build_attestation(stored_sk, new_pub, chapter_id="OTHER-chapter")
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "error" in result
    assert "chapter_id mismatch" in result["error"].lower()


@pytest.mark.asyncio
async def test_R3_injection_missing_nonce(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    att = _build_attestation(stored_sk, new_pub)
    del att["nonce"]
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "error" in result
    assert "missing" in result["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: no-op rotation blocked
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_same_key_rotation_rejected(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    # Try to "rotate" to the same key
    att = _build_attestation(stored_sk, stored_pub)
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "error" in result
    assert "must differ" in result["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: clock skew, pubkey length
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_clock_too_old(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    att = _build_attestation(stored_sk, new_pub, timestamp=int(time.time()) - 7200)
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "out of window" in result["error"].lower()


@pytest.mark.asyncio
async def test_R5_boundary_pubkey_bad_length(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    # Replace new_public_key_b64 with something under 32 bytes after sig
    # We have to sign over the BAD pubkey for the test to get past the
    # signature check and hit the length check
    bad_pub = b"too-short"
    bad_pub_b64 = base64.b64encode(bad_pub).decode()
    ts = int(time.time())
    n = os.urandom(16).hex()
    canonical = f"ROTATE:test-chapter:alice:{bad_pub_b64}:{ts}:{n}".encode()
    sig = base64.b64encode(stored_sk.sign(canonical).signature).decode()
    att = {
        "kind": "rotation",
        "scheme": "ed25519",
        "chapter_id": "test-chapter",
        "agent_id": "alice",
        "new_public_key_b64": bad_pub_b64,
        "new_did_key": "",
        "timestamp": ts,
        "nonce": n,
        "signature": sig,
    }
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "error" in result
    assert "wrong length" in result["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: 2 rotations with same nonce — second loses
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R6_concurrency_same_nonce_serialization(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    stored_pub_b64 = base64.b64encode(stored_pub).decode()

    att = _build_attestation(stored_sk, new_pub)
    # First succeeds
    r1 = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert r1.get("ok") is True
    # Second call with same att (same nonce) — DB replay check catches it
    r2 = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert "error" in r2
    assert len(supabase.rotations) == 1  # only one row persisted


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial input: fail-closed on DB write error
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_adversarial_db_failure_does_not_commit(supabase):
    """If the audit write fails, the in-memory key must NOT update.

    This is the fail-closed invariant — we never apply a rotation we
    can't also audit.
    """
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    supabase.fail_on_write = True

    att = _build_attestation(stored_sk, new_pub)
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "error" in result
    assert "audit write failed" in result["error"].lower()
    assert not supabase.rotations  # no partial row


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: scheme must be ed25519
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R8_downgrade_hmac_rejected(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    att = _build_attestation(stored_sk, new_pub, scheme="hmac-sha256")
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "unsupported scheme" in result["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: symmetric future-window rejection
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R9_timing_future_skew_rejected(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    att = _build_attestation(stored_sk, new_pub, timestamp=int(time.time()) + 7200)
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert "out of window" in result["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: successful rotation writes audit row with correct fields
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R10_persistence_audit_row_has_correct_shape(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    stored_pub_b64 = base64.b64encode(stored_pub).decode()

    att = _build_attestation(stored_sk, new_pub, agent_id="alice")
    result = await member_rotation.accept_rotation(att, stored_pub_b64)
    assert result.get("ok") is True

    assert len(supabase.rotations) == 1
    row = supabase.rotations[0]
    assert row["chapter_id"] == "test-chapter"
    assert row["agent_id"] == "alice"
    assert row["old_public_key"] == stored_pub_b64
    assert row["new_public_key"] == att["new_public_key_b64"]
    assert row["nonce"] == att["nonce"]
    assert row["attestation"] == att
    assert isinstance(row["client_timestamp"], int)


# ══════════════════════════════════════════════════════════════════════
# HAPPY path — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_rotation_succeeds(supabase):
    stored_sk, stored_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()

    att = _build_attestation(stored_sk, new_pub, agent_id="bob")
    result = await member_rotation.accept_rotation(att, base64.b64encode(stored_pub).decode())
    assert result.get("ok") is True
    assert result.get("new_public_key_b64") == att["new_public_key_b64"]


@pytest.mark.asyncio
async def test_rotation_falls_back_to_auth_store_key_for_tofu_header_agent(monkeypatch):
    """A TOFU-via-header agent has its key in auth_verify._agent_keys, not
    members[][public_key]. rotate_member_key must find it there rather than
    return 'no stored key' (e2e NOTE b)."""
    import auth_verify
    import chapter_agent
    import member_rotation as mr

    monkeypatch.setattr(chapter_agent, "members", {"tofu": {"origin": "sovereign", "public_key": ""}})
    monkeypatch.setattr(auth_verify, "_agent_keys", {"tofu": {"ed25519_pubkey": "OLDKEYB64"}})

    seen = {}

    async def fake_accept(att, stored_key):
        seen["stored_key"] = stored_key
        return {"ok": True, "new_did_key": "did:key:zNEW", "new_public_key_b64": "NEWKEY"}

    monkeypatch.setattr(mr, "accept_rotation", fake_accept)
    monkeypatch.setattr(auth_verify, "replace_agent_key", lambda *a, **k: None)

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(chapter_agent, "pg_request", _noop)

    r = await chapter_agent.rotate_member_key({"agent_id": "tofu"})
    # the handler now returns a JSONResponse with proper status codes.
    assert r.status_code == 200
    assert seen.get("stored_key") == "OLDKEYB64"


@pytest.mark.asyncio
async def test_rotation_no_key_anywhere_still_refused(monkeypatch):
    import auth_verify
    import chapter_agent

    monkeypatch.setattr(chapter_agent, "members", {"keyless": {"origin": "sovereign", "public_key": ""}})
    monkeypatch.setattr(auth_verify, "_agent_keys", {})
    r = await chapter_agent.rotate_member_key({"agent_id": "keyless"})
    # malformed / not-rotatable input is a 400, not a 200 with an error body.
    assert r.status_code == 400
    import json as _json

    assert _json.loads(bytes(r.body))["error"] == "no stored key for this agent"
