"""
R1-R10 tests for attestations.py — Ed25519-signed skill vouches.

R1  Forgery      — wrong-key signature rejected
R2  Replay       — UNIQUE constraint on (chapter, skill_id, version, attestor) dedup
R3  Injection    — note_markdown is data not code
R4  Authz        — self-attestation rejected (author == attestor)
R5  Boundary     — trust tier value must be trusted or leader
R6  Concurrency  — two concurrent attestations for the same version from
                    different advisors both succeed (no interaction)
R7  Adversarial  — wrong-length attestor pubkey, malformed signature
R8  Downgrade    — revoke hides from live list but keeps audit row
R9  Timing       — verify uses pynacl VerifyKey (constant-time internally)
R10 Persistence  — canonical-string roundtrip deterministic
"""

from __future__ import annotations

import base64
import os
import time

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import attestations  # noqa: E402


class _FakePostgres:
    def __init__(self):
        self.chapter_skill_attestations: list[dict] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        t = table_or_path.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if v.startswith("is.null"):
                    rows = [r for r in rows if r.get(k) is None]
                else:
                    wanted = v.replace("eq.", "")
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
            return rows
        if method == "POST":
            target = getattr(self, t, None)
            if not isinstance(target, list):
                return None
            # Simulate the UNIQUE (chapter_id, skill_id, skill_version, attestor_did) constraint
            body_dict = dict(body or {})
            for existing in target:
                if (
                    existing.get("chapter_id") == body_dict.get("chapter_id")
                    and existing.get("skill_id") == body_dict.get("skill_id")
                    and existing.get("skill_version") == body_dict.get("skill_version")
                    and existing.get("attestor_did") == body_dict.get("attestor_did")
                ):
                    raise RuntimeError("duplicate key violates unique constraint")
            body_dict["id"] = f"att-{len(target) + 1}"
            target.append(body_dict)
            return [body_dict]
        if method == "PATCH":
            # /api?chapter_id=eq.X&skill_id=eq.Y&skill_version=eq.Z&attestor_did=eq.W
            target = getattr(self, t, [])
            if not isinstance(target, list):
                return []
            filters = {}
            if "?" in table_or_path:
                for pair in table_or_path.split("?", 1)[1].split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        filters[k] = v.replace("eq.", "")
            matched = []
            for row in target:
                if all(str(row.get(k, "")) == v for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched
        return None


@pytest.fixture
def supabase():
    s = _FakePostgres()
    attestations.init(pg_request=s, chapter_id="test-chapter")
    return s


def _fresh_keypair():
    sk = SigningKey.generate()
    priv_b64 = base64.b64encode(bytes(sk)).decode()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode()
    did_key = "did:key:z" + pub_b64[:20]  # simplified DID for tests
    return priv_b64, pub_b64, did_key


def _sign_and_record_args(
    *,
    chapter_id="test-chapter",
    skill_id="demo@1.0.0",
    skill_version="1.0.0",
    content_sha256="a" * 64,
    attestor_did="did:key:zADV1",
    attestor_priv=None,
    attestor_pub=None,
    trust_tier="trusted",
    author_did="did:key:zAUTHOR",
    note="",
    created_unix=None,
):
    """Produce a ready-to-call kwargs dict for attestations.record_attestation."""
    if created_unix is None:
        created_unix = int(time.time())
    sig_b64, ts = attestations.create_attestation_signature(
        private_key_b64=attestor_priv,
        chapter_id=chapter_id,
        skill_id=skill_id,
        skill_version=skill_version,
        content_sha256=content_sha256,
        attestor_did=attestor_did,
        created_unix=created_unix,
    )
    return {
        "skill_id": skill_id,
        "skill_version": skill_version,
        "content_sha256": content_sha256,
        "attestor_did": attestor_did,
        "attestor_agent_id": "agent-1",
        "attestor_public_key_b64": attestor_pub,
        "trust_tier_at_attest": trust_tier,
        "attestation_sig_b64": sig_b64,
        "created_unix": ts,
        "note_markdown": note,
        "author_did": author_did,
    }


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: wrong key → rejected
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_wrong_key_rejected(supabase):
    priv, pub, did = _fresh_keypair()
    attacker_priv, _, _ = _fresh_keypair()

    # Sign with ATTACKER key but claim it's from victim
    args = _sign_and_record_args(attestor_priv=attacker_priv, attestor_pub=pub, attestor_did=did)
    r = await attestations.record_attestation(**args)
    assert "error" in r
    assert "invalid attestation signature" in r["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: duplicate attestation dedup by UNIQUE constraint
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_replay_duplicate_attestor_rejected(supabase):
    priv, pub, did = _fresh_keypair()

    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did)
    r1 = await attestations.record_attestation(**args)
    assert r1.get("ok") is True

    # Second attestation from same advisor on same version → unique violation
    r2 = await attestations.record_attestation(**args)
    assert "error" in r2
    assert "duplicate" in r2["error"].lower() or "insert failed" in r2["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: SQL/markdown in note stays as data
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_markdown_note_stored_as_data(supabase):
    priv, pub, did = _fresh_keypair()
    evil = "<script>alert(1)</script> '; DROP TABLE x; --"

    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did, note=evil)
    r = await attestations.record_attestation(**args)
    assert r.get("ok") is True
    assert supabase.chapter_skill_attestations[-1]["note_markdown"] == evil


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: self-attestation rejected
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_self_attestation_rejected(supabase):
    priv, pub, did = _fresh_keypair()

    # Pass the SAME DID as both author and attestor
    args = _sign_and_record_args(
        attestor_priv=priv,
        attestor_pub=pub,
        attestor_did=did,
        author_did=did,  # same as attestor → self-attestation
    )
    r = await attestations.record_attestation(**args)
    assert "error" in r
    assert "self-attestation" in r["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: trust_tier must be in allowed set
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_rejects_tier_member(supabase):
    priv, pub, did = _fresh_keypair()
    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did, trust_tier="member")
    r = await attestations.record_attestation(**args)
    assert "error" in r
    assert "trust_tier" in r["error"].lower()


@pytest.mark.asyncio
async def test_R5_boundary_accepts_tier_trusted(supabase):
    priv, pub, did = _fresh_keypair()
    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did, trust_tier="trusted")
    r = await attestations.record_attestation(**args)
    assert r.get("ok") is True


@pytest.mark.asyncio
async def test_R5_boundary_accepts_tier_leader(supabase):
    priv, pub, did = _fresh_keypair()
    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did, trust_tier="leader")
    r = await attestations.record_attestation(**args)
    assert r.get("ok") is True


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: different advisors on same skill version coexist
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R6_concurrency_two_advisors_same_version(supabase):
    priv_a, pub_a, did_a = _fresh_keypair()
    priv_b, pub_b, did_b = _fresh_keypair()

    r_a = await attestations.record_attestation(
        **_sign_and_record_args(attestor_priv=priv_a, attestor_pub=pub_a, attestor_did=did_a)
    )
    r_b = await attestations.record_attestation(
        **_sign_and_record_args(attestor_priv=priv_b, attestor_pub=pub_b, attestor_did=did_b)
    )
    assert r_a.get("ok") is True
    assert r_b.get("ok") is True
    assert len(supabase.chapter_skill_attestations) == 2


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: malformed pubkey / signature
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_adversarial_wrong_length_pubkey_rejected(supabase):
    priv, _, did = _fresh_keypair()
    short_pub = base64.b64encode(b"tooshort").decode()

    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=short_pub, attestor_did=did)
    r = await attestations.record_attestation(**args)
    assert "error" in r
    assert "wrong length" in r["error"].lower() or "invalid" in r["error"].lower()


@pytest.mark.asyncio
async def test_R7_adversarial_tampered_signature(supabase):
    priv, pub, did = _fresh_keypair()
    args = _sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did)
    # Flip the signature to a definitely-wrong one
    args["attestation_sig_b64"] = base64.b64encode(b"\x00" * 64).decode()
    r = await attestations.record_attestation(**args)
    assert "error" in r


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: revoke hides from list_live_attestations
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R8_downgrade_revoke_excludes_from_live(supabase):
    priv, pub, did = _fresh_keypair()
    await attestations.record_attestation(
        **_sign_and_record_args(attestor_priv=priv, attestor_pub=pub, attestor_did=did)
    )
    live_before = await attestations.list_live_attestations("demo@1.0.0", "1.0.0")
    assert len(live_before) == 1

    result = await attestations.revoke_attestation(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        attestor_did=did,
        revocation_reason="test",
    )
    assert result.get("ok") is True

    live_after = await attestations.list_live_attestations("demo@1.0.0", "1.0.0")
    assert live_after == []
    # Audit row is still there with revoked_at set
    assert len(supabase.chapter_skill_attestations) == 1
    assert supabase.chapter_skill_attestations[0]["revoked_at"] is not None


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: verify function is a clean wrapper around pynacl
# ══════════════════════════════════════════════════════════════════════


def test_R9_timing_verify_function_is_pure():
    priv, pub, did = _fresh_keypair()
    sig, ts = attestations.create_attestation_signature(
        private_key_b64=priv,
        chapter_id="test-chapter",
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        content_sha256="a" * 64,
        attestor_did=did,
    )
    # Called N times with same inputs, same result each time
    results = [
        attestations.verify_attestation_signature(
            attestor_public_key_b64=pub,
            chapter_id="test-chapter",
            skill_id="demo@1.0.0",
            skill_version="1.0.0",
            content_sha256="a" * 64,
            attestor_did=did,
            created_unix=ts,
            attestation_sig_b64=sig,
        )
        for _ in range(10)
    ]
    assert all(r == (True, "valid") for r in results)


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: canonical string is deterministic
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_canonical_string_deterministic():
    # Sign twice with same inputs including same created_unix → same sig
    priv, _, did = _fresh_keypair()
    shared_ts = 1713700000
    sig1, _ = attestations.create_attestation_signature(
        private_key_b64=priv,
        chapter_id="test-chapter",
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        content_sha256="a" * 64,
        attestor_did=did,
        created_unix=shared_ts,
    )
    sig2, _ = attestations.create_attestation_signature(
        private_key_b64=priv,
        chapter_id="test-chapter",
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        content_sha256="a" * 64,
        attestor_did=did,
        created_unix=shared_ts,
    )
    assert sig1 == sig2  # Ed25519 is deterministic


# ══════════════════════════════════════════════════════════════════════
# HAPPY path — kept last
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_full_attestation_roundtrip(supabase):
    priv, pub, did = _fresh_keypair()
    args = _sign_and_record_args(
        attestor_priv=priv,
        attestor_pub=pub,
        attestor_did=did,
        note="Reviewed the repo + ran tests + verified no net.arbitrary usage.",
    )
    r = await attestations.record_attestation(**args)
    assert r.get("ok") is True
    assert r.get("chapter_id") == "test-chapter"

    count = await attestations.count_live_attestations("demo@1.0.0", "1.0.0")
    assert count == 1


def test_happy_constants_are_exposed():
    # Regression guard — surface of the module
    assert hasattr(attestations, "record_attestation")
    assert hasattr(attestations, "revoke_attestation")
    assert hasattr(attestations, "list_live_attestations")
    assert hasattr(attestations, "verify_attestation_signature")
    assert hasattr(attestations, "create_attestation_signature")
