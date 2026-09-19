"""
R1-R10 + S tests for endorsements.record_endorsement / revoke / list.

R1  Forgery       — bad signature → invalid_signature, no DB row, no trust event
R2  Replay        — same endorser+endorsee twice → row updated, no double trust event
R3  Injection     — note_markdown is stored verbatim (the renderer escapes)
R4  Authz         — endorser trust below MIN_ENDORSER_TRUST → rejected
R5  Boundary      — endorser_trust == MIN_ENDORSER_TRUST → accepted; -0.001 → rejected
R6  Concurrency   — two simultaneous endorsements collapse via UNIQUE pair
R7  Adversarial   — self-endorsement rejected service-side AND DB CHECK
R8  Downgrade     — revoke_endorsement deletes via soft-delete + emits
                    revocation_received trust event
R9  Identity       — verify_endorsement_signature rejects modified canonical fields
R10 Persistence   — refresh leaves the original endorsement_received trust row
                    in place (idempotent at UNIQUE level)
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import base64  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from decimal import Decimal  # noqa: E402

import pytest  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import endorsements  # noqa: E402
import trust_events  # noqa: E402

# ── Helpers ────────────────────────────────────────────────────────


def _make_keypair() -> tuple[str, str]:
    sk = SigningKey.generate()
    priv = base64.b64encode(bytes(sk)).decode()
    pub = base64.b64encode(bytes(sk.verify_key)).decode()
    return priv, pub


def _sign(priv_b64: str, *, chapter_id: str, endorser_did: str, endorsee_agent_id: str, ts: int) -> str:
    sig, _ = endorsements.create_endorsement_signature(
        private_key_b64=priv_b64,
        chapter_id=chapter_id,
        endorser_did=endorser_did,
        endorsee_agent_id=endorsee_agent_id,
        created_unix=ts,
    )
    return sig


# ── Fake Postgres ──────────────────────────────────────────────────


class _FakePostgres:
    """Minimal Postgres-via-PostgREST mock with the trigger emulation
    that test_trust_accrual already pinned in place."""

    def __init__(self, endorser_trust: dict[str, float] | None = None):
        self.trust_events: list[dict] = []
        self.agents: list[dict] = []
        self.endorsements: list[dict] = []
        self._next_event_id = 1
        self._next_endorse_id = 1
        for aid, score in (endorser_trust or {}).items():
            self.agents.append({"agent_id": aid, "trust_score": float(score)})

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        # PATCH-by-filter — the filter now rides in params=, not the path.
        if method == "PATCH":
            kvs = dict(params or {})
            if "?" in table:
                qs = table.split("?", 1)[1]
                kvs.update({p.split("=", 1)[0]: p.split("=", 1)[1] for p in qs.split("&")})
            target_id = int(str(kvs["id"]).replace("eq.", ""))
            for r in getattr(self, t):
                if r.get("id") == target_id:
                    r.update(body or {})
                    return [r]
            return []

        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
                elif isinstance(v, str) and v == "is.null":
                    rows = [r for r in rows if r.get(k) is None]
                elif isinstance(v, str) and v.startswith("gte."):
                    wanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) >= wanted]
            limit = (params or {}).get("limit")
            if limit is not None:
                rows = rows[: int(limit)]
            return rows

        if method == "POST" and t == "trust_events":
            row = dict(body or {})
            if any(
                r.get("agent_id") == row.get("agent_id")
                and r.get("event_type") == row.get("event_type")
                and r.get("source_event_id") == row.get("source_event_id")
                for r in self.trust_events
            ):
                raise RuntimeError("duplicate key value violates unique constraint")
            sa = row.get("source_agent_id")
            if sa is not None and sa == row.get("agent_id"):
                raise RuntimeError("trust_events_no_self violated")
            row["id"] = self._next_event_id
            row["occurred_at"] = row.get("occurred_at") or datetime.now(UTC).isoformat()
            self._next_event_id += 1
            self.trust_events.append(row)
            agent = next((a for a in self.agents if a.get("agent_id") == row["agent_id"]), None)
            if agent is None:
                agent = {"agent_id": row["agent_id"], "trust_score": 0.0}
                self.agents.append(agent)
            agent["trust_score"] = float(
                Decimal(str(agent.get("trust_score") or 0)) + Decimal(str(row.get("delta") or "0"))
            )
            return [row]

        if method == "POST" and t == "endorsements":
            row = dict(body or {})
            if any(
                r.get("endorser_agent_id") == row.get("endorser_agent_id")
                and r.get("endorsee_agent_id") == row.get("endorsee_agent_id")
                for r in self.endorsements
            ):
                raise RuntimeError("endorsements_unique_pair violated")
            if row.get("endorser_agent_id") == row.get("endorsee_agent_id"):
                raise RuntimeError("endorsements_no_self violated")
            row["id"] = self._next_endorse_id
            row["created_at"] = datetime.now(UTC).isoformat()
            self._next_endorse_id += 1
            self.endorsements.append(row)
            return [row]

        return None


@pytest.fixture
def env():
    """Return (db, endorser_priv, endorser_pub) — endorser bootstrapped at
    trust_score=20 by default."""
    priv, pub = _make_keypair()
    db = _FakePostgres(endorser_trust={"alice": 20.0})
    endorsements.init(db, "test-chapter")
    trust_events.init(db, "test-chapter")
    return db, priv, pub


# ── R1: forgery (bad signature) ────────────────────────────────────


@pytest.mark.asyncio
async def test_R1_bad_signature_rejected(env):
    db, _priv, pub = env
    ts = 1700000000
    result = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=base64.b64encode(b"\x00" * 64).decode(),
        created_unix=ts,
        note_markdown="should not work",
    )
    assert result.get("error") == "invalid_signature"
    assert db.endorsements == []
    assert db.trust_events == []


# ── R2: replay leaves trust event count unchanged ──────────────────


@pytest.mark.asyncio
async def test_R2_re_endorsement_does_not_double_mint(env):
    db, priv, pub = env
    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)

    first = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
        note_markdown="great mentor",
    )
    assert first["ok"] is True
    assert first["refreshed"] is False
    assert first["trust_event_minted"] is True

    sig2 = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts + 60)
    second = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig2,
        created_unix=ts + 60,
        note_markdown="even better",
    )
    assert second["ok"] is True
    assert second["refreshed"] is True
    # No new trust event — UNIQUE source_event_id kept it idempotent.
    assert second["trust_event_minted"] is False
    assert len(db.endorsements) == 1
    assert len([r for r in db.trust_events if r["event_type"] == "endorsement_received"]) == 1


# ── R3: note_markdown stored verbatim (renderer escapes) ──────────


@pytest.mark.asyncio
async def test_R3_note_markdown_stored_verbatim(env):
    db, priv, pub = env
    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)
    await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
        note_markdown="<script>alert('xss')</script>",
    )
    # Stored verbatim — sanitization is the renderer's job.
    assert db.endorsements[0]["note_markdown"] == "<script>alert('xss')</script>"


# ── R4: authz — endorser trust gate ────────────────────────────────


@pytest.mark.asyncio
async def test_R4_endorser_below_floor_rejected():
    priv, pub = _make_keypair()
    db = _FakePostgres(endorser_trust={"alice": 19.999})
    endorsements.init(db, "test-chapter")
    trust_events.init(db, "test-chapter")

    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)
    result = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    assert "endorser_trust_below_floor" in result.get("error", "")
    assert db.endorsements == []
    assert db.trust_events == []


# ── R5: boundary at MIN_ENDORSER_TRUST ─────────────────────────────


@pytest.mark.asyncio
async def test_R5_endorser_at_exact_floor_accepted():
    priv, pub = _make_keypair()
    db = _FakePostgres(endorser_trust={"alice": 20.0})
    endorsements.init(db, "test-chapter")
    trust_events.init(db, "test-chapter")

    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)
    result = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    assert result["ok"] is True


# ── R6: concurrent endorsement of same pair → UNIQUE wins ─────────


@pytest.mark.asyncio
async def test_R6_concurrent_endorsements_same_pair_collapse():
    import asyncio

    priv, pub = _make_keypair()
    db = _FakePostgres(endorser_trust={"alice": 20.0})
    endorsements.init(db, "test-chapter")
    trust_events.init(db, "test-chapter")

    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)

    async def emit():
        try:
            return await endorsements.record_endorsement(
                endorser_agent_id="alice",
                endorser_did="did:key:zAlice",
                endorsee_agent_id="bob",
                endorser_pubkey_b64=pub,
                signature_b64=sig,
                created_unix=ts,
            )
        except RuntimeError:
            return None

    await asyncio.gather(emit(), emit())
    # Even with the race, only one row exists (or one row + a refreshed update).
    assert len(db.endorsements) == 1


# ── R7: self-endorsement rejected ──────────────────────────────────


@pytest.mark.asyncio
async def test_R7_self_endorsement_rejected_service_layer(env):
    _, priv, pub = env
    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="alice", ts=ts)
    result = await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="alice",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    assert result.get("error") == "self-endorsement rejected"


# ── R8: revoke_endorsement emits revocation_received ──────────────


@pytest.mark.asyncio
async def test_R8_revoke_emits_compensating_trust_event(env):
    db, priv, pub = env
    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)
    await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    # Bob's trust = +0.5 from the endorsement.
    bob = next(a for a in db.agents if a["agent_id"] == "bob")
    assert Decimal(str(bob["trust_score"])) == Decimal("0.5")

    result = await endorsements.revoke_endorsement(
        endorser_agent_id="alice",
        endorsee_agent_id="bob",
        revocation_reason="actually we never met",
    )
    assert result["ok"] is True
    assert result["trust_event_minted"] is True
    # Bob's trust = +0.5 - 1.0 = -0.5.
    bob = next(a for a in db.agents if a["agent_id"] == "bob")
    assert Decimal(str(bob["trust_score"])) == Decimal("-0.5")


# ── R9: signature verification covers all canonical fields ────────


def test_R9_modified_endorsee_fails_verification():
    priv, pub = _make_keypair()
    ts = 1700000000
    sig, _ts = endorsements.create_endorsement_signature(
        private_key_b64=priv,
        chapter_id="test-chapter",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        created_unix=ts,
    )
    # Same sig, different endorsee → must fail.
    ok = endorsements.verify_endorsement_signature(
        endorser_pubkey_b64=pub,
        chapter_id="test-chapter",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="carol",  # tampered
        created_unix=ts,
        signature_b64=sig,
    )
    assert ok is False


def test_R9_modified_chapter_id_fails_verification():
    priv, pub = _make_keypair()
    ts = 1700000000
    sig, _ts = endorsements.create_endorsement_signature(
        private_key_b64=priv,
        chapter_id="test-chapter",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        created_unix=ts,
    )
    ok = endorsements.verify_endorsement_signature(
        endorser_pubkey_b64=pub,
        chapter_id="other-chapter",  # tampered
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        created_unix=ts,
        signature_b64=sig,
    )
    assert ok is False


# ── R10: refresh leaves original trust_event in place ─────────────


@pytest.mark.asyncio
async def test_R10_refresh_does_not_re_mint_trust_event(env):
    db, priv, pub = env
    ts = 1700000000
    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)

    await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    score_a = await trust_events.replay_score("bob")
    sig2 = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts + 10)
    await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig2,
        created_unix=ts + 10,
    )
    score_b = await trust_events.replay_score("bob")
    assert score_a == score_b == Decimal("0.5")


# ── list_endorsements_received ────────────────────────────────────


@pytest.mark.asyncio
async def test_list_endorsements_received_excludes_revoked_by_default(env):
    _, priv, pub = env
    ts = 1700000000

    # Two endorsers — alice and a synthetic carol with sufficient trust.
    db = env[0]
    db.agents.append({"agent_id": "carol", "trust_score": 25.0})
    priv2, pub2 = _make_keypair()

    sig = _sign(priv, chapter_id="test-chapter", endorser_did="did:key:zAlice", endorsee_agent_id="bob", ts=ts)
    sig2 = _sign(priv2, chapter_id="test-chapter", endorser_did="did:key:zCarol", endorsee_agent_id="bob", ts=ts)
    await endorsements.record_endorsement(
        endorser_agent_id="alice",
        endorser_did="did:key:zAlice",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub,
        signature_b64=sig,
        created_unix=ts,
    )
    await endorsements.record_endorsement(
        endorser_agent_id="carol",
        endorser_did="did:key:zCarol",
        endorsee_agent_id="bob",
        endorser_pubkey_b64=pub2,
        signature_b64=sig2,
        created_unix=ts,
    )
    await endorsements.revoke_endorsement(
        endorser_agent_id="alice",
        endorsee_agent_id="bob",
    )
    live = await endorsements.list_endorsements_received("bob")
    all_rows = await endorsements.list_endorsements_received("bob", include_revoked=True)
    assert len(live) == 1
    assert live[0]["endorser_agent_id"] == "carol"
    assert len(all_rows) == 2
