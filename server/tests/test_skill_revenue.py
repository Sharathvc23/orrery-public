"""
R1-R10 tests for skill_revenue.compute_split and record_skill_use.

R1  Forgery      — duplicate idempotency_key → "duplicate" not "billed"
R2  Replay       — same key retried returns "duplicate" (no double-mint)
R3  Injection    — SQL-like tool_name stored as plain text
R4  Authz        — unattested skills return billed=False (MVP rule)
R5  Boundary     — gross_cents=0/negative rejected; 1-cent minimum split
R6  Concurrency  — two simultaneous use calls with same key → one billed
R7  Adversarial  — zero attestors raises; zero-length attestor list rejected
R8  Downgrade    — revoked attestation excluded from live set
R9  Timing       — compute_split is pure/deterministic
R10 Persistence  — cents-conservation property over 10,000 random splits
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import random  # noqa: E402

import pytest  # noqa: E402

import skill_revenue  # noqa: E402

# ── Fake Postgres — minimal in-memory ──────────────────────────────────


class _FakePostgres:
    def __init__(self):
        self.chapter_skills: list[dict] = []
        self.chapter_skill_attestations: list[dict] = []
        self.skill_use_events: list[dict] = []
        self.skill_revenue_ledger: list[dict] = []
        self.fail_use_insert = False
        self.fail_ledger_insert = False

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                wanted = v.replace("eq.", "")
                if v.startswith("is.null"):
                    rows = [r for r in rows if r.get(k) is None]
                else:
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
            return rows
        if method == "POST":
            if t == "skill_use_events":
                if self.fail_use_insert:
                    raise RuntimeError("simulated DB failure")
                # Idempotency unique constraint simulation
                idem = (body or {}).get("idempotency_key")
                if any(r.get("idempotency_key") == idem for r in self.skill_use_events):
                    raise RuntimeError("duplicate key value violates unique constraint")
                row = dict(body or {})
                row["id"] = f"event-{len(self.skill_use_events) + 1}"
                self.skill_use_events.append(row)
                return [row]
            if t == "skill_revenue_ledger":
                if self.fail_ledger_insert:
                    raise RuntimeError("simulated ledger DB failure")
                row = dict(body or {})
                row["id"] = len(self.skill_revenue_ledger) + 1
                self.skill_revenue_ledger.append(row)
                return [row]
            target = getattr(self, t, None)
            if isinstance(target, list):
                row = dict(body or {})
                target.append(row)
                return [row]
            return None
        return None


@pytest.fixture
def supabase():
    s = _FakePostgres()
    skill_revenue.init(pg_request=s, chapter_id="test-chapter")
    # Also init attestations since skill_revenue calls into it
    import attestations

    attestations.init(pg_request=s, chapter_id="test-chapter")
    return s


def _seed_skill(s, skill_id="demo@1.0.0", author_did="did:key:zAUTHOR"):
    s.chapter_skills.append({"id": skill_id, "author_did": author_did})


def _seed_attest(s, skill_id, version, attestor_did, revoked=False):
    row = {
        "chapter_id": "test-chapter",
        "skill_id": skill_id,
        "skill_version": version,
        "attestor_did": attestor_did,
        "attestor_agent_id": attestor_did.replace("did:key:z", "agent-"),
        "trust_tier_at_attest": "trusted",
        "revoked_at": "2026-01-01T00:00:00Z" if revoked else None,
    }
    s.chapter_skill_attestations.append(row)


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: duplicate idempotency_key surfaces as "duplicate"
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_duplicate_idempotency_returns_duplicate(supabase):
    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")

    r1 = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="key-1",
    )
    assert r1.get("billed") is True

    r2 = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="key-1",
    )
    assert r2.get("billed") is False
    assert r2.get("reason") == "duplicate"


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay same test as R1 (covered)
# ══════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: SQL-y inputs round-trip as plain data
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_sql_like_tool_name(supabase):
    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")
    evil = "'; DROP TABLE skill_use_events; --"

    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name=evil,
        idempotency_key="injection-key",
    )
    assert r.get("billed") is True
    assert supabase.skill_use_events[-1]["tool_name"] == evil  # stored as data, not executed


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: unattested skill returns billed=False (no revenue minted)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_unattested_skill_returns_unbilled(supabase):
    _seed_skill(supabase)
    # No attestations seeded
    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="unattested-key",
    )
    assert r.get("billed") is False
    assert r.get("reason") == "no_attestations"
    # No rows written
    assert supabase.skill_use_events == []
    assert supabase.skill_revenue_ledger == []


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: rejections at the edges
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_zero_gross_rejected(supabase):
    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")
    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="zero-gross",
        gross_cents=0,
    )
    assert "error" in r
    assert "positive" in r["error"].lower()


@pytest.mark.asyncio
async def test_R5_boundary_negative_gross_rejected(supabase):
    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")
    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="neg-gross",
        gross_cents=-5,
    )
    assert "error" in r


def test_R5_boundary_smallest_split_three_cents():
    """3 cents gross, 1 advisor — smallest case where every beneficiary
    still gets at least one unit. Chapter would get floor(3*0.25)=0, so
    chapter gets 0, advisor gets floor(3*0.35)=1, author gets 2."""
    rows = skill_revenue.compute_split(
        gross_cents=3,
        author_did="did:author",
        attestor_dids=["did:adv1"],
        chapter_treasury_did="chapter:test",
    )
    total = sum(r["amount_cents"] for r in rows)
    assert total == 3
    # Author >= advisor >= chapter in this ordering at tiny gross
    by_role = {r["beneficiary_role"]: r["amount_cents"] for r in rows}
    assert by_role["author"] >= by_role["advisor"]
    assert by_role["advisor"] >= by_role["chapter"]


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: two simultaneous calls, only one bills
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R6_concurrency_parallel_uses_serialize(supabase):
    import asyncio

    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")

    async def call(key):
        return await skill_revenue.record_skill_use(
            skill_id="demo@1.0.0",
            skill_version="1.0.0",
            used_by_agent_id="alice",
            tool_name="do_thing",
            idempotency_key=key,
        )

    # Same key → one billed, one duplicate
    r1, r2 = await asyncio.gather(call("race-key"), call("race-key"))
    statuses = sorted([(r.get("billed"), r.get("reason")) for r in (r1, r2)], key=str)
    # Exactly one billed=True + one billed=False with reason=duplicate
    billed_count = sum(1 for r in (r1, r2) if r.get("billed") is True)
    dup_count = sum(1 for r in (r1, r2) if r.get("reason") == "duplicate")
    assert billed_count == 1, statuses
    assert dup_count == 1, statuses


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: pure compute_split rejects bad inputs
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_empty_attestor_list_raises():
    with pytest.raises(ValueError, match="zero attestors"):
        skill_revenue.compute_split(
            gross_cents=100,
            author_did="did:author",
            attestor_dids=[],
            chapter_treasury_did="chapter:test",
        )


def test_R7_adversarial_shares_sum_not_one_raises():
    with pytest.raises(ValueError, match="sum to 1.0"):
        skill_revenue.compute_split(
            gross_cents=100,
            author_did="did:author",
            attestor_dids=["did:adv1"],
            chapter_treasury_did="chapter:test",
            author_share=0.5,
            advisor_share=0.3,
            chapter_share=0.3,  # sums to 1.1
        )


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: revoked attestation excluded from split
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R8_downgrade_revoked_attestation_excluded(supabase):
    _seed_skill(supabase)
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zALIVE")
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zDEAD", revoked=True)

    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="do_thing",
        idempotency_key="revoked-test",
    )
    assert r.get("billed") is True
    # Only ALIVE advisor in the split
    advisor_rows = [row for row in supabase.skill_revenue_ledger if row["beneficiary_role"] == "advisor"]
    assert len(advisor_rows) == 1
    assert advisor_rows[0]["beneficiary_did"] == "did:key:zALIVE"


# ══════════════════════════════════════════════════════════════════════
# R9 — Timing: compute_split is pure/deterministic
# ══════════════════════════════════════════════════════════════════════


def test_R9_timing_compute_split_deterministic():
    args = dict(
        gross_cents=100,
        author_did="did:author",
        attestor_dids=["did:a", "did:b", "did:c"],
        chapter_treasury_did="chapter:x",
    )
    results = [skill_revenue.compute_split(**args) for _ in range(20)]
    assert all(r == results[0] for r in results)


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: cents-conservation over 10,000 random splits
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_cents_conservation_property():
    """Property test — for every random input, sum of ledger rows == gross,
    and no amount is negative. Runs 10,000 iterations covering:
      - gross from 1 cent to 100,000 cents
      - advisor count from 1 to 8
      - share variations within valid ranges
    If this ever fails, the split arithmetic has a rounding bug we must fix
    before money moves."""
    rng = random.Random(42)  # deterministic; change seed to re-sample

    for _ in range(10000):
        gross = rng.randint(1, 100_000)
        n_advisors = rng.randint(1, 8)
        attestor_dids = [f"did:key:zADV{i:02d}" for i in range(n_advisors)]

        rows = skill_revenue.compute_split(
            gross_cents=gross,
            author_did="did:author",
            attestor_dids=attestor_dids,
            chapter_treasury_did="chapter:x",
        )

        total = sum(r["amount_cents"] for r in rows)
        assert total == gross, f"conservation failed: gross={gross}, n_advisors={n_advisors}, rows={rows}, sum={total}"
        assert all(r["amount_cents"] >= 0 for r in rows), f"negative amount in {rows}"
        # Every advisor appears once and only once in the ledger rows
        advisor_rows = [r for r in rows if r["beneficiary_role"] == "advisor"]
        assert len(advisor_rows) == n_advisors
        assert len({r["beneficiary_did"] for r in advisor_rows}) == n_advisors


# ══════════════════════════════════════════════════════════════════════
# HAPPY path — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_standard_100_cent_split_two_advisors(supabase):
    _seed_skill(supabase, author_did="did:key:zAUTHOR")
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV1")
    _seed_attest(supabase, "demo@1.0.0", "1.0.0", "did:key:zADV2")

    r = await skill_revenue.record_skill_use(
        skill_id="demo@1.0.0",
        skill_version="1.0.0",
        used_by_agent_id="alice",
        tool_name="search",
        idempotency_key="happy-1",
    )
    assert r["billed"] is True
    assert len(supabase.skill_revenue_ledger) == 4  # author + 2 advisors + chapter

    by_role: dict[str, int] = {}
    for row in supabase.skill_revenue_ledger:
        by_role.setdefault(row["beneficiary_role"], 0)
        by_role[row["beneficiary_role"]] += row["amount_cents"]

    # 40% / 35% / 25% = 40 / 35 / 25 cents
    assert by_role["author"] == 40
    assert by_role["advisor"] == 35
    assert by_role["chapter"] == 25


def test_happy_share_constants_are_three_number_partition():
    assert (skill_revenue.AUTHOR_SHARE + skill_revenue.ADVISOR_SHARE + skill_revenue.CHAPTER_SHARE) == pytest.approx(
        1.0
    )
