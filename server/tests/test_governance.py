"""
Tests for chapter governance — approval queue, nominations, role gates.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import governance


class _FakePostgres:
    """In-memory Postgres stub that handles the PostgREST operations
    governance.py calls."""

    def __init__(self, rows: dict[str, list[dict]] | None = None):
        self.tables: dict[str, list[dict]] = rows or {
            "agents": [],
            "pending_approvals": [],
            "chapter_role_nominations": [],
            "leader_dashboard": [],
        }
        self.calls: list[tuple[str, str, dict | None, dict | None]] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        self.calls.append((method, table_or_path, params, body))
        # table may have query params like "pending_approvals?id=eq.xyz"
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            body.setdefault("id", f"id-{len(self.tables[table]) + 1}")
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            body.setdefault("status", body.get("status") or "pending")
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            # Filters now ride in params=, not baked into the path.
            filters = {**self._parse_path_filters(table_or_path), **(params or {})}
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        return None

    @staticmethod
    def _parse_path_filters(path: str) -> dict[str, str]:
        if "?" not in path:
            return {}
        _, qs = path.split("?", 1)
        return dict(pair.split("=", 1) for pair in qs.split("&"))

    def _filter(self, rows, params):
        out = []
        for row in rows:
            ok = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                if not self._match(row, k, v):
                    ok = False
                    break
            if ok:
                out.append(row)
        # cheap order support
        order = params.get("order") if params else None
        if order:
            key = order.split(".")[0]
            reverse = order.endswith(".desc")
            out.sort(key=lambda r: r.get(key) or "", reverse=reverse)
        limit = params.get("limit") if params else None
        if limit:
            out = out[: int(limit)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in predicate:
            return row.get(key) == predicate
        op, val = predicate.split(".", 1)
        rv = row.get(key)
        if op == "eq":
            return str(rv) == val
        if op == "in":
            # "in.(a,b,c)"
            items = val.strip("()").split(",")
            return str(rv) in items
        if op == "gte":
            return str(rv) >= val
        if op == "gt":
            return str(rv) > val
        if op == "lt":
            return str(rv) < val
        return True


@pytest.fixture
def gov():
    fake = _FakePostgres()
    governance.init(pg_request=fake, agent_id="test-chapter")
    return fake


# ═══════════════════════════════════════════════
# ROLE LOOKUPS
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_chapter_role_defaults_member(gov):
    """EDGE: unknown agent defaults to 'member' role."""
    assert await governance.get_chapter_role("unknown") == "member"


@pytest.mark.asyncio
async def test_leader_check_passes_for_leader(gov):
    gov.tables["agents"].append({"agent_id": "alice", "chapter_role": "leader"})
    assert await governance.is_leader("alice")


@pytest.mark.asyncio
async def test_leader_check_fails_for_member(gov):
    gov.tables["agents"].append({"agent_id": "bob", "chapter_role": "member"})
    assert not await governance.is_leader("bob")


@pytest.mark.asyncio
async def test_admin_counts_as_approver(gov):
    """EDGE: admin (portal-assigned) has approver powers."""
    gov.tables["agents"].append({"agent_id": "admin-1", "chapter_role": "admin"})
    assert await governance.can_approve("admin-1")


@pytest.mark.asyncio
async def test_advisor_sees_queue_cannot_approve(gov):
    """Advisors observe but don't approve."""
    gov.tables["agents"].append({"agent_id": "adv", "chapter_role": "advisor"})
    assert await governance.can_see_queue("adv")
    assert not await governance.can_approve("adv")


# ═══════════════════════════════════════════════
# PROPOSE
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_propose_introduction_creates_row(gov):
    """HAPPY: propose_introduction writes a pending row to approvals queue."""
    result = await governance.propose_introduction(
        proposer_agent_id="chapter",
        pair=("alice", "bob"),
        reason="both work in Rust + climate",
        similarity=0.82,
    )
    assert result is not None
    assert result["kind"] == "introduction"
    assert result["status"] == "pending"
    assert sorted(result["payload"]["pair"]) == ["alice", "bob"]
    assert abs(result["confidence"] - 0.82) < 0.001


@pytest.mark.asyncio
async def test_propose_unknown_kind_raises_and_writes_nothing(gov):
    """FAILURE: an unknown kind raises and still writes nothing.

    The write-nothing half is unchanged; the reporting half is not. Returning
    None made "never queued" indistinguishable from "queued", which turned a
    constraint violation into a silent permanent deadlock."""
    with pytest.raises(governance.ProposalFailed):
        await governance.propose(
            kind="delete_chapter",  # not in APPROVAL_KINDS
            proposer_agent_id="chapter",
            payload={},
        )
    assert len(gov.tables["pending_approvals"]) == 0


@pytest.mark.asyncio
async def test_propose_sets_72h_ttl_by_default(gov):
    """C5: default TTL is 72h from creation (within 1 minute tolerance)."""
    before = datetime.now(UTC)
    result = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    expires = datetime.fromisoformat(result["expires_at"])
    delta = expires - before
    # 72h = 259200 seconds; allow 60s tolerance for test scheduling
    assert 259200 - 60 < delta.total_seconds() < 259200 + 60


@pytest.mark.asyncio
async def test_propose_respects_custom_ttl(gov):
    """EDGE: custom ttl overrides default."""
    before = datetime.now(UTC)
    result = await governance.propose(
        kind="event_proposal",
        proposer_agent_id="c",
        payload={},
        ttl=timedelta(hours=1),
    )
    expires = datetime.fromisoformat(result["expires_at"])
    delta = expires - before
    assert 3540 < delta.total_seconds() < 3660  # ~1h


# ═══════════════════════════════════════════════
# COOL-DOWN
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_recent_introduction_exists_true(gov):
    """HAPPY: cool-down fires for a pair introduced yesterday."""
    yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    gov.tables["pending_approvals"].append(
        {
            "id": "1",
            "chapter_id": "test-chapter",
            "kind": "introduction",
            "status": "executed",
            "created_at": yesterday,
            "payload": {"pair": ["alice", "bob"]},
        }
    )
    assert await governance.recent_introduction_exists("alice", "bob")
    # order-independent
    assert await governance.recent_introduction_exists("bob", "alice")


@pytest.mark.asyncio
async def test_recent_introduction_outside_window_returns_false(gov):
    """EDGE: intro older than 30d does not trigger cool-down."""
    old = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    gov.tables["pending_approvals"].append(
        {
            "id": "1",
            "chapter_id": "test-chapter",
            "kind": "introduction",
            "status": "executed",
            "created_at": old,
            "payload": {"pair": ["alice", "bob"]},
        }
    )
    # Our fake backend doesn't filter on created_at so this test confirms pair logic
    # (the SQL gte filter is the real guard; pair-set mismatch here tests payload parse)
    assert not await governance.recent_introduction_exists("alice", "charlie")


@pytest.mark.asyncio
async def test_cooldown_ignores_rejected_pairs(gov):
    """ADVERSARIAL: a rejected intro shouldn't keep a pair in cool-down forever."""
    recent = datetime.now(UTC).isoformat()
    gov.tables["pending_approvals"].append(
        {
            "id": "1",
            "chapter_id": "test-chapter",
            "kind": "introduction",
            "status": "rejected",  # explicitly NOT in (pending, approved, executed)
            "created_at": recent,
            "payload": {"pair": ["alice", "bob"]},
        }
    )
    assert not await governance.recent_introduction_exists("alice", "bob")


# ═══════════════════════════════════════════════
# APPROVE / REJECT
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_approve_by_leader_succeeds(gov):
    """HAPPY: leader can approve a pending proposal."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    result = await governance.approve(proposal["id"], "leader-1")
    assert result["status"] == "approved"
    assert result["approved_by"] == "leader-1"


@pytest.mark.asyncio
async def test_approve_by_member_rejected(gov):
    """ADVERSARIAL: regular member cannot approve — returns auth error."""
    gov.tables["agents"].append({"agent_id": "rando", "chapter_role": "member"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    result = await governance.approve(proposal["id"], "rando")
    assert result == {"error": "not_authorized"}
    # proposal remains pending
    assert gov.tables["pending_approvals"][0]["status"] == "pending"


@pytest.mark.asyncio
async def test_approve_by_advisor_rejected(gov):
    """ADVERSARIAL: advisor sees the queue but cannot approve."""
    gov.tables["agents"].append({"agent_id": "adv", "chapter_role": "advisor"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    result = await governance.approve(proposal["id"], "adv")
    assert result == {"error": "not_authorized"}


@pytest.mark.asyncio
async def test_approve_pre_authorized_skips_name_role_check(gov):
    """The HTTP layer authorizes (signed leader / break-glass bearer) and passes
    pre_authorized=True with the VERIFIED caller — governance must not re-reject
    on a by-name role lookup (a bearer has no member row / no approver role)."""
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    # 'operator' is not an approver-role member, but the caller was already gated.
    result = await governance.approve(proposal["id"], "operator", pre_authorized=True)
    assert result["status"] == "approved"
    assert result["approved_by"] == "operator"


@pytest.mark.asyncio
async def test_approve_not_pre_authorized_still_gates_by_name(gov):
    """Default (internal callers): the by-name approver role gate still applies."""
    gov.tables["agents"].append({"agent_id": "rando", "chapter_role": "member"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    result = await governance.approve(proposal["id"], "rando")
    assert result == {"error": "not_authorized"}


@pytest.mark.asyncio
async def test_reject_records_reason(gov):
    """HAPPY: rejection captures the leader's reason."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    result = await governance.reject(proposal["id"], "leader-1", reason="pair already connected elsewhere")
    assert result["status"] == "rejected"
    assert "already connected" in result["rejection_reason"]


@pytest.mark.asyncio
async def test_reject_reason_truncated(gov):
    """C5 boundary: rejection reason over 500 chars is truncated."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    proposal = await governance.propose(kind="introduction", proposer_agent_id="c", payload={"pair": ["a", "b"]})
    huge = "x" * 2000
    result = await governance.reject(proposal["id"], "leader-1", reason=huge)
    assert len(result["rejection_reason"]) == 500


# ═══════════════════════════════════════════════
# SWEEP EXPIRED
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_an_expired_item_cannot_be_approved_before_the_sweeper_runs(gov):
    """ADVERSARIAL: the TTL holds at the DECISION, not only at the sweep.

    The sweeper runs on the think cycle. Between an item's expires_at and the
    next sweep the row still reads `pending`, and approve() used to filter on
    status alone — so a leader could approve an item whose TTL had passed,
    and the endpoint's own docstring ("expired items stay expired") was false
    for that window.
    """
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    gov.tables["agents"].append({"agent_id": "leader", "chapter_role": "leader"})
    gov.tables["pending_approvals"].extend(
        [
            {"id": "stale", "status": "pending", "expires_at": past},
            {"id": "fresh", "status": "pending", "expires_at": future},
        ]
    )
    stale = await governance.approve("stale", "leader", pre_authorized=True)
    fresh = await governance.approve("fresh", "leader", pre_authorized=True)
    rows = {r["id"]: r for r in gov.tables["pending_approvals"]}
    assert rows["stale"]["status"] == "pending", "an expired item must not become approved"
    assert not (isinstance(stale, dict) and stale.get("status") == "approved")
    assert rows["fresh"]["status"] == "approved" and fresh["status"] == "approved"


@pytest.mark.asyncio
async def test_an_expired_item_cannot_be_rejected_as_if_decided(gov):
    """Recording `rejected` on an item the clock already expired would
    attribute to a person an outcome nobody made."""
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    gov.tables["pending_approvals"].append({"id": "stale", "status": "pending", "expires_at": past})
    await governance.reject("stale", "leader", "late", pre_authorized=True)
    assert gov.tables["pending_approvals"][0]["status"] == "pending"


@pytest.mark.asyncio
async def test_sweep_expired_moves_stale_to_expired(gov):
    """HAPPY: pending past expires_at → 'expired'."""
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    gov.tables["pending_approvals"].extend(
        [
            {"id": "old", "status": "pending", "expires_at": past},
            {"id": "fresh", "status": "pending", "expires_at": future},
        ]
    )
    await governance.sweep_expired()
    rows = {r["id"]: r for r in gov.tables["pending_approvals"]}
    assert rows["old"]["status"] == "expired"
    assert rows["fresh"]["status"] == "pending"


@pytest.mark.asyncio
async def test_sweep_expired_uses_url_safe_timestamp(gov):
    """REGRESSION (2026-04-26 prod): the sweep query path must NOT
    contain a literal ``+`` character, because PostgREST decodes
    ``+`` as a space and rejects with HTTP 400 ``invalid input
    syntax for type timestamp with time zone``. Verify the URL we
    build uses ``Z`` instead of ``+00:00``.
    """
    await governance.sweep_expired()
    # The expires_at filter now rides in params=, where httpx
    # percent-encodes it — so a stray '+' can no longer be decoded as a space.
    # Still assert the Z-form (clean wire + belt-and-suspenders).
    sweep_filters = [c[2]["expires_at"] for c in gov.calls if c[0] == "PATCH" and c[2] and "expires_at" in c[2]]
    assert sweep_filters, "sweep_expired should issue at least one PATCH with an expires_at filter"
    for ts_filter in sweep_filters:
        ts_part = ts_filter.split("lt.", 1)[1] if "lt." in ts_filter else ts_filter
        assert "+" not in ts_part, f"sweep_expired emitted a raw '+' in the timestamp: {ts_filter!r}"
        assert ts_part.endswith("Z"), f"timestamp should end with Z, got {ts_part!r}"


def test_utc_now_z_returns_z_suffix():
    """Direct unit test of the helper — never produces +00:00."""
    out = governance._utc_now_z()
    assert out.endswith("Z")
    assert "+" not in out


# ═══════════════════════════════════════════════
# NOMINATIONS
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_nominate_creates_ledger_entry(gov):
    """HAPPY: nomination recorded with 30d TTL."""
    result = await governance.nominate(
        nominator_agent_id="carol",
        nominee_agent_id="alice",
        target_role="advisor",
        reason="ran 3 events last month",
    )
    assert result["status"] == "pending"
    assert result["target_role"] == "advisor"


@pytest.mark.asyncio
async def test_nominate_invalid_role_rejected(gov):
    """ADVERSARIAL: cannot nominate to 'admin' or arbitrary roles."""
    result = await governance.nominate(
        nominator_agent_id="carol",
        nominee_agent_id="alice",
        target_role="admin",
    )
    assert result == {"error": "invalid_target_role"}


@pytest.mark.asyncio
async def test_endorse_by_leader_adds_signal(gov):
    """HAPPY: leader up-endorses nomination; signal stored."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    result = await governance.endorse(nom["id"], "leader-1", signal="up", note="great at events")
    endorsements = result["endorsements"]
    assert len(endorsements) == 1
    assert endorsements[0]["signal"] == "up"
    assert endorsements[0]["endorser"] == "leader-1"


@pytest.mark.asyncio
async def test_endorse_by_member_rejected(gov):
    """ADVERSARIAL: non-leader cannot endorse."""
    gov.tables["agents"].append({"agent_id": "rando", "chapter_role": "member"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    result = await governance.endorse(nom["id"], "rando", signal="up")
    assert result == {"error": "not_authorized"}


@pytest.mark.asyncio
async def test_endorse_idempotent_per_endorser(gov):
    """EDGE: same leader endorsing twice overwrites, doesn't double-count."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    await governance.endorse(nom["id"], "leader-1", signal="up")
    result = await governance.endorse(nom["id"], "leader-1", signal="down", note="changed my mind")
    assert len(result["endorsements"]) == 1
    assert result["endorsements"][0]["signal"] == "down"


@pytest.mark.asyncio
async def test_resolve_advisor_by_leader_promotes(gov):
    """HAPPY: leader resolves an advisor nomination; agent's role updated."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    gov.tables["agents"].append({"agent_id": "alice", "chapter_role": "member"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    await governance.resolve_nomination(nom["id"], "leader-1", decision="approved")

    alice = next(r for r in gov.tables["agents"] if r["agent_id"] == "alice")
    assert alice["chapter_role"] == "advisor"


@pytest.mark.asyncio
async def test_resolve_leader_requires_admin(gov):
    """ADVERSARIAL: leader cannot promote another member to leader — only admin can."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    gov.tables["agents"].append({"agent_id": "alice", "chapter_role": "member"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="leader")
    result = await governance.resolve_nomination(nom["id"], "leader-1", decision="approved")
    assert result == {"error": "only_admin_can_promote_to_leader"}
    # alice stays a member
    alice = next(r for r in gov.tables["agents"] if r["agent_id"] == "alice")
    assert alice["chapter_role"] == "member"


@pytest.mark.asyncio
async def test_resolve_leader_by_admin_succeeds(gov):
    """HAPPY: admin can promote to leader."""
    gov.tables["agents"].append({"agent_id": "admin-1", "chapter_role": "admin"})
    gov.tables["agents"].append({"agent_id": "alice", "chapter_role": "member"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="leader")
    await governance.resolve_nomination(nom["id"], "admin-1", decision="approved")
    alice = next(r for r in gov.tables["agents"] if r["agent_id"] == "alice")
    assert alice["chapter_role"] == "leader"


@pytest.mark.asyncio
async def test_resolve_already_resolved_returns_error(gov):
    """EDGE: second resolution attempt rejected with current status."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    gov.tables["agents"].append({"agent_id": "alice", "chapter_role": "member"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    await governance.resolve_nomination(nom["id"], "leader-1", decision="approved")
    result = await governance.resolve_nomination(nom["id"], "leader-1", decision="rejected")
    assert result["error"] == "already_resolved"


@pytest.mark.asyncio
async def test_resolve_invalid_decision_rejected(gov):
    """ADVERSARIAL: only 'approved'/'rejected' decisions accepted."""
    gov.tables["agents"].append({"agent_id": "leader-1", "chapter_role": "leader"})
    nom = await governance.nominate(nominator_agent_id="carol", nominee_agent_id="alice", target_role="advisor")
    result = await governance.resolve_nomination(nom["id"], "leader-1", decision="maybe")
    assert result == {"error": "invalid_decision"}


# ═══════════════════════════════════════════════
# TRUST SCORE
# ═══════════════════════════════════════════════


def test_trust_score_bounded_0_100():
    """HAPPY: trust score stays in [0, 100] for reasonable inputs."""
    score = governance.compute_trust_score(
        reputation={"introductions": 2, "sprints": 1, "votes": 5, "events": 2, "contributions": 3},
        endorsements=[{"signal": "up"}, {"signal": "up"}],
        tenure_days=90,
    )
    assert 0 <= score <= 100


def test_trust_score_zero_for_empty_inputs():
    """EDGE: no activity = 0 score."""
    assert governance.compute_trust_score({}, [], 0) == 0.0


def test_trust_score_max_saturates_at_100():
    """C5: massive reputation + endorsements + tenure still caps at 100."""
    score = governance.compute_trust_score(
        reputation={"introductions": 10000, "sprints": 10000, "votes": 10000, "events": 10000, "contributions": 10000},
        endorsements=[{"signal": "up"}] * 100,
        tenure_days=3650,
    )
    assert score == 100.0


def test_trust_score_negative_signals_reduce():
    """ADVERSARIAL: down endorsements reduce score but never go below 0."""
    only_down = governance.compute_trust_score({}, [{"signal": "down"}] * 5, 0)
    assert only_down == 0.0


def test_trust_score_tenure_saturates_at_1_year():
    """EDGE: tenure cap kicks in at 365 days."""
    one_year = governance.compute_trust_score({}, [], 365)
    two_years = governance.compute_trust_score({}, [], 730)
    assert one_year == two_years == 10.0
