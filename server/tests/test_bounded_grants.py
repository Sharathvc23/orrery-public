"""Bounded operational grants.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL

The bounds are the feature, so most of this is adversarial: every way to end up
with a grant that is not actually bounded. A bounded grant with an optional cap
is an unbounded grant with extra steps.

Atomicity and retry-idempotency are enforced in SQL (a conditional UPDATE and a
partial UNIQUE INDEX), which a Python fake cannot prove. Those are asserted two
ways here: structurally against the shipped SQL, and behaviourally by pinning
that the Python layer performs NO read-then-write — it makes a single call and
lets the database decide.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import bounded_grants
import governance

NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
SOON = NOW + timedelta(days=2)
REPO = Path(__file__).resolve().parents[2]


class _FakePg:
    """Records calls; returns whatever the RPC is told to return."""

    def __init__(self, rpc_result=None):
        self.calls: list[tuple] = []
        self.rpc_result = rpc_result
        self.rows: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        if table.startswith("rpc/"):
            return [{"consume_operational_grant": json.dumps(self.rpc_result)}] if self.rpc_result else []
        if method == "GET":
            return list(self.rows)
        return [body or {}]

    @property
    def rpc_calls(self):
        return [c for c in self.calls if str(c[1]).startswith("rpc/")]


@pytest.fixture
def pg():
    fake = _FakePg()
    bounded_grants.init(fake, "acme-chapter")
    governance.init(fake, "acme-chapter")
    return fake


# ── ADVERSARIAL: every bound is mandatory ──────────────────────────


@pytest.mark.asyncio
async def test_a_grant_without_a_cap_is_refused(pg):
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=None, expires_at=SOON, created_by="op", now=NOW
        )


@pytest.mark.asyncio
async def test_a_grant_without_an_expiry_is_refused(pg):
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=10, expires_at=None, created_by="op", now=NOW
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("cap", [0, -1, -100])
async def test_a_non_positive_cap_is_refused(pg, cap):
    """cap=0 is not "no sends", it is a grant that cannot be spent — and
    accepting it invites cap=-1 meaning something."""
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=cap, expires_at=SOON, created_by="op", now=NOW
        )


@pytest.mark.asyncio
async def test_a_boolean_cap_is_refused(pg):
    """`True` is an int in Python. A cap of True would be a cap of 1 by
    accident, which is a bound nobody chose."""
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=True, expires_at=SOON, created_by="op", now=NOW
        )


@pytest.mark.asyncio
async def test_an_already_expired_grant_is_refused(pg):
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external",
            scope="mailto:*",
            cap=10,
            expires_at=NOW - timedelta(seconds=1),
            created_by="op",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_a_naive_expiry_is_refused(pg):
    """'Until Friday' has to mean Friday somewhere specific."""
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external",
            scope="mailto:*",
            cap=10,
            expires_at=datetime(2026, 8, 7, 12, 0, 0),
            created_by="op",
            now=NOW,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["", "   ", "*", None])
async def test_a_scope_that_matches_everything_is_refused(pg, scope):
    """The scope is one of the three bounds. `*` with a cap is bounded on two
    axes out of three, and the missing one is the one that says WHAT."""
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(kind="send_external", scope=scope, cap=10, expires_at=SOON, created_by="op", now=NOW)


@pytest.mark.asyncio
async def test_an_unattributed_grant_is_refused(pg):
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=10, expires_at=SOON, created_by="", now=NOW
        )


@pytest.mark.asyncio
async def test_a_non_operational_kind_is_refused(pg):
    """A bounded grant over `introduction` would gate member exposure with a
    counter, which is not what the social path means."""
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(kind="introduction", scope="x*", cap=10, expires_at=SOON, created_by="op", now=NOW)


@pytest.mark.asyncio
async def test_a_grant_that_did_not_persist_is_not_reported_as_issued(pg):
    """pg_request swallows a configured-db failure into None. Reporting
    a grant that does not exist would have an operator believe they had bounded
    something."""

    async def swallowing(*a, **k):
        return None

    bounded_grants.init(swallowing, "acme-chapter")
    with pytest.raises(bounded_grants.GrantRefused):
        await bounded_grants.issue(
            kind="send_external", scope="mailto:*", cap=10, expires_at=SOON, created_by="op", now=NOW
        )


# ── HAPPY ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_fully_bounded_grant_is_issued(pg):
    row = await bounded_grants.issue(
        kind="send_external", scope="mailto:segment-a:*", cap=200, expires_at=SOON, created_by="op", now=NOW
    )
    assert row["cap"] == 200
    assert row["scope"] == "mailto:segment-a:*"
    assert row["consumed"] == 0
    assert row["expires_at"] == SOON.isoformat()


@pytest.mark.parametrize(
    ("scope", "action", "expected"),
    [
        ("mailto:*", "mailto:a@example.com", True),
        ("mailto:a@example.com", "mailto:a@example.com", True),
        ("mailto:a@example.com", "mailto:b@example.com", False),
        ("crm:contact:*", "crm:contact:42", True),
        ("crm:contact:*", "crm:deal:42", False),
        ("mailto:*", "sms:+1555", False),
    ],
)
def test_scope_matching(scope, action, expected):
    assert bounded_grants.matches(scope, action) is expected


# ── ATOMICITY ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_consumption_makes_exactly_one_database_call(pg):
    """A cap enforced by read-then-write in Python is not a cap: four agents
    each read `consumed` before any of them writes. This pins that the Python
    layer does not decide — it asks once and the database decides."""
    pg.rpc_result = {"authorized": True, "grant_id": "g1", "charged": True, "remaining": 199}
    await bounded_grants.consume(kind="send_external", action_key="mailto:a@example.com", actor_agent_id="svc-1")
    assert len(pg.calls) == 1, f"expected a single call, got {[c[1] for c in pg.calls]}"
    assert pg.calls[0][1] == "rpc/consume_operational_grant"


def test_the_sql_increments_conditionally_rather_than_reading_first():
    """The mechanism itself, asserted against the shipped SQL — a Python fake
    cannot prove what Postgres does."""
    sql = (REPO / "infra" / "migrations" / "0004_bounded_operational_grants.sql").read_text()
    assert "SET consumed = consumed + 1" in sql
    assert "AND consumed < cap" in sql, "the cap check must be inside the UPDATE, not before it"


def test_retry_idempotency_is_enforced_by_a_unique_index():
    """Not by a read-then-write: two racing retries must not both charge."""
    sql = (REPO / "infra" / "migrations" / "0004_bounded_operational_grants.sql").read_text()
    assert "CREATE UNIQUE INDEX IF NOT EXISTS operational_grant_consumptions_charged_once_idx" in sql
    assert "(grant_id, action_key)" in sql
    assert "WHERE charged" in sql


def test_the_cap_is_also_a_database_constraint():
    """Enforced by the schema, not only by the code that reads it."""
    sql = (REPO / "infra" / "migrations" / "0004_bounded_operational_grants.sql").read_text()
    assert "CHECK (consumed <= cap)" in sql
    assert "CHECK (cap > 0)" in sql


# ── RETRY SEMANTICS (the stated decision) ──────────────────────────


@pytest.mark.asyncio
async def test_a_retry_of_the_same_action_is_authorized_but_not_charged(pg):
    """THE STATED SEMANTIC: the cap counts DISTINCT ACTIONS, not attempts.
    A crash-after-send-before-record retry must not re-charge the operator."""
    pg.rpc_result = {
        "authorized": True,
        "grant_id": "g1",
        "charged": False,
        "remaining": 199,
        "reason": "retry_of_charged_action",
    }
    out = await bounded_grants.consume(kind="send_external", action_key="mailto:a@example.com", actor_agent_id="svc-1")
    assert out.authorized is True
    assert out.charged is False, "a retry must not consume a second unit"
    assert out.remaining == 199


@pytest.mark.asyncio
async def test_a_new_action_is_charged(pg):
    pg.rpc_result = {"authorized": True, "grant_id": "g1", "charged": True, "remaining": 198}
    out = await bounded_grants.consume(kind="send_external", action_key="mailto:b@example.com", actor_agent_id="svc-1")
    assert out.charged is True


def test_the_sql_records_the_uncharged_retry_too():
    """An uncharged retry storm costs nothing and is still something an
    operator must be able to see."""
    sql = (REPO / "infra" / "migrations" / "0004_bounded_operational_grants.sql").read_text()
    before, _, after = sql.partition("IF _already THEN")
    assert "INSERT INTO public.operational_grant_consumptions" in after.split("RETURN")[0], (
        "the retry branch must still write an audit row"
    )


# ── FAILURE: fail closed ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_grant_store_error_does_not_authorize(pg):
    async def boom(*a, **k):
        raise RuntimeError("db down")

    bounded_grants.init(boom, "acme-chapter")
    out = await bounded_grants.consume(kind="send_external", action_key="x", actor_agent_id="svc-1")
    assert out.authorized is False


@pytest.mark.asyncio
async def test_no_matching_grant_does_not_authorize(pg):
    pg.rpc_result = None
    out = await bounded_grants.consume(kind="send_external", action_key="x", actor_agent_id="svc-1")
    assert out.authorized is False


@pytest.mark.asyncio
async def test_an_exhausted_or_revoked_grant_does_not_authorize(pg):
    pg.rpc_result = {"authorized": False, "reason": "grant_exhausted_or_revoked"}
    out = await bounded_grants.consume(kind="send_external", action_key="x", actor_agent_id="svc-1")
    assert out.authorized is False
    assert "exhausted" in out.reason


# ── REVOCATION ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revocation_only_targets_a_live_grant(pg):
    await bounded_grants.revoke("g1", now=NOW)
    _method, table, params, _body = pg.calls[0]
    assert table == "operational_grants"
    assert params["grant_id"] == "eq.g1"
    assert params["revoked_at"] == "is.null", "re-revoking must not rewrite the original revocation time"


@pytest.mark.asyncio
async def test_a_failed_revocation_is_reported_as_failure(pg):
    async def swallowing(*a, **k):
        return None

    bounded_grants.init(swallowing, "acme-chapter")
    assert await bounded_grants.revoke("g1", now=NOW) is False


def test_the_sql_rechecks_revocation_inside_the_consuming_update():
    """A revoke racing a consumption must not be stepped over."""
    sql = (REPO / "infra" / "migrations" / "0004_bounded_operational_grants.sql").read_text()
    update = sql.split("UPDATE public.operational_grants")[1].split("RETURNING")[0]
    assert "revoked_at IS NULL" in update
    assert "expires_at > _now" in update


# ── The existing single-use path must be unweakened ────────────────


@pytest.mark.asyncio
async def test_an_exact_key_single_use_grant_still_works_and_is_still_single_use(pg):
    """dev measured twice and endorsed keeping this. A bounded grant is an
    addition, not a replacement."""
    approved = {
        "id": "appr-1",
        "chapter_id": "acme-chapter",
        "kind": "send_external",
        "status": "approved",
        "approved_at": "2026-08-05T00:00:00Z",
        "payload": {"action_key": "mailto:one@example.com"},
    }
    pg.rows = [approved]
    row = await governance.consume_operational_approval(
        "send_external", actor_agent_id="svc-1", action_key="mailto:one@example.com"
    )
    assert row["id"] == "appr-1"
    assert pg.rpc_calls == [], "an exact-key grant must be consumed WITHOUT touching the bounded path"


@pytest.mark.asyncio
async def test_the_bounded_path_is_only_consulted_after_the_exact_key_path(pg):
    """Ordering matters: checking bounded first would let a broad grant absorb
    an action an operator had already approved individually, and the exact-key
    grant would linger."""
    pg.rows = []
    pg.rpc_result = {"authorized": True, "grant_id": "g1", "charged": True, "remaining": 5}
    out = await governance.consume_operational_approval(
        "send_external", actor_agent_id="svc-1", action_key="mailto:two@example.com"
    )
    assert out["bounded"] is True
    assert out["grant_id"] == "g1"
    assert pg.rpc_calls, "the bounded path should have been consulted"


@pytest.mark.asyncio
async def test_with_no_grant_of_either_kind_the_action_is_still_refused(pg):
    """The gate's default is unchanged: no grant means no action."""
    pg.rows = []
    pg.rpc_result = None
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:three@example.com"
        )


def test_scope_is_prefix_only_and_an_infix_wildcard_is_refused():
    """The wildcard may only be the LAST character. An infix wildcard reads as
    if it works and would silently mean something else — I wrote one in this
    file's first draft and the validator caught it, which is the behaviour to
    keep rather than the mistake to accommodate."""
    with pytest.raises(bounded_grants.GrantRefused):
        bounded_grants.validate_scope("mailto:*@example.com")
    with pytest.raises(bounded_grants.GrantRefused):
        bounded_grants.validate_scope("a*b*")
    assert bounded_grants.validate_scope("mailto:segment-a:*") == "mailto:segment-a:*"
    assert bounded_grants.validate_scope("crm:contact:42") == "crm:contact:42"
