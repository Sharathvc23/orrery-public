"""Service role + operational approval kinds.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL

The property under test is not "the gate exists" but "the side effect cannot
happen without a grant". Most of these are FAILURE/ADVERSARIAL for that reason:
an operational gate that opens on a store error, or that lets one approval
authorize a second action, is worse than no gate because it is trusted.
"""

from __future__ import annotations

import pytest

import governance
from tests.test_governance import _FakePostgres


@pytest.fixture
def pg():
    fake = _FakePostgres()
    governance.init(fake, "acme-chapter")
    return fake


def _approved(kind: str, action_key: str, **extra):
    return {
        "id": f"appr-{action_key}",
        "chapter_id": "acme-chapter",
        "kind": kind,
        "status": "approved",
        "approved_at": "2026-08-05T00:00:00Z",
        "payload": {"action_key": action_key, **extra},
    }


# ── HAPPY ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approved_grant_authorizes_the_matching_action(pg):
    pg.tables["pending_approvals"].append(_approved("send_external", "mailto:a@example.com"))
    row = await governance.consume_operational_approval(
        "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
    )
    assert row["id"] == "appr-mailto:a@example.com"


def test_the_three_operational_kinds_are_registered():
    assert governance.OPERATIONAL_KINDS <= governance.APPROVAL_KINDS
    assert {"send_external", "record_write", "external_fetch"} <= governance.OPERATIONAL_KINDS


# ── ADVERSARIAL: the grant must not widen ──────────────────────────


@pytest.mark.asyncio
async def test_a_grant_for_one_target_does_not_authorize_another(pg):
    """The whole point of action_key. A kind-only grant would be a standing
    licence to perform the verb against anything."""
    pg.tables["pending_approvals"].append(_approved("send_external", "mailto:approved@example.com"))
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:attacker@example.com"
        )


@pytest.mark.asyncio
async def test_a_grant_is_single_use(pg):
    """Approve once / send forever is the failure this gate exists to prevent."""
    pg.tables["pending_approvals"].append(_approved("send_external", "mailto:a@example.com"))
    await governance.consume_operational_approval(
        "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
    )
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
        )


@pytest.mark.asyncio
async def test_a_grant_of_one_kind_does_not_authorize_another_kind(pg):
    pg.tables["pending_approvals"].append(_approved("external_fetch", "https://api.example.com"))
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="https://api.example.com"
        )


@pytest.mark.asyncio
async def test_a_pending_but_unapproved_request_does_not_authorize(pg):
    row = _approved("send_external", "mailto:a@example.com")
    row["status"] = "pending"
    pg.tables["pending_approvals"].append(row)
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
        )


# ── FAILURE: fail-closed ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_kind_is_refused(pg):
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval("delete_everything", actor_agent_id="svc-1", action_key="x")


@pytest.mark.asyncio
async def test_a_store_error_refuses_rather_than_opens(pg):
    """A gate that opens when its backing store is unreachable is inducible by
    anyone who can make the store fail."""

    async def boom(*a, **k):
        raise RuntimeError("db down")

    governance.init(boom, "acme-chapter")
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
        )


@pytest.mark.asyncio
async def test_an_uninitialised_store_refuses(pg):
    governance.init(None, "acme-chapter")
    with pytest.raises(governance.OperationalApprovalRequired):
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
        )


# ── EDGE: queue hygiene ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_refused_call_queues_exactly_one_request_however_often_it_retries(pg):
    """An unattended agent retries. Duplicates would bury the operator in
    copies of a single decision."""
    for _ in range(5):
        with pytest.raises(governance.OperationalApprovalRequired):
            await governance.consume_operational_approval(
                "record_write", actor_agent_id="svc-1", action_key="crm:contact:42"
            )
    queued = [r for r in pg.tables["pending_approvals"] if r.get("kind") == "record_write"]
    assert len(queued) == 1, f"expected 1 queued request, got {len(queued)}"


@pytest.mark.asyncio
async def test_the_refusal_names_the_pending_approval(pg):
    """§ a refusal an operator cannot act on gets worked around."""
    with pytest.raises(governance.OperationalApprovalRequired) as exc:
        await governance.consume_operational_approval(
            "send_external", actor_agent_id="svc-1", action_key="mailto:a@example.com"
        )
    assert exc.value.kind == "send_external"
    assert exc.value.approval is not None


# ── The service role ───────────────────────────────────────────────


def test_service_cannot_approve_or_vouch():
    """An unattended process must not approve its own operational requests,
    and must not attest for anyone."""
    assert "service" not in governance.APPROVER_ROLES
    assert "service" not in governance.LEADER_ROLES
    assert "service" not in governance.ATTEST_ELIGIBLE_ROLES
    assert governance.role_to_attest_tier("service") is None


def test_service_sees_only_operational_kinds():
    """Pending introductions name both members and why they were matched.
    An unattended agent has no business reading them."""
    kinds = governance.visible_kinds_for_role("service")
    assert kinds == governance.OPERATIONAL_KINDS
    for social in ("introduction", "member_admission", "cross_chapter_message"):
        assert social not in kinds


def test_human_governance_roles_still_see_everything():
    for role in ("leader", "admin", "advisor", "mentor"):
        assert governance.visible_kinds_for_role(role) is None


def test_an_unrecognised_role_sees_nothing():
    """Visibility is granted deliberately, never inherited."""
    assert governance.visible_kinds_for_role("member") == set()
    assert governance.visible_kinds_for_role("some-future-role") == set()


@pytest.mark.asyncio
async def test_service_can_reach_the_queue_at_all(pg):
    pg.tables["agents"].append({"agent_id": "svc-1", "chapter_role": "service"})
    assert await governance.can_see_queue("svc-1") is True


@pytest.mark.asyncio
async def test_a_plain_member_still_cannot_see_the_queue(pg):
    pg.tables["agents"].append({"agent_id": "m-1", "chapter_role": "member"})
    assert await governance.can_see_queue("m-1") is False


# ── Regression: the social path must be untouched ──────────────────


def test_existing_social_kinds_survive_intact():
    """PR1 adds vocabulary; it must not remove or alter any."""
    for kind in (
        "introduction",
        "cross_chapter_intent",
        "cross_chapter_message",
        "event_proposal",
        "member_admission",
        "role_promotion",
        "call_cross_post",
        "broadcast",
    ):
        assert kind in governance.APPROVAL_KINDS


def test_the_schema_permits_the_service_role():
    """The role is enforced by a CHECK constraint, so code alone does not
    ship it — init.sql must agree or every write fails at the database."""
    from pathlib import Path

    sql = (Path(__file__).resolve().parents[2] / "infra" / "init.sql").read_text()
    line = next(ln for ln in sql.splitlines() if "agents_chapter_role_check" in ln)
    assert "'service'::text" in line, "init.sql still rejects chapter_role='service'"


# ── The approval-parity fix: a queue write that does not land must not report "pending" ──


class _RejectingPg:
    """Postgres rejecting the INSERT on the kind CHECK constraint.

    ``pg_request`` catches that, logs, and returns None — so the caller sees a
    quiet None, not an exception. This reproduces the exact shape, because a
    fake that raises would test a path production never takes.
    """

    def __init__(self):
        self.writes = 0

    async def __call__(self, method, table, params=None, body=None):
        if method == "GET":
            return []
        self.writes += 1
        return None


@pytest.mark.asyncio
async def test_a_swallowed_constraint_violation_raises_rather_than_returning_none():
    """THE APPROVAL-PARITY FIX MECHANISM, pinned by name.

    Postgres rejected every operational INSERT, pg_request swallowed it,
    propose() returned None, and the caller reported pending_approval with a
    null id. Correctly refused, never queued, therefore never approvable.
    """
    governance.init(_RejectingPg(), "acme-chapter")
    with pytest.raises(governance.ProposalFailed) as exc:
        await governance.propose(
            kind="send_external", proposer_agent_id="svc-1", payload={"action_key": "mailto:a@example.com"}
        )
    assert "constraint" in str(exc.value).lower(), "the error must name the likely cause"


@pytest.mark.asyncio
async def test_the_gate_does_not_report_pending_when_the_queue_write_failed():
    """The property that actually broke: an unqueued proposal must not surface
    as OperationalApprovalRequired, because callers render that as
    "pending_approval" and wait forever for a row that does not exist.

    ProposalFailed deliberately does NOT subclass OperationalApprovalRequired,
    so a caller catching only the latter cannot mistake one for the other.
    """
    governance.init(_RejectingPg(), "acme-chapter")
    with pytest.raises(governance.ProposalFailed):
        await governance.consume_operational_approval(
            "record_write", actor_agent_id="svc-1", action_key="crm:contact:1"
        )
    assert not issubclass(governance.ProposalFailed, governance.OperationalApprovalRequired)
