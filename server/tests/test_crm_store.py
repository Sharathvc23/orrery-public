"""crm_store — the first service verb, and the governance seam it is built around.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

The 2026-08-05 spike measured that Orrery's governance had ZERO coverage of
operational actions. PR1 closed that, so the tests that matter most here
are not the write path — they are the ones proving this verb is genuinely behind
that gate and cannot slip past it:

  * ``test_a_write_with_no_grant_is_pending_and_nothing_is_written``
  * ``test_an_approved_grant_authorises_exactly_one_write`` — single-use, which
    is the property that separates a gate from a formality.
  * ``test_an_approval_for_one_action_does_not_authorise_a_different_one``
  * ``test_every_mutating_verb_goes_through_the_gate``

⚠️ These drive the REAL ``governance.consume_operational_approval`` against a
fake store rather than stubbing the gate out. Stubbing it would assert only that
this module calls a function whose behaviour the test itself supplied — the
integration is the thing under test, and a mock of it proves nothing about it.
"""

from __future__ import annotations

import pytest

import crm_store


@pytest.fixture
def store(monkeypatch):
    """crm_store wired to an in-memory fake Postgres + captured receipts."""
    writes: list[tuple] = []
    receipts: list[dict] = []

    async def pg(method, table, params=None, body=None):
        writes.append((method, table, params, body))
        if method == "POST":
            return [{"id": f"{table}-1", **(body or {})}]
        if method == "GET":
            return []
        return {}

    async def fake_receipt(action, summary, payload, gate):
        receipts.append({"action": action, "summary": summary, "payload": payload, "governance": gate})

    crm_store.init(pg, "test-org")
    monkeypatch.setattr(crm_store, "_receipt", fake_receipt)
    return type("S", (), {"writes": writes, "receipts": receipts})


# ── the governance seam — the point of this module ─────────────────────────


@pytest.fixture
def governed(store, monkeypatch):
    """Wire the REAL governance gate to an in-memory approvals table.

    ``grant(action_key)`` seeds an approved, spendable grant. Everything else
    behaves as production does: lookups, single-use consumption, re-filing.
    """
    import governance

    approvals: list[dict] = []

    async def gov_pg(method, table, params=None, body=None):
        assert table == "pending_approvals", f"governance touched {table}"
        params = params or {}
        if method == "GET":
            want_status = (params.get("status") or "").removeprefix("eq.")
            want_kind = (params.get("kind") or "").removeprefix("eq.")
            return [
                r
                for r in approvals
                if (not want_status or r["status"] == want_status) and (not want_kind or r["kind"] == want_kind)
            ]
        if method == "PATCH":
            target = (params.get("id") or "").removeprefix("eq.")
            for r in approvals:
                if r["id"] == target:
                    r.update(body or {})
            return []
        if method == "POST":
            row = {"id": f"appr-{len(approvals) + 1}", "status": "pending", **(body or {})}
            approvals.append(row)
            return [row]
        return []

    governance.init(gov_pg, "test-org")

    def grant(action_key: str) -> dict:
        row = {
            "id": f"grant-{len(approvals) + 1}",
            "kind": crm_store.CRM_APPROVAL_KIND,
            "status": "approved",
            "payload": {"action_key": action_key},
        }
        approvals.append(row)
        return row

    store.grant = grant
    store.approvals = approvals
    return store


def test_the_kind_this_module_uses_is_a_registered_operational_kind():
    """Pins the integration to PR1's vocabulary. If the kind is ever renamed or
    dropped, this fails loudly here rather than silently degrading every CRM
    write into an unknown-kind refusal at runtime."""
    import governance

    assert crm_store.CRM_APPROVAL_KIND in governance.OPERATIONAL_KINDS
    assert crm_store.CRM_APPROVAL_KIND in governance.APPROVAL_KINDS


@pytest.mark.asyncio
async def test_a_write_with_no_grant_is_pending_and_nothing_is_written(governed):
    """The default state. No operator has approved anything, so the row is NOT
    created and the caller is told what it is waiting on."""
    out = await crm_store.create_contact(actor_agent_id="a1", name="Ada Lovelace")
    assert out["status"] == "pending_approval"
    gov = out["governance"]
    assert gov["status"] == "pending"
    assert gov["kind"] == "record_write"
    assert gov["action_key"] == "crm:create_contact:Ada Lovelace"
    # THE WRITE MUST NOT HAVE HAPPENED.
    assert not [w for w in governed.writes if w[0] == "POST"], "a pending write was applied anyway"
    # ...and the operator has something to act on rather than a silent drop.
    assert [a for a in governed.approvals if a["status"] == "pending"]


@pytest.mark.asyncio
async def test_an_approved_grant_authorises_exactly_one_write(governed):
    """SINGLE-USE. The first write spends the grant; the second is pending again.

    This is the property that makes the gate real. A grant that stayed valid
    would turn one operator decision into unlimited writes — "approve once,
    write forever" — which is indistinguishable from not gating the verb.
    """
    governed.grant("crm:create_contact:Ada Lovelace")

    first = await crm_store.create_contact(actor_agent_id="a1", name="Ada Lovelace")
    assert first["status"] == "created"
    assert first["governance"]["status"] == "approved"
    assert len([w for w in governed.writes if w[0] == "POST"]) == 1

    second = await crm_store.create_contact(actor_agent_id="a1", name="Ada Lovelace")
    assert second["status"] == "pending_approval", "the grant was spendable twice"
    assert len([w for w in governed.writes if w[0] == "POST"]) == 1


@pytest.mark.asyncio
async def test_an_approval_for_one_action_does_not_authorise_a_different_one(governed):
    """ADVERSARIAL. The action_key is matched exactly against what was approved,
    so approving one thing must not widen into another. Approving a move to
    ``won`` is not approving a move to ``lost``."""
    governed.grant("crm:set_deal_stage:d1:won")

    lost = await crm_store.set_deal_stage(actor_agent_id="a1", deal_id="d1", stage="lost")
    assert lost["status"] == "pending_approval"
    assert not [w for w in governed.writes if w[0] == "PATCH"]

    won = await crm_store.set_deal_stage(actor_agent_id="a1", deal_id="d1", stage="won")
    assert won["status"] == "updated"


@pytest.mark.asyncio
async def test_an_approved_amount_cannot_be_inflated_after_the_fact(governed):
    """ADVERSARIAL. The amount is part of the key, so a grant for a 500.00 deal
    does not authorise a 500,000.00 one — otherwise the operator's decision is
    about the existence of a deal rather than its value."""
    governed.grant("crm:create_deal:c1:50000:USD")

    inflated = await crm_store.create_deal(actor_agent_id="a1", contact_id="c1", title="T", amount_minor=50_000_000)
    assert inflated["status"] == "pending_approval"
    assert not [w for w in governed.writes if w[0] == "POST"]


@pytest.mark.asyncio
async def test_governance_being_unreachable_fails_closed(governed, monkeypatch):
    """ADVERSARIAL: a gate that opens when its store is unreachable is worse than
    no gate, because it is trusted — and it is inducible by anyone who can make
    the store fail."""
    import governance

    async def broken(*a, **kw):
        raise RuntimeError("approvals table unreachable")

    governance.init(broken, "test-org")

    out = await crm_store.create_contact(actor_agent_id="a1", name="Ada Lovelace")
    assert out["status"] == "pending_approval"
    assert not [w for w in governed.writes if w[0] == "POST"]


@pytest.mark.asyncio
async def test_every_mutating_verb_goes_through_the_gate(governed, monkeypatch):
    """No verb may bypass the choke point. A new verb added without routing
    through ``_gate`` would be an ungoverned durable write — exactly what PR1
    exists to make impossible."""
    seen: list[str] = []
    real_gate = crm_store._gate

    async def spy(action, action_key, payload, actor):
        seen.append(action)
        return await real_gate(action, action_key, payload, actor)

    monkeypatch.setattr(crm_store, "_gate", spy)
    await crm_store.create_contact(actor_agent_id="a", name="N")
    await crm_store.update_contact_stage(actor_agent_id="a", contact_id="c1", stage="qualified")
    await crm_store.create_deal(actor_agent_id="a", contact_id="c1", title="T", amount_minor=1000)
    await crm_store.set_deal_stage(actor_agent_id="a", deal_id="d1", stage="won")
    await crm_store.log_interaction(actor_agent_id="a", contact_id="c1", kind="call", summary="Spoke")
    assert seen == [
        "create_contact",
        "update_contact_stage",
        "create_deal",
        "set_deal_stage",
        "log_interaction",
    ]


# ── deterministic write path ────────────────────────────────────────────────


def test_no_llm_in_the_write_path():
    """The design bias, asserted rather than trusted to review: the model
    proposes and drafts, it never triggers or mutates.

    Checked over the AST — imports and call names — not by grepping the source.
    A substring scan would trip over this module's own docstring explaining that
    it uses no LLM, and would equally be satisfied by a comment claiming so
    while the code did the opposite. The AST can only see what actually runs.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(crm_store.__file__).read_text())

    banned_modules = {"openai", "anthropic", "llm", "llm_config", "litellm", "transformers"}
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            f = node.func
            called.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))

    assert not (imported & banned_modules), f"CRM write path imports {sorted(imported & banned_modules)}"
    banned_calls = {"complete", "completion", "chat", "generate", "ask_llm", "infer", "predict"}
    assert not (called & banned_calls), f"CRM write path calls {sorted(called & banned_calls)}"


@pytest.mark.asyncio
async def test_receipt_is_emitted_for_every_mutation(governed):
    governed.grant("crm:create_contact:N")
    governed.grant(f"crm:log_interaction:c1:note:{crm_store._digest('S')}")
    await crm_store.create_contact(actor_agent_id="a", name="N")
    await crm_store.log_interaction(actor_agent_id="a", contact_id="c1", kind="note", summary="S")
    assert [r["action"] for r in governed.receipts] == ["create_contact", "log_interaction"]
    # the receipt carries WHICH grant authorised it, so a record change can be
    # traced back to an operator decision rather than merely to an agent.
    assert all(r["governance"]["status"] == "approved" for r in governed.receipts)
    assert all(r["governance"]["approval_id"] for r in governed.receipts)


# ── validation: refusing rather than coercing ──────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"name": ""}, "name_required"),
        ({"name": "  "}, "name_required"),
        ({"name": "N", "email": "not-an-email"}, "email_invalid"),
        ({"name": "N", "stage": "prospect"}, "stage_invalid"),
        ({"name": "x" * 201}, "name_too_long"),
    ],
)
async def test_contact_validation_refuses(store, kwargs, reason):
    with pytest.raises(crm_store.CrmError) as exc:
        await crm_store.create_contact(actor_agent_id="a", **kwargs)
    assert exc.value.reason == reason
    assert not store.writes, "a refused write still touched the database"


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [10.5, "1000", True, -1])
async def test_deal_amount_is_integer_minor_units_only(store, amount):
    """A float amount is REFUSED, not rounded. A deal value that drifts by a
    rounding step is a number nobody can reconcile against an invoice, and only
    the caller knows the intended precision."""
    with pytest.raises(crm_store.CrmError):
        await crm_store.create_deal(actor_agent_id="a", contact_id="c1", title="T", amount_minor=amount)
    assert not store.writes


@pytest.mark.asyncio
async def test_interaction_history_is_append_only():
    """There is no update or delete verb for interactions, by construction — an
    edited history is not a history."""
    verbs = {n for n in dir(crm_store) if not n.startswith("_")}
    assert not {v for v in verbs if "interaction" in v and ("update" in v or "delete" in v)}


@pytest.mark.asyncio
async def test_reads_are_not_gated(store, monkeypatch):
    """A read is not a mutation. Gating reads would push callers toward caching
    the data outside the org, which is the opposite of the point."""
    called: list[str] = []

    async def spy(action, action_key, payload, actor):
        called.append(action)
        return {"gated": True, "status": "approved", "kind": crm_store.CRM_APPROVAL_KIND}

    monkeypatch.setattr(crm_store, "_gate", spy)
    await crm_store.list_contacts()
    await crm_store.contact_history("c1")
    assert called == []


@pytest.mark.asyncio
async def test_writes_are_scoped_to_this_org(governed):
    """Every row carries chapter_id and every update filters on it — a CRM that
    leaks across orgs is the advisor-earnings hole in a different table."""
    governed.grant("crm:create_contact:N")
    governed.grant("crm:update_contact_stage:c1:customer")
    await crm_store.create_contact(actor_agent_id="a", name="N")
    post = [w for w in governed.writes if w[0] == "POST"][0]
    assert post[3]["chapter_id"] == "test-org"
    await crm_store.update_contact_stage(actor_agent_id="a", contact_id="c1", stage="customer")
    patch = [w for w in governed.writes if w[0] == "PATCH"][0]
    assert patch[2]["chapter_id"] == "eq.test-org"


# ── the HTTP edge ───────────────────────────────────────────────────────────


def test_a_pending_write_is_202_and_an_applied_one_is_200():
    """⚠️ A write awaiting approval must NOT be 200. Every mutating route can
    return having written nothing — the normal path once the gate is live — and
    a caller that reads 2xx-as-stored would go on to reference a record that
    does not exist. 202 says accepted-not-applied."""
    import json

    from routes.crm import _reply

    pending = _reply({"status": "pending_approval", "governance": {"action_key": "crm:x"}})
    assert pending.status_code == 202
    assert json.loads(bytes(pending.body))["governance"]["action_key"] == "crm:x"

    applied = _reply({"status": "created", "contact": {"id": "c1"}})
    assert applied.status_code == 200


def test_every_mutating_route_returns_through_the_202_helper():
    """A route that returned the store result directly would answer 200 for a
    write that never happened — the failure above, reintroduced one route at a
    time. Asserted structurally so a sixth verb cannot quietly skip it."""
    import ast
    import inspect

    import routes.crm as crm_routes

    tree = ast.parse(inspect.getsource(crm_routes))
    mutating = {"create_contact", "update_contact_stage", "create_deal", "set_deal_stage", "log_interaction"}
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name in mutating:
            returns = [n for n in ast.walk(node) if isinstance(n, ast.Return) and n.value is not None]
            assert returns, f"{node.name} returns nothing"
            for r in returns:
                call = r.value
                assert isinstance(call, ast.Call) and getattr(call.func, "id", "") == "_reply", (
                    f"{node.name} returns a store result directly — a pending write would be 200"
                )
            seen.add(node.name)
    assert seen == mutating, f"unchecked mutating routes: {sorted(mutating - seen)}"
