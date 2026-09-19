"""The federation allowlist is writable only by a leader or admin, and only for
this org.

The allowlist decides which peers this org will federate with.
``chapter_auth.is_peer_allowed`` returns True for every peer while the table is
EMPTY and switches to default-deny as soon as it holds one row — so a single
entry does not add one peer, it excludes every peer that is not on the list.
``test_one_row_flips_the_allowlist_from_open_to_default_deny`` states that
property directly, because it is what makes write access to this table a
federation-wide decision rather than a per-peer one.

Both write endpoints previously required only a member signature and took
``chapter_id`` from the request body, so any member with a keypair could add or
remove an entry, for this org or for any other org id they cared to name.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_admin_member,
    register_test_regular_member,
    reset_chapter_agent_module,
)

ORG = "TEST-allowlist-org"
OTHER_ORG = "SOMEONE-ELSE-ENTIRELY"
ADMIN = "allowlist-admin-carol"
MEMBER = "allowlist-ordinary-alice"
REAL_PEER = "london-chapter"


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch, agent_id=ORG)
    mod.members.clear()
    rows: list[dict] = []
    writes: list[tuple] = []

    async def fake_pg(method, table, params=None, body=None, **kw):
        if method == "POST":
            writes.append((method, table, body))
            if table == "chapter_federation_allowlist":
                rows.append(dict(body or {}))
            return [dict(body or {}, id="row-1")]
        if method == "DELETE":
            writes.append((method, table, params))
            return []
        if method == "GET" and table == "chapter_federation_allowlist":
            wanted = (params or {}).get("chapter_id", "").replace("eq.", "")
            return [r for r in rows if r.get("chapter_id") == wanted]
        return []

    import chapter_audit
    import chapter_auth
    import governance

    chapter_auth.init(fake_pg)
    chapter_audit.init(fake_pg)

    admin = register_test_admin_member(mod, agent_id=ADMIN, name="Carol")
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Alice")

    async def role_of(agent_id: str) -> str:
        return (mod.members.get(agent_id) or {}).get("chapter_role", "member")

    monkeypatch.setattr(governance, "get_chapter_role", role_of)
    return mod, admin, member, TestClient(mod.app), rows, writes, chapter_auth


def _post(client, signer, path: str, payload: dict):
    body = json.dumps(payload, separators=(",", ":"))
    headers = signer(method="POST", url_path=path, body=body)
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


def _get(client, signer, path: str):
    headers = signer(method="GET", url_path=path) if signer is not None else {}
    return client.get(path, headers=headers)


def _entry(chapter_id: str = ORG, peer: str = "new-peer", actor: str = MEMBER) -> dict:
    return {
        "chapter_id": chapter_id,
        "peer_chapter_id": peer,
        "added_by_agent_id": actor,
        "reason": "test",
    }


# ══════════════════════════════════════════════════════════════════════
# Why write access matters: one row excludes everyone else
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_one_row_flips_the_allowlist_from_open_to_default_deny(stack):
    """The property that makes an unauthorised write a federation-wide event.

    An empty allowlist admits every peer. A populated one admits only what it
    lists. So a single added entry naming an unrelated peer denies every peer
    the org actually federates with — it reads as adding one peer and behaves
    as excluding all the others.
    """
    _mod, admin, _member, client, _rows, _writes, chapter_auth = stack

    assert await chapter_auth.is_peer_allowed(ORG, REAL_PEER) is True, (
        "an empty allowlist should admit every peer"
    )

    resp = _post(client, admin["signer"], "/api/chapter/allowlist/add",
                 _entry(peer="unrelated-chapter", actor=ADMIN))
    assert resp.status_code == 200, resp.text

    assert await chapter_auth.is_peer_allowed(ORG, "unrelated-chapter") is True
    assert await chapter_auth.is_peer_allowed(ORG, REAL_PEER) is False, (
        "one entry did not switch the allowlist to default-deny; if this is no longer "
        "true the urgency of who may write to this table has changed and the reasoning "
        "in this file needs revisiting"
    )


# ══════════════════════════════════════════════════════════════════════
# Who may write
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("path", ["/api/chapter/allowlist/add", "/api/chapter/allowlist/remove"])
def test_an_ordinary_member_cannot_write_the_allowlist(stack, path):
    _mod, _admin, member, client, rows, writes, _ca = stack
    resp = _post(client, member["signer"], path, _entry(peer="attacker-chapter"))
    assert resp.status_code == 403, f"{path} accepted an ordinary member: {resp.text[:200]}"
    assert "role" in resp.text.lower()
    assert not rows, f"{path} refused and still wrote: {rows}"
    assert not writes, f"{path} refused and still wrote: {writes}"


@pytest.mark.parametrize("path", ["/api/chapter/allowlist/add", "/api/chapter/allowlist/remove"])
def test_an_unauthenticated_caller_cannot_write_the_allowlist(stack, path):
    _mod, _admin, _member, client, rows, _writes, _ca = stack
    resp = client.post(path, json=_entry(), headers={"Content-Type": "application/json"})
    assert resp.status_code in (401, 403)
    assert not rows


@pytest.mark.parametrize("path", ["/api/chapter/allowlist/add", "/api/chapter/allowlist/remove"])
def test_a_leader_or_admin_can_write_the_allowlist(stack, path):
    _mod, admin, _member, client, _rows, _writes, _ca = stack
    resp = _post(client, admin["signer"], path, _entry(actor=ADMIN))
    assert resp.status_code == 200, f"{path} refused an admin: {resp.text[:200]}"


# ══════════════════════════════════════════════════════════════════════
# Which org the write lands on
# ══════════════════════════════════════════════════════════════════════


def test_the_row_is_written_for_the_serving_org_not_the_body(stack):
    """``chapter_id`` came from the request body, so a caller could write a row
    naming any org. It is now this org's own id."""
    _mod, admin, _member, client, rows, _writes, _ca = stack

    resp = _post(client, admin["signer"], "/api/chapter/allowlist/add",
                 _entry(chapter_id=OTHER_ORG, peer="attacker-chapter", actor=ADMIN))

    assert resp.status_code == 200, resp.text
    assert rows, "nothing was written"
    assert rows[0]["chapter_id"] == ORG, (
        f"the row landed on {rows[0]['chapter_id']!r}, which the request named, "
        f"rather than on the serving org {ORG!r}"
    )
    assert resp.json()["entry"]["chapter_id"] == ORG


def test_the_removal_targets_the_serving_org_not_the_body(stack):
    _mod, admin, _member, client, _rows, writes, _ca = stack

    resp = _post(client, admin["signer"], "/api/chapter/allowlist/remove",
                 _entry(chapter_id=OTHER_ORG, peer=REAL_PEER, actor=ADMIN))

    assert resp.status_code == 200, resp.text
    deletes = [w for w in writes if w[0] == "DELETE"]
    assert deletes, "no delete was issued"
    assert deletes[0][2]["chapter_id"] == f"eq.{ORG}", (
        f"the removal targeted {deletes[0][2]['chapter_id']!r} rather than the serving org"
    )


def test_the_audit_row_records_the_serving_org(stack):
    """The audit row is the record of a federation trust change; naming an org
    the write did not touch would make the ledger disagree with the table."""
    _mod, admin, _member, client, _rows, writes, _ca = stack

    _post(client, admin["signer"], "/api/chapter/allowlist/add",
          _entry(chapter_id=OTHER_ORG, peer="new-peer", actor=ADMIN))

    audit = [w for w in writes if w[1] == "chapter_audit_events"]
    assert audit, "no audit row was written"
    assert audit[0][2]["chapter_id"] == ORG


# ══════════════════════════════════════════════════════════════════════
# Every handler that takes an org or peer identifier from the request
# ══════════════════════════════════════════════════════════════════════
#
# The allowlist pair was not the only place a caller could name a scope it does
# not own. This enumerates the class from the app's own route table rather than
# listing the ones already found, so a handler added later joins it.

SCOPE_TOKENS = ("chapter_id", "peer_chapter_id", "peer_id", "org_id")
ROLE_CHECKS = (
    "_authorize_role",
    "_authorize_admin",
    "can_approve",
    "can_moderate",
    "is_leader",
    "get_chapter_role",
)

#: Handlers that accept a scope identifier and have no role check, each with the
#: reason it is acceptable or the reason it is not yet fixed. An entry here is a
#: statement someone can check, not a suppression.
SCOPE_WITHOUT_ROLE_CHECK: dict[tuple[str, str], str] = {
    ("POST", "/api/chapter/audit/record"): (
        "Intentional. Both identities are bound — the actor to the verified caller and "
        "the ledger to this org — so a member can only append an event attributed to "
        "themselves, to their own org's log. No role check, because appending an "
        "attributed event is what the endpoint is for."
    ),
}

#: This enumeration covers MUTATING routes only. It says nothing about reads, and
#: an empty list here does not mean every scope-identifier route is authorised.
#: GET /api/chapter/allowlist/{chapter_id} and GET /api/chapter/audit/{chapter_id}
#: (with its /export.jsonl and /verify siblings) used to answer an unauthenticated
#: request for any chapter_id — now leader-or-admin (allowlist) / admin
#: (audit trio) gated and scoped to this org, same as the write routes above
#: (tests/test_route_auth_classification.py::HANDLER_GATED_PATHS has each).


def _scope_handlers():
    import inspect
    import typing

    from fastapi.routing import APIRoute

    import chapter_agent

    # Both sources. Routers mounted from server/routes/ are absent from
    # chapter_agent.app.routes when the module is imported rather than run as
    # __main__ — the module-alias split test_api_doc_route_parity.py names. An
    # enumeration reading only the app silently omits every one of them, so this
    # scan would report clean on routes it never saw.
    from tests.test_mutating_routes_bind_the_actor import _router_module_routes

    out = []
    for route in list(chapter_agent.app.routes) + _router_module_routes():
        if not isinstance(route, APIRoute):
            continue
        methods = route.methods & {"POST", "PUT", "PATCH", "DELETE"}
        if not methods:
            continue
        fields = []
        try:
            hints = typing.get_type_hints(route.endpoint)
        except Exception:  # noqa: BLE001
            hints = {}
        for _param, annotation in hints.items():
            model_fields = getattr(annotation, "model_fields", None)
            if model_fields:
                fields += [f for f in model_fields if any(t in f.lower() for t in SCOPE_TOKENS)]
        for path_param in route.dependant.path_params or []:
            if any(t in path_param.name.lower() for t in SCOPE_TOKENS):
                fields.append(f"path:{path_param.name}")
        if not fields:
            continue
        try:
            source = inspect.getsource(route.endpoint)
        except (OSError, TypeError):
            source = ""
        has_role = any(check in source for check in ROLE_CHECKS)
        for method in sorted(methods):
            out.append((method, route.path, route.endpoint.__name__, fields, has_role))
    return out


def test_the_scope_enumeration_is_not_empty():
    assert _scope_handlers(), "no handlers take a scope identifier; the enumeration is broken"


def test_every_scope_handler_without_a_role_check_is_declared():
    undeclared = [
        f"{m} {p} -> {fn}() accepts {fields}"
        for m, p, fn, fields, has_role in _scope_handlers()
        if not has_role and (m, p) not in SCOPE_WITHOUT_ROLE_CHECK
    ]
    assert not undeclared, (
        "these handlers accept an org or peer identifier from the request and have no "
        "role check:\n  " + "\n  ".join(undeclared)
        + "\n\nAdd a role check, or declare it in SCOPE_WITHOUT_ROLE_CHECK with the reason."
    )


def test_no_declared_gap_has_quietly_been_fixed():
    """A declaration for a handler that now checks a role is a stale claim that
    the gap is still open."""
    by_key = {(m, p): has_role for m, p, _fn, _f, has_role in _scope_handlers()}
    stale = [
        f"{m} {p}" for (m, p) in SCOPE_WITHOUT_ROLE_CHECK if by_key.get((m, p)) is True
    ]
    assert not stale, "declared as lacking a role check but now has one:\n  " + "\n  ".join(stale)


def test_the_allowlist_pair_is_no_longer_in_the_declared_gaps():
    """The two this change fixed must be gone from the list, not merely passing."""
    for key in (("POST", "/api/chapter/allowlist/add"), ("POST", "/api/chapter/allowlist/remove")):
        assert key not in SCOPE_WITHOUT_ROLE_CHECK


# ══════════════════════════════════════════════════════════════════════
# The four reads: GET /api/chapter/allowlist/{id}, GET /api/chapter/audit/{id}
# and its /export.jsonl + /verify siblings — all four used to answer an
# unauthenticated request for ANY chapter_id.
# ══════════════════════════════════════════════════════════════════════

GET_ROUTES = [
    ("/api/chapter/allowlist/{}", {"leader", "admin"}),
    ("/api/chapter/audit/{}", {"admin"}),
    ("/api/chapter/audit/{}/verify", {"admin"}),
    ("/api/chapter/audit/{}/export.jsonl", {"admin"}),
]


@pytest.mark.parametrize("path_tpl,allowed_roles", GET_ROUTES)
def test_get_rejects_unauthenticated(stack, path_tpl, allowed_roles):
    _mod, _admin, _member, client, _rows, _writes, _ca = stack
    resp = _get(client, None, path_tpl.format(ORG))
    assert resp.status_code in (401, 403)


@pytest.mark.parametrize("path_tpl,allowed_roles", GET_ROUTES)
def test_get_rejects_a_different_chapter_id_even_for_an_authorized_role(stack, path_tpl, allowed_roles):
    """Signed as this org's own admin, naming a DIFFERENT org's chapter_id."""
    _mod, admin, _member, client, _rows, _writes, _ca = stack
    resp = _get(client, admin["signer"], path_tpl.format(OTHER_ORG))
    assert resp.status_code == 403


@pytest.mark.parametrize("path_tpl,allowed_roles", GET_ROUTES)
def test_get_rejects_a_role_not_in_the_allowed_set(stack, path_tpl, allowed_roles):
    """The plain member registered by the fixture has chapter_role='member',
    which is in neither {leader,admin} (allowlist) nor {admin} (audit trio)."""
    _mod, _admin, member, client, _rows, _writes, _ca = stack
    resp = _get(client, member["signer"], path_tpl.format(ORG))
    assert resp.status_code == 403


@pytest.mark.parametrize("path_tpl,allowed_roles", GET_ROUTES)
def test_get_allows_an_authorized_role_for_its_own_org(stack, path_tpl, allowed_roles):
    _mod, admin, _member, client, _rows, _writes, _ca = stack
    resp = _get(client, admin["signer"], path_tpl.format(ORG))
    assert resp.status_code == 200, resp.text
