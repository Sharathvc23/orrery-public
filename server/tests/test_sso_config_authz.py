"""The SSO configuration is readable and writable only by this org's leaders.

An identity-provider binding names the party that decides who may authenticate
to an org. All three endpoints were reachable by any member, or by nobody at
all, for any org id the caller chose to name:

  GET    /api/chapter/sso/{chapter_id}   no authentication
  POST   /api/chapter/sso                member signature; chapter_id from the body
  DELETE /api/chapter/sso/{chapter_id}   member signature; chapter_id from the path

Measured before the change: an ordinary member of one org set another org's
config to an attacker-controlled ``issuer_url`` with ``enforce_sso`` true and
received 200, and cleared another org's config and received 200. The read
required nothing at all, so the same caller could inspect the binding before
replacing it.

``chapter_sso_set`` and ``chapter_sso_clear`` took no ``Request`` parameter, so
they could not consult the caller even in principle — the same shape as
``chapter_audit_record`` before its actor was bound.

WHAT ENFORCE_SSO ACTUALLY DOES TODAY, because it bounds the impact:
``get_sso_config`` has two consumers — the read endpoint and the org-security
A2UI surface. No authentication path reads it. Setting ``enforce_sso`` changes
what that surface displays, including a "required (login blocked without)" label
and a posture of "private", and blocks no login. The takeover is of a
configuration that is displayed and not yet enforced; the tests below do not
assume otherwise.
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

ORG = "TEST-sso-org"
OTHER_ORG = "SOMEONE-ELSE-ENTIRELY"
LEADER = "sso-leader-carol"
MEMBER = "sso-ordinary-alice"

ATTACKER_CONFIG = {
    "chapter_id": OTHER_ORG,
    "provider": "okta",
    "issuer_url": "https://attacker.example",
    "client_id": "attacker",
    "enforce_sso": True,
}


@pytest.fixture
def stack(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch, agent_id=ORG)
    mod.members.clear()
    writes: list[tuple] = []

    async def fake_pg(method, table, params=None, body=None, **kw):
        if method in {"POST", "PATCH", "PUT", "DELETE"}:
            writes.append((method, table, body, params))
            return [dict(body or {}, id="row-1")]
        return []

    import chapter_audit
    import chapter_auth
    import governance

    chapter_auth.init(fake_pg)
    chapter_audit.init(fake_pg)

    leader = register_test_regular_member(mod, agent_id=LEADER, name="Carol", chapter_role="leader")
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Alice")
    register_test_admin_member(mod, agent_id="sso-admin", name="Admin")

    async def role_of(agent_id: str) -> str:
        return (mod.members.get(agent_id) or {}).get("chapter_role", "member")

    monkeypatch.setattr(governance, "get_chapter_role", role_of)
    return mod, leader, member, TestClient(mod.app), writes


def _post(client, signer, path: str, payload: dict):
    body = json.dumps(payload, separators=(",", ":"))
    headers = signer(method="POST", url_path=path, body=body)
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


def _delete(client, signer, path: str):
    return client.delete(path, headers=signer(method="DELETE", url_path=path, body=""))


def _get(client, signer, path: str):
    return client.get(path, headers=signer(method="GET", url_path=path, body=""))


# ══════════════════════════════════════════════════════════════════════
# The cross-tenant case
# ══════════════════════════════════════════════════════════════════════


def test_a_leader_of_this_org_cannot_write_another_orgs_sso_config(stack):
    """A role check alone would leave a leader of one org configuring another.
    The target is this org, so naming a different one changes nothing about
    where the write lands."""
    _mod, leader, _member, client, writes = stack

    resp = _post(client, leader["signer"], "/api/chapter/sso", ATTACKER_CONFIG)

    assert resp.status_code == 200, resp.text
    assert resp.json()["sso"]["chapter_id"] == ORG, (
        f"the config landed on {resp.json()['sso']['chapter_id']!r}, which the request named"
    )
    sso_writes = [w for w in writes if w[1] == "chapter_sso_configs"]
    assert sso_writes and sso_writes[0][2]["chapter_id"] == ORG


def test_a_leader_of_this_org_cannot_clear_another_orgs_sso_config(stack):
    _mod, leader, _member, client, _writes = stack
    resp = _delete(client, leader["signer"], f"/api/chapter/sso/{OTHER_ORG}")
    assert resp.status_code == 403, f"cleared another org's config: {resp.text[:200]}"


def test_a_leader_of_this_org_cannot_read_another_orgs_sso_config(stack):
    _mod, leader, _member, client, _writes = stack
    resp = _get(client, leader["signer"], f"/api/chapter/sso/{OTHER_ORG}")
    assert resp.status_code == 403, f"read another org's config: {resp.text[:200]}"


# ══════════════════════════════════════════════════════════════════════
# Who may reach these endpoints at all
# ══════════════════════════════════════════════════════════════════════


def test_an_ordinary_member_cannot_write_the_sso_config(stack):
    _mod, _leader, member, client, writes = stack
    resp = _post(client, member["signer"], "/api/chapter/sso", dict(ATTACKER_CONFIG, chapter_id=ORG))
    assert resp.status_code == 403, f"an ordinary member configured SSO: {resp.text[:200]}"
    assert not [w for w in writes if w[1] == "chapter_sso_configs"]


def test_an_ordinary_member_cannot_clear_the_sso_config(stack):
    _mod, _leader, member, client, _writes = stack
    resp = _delete(client, member["signer"], f"/api/chapter/sso/{ORG}")
    assert resp.status_code == 403


def test_an_ordinary_member_cannot_read_the_sso_config(stack):
    """The read is reconnaissance for the write: issuer, client id and whether
    enforcement is claimed are what a caller needs to aim a replacement."""
    _mod, _leader, member, client, _writes = stack
    resp = _get(client, member["signer"], f"/api/chapter/sso/{ORG}")
    assert resp.status_code == 403


def test_an_unauthenticated_caller_cannot_read_the_sso_config(stack):
    _mod, _leader, _member, client, _writes = stack
    resp = client.get(f"/api/chapter/sso/{ORG}")
    assert resp.status_code in (401, 403), (
        f"the SSO config answered an unauthenticated request: {resp.status_code} {resp.text[:200]}"
    )


def test_an_unauthenticated_caller_cannot_write_the_sso_config(stack):
    _mod, _leader, _member, client, writes = stack
    resp = client.post("/api/chapter/sso", json=dict(ATTACKER_CONFIG, chapter_id=ORG))
    assert resp.status_code in (401, 403)
    assert not [w for w in writes if w[1] == "chapter_sso_configs"]


def test_a_leader_can_configure_and_clear_this_orgs_sso(stack):
    """The gate must not have closed the endpoint to everyone."""
    _mod, leader, _member, client, _writes = stack

    written = _post(client, leader["signer"], "/api/chapter/sso", dict(ATTACKER_CONFIG, chapter_id=ORG))
    assert written.status_code == 200, written.text

    read = _get(client, leader["signer"], f"/api/chapter/sso/{ORG}")
    assert read.status_code == 200, read.text

    cleared = _delete(client, leader["signer"], f"/api/chapter/sso/{ORG}")
    assert cleared.status_code == 200, cleared.text


def test_the_sso_audit_row_names_this_org_and_the_verified_caller(stack):
    _mod, leader, _member, client, writes = stack
    _post(client, leader["signer"], "/api/chapter/sso", dict(ATTACKER_CONFIG, chapter_id=ORG))
    audit = [w for w in writes if w[1] == "chapter_audit_events"]
    assert audit, "an SSO change was not audited"
    assert audit[0][2]["chapter_id"] == ORG
    assert audit[0][2]["actor_agent_id"] == LEADER


# ══════════════════════════════════════════════════════════════════════
# The audit ledger a member may append to is this org's
# ══════════════════════════════════════════════════════════════════════


def test_an_audit_row_is_written_to_this_orgs_ledger_not_the_named_one(stack):
    """The actor was already bound to the verified caller. The ledger was not:
    chapter_id came from the body, so a correctly-attributed row could be
    appended to a different org's hash-chained ledger."""
    _mod, _leader, member, client, writes = stack

    resp = _post(
        client,
        member["signer"],
        "/api/chapter/audit/record",
        {
            "chapter_id": OTHER_ORG,
            "action": "member.delete",
            "actor_agent_id": MEMBER,
            "outcome": "ok",
        },
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["event"]["chapter_id"] == ORG
    rows = [w for w in writes if w[1] == "chapter_audit_events"]
    assert rows and rows[0][2]["chapter_id"] == ORG, (
        "the row landed on the ledger the request named rather than this org's"
    )


# ══════════════════════════════════════════════════════════════════════
# enforce_sso is displayed, not enforced
# ══════════════════════════════════════════════════════════════════════


def test_no_authentication_path_reads_the_sso_config():
    """Recorded because it bounds the severity of the takeover, and because a
    future change that starts enforcing SSO inherits whatever is in this table.

    ``get_sso_config`` is called from the read endpoint and from the
    org-security surface. If a third caller appears in an authentication path,
    this test fails and the impact of a stale or hostile row changes.
    """
    import subprocess
    from pathlib import Path

    server = Path(__file__).resolve().parents[1]
    out = subprocess.run(
        ["git", "grep", "-n", "get_sso_config", "--", "."],
        cwd=server,
        capture_output=True,
        text=True,
    ).stdout
    call_sites = [
        line
        for line in out.splitlines()
        if "get_sso_config(" in line and "async def" not in line and "/tests/" not in line
    ]
    files = {line.split(":")[0] for line in call_sites}
    assert files <= {"chapter_agent.py", "surfaces.py", "chapter_auth.py"}, (
        f"get_sso_config gained a caller outside the read endpoint and the security "
        f"surface: {sorted(files)}. If one of them is an authentication path, "
        f"enforce_sso is now load-bearing and this table's contents matter more."
    )
