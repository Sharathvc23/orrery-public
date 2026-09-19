"""GET /api/ledger/earnings answers for the CALLER, never an arbitrary did.

``did`` used to be a plain, unverified query parameter: any caller — signed or
not — could read any DID's earnings by naming it, including a DID belonging to
a different org. Driven against a live chapter with a different org's DID and
confirmed to return a ledger record. Same class as the advisor-earnings /
today self-scoping fix (test_advisor_earnings_self_scoped.py): the verified
caller's OWN did:key replaces whatever ``did`` the request named.

Amounts read $0 in these tests (skill_revenue.get_earnings_for_did is stubbed
to record what it was asked about, not what it returns) — the finding is WHICH
PRINCIPAL is queried, not the amount.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import register_test_regular_member

OTHER_ORG_DID = "did:key:z6MkOtherOrgPrincipalNotTheCaller0000000000"


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-ledger-chapter")
    monkeypatch.setenv("AGENT_NAME", "Ledger Fixture Chapter")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    import auth_verify

    chapter_agent_module._rate_limit_store.clear()
    auth_verify._agent_keys.clear()
    return TestClient(chapter_agent_module.app)


@pytest.fixture
def recorded_dids(monkeypatch) -> list:
    """Record every did the earnings lookup is asked about, in call order."""
    seen: list = []

    async def _fake(did, since_iso=None):
        seen.append(did)
        return {"did": did, "total_cents": 0, "by_role": {}, "by_currency": {}, "event_count": 0}

    import skill_revenue

    monkeypatch.setattr(skill_revenue, "get_earnings_for_did", _fake)
    return seen


def test_unauthenticated_caller_is_rejected(client: TestClient, recorded_dids: list) -> None:
    """No signature at all: 401, and the lookup is never reached."""
    resp = client.get(f"/api/ledger/earnings?did={OTHER_ORG_DID}")
    assert resp.status_code == 401
    assert recorded_dids == []


def test_ADVERSARIAL_a_signed_callers_own_did_is_used_regardless_of_the_query_param(
    client: TestClient, chapter_agent_module, recorded_dids: list
) -> None:
    """THE GUARD. A genuinely signed, verified caller names a DIFFERENT org's
    DID in ``did=`` — the query param must be ignored and the caller's OWN
    resolved did:key used instead."""
    import sovereign_identity

    member = register_test_regular_member(chapter_agent_module, agent_id="alice")
    caller_did = sovereign_identity.build_did_key_from_ed25519(member["public_key"])

    url_path = f"/api/ledger/earnings?did={OTHER_ORG_DID}"
    headers = member["signer"](method="GET", url_path=url_path)
    resp = client.get(url_path, headers=headers)

    assert resp.status_code == 200
    assert recorded_dids == [caller_did], (
        f"expected the caller's own did:key to be queried, got {recorded_dids!r} "
        f"— a caller-supplied did reached the earnings lookup"
    )
    assert OTHER_ORG_DID not in recorded_dids


def test_a_signed_caller_with_no_did_param_gets_their_own_earnings(
    client: TestClient, chapter_agent_module, recorded_dids: list
) -> None:
    """Self-service still works with no ``did`` supplied at all."""
    import sovereign_identity

    member = register_test_regular_member(chapter_agent_module, agent_id="bob")
    caller_did = sovereign_identity.build_did_key_from_ed25519(member["public_key"])

    url_path = "/api/ledger/earnings"
    headers = member["signer"](method="GET", url_path=url_path)
    resp = client.get(url_path, headers=headers)

    assert resp.status_code == 200
    assert recorded_dids == [caller_did]


def test_chapter_aggregate_requires_this_chapters_own_caller_or_admin(
    client: TestClient, chapter_agent_module, recorded_dids: list
) -> None:
    """``did=chapter:<id>`` is the org's own aggregate, not a member's — a
    regular member signing a request must not be able to read it."""
    member = register_test_regular_member(chapter_agent_module, agent_id="carol")

    url_path = f"/api/ledger/earnings?did=chapter:{chapter_agent_module.AGENT_ID}"
    headers = member["signer"](method="GET", url_path=url_path)
    resp = client.get(url_path, headers=headers)

    assert resp.status_code == 403
    assert recorded_dids == []


def test_chapter_aggregate_is_reachable_by_the_chapter_itself(
    client: TestClient, chapter_agent_module, recorded_dids: list
) -> None:
    """The chapter's own signed identity (agent_id == AGENT_ID) may read its
    own aggregate."""
    member = register_test_regular_member(chapter_agent_module, agent_id=chapter_agent_module.AGENT_ID)

    url_path = f"/api/ledger/earnings?did=chapter:{chapter_agent_module.AGENT_ID}"
    headers = member["signer"](method="GET", url_path=url_path)
    resp = client.get(url_path, headers=headers)

    assert resp.status_code == 200
    assert recorded_dids == [f"chapter:{chapter_agent_module.AGENT_ID}"]


def test_chapter_aggregate_is_reachable_by_a_valid_admin_bearer(
    client: TestClient, chapter_agent_module, recorded_dids: list, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator's X-Admin-Token break-glass may also read the aggregate,
    with no member signature at all."""
    import admin as admin_mod

    monkeypatch.setattr(admin_mod, "verify_admin_token", lambda token: token == "the-real-admin-token")

    url_path = f"/api/ledger/earnings?did=chapter:{chapter_agent_module.AGENT_ID}"
    resp = client.get(url_path, headers={"X-Admin-Token": "the-real-admin-token"})

    assert resp.status_code == 200
    assert recorded_dids == [f"chapter:{chapter_agent_module.AGENT_ID}"]
