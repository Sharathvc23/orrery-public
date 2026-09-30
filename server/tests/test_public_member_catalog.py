"""Whether an anonymous caller sees member entries, and what they contain.

The member list was closed to anonymous callers after an audit found a member's
free-text description carrying an email address and a phone number, both reachable
by an unauthenticated GET. That closure is still the default, and these tests pin
it.

What is new is that an org can opt in. Two things make that defensible, and both
are asserted here rather than argued: ``description`` cannot leave by this route
at all, and what an opted-in org publishes is exactly what ``PUBLICATION_NOTICE``
already tells every registrant goes "to any crawler that resolves this member's
AgentFacts or catalog entry".

The reason to want it: without member entries, a resolver that has followed the
public index to this document learns that N agents exist and nothing about which
one to ask. Measured on the live estate — every org answered a capability query
with the same undifferentiated result, because the only searchable thing was the
org row.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

_AGENT_ID = "publiccat"
_FLAG = "ORG_PUBLIC_MEMBER_CATALOG"
_LEAKY_PHONE = "555-0100"
_LEAKY_EMAIL = "ceo@example.invalid"


@pytest.fixture
def org(monkeypatch: pytest.MonkeyPatch):
    """A freshly imported org with two members that both have resolvable cards."""
    monkeypatch.setenv("AGENT_ID", _AGENT_ID)
    monkeypatch.setenv("AGENT_NAME", "Public Catalog Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "An org for the public-catalog tests")
    monkeypatch.setenv("AGENT_FOCUS", "scheduling, booking")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv(_FLAG, raising=False)
    # routes.identity caches a module reference to chapter_agent and reads
    # `ca.members`; both must be dropped together or the route consults a stale
    # object. Same reasoning as test_index_v2_registration's fixture.
    for name in [m for m in list(sys.modules) if m == "routes" or m.startswith("routes.")]:
        sys.modules.pop(name, None)
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(
        mod,
        "members",
        {
            "regentix-ceo": {
                "name": "Chief Executive",
                "description": f"reach me on {_LEAKY_PHONE} or {_LEAKY_EMAIL}",
                "endpoint": "https://ceo.example",
                "skills": ["executive", "scheduling", "negotiation"],
            },
            "regentix-ops": {
                "name": "Head of Operations",
                "description": "",
                "endpoint": "https://ops.example",
                "skills": ["operations", "logistics"],
            },
        },
    )
    return mod


@pytest.fixture
def client(org) -> TestClient:
    org._rate_limit_store.clear()
    return TestClient(org.app)


def _catalog(client: TestClient) -> dict:
    response = client.get("/.well-known/ai-catalog.json")
    assert response.status_code == 200
    return response.json()


def _members_in(doc: dict) -> list[str]:
    return sorted(e["identifier"] for e in doc["entries"] if e["identifier"].startswith("regentix-"))


def test_by_default_an_anonymous_caller_still_sees_no_members(client):
    """The closure holds unless an operator turns it off."""
    doc = _catalog(client)
    assert _members_in(doc) == []
    assert doc["withheldMembers"] == 2


def test_an_unrecognised_flag_value_does_not_open_the_surface(client, monkeypatch):
    # "the operator did not decide" must fail closed, not open.
    monkeypatch.setenv(_FLAG, "maybe")
    assert _catalog(client)["withheldMembers"] == 2


def test_an_opted_in_org_publishes_its_members_to_anyone(client, monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    doc = _catalog(client)
    assert _members_in(doc) == ["regentix-ceo", "regentix-ops"]
    assert doc["withheldMembers"] == 0


def test_the_free_text_description_never_leaves_by_this_route(client, monkeypatch):
    """The audit finding, as a property, in both directions of the flag."""
    for flag in ("1", "0"):
        monkeypatch.setenv(_FLAG, flag)
        raw = client.get("/.well-known/ai-catalog.json").text
        assert _LEAKY_PHONE not in raw, f"phone number published with flag={flag}"
        assert _LEAKY_EMAIL not in raw, f"email published with flag={flag}"


def test_an_entry_carries_the_capabilities_that_make_it_searchable(client, monkeypatch):
    """Without these the catalog can be enumerated but not searched."""
    monkeypatch.setenv(_FLAG, "1")
    entries = {e["identifier"]: e for e in _catalog(client)["entries"]}
    assert entries["regentix-ceo"]["tags"] == ["executive", "scheduling", "negotiation"]
    assert entries["regentix-ops"]["tags"] == ["operations", "logistics"]
    # And still no description, which is the field the audit was about.
    assert entries["regentix-ceo"]["description"] == ""


def test_a_member_with_no_skills_gets_an_empty_list_not_a_missing_key(client, monkeypatch, org):
    """A resolver reading ``entry["tags"]`` must not have to guess whether it exists."""
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setattr(
        org,
        "members",
        {"quiet": {"name": "Quiet", "description": "", "endpoint": "https://quiet.example"}},
    )
    entry = [e for e in _catalog(client)["entries"] if e["identifier"] == "quiet"][0]
    assert entry["tags"] == []


def test_the_org_entry_is_present_either_way(client, monkeypatch):
    """The flag governs MEMBERS. The org's own entry is the hop the index points at
    and must never depend on it."""
    for flag in ("1", "0"):
        monkeypatch.setenv(_FLAG, flag)
        doc = _catalog(client)
        assert any(e["identifier"] == _AGENT_ID for e in doc["entries"]), f"org entry lost with flag={flag}"
