"""AgentFacts scoring_method selector (step 3) — GET /agentfacts/{member_id}.json
?scoring_method=nanda-rep/0.2.

Exposes the counterparty-corroborated score on request while the published DEFAULT
stays nanda-rep/0.1 (flipping the default is a separate deployment decision — step 5).
The facet self-describes its method, so a resolver never conflates the two.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AGENT_ID", "test-scoring-chapter")
os.environ.setdefault("AGENT_NAME", "Test Scoring Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import chapter_agent  # noqa: E402
import sovereign_identity  # noqa: E402


@pytest.fixture
def client_with_member():
    sovereign_identity._ed25519_keypairs.clear()
    sovereign_identity._facts_versions.clear()
    chapter_agent.members["alice"] = {"name": "Alice", "skills": ["python"], "description": "t", "public_key": ""}
    try:
        yield TestClient(chapter_agent.app)
    finally:
        chapter_agent.members.pop("alice", None)
        sovereign_identity._facts_versions.clear()


def test_unsupported_scoring_method_returns_400(client_with_member):  # FAILURE
    r = client_with_member.get("/agentfacts/alice.json", params={"scoring_method": "nanda-rep/9.9"})
    assert r.status_code == 400
    assert "unsupported scoring_method" in r.json()["detail"]


def test_default_method_served_and_is_v01(client_with_member):  # HAPPY — flip-safe default
    r = client_with_member.get("/agentfacts/alice.json")
    assert r.status_code == 200
    # Default ETag carries no method tag (back-compatible with existing consumers).
    assert r.headers["ETag"].endswith('"') and "+nanda-rep" not in r.headers["ETag"]


def test_v2_method_accepted(client_with_member):  # HAPPY — opt-in corroborated score
    r = client_with_member.get("/agentfacts/alice.json", params={"scoring_method": "nanda-rep/0.2"})
    assert r.status_code == 200


def test_etag_varies_by_scoring_method(client_with_member):  # EDGE — cache correctness
    """A conditional GET for one method must never be answered 304 against another
    method's cached card — so the ETag must differ by scoring_method."""
    default = client_with_member.get("/agentfacts/alice.json").headers["ETag"]
    v2 = client_with_member.get("/agentfacts/alice.json", params={"scoring_method": "nanda-rep/0.2"}).headers["ETag"]
    assert default != v2
    assert "nanda-rep/0.2" in v2


def test_unknown_member_still_404(client_with_member):  # EDGE — 404 precedes method validation
    assert (
        client_with_member.get("/agentfacts/nobody.json", params={"scoring_method": "nanda-rep/0.2"}).status_code == 404
    )


# ── /.well-known/ canonical paths (root retained as back-compat alias) ──


def test_agentfacts_served_under_well_known(client_with_member):  # HAPPY — canonical web-discovery path
    root = client_with_member.get("/agentfacts.json")
    wk = client_with_member.get("/.well-known/agentfacts.json")
    assert root.status_code == 200 and wk.status_code == 200
    assert wk.json()["id"] == root.json()["id"]  # same document at both paths


def test_member_agentfacts_served_under_well_known(client_with_member):  # HAPPY
    root = client_with_member.get("/agentfacts/alice.json")
    wk = client_with_member.get("/.well-known/agentfacts/alice.json")
    assert root.status_code == 200 and wk.status_code == 200
    assert wk.json()["id"] == root.json()["id"]


def test_well_known_member_agentfacts_404_for_unknown(client_with_member):  # EDGE
    assert client_with_member.get("/.well-known/agentfacts/ghost.json").status_code == 404
