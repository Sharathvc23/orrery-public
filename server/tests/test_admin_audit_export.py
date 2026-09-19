"""Tests for /admin/api/audit/export (A3.2).

Classification: HAPPY / EDGE / FAILURE / AUTHZ / ADVERSARIAL.

The read endpoint (A2) returns audit events as a JSON envelope. This
export endpoint emits the same data as a downloadable NDJSON file with
Content-Disposition: attachment, so operators can pipe it into a SIEM or
archive it for compliance retention. Same admin gate, same filter shape
as the read endpoint — by design, so an operator who can query can also
archive.

Scope (MVP): NDJSON format only. CSV, chain-integrity headers, and an
`until` filter are deliberately deferred to A3.2b if appetite emerges.
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENT_ID", "test-audit-chapter")
os.environ.setdefault("AGENT_NAME", "Test Audit Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def admin_token(monkeypatch):
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "test-token-abc123")
    import admin as admin_mod

    admin_mod._admin_token = "test-token-abc123"  # noqa: S105 — test stub, not a real secret
    return "test-token-abc123"


@pytest.fixture
def stub_audit_events(monkeypatch):
    """Replace chapter_audit.list_events with a controllable stub.

    Matches the shape stub_audit_events uses in test_admin_audit_endpoint.py
    so the export and read paths can be cross-checked against the same data.
    """
    events_data = [
        {
            "id": "audit-1",
            "occurred_at": "2026-05-23T08:00:00Z",
            "action": "admin.role.change",
            "actor_agent_id": "sharath",
            "target_type": "agent",
            "target_id": "ethan-kim-42",
            "outcome": "ok",
            "detail": {
                "role_before": "member",
                "role_after": "leader",
                "compliance_credential": {
                    "type": ["VerifiableCredential", "ComplianceCredential"],
                    "credentialSubject": {"rule_id": "nist-800-171:3.1.5"},
                },
            },
            "prev_hash": "sha256:abc",
            "hash": "sha256:def",
        },
        {
            "id": "audit-2",
            "occurred_at": "2026-05-23T09:00:00Z",
            "action": "admin.dsar.delete",
            "actor_agent_id": "sharath",
            "target_type": "data_subject",
            "target_id": "did:key:zSubject",
            "outcome": "ok",
            "detail": {"total_deleted": 5},
            "prev_hash": "sha256:def",
            "hash": "sha256:ghi",
        },
    ]

    import chapter_audit

    async def fake_list_events(*, chapter_id, action=None, actor_agent_id=None, since=None, limit=100):
        out = list(events_data)
        if action:
            out = [e for e in out if action in e["action"]]
        if actor_agent_id:
            out = [e for e in out if e["actor_agent_id"] == actor_agent_id]
        if since:
            out = [e for e in out if e["occurred_at"] >= since]
        return out[:limit]

    monkeypatch.setattr(chapter_audit, "list_events", fake_list_events)
    return events_data


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL + FAILURE come FIRST (per repo constitution)
# ══════════════════════════════════════════════════════════════════════


def test_AUTHZ_export_requires_admin(client, stub_audit_events):
    """Unauthenticated → 401. Exposing audit data without auth is the
    same kind of disclosure the read endpoint defends against."""
    resp = client.get("/admin/api/audit/export")
    assert resp.status_code == 401


def test_AUTHZ_export_rejects_wrong_token(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": "wrong-token"},
    )
    assert resp.status_code == 401


def test_FAILURE_export_supabase_error_returns_503(client, admin_token, monkeypatch):
    """If list_events raises (Postgres down, network error), return 503,
    not 500. 503 communicates 'try again' semantics to operators."""
    import chapter_audit

    async def boom(**_kwargs):
        raise RuntimeError("supabase timeout")

    monkeypatch.setattr(chapter_audit, "list_events", boom)

    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 503
    assert "supabase timeout" in resp.json()["detail"]


def test_ADVERSARIAL_huge_limit_value_is_clamped_not_crash(client, admin_token, stub_audit_events):
    """limit=99999999999 must clamp safely, not OverflowError or DOS the DB."""
    resp = client.get(
        "/admin/api/audit/export?limit=99999999999",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    # Body present, no crash; clamp behavior verified in EDGE tests below.


def test_ADVERSARIAL_action_filter_with_crlf_does_not_inject_headers(client, admin_token, stub_audit_events):
    """An action filter containing CRLF must NOT split into Content-Disposition.

    The filename is built from AGENT_ID (server-controlled), not from user
    input — so this is defense-in-depth. If a future refactor wires user
    input into the filename, this test fails and we notice.
    """
    # Percent-encoded CRLF — httpx blocks raw \r\n in URLs at the client
    # layer, so we encode to actually exercise the server's URL parser.
    resp = client.get(
        "/admin/api/audit/export?action=admin.role%0D%0AX-Injected:%20yes",
        headers={"X-Admin-Token": admin_token},
    )
    # Either 200 (filter just doesn't match anything) or 400 (rejected);
    # what MUST NOT happen is an injected response header.
    assert resp.status_code in (200, 400)
    assert "X-Injected" not in resp.headers


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_empty_result_returns_200_empty_body(client, admin_token, monkeypatch):
    """No matching events → 200 with empty NDJSON body. Not 404; an empty
    audit slice is a legitimate answer, not a missing resource."""
    import chapter_audit

    async def empty(**_kwargs):
        return []

    monkeypatch.setattr(chapter_audit, "list_events", empty)

    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    assert resp.text == ""
    assert resp.headers["content-type"].startswith("application/x-ndjson")


def test_EDGE_limit_clamps_to_1000(client, admin_token, stub_audit_events, monkeypatch):
    """limit=99999 → 1000. Matches the read endpoint's cap so callers
    don't have to memorize two different ceilings."""
    captured: dict[str, int] = {}
    import chapter_audit

    real_fake = chapter_audit.list_events  # the fixture's fake

    async def capture(**kwargs):
        captured["limit"] = kwargs.get("limit", -1)
        return await real_fake(**kwargs)

    monkeypatch.setattr(chapter_audit, "list_events", capture)
    resp = client.get(
        "/admin/api/audit/export?limit=99999",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    assert captured["limit"] == 1000


def test_EDGE_limit_minimum_clamps_to_1(client, admin_token, stub_audit_events, monkeypatch):
    """limit=0 → 1 (no zero-row exports — a zero-row response is fine but
    the upstream call should not pass 0, which Postgres treats unevenly)."""
    captured: dict[str, int] = {}
    import chapter_audit

    real_fake = chapter_audit.list_events

    async def capture(**kwargs):
        captured["limit"] = kwargs.get("limit", -1)
        return await real_fake(**kwargs)

    monkeypatch.setattr(chapter_audit, "list_events", capture)
    resp = client.get(
        "/admin/api/audit/export?limit=0",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    assert captured["limit"] == 1


def test_EDGE_each_line_is_valid_json(client, admin_token, stub_audit_events):
    """Every line of NDJSON must parse as JSON independently — that's the
    invariant SIEMs assume when consuming an NDJSON stream."""
    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    lines = [ln for ln in resp.text.split("\n") if ln.strip()]
    assert len(lines) == 2
    for ln in lines:
        parsed = json.loads(ln)
        assert "action" in parsed
        assert "hash" in parsed


def test_EDGE_compliance_credential_in_detail_preserved_verbatim(client, admin_token, stub_audit_events):
    """The W3C ComplianceCredential nested in `detail` must round-
    trip through NDJSON without re-shaping. Auditors verify VCs against the
    bytes they were given."""
    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    lines = [json.loads(ln) for ln in resp.text.split("\n") if ln.strip()]
    role_change = next(e for e in lines if e["action"] == "admin.role.change")
    cred = role_change["detail"]["compliance_credential"]
    assert "VerifiableCredential" in cred["type"]
    assert cred["credentialSubject"]["rule_id"] == "nist-800-171:3.1.5"


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_export_returns_ndjson_with_correct_media_type(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    lines = [ln for ln in resp.text.split("\n") if ln.strip()]
    assert len(lines) == 2


def test_HAPPY_export_content_disposition_is_attachment(client, admin_token, stub_audit_events):
    """Browsers must download the file rather than display it. Auditors
    expect a file on disk, not a tab."""
    resp = client.get(
        "/admin/api/audit/export",
        headers={"X-Admin-Token": admin_token},
    )
    cd = resp.headers.get("content-disposition", "")
    assert cd.startswith("attachment;")
    assert "filename=" in cd
    # Filename includes the runtime AGENT_ID and ends with .ndjson.
    # Pull AGENT_ID from chapter_agent rather than asserting a literal,
    # because pytest's module-import order can shuffle which test's
    # ``setdefault("AGENT_ID", ...)`` wins.
    assert chapter_agent.AGENT_ID in cd
    assert ".ndjson" in cd


def test_HAPPY_export_filter_by_action(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit/export?action=admin.dsar",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    lines = [json.loads(ln) for ln in resp.text.split("\n") if ln.strip()]
    assert len(lines) == 1
    assert lines[0]["action"] == "admin.dsar.delete"


def test_HAPPY_export_filter_by_actor(client, admin_token, stub_audit_events):
    resp = client.get(
        "/admin/api/audit/export?actor_agent_id=sharath",
        headers={"X-Admin-Token": admin_token},
    )
    lines = [json.loads(ln) for ln in resp.text.split("\n") if ln.strip()]
    assert len(lines) == 2  # both events from sharath


def test_HAPPY_export_filter_by_since(client, admin_token, stub_audit_events):
    """`since` becomes the SIEM watermark — repeated calls with the last
    occurred_at let operators ingest the ledger incrementally."""
    resp = client.get(
        "/admin/api/audit/export?since=2026-05-23T08:30:00Z",
        headers={"X-Admin-Token": admin_token},
    )
    lines = [json.loads(ln) for ln in resp.text.split("\n") if ln.strip()]
    assert len(lines) == 1
    assert lines[0]["occurred_at"] == "2026-05-23T09:00:00Z"
