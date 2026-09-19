"""the divergence detector is observable over HTTP.

Two things this locks:

1. ``federation.registry.divergence`` is a REGISTERED event type — so the
   detector's ``event_bus`` emit actually persists instead of being silently
   swallowed by ``safe_publish`` (the root cause of that change: the type was absent
   from the closed enum, so ``validate_event`` raised and the finding was
   dropped on the floor). Every finding shape the detector emits validates.

2. ``GET /api/federation/divergence`` renders planted findings from
   ``event_log`` — the read surface the sweep needed to see the detector work.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import importlib  # noqa: E402
import sys  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import event_types  # noqa: E402

# The exact finding shapes registry_divergence emits (one per kind).
FINDINGS = [
    {"kind": "omission", "agent_id": "acme", "present_on": ["https://a"], "missing_from": ["https://b"]},
    {"kind": "endpoint", "agent_id": "acme", "endpoints": {"https://a": "https://real", "https://b": "https://evil"}},
    {"kind": "did", "agent_id": "acme", "dids": {"https://a": "did:key:z1", "https://b": "did:key:z2"}},
    {"kind": "unconfirmed", "agent_id": "acme", "present_on": ["https://a"], "unconfirmed_on": ["https://b"]},
]


@pytest.mark.parametrize("finding", FINDINGS)
def test_every_finding_shape_is_a_valid_registered_event(finding):
    """Root-cause guard: before that change the type was unregistered, so
    validate_event raised and safe_publish swallowed it — findings never
    persisted. Each kind the detector emits must now validate."""
    validated = event_types.validate_event("federation.registry.divergence", finding)
    assert validated.kind == finding["kind"]
    assert validated.agent_id == "acme"


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        event_types.validate_event("federation.registry.divergence", {"kind": "bogus", "agent_id": "x"})


@pytest.fixture
def chapter_app(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "test-div-chapter")
    monkeypatch.setenv("AGENT_NAME", "Test Div Chapter")
    monkeypatch.setenv("XAI_API_KEY", "test")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


def test_endpoint_renders_planted_findings(chapter_app, monkeypatch):
    """A planted event_log row (what a real publish stores) renders through
    GET /api/federation/divergence with kind/agent_id/detail intact."""
    captured = {}

    async def fake_pg(method, table, params=None, body=None):
        captured["table"] = table
        captured["params"] = params
        # event_log rows as PostgREST returns them (id desc).
        return [
            {"id": 42, "created_at": "2026-07-08T20:00:00Z", "payload": FINDINGS[1]},  # endpoint
            {"id": 41, "created_at": "2026-07-08T19:59:00Z", "payload": FINDINGS[0]},  # omission
        ]

    monkeypatch.setattr(chapter_app, "pg_request", fake_pg)
    client = TestClient(chapter_app.app)

    r = client.get("/api/federation/divergence")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    # Queried the right table + event_type, newest-first.
    assert captured["table"] == "event_log"
    assert captured["params"]["event_type"] == "eq.federation.registry.divergence"

    first = body["findings"][0]
    assert first["event_id"] == 42
    assert first["kind"] == "endpoint"
    assert first["agent_id"] == "acme"
    assert first["observed_at"] == "2026-07-08T20:00:00Z"
    assert first["detail"]["endpoints"] == {"https://a": "https://real", "https://b": "https://evil"}
    # Envelope keys are not duplicated into detail.
    assert "kind" not in first["detail"] and "agent_id" not in first["detail"]

    assert body["findings"][1]["kind"] == "omission"
    assert body["findings"][1]["detail"]["missing_from"] == ["https://b"]


def test_endpoint_empty_when_no_findings(chapter_app, monkeypatch):
    async def fake_pg(method, table, params=None, body=None):
        return []

    monkeypatch.setattr(chapter_app, "pg_request", fake_pg)
    client = TestClient(chapter_app.app)
    r = client.get("/api/federation/divergence")
    assert r.status_code == 200
    body = r.json()
    assert body["findings"] == []
    assert body["total"] == 0
    # An empty list is the ambiguous case this endpoint most needs to explain:
    # it means "compared everything, found nothing" OR "compared nothing". The
    # status travels with the response so a reader does not have to cross-
    # reference /health to tell which — regentix ran as the second case for
    # weeks and looked exactly like the first.
    assert "corroboration" in body, "an empty findings list must say whether anything was compared"
    assert "corroborating" in body["corroboration"]


def test_endpoint_limit_clamped(chapter_app, monkeypatch):
    seen = {}

    async def fake_pg(method, table, params=None, body=None):
        seen["limit"] = params.get("limit")
        return []

    monkeypatch.setattr(chapter_app, "pg_request", fake_pg)
    client = TestClient(chapter_app.app)
    client.get("/api/federation/divergence?limit=9999")
    assert seen["limit"] == "500"  # clamped
    client.get("/api/federation/divergence?limit=0")
    assert seen["limit"] == "1"  # floored
