"""P1 — PostgREST filter injection under the service-role key.

Several sinks baked user-controlled values straight into the PostgREST resource
string, e.g. ``f"agent_intents?id=eq.{intent_id}"``. Because pg_request
runs with the SERVICE_KEY (BYPASSRLS) and httpx does NOT re-encode a filter
that's already part of the table argument, a crafted id (``...&select=*``,
``...&or=(...)``) could tamper with the query / exfiltrate across the row set.

The fix routes every filter through ``params=`` so httpx percent-encodes the
value — ``&``/``=``/``(`` in an id become literal characters PostgREST treats as
part of the value, never query syntax.

These tests assert the load-bearing invariant: the table argument carries NO
``?`` filter, and the filter rides in ``params``.

Classification: ADVERSARIAL.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import consent_gate  # noqa: E402
import intents as intents_mod  # noqa: E402

EVIL = "00000000-0000-0000-0000-000000000000&select=*"


def _assert_no_baked_filter(calls, method):
    hits = [c for c in calls if c[0] == method]
    assert hits, f"no {method} call captured"
    for _m, table, params in hits:
        assert "?" not in table, f"{method}: filter baked into table arg {table!r} (injectable)"
        assert params, f"{method}: filter not routed through params"


@pytest.mark.asyncio
async def test_respond_to_intent_patch_uses_params(monkeypatch):
    calls = []

    async def fake(method, table, params=None, body=None):
        calls.append((method, table, params))
        if method == "GET":
            return [{"id": "r1", "response": "pending"}]  # matched responder
        return None

    monkeypatch.setattr(consent_gate, "_pg_request", fake)
    await consent_gate.respond_to_intent(EVIL, "alice", "accept")
    _assert_no_baked_filter(calls, "PATCH")


@pytest.mark.asyncio
async def test_check_mutual_consent_patch_uses_params(monkeypatch):
    calls = []

    async def fake(method, table, params=None, body=None):
        calls.append((method, table, params))
        if method == "GET" and table == "agent_intents":
            return [{"requester_agent_id": "alice", "intent_text": "x", "intent_tags": []}]
        if method == "GET" and table == "agents":
            return [{"agent_id": "alice", "name": "A"}]
        return None

    monkeypatch.setattr(consent_gate, "_pg_request", fake)
    await consent_gate.check_mutual_consent(EVIL, "bob")
    _assert_no_baked_filter(calls, "PATCH")


@pytest.mark.asyncio
async def test_cancel_intent_patch_uses_params(monkeypatch):
    calls = []

    async def fake(method, table, params=None, body=None):
        calls.append((method, table, params))
        if method == "GET":
            return [{"id": "i1"}]  # owned
        return None

    monkeypatch.setattr(intents_mod, "_pg_request", fake)
    await intents_mod.cancel_intent(EVIL, "alice")
    _assert_no_baked_filter(calls, "PATCH")
