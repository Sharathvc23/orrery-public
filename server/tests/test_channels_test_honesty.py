"""P2 — channels.test() must not report a fake "✓ ok".

channels.test() is a stub (W7 wires real Slack/IMAP/SMTP checks) but it wrote
last_test_ok=True, which the admin UI rendered as a literal "✓ ok" chip — a human
clicking "test connection" ALWAYS saw green. Now the stub records last_test_ok=NULL
(untested) and the surface renders "untested" for a recorded-but-unverified attempt.

Classification: FAILURE (misleading green).
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import channels  # noqa: E402
import surfaces  # noqa: E402


@pytest.mark.asyncio
async def test_stub_test_does_not_claim_ok(monkeypatch):
    captured = {}

    async def fake_sb(method, table, params=None, body=None):
        if method == "GET":
            return [{"id": "c1", "kind": "slack", "display_name": "x", "remote_id": "r", "status": "active"}]
        if method == "PATCH":
            captured["body"] = body
        return None

    monkeypatch.setattr(channels, "_pg_request", fake_sb)
    out = await channels.test("c1")

    assert out["ok"] is None, "stub claimed ok"
    assert out["stub"] is True
    assert captured["body"]["last_test_ok"] is None, "stub still wrote a fake last_test_ok=True"


@pytest.mark.asyncio
async def test_surface_renders_untested_not_ok_for_stub(monkeypatch):
    async def fake_list(target):
        return [
            {
                "kind": "slack",
                "display_name": "Acme Slack",
                "remote_id": "T123",
                "status": "active",
                "last_test_at": "2026-06-22T00:00:00Z",
                "last_test_ok": None,  # the stub attempt — recorded but not verified
            }
        ]

    # build_channels_surface does `import channels as channels_mod`, so patching
    # the real channels.list_connections is what it calls.
    monkeypatch.setattr(channels, "list_connections", fake_list)
    out = await surfaces.build_channels_surface(target="alice")
    blob = json.dumps(out)
    assert "untested" in blob, "stub connection not surfaced as untested"
    assert "✓ ok" not in blob, "stub connection still rendered as a false ✓ ok"
