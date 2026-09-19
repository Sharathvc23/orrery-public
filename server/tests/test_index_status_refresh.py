"""update_index_entry must record the heartbeat's REAL status so /health
reflects the live index state — not the stale boot-time 403.

Regression: the boot register_on_index runs before the chapter keypair is
ensured, so it can't attest and the lean index 403s once; the attested
heartbeat refresh (update_index_entry) succeeds, but until the fix it never
updated the status, leaving /health stuck on http_403 forever.
"""

from __future__ import annotations

import pytest


class _Resp:
    def __init__(self, code: int) -> None:
        self.status_code = code


class _PutClient:
    def __init__(self, code: int) -> None:
        self._code = code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def put(self, url, json=None, timeout=None):
        return _Resp(self._code)


def _wire(monkeypatch, code: int) -> None:
    import nanda_registry

    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", lambda *a, **k: _PutClient(code))
    monkeypatch.setattr(nanda_registry, "_index_urls", ["http://idx"])
    monkeypatch.setattr(nanda_registry, "_public_url", "https://org.example")
    monkeypatch.setattr(nanda_registry, "_agent_id", "demo")
    nanda_registry._last_status.pop("index:http://idx", None)


@pytest.mark.asyncio
async def test_successful_refresh_records_ok(monkeypatch) -> None:
    import nanda_registry

    _wire(monkeypatch, 200)
    ok = await nanda_registry.update_index_entry("demo", {"id": "x"})
    assert ok is True
    st = nanda_registry._last_status["index:http://idx"]
    assert st["last_ok"] is True
    assert st["detail"] == "updated"


@pytest.mark.asyncio
async def test_failed_refresh_records_the_http_status(monkeypatch) -> None:
    import nanda_registry

    _wire(monkeypatch, 403)
    ok = await nanda_registry.update_index_entry("demo", {"id": "x"})
    assert ok is False
    st = nanda_registry._last_status["index:http://idx"]
    assert st["last_ok"] is False
    assert st["detail"] == "http_403"
