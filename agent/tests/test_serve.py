"""serve.py headless launcher — the cheap, side-effect-free units.

The full boot + stable-identity-across-restart path is verified by the
Dockerfile.agent restart smoke (binds 0.0.0.0:$PORT, same did:key after a
redeploy against the same volume). Here we pin only the pure helpers.
"""

from __future__ import annotations

import serve


def test_resolve_port_reads_railway_PORT(monkeypatch) -> None:
    monkeypatch.setenv("PORT", "9123")
    assert serve._resolve_port() == 9123


def test_resolve_port_falls_back_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("PORT", raising=False)
    assert serve._resolve_port() == serve.DASHBOARD_PORT


def test_resolve_port_falls_back_on_garbage(monkeypatch) -> None:
    monkeypatch.setenv("PORT", "not-a-number")
    assert serve._resolve_port() == serve.DASHBOARD_PORT
