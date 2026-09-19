"""The dashboard's listen address.

``/api/local/*`` carries no authentication and can change the consent gate's
settings, so the bind host decides who can reach it.
"""

from __future__ import annotations

import asyncio
import importlib
import socket
import sys

import pytest


def _reload_package(monkeypatch, value: str | None):
    """Re-import ``community_member`` with COMMUNITY_MEMBER_BIND_HOST set.

    The constant is read at import time, so the env var only takes effect on a
    fresh import.
    """
    if value is None:
        monkeypatch.delenv("COMMUNITY_MEMBER_BIND_HOST", raising=False)
    else:
        monkeypatch.setenv("COMMUNITY_MEMBER_BIND_HOST", value)
    return importlib.reload(sys.modules["community_member"])


def test_bind_host_defaults_to_loopback(monkeypatch):
    pkg = _reload_package(monkeypatch, None)
    try:
        assert pkg.DASHBOARD_BIND_HOST == "127.0.0.1"
    finally:
        _reload_package(monkeypatch, None)


def test_bind_host_is_overridable(monkeypatch):
    pkg = _reload_package(monkeypatch, "0.0.0.0")
    try:
        assert pkg.DASHBOARD_BIND_HOST == "0.0.0.0"
    finally:
        _reload_package(monkeypatch, None)


def test_blank_override_falls_back_to_loopback(monkeypatch):
    pkg = _reload_package(monkeypatch, "   ")
    try:
        assert pkg.DASHBOARD_BIND_HOST == "127.0.0.1"
    finally:
        _reload_package(monkeypatch, None)


def test_run_both_binds_the_configured_host(monkeypatch):
    """``_run_both`` hands uvicorn the bind host rather than all interfaces."""
    import uvicorn

    from community_member import cli

    captured: dict[str, object] = {}

    class _StopBeforeServing(Exception):
        pass

    def _fake_config(app, *, host, port, log_level):
        captured["host"] = host
        captured["port"] = port
        raise _StopBeforeServing

    monkeypatch.setattr(uvicorn, "Config", _fake_config)

    with pytest.raises(_StopBeforeServing):
        asyncio.run(cli._run_both(object(), object(), 7777))

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 7777


def test_run_both_accepts_an_explicit_host(monkeypatch):
    import uvicorn

    from community_member import cli

    captured: dict[str, object] = {}

    class _StopBeforeServing(Exception):
        pass

    def _fake_config(app, *, host, port, log_level):
        captured["host"] = host
        raise _StopBeforeServing

    monkeypatch.setattr(uvicorn, "Config", _fake_config)

    with pytest.raises(_StopBeforeServing):
        asyncio.run(cli._run_both(object(), object(), 7777, host="0.0.0.0"))

    assert captured["host"] == "0.0.0.0"


def test_find_free_port_probes_the_bind_host():
    """The port probe binds the address the server will bind.

    A port held on one interface must not make the probe skip a port that is
    free on the bind host.
    """
    from community_member import find_free_port

    port = find_free_port()
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    held.bind(("127.0.0.1", port))
    held.listen(1)
    try:
        assert find_free_port(port, host="127.0.0.1") != port
    finally:
        held.close()
