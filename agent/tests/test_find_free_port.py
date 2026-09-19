"""The dashboard auto-picks a free port so it runs even when 7777 is taken."""

from __future__ import annotations

import socket

from community_member import find_free_port


def _occupy(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    return s


def _is_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def test_returns_preferred_when_free():
    # Find a definitely-free port, then ask for it.
    free = find_free_port()
    assert find_free_port(free) == free


def test_skips_an_occupied_port():
    base = find_free_port()
    held = _occupy(base)
    try:
        picked = find_free_port(base)
        assert picked != base
        assert _is_free(picked)
    finally:
        held.close()


def test_always_returns_a_usable_port():
    p = find_free_port()
    assert isinstance(p, int) and 1024 <= p <= 65535
    assert _is_free(p)
