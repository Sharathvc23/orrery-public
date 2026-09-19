"""Every run says which port each service has, and why.

The pin — ports allocated once, then read back from `.env` so the org's
did:web holds still — used to be invisible in the installer's output. The
only port line was printed when an allocation moved off its default, so a
re-run said nothing about ports at all, and a reader could not distinguish
"pinned" from "re-allocated to the same number" without opening `.env` and
comparing two banners. The property was real and unobservable.

Now `announce_ports` prints one line on every run naming every service's
port and its source: `allocated` (first run), `pinned in .env` (every run
after), `named by --<flag>` (an operator's choice). This module pins that
the line is printed for every source, not only when something moved.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_installer():
    spec = importlib.util.spec_from_loader(
        "orrery_up_ports_line",
        importlib.machinery.SourceFileLoader(
            "orrery_up_ports_line", str(REPO / "orrery-up")
        ),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installer():
    return _load_installer()


def _said(installer, monkeypatch, resolved) -> list[str]:
    lines: list[str] = []
    monkeypatch.setattr(installer, "say", lambda msg: lines.append(msg))
    installer.announce_ports(resolved)
    return lines


UNNAMED = SimpleNamespace(server_port=None, agent_port=None, renderer_port=None)
PINNED = {"SERVER_PORT": "7000", "AGENT_PORT": "8080", "RENDERER_PORT": "8600"}


def test_a_re_run_says_every_port_is_pinned(installer, monkeypatch):
    """THE DEFECT. Ports pinned at their defaults — the common re-run — must
    still produce a line, and that line must say `pinned` for each."""
    resolved = installer.resolve_ports(UNNAMED, PINNED)
    assert {c["source"] for c in resolved} == {"pinned"}

    lines = _said(installer, monkeypatch, resolved)

    assert len(lines) == 1, f"exactly one ports line per run, got {lines}"
    for c in resolved:
        assert f"{c['what']} {c['port']} (pinned in .env as {c['key']})" in lines[0], (
            lines[0]
        )


def test_a_first_run_says_allocated_even_at_the_default(installer, monkeypatch):
    """Allocation at the default and pinning at the default land on the same
    number; the words tell them apart."""
    resolved = [
        {**c, "source": "allocated", "port": c["default"]}
        for c in installer.resolve_ports(UNNAMED, PINNED)
    ]
    line = _said(installer, monkeypatch, resolved)[0]
    assert "pinned" not in line
    for c in resolved:
        assert f"{c['what']} {c['port']} (allocated at the default)" in line


def test_an_allocation_that_moved_names_the_busy_default(installer, monkeypatch):
    resolved = [
        {**c, "source": "allocated", "port": c["default"] + 1}
        for c in installer.resolve_ports(UNNAMED, PINNED)
    ]
    line = _said(installer, monkeypatch, resolved)[0]
    for c in resolved:
        assert (
            f"{c['what']} {c['port']} (allocated; default {c['default']} was busy)"
            in line
        )


def test_a_named_port_says_which_flag_named_it(installer, monkeypatch):
    named = SimpleNamespace(server_port=7100, agent_port=None, renderer_port=None)
    resolved = installer.resolve_ports(named, PINNED)
    line = _said(installer, monkeypatch, resolved)[0]
    assert "org server 7100 (named by --server-port)" in line
    assert "agent 8080 (pinned in .env as AGENT_PORT)" in line, (
        "naming one port must not relabel the others"
    )


def test_the_line_is_printed_on_the_up_path(installer):
    """Placement: after the ports are settled, before the stack is started,
    so the reader sees the decision before the build output scrolls past."""
    source = (REPO / "orrery-up").read_text(encoding="utf-8")
    up = source[source.index("    # up\n") :]
    assert up.index("settle_env(") < up.index("announce_ports(") < up.index("up()")
