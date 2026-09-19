"""Every command README.md and docs/QUICKSTART.md show is one that was driven.

The release pages promise a reader that the commands on them ran, end to end,
on a clean machine before they were written down. A command composed for the
page — plausible, unrun — is the failure this guard exists to refuse: it reads
as tested and is not.

``DRIVEN`` is the list of commands the release drives executed, each with the
drive that ran it. A fenced ``bash`` block on either page may contain only
lines that match an entry (exactly, or by the entry's pattern where an argument
is the reader's to supply). Adding a command to a page therefore means adding
it here with its drive — which is the point: the list is the evidence, and a
line that cannot name its drive does not belong on the page.

Comments after ``#`` and blank lines are ignored; a ``$``/``>`` prompt prefix
is stripped. Only ``bash`` blocks are commands; ``text`` and untagged blocks
are output samples or configuration and are not checked.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGES = ("README.md", "docs/QUICKSTART.md")

#: (pattern, drive that ran it). A plain string matches exactly; a compiled
#: pattern matches the whole line.
DRIVEN: tuple[tuple[str | re.Pattern[str], str], ...] = (
    # ── path 1: verify evidence with sm-arp alone — the VERIFY_A_RECEIPT recipe,
    #    run against a stock keyless org (the venv built with uv where ensurepip
    #    was absent, per the page's own caveat)
    ("python3 -m venv verify-receipt", "verify-a-receipt drive"),
    ("source verify-receipt/bin/activate", "verify-a-receipt drive"),
    ("pip install sm-arp", "verify-a-receipt drive"),
    # ── path 2: the MCP server over stdio with a stock client, from the
    #    mcp_server README's own block; the wizard command is the one
    #    register_agent names and the CLI parses
    (
        "pip install -r agent/requirements.lock",
        "mcp stdio drive; the mcp_server CI job",
    ),
    ("pip install -e ./agent --no-deps", "mcp stdio drive; the mcp_server CI job"),
    ('pip install "mcp>=1.24.0,<2.0.0"', "mcp stdio drive; the mcp_server CI job"),
    ("python -m mcp_server", "mcp stdio drive; mcp_server/test_stdio_oracle.py"),
    (
        re.compile(r"community-member wizard --express --name \S+"),
        "mcp stdio drive; agent/tests/test_cli.py",
    ),
    # ── path 3: the installer, from a clean clone
    (
        "git clone https://github.com/Sharathvc23/orrery-public",
        "clean-install drives; tests/test_clone_instruction.py",
    ),
    ("cd orrery-public", "clean-install drives; tests/test_clone_instruction.py"),
    ("./orrery-up", "clean-install drives; the installer CI job"),
    ("./orrery-up --yes", "clean-install drives; the installer CI job"),
    (
        "./orrery-up down",
        "installer teardown drives; scripts/installer_lifecycle_check.py",
    ),
    (
        "./orrery-up down --purge",
        "installer teardown drives; scripts/installer_lifecycle_check.py",
    ),
    # ── the open surfaces read on a keyless install, each observed 200
    ("curl localhost:7000/agentfacts.json", "keyless-install drive"),
    ("curl localhost:7000/.well-known/conformance.json", "keyless-install drive"),
    ("curl localhost:7000/.well-known/agent.json", "keyless-install drive"),
    ("curl localhost:7000/api/skills", "keyless-install drive"),
    ("curl localhost:7000/api/surfaces/dashboard", "keyless-install drive"),
    # ── the two-agent demo: the script asserts its own five outcomes and runs
    #    as the two_agent_demo CI job on every change to what it executes
    (
        "bash scripts/demo_two_agents.sh",
        "two-agent demo drives; the two_agent_demo CI job",
    ),
)

_FENCE = re.compile(r"^```(\w*)[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _command_lines(page: str) -> list[tuple[int, str]]:
    text = (REPO / page).read_text(encoding="utf-8")
    found: list[tuple[int, str]] = []
    for block in _FENCE.finditer(text):
        if block.group(1) != "bash":
            continue
        start_line = text.count("\n", 0, block.start(2)) + 1
        for offset, raw in enumerate(block.group(2).splitlines()):
            line = raw.split("#", 1)[0].strip()
            if line.startswith(("$ ", "> ")):
                line = line[2:].strip()
            if line:
                found.append((start_line + offset, line))
    return found


def _is_driven(line: str) -> bool:
    for pattern, _drive in DRIVEN:
        if isinstance(pattern, str):
            if line == pattern:
                return True
        elif pattern.fullmatch(line):
            return True
    return False


def test_every_command_on_the_release_pages_was_driven() -> None:
    undriven: list[str] = []
    for page in PAGES:
        for line_no, line in _command_lines(page):
            if not _is_driven(line):
                undriven.append(f"{page}:{line_no}: {line}")
    assert not undriven, (
        "command(s) on a release page that no drive ran — add the drive to DRIVEN "
        "or take the command off the page:\n  " + "\n  ".join(undriven)
    )


def test_the_pages_still_carry_commands() -> None:
    """The check above passes vacuously over a page with no bash blocks; the
    pages are meant to carry the three paths, so their absence is a failure."""
    for page in PAGES:
        assert _command_lines(page), f"{page} carries no bash command block"


def test_every_driven_entry_names_its_drive() -> None:
    for pattern, drive in DRIVEN:
        assert drive.strip(), f"DRIVEN entry {pattern!r} names no drive"
