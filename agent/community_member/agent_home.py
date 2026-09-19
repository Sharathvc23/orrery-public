"""Resolve the agent's ``.nanda/`` data dir, carrying over a legacy ``~/.nanda/``.

The agent keeps part of its operator-visible state (the signed conformance
badge, the A2A task log, the settings cache) under a ``.nanda`` dir. That name
is a convention shared with the sibling member-SDK and is kept; what changes
here is where the dir is rooted.

``conformance_badge.badge_path`` already rooted it under the configured home
"so multiple agents (and tests) don't collide". The task log and the settings
cache did not, and used the literal ``~/.nanda`` — so setting
``COMMUNITY_MEMBER_HOME`` moved most of an agent's state but left those two in
the invoking user's home, shared by every agent on the machine.

Migration is copy-and-keep, mirroring ``server/org_home.py``: the legacy file
stays where it is as a backup, and the new location wins once it exists.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

NANDA_DIRNAME = ".nanda"


def base_dir() -> Path:
    """The agent home: ``COMMUNITY_MEMBER_HOME`` if set, else the default.

    Read on every call rather than bound at import, so a process that sets the
    variable late (a test, a wizard, an embedding host) is not left reading a
    directory chosen before it got the chance.
    """
    home = os.environ.get("COMMUNITY_MEMBER_HOME", "").strip()
    return Path(home).expanduser() if home else Path.home() / ".community-member"


def nanda_dir() -> Path:
    """``<agent home>/.nanda``. Not created here; callers create on write."""
    return base_dir() / NANDA_DIRNAME


def resolve(filename: str) -> Path:
    """Return ``<agent home>/.nanda/<filename>``, carrying over the legacy copy.

    - Legacy ``~/.nanda/<filename>`` present, new absent → copy it across, so an
      existing task log or settings cache is not silently orphaned. The legacy
      file is left in place as a backup.
    - Both present → the new one wins; the legacy is ignored.
    - Neither → the new path is returned and the caller creates it.

    Never raises: a migration that cannot be completed leaves the agent running
    against the new location rather than failing to start.
    """
    new = nanda_dir() / filename
    legacy = Path.home() / NANDA_DIRNAME / filename
    if new.exists() or not legacy.exists() or legacy.resolve() == new.resolve():
        return new
    try:
        new.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, new)
        print(f"[agent_home] carried {legacy} over to {new}; the original is left as a backup")
    except Exception as e:  # noqa: BLE001 — migration is best-effort; never break startup
        print(f"[agent_home] could not carry {legacy} over to {new} ({e!r}); continuing with {new}")
    return new
