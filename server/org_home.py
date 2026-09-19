"""Resolve the org's on-disk data dir, migrating legacy ``.nanda/`` → ``.org/``.

The server keeps its operator-visible state (org-config.json, the signed
conformance badge, the issuer-log, the Ed25519 keypair file) under a dotdir in
the server home / container volume. That dir is renamed ``.nanda`` → ``.org`` for
org-readiness, NON-BREAKING: on first use we migrate an existing ``.nanda/`` into
``.org/`` (read-old-migrate, mirroring the ORG_HOME env back-compat in that change).

Server-only. The AGENT's ``~/.nanda/`` is a convention SHARED with the sibling
member-SDK and is intentionally left untouched (see that change).
"""

from __future__ import annotations

import shutil
from pathlib import Path

LEGACY_DIRNAME = ".nanda"
ORG_DIRNAME = ".org"


def resolve_org_dir(base: Path) -> Path:
    """Return ``base/.org``, migrating ``base/.nanda`` into it on first use.

    - Legacy present, new absent → copy the whole legacy dir into ``.org`` (so
      org-config.json / conformance.json / issuer-log / keypair all carry over).
      Non-destructive: the legacy dir is left in place as a backup.
    - Both present → ``.org`` wins (already migrated); legacy is ignored.
    - Neither → a fresh empty ``.org`` is created.
    """
    new = base / ORG_DIRNAME
    old = base / LEGACY_DIRNAME
    if not new.exists() and old.exists():
        try:
            shutil.copytree(old, new)
        except Exception as e:  # noqa: BLE001 — migration is best-effort; never crash boot
            print(f"[org_home] .nanda→.org migration failed ({e!r}); continuing with {new}")
    new.mkdir(parents=True, exist_ok=True)
    return new
