"""Signed conformance badge for the sovereign agent — via sm-conformance.

The badge is a signed, offline-verifiable envelope proving this runtime passed
the client signing-conformance suite against a pinned vector corpus
(``suite_digest``). It is served at ``GET /.well-known/conformance.json`` and
anyone verifies it against the embedded ``signed_by`` did:key with no service on
the path — the projectnanda conformance surface.

Honesty contract: this module never fabricates results — it only signs the
counts handed to it, and verifies. The signature therefore proves WHO produced
the badge and that it is untampered, NOT that a suite actually ran. The badge is
trustworthy to the extent its counts came from a real run: the generator
(``scripts/gen_conformance_badge.py``) takes them from a pytest ``--junitxml``
report, or from operator-asserted ``--passed/--failed`` (which it warns about
loudly). The signing/encoding/schema are all sm-conformance's (the published
primitive); we never fork them.

The signing vectors + the suite runner live at the repo root
(``conformance/`` + ``vectors/``) and in sm-conformance, not vendored into
the agent package — so, like the org server's badge, the production badge is
generated where the corpus lives and deployed as a file the agent serves.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_RUNTIME = "orrery-agent"


def badge_path() -> Path:
    """Where the agent's signed badge lives. Honors COMMUNITY_MEMBER_HOME so
    multiple agents (and tests) don't collide."""
    home = os.environ.get("COMMUNITY_MEMBER_HOME", "").strip()
    base = Path(home).expanduser() if home else Path.home() / ".community-member"
    return base / ".nanda" / "conformance.json"


def signing_key32(config) -> bytes | None:
    """The agent's 32-byte Ed25519 seed (what ``build_badge`` signs with), or
    None if there's no usable key. ``config.private_key`` is base64(seed)."""
    if not config.private_key:
        return None
    try:
        raw = base64.b64decode(config.private_key)
    except Exception:
        return None
    return raw if len(raw) == 32 else None


def build_self_badge(
    config,
    *,
    suite_digest: str,
    protocol_versions: list[str],
    passed: int,
    failed: int,
    completed_at: str,
    runtime: str = DEFAULT_RUNTIME,
    skipped: int = 0,
    extensions: dict[str, str] | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Build + sign this agent's conformance badge via sm-conformance.

    Raises ValueError if the agent has no usable signing key. Counts are passed
    through verbatim from a real run — this function does not run the suite.
    """
    key = signing_key32(config)
    if key is None:
        raise ValueError("agent has no 32-byte Ed25519 signing key; cannot sign a badge")

    from sm_conformance.badge import build_badge

    return build_badge(
        runtime,
        signing_key32=key,
        suite_digest=suite_digest,
        protocol_versions=protocol_versions,
        completed_at=completed_at,
        passed=passed,
        failed=failed,
        skipped=skipped,
        extensions=extensions,
        signed_at=signed_at,
    )


def verify_badge(badge: dict[str, Any]) -> dict[str, Any]:
    """Verify a badge envelope's signature + schema (sm-conformance).

    Returns the verified payload. Raises on any failure (bad signature,
    tampered payload, schema violation)."""
    from sm_conformance.badge import verify_envelope

    return verify_envelope(badge)


def load_badge(path: Path | None = None) -> dict[str, Any] | None:
    """Load the served badge, or None if absent / unreadable."""
    p = path or badge_path()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_badge(badge: dict[str, Any], path: Path | None = None) -> Path:
    """Persist a signed badge (0700 dir, 0644 file). Returns the path written."""
    p = path or badge_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(badge, indent=2), encoding="utf-8")
    return p


__all__ = [
    "badge_path",
    "build_self_badge",
    "load_badge",
    "signing_key32",
    "verify_badge",
    "write_badge",
]
