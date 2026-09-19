"""Chapter admin management — system-level operator interface.

Distinct from chapter_role (member-level admin). This module handles
*operator* concerns: the human or service that deploys, configures, and
maintains a chapter doesn't necessarily have a member identity inside
the chapter. They need a stable system-level credential (the admin
token) and a small set of endpoints that don't require knowing the
member-auth scheme.

The admin token is:

  * 32 bytes of secrets-grade randomness, rendered as 64 hex characters.
  * Generated on first org startup if absent.
  * Stored at ``<org_home>/.org-admin-token`` (mode 0600) and optionally also in
    ``.env`` if one exists in the org dir. (The legacy ``.chapter-admin-token`` /
    ``CHAPTER_*`` names are still read for back-compat — see that change.)
  * Read from ``ORG_ADMIN_TOKEN`` env var if set (env wins over file).
  * Printed exactly ONCE to stdout at first generation, then never
    surfaced again. Operators must capture it on first run.

Security model:

  * The token grants full admin authority on a single chapter. It is
    NOT a member identity — admin-token-authenticated requests cannot
    sign as a chapter member or take member-level actions like
    submitting an intent or RSVPing to a call.
  * HTTPS-only in production. The chapter does NOT downgrade-warn — the
    operator is responsible for terminating TLS in front (Railway,
    Vercel, Caddy, nginx, etc.).
  * Constant-time compare on every check to avoid timing oracle.
  * Rotation: ``setup_admin --rotate`` writes a new token and
    invalidates the old one immediately. Old admin sessions in any
    browser/CLI must re-paste the new token.

Future (not in v1):

  * Multi-admin tokens with per-token scopes
  * OAuth/SSO bridging for enterprise deployments (Q1-2027 backlog
    per docs/technical/ENTERPRISE.md)
  * Token rotation via the admin endpoint itself (today: CLI only)
"""

from __future__ import annotations

import os
import secrets
from hmac import compare_digest
from pathlib import Path

# Resolved at import time but mutable through init() — same pattern as
# other server modules. The token lives in process memory; admin
# endpoints reach for it through verify_admin_token().
_admin_token: str = ""
_token_file: Path | None = None
_was_generated_this_startup: bool = False


def _token_dir() -> Path:
    """The directory the admin token lives in. Per-org-home so a multi-org host
    (one process per org on the same machine) doesn't collide. ORG_HOME is the
    canonical env; CHAPTER_HOME is read for back-compat with pre-rename
    deployments."""
    home = os.environ.get("ORG_HOME", "").strip() or os.environ.get("CHAPTER_HOME", "").strip()
    return Path(home) if home else Path(__file__).resolve().parent


def _resolve_token_file() -> Path:
    """Canonical admin-token path: ``<org_home>/.org-admin-token`` (mode 0600)."""
    return _token_dir() / ".org-admin-token"


def _legacy_token_file() -> Path:
    """Pre-rename path (``.chapter-admin-token``) — read for back-compat with
    deployments provisioned before the operator-facing org rename."""
    return _token_dir() / ".chapter-admin-token"


def generate_token() -> str:
    """Return a 64-hex-character token sourced from secrets.token_hex(32).

    Constant-time-comparable. Hex chosen over base64 so the token is
    safe to copy/paste into env vars, URLs, query strings, JSON, and
    shell scripts without escaping."""
    return secrets.token_hex(32)


def _write_token_file(path: Path, token: str) -> None:
    """Write the token to ``path`` with permissive-rejecting umask.

    Mode 0600. Parent dir is created if missing. If the write fails
    (permission denied on a read-only filesystem, etc.), we surface a
    clear error rather than silently continuing — an admin token only
    in memory is a footgun (lost on restart, no recovery path)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Open with O_CREAT | O_WRONLY | O_TRUNC, mode 0600
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)


def _load_token_from_file(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="ascii").strip()
    except Exception:
        return ""


def init(*, force_regenerate: bool = False) -> tuple[str, bool]:
    """Resolve the admin token at chapter startup.

    Resolution order:
      1. ``ORG_ADMIN_TOKEN`` env var (env wins; legacy ``CHAPTER_ADMIN_TOKEN`` also read).
      2. The on-disk token file at ``<org_home>/.org-admin-token`` (legacy
         ``.chapter-admin-token`` read as a fallback).
      3. Generate a fresh token, write to disk, return for printing.

    Returns ``(token, was_freshly_generated)``. The caller is responsible
    for printing the token EXACTLY ONCE when ``was_freshly_generated``
    is True. Never log the token at any other time.

    ``force_regenerate=True`` rotates: ignores the existing env/file
    token, generates a new one, writes to disk. Old token becomes
    invalid immediately.
    """
    global _admin_token, _token_file, _was_generated_this_startup
    _token_file = _resolve_token_file()

    if force_regenerate:
        token = generate_token()
        _write_token_file(_token_file, token)
        _admin_token = token
        _was_generated_this_startup = True
        return token, True

    # ORG_ADMIN_TOKEN is canonical; CHAPTER_ADMIN_TOKEN is read for back-compat.
    env_token = os.environ.get("ORG_ADMIN_TOKEN", "").strip() or os.environ.get("CHAPTER_ADMIN_TOKEN", "").strip()
    if env_token:
        _admin_token = env_token
        _was_generated_this_startup = False
        return env_token, False

    # Prefer the canonical .org-admin-token; fall back to the legacy
    # .chapter-admin-token so a pre-rename deployment keeps working.
    file_token = _load_token_from_file(_token_file) or _load_token_from_file(_legacy_token_file())
    if file_token:
        _admin_token = file_token
        _was_generated_this_startup = False
        return file_token, False

    # Nothing on env or disk — generate one and write it.
    token = generate_token()
    _write_token_file(_token_file, token)
    _admin_token = token
    _was_generated_this_startup = True
    return token, True


def verify_admin_token(provided: str) -> bool:
    """Constant-time compare. Empty token never verifies even if both
    sides are empty — refuse to authenticate against an unset admin
    credential (prevents misconfiguration from silently opening the
    admin surface).

    Encodes both sides to bytes for compare_digest because the str-vs-str
    path raises TypeError on non-ASCII input; we want garbage input to
    return False, not crash the request pipeline.
    """
    if not provided or not _admin_token:
        return False
    try:
        return compare_digest(provided.encode("utf-8"), _admin_token.encode("utf-8"))
    except Exception:  # noqa: BLE001 — auth check MUST never raise
        return False


def is_initialized() -> bool:
    return bool(_admin_token)


def token_file_path() -> Path | None:
    """For diagnostic / setup-wizard use only. NEVER return the token
    contents through this surface; only the path."""
    return _token_file


def format_startup_message(token: str, *, public_url: str = "") -> str:
    """Build the one-time printable banner shown when the admin token
    is freshly generated. Designed to be copy-pasteable from a terminal
    or a Railway/Render log viewer.

    Caller MUST only invoke this when init() returned ``was_freshly_generated=True``;
    otherwise the token would leak into log streams on every restart."""
    base = public_url.rstrip("/") if public_url else "http://localhost:<PORT>"
    return (
        "\n"
        "═══════════════════════════════════════════════════════════════\n"
        "  ORG ADMIN TOKEN — STORE THIS NOW. IT WILL NOT BE SHOWN AGAIN.\n"
        "═══════════════════════════════════════════════════════════════\n"
        f"  Token:    {token}\n"
        f"  Saved to: {token_file_path()}\n"
        "\n"
        "  Use it as the X-Admin-Token header on any /admin/* endpoint:\n"
        f"    curl -H 'X-Admin-Token: {token}' {base}/admin/status\n"
        "\n"
        f"  Open the admin UI at {base}/admin/ and paste this token.\n"
        "═══════════════════════════════════════════════════════════════\n"
    )


__all__ = [
    "init",
    "verify_admin_token",
    "generate_token",
    "is_initialized",
    "token_file_path",
    "format_startup_message",
]
