"""
Settings sync — keep the member-agent's local settings cache and the
chapter's `agent_settings` jsonb bag in lockstep.

On agent startup we pull settings from the chapter, merge over our
local cache, and write back anything the local user changed while
the agent was offline. On every mutation (via the `update_settings`
agent tool or direct CLI), we push through to the chapter and update
the local cache atomically.

Conflict rule: **last-write-wins by server-side updated_at**. If the
chapter has a newer row than our cache, chapter values beat local.
If our cache has unpushed local edits newer than the chapter, we push
them first (pull-then-push sequence).

Local cache lives at <agent home>/.nanda/settings.json (mode 0600), where the
agent home is COMMUNITY_MEMBER_HOME when set, else ~/.community-member. A
cache left at the legacy ~/.nanda/settings.json is carried over on first use
and kept in place as a backup. Never contains
secrets — secrets live in the owner-only encrypted keystore. This file
is a plain-text cache of the public settings bag.

Public API
----------
pull_from_chapter(agent_id, client)           — fetch + merge + persist
push_to_chapter(agent_id, patch, client)      — validate + push + update cache
read_local() / write_local(settings)          — cache I/O
sync_on_startup(agent_id, client)             — idempotent full sync
effective_settings(agent_id, client)          — merged read helper

Validation
----------
KNOWN_TOP_LEVEL_KEYS mirrors chapter-side settings.py exactly so bad
patches fail client-side before the round-trip.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Override, not a location — see ``task_store.TASK_STORE_PATH``.
SETTINGS_CACHE: Path | None = None

# Mirrors the org server runtime settings.py DEFAULTS exactly.
# If the server adds a top-level key, we update this set in lockstep.
KNOWN_TOP_LEVEL_KEYS = frozenset({"llm", "voice", "channels", "trust", "privacy"})

# Defaults applied when nothing is cached and the server hasn't been reached.
# Structurally identical to the server's defaults.
DEFAULTS: dict[str, Any] = {
    "llm": {"provider": "anthropic", "model": "claude-opus-4-7"},
    "voice": {
        "stt_provider": None,
        "tts_provider": None,
        "wake_word": False,
        "always_on": False,
    },
    "channels": {"slack": {"enabled": False}, "email": {"enabled": False}},
    "trust": {},
    "privacy": {"telemetry": False},
}

MAX_SETTINGS_BYTES = 64 * 1024


# ── Pure helpers ─────────────────────────────────────────


def _deep_merge(base: dict, patch: dict) -> dict:
    """Recursive dict merge — patch wins on leaf keys."""
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def validate_patch(patch: dict) -> tuple[bool, str]:
    """Reject unknown top-level keys + oversize payloads.

    Identical contract to chapter-side settings.py — catches bad input
    before the round-trip so the LLM gets an immediate error.
    """
    if not isinstance(patch, dict):
        return False, "patch must be a dict"
    if len(json.dumps(patch).encode("utf-8")) > MAX_SETTINGS_BYTES:
        return False, f"patch too large (max {MAX_SETTINGS_BYTES} bytes)"
    for k in patch:
        if k not in KNOWN_TOP_LEVEL_KEYS:
            return False, f"unknown top-level key {k!r} — allowed: {sorted(KNOWN_TOP_LEVEL_KEYS)}"
    return True, "ok"


# ── Local cache I/O ──────────────────────────────────────


def _cache_path() -> Path:
    """``<agent home>/.nanda/settings.json``, carrying over a legacy copy.

    Indirected so tests can monkeypatch SETTINGS_CACHE to pin a temp file.
    """
    if SETTINGS_CACHE is not None:
        return SETTINGS_CACHE
    from community_member import agent_home

    return agent_home.resolve("settings.json")


def read_local() -> dict:
    """Return the cache dict (empty if missing / corrupt). Never raises."""
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
        # Anything malformed — corrupt file, binary garbage from another
        # process, partial write from a crash — we lose the cache, not
        # the agent. The next pull_from_chapter repopulates it.
        return {}


def write_local(settings: dict) -> None:
    """Persist the cache with mode 0600. Adds a `_cached_at` timestamp so
    the caller can break ties against chapter-side `updated_at`."""
    path = _cache_path()
    path.parent.mkdir(exist_ok=True, parents=True, mode=0o700)
    payload = {**settings, "_cached_at": datetime.now(UTC).isoformat()}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def _strip_meta(settings: dict) -> dict:
    """Remove our local metadata before sending to the chapter."""
    return {k: v for k, v in settings.items() if not k.startswith("_")}


# ── Remote sync ──────────────────────────────────────────


def pull_from_chapter(agent_id: str, client) -> dict:
    """Fetch the chapter's view of our settings, merge over defaults, cache locally.

    `client` must have `get_settings(agent_id)` returning
    `{"agent_id": ..., "settings": {...}}`.

    Returns the merged (effective) settings dict. On chapter error, falls
    back to whatever's in the local cache (so an offline agent still works).
    """
    try:
        response = client.get_settings(agent_id)
    except Exception as exc:
        _log.warning("chapter unreachable on settings pull, using local cache: %s", exc)
        cached = read_local()
        if cached:
            return _deep_merge(DEFAULTS, _strip_meta(cached))
        return dict(DEFAULTS)

    remote = (response or {}).get("settings") or {}
    merged = _deep_merge(DEFAULTS, remote)
    write_local(remote)
    return merged


def push_to_chapter(agent_id: str, patch: dict, client) -> dict:
    """Validate `patch`, send it to the chapter, update the local cache.

    On network failure, the patch is **enqueued in the offline outbox** +
    applied to the local cache, and the function returns an optimistic
    merged view (local state + patch). The patch replays to the chapter
    on next reconnect via outbox.drain().

    Raises ValueError on invalid input only — never on network failure.
    """
    from . import outbox

    ok, reason = validate_patch(patch)
    if not ok:
        raise ValueError(f"patch rejected: {reason}")

    try:
        response = client.update_settings(agent_id, patch)
        if response is None:
            raise RuntimeError("client returned None")
        merged = (response or {}).get("settings") or {}
        # Also update the local cache with the server's post-patch view
        # (server is source of truth on the wire; local is a cache).
        write_local(_strip_meta(merged))
        return merged
    except Exception:
        # Offline path: enqueue for replay + optimistic local apply.
        # We don't log the error here; the caller sees it via pending_count.
        outbox.enqueue(agent_id, patch)
        local = read_local()
        optimistic = _deep_merge(local, patch)
        write_local(optimistic)
        return {**optimistic, "_queued": True}


def drain_outbox(agent_id: str, client) -> dict:
    """On reconnect, replay any queued settings changes to the chapter.

    Returns the outbox drain stats dict.
    """
    import asyncio

    from . import outbox

    try:
        return asyncio.run(outbox.drain(agent_id, client))
    except RuntimeError:
        # Already in an event loop (e.g. called from async context) —
        # caller should await outbox.drain directly instead
        raise


def sync_on_startup(agent_id: str, client) -> dict:
    """Idempotent full sync for agent startup.

    Sequence:
      1. Read local cache (may be stale if chapter was updated via a client)
      2. Pull from chapter (overwrites cache with server's view)
      3. Return the effective merged settings

    Safe to call repeatedly. No local state is lost because the local
    cache only reflects what the chapter told us — local-only edits go
    through push_to_chapter first.
    """
    return pull_from_chapter(agent_id, client)


def effective_settings(agent_id: str, client) -> dict:
    """Shortcut: the settings the agent SHOULD act on right now.

    Tries a fresh pull; falls back to cache; falls back to defaults.
    Always returns a dict — never raises.
    """
    try:
        return pull_from_chapter(agent_id, client)
    except Exception as exc:
        _log.warning("effective_settings fell back to defaults: %s", exc)
        return dict(DEFAULTS)
