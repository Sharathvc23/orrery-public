"""
Agent settings store — jsonb bag for every configurable knob.

Stores LLM provider, voice preferences, channel configs, trust policy
overrides, etc. A dedicated `agent_settings` row per agent_id with a
single `settings` jsonb column.

Secrets (API keys, OAuth tokens) do NOT live here — they stay in
`agent_private_memory`. This table is readable by the chapter agent;
private memory is owner-only.

Public API
----------
get_settings(agent_id)               — full dict (merged with defaults)
get_setting(agent_id, key, default)  — single key
update_settings(agent_id, patch)     — merge patch into settings
reset_settings(agent_id)             — wipe to defaults
mark_onboarding_complete(agent_id)   — sets onboarding_completed_at timestamp

Settings schema
---------------
The settings jsonb bag supports these top-level keys (all optional):

    llm.provider           str        "anthropic" | "openai" | "xai" | "groq" | "ollama_local"
    llm.model              str        provider-specific model id
    voice.*                            ROADMAP — configures voice for when the
                                       desktop audio runtime ships; no STT/TTS
                                       audio runs today (see voice.py).
    voice.stt_provider     str        "whisper_local" | "openai" | null
    voice.tts_provider     str        "piper_local" | "elevenlabs" | "openai" | null
    voice.voice_id         str        provider-specific
    voice.wake_word        bool       default false
    voice.always_on        bool       default false
    channels.slack         dict       {enabled, workspace_id, ...}
    channels.email         dict       {enabled, imap_host, ...}
    trust.cooldown_hours   int        override chapter default
    trust.confidence_floor real       override chapter default
    privacy.telemetry      bool       opt-in (default false)

New keys land here without schema changes — the UI (build_settings_surface)
introspects defaults + known keys and renders a Form per section.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# ── Config + DI ───────────────────────────────────────────

_pg_request: Callable | None = None
_pg_write: Callable | None = None

#: Fallback shown only when ``llm_config`` cannot be imported. NOT the answer to
#: "what does this chapter run" — see :func:`resolved_llm`. Kept as a literal so
#: the settings module stays importable on its own.
_LLM_UNRESOLVED: dict[str, Any] = {"provider": "unknown", "model": "unknown"}

# Sensible defaults. Merged under the agent's stored settings on read.
DEFAULTS: dict[str, Any] = {
    # ⚠️ PLACEHOLDER, NOT A DEFAULT. The real value comes from resolved_llm() via
    # effective_defaults(). This entry exists so the section's KEYS are still
    # discoverable by VALID_TOP_LEVEL_KEYS and by the form introspection.
    #
    # It used to be a literal {"provider": "anthropic", "model": "claude-opus-4-7"}
    # while llm_config resolved claude-sonnet-4-6 — a ~2.5x output-price
    # misstatement on the one surface an operator uses to reason about cost. A
    # second literal would have been the same bug with a fresher string, so the
    # value is now READ FROM THE THING THAT EXECUTES rather than restated here.
    "llm": dict(_LLM_UNRESOLVED),
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


def resolved_llm() -> dict[str, str]:
    """The provider and model this chapter will ACTUALLY execute with.

    Read off ``llm_config``'s module constants — the same ones ``build_client()``
    uses — so the displayed pair cannot drift from the executed one. They are
    resolved once at that module's import, which is exactly right here: a value
    re-resolved from the current environment could disagree with the client the
    process already built.

    Imported lazily and defensively: ``llm_config`` resolves the environment and
    prints at import, and this module must stay importable without that.
    """
    try:
        import llm_config
    except Exception:  # noqa: BLE001 — an unreadable resolution is "unknown", never a guess
        return dict(_LLM_UNRESOLVED)
    return {
        "provider": getattr(llm_config, "PROVIDER", "") or _LLM_UNRESOLVED["provider"],
        "model": getattr(llm_config, "DEFAULT_MODEL", "") or _LLM_UNRESOLVED["model"],
    }


def effective_defaults() -> dict[str, Any]:
    """:data:`DEFAULTS` with the ``llm`` section resolved from what executes.

    A function rather than a constant because the answer is an observation of
    another module, not a policy of this one.
    """
    return {**DEFAULTS, "llm": resolved_llm()}


def _with_resolved_llm(effective: dict[str, Any]) -> dict[str, Any]:
    """Force the ``llm`` section to what the runtime actually executes.

    ⚠️ THE ONE SECTION A STORED VALUE MAY NOT OVERRIDE, and the reason is the
    defect this closes. Onboarding writes the operator's chosen provider into
    stored settings; nothing on the executing path reads it. Letting it win the
    merge meant the surface an operator uses to reason about cost reported their
    CHOICE as though it were in effect, while the runtime ran something else —
    the same misstatement as the hardcoded model default, arriving by a
    different route and surviving the fix for that one.

    Every other section is a preference and still merges normally. ``llm`` is
    not a preference here; it is an observation, and an observation a caller can
    overwrite is not one. The stored choice is still stored, and is still
    readable by whatever eventually consumes it — it just cannot claim to be
    what is running.
    """
    return {**effective, "llm": resolved_llm()}

# Known top-level keys — anything else is rejected by update_settings.
# Prevents hostile payloads from dumping arbitrary nested structures.
VALID_TOP_LEVEL_KEYS = frozenset(DEFAULTS.keys())


class SettingsWriteFailed(RuntimeError):
    """A settings write a caller asked to be strict about was refused."""


def init(pg_request_fn: Callable, execute_strict_fn: Callable | None = None) -> None:
    """``execute_strict_fn`` is used only by callers that pass ``strict=True``.

    Deliberately per-call rather than a module-wide flip. This module is a
    singleton shared with the settings routes and the voice config, where a
    swallowed write is a preference that did not stick — annoying, recoverable,
    and visible the next time the page is opened. Onboarding is the one caller
    where the human types the value once and is told it is saved, so it is the
    one caller that asks for strict. Making it global would change five other
    surfaces to fix one.
    """
    global _pg_request, _pg_write
    _pg_request = pg_request_fn
    _pg_write = execute_strict_fn


async def _write(method: str, table: str, params: dict | None = None, body: Any = None, *, strict: bool) -> Any:
    """One write, best-effort or strict depending on what the caller asked for."""
    if not strict:
        return await _pg_request(method, table, params=params, body=body)  # type: ignore[misc]
    writer = _pg_write or _pg_request
    result = await writer(method, table, params=params, body=body)  # type: ignore[misc]
    if result is None:
        raise SettingsWriteFailed(f"{method} {table}: the database refused the write")
    return result


# ── Merge helpers ────────────────────────────────────────


def _deep_merge(base: dict, patch: dict) -> dict:
    """Recursive dict merge — patch wins on leaf keys."""
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _validate_patch(patch: dict) -> tuple[bool, str]:
    """Reject unknown top-level keys + oversize payloads."""
    if not isinstance(patch, dict):
        return False, "patch must be a dict"
    import json as _json

    if len(_json.dumps(patch).encode("utf-8")) > MAX_SETTINGS_BYTES:
        return False, f"patch too large (max {MAX_SETTINGS_BYTES} bytes)"
    for k in patch:
        if k not in VALID_TOP_LEVEL_KEYS:
            return False, f"unknown top-level key {k!r} — allowed: {sorted(VALID_TOP_LEVEL_KEYS)}"
    return True, "ok"


# ── Core ops ─────────────────────────────────────────────


async def get_settings(agent_id: str) -> dict:
    """Return the effective settings dict (defaults ⊕ stored patch)."""
    if _pg_request is None:
        raise RuntimeError("settings not initialized — call init() first")

    rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "settings,onboarding_completed_at", "limit": "1"},
    )
    stored = (rows[0].get("settings") if rows else {}) or {}
    return _with_resolved_llm(_deep_merge(effective_defaults(), stored))


async def get_setting(agent_id: str, dotted_key: str, default: Any = None) -> Any:
    """Fetch a single setting by dotted path, e.g. 'llm.provider'."""
    settings = await get_settings(agent_id)
    cur: Any = settings
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


async def update_settings(agent_id: str, patch: dict, *, strict: bool = False) -> dict:
    """Merge `patch` into the agent's stored settings. Returns new effective settings.

    Raises ValueError on invalid input. With ``strict=True``, also raises
    ``SettingsWriteFailed`` when the store refuses the write — the return value
    is computed from the in-memory merge and NOT read back, so without this a
    caller has no way to tell a stored patch from a dropped one.
    """
    if _pg_request is None:
        raise RuntimeError("settings not initialized")

    ok, reason = _validate_patch(patch)
    if not ok:
        raise ValueError(f"patch rejected: {reason}")

    # Load current, merge, upsert.
    rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "settings", "limit": "1"},
    )
    current = (rows[0].get("settings") if rows else {}) or {}
    new_stored = _deep_merge(current, patch)

    if rows:
        await _write(
            "PATCH",
            "agent_settings",
            params={"agent_id": f"eq.{agent_id}"},
            body={"settings": new_stored},
            strict=strict,
        )
    else:
        await _write(
            "POST",
            "agent_settings",
            body={"agent_id": agent_id, "settings": new_stored},
            strict=strict,
        )
    return _with_resolved_llm(_deep_merge(effective_defaults(), new_stored))


async def reset_settings(agent_id: str) -> dict:
    """Wipe stored settings → agent reverts to defaults."""
    if _pg_request is None:
        raise RuntimeError("settings not initialized")

    rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "settings", "limit": "1"},
    )
    if rows:
        await _pg_request(
            "PATCH",
            "agent_settings",
            params={"agent_id": f"eq.{agent_id}"},
            body={"settings": {}},
        )
    return effective_defaults()


async def mark_onboarding_complete(agent_id: str, *, strict: bool = False) -> None:
    """Flip the completion timestamp — idempotent.

    ``strict=True`` for the same reason as ``update_settings``: onboarding
    reports ``completed`` off arithmetic, not off this write landing.
    """
    if _pg_request is None:
        raise RuntimeError("settings not initialized")

    from datetime import UTC, datetime

    ts = datetime.now(UTC).isoformat()
    rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "agent_id", "limit": "1"},
    )
    if rows:
        await _write(
            "PATCH",
            "agent_settings",
            params={"agent_id": f"eq.{agent_id}"},
            body={"onboarding_completed_at": ts},
            strict=strict,
        )
    else:
        await _write(
            "POST",
            "agent_settings",
            body={"agent_id": agent_id, "settings": {}, "onboarding_completed_at": ts},
            strict=strict,
        )


async def is_onboarding_complete(agent_id: str) -> bool:
    if _pg_request is None:
        raise RuntimeError("settings not initialized")
    rows = await _pg_request(
        "GET",
        "agent_settings",
        params={"agent_id": f"eq.{agent_id}", "select": "onboarding_completed_at", "limit": "1"},
    )
    return bool(rows and rows[0].get("onboarding_completed_at"))
