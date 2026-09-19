"""
Voice configuration — provider catalogs + validation.

ROADMAP: no speech-to-text / text-to-speech audio runtime ships today on
either side. Audio I/O (microphones, speakers, real-time streams) is planned
to run in the member-agent desktop app (community-member). This chapter-side
module only defines the provider catalog, validates config, and hands the
A2UI surface builder the options list — so a member can pre-configure voice
for when the runtime lands. Setting a provider does NOT capture or synthesize
audio yet.

Secrets (API keys for ElevenLabs / OpenAI TTS / etc.) live in
agent_private_memory, never in agent_settings.

Public API
----------
stt_providers()                   — list of available speech-to-text providers
tts_providers()                   — list of available text-to-speech providers
voice_options_for(tts_provider)   — voice ids for a given TTS provider
validate_config(patch)            — (ok, reason) for a voice settings patch
"""

from __future__ import annotations

from typing import Any

# ─── Provider catalogs ───────────────────────────────────────

# Each entry: id, label, requires_api_key, local, notes
STT_PROVIDERS: list[dict[str, Any]] = [
    {
        "id": "disabled",
        "label": "Disabled",
        "requires_api_key": False,
        "local": True,
        "notes": "No speech-to-text. Keyboard + text only.",
    },
    {
        "id": "whisper_local",
        "label": "Whisper (local)",
        "requires_api_key": False,
        "local": True,
        "notes": "Runs on your device via whisper.cpp / MLX. Privacy-preserving. "
        "Needs ~500 MB model download on first use.",
    },
    {
        "id": "openai",
        "label": "OpenAI Whisper API",
        "requires_api_key": True,
        "local": False,
        "notes": "Cloud API. Faster than local on low-end hardware but sends your audio to OpenAI.",
    },
]

TTS_PROVIDERS: list[dict[str, Any]] = [
    {
        "id": "disabled",
        "label": "Disabled",
        "requires_api_key": False,
        "local": True,
        "notes": "Text replies only.",
    },
    {
        "id": "piper_local",
        "label": "Piper (local)",
        "requires_api_key": False,
        "local": True,
        "notes": "Runs on your device. Fast. ~50MB per voice model.",
    },
    {
        "id": "elevenlabs",
        "label": "ElevenLabs",
        "requires_api_key": True,
        "local": False,
        "notes": "Best voice quality. Cloud API — your replies are synthesized on their servers.",
    },
    {
        "id": "openai",
        "label": "OpenAI TTS",
        "requires_api_key": True,
        "local": False,
        "notes": "Good quality, integrates with OpenAI billing.",
    },
]

# Voice catalogs per TTS provider. For cloud providers these are a curated
# subset — the full lists are much longer but too noisy for a Select.
VOICES_BY_PROVIDER: dict[str, list[dict[str, str]]] = {
    "piper_local": [
        {"label": "Amy (en-US, female)", "value": "en_US-amy-medium"},
        {"label": "Ryan (en-US, male)", "value": "en_US-ryan-medium"},
        {"label": "Alba (en-GB, female)", "value": "en_GB-alba-medium"},
    ],
    "elevenlabs": [
        {"label": "Rachel", "value": "21m00Tcm4TlvDq8ikWAM"},
        {"label": "Domi", "value": "AZnzlk1XvdvUeBnXmlld"},
        {"label": "Antoni", "value": "ErXwobaYiN019PkySvjV"},
        {"label": "Custom (use voice_id field)", "value": "custom"},
    ],
    "openai": [
        {"label": "Alloy", "value": "alloy"},
        {"label": "Echo", "value": "echo"},
        {"label": "Fable", "value": "fable"},
        {"label": "Onyx", "value": "onyx"},
        {"label": "Nova", "value": "nova"},
        {"label": "Shimmer", "value": "shimmer"},
    ],
}


# ─── Lookups ─────────────────────────────────────────────────


def stt_providers() -> list[dict[str, Any]]:
    return list(STT_PROVIDERS)


def tts_providers() -> list[dict[str, Any]]:
    return list(TTS_PROVIDERS)


def _provider_by_id(catalog: list[dict[str, Any]], pid: str) -> dict[str, Any] | None:
    for p in catalog:
        if p["id"] == pid:
            return p
    return None


def voice_options_for(tts_provider: str) -> list[dict[str, str]]:
    """Voice IDs available for a given TTS provider (empty if unknown / disabled)."""
    return list(VOICES_BY_PROVIDER.get(tts_provider, []))


def provider_requires_key(kind: str, pid: str) -> bool:
    """kind in {stt, tts}. Returns True if the provider needs an API key."""
    catalog = STT_PROVIDERS if kind == "stt" else TTS_PROVIDERS
    p = _provider_by_id(catalog, pid)
    return bool(p and p.get("requires_api_key"))


# ─── Validation ──────────────────────────────────────────────


VALID_STT_IDS = frozenset(p["id"] for p in STT_PROVIDERS)
VALID_TTS_IDS = frozenset(p["id"] for p in TTS_PROVIDERS)


def validate_config(patch: dict) -> tuple[bool, str]:
    """Validate a voice settings patch — shape mirrors settings.DEFAULTS['voice']."""
    if not isinstance(patch, dict):
        return False, "voice config must be a dict"
    stt = patch.get("stt_provider")
    tts = patch.get("tts_provider")
    if stt is not None and stt not in VALID_STT_IDS:
        return False, f"invalid stt_provider {stt!r} — allowed: {sorted(VALID_STT_IDS)}"
    if tts is not None and tts not in VALID_TTS_IDS:
        return False, f"invalid tts_provider {tts!r} — allowed: {sorted(VALID_TTS_IDS)}"
    voice_id = patch.get("voice_id")
    if voice_id is not None:
        if not isinstance(voice_id, str) or len(voice_id) > 128:
            return False, "voice_id must be a string ≤128 chars"
    for flag_key in ("wake_word", "always_on"):
        if flag_key in patch and not isinstance(patch[flag_key], bool):
            return False, f"{flag_key} must be boolean"
    return True, "ok"
