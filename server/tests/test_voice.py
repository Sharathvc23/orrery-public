"""
Prosecution-grade tests for voice.py — provider catalogs + config validation.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import voice

# ═══════════════════════════════════════════════════════════════
# Catalog invariants
# ═══════════════════════════════════════════════════════════════


def test_stt_catalog_has_disabled_entry():
    """HAPPY: users must always be able to opt out of voice entirely."""
    ids = {p["id"] for p in voice.stt_providers()}
    assert "disabled" in ids


def test_tts_catalog_has_disabled_entry():
    ids = {p["id"] for p in voice.tts_providers()}
    assert "disabled" in ids


def test_every_provider_has_required_fields():
    for p in voice.stt_providers() + voice.tts_providers():
        for field in ("id", "label", "requires_api_key", "local", "notes"):
            assert field in p, f"{p} missing {field}"


def test_provider_ids_are_unique():
    for catalog in (voice.stt_providers(), voice.tts_providers()):
        ids = [p["id"] for p in catalog]
        assert len(ids) == len(set(ids)), f"duplicate provider id in {ids}"


# ═══════════════════════════════════════════════════════════════
# voice_options_for
# ═══════════════════════════════════════════════════════════════


def test_voice_options_for_piper_returns_local_voices():
    opts = voice.voice_options_for("piper_local")
    assert len(opts) > 0
    assert all("label" in o and "value" in o for o in opts)


def test_voice_options_for_disabled_returns_empty():
    """EDGE: disabled TTS → no voices."""
    assert voice.voice_options_for("disabled") == []


def test_voice_options_for_unknown_returns_empty():
    """ADVERSARIAL: made-up provider id → empty, not crash."""
    assert voice.voice_options_for("some-bogus-provider") == []


# ═══════════════════════════════════════════════════════════════
# provider_requires_key
# ═══════════════════════════════════════════════════════════════


def test_requires_key_local_providers_false():
    assert voice.provider_requires_key("stt", "whisper_local") is False
    assert voice.provider_requires_key("tts", "piper_local") is False


def test_requires_key_cloud_providers_true():
    assert voice.provider_requires_key("stt", "openai") is True
    assert voice.provider_requires_key("tts", "elevenlabs") is True
    assert voice.provider_requires_key("tts", "openai") is True


def test_requires_key_unknown_returns_false():
    assert voice.provider_requires_key("stt", "ghost") is False
    assert voice.provider_requires_key("tts", "ghost") is False


# ═══════════════════════════════════════════════════════════════
# validate_config
# ═══════════════════════════════════════════════════════════════


def test_validate_empty_patch_ok():
    ok, _ = voice.validate_config({})
    assert ok is True


def test_validate_all_valid_fields():
    ok, _ = voice.validate_config(
        {
            "stt_provider": "whisper_local",
            "tts_provider": "piper_local",
            "voice_id": "en_US-amy-medium",
            "wake_word": True,
            "always_on": False,
        }
    )
    assert ok is True


def test_validate_rejects_unknown_stt_provider():
    ok, reason = voice.validate_config({"stt_provider": "hal9000"})
    assert ok is False
    assert "stt_provider" in reason


def test_validate_rejects_unknown_tts_provider():
    ok, reason = voice.validate_config({"tts_provider": "speechify-pro"})
    assert ok is False
    assert "tts_provider" in reason


def test_validate_rejects_non_bool_wake_word():
    """ADVERSARIAL: client passes 'true' string; must reject — we don't silently coerce."""
    ok, reason = voice.validate_config({"wake_word": "true"})
    assert ok is False
    assert "wake_word" in reason


def test_validate_rejects_non_bool_always_on():
    ok, reason = voice.validate_config({"always_on": 1})
    assert ok is False
    assert "always_on" in reason


def test_validate_rejects_oversized_voice_id():
    """ADVERSARIAL: 200-char voice_id rejected."""
    ok, reason = voice.validate_config({"voice_id": "x" * 200})
    assert ok is False
    assert "voice_id" in reason


def test_validate_rejects_non_string_voice_id():
    ok, reason = voice.validate_config({"voice_id": 12345})  # type: ignore[dict-item]
    assert ok is False


def test_validate_rejects_non_dict_patch():
    ok, reason = voice.validate_config("stt=whisper_local")  # type: ignore[arg-type]
    assert ok is False
    assert "dict" in reason


def test_validate_partial_patch_ok():
    """EDGE: just updating one field is fine."""
    ok, _ = voice.validate_config({"wake_word": True})
    assert ok is True


# ═══════════════════════════════════════════════════════════════
# Scope-down: the settings surface must not imply voice audio is live
# ═══════════════════════════════════════════════════════════════


def test_settings_surface_labels_voice_as_roadmap():
    """No STT/TTS audio runtime ships yet, so the settings surface carries a
    roadmap note + labeled heading — a member never thinks setting a provider
    makes their agent listen or speak."""
    import asyncio

    import settings as settings_mod
    import surfaces

    class _FakePg:
        async def __call__(self, method, table, params=None, body=None):
            return []

    prev = settings_mod._pg_request
    settings_mod.init(_FakePg())
    try:
        out = asyncio.run(surfaces.build_settings_surface("alice"))
    finally:
        settings_mod._pg_request = prev

    by_id = {c.get("id"): c for c in out["updateComponents"]["components"]}
    assert by_id["voice-heading"]["text"] == "Voice (roadmap)"
    assert "Roadmap" in by_id["voice-note"]["text"]
