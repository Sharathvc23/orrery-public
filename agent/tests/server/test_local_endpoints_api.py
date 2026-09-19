"""HTTP-level coverage for previously-untested /api/local/* endpoints.

These routes back the agent dashboard but had no endpoint tests — only their
underlying modules were covered. This file drives them through a FastAPI
``TestClient`` so request/response contracts (and the regressions they've
already had) are locked in:

  - status / config / capabilities  — read-only shape contracts
  - memory                          — POST→GET→DELETE round trip + bad index
  - settings (GET/PUT)              — provider catalogue + the runtime
                                      provider-switch guard rails
  - profile (GET/PUT)               — round trip, private-field visibility
  - surfaces/compose                — the local-LLM key gate, incl. the PR
                                      regression: local providers must get PAST
                                      the api-key check (ollama needs no key)

The OpenAI client is stubbed (``_FlexClient``) so no network or real key is
needed; it records the connection params so provider-routing can be asserted.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import keystore
from community_member.config import Config
from community_member.consent import ledger
from community_member.server import create_app


@pytest.fixture(autouse=True)
def _reset():
    ledger._reset_for_tests()
    keystore.reset_for_tests()
    yield
    ledger._reset_for_tests()
    keystore.reset_for_tests()


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    from community_member import config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    ledger.init(tmp_path / "consent.db")
    return tmp_path


@pytest.fixture
def cfg(tmp_env) -> Config:
    c = Config()
    c.agent_id = "alice"
    c.name = "Alice"
    c.description = "test agent"
    c.chapter_url = "https://chapter.example"
    c.provider = "xai"
    c.api_key = "sk-secret-value-1234567890"
    c.model = "grok-3-mini"
    c.public_key = "PUBKEYpublickeyPUBKEYpublickey1234567890"
    return c


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg, agent=None))


# ── OpenAI stub (non-streaming create + models.list) ─────────────


class _FlexClient:
    """Stub OpenAI client: records init params, replays a canned non-stream
    completion, and answers models.list() so the settings probe passes."""

    last_init: dict | None = None
    content: str = '{"components": [{"id": "t1", "component": "Text", "text": "hi"}]}'
    models_raises: bool = False

    # **kwargs so the stub accepts what the real client does: build_client
    # now passes max_retries and timeout, and a double that rejects them
    # would fail on arguments the production path depends on.
    def __init__(self, *, api_key=None, base_url=None, **kwargs):
        _FlexClient.last_init = {"api_key": api_key, "base_url": base_url}

    class _Models:
        @staticmethod
        def list():
            if _FlexClient.models_raises:
                raise RuntimeError("bad key")
            return []

    models = _Models()

    class _Chat:
        class _Completions:
            @staticmethod
            def create(**kwargs):
                msg = type("M", (), {"content": _FlexClient.content})()
                choice = type("C", (), {"message": msg})()
                return type("R", (), {"choices": [choice]})()

        completions = _Completions()

    chat = _Chat()


@pytest.fixture
def patch_openai(monkeypatch):
    import openai

    _FlexClient.last_init = None
    _FlexClient.content = '{"components": [{"id": "t1", "component": "Text", "text": "hi"}]}'
    _FlexClient.models_raises = False
    monkeypatch.setattr(openai, "OpenAI", _FlexClient)
    return _FlexClient


# ── status ───────────────────────────────────────────────────────


def test_status_not_started_without_agent(client):
    r = client.get("/api/local/status")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "not_started"
    assert body["agent_id"] == "alice"


# ── config (api-key masking) ─────────────────────────────────────


def test_config_masks_api_key_and_truncates_pubkey(client):
    body = client.get("/api/local/config").json()
    assert body["agent_id"] == "alice"
    assert body["provider"] == "xai"
    # The raw secret must never be returned verbatim.
    assert body["api_key"] != "sk-secret-value-1234567890"
    assert "sk-secret-value-1234567890" not in str(body)
    assert body["public_key"].endswith("...")


# ── capabilities ─────────────────────────────────────────────────


def test_capabilities_lists_discoverable_actions(client):
    caps = client.get("/api/local/capabilities").json()["capabilities"]
    assert len(caps) >= 5
    for c in caps:
        assert {"id", "label", "risk", "example"} <= set(c)
    ids = {c["id"] for c in caps}
    assert "browser.navigate" in ids


# ── memory round trip ────────────────────────────────────────────


def test_memory_save_list_delete_round_trip(client):
    assert client.get("/api/local/memory").json()["notes"] == []

    save = client.post(
        "/api/local/memory",
        json={"key": "fact", "value": "the sky is blue", "memory_type": "note"},
    )
    assert save.json()["saved"] is True

    notes = client.get("/api/local/memory").json()["notes"]
    assert len(notes) == 1
    assert "blue" in str(notes[0])

    assert client.request("DELETE", "/api/local/memory/0").json()["deleted"] is True
    assert client.get("/api/local/memory").json()["notes"] == []


def test_memory_delete_out_of_range_is_clean_error(client):
    body = client.request("DELETE", "/api/local/memory/99").json()
    assert "error" in body


# ── settings ─────────────────────────────────────────────────────


def test_settings_get_lists_provider_catalogue(client):
    body = client.get("/api/local/settings").json()
    assert body["current"]["provider"] == "xai"
    ids = {p["id"] for p in body["providers"]}
    assert {"ollama", "openai", "xai"} <= ids
    ollama = next(p for p in body["providers"] if p["id"] == "ollama")
    assert ollama["is_local"] is True


def test_settings_put_rejects_unknown_provider(client):
    r = client.put("/api/local/settings", json={"provider": "bogus", "model": "x"})
    assert r.status_code == 400


def test_settings_put_cloud_requires_api_key(client):
    r = client.put(
        "/api/local/settings",
        json={"provider": "openai", "model": "gpt-4o", "api_key": ""},
    )
    assert r.status_code == 400


def test_settings_put_local_provider_accepts_empty_key(client, patch_openai, cfg):
    # Local providers may refuse models.list yet still serve chat — the
    # endpoint must accept the switch with an empty key.
    patch_openai.models_raises = True
    r = client.put(
        "/api/local/settings",
        json={"provider": "ollama", "model": "llama3.2", "api_key": ""},
    )
    assert r.status_code == 200
    assert r.json()["provider"] == "ollama"
    assert cfg.provider == "ollama"


def test_settings_put_cloud_persists_after_probe(client, patch_openai, cfg):
    r = client.put(
        "/api/local/settings",
        json={"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-live"},
    )
    assert r.status_code == 200
    assert cfg.provider == "openai"
    assert cfg.model == "gpt-4o-mini"


# ── profile ──────────────────────────────────────────────────────


def test_profile_put_get_round_trip_and_visibility(client):
    put = client.put(
        "/api/local/profile",
        json={
            "name": "Ada Lovelace",
            "bio": "first programmer",
            "skills": ["math"],
            "email": {"value": "ada@example.com", "visible": False},
        },
    )
    assert put.status_code == 200

    got = client.get("/api/local/profile").json()
    assert got["name"] == "Ada Lovelace"
    assert got["skills"] == ["math"]
    # The value persists locally; visibility governs publication, not storage.
    assert got["email"]["value"] == "ada@example.com"
    assert got["email"]["visible"] is False


# ── surfaces/compose (local-LLM key gate; PR regression) ─────


def test_compose_rejects_empty_intent(client):
    assert client.post("/api/local/surfaces/compose", json={"intent": "  "}).json() == {"error": "empty_intent"}


def test_compose_cloud_without_key_returns_no_api_key(client, cfg, monkeypatch):
    cfg.provider = "openai"
    cfg.api_key = ""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    body = client.post("/api/local/surfaces/compose", json={"intent": "show me my org"}).json()
    assert body == {"error": "no_api_key_configured"}


def test_compose_local_provider_bypasses_key_gate(client, cfg, patch_openai, monkeypatch):
    """REGRESSION: ollama needs no API key. The endpoint must get
    past the key gate, route to the local base_url, and return components."""
    cfg.provider = "ollama"
    cfg.model = "llama3.2"
    cfg.api_key = ""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("XAI_API_KEY", raising=False)

    body = client.post("/api/local/surfaces/compose", json={"intent": "show me my org"}).json()
    assert "error" not in body
    assert body["components"] and body["components"][0]["component"] == "Text"
    # Routed to the local OpenAI-compatible endpoint with a placeholder key.
    assert patch_openai.last_init["base_url"] == "http://localhost:11434/v1"
    assert patch_openai.last_init["api_key"] == "local"
