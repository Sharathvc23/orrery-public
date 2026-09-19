"""That change — standard NANDA/A2A agent card + /run invoke (drop the custom dialect).

A by-the-book NANDA resolver (Index → registry/host39 → agent card → invoke)
consumes a *standard* A2A AgentCard at /.well-known/agent.json and invokes the
runtime at ``POST <card.url>/run`` with ``{message:{role,parts:[{text}]}}``.
Verified against the local testbed: host39's served SMB card IS conformant, so
Orrery was the outlier.

Locked here:
  * GET /.well-known/agent.json — public, standard A2AAgentCard shape, a usable
    ``url`` (= PUBLIC_URL, the base the resolver appends ``/run`` to),
    Content-Type application/a2a-agent-card+json.
  * POST /run — Ed25519 v0.2 control set (unsigned→401, signed→200, tampered→401),
    robust text extraction from parts. The LIVE resolver/demo send bare
    ``{"text": ...}`` parts (no kind/type) — that case is asserted explicitly,
    alongside the kind/type variants.
  * Back-compat: POST /a2a (signed) + GET /.well-known/nanda-agent.json still 200.

Classification: INTEROP + ADVERSARIAL (the signed control set is the security gate).
"""

from __future__ import annotations

import base64
import importlib
import json
import sys
import time

import nacl.signing
import pytest
from fastapi.testclient import TestClient

_PUBLIC_URL = "https://test-org.example"


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-card-org")
    monkeypatch.setenv("AGENT_NAME", "Test Card Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "An org for the A2A card test")
    monkeypatch.setenv("AGENT_FOCUS", "datetime, web-fetch")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    # lifespan (which sets PUBLIC_URL) doesn't run for a non-context TestClient;
    # the card handler reads the module global, so set it directly.
    monkeypatch.setattr(mod, "PUBLIC_URL", _PUBLIC_URL)
    return mod


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    import auth_verify

    chapter_agent_module._rate_limit_store.clear()
    auth_verify._agent_keys.clear()  # no TOFU keys leaking across tests
    return TestClient(chapter_agent_module.app)


# ── signing helpers — real Ed25519 v0.2 (body:agent_id:timestamp) ─────


def _new_keypair():
    sk = nacl.signing.SigningKey.generate()
    priv_b64 = base64.b64encode(bytes(sk)).decode()
    pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode()
    return priv_b64, pub_b64


def _signed_headers(
    agent_id: str, body_str: str, priv_b64: str, pub_b64: str, url_path: str = "/run"
) -> dict:
    """v0.3 (`ed25519+nonce`) headers — what a compliant client sends.

    These tests are about body extraction and routing, not about the signing
    scheme. `/run` stopped accepting v0.2 when this org started advertising
    spec 0.5: it is a §3-signed POST and spec/0.5's v0.2 carve-out names
    the `/a2a` family only. The scheme rule itself is prosecuted in
    test_c4_method_binding_middleware.py and test_spec_05_advertisement.py.
    """
    import base64
    import os

    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    message = f"POST:{url_path}:{body_str}:{agent_id}:{ts}:{nonce}"
    sig = sovereign_identity.ed25519_sign(message, priv_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub_b64),  # TOFU first contact
        "Content-Type": "application/json",
    }


def _mock_agent_logic(mod, monkeypatch):
    """Deterministic, no-LLM agent_logic that echoes the text it received."""

    async def fake_logic(message: str, conversation_id: str):
        return (f"echo:{message}", None)

    monkeypatch.setattr(mod, "agent_logic", fake_logic)


# ── GET /.well-known/agent.json — standard A2A AgentCard ──────────────


def test_agent_json_is_standard_a2a_card(client: TestClient) -> None:
    resp = client.get("/.well-known/agent.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/a2a-agent-card+json")
    card = resp.json()
    # Standard A2AAgentCard shape (matches host39's served SMB card).
    assert card["name"] == "Test Card Org"
    assert card["url"] == _PUBLIC_URL  # the base the resolver appends /run to
    assert card["version"]  # non-empty version string
    assert card["capabilities"] == {"streaming": False, "pushNotifications": False}
    assert card["authentication"]["schemes"] == ["ed25519"]
    assert isinstance(card["skills"], list)
    assert card["provider"]["organization"] == "Test Card Org"
    assert card["provider"]["url"] == _PUBLIC_URL


def test_agent_json_classified_open() -> None:
    import auth_verify

    assert auth_verify.is_open_path("GET", "/.well-known/agent.json") is True
    assert auth_verify.requires_auth("GET", "/.well-known/agent.json") is False


# ── POST /run — classification + Ed25519 v0.2 control set ─────────────


def test_run_requires_auth() -> None:
    import auth_verify

    assert auth_verify.requires_auth("POST", "/run") is True
    assert auth_verify.is_open_path("POST", "/run") is False


def test_run_unsigned_is_401(client: TestClient) -> None:
    resp = client.post("/run", json={"message": {"role": "user", "parts": [{"text": "hi"}]}})
    assert resp.status_code == 401


def test_run_signed_bare_text_part_reaches_agent(client, chapter_agent_module, monkeypatch) -> None:
    """The LIVE resolver/demo send parts as bare {"text": ...} (no kind/type).
    Signed → 200, and the agent receives the extracted text."""
    _mock_agent_logic(chapter_agent_module, monkeypatch)
    priv, pub = _new_keypair()
    body = json.dumps({"id": "task-1", "message": {"role": "user", "parts": [{"text": "what time is it?"}]}})
    headers = _signed_headers("TEST-runner", body, priv, pub)

    resp = client.post("/run", content=body, headers=headers)
    assert resp.status_code == 200
    assert "echo:what time is it?" in resp.text  # text extracted + routed to agent_logic


def test_run_signed_extracts_text_from_kind_and_type(client, chapter_agent_module, monkeypatch) -> None:
    """Accept both `kind` and `type` part keys; concatenate multiple text parts."""
    _mock_agent_logic(chapter_agent_module, monkeypatch)
    priv, pub = _new_keypair()
    body = json.dumps(
        {
            "message": {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": "alpha"},
                    {"type": "text", "text": "beta"},
                ],
            }
        }
    )
    headers = _signed_headers("TEST-runner2", body, priv, pub)

    resp = client.post("/run", content=body, headers=headers)
    assert resp.status_code == 200
    assert "alpha" in resp.text and "beta" in resp.text


def test_run_tampered_body_is_401(client, chapter_agent_module, monkeypatch) -> None:
    """Sign one body, send a different one → signature mismatch → 401."""
    _mock_agent_logic(chapter_agent_module, monkeypatch)
    priv, pub = _new_keypair()
    signed_body = json.dumps({"message": {"role": "user", "parts": [{"text": "original"}]}})
    headers = _signed_headers("TEST-runner3", signed_body, priv, pub)

    tampered = json.dumps({"message": {"role": "user", "parts": [{"text": "TAMPERED"}]}})
    resp = client.post("/run", content=tampered, headers=headers)
    assert resp.status_code == 401


def test_run_returns_a2a_task_result(client, chapter_agent_module, monkeypatch) -> None:
    """The response is a standard A2A task result carrying the answer text."""
    _mock_agent_logic(chapter_agent_module, monkeypatch)
    priv, pub = _new_keypair()
    body = json.dumps({"id": "task-42", "message": {"role": "user", "parts": [{"text": "ping"}]}})
    headers = _signed_headers("TEST-runner4", body, priv, pub)

    resp = client.post("/run", content=body, headers=headers)
    assert resp.status_code == 200
    result = resp.json()
    assert result["status"]["state"] == "completed"
    text_parts = [p.get("text", "") for art in result["artifacts"] for p in art["parts"]]
    assert any("echo:ping" in t for t in text_parts)


# ── Back-compat: /a2a (signed) + nanda-agent.json (open) still 200 ────


def test_a2a_backcompat_signed_still_200(client, chapter_agent_module, monkeypatch) -> None:
    """/a2a is a default-POST → requires auth; a SIGNED request still 200s."""
    _mock_agent_logic(chapter_agent_module, monkeypatch)
    priv, pub = _new_keypair()
    body = json.dumps({"role": "user", "content": {"type": "text", "text": "hello"}, "conversation_id": "c1"})
    # v0.3 binds the url_path, so it must be the path actually requested.
    headers = _signed_headers("TEST-runner5", body, priv, pub, url_path="/a2a")

    resp = client.post("/a2a", content=body, headers=headers)
    assert resp.status_code == 200


def test_nanda_agent_json_backcompat_still_200(client: TestClient) -> None:
    resp = client.get("/.well-known/nanda-agent.json")
    assert resp.status_code == 200
    assert "a2a_url" in resp.json()  # the legacy custom dialect is preserved
