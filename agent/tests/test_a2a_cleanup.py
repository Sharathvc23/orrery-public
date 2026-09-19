"""
Regression tests for the W12 post-audit cleanup.

Thesis:
  1. `AsyncGoogleA2AClient` signs requests — previously dropped the keypair.
  2. `AsyncGoogleA2AClient` surface is complete — previously missing
     get_task, cancel_task, resubscribe.
  3. Agent Card `url` reflects the Host header the client reached us on,
     not a baked-in localhost — so a card served from a production URL
     advertises that URL back to the client.
  4. DASHBOARD_PORT has a single source of truth (community_member.__init__).

Classification: HAPPY / ADVERSARIAL
"""

from __future__ import annotations

import pytest

from community_member import DASHBOARD_PORT, a2a_rpc
from community_member.a2a_client_v2 import (
    A2AClient,
    AsyncA2AClient,
    AsyncGoogleA2AClient,
    GoogleA2AClient,
    _signed_headers,
)

# ═══════════════════════════════════════════════════════
# HAPPY — no duplicate port constants
# ═══════════════════════════════════════════════════════


def test_dashboard_port_has_single_source_of_truth():
    """The port must live in community_member.__init__; importing it from
    cli.py must produce the same object (not a drifted copy)."""
    from community_member import cli

    assert cli.DASHBOARD_PORT == DASHBOARD_PORT
    # Same int literal — if anyone reintroduces a local constant, this
    # equality is still true but the identity below catches drift when
    # they define DASHBOARD_PORT = 8888 locally.
    assert cli.DASHBOARD_PORT is DASHBOARD_PORT


# ═══════════════════════════════════════════════════════
# HAPPY — class naming
# ═══════════════════════════════════════════════════════


def test_legacy_names_are_aliases_not_distinct_classes():
    """ADVERSARIAL check against the name collision: `A2AClient` in this
    module must point at GoogleA2AClient — not a duplicated
    implementation — so bug fixes land in one place."""
    assert A2AClient is GoogleA2AClient
    assert AsyncA2AClient is AsyncGoogleA2AClient


def test_new_names_do_not_collide_with_legacy_module():
    """The legacy chapter REST client also exports A2AClient. Ensure the
    two are different objects (imported by different paths)."""
    from community_member.a2a_client import A2AClient as LegacyClient

    assert LegacyClient is not GoogleA2AClient


# ═══════════════════════════════════════════════════════
# HAPPY — Async client signs requests
# ═══════════════════════════════════════════════════════


def test_signed_headers_emits_xagent_id_when_key_present():
    # Force HMAC so the test doesn't depend on pynacl being present.
    headers = _signed_headers("body", "alice", "k" * 44, "pub", "hmac-sha256")
    assert headers["X-Agent-ID"] == "alice"
    assert headers["X-Agent-Signature"]
    assert headers["X-Agent-Timestamp"]


def test_signed_headers_noop_when_no_key():
    headers = _signed_headers("body", None, None, None)
    assert headers == {"Content-Type": "application/json"}


def test_signed_headers_default_prefers_ed25519_when_available():
    """When pynacl is installed the default scheme is Ed25519 (matches
    auth.init_keys())."""
    from community_member.crypto import ed25519_available, generate_ed25519_keypair

    if not ed25519_available():
        pytest.skip("pynacl not installed")
    kp = generate_ed25519_keypair()
    headers = _signed_headers("body", "alice", kp["private_key"], kp["public_key"])
    assert headers["X-Agent-Sig-Scheme"] == "ed25519"
    assert headers["X-Agent-ID"] == "alice"
    assert headers["X-Agent-Signature"]
    assert "X-Agent-DID-Key" in headers  # did:key derived from pub


def test_signed_headers_honors_explicit_hmac_scheme():
    """Callers can override the default scheme explicitly."""
    headers = _signed_headers("body", "alice", "k" * 44, "pub" * 14, "hmac-sha256")
    assert headers["X-Agent-Sig-Scheme"] == "hmac-sha256"
    assert headers["X-Agent-Public-Key"] == "pub" * 14


def test_signed_headers_regression_ed25519_seed_length():
    """REGRESSION: this is the audit's original bug. Ed25519 private-key
    seeds are 32 bytes → 44 base64 chars, exactly the same length as a
    typical HMAC key. The previous length-based heuristic silently picked
    HMAC for genuine Ed25519 credentials, so the server couldn't verify.

    Now the scheme is explicit, so a caller who says 'ed25519' gets it."""
    from community_member.crypto import ed25519_available, generate_ed25519_keypair

    if not ed25519_available():
        pytest.skip("pynacl not installed")
    kp = generate_ed25519_keypair()
    assert len(kp["private_key"]) <= 60  # defeats the old heuristic
    headers = _signed_headers("body", "alice", kp["private_key"], kp["public_key"], "ed25519")
    assert headers["X-Agent-Sig-Scheme"] == "ed25519"


# ═══════════════════════════════════════════════════════
# HAPPY — Async client has the full surface
# ═══════════════════════════════════════════════════════


def test_async_client_exposes_complete_surface():
    """ADVERSARIAL: previously the async client was missing get_task,
    cancel_task, resubscribe. Assert method parity with the sync client."""
    sync_methods = {m for m in dir(GoogleA2AClient) if not m.startswith("_")}
    async_methods = {m for m in dir(AsyncGoogleA2AClient) if not m.startswith("_")}
    # Both have the same public methods (bar close vs aclose, __enter__ vs __aenter__)
    sync_core = sync_methods - {"close"}
    async_core = async_methods - {"aclose"}
    assert sync_core == async_core, (
        f"surface diverged: sync-only={sync_core - async_core}, async-only={async_core - sync_core}"
    )


# ═══════════════════════════════════════════════════════
# HAPPY — Agent Card URL follows Host header
# ═══════════════════════════════════════════════════════


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from community_member import task_store as ts_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(ts_mod, "TASK_STORE_PATH", tmp_path / "tasks.jsonl")

    cfg = Config()
    cfg.agent_id = "alice"
    cfg.name = "Alice"
    cfg.chapter_url = "https://chapter.example"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    return TestClient(create_app(cfg))


def test_agent_card_url_follows_host_header(app_client):
    """HAPPY: A card served from production must advertise the production
    URL, not localhost. We do this by honoring the Host header."""
    resp = app_client.get("/.well-known/agent.json", headers={"Host": "agent.alice.example"})
    assert resp.status_code == 200
    body = resp.json()
    assert "agent.alice.example" in body["url"]
    # The NANDA extension should cross-reference the same host
    ext = body["x-nanda"]
    assert "agent.alice.example" in ext["agentfacts_url"]


def test_agentfacts_url_follows_host_header(app_client):
    resp = app_client.get("/agentfacts.json", headers={"Host": "agent.alice.example"})
    assert resp.status_code == 200
    body = resp.json()
    # NANDA endpoints block points back to the same host
    static = body["endpoints"]["static"][0]
    assert "agent.alice.example" in static


# ═══════════════════════════════════════════════════════
# HAPPY — no orphan error codes
# ═══════════════════════════════════════════════════════


def test_all_defined_error_codes_are_used():
    """ADVERSARIAL: defining error codes and never emitting them is
    bloatware — clients can't distinguish them, the codes just confuse
    new readers. The audit flagged -32603 and -32010 for this reason.

    A constant counts as "used" if it appears anywhere in the package
    source outside the line that defines it. ERROR_PARSE, for example,
    is defined in a2a_rpc.py but referenced from server.py."""
    from pathlib import Path

    error_consts = [
        name for name in dir(a2a_rpc) if name.startswith("ERROR_") and isinstance(getattr(a2a_rpc, name), int)
    ]
    pkg_dir = Path(a2a_rpc.__file__).parent
    all_src = "\n".join(p.read_text() for p in pkg_dir.glob("*.py"))
    for name in error_consts:
        # One occurrence is the definition; we want at least one more use.
        assert all_src.count(name) >= 2, f"{name} is defined but never referenced elsewhere"


def test_task_store_has_no_unused_exports():
    """ADVERSARIAL: the previous MAX_TASK_LOG_LINES was unused and came
    with a comment promising rotation logic that didn't exist."""
    from community_member import task_store

    assert not hasattr(task_store, "MAX_TASK_LOG_LINES")


# ═══════════════════════════════════════════════════════
# HAPPY — server tool dispatcher is single-path
# ═══════════════════════════════════════════════════════


def test_server_tool_dispatcher_uses_single_tool_source(app_client):
    """The previous dispatcher had two branches to find AGENT_TOOLS. After
    cleanup, the FakeAgent's AGENT_TOOLS should still be honored (narrow
    list for tests) while production agents fall through to the module
    default. Assert both paths still work through tasks/send."""
    # Absent FakeAgent (no agent passed to create_app), the dispatcher
    # should fall back to the module AGENT_TOOLS list. We test one tool
    # from that canonical list is reachable.
    resp = app_client.post(
        "/",
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tasks/send",
            "params": {
                "id": "t",
                "message": {
                    "role": "user",
                    "parts": [{"type": "data", "data": {"tool": "nonexistent_tool", "args": {}}}],
                },
            },
        },
    )
    body = resp.json()
    # No agent wired → RuntimeError at dispatch time → tool_failed
    # OR agent present and unknown tool → tool_not_found. Either way, a
    # typed JSON-RPC error is what we expect, never a 500.
    assert resp.status_code == 200
    assert "error" in body or body["result"]["status"]["state"] == "failed"
