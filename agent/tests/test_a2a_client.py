"""
Tests for A2AClient — Phase 0 observability hook + backward compatibility.

Tests that:
1. A2AClient without credentials works identically (backward compat)
2. A2AClient with credentials includes auth headers
3. Auth header generation doesn't crash on errors
"""

from unittest.mock import MagicMock, patch

import pytest

from community_member.a2a_client import A2AClient


def test_client_without_credentials_raises_missing_credentials():
    """A signed call with no credentials must raise — not silently send unsigned.

    Previously this returned ``{}``, which caused requests to go out
    without an X-Agent-ID header. The chapter then rejected with
    ``missing_agent_id``, hiding the real cause (the local SDK had no
    keypair). Now ``_auth_headers`` raises ``MissingCredentialsError``
    so the failure surfaces at the SDK boundary instead.
    """
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient("https://chapter.example.com")
    with pytest.raises(MissingCredentialsError):
        client._auth_headers("test body")


def test_client_with_credentials_produces_headers():
    """HAPPY: A2AClient with credentials produces auth headers."""
    from community_member.crypto import generate_keypair

    kp = generate_keypair()
    from community_member.auth import init_keys

    init_keys(kp["private_key"], kp["public_key"])

    client = A2AClient(
        "https://chapter.example.com",
        agent_id="test-agent",
        private_key=kp["private_key"],
        public_key=kp["public_key"],
    )
    headers = client._auth_headers("test body")
    assert "X-Agent-ID" in headers
    assert "X-Agent-Signature" in headers
    assert "X-Agent-Timestamp" in headers
    assert headers["X-Agent-ID"] == "test-agent"


def test_client_empty_agent_id_raises():
    """EDGE: empty agent_id raises (not silent {})."""
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient("https://chapter.example.com", agent_id="", private_key="key")
    with pytest.raises(MissingCredentialsError, match="agent_id"):
        client._auth_headers("body")


def test_client_empty_private_key_raises():
    """EDGE: empty private_key raises (not silent {})."""
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient("https://chapter.example.com", agent_id="agent", private_key="")
    with pytest.raises(MissingCredentialsError, match="private_key"):
        client._auth_headers("body")


def test_client_garbage_key_does_not_silently_succeed():
    """FAILURE: a non-empty but garbage private_key may sign with garbage
    bytes (which the chapter will then reject as invalid_signature) OR
    raise during signing. Both are acceptable failure modes — what is
    NOT acceptable is the previous behavior of silently returning ``{}``
    so the request goes out unsigned.
    """
    from community_member.a2a_client import MissingCredentialsError

    client = A2AClient(
        "https://chapter.example.com",
        agent_id="agent",
        private_key="invalid-not-base64!!!",
        public_key="also-invalid",
    )
    try:
        headers = client._auth_headers("body")
    except MissingCredentialsError:
        return  # raise path — acceptable
    # If signing returned headers, they MUST contain the X-Agent-* set —
    # this is the "garbage but well-formed signature" path. The thing
    # we are guarding against is an empty dict.
    assert headers, "Garbage key produced no headers — silent unsigned send."
    assert "X-Agent-ID" in headers
    assert "X-Agent-Signature" in headers


def test_client_backward_compatible_constructor():
    """HAPPY: old constructor with just URL still works."""
    client = A2AClient("https://chapter.example.com")
    assert client.chapter_url == "https://chapter.example.com"
    assert client.agent_id == ""
    assert client.private_key == ""


def test_post_includes_auth_headers():
    """HAPPY: _post method includes auth headers in request."""
    from community_member.auth import init_keys
    from community_member.crypto import generate_keypair

    kp = generate_keypair()
    init_keys(kp["private_key"], kp["public_key"])

    client = A2AClient(
        "https://chapter.example.com",
        agent_id="test",
        private_key=kp["private_key"],
        public_key=kp["public_key"],
    )

    # Mock httpx.post to capture headers
    with patch("httpx.post") as mock_post:
        mock_post.return_value = MagicMock(json=MagicMock(return_value={"ok": True}))
        client._post("/api/test", {"data": "value"})

        # Verify auth headers were passed
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers", {}) if call_kwargs.kwargs else call_kwargs[1].get("headers", {})
        assert "X-Agent-ID" in headers
        assert "X-Agent-Signature" in headers


# ── api_call: signed dispatch for injectable chapter_api_fn (skill install) ────


def test_api_call_get_routes_to_signed_get():
    """GET dispatches to the signed _get (auth headers), ignoring the body."""
    client = A2AClient("https://chapter.example.com", agent_id="a", private_key="k", public_key="p")
    with patch.object(client, "_get", return_value={"ok": "get"}) as mget, patch.object(client, "_post") as mpost:
        out = client.api_call("GET", "/api/skills/x@1.0.0", {"ignored": True})
    assert out == {"ok": "get"}
    mget.assert_called_once_with("/api/skills/x@1.0.0")
    mpost.assert_not_called()


def test_api_call_post_routes_to_signed_post_with_body():
    """Non-GET dispatches to the signed _post carrying the body — this is what
    fixes the skill-install 401 (the install POST must be Ed25519-signed)."""
    client = A2AClient("https://chapter.example.com", agent_id="a", private_key="k", public_key="p")
    with patch.object(client, "_post", return_value={"ok": "post"}) as mpost, patch.object(client, "_get") as mget:
        out = client.api_call("POST", "/api/skills/x@1.0.0/install", {"agent_id": "a"})
    assert out == {"ok": "post"}
    mpost.assert_called_once_with("/api/skills/x@1.0.0/install", {"agent_id": "a"})
    mget.assert_not_called()


def test_api_call_post_defaults_empty_body():
    client = A2AClient("https://chapter.example.com", agent_id="a", private_key="k", public_key="p")
    with patch.object(client, "_post", return_value={}) as mpost:
        client.api_call("POST", "/api/x")
    mpost.assert_called_once_with("/api/x", {})
