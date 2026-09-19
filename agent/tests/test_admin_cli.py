"""Tests for community_member.admin CLI subcommand.

Classification: HAPPY / EDGE / FAILURE.

The CLI is thin: it loads config + signing keys, builds signed
requests, hits chapter endpoints, surfaces responses. Tests stub the
HTTP layer + config/auth modules to verify the glue.
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

from community_member import admin as admin_mod


def _mock_chapter_and_agent(monkeypatch, chapter_url="https://test-chapter.example.com", agent_id="alice"):
    """Stub config.load_config + auth.is_loaded so subcommand handlers
    don't need a real SDK config on disk."""
    fake_cfg = MagicMock()
    fake_cfg.chapter_url = chapter_url
    fake_cfg.agent_id = agent_id
    monkeypatch.setattr("community_member.admin.config.Config.load", classmethod(lambda cls: fake_cfg))

    # auth.is_loaded may not exist; patch with a noop is_loaded that
    # claims True so the admin module's loader check passes.
    monkeypatch.setattr("community_member.admin.auth.is_loaded", lambda: True, raising=False)

    # auth.sign_request_body — return realistic signed headers shape
    def fake_sign(*, body, agent_id, method, url_path):
        return {
            "X-Agent-ID": agent_id,
            "X-Agent-Signature": "fake-sig",
            "X-Agent-Timestamp": "1234567890",
            "X-Agent-Nonce": "fake-nonce",
            "X-Agent-Sig-Scheme": "ed25519+nonce",
        }

    monkeypatch.setattr("community_member.admin.auth.sign_request_body", fake_sign)


def _mock_httpx_response(status_code=200, json_body=None):
    """Build a fake httpx.Response-like object."""
    r = MagicMock()
    r.status_code = status_code
    r.json = MagicMock(return_value=json_body or {})
    r.text = json.dumps(json_body) if json_body else ""
    return r


def _patch_httpx_client(monkeypatch, response):
    """Patch httpx.Client so requests return the stub response."""
    client_mock = MagicMock()
    client_mock.__enter__ = MagicMock(return_value=client_mock)
    client_mock.__exit__ = MagicMock(return_value=False)
    client_mock.get = MagicMock(return_value=response)
    client_mock.delete = MagicMock(return_value=response)
    client_mock.request = MagicMock(return_value=response)
    monkeypatch.setattr("community_member.admin.httpx.Client", lambda *a, **kw: client_mock)
    return client_mock


# ══════════════════════════════════════════════════════════════════════
# Argparse registration
# ══════════════════════════════════════════════════════════════════════


def test_register_subcommands_adds_admin_with_five_actions():
    """The admin subcommand should expose: status, members, set-role, remove, revoke."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    admin_mod.register_subcommands(sub)

    # Parse each subcommand to confirm it's wired
    for action in ["status", "members", "set-role", "remove", "revoke"]:
        if action == "set-role":
            args = parser.parse_args(["admin", action, "alice", "leader"])
            assert args.agent_id == "alice"
            assert args.role == "leader"
        elif action in ("remove", "revoke"):
            args = parser.parse_args(["admin", action, "alice"])
            assert args.agent_id == "alice"
        else:
            args = parser.parse_args(["admin", action])
        assert hasattr(args, "func")


# ══════════════════════════════════════════════════════════════════════
# status
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_status_prints_chapter_metadata(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(
            200,
            {
                "agent_id": "bayarea",
                "agent_name": "Bay Area Chapter",
                "members_total": 66,
                "federation_peers": 4,
            },
        ),
    )
    exit_code = admin_mod._cmd_status()
    assert exit_code == 0
    captured = capsys.readouterr()
    assert '"agent_id": "bayarea"' in captured.out
    assert '"members_total": 66' in captured.out


def test_AUTHZ_status_signed_by_non_admin_surfaces_403(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(
            403,
            {
                "error": "admin role required",
                "hint": "agent_id=alice has chapter_role='member'; needs 'admin'",
                "remediation": "ask an existing admin to promote you via POST /admin/api/members/{your_id}/role",
            },
        ),
    )
    exit_code = admin_mod._cmd_status()
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "admin role required" in captured.err
    assert "remediation" in captured.err.lower() or "promote" in captured.err.lower()


# ══════════════════════════════════════════════════════════════════════
# members
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_members_prints_table(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(
            200,
            {
                "members": [
                    {"agent_id": "alice", "name": "Alice", "skills": ["python", "ml"]},
                    {"agent_id": "bob", "name": "Bob", "skills": ["design"]},
                ],
                "total": 2,
            },
        ),
    )
    exit_code = admin_mod._cmd_members(100)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "alice" in captured.out
    assert "bob" in captured.out
    assert "Alice" in captured.out


def test_EDGE_members_limit_clamps_to_500(monkeypatch):
    """Limit out of range gets clamped to [1, 500]."""
    _mock_chapter_and_agent(monkeypatch)
    client = _patch_httpx_client(monkeypatch, _mock_httpx_response(200, {"members": [], "total": 0}))
    admin_mod._cmd_members(10000)
    # The GET URL should carry limit=500, not 10000
    args, _kwargs = client.get.call_args
    assert "limit=500" in args[0]


# ══════════════════════════════════════════════════════════════════════
# set-role
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_set_role_succeeds(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(200, {"agent_id": "bob", "chapter_role": "leader"}),
    )
    exit_code = admin_mod._cmd_set_role("bob", "leader")
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "@bob" in captured.out
    assert "leader" in captured.out


def test_AUTHZ_set_role_last_admin_demotion_surfaces_409(monkeypatch, capsys):
    """E2 protection — server returns 409 when signed admin tries to
    demote themselves and they're the only admin."""
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(
            409,
            {
                "error": "would leave no admin",
                "hint": "Retry with ?force=true (bearer-only) if intentional.",
            },
        ),
    )
    exit_code = admin_mod._cmd_set_role("alice", "leader")
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "would leave no admin" in captured.err


# ══════════════════════════════════════════════════════════════════════
# remove
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_remove_with_confirmation_succeeds(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(monkeypatch, _mock_httpx_response(200, {"removed": "bob"}))
    with patch("builtins.input", return_value="yes"):
        exit_code = admin_mod._cmd_remove("bob")
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "removed" in captured.out


def test_ADVERSARIAL_remove_without_confirmation_aborts(monkeypatch, capsys):
    """Anything other than 'yes' aborts the destructive action."""
    _mock_chapter_and_agent(monkeypatch)
    # No httpx patch — we expect no request to be made
    with patch("builtins.input", return_value="no"):
        exit_code = admin_mod._cmd_remove("bob")
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "aborted" in captured.out


# ══════════════════════════════════════════════════════════════════════
# revoke
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_revoke_with_confirmation_succeeds(monkeypatch, capsys):
    _mock_chapter_and_agent(monkeypatch)
    _patch_httpx_client(
        monkeypatch,
        _mock_httpx_response(
            200,
            {"agent_id": "bob", "revoked": True, "hint": "TOFU on next signed request"},
        ),
    )
    with patch("builtins.input", return_value="yes"):
        exit_code = admin_mod._cmd_revoke("bob")
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "key revoked" in captured.out
    assert "TOFU" in captured.out


# ══════════════════════════════════════════════════════════════════════
# Config errors — bail cleanly without a panic
# ══════════════════════════════════════════════════════════════════════


def test_FAILURE_missing_chapter_url_surfaces_clean_error(monkeypatch, capsys):
    """If SDK isn't initialized (no chapter_url), the CLI prints a
    clear error and returns exit=2."""
    fake_cfg = MagicMock()
    fake_cfg.chapter_url = ""  # not configured
    fake_cfg.agent_id = "alice"
    monkeypatch.setattr("community_member.admin.config.Config.load", classmethod(lambda cls: fake_cfg))
    exit_code = admin_mod._cmd_status()
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "chapter_url" in captured.err.lower()


def test_FAILURE_missing_agent_id_surfaces_clean_error(monkeypatch, capsys):
    fake_cfg = MagicMock()
    fake_cfg.chapter_url = "https://chapter.example.com"
    fake_cfg.agent_id = ""
    monkeypatch.setattr("community_member.admin.config.Config.load", classmethod(lambda cls: fake_cfg))
    exit_code = admin_mod._cmd_status()
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "agent_id" in captured.err.lower()
