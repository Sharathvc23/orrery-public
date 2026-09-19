"""Two headless-provisioning CLI additions:

  * ``community-member receipt verify <receipt.json>`` — verify a SINGLE raw
    ARP receipt fully OFFLINE (schema + Ed25519 signature + hash chain), a thin
    wrapper over ``arp.verify_receipt``. Exit 0 on a valid receipt, non-zero on
    a tampered/invalid one, and it must touch no network.
  * ``community-member init --express --name <NAME>`` / the env twin
    (COMMUNITY_MEMBER_EXPRESS=1 + COMMUNITY_MEMBER_NAME) — stand up a working,
    keyless, configured agent with ZERO interactive prompts, so an agent can be
    provisioned with no TTY. It must not start the server.

The verification/identity libraries themselves are covered elsewhere
(test_arp, test_arp_verify_lockstep, test_wizard_recovery); these tests pin the
CLI plumbing + the headless contract.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from community_member import cli, keystore
from community_member import config as config_mod
from community_member.arp import (
    build_receipt,
    did_from_private_key,
    sign_receipt,
    verify_receipt_signature,
)

# A fixed 32-byte seed so receipts are deterministic and self-verifying.
_ISSUER_SK = b"member-sdk-arp-test-issuer-seed!"
assert len(_ISSUER_SK) == 32


def _signed_receipt() -> dict:
    did = did_from_private_key(_ISSUER_SK)
    r = build_receipt(
        action={"category": "message_sent", "human_summary": "hi", "outcome": "completed"},
        issuer_did=did,
        principal_did=did,
    )
    sign_receipt(r, _ISSUER_SK)
    assert verify_receipt_signature(r) is True
    return r


def _write(p: Path, obj: object) -> Path:
    p.write_text(json.dumps(obj))
    return p


# ══════════════════════════════════════════════════════════════════════
# PART 1 — receipt verify
# ══════════════════════════════════════════════════════════════════════


def test_receipt_verify_valid_exit0(tmp_path, capsys):
    f = _write(tmp_path / "r.json", _signed_receipt())
    assert cli._cmd_receipt_verify(f) == 0
    assert "PASS" in capsys.readouterr().out


def test_receipt_verify_tampered_exit_nonzero(tmp_path, capsys):
    r = _signed_receipt()
    r["action"]["human_summary"] = "actually I said something else"  # break the signature
    f = _write(tmp_path / "r.json", r)
    rc = cli._cmd_receipt_verify(f)
    assert rc != 0
    out = capsys.readouterr().out
    assert "FAIL" in out and "signature" in out


def test_receipt_verify_unreadable_exit1(tmp_path):
    assert cli._cmd_receipt_verify(tmp_path / "does-not-exist.json") == 1


def test_receipt_verify_not_json_object_exit1(tmp_path, capsys):
    f = _write(tmp_path / "r.json", ["not", "an", "object"])
    assert cli._cmd_receipt_verify(f) == 1
    assert "Malformed receipt" in capsys.readouterr().out


def test_receipt_verify_malformed_schema_is_failure(tmp_path):
    # Missing required fields → schema failure (not a crash), non-zero exit.
    f = _write(tmp_path / "r.json", {"version": "arp/0.1"})
    assert cli._cmd_receipt_verify(f) == 2


def test_receipt_verify_touches_no_network(tmp_path, monkeypatch):
    """Skeptic proof: the whole path is offline — opening a socket during
    verification is a hard failure."""
    import socket

    def _boom(*a, **k):
        raise AssertionError("receipt verify must not open a network socket")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    f = _write(tmp_path / "r.json", _signed_receipt())
    assert cli._cmd_receipt_verify(f) == 0


def test_main_wires_receipt_verb(tmp_path):
    f = _write(tmp_path / "r.json", _signed_receipt())
    with pytest.raises(SystemExit) as e:
        cli.main(["receipt", "verify", str(f)])
    assert e.value.code == 0


def test_receipt_verify_parses_cleanly():
    parser = cli._build_parser()
    ns = parser.parse_args(["receipt", "verify", "/tmp/whatever.json"])
    assert ns.receipt_command == "verify"
    assert str(ns.receipt) == "/tmp/whatever.json"


# ══════════════════════════════════════════════════════════════════════
# PART 2 — express (headless) onboarding
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Point config + keystore at a throwaway dir so express provisioning never
    touches the developer's real ~/.community-member."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(config_mod, "CONFIG_DIR", home)
    keystore.reset_for_tests(home)
    yield home
    keystore.reset_for_tests()  # restore the real keystore dir for other tests


def test_express_setup_mints_keyless_local_identity(isolated_home):
    from community_member.wizard import EXPRESS_MODEL, EXPRESS_PROVIDER_ID, express_setup

    config, phrase = express_setup("Ada Lovelace")

    assert config.is_configured(), "express must produce a configured agent"
    assert config.agent_id == "adalovelace"
    assert config.public_key and config.private_key, "identity keypair must be set"
    # Keyless: a LOCAL provider with no real API key.
    assert config.provider == EXPRESS_PROVIDER_ID
    assert config.model == EXPRESS_MODEL
    assert config.api_key == "local"
    assert config.chapter_url == "", "express stands up standalone — no org"
    # The freshly-minted phrase actually restores this identity.
    assert phrase is not None and len(phrase.split()) == 24
    from community_member import recovery

    restored = recovery.recover_from_mnemonic(phrase)
    assert restored.public_key_b64 == config.public_key


def test_express_setup_persists_and_is_idempotent(isolated_home):
    from community_member.wizard import express_setup

    first, phrase1 = express_setup("Ada")
    assert phrase1 is not None
    # config.json + agent.json landed on disk.
    assert (isolated_home / "config.json").exists()
    assert (isolated_home / "agent.json").exists()

    # Re-running an already-configured home is a no-op that mints no new phrase
    # and keeps the same identity.
    second, phrase2 = express_setup("Ada")
    assert phrase2 is None
    assert second.public_key == first.public_key
    assert second.agent_id == first.agent_id


def test_express_setup_empty_name_falls_back(isolated_home):
    from community_member.wizard import express_setup

    config, _ = express_setup("---")  # no usable characters
    assert config.agent_id == "agent"


def test_cmd_express_prints_identity_and_persists(isolated_home, capsys):
    rc = cli._cmd_express("Grace Hopper")
    assert rc == 0
    out = capsys.readouterr().out
    assert "agent_id: gracehopper" in out
    assert "did:key: did:key:z" in out
    # Persisted + loadable as a working identity.
    reloaded = config_mod.Config.load()
    assert reloaded.is_configured()
    assert reloaded.private_key  # signing key round-trips out of the keystore
    sk = base64.b64decode(reloaded.private_key)
    did = did_from_private_key(sk)
    r = build_receipt(
        action={"category": "message_sent", "human_summary": "x", "outcome": "completed"},
        issuer_did=did,
        principal_did=did,
    )
    sign_receipt(r, sk)
    assert verify_receipt_signature(r) is True


def test_cmd_express_missing_name_exit1(isolated_home, capsys):
    assert cli._cmd_express("") == 1
    assert "needs a name" in capsys.readouterr().out


def test_express_requested_honors_flag_and_env(monkeypatch):
    import argparse

    monkeypatch.delenv("COMMUNITY_MEMBER_EXPRESS", raising=False)
    assert cli._express_requested(argparse.Namespace(express=True)) is True
    assert cli._express_requested(argparse.Namespace(express=False)) is False
    assert cli._express_requested(argparse.Namespace()) is False

    monkeypatch.setenv("COMMUNITY_MEMBER_EXPRESS", "1")
    assert cli._express_requested(argparse.Namespace(express=False)) is True
    monkeypatch.setenv("COMMUNITY_MEMBER_EXPRESS", "off")
    assert cli._express_requested(argparse.Namespace(express=False)) is False


def test_express_name_flag_beats_env(monkeypatch):
    import argparse

    monkeypatch.setenv("COMMUNITY_MEMBER_NAME", "FromEnv")
    assert cli._express_name(argparse.Namespace(name="FromFlag")) == "FromFlag"
    assert cli._express_name(argparse.Namespace(name=None)) == "FromEnv"


def test_express_flags_parse_on_init_and_wizard():
    parser = cli._build_parser()
    for verb in ("init", "wizard"):
        ns = parser.parse_args([verb, "--express", "--name", "Ada"])
        assert ns.express is True
        assert ns.name == "Ada"


def test_cmd_wizard_express_shortcut_does_not_start_server(isolated_home, monkeypatch):
    """When express is requested, _cmd_wizard must provision and return WITHOUT
    ever constructing the agent/server."""
    import argparse

    def _explode(*a, **k):
        raise AssertionError("express path must not run the interactive wizard or start the server")

    monkeypatch.setattr(cli, "run_wizard", _explode)
    monkeypatch.setattr(cli, "LocalAgent", _explode)
    monkeypatch.setattr(cli, "create_app", _explode)
    rc = cli._cmd_wizard(argparse.Namespace(express=True, name="Ada", no_browser=True))
    assert rc == 0
    assert config_mod.Config.load().is_configured()


# ── the real acceptance: a non-TTY subprocess piping from /dev/null ──


def test_express_headless_subprocess_no_tty(tmp_path):
    """Acceptance: provision an agent in a subprocess with stdin closed
    (/dev/null) — zero prompts, exit 0, identity persisted."""
    home = tmp_path / "home"
    env = {
        "COMMUNITY_MEMBER_HOME": str(home),
        "PATH": __import__("os").environ.get("PATH", ""),
        # Force the file-backed keystore path (no OS keyring in CI).
        "COMMUNITY_MEMBER_KEYSTORE": "device",
    }
    with open("/dev/null") as devnull:
        proc = subprocess.run(
            [sys.executable, "-m", "community_member.cli", "init", "--express", "--name", "Ada Lovelace"],
            stdin=devnull,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=60,
            text=True,
        )
    assert proc.returncode == 0, proc.stdout
    assert "agent_id: adalovelace" in proc.stdout
    assert "did:key: did:key:z" in proc.stdout
    # The identity is on disk and loadable.
    cfg = json.loads((home / "config.json").read_text())
    assert cfg["agent_id"] == "adalovelace"
    assert cfg["public_key"]
    assert cfg["provider"] == "ollama"
    assert cfg["api_key"] == "local"


def test_express_headless_subprocess_via_env(tmp_path):
    """Same, but driven entirely by env (bare `community-member`, no argv)."""
    home = tmp_path / "home"
    env = {
        "COMMUNITY_MEMBER_HOME": str(home),
        "PATH": __import__("os").environ.get("PATH", ""),
        "COMMUNITY_MEMBER_KEYSTORE": "device",
        "COMMUNITY_MEMBER_EXPRESS": "1",
        "COMMUNITY_MEMBER_NAME": "Grace Hopper",
    }
    with open("/dev/null") as devnull:
        proc = subprocess.run(
            [sys.executable, "-m", "community_member.cli"],
            stdin=devnull,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=60,
            text=True,
        )
    assert proc.returncode == 0, proc.stdout
    assert "agent_id: gracehopper" in proc.stdout
