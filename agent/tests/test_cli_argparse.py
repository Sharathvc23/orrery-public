"""CLI surface tests (Track 2 of pre-launch audit).

Pre-launch audit found that the bare-handcrafted `argv` parser had no
``--help``, no ``--version``, no ``wizard`` subcommand (the README
documented one), no ``init`` subcommand (a runtime error message
documented one). Friction-to-first-success was 10/10: the very first
command in the README returned PyPI 404, and the runtime error
messages directed users at non-existent commands.

This module locks the argparse contract so a future PR cannot regress
the public CLI shape — every subcommand the README mentions must
parse, ``--help`` must work, ``--version`` must report a real string,
and the bare invocation must still route to the wizard for backward
compat with every existing user.
"""

from __future__ import annotations

import pytest

from community_member.cli import _build_parser, _package_version

# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_help_runs_without_error(capsys: pytest.CaptureFixture[str]) -> None:
    """``community-member --help`` must succeed and list every subcommand
    the README mentions. argparse exits with SystemExit(0) on --help."""
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for cmd in ("wizard", "init", "panic", "reset", "audit", "graduations", "keystore"):
        assert cmd in out, f"--help output missing {cmd!r}"


def test_version_reports_a_string(capsys: pytest.CaptureFixture[str]) -> None:
    """``--version`` must return SOMETHING — even 'unknown' is better
    than silent. Real installs report the pyproject version."""
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "community-member" in out


def test_package_version_helper_returns_non_empty() -> None:
    """The helper that backs --version MUST never return empty."""
    v = _package_version()
    assert v
    # In dev environments this resolves to the pyproject version (0.6.0+).
    # In edge cases it falls back to "unknown" — both are non-empty.
    assert isinstance(v, str)


# ---------------------------------------------------------------------------
# Subcommand parsing — every README-documented command must resolve
# ---------------------------------------------------------------------------


def test_bare_invocation_has_no_subcommand() -> None:
    """No subcommand → command attr is None. main() then routes to
    the wizard (verified separately so we don't have to spin up the
    actual wizard which prompts for input)."""
    parser = _build_parser()
    args = parser.parse_args([])
    assert args.command is None


def test_wizard_subcommand_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["wizard"])
    assert args.command == "wizard"
    assert args.no_browser is False


def test_wizard_no_browser_flag_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["wizard", "--no-browser"])
    assert args.no_browser is True


def test_init_subcommand_is_alias_for_wizard() -> None:
    """The ``init`` subcommand routes to the same handler as ``wizard``.
    a2a_client.MissingCredentialsError points users at ``init``; this
    alias makes that error message non-fictional."""
    parser = _build_parser()
    args_wizard = parser.parse_args(["wizard"])
    args_init = parser.parse_args(["init"])
    assert args_wizard.func is args_init.func


def test_panic_subcommand_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["panic"])
    assert args.command == "panic"


def test_reset_subcommand_parses_with_yes() -> None:
    parser = _build_parser()
    args = parser.parse_args(["reset", "--yes"])
    assert args.command == "reset"
    assert args.yes is True


def test_reset_short_yes_flag() -> None:
    parser = _build_parser()
    args = parser.parse_args(["reset", "-y"])
    assert args.yes is True


def test_audit_verify_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["audit", "verify"])
    assert args.command == "audit"
    assert args.audit_command == "verify"


def test_graduations_list_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["graduations", "list"])
    assert args.command == "graduations"
    assert args.graduations_command == "list"


def test_graduations_revoke_requires_three_positionals() -> None:
    parser = _build_parser()
    args = parser.parse_args(["graduations", "revoke", "files.read", "scope-x", "abc123"])
    assert args.capability == "files.read"
    assert args.scope == "scope-x"
    assert args.ctx == "abc123"


def test_graduations_revoke_missing_args_fails(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["graduations", "revoke", "files.read"])
    assert exc.value.code == 2  # argparse usage error


def test_keystore_status_parses() -> None:
    parser = _build_parser()
    args = parser.parse_args(["keystore", "status"])
    assert args.keystore_command == "status"


@pytest.mark.parametrize("backend", ["keyring", "passphrase", "device"])
def test_keystore_rotate_accepts_each_documented_backend(backend: str) -> None:
    """The README documents three backends. argparse choices=[...]
    enforces the closed set — typos like 'keychain' fail before any
    real work happens, instead of much later inside keystore.rotate."""
    parser = _build_parser()
    args = parser.parse_args(["keystore", "rotate", backend])
    assert args.backend == backend


def test_keystore_rotate_rejects_unknown_backend(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["keystore", "rotate", "keychain"])
    # argparse exits 2 on usage error.
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "keychain" in err  # complaint mentions the bad value


def test_unknown_subcommand_fails_with_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["bogus-command"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# Subparsers all set defaults(func=...) so main() can dispatch without
# a long if/elif chain. Lock that contract.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["wizard"],
        ["init"],
        ["panic"],
        ["reset"],
        ["audit", "verify"],
        ["graduations", "list"],
        ["graduations", "revoke", "x", "y", "z"],
        ["keystore", "status"],
        ["keystore", "rotate", "keyring"],
    ],
)
def test_every_resolved_subcommand_attaches_a_handler(argv: list[str]) -> None:
    """Every leaf subcommand MUST set ``func`` so main() can dispatch.
    A subcommand that resolves but has no func attached is a routing
    bug — the user sees an opaque crash at runtime."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    assert hasattr(args, "func"), f"argv={argv!r} resolved without a func handler"
    assert callable(args.func)


# ── That change: --version must report the real version, never "unknown" ──────────
def test_package_version_falls_back_to_dunder_version_not_unknown(monkeypatch):
    """On a clean install where neither dist name is registered in importlib
    metadata (or an editable checkout), --version must fall back to the
    in-package __version__, NOT 'unknown'."""
    import importlib.metadata as md

    import community_member.cli as cli
    from community_member import __version__

    def _not_found(name):
        raise md.PackageNotFoundError(name)

    monkeypatch.setattr(md, "version", _not_found)
    assert cli._package_version() == __version__
    assert cli._package_version() != "unknown"


def test_package_version_prefers_orrery_agent_dist(monkeypatch):
    """The current dist name is 'orrery-agent'; the pre-rename 'community-member'
    is only a legacy fallback."""
    import importlib.metadata as md

    import community_member.cli as cli

    def _fake(name):
        if name == "orrery-agent":
            return "9.9.9"
        raise md.PackageNotFoundError(name)

    monkeypatch.setattr(md, "version", _fake)
    assert cli._package_version() == "9.9.9"
