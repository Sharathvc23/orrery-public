"""The installer says what is true for the kind of run it is.

Three lines were wrong or missing, each observed on a re-run of the shipped
installer:

  * "first run pulls images, be patient…" was printed on every run, first or
    fifth; a reconcile of a running stack is a different thing and takes
    seconds;
  * `down --purge` dropped the volumes and said "volumes purged", leaving
    `.env` — every generated secret and the org's pinned ports — behind
    without a word, so the next run was silently the same org on an empty
    database;
  * a run interrupted with Ctrl-C printed nothing at all, leaving a reader
    with a half-started stack and no word on whether running again is safe.
    It is: `.env` is kept and Compose reconciles what is running.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_installer():
    spec = importlib.util.spec_from_loader(
        "orrery_up_run_messages",
        importlib.machinery.SourceFileLoader(
            "orrery_up_run_messages", str(REPO / "orrery-up")
        ),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installer(tmp_path, monkeypatch):
    module = _load_installer()
    monkeypatch.setattr(module, "ENV_PATH", tmp_path / ".env")
    monkeypatch.setattr(module, "REPO", tmp_path)
    return module


# ── first start vs reconcile ───────────────────────────────────────────────


def test_a_first_start_says_it_pulls_and_builds(installer):
    assert "first start" in installer.up_message(existing=False)
    assert "pulling images" in installer.up_message(existing=False)


def test_a_re_run_says_it_reconciles_and_does_not_claim_a_first_run(installer):
    """THE DEFECT: the first-run line on every run."""
    msg = installer.up_message(existing=True)
    assert "reconcil" in msg
    assert "first" not in msg and "pull" not in msg, msg


def test_up_decides_by_whether_compose_holds_containers(installer, monkeypatch):
    """The question is asked of Compose (`ps -a`, stopped containers
    included), not inferred from `.env` — an `.env` with no stack behind it
    is still a first start."""
    said: list[str] = []
    monkeypatch.setattr(installer, "say", said.append)
    monkeypatch.setattr(
        installer, "compose", lambda *a, **k: SimpleNamespace(returncode=0)
    )
    monkeypatch.setattr(installer, "git_commit", lambda: "abc1234")

    monkeypatch.setattr(
        installer, "_run", lambda cmd, **k: SimpleNamespace(stdout="", returncode=0)
    )
    installer.up()
    assert said[-1] == installer.up_message(existing=False)

    monkeypatch.setattr(
        installer,
        "_run",
        lambda cmd, **k: SimpleNamespace(stdout="db\nserver\n", returncode=0),
    )
    installer.up()
    assert said[-1] == installer.up_message(existing=True)


# ── what `down --purge` kept ───────────────────────────────────────────────


def test_purge_says_env_was_kept_and_what_that_means(installer):
    lines = installer.down_messages(purge=True, env_kept=True)
    text = " ".join(lines)
    assert "volumes purged" in text
    assert ".env kept" in text, "a purge that keeps .env must say so"
    assert "same org" in text and "Delete .env" in text


def test_purge_with_no_env_says_the_next_run_is_fresh(installer):
    text = " ".join(installer.down_messages(purge=True, env_kept=False))
    assert "no .env" in text and "fresh install" in text


def test_a_plain_down_keeps_data_and_says_so(installer):
    lines = installer.down_messages(purge=False, env_kept=True)
    assert lines == [f"{installer.OK} stack stopped (data kept — --purge to drop)"]


def test_the_down_path_reports_env_state_after_the_teardown(installer):
    source = (REPO / "orrery-up").read_text(encoding="utf-8")
    down = source[source.index('if args.command == "down":') :]
    down = down[: down.index('if args.command == "e2e":')]
    assert 'compose("down"' in down
    assert "down_messages(args.purge, ENV_PATH.exists())" in down


# ── an interrupted run says something ──────────────────────────────────────


def test_an_interrupted_run_exits_130_and_says_it_is_safe_to_run_again():
    """Driven as a subprocess so the handler under test is the real
    entrypoint's, not a re-implementation: a SIGINT-shaped exception raised
    from inside main() must reach the reader as a message and 130."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import importlib.machinery, importlib.util, sys\n"
            "loader = importlib.machinery.SourceFileLoader('orrery_up_main', sys.argv[1])\n"
            "spec = importlib.util.spec_from_loader(loader.name, loader)\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(m)\n"
            "def boom(): raise KeyboardInterrupt\n"
            "m.preflight = boom\n"
            "sys.argv = ['orrery-up', '--yes']\n"
            "try:\n"
            "    sys.exit(m.main())\n"
            "except KeyboardInterrupt:\n"
            "    sys.exit(m.interrupted())\n",
            str(REPO / "orrery-up"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 130, proc.stderr
    assert "interrupted" in proc.stderr
    assert "./orrery-up again resumes" in proc.stderr and "down stops it" in proc.stderr


def test_the_entrypoint_routes_keyboard_interrupt_to_the_message():
    """The subprocess above stands in for the `__main__` block; this pins
    that the block itself routes KeyboardInterrupt the same way."""
    source = (REPO / "orrery-up").read_text(encoding="utf-8")
    entry = source[source.index('if __name__ == "__main__":') :]
    assert "except KeyboardInterrupt:" in entry
    assert "sys.exit(interrupted())" in entry
