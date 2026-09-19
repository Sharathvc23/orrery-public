"""A database volume that outlives its `.env` is refused by name, not waited on.

Postgres initialises its data directory once, with the POSTGRES_PASSWORD it
was first started with, and authenticates every later start against that
directory. Delete `.env` with the volume kept and re-run: the installer wrote
a fresh `.env` with a fresh password, re-allocated ports (renaming the org),
and `db-ready` looped "waiting for db to finish initializing…" with no bound
and no cause, while `docker compose up` waited on it. Killed after ten
minutes by the person who found it.

Two halves, pinned here offline (the doc-guards job) and driven live in the
installer job:

  * the installer refuses to write a fresh `.env` while this project's
    database volume exists, naming the volume and both fixes;
  * `db-ready` is bounded, and on the bound it prints the probe's own error
    and what to do about it;
  * `./orrery-up down --purge` — the stated "start over" fix — works with no
    `.env`, which Compose's `${VAR:?}` variables otherwise prevent.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_installer():
    spec = importlib.util.spec_from_loader(
        "orrery_up_kept_volume",
        importlib.machinery.SourceFileLoader(
            "orrery_up_kept_volume", str(REPO / "orrery-up")
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
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    return module


# ── the refusal ────────────────────────────────────────────────────────────


def test_no_env_and_a_kept_db_volume_is_refused_by_name(installer, monkeypatch, capsys):
    """THE DEFECT. No .env, the project's db volume exists: refuse before
    writing anything, and say which volume, why, and both ways out."""
    monkeypatch.setattr(
        installer, "db_volumes_of", lambda project: [f"{project}_db-data"]
    )
    assert not installer.ENV_PATH.exists()

    with pytest.raises(SystemExit) as ex:
        installer.refuse_orphaned_db_volume()

    assert ex.value.code == 1
    err = capsys.readouterr().err
    assert f"{installer.compose_project_name()}_db-data" in err, (
        "the refusal must name the volume"
    )
    assert "POSTGRES_PASSWORD" in err, "the refusal must name the disagreement"
    assert "restore the .env" in err, "the keep-your-data fix must be stated"
    assert "down --purge" in err, "the start-over fix must be stated"
    assert not installer.ENV_PATH.exists(), "a refused run must not have written .env"


def test_a_present_env_is_never_refused_and_never_asks_docker(installer, monkeypatch):
    """The check is about a MISSING .env. With one present, the volume is
    the one that .env's password initialised (or db-ready will say
    otherwise), and docker is not even consulted."""
    installer.ENV_PATH.write_text("POSTGRES_PASSWORD=whatever\n")

    def never(*_a, **_k):
        raise AssertionError("docker was consulted although .env exists")

    monkeypatch.setattr(installer, "_run", never)
    installer.refuse_orphaned_db_volume()  # returns, no exit


def test_no_env_and_no_volume_is_a_first_install(installer, monkeypatch):
    monkeypatch.setattr(installer, "db_volumes_of", lambda project: [])
    installer.refuse_orphaned_db_volume()  # returns, no exit


def test_the_volume_lookup_asks_by_compose_labels(installer, monkeypatch):
    """Found by the labels Compose writes, not by a guessed name, and scoped
    to THIS project — a sibling checkout's volume is not this install's."""
    seen = {}

    def fake_run(cmd, **_k):
        seen["cmd"] = cmd
        return SimpleNamespace(stdout="proj_db-data\n", returncode=0)

    monkeypatch.setattr(installer, "_run", fake_run)
    assert installer.db_volumes_of("proj") == ["proj_db-data"]
    assert "label=com.docker.compose.project=proj" in seen["cmd"]
    assert "label=com.docker.compose.volume=db-data" in seen["cmd"]


@pytest.mark.parametrize(
    ("basename", "expected"),
    [
        ("orrery", "orrery"),
        ("checkout-2", "checkout-2"),
        ("Orrery Checkout.v2", "orrerycheckoutv2"),
        ("_leading", "leading"),
    ],
)
def test_the_project_name_is_derived_the_way_compose_derives_it(
    installer, monkeypatch, tmp_path, basename, expected
):
    monkeypatch.setattr(installer, "REPO", tmp_path / basename)
    assert installer.compose_project_name() == expected


def test_compose_project_name_honours_the_override(installer, monkeypatch):
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "named-by-operator")
    assert installer.compose_project_name() == "named-by-operator"


def test_the_refusal_runs_before_env_is_written_on_up_and_e2e(installer):
    """Placement is the property: after preflight and before anything that
    writes .env — the interactive prompt, resolve_ports, settle_env."""
    source = (REPO / "orrery-up").read_text(encoding="utf-8")
    main = source[source.index("def main()") :]
    for command in ('if args.command == "e2e":', "# up\n"):
        block = main[main.index(command) :]
        assert block.index("refuse_orphaned_db_volume()") < block.index(
            "settle_env("
        ), command
        assert block.index("preflight()") < block.index(
            "refuse_orphaned_db_volume()"
        ), command


# ── the stated fix works without .env ──────────────────────────────────────


def _required_at_interpolation() -> set[str]:
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    return set(re.findall(r"\$\{([A-Z_]+):\?", text))


def test_down_without_env_supplies_every_variable_compose_requires(
    installer, monkeypatch
):
    """`down --purge` is the fix the refusal names, so it must run with no
    .env. Compose refuses to evaluate the project without its `${VAR:?}`
    variables; `compose("down")` supplies placeholders for exactly that set,
    read here out of docker-compose.yml so a new required variable cannot
    strand the teardown."""
    seen = {}

    def fake_run(cmd, cwd=None, env=None):
        seen["cmd"], seen["env"] = cmd, env
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    assert not installer.ENV_PATH.exists()

    installer.compose("down", "-v")

    required = _required_at_interpolation()
    assert required, (
        "docker-compose.yml no longer marks any variable required — update this test"
    )
    assert set(installer.COMPOSE_REQUIRED_VARS) == required
    assert seen["env"] is not None and all(seen["env"].get(k) for k in required)


def test_up_never_gets_placeholders(installer, monkeypatch):
    """Only `down`. An `up` with placeholders would initialise a database
    with a password nobody holds."""
    seen = {}

    def fake_run(cmd, cwd=None, env=None):
        seen["env"] = env
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer.compose("up", "-d")
    assert seen["env"] is None


# ── db-ready is bounded and names its cause ────────────────────────────────


def _db_ready_command() -> str:
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    start = text.index("\n  db-ready:")
    end = text.index("\n  server:", start)
    return text[start:end]


def test_db_ready_is_bounded():
    """The wait must end. Unbounded, a password disagreement was an infinite
    'waiting for db to finish initializing…' with `up` blocked behind it."""
    block = _db_ready_command()
    assert "DB_READY_TIMEOUT_SECONDS" in block
    assert re.search(r"-ge\s+\"\$\$\{DB_READY_TIMEOUT_SECONDS\}\"", block), (
        "no comparison against the bound"
    )
    assert "exit 1" in block, (
        "reaching the bound must fail the gate, so `up` fails instead of waiting"
    )
    assert 'restart: "no"' in block


def test_db_ready_names_the_cause_when_it_gives_up():
    block = _db_ready_command()
    assert "Last probe said" in block, (
        "the probe's own error must be printed on the bound"
    )
    assert "password authentication failed" in block
    assert "restore the .env" in block and "down --purge" in block


def test_db_ready_bound_is_generous_enough_for_a_first_initialisation():
    """The db healthcheck allows 180s of start_period for the schema load;
    the gate must not give up before a genuine first init can finish."""
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    default = int(re.search(r"DB_READY_TIMEOUT_SECONDS:-(\d+)", text).group(1))
    start_period = int(re.search(r"start_period:\s*(\d+)s", text).group(1))
    assert default > start_period
