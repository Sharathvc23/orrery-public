"""Which stores follow a pinned ``Config(home=...)``, and which do not.

``Config.__init__`` states both lists. A comment cannot be checked by running
it, so this module derives the import-time path bindings from the package and
pins each one as either following a per-instance home or resolving to the
process-global ``CONFIG_DIR``. A binding added later belongs to neither set and
fails ``test_every_import_time_path_binding_is_classified`` until someone
decides which it is.

The sweep asserts it finds the two bindings that motivated it. A detector that
silently stops matching reports "all deliberate", which is the same output as a
clean codebase.
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from community_member import skills
from community_member.config import Config

PKG = Path(skills.__file__).resolve().parent

# Names bound at import to a filesystem location. Kept as a set, not a count:
# a count is satisfied by one binding disappearing while another appears.
PINNED_TO_PROCESS_GLOBAL = {
    "CONFIG_DIR",  # config.py — the root itself, read from the env at import
    "KEYSTORE_DIR",  # keystore.py — a default; call sites pass dir=config._home
    "SKILLS_ROOT",
    "REGISTRY_PATH",
    "TRUST_FILE",
    "INBOX_PATH",
    "SECRETS_FILE",
}
# Resolved on use rather than bound at import, so they follow the agent home
# even when it is set after this package is first imported.
RESOLVED_ON_USE = {"TASK_STORE_PATH", "SETTINGS_CACHE"}
# Package data shipped with the code; correctly bound to the install location.
PACKAGE_DATA = {"SCHEMA_ROOT", "BUILTIN_SKILLS_DIR", "PACKS_DIR"}
# Matched by the detector but not filesystem locations. Recorded so the next
# reader does not re-investigate them.
NOT_A_LOCATION = {
    "_VALIDATORS",
    "OPEN_ROUTES",
    "DOMAIN_CHALLENGE_HTTP_PATH",
    "GRANTS_FILENAME",
    "BINDING_FILE",
    "EVENT_LEDGER_FILE",
    "_LOCAL_TRUST_FILENAME",
    "_CHAPTER_TRUST_FILENAME",
    "NANDA_DIRNAME",
    # llm_caps.py — a relative fragment joined at call time by
    # default_probe_path(), which walks parents looking for it. Nothing is
    # bound to a location at import, and the file it names is a checked-in
    # measurement rather than agent state, so a pinned home does not apply.
    "PROBE_RELATIVE_PATH",
}

PATHY = {"Path", "home", "expanduser", "gettempdir", "mkdtemp", "abspath", "realpath"}
FS_SUFFIX = (".db", ".json", ".policy", ".log", ".enc", ".jsonl", ".key", ".txt")


def _sweep() -> dict[str, str]:
    """{name: "file:line"} for every module-level binding of a path.

    Follows module-local helper calls one level — ``CONFIG_DIR`` is assigned
    from ``_resolve_config_dir()``, so an expression-only scan misses it — and
    iterates to a fixpoint, because ``SKILLS_ROOT = CONFIG_DIR / "skills"`` is a
    path only by virtue of a name found on an earlier pass.
    """
    known: set[str] = {"CONFIG_DIR", "KEYSTORE_DIR"}
    found: dict[str, str] = {}
    for _ in range(6):
        found = {}
        for f in sorted(PKG.rglob("*.py")):
            if "/tests/" in str(f):
                continue
            try:
                tree = ast.parse(f.read_text())
            except SyntaxError:
                continue
            funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}

            def pathish(node, depth=0, _funcs=funcs):
                for n in ast.walk(node):
                    if isinstance(n, ast.Name) and (n.id in PATHY or n.id in known):
                        return True
                    if isinstance(n, ast.Attribute) and n.attr in PATHY:
                        return True
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        v = n.value
                        if v.endswith(FS_SUFFIX) or v.startswith(("~", "/.")) or v in (".nanda", ".community-member"):
                            return True
                    if depth == 0 and isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                        if n.func.id in _funcs and pathish(_funcs[n.func.id], 1):
                            return True
                return False

            for node in tree.body:
                if not isinstance(node, ast.Assign | ast.AnnAssign):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if not names or node.value is None:
                    continue
                if isinstance(node.value, ast.Lambda) or "Callable" in ast.unparse(node.value):
                    continue
                if pathish(node.value):
                    found[names[0]] = f"{f.relative_to(PKG)}:{node.lineno}"
        if set(found) <= known:
            break
        known |= set(found)
    return found


# ── The detector finds what it already knows about ────────────────────


def test_the_sweep_finds_its_own_motivating_cases():
    """CONFIG_DIR hid behind a helper call; SKILLS_ROOT behind a directory name
    with no file suffix. Both were missed by earlier versions of this sweep,
    which reported a clean result."""
    found = _sweep()
    assert "CONFIG_DIR" in found, "sweep no longer finds CONFIG_DIR — it is unsound"
    assert "SKILLS_ROOT" in found, "sweep no longer finds SKILLS_ROOT — it is unsound"


def test_the_sweep_is_not_empty():
    assert _sweep(), "sweep matched nothing — every assertion below would be vacuous"


def test_every_import_time_path_binding_is_classified():
    """A binding added later must be placed in one of the three sets, so that
    deciding whether it should follow a pinned home is not optional."""
    classified = PINNED_TO_PROCESS_GLOBAL | PACKAGE_DATA | NOT_A_LOCATION | RESOLVED_ON_USE
    unclassified = sorted(set(_sweep()) - classified)
    assert not unclassified, (
        f"new import-time path binding(s) {unclassified}: decide whether each follows "
        f"Config(home=...) and add it to the matching set in this file"
    )


def test_the_classification_sets_do_not_overlap():
    sets = [PINNED_TO_PROCESS_GLOBAL, PACKAGE_DATA, NOT_A_LOCATION, RESOLVED_ON_USE]
    for i, a in enumerate(sets):
        for b in sets[i + 1 :]:
            assert not (a & b), f"a binding is in two classification sets: {sorted(a & b)}"


# ── The agent home is followed, and existing state is carried over ────


def test_the_task_log_and_settings_follow_the_agent_home(tmp_path, monkeypatch):
    """Both used the literal ~/.nanda, so every agent on a machine shared one
    task log no matter which home it was given."""
    from community_member import settings_sync, task_store

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))
    monkeypatch.setattr(task_store, "TASK_STORE_PATH", None)
    monkeypatch.setattr(settings_sync, "SETTINGS_CACHE", None)
    assert task_store.default_path().is_relative_to(tmp_path / "agent-home")
    assert settings_sync._cache_path().is_relative_to(tmp_path / "agent-home")


def test_a_constructed_task_store_lands_under_the_agent_home(tmp_path, monkeypatch):
    """The resolver being right is not enough — TaskStore must actually use it."""
    from community_member import task_store

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))
    monkeypatch.setattr(task_store, "TASK_STORE_PATH", None)
    assert task_store.TaskStore().path.is_relative_to(tmp_path / "agent-home")


def test_a_home_set_after_import_is_still_followed(tmp_path, monkeypatch):
    """The reason these resolve on use: an import-time binding is chosen before
    a test or embedding host has had the chance to set the variable."""
    from community_member import task_store

    monkeypatch.setattr(task_store, "TASK_STORE_PATH", None)
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "first"))
    assert task_store.default_path().is_relative_to(tmp_path / "first")
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "second"))
    assert task_store.default_path().is_relative_to(tmp_path / "second")


def test_a_legacy_task_log_is_carried_over_and_kept(tmp_path, monkeypatch):
    """Relocating a store that already holds data must not orphan it."""
    from community_member import agent_home

    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    legacy = tmp_path / "user" / ".nanda" / "tasks.jsonl"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"id":"t1"}\n')
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))

    resolved = agent_home.resolve("tasks.jsonl")
    assert resolved.read_text() == '{"id":"t1"}\n', "existing task log was orphaned"
    assert legacy.exists(), "the legacy file must stay as a backup"


def test_an_existing_new_file_is_never_overwritten_by_the_legacy_one(tmp_path, monkeypatch):
    from community_member import agent_home

    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    legacy = tmp_path / "user" / ".nanda" / "tasks.jsonl"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("stale\n")
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))
    current = tmp_path / "agent-home" / ".nanda" / "tasks.jsonl"
    current.parent.mkdir(parents=True)
    current.write_text("current\n")

    assert agent_home.resolve("tasks.jsonl").read_text() == "current\n"


def test_the_badge_keeps_the_location_it_already_had(tmp_path, monkeypatch):
    """conformance_badge already rooted .nanda under the agent home. This change
    must not move it."""
    from community_member import agent_home, conformance_badge

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))
    assert conformance_badge.badge_path() == agent_home.nanda_dir() / "conformance.json"


def test_the_outbox_follows_the_agent_home(tmp_path, monkeypatch):
    from community_member import outbox

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "agent-home"))
    monkeypatch.delenv("COMMUNITY_MEMBER_OUTBOX", raising=False)
    monkeypatch.setattr(outbox, "_OUTBOX_PATH", None)
    assert outbox._path().is_relative_to(tmp_path / "agent-home")


# ── What a pinned home actually covers ────────────────────────────────


@pytest.fixture
def pinned(tmp_path):
    return Config(home=tmp_path / "tenant")


@pytest.mark.parametrize("filename", ["config.json", "agent.json", "memory.json", "consent.db"])
def test_config_owned_stores_follow_the_pinned_home(pinned, filename, tmp_path):
    assert (pinned.home / filename).is_relative_to(tmp_path / "tenant")


def test_the_consent_ledger_is_opened_under_the_pinned_home():
    """agent.py initialised the ledger from the module-global CONFIG_DIR while
    reading grants from self.config.home, thirty lines apart in one file."""
    src = (PKG / "agent.py").read_text()
    assert 'CONFIG_DIR / "consent.db"' not in src, "the consent ledger is opened from the process-global home"
    # Three: the two ledger init call sites, plus the skip watermark, which reads
    # how far this agent's consent ledger has advanced. The count is here to stop
    # a call site drifting back to CONFIG_DIR unnoticed, so a new reader raises it
    # deliberately — the invariant is the line above, and it is unchanged.
    assert src.count('self.config.home / "consent.db"') == 3


def test_the_keystore_is_read_under_the_pinned_home():
    """Both ledger call sites load the signing key; neither passed dir=."""
    src = (PKG / "agent.py").read_text()
    bare = [
        line.strip()
        for line in src.splitlines()
        if "keystore.load_private_key(" in line and "dir=" not in line and "def " not in line
    ]
    assert not bare, f"keystore read without a per-instance dir: {bare}"


# ── The registry belongs to the root it indexes ───────────────────────


def test_a_pinned_skills_root_keeps_its_own_registry(tmp_path):
    a = tmp_path / "a" / "skills"
    a.mkdir(parents=True)
    skills.save_installed_registry({"weather@1.0.0": {"path": str(a / "weather")}}, a)
    assert (a / "registry.json").exists(), "the registry did not land under the root it indexes"
    assert skills.load_installed_registry(a) != {}


def test_one_tenant_cannot_deregister_anothers_skill(tmp_path, monkeypatch):
    """Reproduction: with a shared registry, tenant B's uninstall removed the
    entry tenant A had installed, and reported success.

    The entry is planted in the process-global registry as well. Without that,
    an unthreaded uninstall reads an EMPTY global registry and raises
    "not installed" — the same exception a correct implementation raises, so
    the test would pass either way.
    """
    a = tmp_path / "a" / "skills"
    b = tmp_path / "b" / "skills"
    shared = tmp_path / "shared" / "skills"
    for d in (a, b, shared):
        d.mkdir(parents=True)
    (a / "weather").mkdir()
    entry = {"weather@1.0.0": {"path": str(a / "weather")}}
    monkeypatch.setattr(skills, "SKILLS_ROOT", shared)
    monkeypatch.setattr(skills, "REGISTRY_PATH", shared / "registry.json")
    skills.save_installed_registry(dict(entry), a)
    skills.save_installed_registry(dict(entry), None)  # the shared registry
    assert skills.load_installed_registry(None), "the shared registry must be non-empty for this to prove anything"

    with pytest.raises(ValueError, match="not installed"):
        skills.uninstall_skill("weather@1.0.0", skills_root=b, hard_delete=True)

    assert "weather@1.0.0" in skills.load_installed_registry(a), "tenant A's entry was removed by tenant B"
    assert "weather@1.0.0" in skills.load_installed_registry(None), (
        "the shared registry was mutated by a pinned uninstall"
    )
    assert (a / "weather").exists()


def test_an_unpinned_registry_still_uses_the_process_global_root():
    """The default path is unchanged, so single-agent behaviour is untouched."""
    assert skills._registry_path(None) == skills.REGISTRY_PATH
    assert skills._registry_path(Path(tempfile.gettempdir()) / "x") != skills.REGISTRY_PATH
