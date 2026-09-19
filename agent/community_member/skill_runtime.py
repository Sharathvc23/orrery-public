"""
Dynamic skill runtime — load installed .nandaskill packages and expose
their tools to the agent's LLM.

Loaded skills live in their own Python module namespace (no subprocess
isolation in W11 MVP — that's a separate hardening sprint). Capability
enforcement happens at tool-invocation time: the skill declares what it
needs in `manifest.json.capabilities`; when the agent calls a tool the
skill exported, we re-check that those capabilities were granted by the
user.

Public API
----------
load_installed_skills(user_grants) → list[LoadedSkill]
    Read ~/.community-member/skills/registry.json + dynamically import each
    skill.py; register its TOOLS. user_grants is a dict mapping
    skill_id → set[capability] of what the user said yes to.

invoke_tool(skill_id, tool_name, args, user_grants) → Any
    Capability-gated dispatch. Refuses if the skill's declared
    capabilities aren't covered by user_grants.

unload_skill(skill_id) → None
    Remove from the loaded set; future invoke_tool calls fail.

agent_tool_specs(loaded) → list[dict]
    Build the OpenAI-style tool schemas the LLM sees. The tool name
    is prefixed `skill__<skill_id>__<tool_name>` to avoid collisions.

Safety rails
------------
- HIGH_RISK_CAPABILITIES (shell.exec / net.arbitrary / fs.any /
  eval.code) require per-invocation consent — the caller must pass
  `consent_per_invocation=True` AND the user's consent must be
  fresh (we return a sentinel requiring re-approval). MVP throws
  ConsentRequired and lets the agent ask the user.
- Skill-side exceptions are caught + surfaced as clean ToolError
  results; they never crash the agent's turn loop.
- Unknown tool names raise ToolNotFound (not a silent no-op).
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from community_member import skills as _skills
from community_member.config import CONFIG_DIR

_log = logging.getLogger(__name__)

HIGH_RISK_CAPABILITIES = _skills.HIGH_RISK_CAPABILITIES

# Tool name separator to namespace skills.
TOOL_PREFIX = "skill__"
TOOL_SEP = "__"


# ── Errors ────────────────────────────────────────────────


class ToolError(Exception):
    """Tool invocation failed cleanly — reported to the LLM, not fatal."""


class ToolNotFound(ToolError):
    """Named tool does not exist on the requested skill."""


class CapabilityDenied(ToolError):
    """The skill declared a capability the user has not granted."""


class ConsentRequired(ToolError):
    """High-risk capability needs fresh per-invocation consent."""


# ── Data ─────────────────────────────────────────────────


@dataclass
class LoadedSkill:
    skill_id: str
    name: str
    version: str
    declared_capabilities: list[str]
    tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    tool_specs: dict[str, dict] = field(default_factory=dict)  # name → {description, parameters}
    module_name: str = ""


# ── Load pipeline ────────────────────────────────────────


def _load_skill_module(skill_id: str, skill_dir: Path) -> Any | None:
    """Import skill.py from a skill's install dir under a namespaced module name.

    Returns the imported module, or None if no skill.py present / import fails.
    """
    skill_py = skill_dir / "skill.py"
    if not skill_py.exists():
        _log.info("skill %s has no skill.py — metadata-only install", skill_id)
        return None

    module_name = f"nanda_skill__{skill_id.replace('@', '_at_').replace('-', '_').replace('.', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, str(skill_py))
    if spec is None or spec.loader is None:
        _log.warning("could not create import spec for %s", skill_id)
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except Exception as exc:
        _log.warning("skill %s failed to import: %s", skill_id, exc)
        sys.modules.pop(module_name, None)
        return None

    return module


def _extract_tools(module: Any) -> tuple[dict[str, Callable], dict[str, dict]]:
    """A skill exports its tools via a `TOOLS` list of {name, description,
    parameters, fn} dicts. Returns ({name: fn}, {name: spec}).

    Skills without a TOOLS attribute produce empty dicts — they may still
    be useful as metadata-only entries.
    """
    tools_decl = getattr(module, "TOOLS", None)
    if not isinstance(tools_decl, list):
        return {}, {}

    fns: dict[str, Callable] = {}
    specs: dict[str, dict] = {}
    for entry in tools_decl:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        fn = entry.get("fn")
        if not isinstance(name, str) or not callable(fn):
            continue
        fns[name] = fn
        specs[name] = {
            "description": str(entry.get("description", ""))[:500],
            "parameters": entry.get("parameters") or {},
        }
    return fns, specs


def load_installed_skills() -> list[LoadedSkill]:
    """Walk the registry, dynamically import each skill, return the set."""
    loaded: list[LoadedSkill] = []
    registry = _skills.load_installed_registry()

    for skill_id, entry in registry.items():
        path = Path(entry.get("path", ""))
        if not path.exists():
            _log.warning("skill %s disk path missing: %s", skill_id, path)
            continue

        module = _load_skill_module(skill_id, path)
        fns, specs = _extract_tools(module) if module else ({}, {})
        manifest = entry.get("manifest", {})

        loaded.append(
            LoadedSkill(
                skill_id=skill_id,
                name=manifest.get("name", skill_id.split("@")[0]),
                version=manifest.get("version", skill_id.split("@")[-1]),
                declared_capabilities=list(entry.get("capabilities", [])),
                tools=fns,
                tool_specs=specs,
                module_name=module.__name__ if module is not None else "",
            )
        )

    return loaded


# First-party skills shipped inside the package — always available, no
# registry entry and no signature. The agent auto-grants their declared
# capabilities since the user implicitly trusts code that ships with the
# runtime. Which of them are ACTIVE is decided by skill PACKS (below).
BUILTIN_SKILLS_DIR = Path(__file__).parent / "builtin_skills"
PACKS_DIR = Path(__file__).parent / "packs"


def _load_one_builtin_skill(skill_dir: Path) -> LoadedSkill | None:
    """Load a single ``builtin_skills/<dir>`` (with skill.py + manifest.json)."""
    if not skill_dir.is_dir() or not (skill_dir / "skill.py").exists():
        return None

    manifest: dict = {}
    manifest_path = skill_dir / "manifest.json"
    if manifest_path.exists():
        try:
            import json

            manifest = json.loads(manifest_path.read_text())
        except Exception as exc:
            _log.warning("builtin skill %s has unreadable manifest: %s", skill_dir.name, exc)
            manifest = {}

    name = manifest.get("name", skill_dir.name)
    version = str(manifest.get("version", "1.0.0"))
    skill_id = f"{name}@{version}"
    module = _load_skill_module(skill_id, skill_dir)
    fns, specs = _extract_tools(module) if module else ({}, {})
    return LoadedSkill(
        skill_id=skill_id,
        name=name,
        version=version,
        declared_capabilities=list(manifest.get("capabilities", [])),
        tools=fns,
        tool_specs=specs,
        module_name=module.__name__ if module is not None else "",
    )


# ── Skill packs ──────────────────────────────────────────


def load_pack_manifests() -> dict[str, dict]:
    """Read every bundled pack manifest (``packs/<id>.json``) → {id: manifest}."""
    out: dict[str, dict] = {}
    if not PACKS_DIR.is_dir():
        return out
    import json

    for path in sorted(PACKS_DIR.glob("*.json")):
        try:
            m = json.loads(path.read_text())
        except Exception as exc:
            _log.warning("pack %s unreadable: %s", path.name, exc)
            continue
        pid = m.get("id") or path.stem
        m.setdefault("id", pid)
        out[pid] = m
    return out


def _packs_registry_path() -> Path:
    return CONFIG_DIR / "packs.json"


def installed_pack_ids() -> set[str]:
    """Pack ids the user has EXPLICITLY installed (persisted in packs.json)."""
    p = _packs_registry_path()
    if not p.exists():
        return set()
    try:
        import json

        data = json.loads(p.read_text())
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def active_pack_ids() -> set[str]:
    """Packs whose skills are active = default_installed packs ∪ installed."""
    manifests = load_pack_manifests()
    active = {pid for pid, m in manifests.items() if m.get("default_installed")}
    active |= installed_pack_ids() & set(manifests)
    return active


def set_pack_installed(pack_id: str, installed: bool) -> None:
    """Persist a pack's installed state to packs.json (default packs ignore
    uninstall — they're always active)."""
    import json

    current = installed_pack_ids()
    if installed:
        current.add(pack_id)
    else:
        current.discard(pack_id)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _packs_registry_path().write_text(json.dumps(sorted(current), indent=2))


def active_pack_skill_dirs() -> set[str]:
    """The set of skill DIR names belonging to the currently-active packs."""
    manifests = load_pack_manifests()
    dirs: set[str] = set()
    for pid in active_pack_ids():
        dirs.update(manifests.get(pid, {}).get("skills", []))
    return dirs


def load_active_pack_skills() -> list[LoadedSkill]:
    """Load the built-in skills belonging to the currently-active packs.

    This is the first-party skill set the agent exposes. A pack that isn't
    active (an un-installed opt-in pack) contributes nothing; installing it
    (``set_pack_installed``) + reloading makes its skills appear.
    """
    if not BUILTIN_SKILLS_DIR.is_dir():
        return []
    wanted = active_pack_skill_dirs()
    loaded: list[LoadedSkill] = []
    for skill_dir in sorted(BUILTIN_SKILLS_DIR.iterdir()):
        if skill_dir.name not in wanted:
            continue
        skill = _load_one_builtin_skill(skill_dir)
        if skill is not None:
            loaded.append(skill)
    return loaded


def load_builtin_skills() -> list[LoadedSkill]:
    """Back-compat alias: the active-pack skills are the built-in set the agent
    auto-grants. Kept because tests + the think_v2 catalog call it."""
    return load_active_pack_skills()


def skill_summary(skill_dir: str) -> dict:
    """Lightweight {name, description, capabilities} for a built-in skill dir,
    read from its manifest.json WITHOUT executing skill.py — for listing packs
    in the UI without importing every skill module."""
    import json

    mp = BUILTIN_SKILLS_DIR / skill_dir / "manifest.json"
    name, description, caps = skill_dir, "", []
    if mp.exists():
        try:
            m = json.loads(mp.read_text())
            name = m.get("name", skill_dir)
            description = m.get("description", "")
            caps = list(m.get("capabilities", []))
        except Exception:
            pass
    return {"name": name, "description": description, "capabilities": caps}


def list_packs_for_ui() -> list[dict]:
    """Every pack with its skills + installed/default flags, for the UI."""
    manifests = load_pack_manifests()
    active = active_pack_ids()
    installed = installed_pack_ids()
    out: list[dict] = []
    for pid, m in sorted(manifests.items()):
        is_default = bool(m.get("default_installed"))
        out.append(
            {
                "id": pid,
                "name": m.get("name", pid),
                "description": m.get("description", ""),
                "default": is_default,
                "installed": pid in active,
                # default packs are always-on; only explicitly-installed
                # non-default packs can be removed.
                "can_uninstall": (pid in installed) and not is_default,
                "skills": [skill_summary(s) for s in m.get("skills", [])],
            }
        )
    return out


# ── Invocation ───────────────────────────────────────────


def invoke_tool(
    loaded: list[LoadedSkill],
    skill_id: str,
    tool_name: str,
    args: dict,
    user_grants: dict[str, set[str]] | None = None,
    consent_per_invocation: bool = False,
    *,
    chapter_url: str | None = None,
    revocation_fetcher=None,
) -> Any:
    """Dispatch a tool call on a loaded skill.

    user_grants maps skill_id → set of capabilities the user approved
    at install time.

    Raises ToolNotFound / CapabilityDenied / ConsentRequired / ToolError.
    The agent's turn loop catches these and translates to tool-result
    messages for the LLM.
    """
    skill = next((s for s in loaded if s.skill_id == skill_id), None)
    if skill is None:
        raise ToolNotFound(f"skill {skill_id!r} not installed")

    if tool_name not in skill.tools:
        raise ToolNotFound(f"skill {skill_id!r} has no tool {tool_name!r}")

    grants = (user_grants or {}).get(skill_id, set())
    ungranted = [c for c in skill.declared_capabilities if c not in grants]
    if ungranted:
        raise CapabilityDenied(f"skill {skill_id!r} needs {ungranted} — not granted by user at install time")

    high_risk = [c for c in skill.declared_capabilities if c in HIGH_RISK_CAPABILITIES]
    if high_risk and not consent_per_invocation:
        raise ConsentRequired(f"skill {skill_id!r} uses high-risk {high_risk} — needs per-invocation consent")

    # Revocation freshness: re-check with the server before running
    # any high-risk tool. 24h cache + fail-closed when offline too
    # long. Low-risk skills skip this check — install-time verification
    # is sufficient since they can't do damage worth yanking urgently.
    if high_risk and chapter_url:
        from community_member import revocation as _revocation

        try:
            _revocation.check_fresh(chapter_url, skill_id, fetcher=revocation_fetcher)
        except _revocation.RevocationCheckFailed as e:
            # Translate to ToolError so the agent's turn loop sees a
            # uniform exception shape, but keep the reason string so
            # callers + audit can distinguish stale from revoked.
            raise ToolError(f"revocation_check_failed: {e.reason}: {e}") from e

    try:
        return skill.tools[tool_name](args or {})
    except Exception as exc:
        # Skills must never take down the turn loop.
        raise ToolError(f"skill {skill_id!r} tool {tool_name!r} raised: {type(exc).__name__}: {exc}") from exc


# ── Agent-tool spec generation ───────────────────────────


def agent_tool_specs(loaded: list[LoadedSkill]) -> list[dict]:
    """Flatten the loaded skills into the tool schema list the LLM sees.

    Tool names are namespaced `skill__<skill_id>__<tool_name>` so two
    skills can each export a `read` tool without colliding.
    """
    out: list[dict] = []
    for skill in loaded:
        for tname, spec in skill.tool_specs.items():
            safe_id = skill.skill_id.replace("@", "_at_").replace(".", "_")
            full_name = f"{TOOL_PREFIX}{safe_id}{TOOL_SEP}{tname}"
            out.append(
                {
                    "name": full_name,
                    "description": spec.get("description") or f"{skill.name}: {tname}",
                    "parameters": spec.get("parameters") or {},
                    "_skill_id": skill.skill_id,
                    "_tool_name": tname,
                }
            )
    return out


def unload_skill(loaded: list[LoadedSkill], skill_id: str) -> list[LoadedSkill]:
    """Remove a skill from the loaded list. Also purges its module from sys.modules."""
    remaining: list[LoadedSkill] = []
    for skill in loaded:
        if skill.skill_id != skill_id:
            remaining.append(skill)
            continue
        if skill.module_name:
            sys.modules.pop(skill.module_name, None)
    return remaining
