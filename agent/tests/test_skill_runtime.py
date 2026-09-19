"""
Prosecution-grade tests for community_member.skill_runtime — dynamic
skill loading + capability-gated invocation.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from community_member import skill_runtime as sr
from community_member import skills as sk

# ─── Fixtures: an on-disk "installed skill" ────────────


def _install_fake_skill(
    skills_root: Path,
    skill_id: str = "file-ops@1.0.0",
    capabilities: list[str] | None = None,
    skill_py: str | None = None,
    include_skill_py: bool = True,
) -> dict:
    """Write a skill's files + registry entry so skill_runtime can load it."""
    safe_id = skill_id.replace("/", "_").replace("@", "_at_")
    skill_dir = skills_root / safe_id
    skill_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "name": skill_id.split("@")[0],
        "version": skill_id.split("@")[1],
        "capabilities": capabilities or ["fs.read"],
    }
    (skill_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")

    if include_skill_py:
        default_src = skill_py or (
            "def _read(args):\n"
            '    return {"ok": True, "echo": args.get("text", "")}\n'
            "\n"
            "TOOLS = [\n"
            '    {"name": "read", "description": "echo", "parameters": {"text": "string"}, "fn": _read},\n'
            "]\n"
        )
        (skill_dir / "skill.py").write_text(default_src)

    entry = {
        "skill_id": skill_id,
        "installed_version": manifest["version"],
        "install_proof": "a" * 64,
        "signing_key_did": "did:key:ztest",
        "content_sha256": "b" * 64,
        "capabilities": manifest["capabilities"],
        "path": str(skill_dir),
        "manifest": manifest,
        "is_tarball": False,
    }
    registry = sk.load_installed_registry()
    registry[skill_id] = entry
    sk.save_installed_registry(registry)
    return entry


@pytest.fixture
def tmp_skills_root(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    monkeypatch.setattr(sk, "SKILLS_ROOT", root)
    monkeypatch.setattr(sk, "REGISTRY_PATH", root / "registry.json")
    return root


# ═══════════════════════════════════════════════════════════════
# load_installed_skills
# ═══════════════════════════════════════════════════════════════


def test_load_skills_from_registry(tmp_skills_root):
    _install_fake_skill(tmp_skills_root)
    loaded = sr.load_installed_skills()
    assert len(loaded) == 1
    assert loaded[0].skill_id == "file-ops@1.0.0"
    assert "read" in loaded[0].tools
    assert loaded[0].tool_specs["read"]["description"] == "echo"


def test_load_skills_without_skill_py(tmp_skills_root):
    """EDGE: manifest-only skill installs without skill.py → loaded with no tools."""
    _install_fake_skill(tmp_skills_root, include_skill_py=False)
    loaded = sr.load_installed_skills()
    assert len(loaded) == 1
    assert loaded[0].tools == {}


def test_load_skills_survives_import_failure(tmp_skills_root):
    """EDGE: skill.py raises on import — agent must not crash."""
    bad_py = "raise RuntimeError('boom at import time')\n"
    _install_fake_skill(tmp_skills_root, skill_py=bad_py)
    loaded = sr.load_installed_skills()
    # The entry is still present but has no tools.
    assert len(loaded) == 1
    assert loaded[0].tools == {}


def test_load_skills_survives_missing_tools_list(tmp_skills_root):
    """EDGE: skill.py has no TOOLS attribute — loaded with zero tools, not crashed."""
    src = "def _inner(args): return args\n"
    _install_fake_skill(tmp_skills_root, skill_py=src)
    loaded = sr.load_installed_skills()
    assert loaded[0].tools == {}


def test_load_skills_rejects_malformed_tool_entries(tmp_skills_root):
    """ADVERSARIAL: skill declares TOOLS entries with bad types — skip them silently."""
    src = (
        "TOOLS = [\n"
        "    'not a dict',\n"
        "    {'name': 'missing_fn'},\n"
        "    {'fn': lambda a: 1, 'name': 123},\n"  # non-string name
        "]\n"
    )
    _install_fake_skill(tmp_skills_root, skill_py=src)
    loaded = sr.load_installed_skills()
    assert loaded[0].tools == {}


def test_load_skills_skips_missing_disk_path(tmp_skills_root):
    """EDGE: registry entry points to a deleted dir → skip (don't crash)."""
    _install_fake_skill(tmp_skills_root)
    # Delete the disk dir the registry points at.
    import shutil

    for skill_dir in tmp_skills_root.iterdir():
        if skill_dir.is_dir():
            shutil.rmtree(skill_dir)
    loaded = sr.load_installed_skills()
    assert loaded == []


# ═══════════════════════════════════════════════════════════════
# invoke_tool
# ═══════════════════════════════════════════════════════════════


def test_invoke_happy(tmp_skills_root):
    _install_fake_skill(tmp_skills_root, capabilities=["fs.read"])
    loaded = sr.load_installed_skills()
    result = sr.invoke_tool(
        loaded,
        "file-ops@1.0.0",
        "read",
        {"text": "hi"},
        user_grants={"file-ops@1.0.0": {"fs.read"}},
    )
    assert result == {"ok": True, "echo": "hi"}


def test_invoke_unknown_skill_raises(tmp_skills_root):
    loaded = sr.load_installed_skills()
    with pytest.raises(sr.ToolNotFound, match="not installed"):
        sr.invoke_tool(loaded, "ghost@1.0.0", "read", {}, user_grants={})


def test_invoke_unknown_tool_raises(tmp_skills_root):
    _install_fake_skill(tmp_skills_root, capabilities=["fs.read"])
    loaded = sr.load_installed_skills()
    with pytest.raises(sr.ToolNotFound, match="has no tool"):
        sr.invoke_tool(
            loaded,
            "file-ops@1.0.0",
            "does_not_exist",
            {},
            user_grants={"file-ops@1.0.0": {"fs.read"}},
        )


def test_invoke_refuses_ungranted_capability(tmp_skills_root):
    """ADVERSARIAL: skill declared fs.write but user only granted fs.read."""
    _install_fake_skill(tmp_skills_root, capabilities=["fs.read", "fs.write"])
    loaded = sr.load_installed_skills()
    with pytest.raises(sr.CapabilityDenied, match="fs.write"):
        sr.invoke_tool(
            loaded,
            "file-ops@1.0.0",
            "read",
            {},
            user_grants={"file-ops@1.0.0": {"fs.read"}},  # missing fs.write
        )


def test_invoke_refuses_empty_grants(tmp_skills_root):
    """ADVERSARIAL: user_grants dict is missing → treat as empty set → refuse."""
    _install_fake_skill(tmp_skills_root, capabilities=["fs.read"])
    loaded = sr.load_installed_skills()
    with pytest.raises(sr.CapabilityDenied):
        sr.invoke_tool(loaded, "file-ops@1.0.0", "read", {}, user_grants=None)
    with pytest.raises(sr.CapabilityDenied):
        sr.invoke_tool(loaded, "file-ops@1.0.0", "read", {}, user_grants={})


def test_invoke_high_risk_requires_per_invocation_consent(tmp_skills_root):
    """ADVERSARIAL: shell.exec never runs without fresh consent, even if granted."""
    src = (
        "def _shell(args):\n"
        '    return {"ok": True}\n'
        "TOOLS = [{'name': 'exec', 'description': 'run shell', 'parameters': {}, 'fn': _shell}]\n"
    )
    _install_fake_skill(
        tmp_skills_root,
        skill_id="shell@1.0.0",
        capabilities=["shell.exec"],
        skill_py=src,
    )
    loaded = sr.load_installed_skills()

    # Even with the capability granted, per-invocation consent is needed.
    with pytest.raises(sr.ConsentRequired, match="per-invocation consent"):
        sr.invoke_tool(
            loaded,
            "shell@1.0.0",
            "exec",
            {},
            user_grants={"shell@1.0.0": {"shell.exec"}},
            consent_per_invocation=False,
        )

    # With per-invocation consent, it proceeds.
    result = sr.invoke_tool(
        loaded,
        "shell@1.0.0",
        "exec",
        {},
        user_grants={"shell@1.0.0": {"shell.exec"}},
        consent_per_invocation=True,
    )
    assert result == {"ok": True}


def test_invoke_tool_exception_becomes_toolerror(tmp_skills_root):
    """HAPPY (defensive): skill raises → agent gets ToolError, not a crash."""
    src = (
        "def _broken(args):\n"
        "    raise ValueError('deliberate')\n"
        "TOOLS = [{'name': 'broken', 'description': 'raises', 'parameters': {}, 'fn': _broken}]\n"
    )
    _install_fake_skill(tmp_skills_root, capabilities=["fs.read"], skill_py=src)
    loaded = sr.load_installed_skills()
    with pytest.raises(sr.ToolError, match="deliberate"):
        sr.invoke_tool(
            loaded,
            "file-ops@1.0.0",
            "broken",
            {},
            user_grants={"file-ops@1.0.0": {"fs.read"}},
        )


# ═══════════════════════════════════════════════════════════════
# agent_tool_specs + unload_skill
# ═══════════════════════════════════════════════════════════════


def test_agent_tool_specs_namespaces_tool_names(tmp_skills_root):
    """HAPPY: two skills with the same tool name get distinct agent-facing names."""
    _install_fake_skill(tmp_skills_root, skill_id="file-ops@1.0.0", capabilities=["fs.read"])
    _install_fake_skill(tmp_skills_root, skill_id="sqlite@1.0.0", capabilities=["fs.read"])

    loaded = sr.load_installed_skills()
    specs = sr.agent_tool_specs(loaded)
    names = [s["name"] for s in specs]

    assert all(n.startswith("skill__") for n in names)
    # Distinct namespaces prevent collision.
    assert len(set(names)) == len(names)
    # The _skill_id + _tool_name metadata preserves the origin.
    assert all("_skill_id" in s and "_tool_name" in s for s in specs)


def test_agent_tool_specs_handles_empty_load():
    assert sr.agent_tool_specs([]) == []


def test_unload_skill_removes_from_list(tmp_skills_root):
    _install_fake_skill(tmp_skills_root, skill_id="file-ops@1.0.0")
    _install_fake_skill(tmp_skills_root, skill_id="sqlite@1.0.0")
    loaded = sr.load_installed_skills()
    assert len(loaded) == 2

    remaining = sr.unload_skill(loaded, "file-ops@1.0.0")
    assert len(remaining) == 1
    assert remaining[0].skill_id == "sqlite@1.0.0"


def test_unload_unknown_skill_is_noop(tmp_skills_root):
    _install_fake_skill(tmp_skills_root)
    loaded = sr.load_installed_skills()
    remaining = sr.unload_skill(loaded, "ghost@1.0.0")
    assert len(remaining) == len(loaded)
