"""Gate every shipped JSON Schema + the skill manifest instance.

Before this, ``schema/**`` had no CI: the 19 schemas could become
malformed, and ``schema/0.3|0.4`` were only hand-mirrored in code
comments (drift risk). The skill bundle also shipped no manifest
*instance* validated against its schema. These tests close all three.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from conformance.tests.conftest import REPO_ROOT, SCHEMA_ROOT, _load_json

ALL_SCHEMAS = sorted(SCHEMA_ROOT.rglob("*.json"))


def _registry_for(directory: Path) -> Registry:
    """Build a referencing Registry from every schema in a directory, keyed
    by its ``$id`` so relative ``$ref``s (e.g. ``common.schema.json``)
    resolve against the sibling schemas."""
    resources = []
    for path in sorted(directory.glob("*.json")):
        doc = _load_json(path)
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def test_schema_corpus_is_non_empty() -> None:
    # Guards against a path/refactor mistake silently making the gate a no-op.
    assert len(ALL_SCHEMAS) >= 19, f"expected >=19 schemas, found {len(ALL_SCHEMAS)}"


@pytest.mark.parametrize("schema_path", ALL_SCHEMAS, ids=lambda p: str(p.relative_to(SCHEMA_ROOT)))
def test_every_schema_is_a_valid_jsonschema(schema_path: Path) -> None:
    """Meta-validate each schema against its declared dialect. This both
    gates well-formedness AND ensures the schema is loaded by code (the
    audit's 'never loaded by code' finding for schema/0.3|0.4)."""
    doc = _load_json(schema_path)
    Draft202012Validator.check_schema(doc)


def test_skill_manifest_instance_validates() -> None:
    """The skill bundle ships a manifest instance; it MUST validate against
    schema/skill/0.1/skill-manifest.schema.json (audit: no instance shipped)."""
    schema = _load_json(SCHEMA_ROOT / "skill" / "0.1" / "skill-manifest.schema.json")
    instance = _load_json(REPO_ROOT / "skill" / "skill-manifest.json")
    Draft202012Validator(schema).validate(instance)


def test_skill_manifest_matches_skill_md_frontmatter() -> None:
    """Drift guard: the JSON manifest instance and the SKILL.md YAML
    frontmatter describe the same skill — name/version/capabilities must
    agree, or one was edited without the other."""
    instance = _load_json(REPO_ROOT / "skill" / "skill-manifest.json")
    front = _read_skill_md_frontmatter(REPO_ROOT / "skill" / "SKILL.md")
    assert instance["name"] == front["name"]
    assert instance["version"] == front["version"]
    assert set(instance["capabilities"]) == set(front["capabilities"])


def _read_skill_md_frontmatter(path: Path) -> dict:
    """Minimal YAML-frontmatter reader (name/version/capabilities list) so
    the test has no PyYAML dependency."""
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---"), "SKILL.md must open with a YAML frontmatter block"
    block = text.split("---", 2)[1]
    out: dict = {"capabilities": []}
    in_caps = False
    for raw in block.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("capabilities:"):
            in_caps = True
            continue
        if in_caps:
            stripped = line.strip()
            if stripped.startswith("- "):
                out["capabilities"].append(stripped[2:].strip())
                continue
            in_caps = False
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            out[key.strip()] = val.strip().strip('"')
    return out


def test_a2ui_v04_surface_schema_accepts_valid_instance() -> None:
    """Wire schema/0.4 into a real validator (audit: 'never loaded by
    code'). A minimal valid v0.10 surface must validate, exercising the
    surface→component $ref."""
    registry = _registry_for(SCHEMA_ROOT / "0.4")
    surface_schema = _load_json(SCHEMA_ROOT / "0.4" / "a2ui-surface.json")
    validator = Draft202012Validator(surface_schema, registry=registry)
    valid = {
        "version": "0.10",
        "createSurface": {"surfaceId": "s1"},
        "updateComponents": {
            "surfaceId": "s1",
            "root": "c1",
            "components": [{"id": "c1", "component": "Text", "text": "hello"}],
        },
    }
    validator.validate(valid)


def test_a2ui_v04_surface_schema_rejects_bad_version_and_component() -> None:
    """The wired schema must also REJECT malformed surfaces, or it isn't a
    real gate: a wrong version const and an unknown component type."""
    from jsonschema import ValidationError

    registry = _registry_for(SCHEMA_ROOT / "0.4")
    surface_schema = _load_json(SCHEMA_ROOT / "0.4" / "a2ui-surface.json")
    validator = Draft202012Validator(surface_schema, registry=registry)

    bad_version = {
        "version": "0.9",  # schema pins const "0.10"
        "createSurface": {"surfaceId": "s1"},
        "updateComponents": {"surfaceId": "s1", "root": "c1", "components": []},
    }
    with pytest.raises(ValidationError):
        validator.validate(bad_version)

    bad_component = {
        "version": "0.10",
        "createSurface": {"surfaceId": "s1"},
        "updateComponents": {
            "surfaceId": "s1",
            "root": "c1",
            "components": [{"id": "c1", "component": "NotARealComponent"}],
        },
    }
    with pytest.raises(ValidationError):
        validator.validate(bad_component)
