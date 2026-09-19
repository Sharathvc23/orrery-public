"""
R1-R10 tests for scripts/skill_gen.py scaffold.

Tests verify the scaffolding (CLI, slug, manifest validator, write_candidate,
frontmatter parser). The LLM-call itself is stubbed with NotImplementedError
in this PR — that gets tested in the follow-up PR that wires the LLM.

R1  Forgery            — slug sanitization
R2  Replay             — write_candidate refuses to overwrite
R3  Injection          — unsafe helper filenames rejected
R4  Authorization      — banned capabilities rejected
R5  Boundary           — slug length cap, empty input
R6  Concurrency        — validate_manifest is pure
R7  Adversarial input  — weird characters, unicode
R8  Downgrade          — version semver enforcement
R9  Timing             — N/A
R10 Persistence        — GenerationMetadata shape stable
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

# Import the module by path since scripts/ is not a package
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import skill_gen  # noqa: E402

# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: slug sanitization (can't inject path separators)
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_slug_strips_path_traversal():
    assert skill_gen.slugify("../../../etc/passwd") == "etc-passwd"


def test_R1_forgery_slug_strips_quotes_and_shell_metachars():
    assert skill_gen.slugify("'; rm -rf / #") == "rm-rf"


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: write_candidate refuses to overwrite
# ══════════════════════════════════════════════════════════════════════


def test_R2_replay_write_candidate_refuses_overwrite(tmp_path):
    meta = skill_gen.GenerationMetadata(
        slug="test-skill",
        spec_url="https://example.com/openapi.json",
        description="test",
        generated_at=0,
    )
    skill_gen.write_candidate(tmp_path, meta, "---\nname: x\n---\n", {})
    with pytest.raises(FileExistsError):
        skill_gen.write_candidate(tmp_path, meta, "---\nname: x\n---\n", {})


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: unsafe helper filenames rejected
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_helper_with_path_separator_rejected(tmp_path):
    meta = skill_gen.GenerationMetadata(slug="test-skill", spec_url="x", description="x", generated_at=0)
    with pytest.raises(ValueError, match="unsafe helper filename"):
        skill_gen.write_candidate(tmp_path, meta, "---\nname: x\n---\n", {"../../evil.py": "print(1)"})


def test_R3_injection_helper_starting_with_dot_rejected(tmp_path):
    meta = skill_gen.GenerationMetadata(slug="test-skill-2", spec_url="x", description="x", generated_at=0)
    with pytest.raises(ValueError, match="unsafe helper filename"):
        skill_gen.write_candidate(tmp_path, meta, "---\nname: x\n---\n", {".hidden": "evil"})


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: banned capabilities rejected
# ══════════════════════════════════════════════════════════════════════


def test_R4_authz_shell_exec_capability_rejected():
    manifest = {
        "name": "evil-skill",
        "version": "1.0.0",
        "description": "evil",
        "author": "attacker",
        "license": "MIT",
        "capabilities": ["shell.exec"],
    }
    errors = skill_gen.validate_manifest(manifest)
    assert any("banned capabilities" in e for e in errors)


def test_R4_authz_all_banned_capabilities_caught():
    for banned in ("shell.exec", "net.arbitrary", "fs.any", "eval.code"):
        manifest = {
            "name": "bad",
            "version": "1.0.0",
            "description": "bad",
            "author": "x",
            "license": "MIT",
            "capabilities": [banned],
        }
        errors = skill_gen.validate_manifest(manifest)
        assert any("banned" in e for e in errors), f"{banned} should be banned"


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: slug length, empty input
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_slug_caps_at_48_chars():
    long = "a" * 200
    assert len(skill_gen.slugify(long)) <= 48


def test_R5_boundary_empty_description_produces_fallback():
    assert skill_gen.slugify("") == "unnamed-skill"


def test_R5_boundary_pure_punctuation_produces_fallback():
    assert skill_gen.slugify("!@#$%^&*()") == "unnamed-skill"


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: validate_manifest is pure
# ══════════════════════════════════════════════════════════════════════


def test_R6_concurrency_validate_manifest_is_pure():
    manifest = {
        "name": "x-skill",
        "version": "0.1.0",
        "description": "x",
        "author": "x",
        "license": "MIT",
    }
    results = [skill_gen.validate_manifest(manifest) for _ in range(10)]
    assert all(r == results[0] for r in results)


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: weird inputs
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_unicode_slugs_to_ascii():
    # Cyrillic + emoji
    result = skill_gen.slugify("привет 🚀 world")
    # Only ASCII alphanumerics survive; unicode removed
    assert result == "world"


def test_R7_adversarial_null_bytes_stripped():
    result = skill_gen.slugify("a\x00b\x00c")
    assert "\x00" not in result
    assert result == "a-b-c"


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: version semver enforcement
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_non_semver_version_rejected():
    manifest = {
        "name": "x",
        "version": "latest",
        "description": "x",
        "author": "x",
        "license": "MIT",
    }
    errors = skill_gen.validate_manifest(manifest)
    assert any("semver" in e for e in errors)


def test_R8_downgrade_prerelease_semver_accepted():
    manifest = {
        "name": "x-pre",
        "version": "1.0.0-beta.1",
        "description": "x",
        "author": "x",
        "license": "MIT",
    }
    errors = skill_gen.validate_manifest(manifest)
    assert not any("semver" in e for e in errors)


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: GenerationMetadata shape + round-trip
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_metadata_roundtrip(tmp_path):
    meta = skill_gen.GenerationMetadata(
        slug="roundtrip-test",
        spec_url="https://api.example.com/openapi.json",
        description="Round trip",
        generated_at=1700000000,
        llm_provider="anthropic",
        llm_model="claude-opus-4-7",
        llm_tokens_used=1500,
    )
    out = skill_gen.write_candidate(tmp_path, meta, "---\nname: x\n---\n", {})
    loaded = json.loads((out / "meta.json").read_text())
    assert loaded == asdict(meta)


def test_R10_persistence_llm_wiring_present():
    """Phase 5 is wired. This test pins that the generate_skill call
    has moved past the NotImplementedError stub and now requires infra
    (spec fetch or API key). A regression to the stub would fail here."""
    # If we had a valid API key + reachable spec URL, this would actually
    # call the LLM. In CI without network, we expect a RuntimeError from
    # spec fetch, NOT a NotImplementedError.
    try:
        skill_gen.generate_skill("http://127.0.0.1:9/never-resolvable.json", "test")
    except NotImplementedError:
        pytest.fail("generate_skill should no longer raise NotImplementedError")
    except RuntimeError as e:
        # Expected: spec fetch fails. The wiring is live.
        msg = str(e).lower()
        assert any(tok in msg for tok in ("spec fetch", "spec_fetch", "llm call", "anthropic"))
    except Exception:
        # Any other exception (network, API key) also confirms wiring
        pass


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


def test_happy_slug_generates_clean_dashed():
    assert skill_gen.slugify("GitHub Issue Creator") == "github-issue-creator"


def test_happy_minimal_valid_manifest_passes():
    manifest = {
        "name": "my-skill",
        "version": "1.0.0",
        "description": "Does things",
        "author": "somebody",
        "license": "MIT",
        "capabilities": ["net.http"],
    }
    assert skill_gen.validate_manifest(manifest) == []


def test_happy_frontmatter_parses_correctly():
    md = """---
name: example-skill
version: 0.1.0
description: Example
capabilities:
  - net.http
  - crypto.ed25519
---

# Example
Some markdown.
"""
    parsed = skill_gen._parse_frontmatter(md)
    assert parsed["name"] == "example-skill"
    assert parsed["version"] == "0.1.0"
    assert parsed["capabilities"] == ["net.http", "crypto.ed25519"]


def test_happy_write_candidate_creates_expected_layout(tmp_path):
    meta = skill_gen.GenerationMetadata(slug="layout-test", spec_url="x", description="x", generated_at=0)
    out = skill_gen.write_candidate(
        tmp_path,
        meta,
        "---\nname: layout-test\nversion: 0.1.0\n---\n\nHello.\n",
        {"sign.py": "print('hi')"},
    )
    assert (out / "SKILL.md").exists()
    assert (out / "meta.json").exists()
    assert (out / "helpers" / "sign.py").read_text() == "print('hi')"
