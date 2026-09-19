"""
R1-R10 tests for the LLM wire-up in scripts/skill_gen.py.

These test the wiring (provider-agnostic LLM call via llm_config, spec
fetch, JSON extraction, helper sanitization). LLM calls are mocked — we
never hit the network or spend tokens during CI.

R1  Forgery            — LLM output claims banned capabilities → caught
R2  Replay             — N/A (call is stateless)
R3  Injection          — LLM output contains path-traversal helper names
R4  Authorization      — LLM credential/transport failure → clean error
R5  Boundary           — huge LLM output, helper >32 KiB gets dropped
R6  Concurrency        — _extract_json_object is pure
R7  Adversarial input  — LLM output with prose + fences, malformed JSON
R8  Downgrade          — LLM output with wrong-case manifest fields
R9  Timing             — N/A (handled upstream)
R10 Persistence        — metadata tracks tokens + errors correctly
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import skill_gen  # noqa: E402

# ── Shared doubles ────────────────────────────────────────────────────


def _valid_llm_output(name="demo-skill"):
    """Produce a minimal valid LLM response JSON string."""
    skill_md = f"""---
name: {name}
version: 0.1.0
description: Minimal demo skill
author: testuser
license: MIT
capabilities:
  - net.http
---

# Demo skill

## Verbs
- do thing — Does the thing.

## What the agent will do
Calls the endpoint once.

## Setup
Set `DEMO_API_KEY`.

## Capability justification
- net.http: to call the demo endpoint

## Limitations
Does not support pagination.
"""
    return json.dumps(
        {
            "skill_md": skill_md,
            "helpers": {},
            "rationale": "Minimal viable skill for testing.",
        }
    )


@pytest.fixture
def mock_llm():
    """Patch the LLM call globally for a test."""
    with patch("skill_gen._call_llm") as m:
        yield m


@pytest.fixture
def mock_fetch():
    """Patch OpenAPI spec fetch so we don't hit the network."""
    with patch("skill_gen._fetch_openapi", return_value='{"openapi": "3.0.0"}'):
        yield


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: LLM claims banned capabilities
# ══════════════════════════════════════════════════════════════════════


def test_R1_forgery_banned_capabilities_flagged(mock_llm, mock_fetch):
    """If the LLM tries to generate a skill with shell.exec, validate_manifest
    flags it in meta.errors (but generate_skill doesn't refuse — the human
    reviewer decides)."""
    skill_md = """---
name: evil-skill
version: 0.1.0
description: Innocent-looking skill
author: attacker
license: MIT
capabilities:
  - net.http
  - shell.exec
---

# Evil
"""
    mock_llm.return_value = (
        json.dumps({"skill_md": skill_md, "helpers": {}, "rationale": "x"}),
        1500,
    )
    _, _, meta = skill_gen.generate_skill("https://example.com/openapi.json", "evil test")
    assert any("banned" in err for err in meta.errors)


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: helper filenames with path traversal
# ══════════════════════════════════════════════════════════════════════


def test_R3_injection_path_traversal_helper_dropped(mock_llm, mock_fetch):
    mock_llm.return_value = (
        json.dumps(
            {
                "skill_md": _valid_llm_output(),
                "helpers": {"../../etc/shadow": "evil", "legit.py": "print('ok')"},
                "rationale": "x",
            }
        ).replace(
            '"skill_md": "',
            '"skill_md": '
            + json.dumps(
                """---
name: demo-skill
version: 0.1.0
description: x
author: t
license: MIT
---
"""
            )[0]
            + '"',
        ),  # awkward but avoids double-quoting
        1500,
    )
    # Simpler: build the output directly
    mock_llm.return_value = (
        json.dumps(
            {
                "skill_md": "---\nname: ok-skill\nversion: 0.1.0\ndescription: x\nauthor: t\nlicense: MIT\n---\n\n# OK\n",
                "helpers": {"../../etc/shadow": "evil", "legit.py": "print('ok')", ".hidden": "evil"},
                "rationale": "x",
            }
        ),
        1500,
    )
    _, helpers, meta = skill_gen.generate_skill("https://example.com/openapi.json", "test")
    assert "legit.py" in helpers
    assert "../../etc/shadow" not in helpers
    assert ".hidden" not in helpers
    assert any("unsafe filename" in err for err in meta.errors)


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: missing API key
# ══════════════════════════════════════════════════════════════════════


def test_R4_authz_llm_failure_surfaces_error(mock_fetch, monkeypatch):
    """A credential/transport failure in the provider-agnostic LLM call surfaces
    as RuntimeError('LLM call failed'), never a silent pass."""
    import llm_config

    def _boom() -> None:
        raise RuntimeError("no API key resolved")

    monkeypatch.setattr(llm_config, "build_client", _boom)
    with pytest.raises(RuntimeError) as exc_info:
        skill_gen.generate_skill("https://example.com/openapi.json", "test")
    assert "LLM call failed" in str(exc_info.value)


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: helper >32 KiB is dropped
# ══════════════════════════════════════════════════════════════════════


def test_R5_boundary_huge_helper_dropped(mock_llm, mock_fetch):
    huge = "x" * (33 * 1024)
    mock_llm.return_value = (
        json.dumps(
            {
                "skill_md": "---\nname: big-skill\nversion: 0.1.0\ndescription: x\nauthor: t\nlicense: MIT\n---\n\n# Big\n",
                "helpers": {"big.py": huge, "small.py": "print('ok')"},
                "rationale": "x",
            }
        ),
        1500,
    )
    _, helpers, meta = skill_gen.generate_skill("https://example.com/openapi.json", "test")
    assert "small.py" in helpers
    assert "big.py" not in helpers
    assert any("32KiB" in err for err in meta.errors)


# ══════════════════════════════════════════════════════════════════════
# R6 — Concurrency: _extract_json_object is pure
# ══════════════════════════════════════════════════════════════════════


def test_R6_concurrency_json_extract_is_pure():
    sample = '```json\n{"a": 1, "b": [2, 3]}\n```'
    results = [skill_gen._extract_json_object(sample) for _ in range(10)]
    assert all(r == results[0] for r in results)


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial input: LLM prose around JSON, malformed output
# ══════════════════════════════════════════════════════════════════════


def test_R7_adversarial_json_inside_fenced_code():
    """LLM wraps output in ```json fences — extractor handles it."""
    output = 'Here is the skill:\n\n```json\n{"skill_md": "a", "helpers": {}}\n```\n\nHope this helps!'
    parsed = skill_gen._extract_json_object(output)
    assert parsed == {"skill_md": "a", "helpers": {}}


def test_R7_adversarial_malformed_json_raises(mock_llm, mock_fetch):
    mock_llm.return_value = ("this is not JSON at all", 500)
    with pytest.raises(RuntimeError, match="not valid JSON"):
        skill_gen.generate_skill("https://example.com/openapi.json", "test")


def test_R7_adversarial_llm_returns_non_string_skill_md(mock_llm, mock_fetch):
    mock_llm.return_value = (
        json.dumps({"skill_md": 42, "helpers": {}, "rationale": "x"}),
        500,
    )
    with pytest.raises(RuntimeError, match="valid skill_md"):
        skill_gen.generate_skill("https://example.com/openapi.json", "test")


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: skill_md missing frontmatter
# ══════════════════════════════════════════════════════════════════════


def test_R8_downgrade_skill_md_without_frontmatter(mock_llm, mock_fetch):
    mock_llm.return_value = (
        json.dumps(
            {
                "skill_md": "# Just markdown, no frontmatter\n",
                "helpers": {},
                "rationale": "x",
            }
        ),
        500,
    )
    with pytest.raises(RuntimeError, match="valid skill_md"):
        skill_gen.generate_skill("https://example.com/openapi.json", "test")


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: metadata tracks tokens + errors
# ══════════════════════════════════════════════════════════════════════


def test_R10_persistence_tokens_tracked(mock_llm, mock_fetch):
    mock_llm.return_value = (_valid_llm_output(), 2500)
    _, _, meta = skill_gen.generate_skill("https://example.com/openapi.json", "happy test")
    import llm_config

    assert meta.llm_tokens_used == 2500
    assert meta.llm_provider == llm_config.PROVIDER
    assert meta.llm_model == llm_config.DEFAULT_MODEL


def test_R10_persistence_errors_written_to_meta(mock_llm, mock_fetch):
    """When manifest has validation errors, they go to meta.errors but
    the function returns normally."""
    skill_md = """---
name: Bad-Name-With-Dashes-And-Uppercase
version: not-semver
description: x
author: t
license: MIT
---

# Bad
"""
    mock_llm.return_value = (
        json.dumps({"skill_md": skill_md, "helpers": {}, "rationale": "x"}),
        1500,
    )
    _, _, meta = skill_gen.generate_skill("https://example.com/openapi.json", "test")
    assert meta.errors
    assert any("does not match" in err for err in meta.errors)
    assert any("semver" in err for err in meta.errors)


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


def test_happy_end_to_end_mocked(mock_llm, mock_fetch, tmp_path):
    mock_llm.return_value = (_valid_llm_output(), 1500)
    skill_md, helpers, meta = skill_gen.generate_skill("https://example.com/openapi.json", "demo skill test")
    assert skill_md.startswith("---\nname: demo-skill")
    assert helpers == {}
    assert meta.llm_tokens_used == 1500
    assert meta.errors == []

    # Write candidate works end-to-end
    out = skill_gen.write_candidate(tmp_path, meta, skill_md, helpers)
    assert (out / "SKILL.md").exists()
    assert (out / "meta.json").exists()
    loaded = json.loads((out / "meta.json").read_text())
    assert loaded["llm_tokens_used"] == 1500


def test_happy_system_prompt_is_readable():
    """Sanity: the system prompt file exists and is non-trivial."""
    text = skill_gen._load_system_prompt()
    assert len(text) > 500
    assert "SKILL.md" in text
    assert "capabilities" in text.lower()
