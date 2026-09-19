"""Tests for scripts/approve_candidate.py — the approve → publish review gate.

The generate step never auto-publishes; this CLI is the human gate that
validates a candidate, stamps approval, and moves it to the publish dir.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
import approve_candidate  # noqa: E402

_VALID_SKILL_MD = """---
name: demo-skill
version: 0.1.0
description: Minimal demo skill
author: testuser
license: MIT
capabilities:
  - net.http
---

# Demo skill
"""


def _make_candidate(root: Path, *, slug="demo-skill", errors=None, approved_at=None, skill_md=_VALID_SKILL_MD) -> Path:
    cand = root / slug
    cand.mkdir(parents=True)
    (cand / "SKILL.md").write_text(skill_md)
    meta = {
        "slug": slug,
        "spec_url": "https://x/openapi.json",
        "description": "d",
        "generated_at": 1,
        "approved_at": approved_at,
        "approved_by": None,
        "llm_provider": "openai",
        "llm_model": "gpt-4o-mini",
        "errors": errors or [],
    }
    (cand / "meta.json").write_text(json.dumps(meta))
    return cand


# ── HAPPY ──


def test_approve_happy_moves_and_stamps(tmp_path):
    cand = _make_candidate(tmp_path / "candidate-skills")
    publish = tmp_path / "published"
    dest = approve_candidate.approve(cand, "@alice", publish)
    assert dest == publish / "demo-skill"
    assert dest.exists()
    assert not cand.exists()  # moved, not copied
    meta = json.loads((dest / "meta.json").read_text())
    assert meta["approved_by"] == "@alice"
    assert isinstance(meta["approved_at"], int) and meta["approved_at"] > 0


def test_main_cli_happy(tmp_path):
    cand = _make_candidate(tmp_path / "candidate-skills")
    rc = approve_candidate.main([str(cand), "--approved-by", "@bob", "--publish-dir", str(tmp_path / "pub")])
    assert rc == 0
    assert (tmp_path / "pub" / "demo-skill").exists()


# ── ADVERSARIAL / gates (nothing moved or stamped) ──


def test_approve_refuses_already_approved(tmp_path):
    cand = _make_candidate(tmp_path / "c", approved_at=123)
    with pytest.raises(RuntimeError, match="already approved"):
        approve_candidate.approve(cand, "@alice", tmp_path / "pub")
    assert cand.exists()  # untouched


def test_approve_refuses_generation_errors(tmp_path):
    cand = _make_candidate(tmp_path / "c", errors=["parse: bad"])
    with pytest.raises(RuntimeError, match="unresolved generation error"):
        approve_candidate.approve(cand, "@alice", tmp_path / "pub")


def test_approve_refuses_invalid_manifest(tmp_path):
    # A hand-edited candidate that slipped a banned capability past generation.
    bad_md = _VALID_SKILL_MD.replace("  - net.http", "  - net.http\n  - shell.exec")
    cand = _make_candidate(tmp_path / "c", skill_md=bad_md)
    with pytest.raises(RuntimeError, match="manifest validation failed"):
        approve_candidate.approve(cand, "@alice", tmp_path / "pub")


def test_approve_refuses_existing_published(tmp_path):
    cand = _make_candidate(tmp_path / "c")
    publish = tmp_path / "pub"
    (publish / "demo-skill").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="already published"):
        approve_candidate.approve(cand, "@alice", publish)


def test_approve_refuses_missing_skill_md(tmp_path):
    cand = tmp_path / "c" / "demo-skill"
    cand.mkdir(parents=True)
    (cand / "meta.json").write_text(json.dumps({"slug": "demo-skill", "errors": []}))
    with pytest.raises(RuntimeError, match="no SKILL.md"):
        approve_candidate.approve(cand, "@alice", tmp_path / "pub")


def test_approve_refuses_empty_reviewer(tmp_path):
    cand = _make_candidate(tmp_path / "c")
    with pytest.raises(RuntimeError, match="approved-by"):
        approve_candidate.approve(cand, "  ", tmp_path / "pub")
