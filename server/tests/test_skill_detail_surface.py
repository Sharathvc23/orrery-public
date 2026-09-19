"""build_skill_detail_surface renders the open Agent-Skills interop metadata
(category, safety_level, license, risk_tags, compatibility, use_cases, I/O) when
present — and stays clean (those sections absent) for skills that don't declare it.

Classification: HAPPY / EDGE.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402

import skill_registry as sr  # noqa: E402
import surfaces  # noqa: E402


def _skill(**overrides) -> dict:
    s = {
        "id": "file-ops@2.0.0",
        "name": "file-ops",
        "version": "2.0.0",
        "description": "safe file operations",
        "capabilities": ["fs.read", "fs.write"],
        "trust_score": 10,
        "install_count": 3,
        "author_did": "did:key:zAuthor",
        "author_agent_id": "alice",
        "content_sha256": "a" * 64,
        "signing_key_did": "did:key:zAuthor",
        "signature": "sig",
    }
    s.update(overrides)
    return s


def _ids(surface_dict: dict) -> set[str]:
    return {c["id"] for c in surface_dict["updateComponents"]["components"]}


def _by_id(surface_dict: dict) -> dict[str, dict]:
    return {c["id"]: c for c in surface_dict["updateComponents"]["components"]}


@pytest.fixture
def with_skill(monkeypatch):
    def _install(skill: dict):
        async def _get(_target):
            return skill

        monkeypatch.setattr(sr, "get_skill", _get)

    return _install


@pytest.mark.asyncio
async def test_renders_interop_metadata_when_present(with_skill):  # HAPPY
    with_skill(
        _skill(
            category="agent-infra",
            safety_level="medium",
            license="CC0-1.0",
            risk_tags=["filesystem"],
            compatibility={"generic_agents": "supported", "nanda_agentfacts": "supported"},
            use_cases=["Read a file", "Write a file"],
            inputs=[{"name": "path", "description": "file path"}],
            outputs=[{"name": "contents", "description": "bytes"}],
        )
    )
    result = await surfaces.build_skill_detail_surface(target="file-ops@2.0.0")
    ids = _ids(result)
    assert {"meta-table", "uses-list", "io-table"} <= ids
    meta = _by_id(result)["meta-table"]
    flat = " ".join(" ".join(r) for r in meta["rows"])
    assert "agent-infra" in flat and "medium" in flat and "CC0-1.0" in flat and "nanda_agentfacts" in flat
    io = _by_id(result)["io-table"]["rows"]
    assert ["input", "path", "file path"] in io
    assert any(r[0] == "output" for r in io)


@pytest.mark.asyncio
async def test_no_metadata_sections_when_absent(with_skill):  # EDGE — additive, no clutter
    with_skill(_skill())  # no interop fields
    result = await surfaces.build_skill_detail_surface(target="file-ops@2.0.0")
    ids = _ids(result)
    assert "meta-table" not in ids
    assert "uses-list" not in ids
    assert "io-table" not in ids
    # Core sections still render.
    assert "caps-table" in ids and "sig-block" in ids
