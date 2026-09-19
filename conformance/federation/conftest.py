"""Fixtures for the sm-federation 0.1 conformance suite.

Two things this file is careful about, both of which are the point of the suite:

**The schemas come from the installed distribution, never from this repo.**
``sm_federation.wire.load_schema`` resolves the bytes ``sm-federation``
published. A transcribed copy under ``schema/`` would be a second source of
truth that nothing compares — and a conformance suite that validates against its
own copy of the contract proves only that it agrees with itself. If
``sm-federation`` is not installed, these tests **fail**; they do not skip.
A skipped conformance suite reports green.

**The runtime is the real app.** The surface claims are checked against a booted
``chapter_agent`` via ``TestClient``, not against a route table read by eye, so a
route that exists but errors is not mistaken for a route that works.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_ROOT = REPO_ROOT / "server"
CLAIMS_PATH = Path(__file__).parent / "claims.json"
FIELD_MAP_PATH = Path(__file__).parent / "envelope_field_map.json"

# Deterministic, self-contained runtime config. Mirrors server/tests/conftest.py's
# defaults; `setdefault` so a real environment still wins.
for _k, _v in {
    "AGENT_ID": "orrery-federation-conformance",
    "AGENT_NAME": "Orrery Federation Conformance",
    "DATABASE_URL": "postgres://test@localhost/test",
    "LLM_API_KEY": "test",
    "OPENAI_API_KEY": "test",
    "ORRERY_KEY_SECRET": "federation-conformance-secret",
}.items():
    os.environ.setdefault(_k, _v)

if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))


def _load(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def wire():
    """The published wire contract, resolved from the installed distribution.

    Imported inside the fixture so the ImportError names what is missing and why
    it is fatal, rather than surfacing as a collection error.
    """
    try:
        from sm_federation import wire as _wire
    except ImportError as exc:  # pragma: no cover - environment guard
        pytest.fail(
            "sm-federation is not installed, so there is no published contract to "
            "validate against. This suite must not skip: install the pinned "
            "sm-federation (see server/requirements-dev.txt). Underlying error: " + str(exc)
        )
    return _wire


@pytest.fixture(scope="session")
def published_schema(wire):
    """``name -> Draft202012Validator`` over the *published* schemas."""
    from jsonschema import Draft202012Validator

    return {name: Draft202012Validator(wire.load_schema(name)) for name in wire.SCHEMA_NAMES}


@pytest.fixture(scope="session")
def claims() -> dict[str, Any]:
    return _load(CLAIMS_PATH)


@pytest.fixture(scope="session")
def field_map() -> dict[str, Any]:
    return _load(FIELD_MAP_PATH)


@pytest.fixture(scope="session")
def orrery_client():
    """A booted Orrery org server."""
    from fastapi.testclient import TestClient

    import chapter_agent

    with TestClient(chapter_agent.app) as client:
        yield client


@pytest.fixture(scope="session")
def orrery_summary() -> dict[str, Any]:
    """What ``get_our_summary`` emits with a populated intelligence cache.

    Derived by running the real emitter rather than transcribed from a reading of
    it, so a change to the emitter is observed here without anyone updating a
    literal.
    """
    import federation_intelligence as fi

    cache = {
        "chapter_intelligence": {
            "skill_graph": {"rust": 4, "ml": 2},
            "skill_gaps": ["design"],
            "trending_topics": ["agents"],
            "recommendations": ["pair up with a design-heavy peer"],
            "patterns": ["weekly cadence"],
            "member_count": 12,
            "active_members": ["a", "b", "c"],
            "last_reflected": "2026-01-01T00:00:00Z",
        }
    }
    fi.init(lambda *a, **k: None, cache, "orrery-node", "Orrery Node")
    return fi.get_our_summary()


@pytest.fixture(scope="session")
def orrery_summary_empty() -> dict[str, Any]:
    """The same emitter's other branch — an empty intelligence cache.

    ``get_our_summary`` returns a *different key set* depending on whether the
    cache is populated, so classifying only one branch would leave the other
    unguarded.
    """
    import federation_intelligence as fi

    fi.init(lambda *a, **k: None, {}, "orrery-node", "Orrery Node")
    return fi.get_our_summary()


@pytest.fixture(scope="session")
def orrery_emitted_fields(orrery_summary, orrery_summary_empty) -> set[str]:
    return set(orrery_summary) | set(orrery_summary_empty)
