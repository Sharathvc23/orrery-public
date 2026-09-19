"""Shared fixtures for the conformance gate.

These tests gate two things that previously had no CI:

  1. Every JSON Schema under ``schema/**`` is a well-formed JSON Schema
     (meta-validation) and is actually *loaded* by code, not just
     hand-mirrored in comments.
  2. The deterministic ARP test-vector generators agree with the ARP
     receipt schema — so the generators and the schema cannot drift.

The vectors are a generated artifact (``vectors/`` is gitignored and
absent in a fresh clone), so the ``arp_vectors`` fixture regenerates
them on demand by running the in-repo generator.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = REPO_ROOT / "schema"
VECTORS_ROOT = REPO_ROOT / "vectors"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def schema_root() -> Path:
    return SCHEMA_ROOT


@pytest.fixture(scope="session")
def arp_vectors() -> list[Path]:
    """Ensure the ARP v0.1 vectors exist (generate if absent) and return them.

    The generator is deterministic (fixed seeds), so regenerating in CI
    yields byte-identical output. We run it as a subprocess to exercise
    the exact entrypoint a fresh clone would invoke.
    """
    out_dir = VECTORS_ROOT / "arp" / "0.1"
    if not list(out_dir.glob("*.json")):
        # Invoke as a module from the repo root so the `conformance` package
        # is importable (some generators do absolute `from conformance...`
        # imports that fail when run as a bare script).
        subprocess.run(
            [sys.executable, "-m", "conformance.arp._vector_gen"],
            cwd=REPO_ROOT,
            check=True,
        )
    vectors = sorted(out_dir.glob("*.json"))
    assert vectors, "ARP vector generation produced no vectors"
    return vectors
