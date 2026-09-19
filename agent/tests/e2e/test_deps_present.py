"""Green-means-green guard.

Large parts of the unit suite ``importorskip`` the sm-* family and PyNaCl.
In the e2e environment those silent skips would hollow out the evidence —
here they hard-fail instead, so a green e2e run proves the full stack was
actually exercised.
"""

from __future__ import annotations

import importlib

import pytest

from tests.e2e.conftest import e2e_gate

pytestmark = e2e_gate

REQUIRED = [
    "nacl.signing",
    "base58",
    "sm_arp",
    "sm_aae",
    "sm_parc",
    "sm_bridge",
    "sm_conformance",
]


@pytest.mark.parametrize("mod", REQUIRED)
def test_dependency_importable(mod: str):
    importlib.import_module(mod)  # ImportError = fail, never skip
