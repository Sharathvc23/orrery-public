"""Pytest wiring for the client signing-conformance suite.

Selects which runtime's signing helper to verify via ``--adapter`` (default
``spec-reference``, the self-contained executable spec). Every adapter is run
against the SAME committed vector corpus under ``vectors/signing/`` so any
runtime that signs differently from the spec fails immediately.

Shipped adapters:
  * ``spec-reference``  — pure-Python executable specification.
  * ``openclaw-skill``  — Orrery's ``skill/helpers/sign_request.py`` helper.
  * ``member-sdk``      — Orrery's ``agent/`` SDK.

Adapters remain optional for portable local and downstream use.  Orrery's
release CI selects each shipped adapter with ``--require-adapter`` so a missing
runtime fails closed instead of turning the five checks into skips.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Final

import pytest

_CLIENT_DIR = Path(__file__).resolve().parent
_ADAPTERS_DIR = _CLIENT_DIR / "adapters"
VECTORS_DIR = _CLIENT_DIR.parents[1] / "vectors" / "signing"

_ADAPTER_CLASS = {
    "spec-reference": ("spec_reference", "SpecReferenceAdapter"),
    "openclaw-skill": ("openclaw_skill", "OpenClawSkillAdapter"),
    "member-sdk": ("member_sdk", "MemberSDKAdapter"),
}
SHIPPED_ADAPTERS: Final[tuple[str, ...]] = tuple(_ADAPTER_CLASS)


def _load_adapter(name: str) -> Any:
    if name not in _ADAPTER_CLASS:
        raise ValueError(f"unknown adapter {name!r}; choose one of {sorted(_ADAPTER_CLASS)}")
    module_name, class_name = _ADAPTER_CLASS[name]
    spec = importlib.util.spec_from_file_location(module_name, _ADAPTERS_DIR / f"{module_name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, class_name)()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--adapter",
        action="store",
        default="spec-reference",
        help=f"Signing runtime to verify ({' | '.join(SHIPPED_ADAPTERS)}).",
    )
    parser.addoption(
        "--require-adapter",
        action="store_true",
        default=False,
        help="Fail instead of skip when the selected signing adapter is unavailable.",
    )


@pytest.fixture(scope="session")
def adapter(request: pytest.FixtureRequest) -> Any:
    name = request.config.getoption("--adapter")
    try:
        return _load_adapter(name)
    except (ImportError, ModuleNotFoundError, FileNotFoundError) as e:
        if request.config.getoption("--require-adapter"):
            raise pytest.UsageError(
                f"required adapter {name!r} unavailable in this environment: {e}"
            ) from e
        pytest.skip(f"adapter {name!r} unavailable in this environment: {e}")


@pytest.fixture(scope="session")
def signing_vectors() -> Any:
    def _load(name: str) -> dict:
        with (VECTORS_DIR / name).open(encoding="utf-8") as fh:
            return json.load(fh)

    return _load
