"""Guard the repo's Claude model pins against silent rot.

A model pin is a string. Nothing type-checks it, nothing lints it, and the
failure mode when it goes stale is invisible until a user hits it: Anthropic
**retires** models, and "requests to retired models will fail". That is what
happened here — ``claude-sonnet-4-20250514`` was retired on 2026-06-15 and sat
in the onboarding wizard's provider catalogue for weeks afterwards, so every new
user who picked "Anthropic (Claude)" got a dead model.

The durable fix is not "remember to update the pins"; it is this file. A
retired id anywhere in the tree fails the suite, so the next retirement is
caught by CI instead of by a user.

Deliberately offline and dependency-free: it reads the repo as text. It makes no
API call, so it needs no key and cannot flake on the network. It cannot know
about a retirement announced after it was written, which is why
:data:`RETIRED_MODEL_IDS` carries retirement dates — refresh it from
https://platform.claude.com/docs/en/about-claude/model-deprecations when a pin
is next reviewed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: Retired Claude models — requests to these FAIL. Source: Anthropic's model
#: deprecations page, read 2026-08-01. Value is the retirement date.
RETIRED_MODEL_IDS = {
    "claude-sonnet-4-20250514": "2026-06-15",
    "claude-opus-4-20250514": "2026-06-15",
    "claude-3-7-sonnet-20250219": "2026-02-19",
    "claude-3-5-haiku-20241022": "2026-02-19",
    "claude-3-haiku-20240307": "2026-04-20",
    "claude-3-opus-20240229": "2026-01-05",
    "claude-3-5-sonnet-20241022": "2025-10-28",
    "claude-3-5-sonnet-20240620": "2025-10-28",
    "claude-3-sonnet-20240229": "2025-07-21",
}

#: Deprecated-but-still-served models, with their scheduled retirement. Not a
#: failure — a warning surface, so a pin on one of these is a known clock.
DEPRECATED_MODEL_IDS = {
    "claude-opus-4-1-20250805": "2026-08-05",
}

#: Directories that are not shipped source.
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".mypy_cache",
}

#: Extensions worth scanning — anything that can carry a live pin.
_SCAN_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".toml", ".yml", ".yaml", ".sh"}


def _source_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO.rglob("*"):
        if not path.is_file() or path.suffix not in _SCAN_SUFFIXES:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        # This file necessarily names every retired id.
        if path.resolve() == Path(__file__).resolve():
            continue
        files.append(path)
    return files


def _hits(model_id: str) -> list[str]:
    """Files containing ``model_id``, as repo-relative ``path:line`` strings."""
    found: list[str] = []
    pattern = re.compile(re.escape(model_id))
    for path in _source_files():
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if model_id not in text:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                found.append(f"{path.relative_to(REPO)}:{number}")
    return found


@pytest.mark.parametrize("model_id", sorted(RETIRED_MODEL_IDS))
def test_no_retired_model_is_pinned_anywhere(model_id: str) -> None:
    """A retired model id in shipped source is a live break, not staleness.

    Requests to a retired model fail outright, so this is the one model-pin
    problem that cannot wait for a compatibility probe.
    """
    hits = _hits(model_id)
    assert not hits, (
        f"{model_id} was RETIRED on {RETIRED_MODEL_IDS[model_id]} — requests to it fail. "
        f"Still pinned at: {', '.join(hits)}. "
        "Replace it (see docs/integrations/LLM_MODEL_PINS.md)."
    )


def test_deprecated_pins_are_listed_not_silent() -> None:
    """Deprecated models still work, so this does not fail the suite — but it
    names them, so a scheduled retirement is never a surprise."""
    pinned = {m: _hits(m) for m in DEPRECATED_MODEL_IDS}
    still_pinned = {m: h for m, h in pinned.items() if h}
    for model_id, hits in still_pinned.items():
        print(
            f"NOTE: {model_id} is deprecated and retires {DEPRECATED_MODEL_IDS[model_id]}; pinned at {', '.join(hits)}"
        )
    # Informational by design — the assertion is only that the scan ran.
    assert isinstance(pinned, dict)


def test_the_wizard_offers_a_live_anthropic_model() -> None:
    """The onboarding path is the one that burned us: a new user picking
    'Anthropic (Claude)' must not be handed a retired id."""
    from community_member.wizard import PROVIDERS

    anthropic = [p for p in PROVIDERS if p[0] == "anthropic"]
    assert anthropic, "the wizard no longer offers Anthropic"
    default_model = anthropic[0][3]
    assert default_model not in RETIRED_MODEL_IDS, (
        f"the onboarding wizard offers {default_model}, retired on {RETIRED_MODEL_IDS.get(default_model)}"
    )


def test_agent_and_server_provider_catalogues_agree() -> None:
    """``wizard.py::PROVIDERS`` and ``server.py::_PROVIDER_CATALOGUE`` are
    hand-maintained mirrors. They drifted once; this keeps them honest."""
    from community_member.server import _PROVIDER_CATALOGUE
    from community_member.wizard import PROVIDERS

    wizard = {p[0]: (p[2], p[3]) for p in PROVIDERS}
    server = {p[0]: (p[1], p[2]) for p in _PROVIDER_CATALOGUE}
    assert wizard == server, (
        f"provider catalogues disagree between wizard.py and server.py — wizard={wizard} server={server}"
    )
