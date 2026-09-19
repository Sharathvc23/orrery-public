"""Per-model capability records, read from a measurement rather than assumed.

``scripts/probe_llm_compat.py`` measures what an OpenAI-compatible endpoint
actually does with the two request shapes this codebase depends on — a forced
``tool_choice`` and ``response_format={"type": "json_object"}`` — and writes
``docs/integrations/llm-compat-probe.json``. This module reads that file so a
caller can branch on what was measured.

WHY A FILE RATHER THAN A CONSTANT. The failure this guards against is not that
a provider rejects a request shape; a rejection is a 4xx and the caller finds
out immediately. It is that a provider ACCEPTS the request, answers 200, and
silently does not honour the constraint. ``planner_llm.plan_from_llm`` turns
that into an empty Plan with no exception raised, so an agent pointed at such a
model loops at its normal rate producing nothing. A hardcoded table of
"providers that support tools" would be the same guess that produced the
problem.

The four verdicts carry different consequences and the code branches on the
distinction:

  ``supported``  measured, every trial honoured it — use the shape.
  ``ignored``    answered 200 and did not honour it — do NOT use the shape.
  ``rejected``   answered 4xx — do NOT use the shape.
  ``unknown``    never measured, or the endpoint was unreachable.

``unknown`` deliberately reads as "try it": a model absent from the probe must
behave exactly as it did before this module existed, or adding the file would
change behaviour for every unmeasured deployment. Only a MEASURED failure
changes a code path.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "IGNORED",
    "REJECTED",
    "SUPPORTED",
    "UNKNOWN",
    "ModelCaps",
    "caps_for",
    "default_probe_path",
    "load_probe",
]

SUPPORTED = "supported"
IGNORED = "ignored"
REJECTED = "rejected"
UNKNOWN = "unknown"

#: Overrides the probe location. Unset and empty are treated the same.
PROBE_PATH_ENV = "LLM_COMPAT_PROBE"

#: Where the committed measurement lives, relative to the repository root.
PROBE_RELATIVE_PATH = "docs/integrations/llm-compat-probe.json"


@dataclass(frozen=True)
class ModelCaps:
    """What was measured about one model. Absent measurements stay ``unknown``."""

    model: str
    forced_tool_choice: str = UNKNOWN
    json_object_response_format: str = UNKNOWN

    @property
    def forced_tool_choice_usable(self) -> bool:
        """True unless a forced ``tool_choice`` was MEASURED to fail.

        ``unknown`` is usable: an unmeasured model keeps the behaviour it had
        before the probe existed.
        """
        return self.forced_tool_choice not in (IGNORED, REJECTED)

    @property
    def json_object_usable(self) -> bool:
        """True only when JSON mode was measured to work.

        Stricter than its counterpart on purpose. This one gates a fallback
        that parses the model's message CONTENT, and content is only safe to
        parse when the endpoint was measured to constrain it to a JSON object.
        Guessing here would mean parsing free text, which is the thing the
        planner refuses to do.
        """
        return self.json_object_response_format == SUPPORTED


def default_probe_path() -> Path | None:
    """The probe file to read, or None if there is nothing to read.

    ``LLM_COMPAT_PROBE`` wins. Otherwise walk up from this module looking for
    the committed file, which finds it in a source checkout and finds nothing
    in an installed package — where returning None is the correct answer.
    """
    override = os.environ.get(PROBE_PATH_ENV, "").strip()
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / PROBE_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    return None


def load_probe(path: str | os.PathLike[str] | None = None) -> dict[str, ModelCaps]:
    """Read the probe file into a table keyed by model id.

    Returns an empty table when there is no file, when it does not parse, or
    when its schema is one this code does not know — an unreadable measurement
    is no measurement, and every model then reads as ``unknown``. It never
    raises: a missing or malformed capability file must not stop an agent from
    running the way it ran yesterday.
    """
    resolved = Path(path) if path is not None else default_probe_path()
    if resolved is None or not resolved.is_file():
        return {}
    try:
        payload = json.loads(resolved.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != "llm-compat-probe/1":
        return {}
    models = payload.get("models")
    if not isinstance(models, dict):
        return {}

    table: dict[str, ModelCaps] = {}
    for model, entry in models.items():
        if not isinstance(entry, dict):
            continue
        caps = entry.get("caps")
        if not isinstance(caps, dict):
            continue
        table[str(model)] = ModelCaps(
            model=str(model),
            forced_tool_choice=str(caps.get("forced_tool_choice", UNKNOWN)),
            json_object_response_format=str(caps.get("json_object_response_format", UNKNOWN)),
        )
    return table


def caps_for(model: str, table: dict[str, ModelCaps] | None = None) -> ModelCaps:
    """The caps for ``model``, or an all-``unknown`` record.

    Matching is exact. A pin like ``llama3.1:8b`` and a pin like
    ``llama3.1:70b`` are different measurements and must not share a verdict;
    prefix matching would let one model's PASS vouch for another's.
    """
    lookup = load_probe() if table is None else table
    found = lookup.get(model)
    return found if found is not None else ModelCaps(model=model)
