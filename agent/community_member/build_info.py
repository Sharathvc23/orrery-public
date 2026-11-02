"""This agent's own build identity — the commit its image was built from.

The value is baked into ``_build_info.json`` next to this module by
``infra/bake_build_info.py`` at image build time. It is deliberately NOT read
from the environment: the org's ``/health`` spent weeks reporting a stale
commit because its stamp was a service variable, which survives every rebuild
and describes a deploy that is no longer running.

No file means nothing baked one — a source checkout or a ``pip install`` outside
the image — and the answer is an honest ``"unknown"``. There is no ``git
rev-parse`` fallback: an installed package can sit inside an unrelated
checkout (a venv in a repo), and that checkout's HEAD would be reported as this
agent's build.

The field names are the org server's ``/version`` fields, so a probe reads one
shape from either service.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

__all__ = ["BUILD_INFO_FILE", "UNKNOWN", "read_build_info"]

log = logging.getLogger(__name__)

BUILD_INFO_FILE = Path(__file__).with_name("_build_info.json")
UNKNOWN = "unknown"

_FIELDS = ("git_commit", "git_branch", "build_timestamp")


def _unknown() -> dict[str, str | bool]:
    return dict.fromkeys(_FIELDS, UNKNOWN)


def read_build_info(path: Path | None = None) -> dict[str, str | bool]:
    """Return ``git_commit`` / ``git_branch`` / ``build_timestamp``, plus
    ``platform_commit`` and ``provenance_conflict`` when the build recorded
    that its two commit sources disagreed."""
    source = path if path is not None else BUILD_INFO_FILE
    try:
        raw = source.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _unknown()
    except OSError as e:
        log.warning("[build-info] %s present but unreadable (%r); reporting unknown", source, e)
        return _unknown()
    try:
        data = json.loads(raw)
    except ValueError as e:
        log.warning("[build-info] %s is not JSON (%r); reporting unknown", source, e)
        return _unknown()
    if not isinstance(data, dict):
        log.warning("[build-info] %s is not a JSON object; reporting unknown", source)
        return _unknown()

    info: dict[str, str | bool] = {k: str(data.get(k) or "").strip() or UNKNOWN for k in _FIELDS}
    platform = str(data.get("platform_commit") or "").strip()
    if data.get("provenance_conflict") is True and platform:
        info["platform_commit"] = platform
        info["provenance_conflict"] = True
    return info
