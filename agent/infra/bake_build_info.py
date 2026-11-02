"""Bake the build's commit into the agent image, as a file.

Run by ``infra/Dockerfile.agent`` after ``COPY . /app`` and before the package
is installed, so both the source tree ``serve.py`` imports from and the
installed wheel carry it::

    python infra/bake_build_info.py community_member/_build_info.json

It reads the Dockerfile's build ARGs from its environment. Those exist only for
the ``RUN`` that invokes this script — the image declares no ``ENV`` for them —
so nothing set on the running service can change what the file says. That is
the point: the org's ``/health`` reported a stale commit for weeks because its
stamp was an environment variable, and a service variable survives every
rebuild. A file in the image cannot drift from the code it was built with.

Stdlib only: it runs before any dependency is installed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

UNKNOWN = "unknown"


def _same_commit(a: str, b: str) -> bool:
    """Two commit ids name the same commit — compared over the shorter of the
    two, so a short stamp still matches its full hash, while two full hashes
    must match in full. The same rule the org server applies."""
    a, b = a.lower(), b.lower()
    n = min(len(a), len(b))
    return a[:n] == b[:n]


def build_info(env: dict[str, str]) -> dict[str, str | bool]:
    """The document to bake, from the build's ARGs.

    ``GIT_COMMIT`` already defaults to ``RAILWAY_GIT_COMMIT_SHA`` in the
    Dockerfile, so the two differ only when something passed an explicit
    ``--build-arg GIT_COMMIT``. On a github-connected Railway build that can be
    a service variable of the same name, which Railway hands to the builder —
    the stale-stamp failure moved from runtime to build time. When that happens
    both are recorded and neither is asserted, matching the org's
    ``platform_commit`` / ``provenance_conflict`` fields.
    """

    def _get(name: str) -> str:
        return env.get(name, "").strip()

    commit = _get("GIT_COMMIT") or UNKNOWN
    info: dict[str, str | bool] = {
        "git_commit": commit,
        "git_branch": _get("GIT_BRANCH") or UNKNOWN,
        "build_timestamp": _get("BUILD_TIMESTAMP") or UNKNOWN,
    }
    platform = _get("RAILWAY_GIT_COMMIT_SHA")
    if platform and commit != UNKNOWN and not _same_commit(commit, platform):
        info["platform_commit"] = platform
        info["provenance_conflict"] = True
    return info


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <output.json>", file=sys.stderr)
        return 2
    info = build_info(dict(os.environ))
    Path(argv[1]).write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if info.get("provenance_conflict"):
        print(
            f"[build-info] CONFLICT: --build-arg GIT_COMMIT={info['git_commit']} disagrees with the "
            f"platform's {info['platform_commit']}. Remove the GIT_COMMIT variable from the service "
            "so the builder's own commit is baked.",
            file=sys.stderr,
        )
    print(f"[build-info] baked {json.dumps(info, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
