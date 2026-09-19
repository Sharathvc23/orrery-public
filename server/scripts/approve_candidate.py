#!/usr/bin/env python3
"""Approve a generated skill candidate → move it into the publish directory.

The generate → approve → publish workflow never auto-publishes. ``skill_gen.py``
writes candidates to ``candidate-skills/{slug}/`` with ``meta.json.approved_at``
= null; a human reviews the manifest + capability list, then runs THIS CLI to:

  1. re-validate the candidate (SKILL.md + meta.json present, manifest valid,
     no unresolved generation errors, not already approved),
  2. stamp ``meta.json`` with ``approved_at`` (now) + ``approved_by``,
  3. move the candidate directory into the publish directory.

Usage:
    python scripts/approve_candidate.py candidate-skills/github-issue-creator \\
        --approved-by @alice \\
        --publish-dir published-skills/

Refuses to: approve a candidate carrying generation errors, re-approve an
already-approved candidate, publish an invalid manifest, or overwrite an
existing published skill.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

# skill_gen lives beside this script (server/scripts/); reuse its manifest
# validators so approval enforces the same rules generation did.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from skill_gen import _parse_frontmatter, validate_manifest  # noqa: E402


def _load_meta(candidate: Path) -> dict:
    meta_path = candidate / "meta.json"
    if not meta_path.exists():
        raise RuntimeError(f"no meta.json in {candidate} — not a skill candidate")
    try:
        data = json.loads(meta_path.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"meta.json is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise RuntimeError("meta.json is not an object")
    return data


def approve(candidate: Path, approved_by: str, publish_dir: Path) -> Path:
    """Validate + stamp + move a candidate. Returns the published path.

    Raises RuntimeError on any gate failure (nothing is moved or stamped).
    """
    if not approved_by.strip():
        raise RuntimeError("--approved-by is required (name / github handle of the reviewer)")
    if not candidate.is_dir():
        raise RuntimeError(f"candidate directory not found: {candidate}")
    skill_md = candidate / "SKILL.md"
    if not skill_md.exists():
        raise RuntimeError(f"no SKILL.md in {candidate}")

    meta = _load_meta(candidate)
    if meta.get("approved_at"):
        raise RuntimeError(f"already approved at {meta['approved_at']} by {meta.get('approved_by')}")
    if meta.get("errors"):
        raise RuntimeError(
            f"candidate carries {len(meta['errors'])} unresolved generation error(s) — "
            f"fix or regenerate before approving: {meta['errors']}"
        )

    # Re-validate the manifest at approval time (defense in depth — the file may
    # have been hand-edited since generation).
    validation_errors = validate_manifest(_parse_frontmatter(skill_md.read_text()))
    if validation_errors:
        raise RuntimeError(f"manifest validation failed: {validation_errors}")

    slug = meta.get("slug") or candidate.name
    dest = publish_dir / slug
    if dest.exists():
        raise RuntimeError(f"already published: {dest} (delete it first to re-publish)")

    # Stamp approval in meta BEFORE moving, so the published copy carries it.
    meta["approved_at"] = int(time.time())
    meta["approved_by"] = approved_by
    (candidate / "meta.json").write_text(json.dumps(meta, indent=2))

    publish_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(candidate), str(dest))
    return dest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("candidate", help="path to the candidate-skills/{slug} directory")
    p.add_argument("--approved-by", required=True, help="reviewer name / github handle")
    p.add_argument("--publish-dir", default="published-skills", help="where approved skills land")
    args = p.parse_args(argv)

    try:
        dest = approve(Path(args.candidate), args.approved_by, Path(args.publish_dir))
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(f"Approved + published: {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
