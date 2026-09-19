#!/usr/bin/env python3
"""Compare two capability probe runs and print what changed.

The committed ``docs/integrations/llm-compat-probe.json`` is a measurement with
a date on it. What it describes — a model file and an inference server — can
change without a line of this repository changing, so the nightly run exists to
notice. This script is what turns two JSON files into a statement.

It prints one line per model per capability and exits 0 whether or not anything
drifted. Drift is a finding to read, not a broken build: failing the nightly on
a changed verdict would make a red cron routine, and a red cron nobody reads is
the same as no cron. The exit code is reserved for this script being unable to
do its job at all — a missing or unparseable file.

USAGE::

    scripts/llm_compat_diff.py committed.json fresh.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CAP_KEYS = ("forced_tool_choice", "json_object_response_format")


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if not isinstance(payload, dict):
        print(f"{path} is not a probe payload", file=sys.stderr)
        raise SystemExit(2)
    return payload


def _caps(payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    models = payload.get("models")
    out: dict[str, dict[str, str]] = {}
    if not isinstance(models, dict):
        return out
    for model, entry in models.items():
        caps = (entry or {}).get("caps") if isinstance(entry, dict) else None
        if isinstance(caps, dict):
            out[str(model)] = {k: str(caps.get(k, "unknown")) for k in CAP_KEYS}
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("committed", type=Path)
    parser.add_argument("fresh", type=Path)
    args = parser.parse_args(argv)

    before = _caps(_load(args.committed))
    after = _caps(_load(args.fresh))

    print(f"committed: {args.committed}  ({len(before)} models)")
    print(f"fresh:     {args.fresh}  ({len(after)} models)")
    print()

    drift = 0
    for model in sorted(set(before) | set(after)):
        if model not in after:
            # Not drift: the nightly probes a smaller model set than the
            # committed file records, so silence about a model is expected and
            # must not read as a change.
            print(f"  {model}: not probed in this run")
            continue
        if model not in before:
            print(f"  {model}: NEW — {after[model]}")
            drift += 1
            continue
        for cap in CAP_KEYS:
            was, now = before[model][cap], after[model][cap]
            marker = "CHANGED" if was != now else "same"
            if was != now:
                drift += 1
            print(f"  {model} {cap}: {was} -> {now}  [{marker}]")

    print()
    print(f"{drift} capability verdict(s) differ from the committed measurement.")
    if drift:
        print("Re-run the probe locally and commit the new file if the change is real.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
