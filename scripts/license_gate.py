#!/usr/bin/env python3
"""Every runtime dependency carries a license this repository may redistribute under MIT.

What it reads
  Python: agent/requirements.lock, server/requirements.lock, index/requirements.lock,
          conformance/federation/requirements.txt — every `name==version` pin.
  npm:    renderer/package.json, smb_funnel/package.json — the runtime `dependencies`
          map (devDependencies are not shipped and are reported, not gated).
What it checks
  Each pin must appear in scripts/license_manifest.json with the license PyPI
  declares for exactly that version, and that license must be in the permissive
  set below. A pin missing from the manifest is UNKNOWN and fails — the manifest
  is the evidence and it does not grow on its own; run `--refresh` to fetch the
  metadata from PyPI and rewrite it, then read the diff.
Why a committed manifest rather than a live query
  The gate runs on every PR and must be deterministic and offline; PyPI
  metadata can change under a version (it has: license fields are edited).
  The manifest is what was read, when, and is reviewed like any other change.

Modes
  (default)   gate: exit 1 on any copyleft or unknown license
  --refresh   fetch metadata for every pin from PyPI and rewrite the manifest
  --self-test plant a GPL entry and a missing entry in memory and assert both fail
  --table     print the Markdown table docs/LICENSES.md embeds
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts" / "license_manifest.json"
# What SHIPS. agent/requirements-dev.lock (pytest, mypy, ruff and their deps)
# is installed only where CI runs the agent's tests, never into an image or by
# ./orrery-up, so it is audited for CVEs but not tabled as a distributed
# dependency; docs/LICENSES.md lists it separately.
PY_LOCKS = [
    "agent/requirements.lock",
    "server/requirements.lock",
    "index/requirements.lock",
    "conformance/federation/requirements.txt",
]
NPM_MANIFESTS = ["renderer/package.json", "smb_funnel/package.json"]

# SPDX identifiers (and the exact PyPI spellings that map to them) this
# repository may redistribute under its MIT license. MPL-2.0 is file-level
# weak copyleft: unmodified MPL files stay MPL, which MIT distribution permits;
# it is allowed and marked so in the table. Anything else — GPL, LGPL, AGPL,
# SSPL, EUPL, CC-BY-SA, proprietary, or a metadata field nobody filled in —
# fails here and becomes a question for a human, not a merge.
PERMISSIVE = {
    "MIT",
    "MIT-0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD",
    "ISC",
    "Apache-2.0",
    "PSF-2.0",
    "Python-2.0",
    "MPL-2.0",
    "Unlicense",
    "0BSD",
    "Zlib",
    "HPND",
}
WEAK_COPYLEFT = {"MPL-2.0"}
# PyPI license field / classifier spellings → SPDX.
SPELLINGS = {
    "mit license": "MIT",
    "mit": "MIT",
    "mit-0": "MIT-0",
    "bsd license": "BSD-3-Clause",
    "bsd": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "apache software license": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache": "Apache-2.0",
    "isc": "ISC",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "the unlicense (unlicense)": "Unlicense",
}
COPYLEFT_MARKERS = ("gpl", "agpl", "sspl", "eupl", "cc-by-sa", "proprietary", "commercial")


def _spdx_terms(expr: str) -> list[str]:
    """Split an SPDX expression into its identifiers ('A OR B', 'A AND B')."""
    return [t.strip("() ") for t in re.split(r"\s+(?:OR|AND|WITH)\s+", expr, flags=re.I) if t.strip("() ")]


def normalise(license_expression: str, license_field: str, classifiers: list[str]) -> tuple[str, str]:
    """Return (declared, spdx). `declared` is what PyPI said, verbatim-ish;
    `spdx` is the normalised expression or "" when nothing usable was declared."""
    if license_expression.strip():
        return license_expression.strip(), license_expression.strip()
    field = license_field.strip()
    if field and len(field) <= 60 and "\n" not in field:
        terms = _spdx_terms(field)
        mapped = [SPELLINGS.get(t.lower(), t) for t in terms]
        joined = " OR ".join(mapped) if re.search(r"\bOR\b", field, re.I) else " AND ".join(mapped)
        return field, joined
    cls = [c for c in classifiers if c.lower() not in ("osi approved",)]
    mapped = [SPELLINGS.get(c.lower(), "") for c in cls]
    mapped = [m for m in mapped if m]
    if mapped:
        return "; ".join(cls), " OR ".join(dict.fromkeys(mapped))
    return field or "; ".join(cls) or "", ""


def verdict(spdx: str) -> str:
    """'ok', 'weak-copyleft', 'copyleft' or 'unknown'."""
    if not spdx:
        return "unknown"
    low = spdx.lower()
    if any(m in low for m in COPYLEFT_MARKERS) and not any(t in PERMISSIVE for t in _spdx_terms(spdx)):
        return "copyleft"
    terms = _spdx_terms(spdx)
    # An OR expression is satisfiable if any branch is permissive; AND needs all.
    if re.search(r"\bOR\b", spdx, re.I):
        ok = any(t in PERMISSIVE for t in terms)
    else:
        ok = all(t in PERMISSIVE for t in terms)
    if not ok:
        return "copyleft" if any(m in low for m in COPYLEFT_MARKERS) else "unknown"
    if any(t in WEAK_COPYLEFT for t in terms) and not any(
        t in PERMISSIVE - WEAK_COPYLEFT for t in terms if re.search(r"\bOR\b", spdx, re.I)
    ):
        return "weak-copyleft"
    return "ok"


# ── inputs ──────────────────────────────────────────────────────────────────

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\;#]+)")


def python_pins() -> dict[str, set[str]]:
    """{'name==version': {lock files}} for every pinned name across the locks."""
    pins: dict[str, set[str]] = {}
    for rel in PY_LOCKS:
        for raw in (ROOT / rel).read_text(encoding="utf-8").splitlines():
            m = _PIN.match(raw.strip())
            if m:
                key = f"{m.group(1).lower().replace('_', '-')}=={m.group(2)}"
                pins.setdefault(key, set()).add(rel)
    return pins


def npm_runtime_deps() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for rel in NPM_MANIFESTS:
        data = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        out[rel] = dict(data.get("dependencies") or {})
    return out


# ── manifest ────────────────────────────────────────────────────────────────


def fetch(name: str, version: str) -> dict:
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as r:
                info = json.load(r)["info"]
            break
        except Exception as e:  # noqa: BLE001 — a flaky fetch is retried, a dead one raises below
            last = e
    else:
        raise RuntimeError(f"PyPI metadata for {name}=={version} could not be fetched: {last}")
    classifiers = [c.split("::")[-1].strip() for c in info.get("classifiers", []) if c.startswith("License ::")]
    declared, spdx = normalise(info.get("license_expression") or "", info.get("license") or "", classifiers)
    return {"declared": declared, "spdx": spdx, "classifiers": classifiers, "verdict": verdict(spdx)}


def refresh() -> None:
    pins = python_pins()
    previous = load_manifest() if MANIFEST.exists() else {}
    overrides = previous.get("overrides", {})
    entries = {}
    for key in sorted(pins):
        name, version = key.split("==", 1)
        entry = fetch(name, version)
        entry["sources"] = sorted(pins[key])
        # A hand-written "reason" on an entry survives a refresh: it is the
        # reviewer's reading of ambiguous metadata (a stray classifier, a
        # non-standard spelling), kept next to the metadata it explains.
        reason = (previous.get("python", {}).get(key) or {}).get("reason")
        if reason:
            entry["reason"] = reason
        entries[key] = entry
        print(f"  {key:40s} {entry['spdx'] or '(none declared)':30s} {entry['verdict']}")
    manifest = {
        "_": "Generated by scripts/license_gate.py --refresh from PyPI JSON metadata. "
        "Read, not guessed. Review the diff; the gate fails on any entry whose verdict is not ok/weak-copyleft. "
        "`overrides` is hand-written: a pin whose PyPI JSON declares nothing, with the evidence a human read "
        "(the sdist's own metadata or LICENSE file) and who accepted it. --refresh keeps it.",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overrides": overrides,
        "python": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(entries)} pins)")


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


# ── gate ────────────────────────────────────────────────────────────────────


def gate(manifest: dict, pins: dict[str, set[str]], npm: dict[str, dict[str, str]]) -> list[str]:
    """Every problem, one line each. Empty means green."""
    problems: list[str] = []
    entries = manifest.get("python", {})
    overrides = manifest.get("overrides", {})
    for key, sources in sorted(pins.items()):
        entry = entries.get(key)
        if entry is None:
            problems.append(
                f"UNKNOWN  {key} ({', '.join(sorted(sources))}) — not in the manifest; run --refresh and review"
            )
            continue
        # Recomputed from the spdx string EVERY time. The stored "verdict" is a
        # rendering convenience; trusting it would let a manifest edited to a
        # copyleft expression with a stale "ok" walk through the gate.
        v = verdict(entry.get("spdx", ""))
        if v == "unknown" and key in overrides:
            o = overrides[key]
            if not (o.get("spdx") and o.get("evidence") and o.get("accepted_by") and o.get("date")):
                problems.append(
                    f"UNKNOWN  {key} — override present but incomplete (needs spdx, evidence, accepted_by, date)"
                )
                continue
            v = verdict(o["spdx"])
            if v == "ok":
                continue
        if v == "unknown":
            problems.append(f"UNKNOWN  {key} — PyPI declares no usable license ({entry.get('declared') or 'nothing'})")
        elif v == "copyleft":
            problems.append(f"COPYLEFT {key} — {entry.get('spdx') or entry.get('declared')}")
    stale = sorted(set(entries) - set(pins))
    for key in stale:
        problems.append(f"STALE    {key} — in the manifest but pinned nowhere; run --refresh")
    for rel, deps in npm.items():
        for name, spec in deps.items():
            problems.append(
                f"UNKNOWN  npm {name}@{spec} ({rel}) — runtime npm dependencies are not gated yet; "
                "this repository ships none, so adding one needs the gate extended first"
            )
    return problems


def table(manifest: dict) -> str:
    rows = ["| package | version | license (PyPI) | where | verdict |", "|---|---|---|---|---|"]
    overrides = manifest.get("overrides", {})
    for key, e in sorted(manifest["python"].items()):
        name, version = key.split("==", 1)
        where = ", ".join(s.split("/")[0] for s in e["sources"])
        lic = e["spdx"] or e["declared"] or "—"
        v = verdict(e["spdx"])
        if v == "unknown" and key in overrides:
            lic = f"{overrides[key]['spdx']} (PyPI JSON declares nothing; {overrides[key]['evidence']})"
            v = verdict(overrides[key]["spdx"])
        mark = {
            "ok": "✅ MIT-compatible",
            "weak-copyleft": "✅ MPL-2.0 file-level (kept verbatim)",
            "copyleft": "❌ copyleft",
            "unknown": "⚠️ unknown",
        }[v]
        rows.append(f"| {name} | {version} | {lic} | {where} | {mark} |")
    return "\n".join(rows)


def self_test() -> None:
    manifest = load_manifest()
    pins = python_pins()
    # 1. a planted copyleft pin
    m = json.loads(json.dumps(manifest))
    m["python"]["planted-gpl==1.0.0"] = {
        "declared": "GPL-3.0-only",
        "spdx": "GPL-3.0-only",
        "classifiers": [],
        "verdict": verdict("GPL-3.0-only"),
        "sources": ["agent/requirements.lock"],
    }
    p = dict(pins)
    p["planted-gpl==1.0.0"] = {"agent/requirements.lock"}
    out = gate(m, p, {})
    assert any(line.startswith("COPYLEFT planted-gpl==1.0.0") for line in out), out
    # 1b. a copyleft spdx with a STALE stored verdict of "ok" — the stored key is not trusted
    m1b = json.loads(json.dumps(manifest))
    k1 = next(iter(pins))
    m1b["python"][k1] = {**m1b["python"][k1], "spdx": "AGPL-3.0-only", "verdict": "ok"}
    out = gate(m1b, pins, {})
    assert any(line.startswith(f"COPYLEFT {k1}") for line in out), out
    # 1c. and an empty spdx with a stale "ok" is unknown, not ok
    m1c = json.loads(json.dumps(manifest))
    m1c["python"][k1] = {**m1c["python"][k1], "spdx": "", "declared": "", "verdict": "ok"}
    out = gate(m1c, pins, {})
    assert any(line.startswith(f"UNKNOWN  {k1}") for line in out), out
    # 2. a pin the manifest has never seen
    p2 = dict(pins)
    p2["never-seen==0.0.1"] = {"server/requirements.lock"}
    out = gate(manifest, p2, {})
    assert any(line.startswith("UNKNOWN  never-seen==0.0.1") for line in out), out
    # 3. an entry whose metadata declares nothing
    m3 = json.loads(json.dumps(manifest))
    k = next(iter(pins))
    m3["python"][k] = {**m3["python"][k], "spdx": "", "declared": "", "verdict": "unknown"}
    out = gate(m3, pins, {})
    assert any(line.startswith(f"UNKNOWN  {k}") for line in out), out
    # 3b. an override may only rescue an unknown when it carries evidence and a name
    m3b = json.loads(json.dumps(m3))
    m3b["overrides"] = {k: {"spdx": "MIT"}}
    out = gate(m3b, pins, {})
    assert any(line.startswith(f"UNKNOWN  {k}") and "incomplete" in line for line in out), out
    m3b["overrides"] = {k: {"spdx": "MIT", "evidence": "sdist LICENSE", "accepted_by": "test", "date": "2026-01-01"}}
    assert not [line for line in gate(m3b, pins, {}) if line.startswith(f"UNKNOWN  {k}")]
    # 4. the normaliser reads the three PyPI shapes
    assert normalise("MIT", "", []) == ("MIT", "MIT")
    assert normalise("", "BSD-3-Clause", ["BSD License"])[1] == "BSD-3-Clause"
    assert normalise("", "", ["MIT License"])[1] == "MIT"
    assert normalise("", "", [])[1] == ""
    assert verdict("Apache-2.0 OR BSD-3-Clause") == "ok"
    assert verdict("MPL-2.0 AND MIT") == "weak-copyleft"
    assert verdict("GPL-3.0-or-later") == "copyleft"
    assert verdict("LGPL-2.1") == "copyleft"  # weak copyleft is still a question for a human, not a merge
    assert verdict("") == "unknown"
    # 5. an npm runtime dependency is refused until the gate learns npm licenses
    out = gate(manifest, pins, {"renderer/package.json": {"left-pad": "^1.0.0"}})
    assert any("npm left-pad" in line for line in out), out
    print(
        "SELF-TEST OK: a planted GPL pin, a copyleft spdx under a stale ok verdict, an unseen pin, an empty license field and an npm runtime dependency each fail by name"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--table", action="store_true")
    args = ap.parse_args()
    if args.refresh:
        refresh()
        return 0
    if args.self_test:
        self_test()
        return 0
    manifest = load_manifest()
    if args.table:
        print(table(manifest))
        return 0
    problems = gate(manifest, python_pins(), npm_runtime_deps())
    if problems:
        print("LICENSE GATE FAILED:")
        for line in problems:
            print("  " + line)
        return 1
    n = len(manifest["python"])
    weak = sorted(k for k, e in manifest["python"].items() if verdict(e["spdx"]) == "weak-copyleft")
    print(
        f"OK: {n} pinned Python packages carry MIT-compatible licenses ({len(weak)} MPL-2.0 file-level: {', '.join(weak)}); "
        "no runtime npm dependencies"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
