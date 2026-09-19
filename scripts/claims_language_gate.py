#!/usr/bin/env python3
"""Refuse prose that describes aspirational infrastructure as operating.

Sibling of ``internal_reference_gate.py`` and a separate module by design. That
gate detects a reference a reader cannot resolve: a task ID, a role handle, a
private repo, a bare tracker number, a developer's home directory. This gate
detects a claim whose words resolve but whose subject does not exist.

Three patterns, each matching a shape found in this tree:

1. ``coined-network`` — a network named as though it exists ("agent-internet",
   "internet of agents", "agentic web", "web of agents").
2. ``unowned-operator`` — operation attributed to no operator ("run by the
   network"). The negative lookahead is load-bearing: "run by the network
   administrator" names an operator and must not match.
3. ``citizenship-metaphor`` — "native citizen", "NANDA-native". Scoped tightly,
   and deliberately not a bare "citizen of the", which would match the ordinary
   idiom "a first-class citizen of the runtime". It also does not match
   "NANDA-ready", which is a claim about this project's own surfaces.

Scope: this catches coined nouns, absent operators and the citizenship metaphor.
It does not catch a planned feature written in the present tense, which is
ordinary English — no pattern separates "the detector emits divergence findings"
from the same sentence about a detector that is not wired up. Claims of that kind
are checked against evidence in ``docs/CLAIMS.md`` rather than by grammar.

The must-not-match cases in ``SELF_TEST_CASES`` carry the same weight as the
must-match ones. Each is correct prose that a careless pattern would block, and a
gate that blocks correct prose is removed rather than followed. Widening a
pattern requires adding the negative case that shows it did not overreach.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# ── The patterns ────────────────────────────────────────────────────────────

#: Networks named as though they exist. "agent-internet" and "agent internet"
#: are the same claim with different punctuation; both occurred.
COINED_NETWORK_RE = re.compile(
    r"\bagent[-\s]internet\b"
    r"|\binternet of agents\b"
    r"|\bagentic web\b"
    r"|\bweb of agents\b",
    re.IGNORECASE,
)

#: Operation attributed to no operator. The negative lookahead distinguishes
#: "run by the network administrator", which names one, from "run by the
#: network", which does not.
UNOWNED_OPERATOR_RE = re.compile(
    r"\b(?:run|runs|operated|hosted|maintained|governed)\s+by\s+the\s+"
    r"(?:network|mesh|ecosystem)\b"
    r"(?!\s+(?:admin\w*|operator|owner|team|provider|layer|node))",
    re.IGNORECASE,
)

#: The citizenship metaphor. Scoped to "native citizen" and "NANDA-native", not
#: a bare "citizen of the", which would match "a first-class citizen of the
#: runtime". Does not match "NANDA-ready", a claim about this project's own
#: surfaces.
CITIZENSHIP_RE = re.compile(
    r"\bnative citizen\b|\bNANDA[-\s]native\b",
    re.IGNORECASE,
)

PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "coined-network",
        COINED_NETWORK_RE,
        "a network named as though it exists. NANDA is a research project with "
        "artefacts: the Index (a registry you can resolve against), AgentFacts, "
        "NEST, host39. Name the artefact used and what this software does with "
        "it.",
    ),
    (
        "unowned-operator",
        UNOWNED_OPERATOR_RE,
        "infrastructure attributed to no operator. Name the operator, or describe "
        "the service as a deployment someone operates.",
    ),
    (
        "citizenship-metaphor",
        CITIZENSHIP_RE,
        "the citizenship metaphor. State what the software does — publishes "
        "AgentFacts, registers with and resolves through an Index — rather than "
        "what it belongs to.",
    ),
)

SKIP_DIRS = ("node_modules/", "__pycache__/", ".venv/")
SKIP_SUFFIXES = (
    ".lock",
    ".png",
    ".webp",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
)
SELF = "scripts/claims_language_gate.py"

#: Files that quote the retired phrasing as the record of a claim that was
#: removed. A historical record is not a live claim, and removing the quote from
#: one would remove the evidence that the correction happened.
#:
#: Currently empty: nothing in the tree quotes the retired wording. A file is
#: added here when the gate flags it and the quote is deliberate — for example a
#: changelog entry recording the removal of a claim.
QUOTING_ALLOWLIST: tuple[str, ...] = ()


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [
        f
        for f in out.split("\n")
        if f
        and f != SELF
        and not f.endswith(SELF)
        and f not in QUOTING_ALLOWLIST
        and not any(d in f for d in SKIP_DIRS)
        and not f.lower().endswith(SKIP_SUFFIXES)
    ]


def scan(files: list[str]) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or gone; nothing a reader will read as prose
        for label, pattern, _ in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append((name, line, label, match.group(0)))
    return findings


#: (text, expected-labels). Positives are wording that shipped in this tree.
#: Negatives are prose from the correction that replaced it; if one of them
#: starts matching, the pattern has widened too far.
SELF_TEST_CASES: tuple[tuple[str, set[str]], ...] = (
    # ── Positives: wording that shipped in this tree ──
    (
        "Orrery is a native citizen of the NANDA agent-internet, and extends it in kind",
        {"coined-network", "citizenship-metaphor"},
    ),
    (
        "NANDA agent-internet   (discovery + trust — run by the network)",
        {"coined-network", "unowned-operator"},
    ),
    ("- **Discoverable on the open agent-internet.**", {"coined-network"}),
    ("Get your business on the agent internet · NANDA", {"coined-network"}),
    ('title="Internet of agents",', {"coined-network"}),
    ("Orrery is a NANDA-native citizen: it registers, resolves", {"citizenship-metaphor"}),
    ("| **NANDA (Index, NEST, host39)** | The open agent-internet's discovery layer |", {"coined-network"}),
    # ── Positives: other instances of the same class ──
    ("the agentic web is here", {"coined-network"}),
    ("a web of agents, discoverable by anyone", {"coined-network"}),
    ("the trust layer is operated by the network", {"unowned-operator"}),
    ("discovery is maintained by the ecosystem", {"unowned-operator"}),
    ("records are hosted by the mesh", {"unowned-operator"}),
    # ── Negatives: prose from the correction ──
    ("Project NANDA is a research project with published artefacts", set()),
    ("the Index is a registry you can resolve against", set()),
    ("the NANDA Index, NEST and host39 are other people's deployments", set()),
    ("DISCOVERY SERVICES   (each one is a deployment someone operates)", set()),
    ("a registry is a service with an address, not a fabric", set()),
    ("The mesh is the federation between orgs running Orrery.", set()),
    ("Orrery publishes AgentFacts and resolves through the NANDA Index", set()),
    ("it registers with and resolves through the Index, and adds accountability", set()),
    ("Nobody operates a trust layer on your behalf", set()),
    ('<img src="https://img.shields.io/badge/NANDA-ready-7c3aed.svg" alt="NANDA-ready">', set()),
    # ── Negatives: ordinary prose a wider pattern would break ──
    ("the org is run by the network administrator", set()),
    ("agents run by the operator, not by us", set()),
    ("the service is maintained by the mesh operator", set()),
    ("MCP is a first-class citizen of the runtime", set()),
    ("on a host with a public address, to the internet", set()),
    ("Reaching your org from another machine over the internet", set()),
    ("A2A moves the messages; Orrery proves what happened", set()),
    ("independent orgs corroborating each other's records", set()),
)


def self_test() -> int:
    failures = []
    for text, expected in SELF_TEST_CASES:
        got = {label for label, pattern, _ in PATTERNS if pattern.search(text)}
        if got != expected:
            failures.append(
                f"  {text!r}\n    expected {sorted(expected) or 'no match'}, got {sorted(got) or 'none'}"
            )
    if failures:
        print(
            "SELF-TEST FAILED — the gate no longer detects what it claims:",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        return 1
    positives = sum(1 for _, expected in SELF_TEST_CASES if expected)
    negatives = len(SELF_TEST_CASES) - positives
    print(
        f"OK: self-test — {len(SELF_TEST_CASES)} cases "
        f"({positives} must-match, {negatives} must-NOT-match), both as declared"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the patterns still detect AND still leave correct prose alone, then exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    files = tracked_files()
    if len(files) < 100:
        print(
            f"REFUSING: only {len(files)} tracked files enumerated, which is too few to be the tree — "
            "`git ls-files` is not reaching it and a clean result here would mean nothing.",
            file=sys.stderr,
        )
        return 1

    findings = scan(files)
    if findings:
        reasons = {label: reason for label, _, reason in PATTERNS}
        print(
            f"::error::{len(findings)} aspirational-infrastructure claim(s) in a repository strangers read:",
            file=sys.stderr,
        )
        for name, line, label, text in findings:
            print(f"  {name}:{line}  [{label}]  {text}", file=sys.stderr)
        print("", file=sys.stderr)
        for label in sorted({f[2] for f in findings}):
            print(f"  [{label}] {reasons[label]}", file=sys.stderr)
        return 1

    print(
        f"OK: no coined networks, unowned operators, or citizenship metaphors "
        f"in {len(files)} tracked files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
