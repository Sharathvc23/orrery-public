#!/usr/bin/env python3
"""Refuse committed git conflict markers.

A conflict marker reached `main` and survived the reference gate, the claims
gate, ruff, sixteen CI jobs and review, because nothing looked for one. The
marker is mechanical: it is not a reference a reader cannot resolve, and it is
not a claim whose subject does not exist, so neither existing gate had any
reason to see it. That is why this is a third module rather than a check bolted
into one of the other two — those ask what the prose means, and this one asks
whether the file is intact. A module that did both would need a name that
described neither.

Marker forms, all four that git can write::

    <<<<<<< HEAD
    ours
    ||||||| merged common ancestors     (diff3 conflict style only)
    base
    =======
    theirs
    >>>>>>> some-ref

``<<<<<<<``, ``|||||||`` and ``>>>>>>>`` are seven characters at the start of a
line, optionally followed by a label. Nothing writes those shapes innocently, so
they are reported wherever they appear.

``=======`` is the hard one, and it is the reason this gate needs a rule rather
than a regex. Markdown's setext heading underline is a run of ``=``, so a
document containing::

    Summary
    =======

has a line that is byte-identical to a conflict separator. Three files in this
tree carry ``=`` rules today (``agent/community_member/host39.py``,
``scripts/run_server_tests.sh``, ``skill/NOTICE``); all are innocent. Two
signals separate the cases:

1. **Length.** A conflict separator is exactly seven ``=`` alone on the line. The
   rules in this tree are 27 to 80 characters long. Length alone is not enough,
   because a seven-character heading produces a seven-character underline.
2. **The pair.** A separator only exists inside a conflict, and a conflict always
   carries a ``<<<<<<<`` or a ``>>>>>>>`` somewhere in the same file. A bare
   ``=======`` in a file with neither is a heading rule.

Both must hold, so a document may use setext headings freely and a real conflict
is still caught by its opening or closing marker even if the separator is missed.

Known limit, stated rather than left to be discovered: a markdown file whose
blockquote nesting reaches exactly seven levels written without spaces
(``>>>>>>> text``) would be reported. No such line exists in this tree, and the
alternative — requiring the label to look like a git ref — would miss a marker
left by a hand-edited resolution.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: Opening, base and closing markers: seven characters, optionally labelled.
#: These shapes do not occur in ordinary text, so they are reported on sight.
UNAMBIGUOUS_RE = re.compile(r"^(?:<{7}|\|{7}|>{7})(?: .*)?$")

#: The separator. Exactly seven ``=`` alone on a line — a longer run is a
#: heading rule, never a marker.
SEPARATOR_RE = re.compile(r"^={7}$")

#: What makes a bare separator a conflict rather than a heading rule: the file
#: also holds an opening or closing marker.
PAIR_RE = re.compile(r"^(?:<{7}|>{7})(?: .*)?$", re.MULTILINE)

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
SELF = "scripts/conflict_marker_gate.py"


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
        and not any(d in f for d in SKIP_DIRS)
        and not f.lower().endswith(SKIP_SUFFIXES)
    ]


def findings_in(text: str) -> list[tuple[int, str, str]]:
    """(line, kind, text) for every conflict marker in ``text``.

    Separators are resolved against the whole file, not the line, which is the
    rule that keeps setext headings out of the results.
    """
    has_pair = bool(PAIR_RE.search(text))
    out: list[tuple[int, str, str]] = []
    for n, line in enumerate(text.split("\n"), 1):
        if UNAMBIGUOUS_RE.match(line):
            out.append((n, "marker", line[:80]))
        elif has_pair and SEPARATOR_RE.match(line):
            out.append((n, "separator", line))
    return out


def scan(files: list[str]) -> list[tuple[str, int, str, str]]:
    found: list[tuple[str, int, str, str]] = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or gone
        for line, kind, snippet in findings_in(text):
            found.append((name, line, kind, snippet))
    return found


#: (file body, expected findings). The negatives carry the weight here: every
#: one is a real file in this tree, and a gate that failed on them would be
#: removed rather than followed.
SELF_TEST_CASES: tuple[tuple[str, int], ...] = (
    # ── Positives ──
    ("<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> feature-branch\n", 3),
    # the marker that reached main, verbatim in shape
    (">>>>>>> d41dbad (fix(disclosure): require the issuer a bundle is checked against)\n", 1),
    ("<<<<<<< ours\na\n||||||| merged common ancestors\nb\n=======\nc\n>>>>>>> theirs\n", 4),
    # unlabelled markers, as a hand-edited resolution can leave them
    ("<<<<<<<\nours\n=======\ntheirs\n>>>>>>>\n", 3),
    # a separator counts once the file carries its pair, wherever it sits
    ("intro\n=======\nmore\n>>>>>>> ref\n", 2),
    # ── Negatives: setext heading rules, all three shapes present in this tree ──
    ("host39 publication\n===================================================\n", 0),
    ("Running the server suite\n" + "=" * 80 + "\n", 0),
    ("NOTICE\n===========\n", 0),
    # a seven-character heading underline: byte-identical to a separator, and
    # innocent because the file holds no opening or closing marker
    ("Summary\n=======\n\nText follows.\n", 0),
    # several of them, still innocent
    ("Summary\n=======\n\nDetails\n=======\n", 0),
    # ── Negatives: ordinary content that resembles a marker ──
    ("a < b and b > c\n", 0),
    ("<<< not seven\n", 0),
    (">>>>>>>> eight is not a marker\n", 0),
    ("======== eight equals is a rule\n", 0),
    ("    <<<<<<< HEAD\n", 0),  # indented: not how git writes one
    ("text with ======= inline stays inline\n", 0),
    ("|| logical or\n", 0),
    ("shell: cmd <<<<<<< here-string-ish\n", 0),
)


def self_test() -> int:
    failures = []
    for body, expected in SELF_TEST_CASES:
        got = len(findings_in(body))
        if got != expected:
            failures.append(f"  {body!r}\n    expected {expected} finding(s), got {got}")
    if failures:
        print(
            "SELF-TEST FAILED — the gate no longer detects what it claims:",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        return 1
    positives = sum(1 for _, e in SELF_TEST_CASES if e)
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
        help="prove the patterns still detect AND still leave heading rules alone, then exit",
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

    found = scan(files)
    if found:
        print(
            f"::error::{len(found)} git conflict marker(s) committed to the tree:",
            file=sys.stderr,
        )
        for name, line, kind, snippet in found:
            print(f"  {name}:{line}  [{kind}]  {snippet}", file=sys.stderr)
        print(
            "\n  A merge or rebase was resolved with the markers left in. Remove them and "
            "keep the intended side.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: no git conflict markers in {len(files)} tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
