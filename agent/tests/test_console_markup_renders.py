"""Every console.print() in the tree must be renderable by rich.

Rich parses each print call independently. A style tag opened in one call and
closed in the next is not a style that spans two lines — it is an unmatched
closing tag, and rich raises MarkupError when it renders it:

    console.print("  [dim]first half of a sentence")
    console.print("  second half.[/dim]")     # MarkupError, at run time

This reads as correct in the source, which is how three of them reached main.
One sat at wizard.py:546, inside step 5 of the 7-step first-run wizard and
before its individual/business branch, so the first run of `community-member`
raised on every path. The crash surfaced as a traceback about markup, because
the handler in cli.py reports failures with
`console.print(f"Error: {e}")` — and that message contained the offending tag,
so printing the error raised the same error again and the original was lost.

The existing wizard tests did not catch it: they assert on the values the
prompts return, with the console patched out, so no markup is ever rendered.
The defect is only in the rendering.

WHY THIS RENDERS RATHER THAN PATTERN-MATCHES: the verdict comes from the same
rich version that will run in production, not from a second implementation of
rich's grammar that could disagree with it.

DIRECTION OF FAILURE: a false alarm is the safe direction — it names a line, and
a human reads it. The unsafe direction is a call this cannot see, so the scan
covers what it can judge statically and no more: literal arguments, and the
literal parts of f-strings with each interpolation standing in as a placeholder
(so `f"[{color}]…[/{color}]"` is correctly read as balanced rather than as the
"[][/]" that dropping the slots would produce). A string built by other means —
concatenated at run time, or fetched from elsewhere — is NOT checked here.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from rich.errors import MarkupError
from rich.markup import render

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Method names on a rich Console that parse markup in their first arguments.
PRINT_METHODS = {"print", "log"}

SKIP_DIRS = {".venv", "venv", "node_modules", "build", "dist", ".git", "__pycache__"}


def _literal_texts(call: ast.Call) -> list[str]:
    """The statically-known text of each markup-parsing argument."""
    texts = []
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            texts.append(arg.value)
        elif isinstance(arg, ast.JoinedStr):
            texts.append(
                "".join(
                    v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "x" for v in arg.values
                )
            )
    return texts


def _console_print_calls() -> list[tuple[pathlib.Path, int, str]]:
    found = []
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr in PRINT_METHODS:
                for text in _literal_texts(node):
                    if "[" in text:
                        found.append((path, node.lineno, text))
    return found


def test_the_scan_can_see_console_prints():
    """A scan that finds nothing to check would pass while proving nothing.

    This is the failure mode the test below cannot detect on its own: if the
    walk stopped matching console.print calls — a rename, a helper, a moved
    package — every assertion would still pass, on an empty set.
    """
    calls = _console_print_calls()
    assert len(calls) > 100, (
        f"only {len(calls)} markup-bearing console.print calls found; the scan has "
        "probably stopped matching them rather than the calls having gone away"
    )


def test_every_console_print_renders():
    unrenderable = []
    for path, lineno, text in _console_print_calls():
        try:
            render(text)
        except MarkupError as exc:
            rel = path.relative_to(REPO_ROOT)
            unrenderable.append(f"{rel}:{lineno}: {exc}\n      {text[:90]!r}")

    assert not unrenderable, (
        "rich will raise MarkupError when these render:\n  "
        + "\n  ".join(unrenderable)
        + "\n\nA style tag cannot span two console.print calls — rich parses each one "
        "separately. Put the whole paragraph in a single call with embedded \\n."
    )


@pytest.mark.parametrize(
    "text",
    [
        "  second half of a sentence.[/dim]",  # the defect this test exists for
        "[bold]never closed [/italic]",  # a mismatched pair
    ],
)
def test_the_check_rejects_what_it_is_meant_to_reject(text):
    """The assertion above is only worth its runtime if it can fail.

    A green result means nothing unless the check refuses something; these are
    the shapes it must refuse.
    """
    with pytest.raises(MarkupError):
        render(text)
