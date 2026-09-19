"""docs/TRUST_MODEL.md cannot outlive its evidence.

The trust model ties every claim to a code symbol or a named test, written
inline as ``path::symbol``. A citation is only worth something while the thing
it names exists: a test that was renamed or deleted leaves the sentence it
supported reading exactly as before, and nothing about the page looks wrong.
So the citations are checked, not trusted.

What is checked, over the raw page:

``test_every_cited_file_exists``
    Every backticked token that names a tracked-file path resolves from the
    repository root.

``test_every_cited_symbol_exists_in_its_file``
    Every ``path::symbol`` names a ``def``, ``async def``, ``class`` or a
    module-level assignment in that file. A bare ``::symbol`` continues the
    most recent path, which is how the page cites several tests from one
    module without repeating it.

``test_the_page_cites_tests_and_code``
    The page has to carry citations at all, and of both kinds; a page whose
    citations were all edited out would otherwise pass the two checks above
    with nothing to check.

Backtick spans are read with newlines allowed inside them and their
whitespace collapsed before matching, because the prose is hard-wrapped and a
citation that lands on a line break must still be checked rather than
silently skipped — a skipped citation is one that can go stale unseen.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "TRUST_MODEL.md"

_SPAN = re.compile(r"`([^`]+)`", re.DOTALL)
_CITATION = re.compile(
    r"^(?P<path>[\w./-]+\.(?:py|md|sql|yml|yaml|json|sh))(?:::(?P<symbol>[\w.]+))?$"
)
_CONTINUATION = re.compile(r"^::(?P<symbol>[\w.]+)$")


def _resolve(path: str) -> Path:
    """A citation is repository-root relative; a bare document name is a
    sibling page under docs/, which is how this page links its neighbours."""
    candidate = REPO / path
    if not candidate.is_file() and "/" not in path:
        candidate = REPO / "docs" / path
    return candidate


def _citations() -> list[tuple[str, str | None]]:
    """(path, symbol-or-None) for every citation on the page, in order.

    A token starting with ``/`` is a URL path on the served API, not a file,
    and is not a citation."""
    text = PAGE.read_text(encoding="utf-8")
    found: list[tuple[str, str | None]] = []
    last_path: str | None = None
    for span in _SPAN.findall(text):
        token = "".join(span.split())
        if token.startswith("/"):
            continue
        if (m := _CITATION.match(token)) is not None:
            last_path = m.group("path")
            found.append((last_path, m.group("symbol")))
        elif (m := _CONTINUATION.match(token)) is not None:
            assert last_path is not None, (
                f"`{token}` continues no earlier path citation"
            )
            found.append((last_path, m.group("symbol")))
    return found


def _defines(source: str, symbol: str) -> bool:
    name = re.escape(symbol.split(".")[-1])
    pattern = re.compile(
        rf"^\s*(?:async\s+def|def|class)\s+{name}\b|^{name}\s*(?::|=)",
        re.MULTILINE,
    )
    return pattern.search(source) is not None


def test_every_cited_file_exists() -> None:
    missing = sorted({path for path, _ in _citations() if not _resolve(path).is_file()})
    assert not missing, (
        f"TRUST_MODEL.md cites file(s) that are not in the tree: {missing}"
    )


def test_every_cited_symbol_exists_in_its_file() -> None:
    missing: list[str] = []
    sources: dict[str, str] = {}
    for path, symbol in _citations():
        if symbol is None or not _resolve(path).is_file():
            continue
        if path not in sources:
            sources[path] = _resolve(path).read_text(encoding="utf-8")
        source = sources[path]
        present = _defines(source, symbol) if path.endswith(".py") else symbol in source
        if not present:
            missing.append(f"{path}::{symbol}")
    assert not missing, (
        "TRUST_MODEL.md cites symbol(s) its file no longer defines — "
        "the sentence each one supports has lost its evidence: "
        + ", ".join(sorted(set(missing)))
    )


def test_the_page_cites_tests_and_code() -> None:
    cited = _citations()
    tests = [s for p, s in cited if s and s.startswith("test_")]
    code = [
        s for p, s in cited if s and not s.startswith("test_") and p.endswith(".py")
    ]
    assert len(tests) >= 20, (
        f"expected the page to cite at least 20 named tests, found {len(tests)}"
    )
    assert len(code) >= 20, (
        f"expected the page to cite at least 20 code symbols, found {len(code)}"
    )
