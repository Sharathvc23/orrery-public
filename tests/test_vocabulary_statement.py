"""The protocol-noun / product-noun mapping is stated once, and everything that
relies on it points at that one statement.

The org server implements the Chapter Protocol and the product calls the thing
an org. A reader of the code meets the protocol noun in routes, headers, tables
and module names, and the README says org; nothing about either looks wrong on
its own. So the mapping is written down exactly once, in
``docs/ARCHITECTURE.md`` under the heading these guards pin, and the places a
reader lands first — the server's main module, the agent package, the
vocabulary gate and the contributor rules — each carry a one-line pointer to
it.

A pointer is only worth something while its target exists and says what the
pointer promises, so:

``test_the_statement_exists_under_its_heading``
    The section is present, and it names the surfaces that carry the protocol
    noun as the code actually has them: every ``X-Chapter-*`` request header
    the federation signer uses, every ``chapter.*`` event name the event bus
    defines, and the number of ``chapter``-named tables in the schema. Those
    are read from the code, not from a list here, so a header or table added
    without a matching line in the statement is caught.

``test_every_pointer_names_the_statement``
    Each landing file names ``docs/ARCHITECTURE.md`` and the section, and each
    Markdown pointer links to the heading's actual anchor.

Files are read whitespace-normalized, because the prose and the docstrings are
hard-wrapped and a pointer split across a line break must still count as
present rather than as missing.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STATEMENT = REPO / "docs" / "ARCHITECTURE.md"
HEADING = "## Two nouns for one thing: protocol and product"
SECTION_NAME = "Two nouns"

#: Where a reader lands first, and therefore where the pointer has to be.
POINTERS = (
    "server/chapter_agent.py",
    "agent/community_member/__init__.py",
    "scripts/org_vocabulary_gate.py",
    "CONTRIBUTING.md",
    "docs/README.md",
    "docs/PRODUCT.md",
    "docs/GATES.md",
)


def _normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _anchor(heading: str) -> str:
    """GitHub's slug for a heading: lower-case, punctuation dropped, spaces to hyphens."""
    text = heading.lstrip("#").strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text)


def _section() -> str:
    text = STATEMENT.read_text(encoding="utf-8")
    assert HEADING in text, (
        f"{STATEMENT.relative_to(REPO)} no longer has the heading {HEADING!r}"
    )
    body = text.split(HEADING, 1)[1]
    next_heading = re.search(r"^## ", body, re.MULTILINE)
    return " ".join((body[: next_heading.start()] if next_heading else body).split())


def _headers_in_code() -> set[str]:
    source = (REPO / "server" / "federation_signing.py").read_text(encoding="utf-8")
    return set(re.findall(r'"(X-Chapter-[A-Za-z-]+)"', source))


def _event_names_in_code() -> set[str]:
    source = (REPO / "server" / "event_types.py").read_text(encoding="utf-8")
    return set(re.findall(r'"(chapter\.[a-z_.]+)"', source))


def _chapter_tables_in_schema() -> int:
    sql = (REPO / "infra" / "init.sql").read_text(encoding="utf-8")
    names = re.findall(
        r"CREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?(\w*chapter\w*)",
        sql,
        re.IGNORECASE,
    )
    return len(set(names))


def test_the_statement_exists_under_its_heading() -> None:
    section = _section()
    headers = _headers_in_code()
    assert headers, (
        "no X-Chapter-* headers found in server/federation_signing.py — the probe is broken"
    )
    for header in sorted(headers):
        assert header in section, f"the statement does not list request header {header}"
    events = _event_names_in_code()
    assert events, (
        "no chapter.* event names found in server/event_types.py — the probe is broken"
    )
    for event in sorted(events):
        assert event in section, f"the statement does not list event name {event}"
    tables = _chapter_tables_in_schema()
    assert tables > 0
    assert f"{tables} tables" in section, (
        f"the statement's table count must be {tables}, the number of chapter-named tables in infra/init.sql"
    )


def test_every_pointer_names_the_statement() -> None:
    anchor = _anchor(HEADING)
    for rel in POINTERS:
        text = _normalized(REPO / rel)
        assert "docs/ARCHITECTURE.md" in text or "ARCHITECTURE.md" in text, (
            f"{rel} does not point at the statement"
        )
        assert SECTION_NAME in text, (
            f"{rel} does not name the section ({SECTION_NAME!r})"
        )
        if rel.endswith(".md"):
            assert f"ARCHITECTURE.md#{anchor}" in text, (
                f"{rel} links to a different anchor than the heading's ({anchor})"
            )
