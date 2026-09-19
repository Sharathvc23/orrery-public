"""Every table init.sql creates is read by something. A table nothing reads must not regrow.

``infra/init.sql`` created 112 tables. Forty-five were referenced by no non-test
source anywhere in the repository — the fossil of the product this codebase was
before the agent-native pivot — and every self-hoster created them on first
boot. They are gone (migration 0009 drops them from existing databases, only
when empty). This guard holds the property: it parses every ``CREATE TABLE``
out of init.sql and fails, naming each one, for any table that no non-test
source references.

WHAT COUNTS AS A REFERENCE. The name as a whole word in any tracked non-test
source file other than init.sql itself — code, scripts, migrations, the seed,
compose, the installer. Documentation does not count: a table described in a
guide and read by nothing is exactly what this guard exists to catch. Inside
init.sql, a foreign key FROM a table that is itself referenced counts, so a
child table that only a live parent points at is live (computed to a fixed
point); a foreign key from one dead table to another does not rescue either.

The method is deliberately generous — a whole-word match anywhere in source —
so it cannot fail on a table that is merely read through a helper this file
does not know about. Its false negatives are tables whose name collides with
an ordinary word in code; those are a manual audit, not a guard's job.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INIT_SQL = REPO / "infra" / "init.sql"

_SOURCE_SUFFIXES = (
    ".py",
    ".sh",
    ".js",
    ".mjs",
    ".ts",
    ".tsx",
    ".sql",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
)
_TEST_DIR_NAMES = {"tests", "test", "__tests__"}


def _tables(sql: str) -> list[str]:
    return sorted(
        set(
            re.findall(
                r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?\"?([A-Za-z_][A-Za-z0-9_]*)\"?",
                sql,
            )
        )
    )


def _is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return (
        any(p in _TEST_DIR_NAMES for p in parts)
        or name.startswith("test_")
        or ".test." in name
    )


def _is_drop_migration(rel: str) -> bool:
    """A migration that REMOVES schema names every table it removes; that is
    not a reader, and counting it would let any dropped table come back
    unnoticed — re-adding one of the forty-five passed the first version of
    this guard for exactly that reason."""
    return rel.startswith("infra/migrations/") and "drop" in rel.rsplit("/", 1)[-1]


def _source_files() -> list[Path]:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    out = []
    for rel in tracked:
        if rel == "infra/init.sql" or _is_test_path(rel) or _is_drop_migration(rel):
            continue
        name = rel.rsplit("/", 1)[-1]
        if rel.endswith(_SOURCE_SUFFIXES) or name == "orrery-up" or "." not in name:
            out.append(REPO / rel)
    return out


def _word(name: str, text: str) -> bool:
    return (
        re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", text)
        is not None
    )


def _fk_edges(sql: str) -> list[tuple[str, str]]:
    """(child, parent) for every FOREIGN KEY ... REFERENCES in init.sql."""
    edges = []
    for m in re.finditer(
        r"ALTER TABLE (?:ONLY )?(?:public\.)?\"?(\w+)\"?\s+ADD CONSTRAINT \w+ FOREIGN KEY \([^)]*\) REFERENCES (?:public\.)?\"?(\w+)\"?",
        sql,
    ):
        edges.append((m.group(1), m.group(2)))
    for m in re.finditer(
        r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?\"?(\w+)\"? \((.*?)\n\);",
        sql,
        re.S,
    ):
        child, body = m.group(1), m.group(2)
        for ref in re.findall(r"REFERENCES (?:public\.)?\"?(\w+)\"?", body):
            edges.append((child, ref))
    return edges


def unreferenced_tables(sql: str, sources: list[Path]) -> list[str]:
    tables = _tables(sql)
    texts = []
    for p in sources:
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        if p.suffix == ".sql":
            # A name in an SQL comment is prose, not a reference.
            text = re.sub(r"--[^\n]*", "", text)
        texts.append(text)
    blob = "\n".join(texts)
    live = {t for t in tables if _word(t, blob)}
    edges = _fk_edges(sql)
    # A parent that a LIVE child points at is live; iterate to a fixed point.
    changed = True
    while changed:
        changed = False
        for child, parent in edges:
            if child in live and parent in tables and parent not in live:
                live.add(parent)
                changed = True
    return [t for t in tables if t not in live]


#: Tables the word-match above counts as referenced, but which no non-test
#: source uses AS A TABLE — the name matches an ordinary identifier or a JSON
#: key (``from chapter_agent import members as chapter_members``, a
#: ``"chapters"`` dict key, ``groups``/``connections``/``comments`` as plain
#: words). Recorded here, not dropped: the release drop was scoped to the
#: forty-five tables with no reference at all, and widening it widens the
#: compatibility matrix. Candidates for a second pass after the live row counts.
#: The test below keeps this list accurate in both directions: an entry that
#: gains a real table-shaped use, or loses its word match, has to leave.
REFERENCED_ONLY_BY_INCIDENTAL_WORDS = frozenset(
    {
        "chapters",
        "chapter_members",
        "comments",
        "connections",
        "group_members",
        "groups",
    }
)


def _table_shaped_refs(name: str, blob: str) -> bool:
    """Whether ``name`` is used AS A TABLE somewhere: a pg_request table
    argument, a TABLE constant, SQL text, or an rpc name."""
    patterns = (
        r"pg_request\(\s*(?:\"[A-Z]+\"|[a-z_]+),\s*\"" + re.escape(name) + r"\"",
        r"\b[A-Z_]*TABLE\s*=\s*\"" + re.escape(name) + r"\"",
        r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+(?:public\.)?" + re.escape(name) + r"\b",
        r"rpc/[a-z_]*" + re.escape(name),
        r"table\s*==\s*\"" + re.escape(name) + r"\"",
    )
    return any(re.search(p, blob) for p in patterns)


def test_every_table_in_init_sql_is_referenced_by_non_test_source():
    dead = unreferenced_tables(INIT_SQL.read_text(), _source_files())
    assert not dead, (
        "init.sql creates tables that no non-test source references — every self-hoster would create them "
        "on first boot for nothing. Either wire them to the code that needs them or remove them "
        "(and add a numbered drop migration): " + ", ".join(dead)
    )


def test_the_scan_sees_the_tables_it_is_guarding():
    """A parse that found nothing would make the guard above vacuously green."""
    tables = _tables(INIT_SQL.read_text())
    assert len(tables) >= 60, f"only {len(tables)} CREATE TABLEs parsed out of init.sql"
    assert "agents" in tables and "rate_limit_buckets" in tables


def test_a_drop_migration_does_not_count_as_a_reference():
    """The guard's own blind spot, held: every table 0009 drops is named in
    0009, and a reader-count that included it passed a re-added table."""
    sources = _source_files()
    assert not any(_is_drop_migration(str(p.relative_to(REPO))) for p in sources)
    assert (
        REPO / "infra" / "migrations" / "0009_drop_unreferenced_tables.sql"
    ).exists()
    sql = (
        INIT_SQL.read_text()
        + "\nCREATE TABLE public.startup_pitches (id uuid PRIMARY KEY);\n"
    )
    assert "startup_pitches" in unreferenced_tables(sql, sources)


def test_the_method_finds_a_planted_dead_table():
    """The guard, applied to a schema with a table nothing references."""
    sql = (
        INIT_SQL.read_text()
        + "\nCREATE TABLE public.zz_nothing_reads_this (id uuid PRIMARY KEY);\n"
    )
    assert unreferenced_tables(sql, _source_files()) == ["zz_nothing_reads_this"]


def test_the_incidental_word_list_is_accurate_in_both_directions():
    """Each listed table is still created, still matches a word somewhere, and
    still has no table-shaped use. Wire one up or drop it and this list must
    change with it — the debt stays visible and true."""
    sql = INIT_SQL.read_text()
    tables = set(_tables(sql))
    blob = "\n".join(
        p.read_text(errors="ignore") for p in _source_files() if p.is_file()
    )
    for name in sorted(REFERENCED_ONLY_BY_INCIDENTAL_WORDS):
        assert name in tables, (
            f"{name} is no longer created by init.sql — remove it from the list"
        )
        assert _word(name, blob), (
            f"{name} no longer matches any word in source — it is dead, not incidental"
        )
        assert not _table_shaped_refs(name, blob), (
            f"{name} now has a table-shaped use in source — it is live; remove it from the list"
        )
