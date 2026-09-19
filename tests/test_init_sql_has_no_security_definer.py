"""No function in the schema runs with the table owner's privileges.

A ``SECURITY DEFINER`` function executes as the role that created it — the
superuser that ran ``init.sql`` — rather than as the caller, so any flaw in its
body is a flaw with full table-owner access and the application role's
least-privilege grants do not apply inside it. init.sql declared thirteen; all
were removed or made ``SECURITY INVOKER`` (migrations 0009 and 0010). This
guard holds the property for fresh installs: any function declared
``SECURITY DEFINER`` in init.sql fails the suite by name.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INIT_SQL = REPO / "infra" / "init.sql"


def security_definer_functions(sql: str) -> list[str]:
    """Names of functions whose CREATE FUNCTION carries SECURITY DEFINER."""
    out = []
    for m in re.finditer(
        r"CREATE (?:OR REPLACE )?FUNCTION (?:public\.)?(\w+)\s*\(", sql
    ):
        end = sql.find("$$;", m.end())
        if end == -1:
            end = sql.find(";", m.end())
        head = sql[m.start() : end]
        # The clause lives between the signature and the body opener.
        clauses = head.split("AS $$", 1)[0] if "AS $$" in head else head
        if re.search(r"\bSECURITY\s+DEFINER\b", clauses):
            out.append(m.group(1))
    return sorted(set(out))


def test_init_sql_declares_no_security_definer_function():
    found = security_definer_functions(INIT_SQL.read_text())
    assert not found, (
        "init.sql declares SECURITY DEFINER functions — each runs as the table owner, not the caller, "
        "so the application role's grants do not bound it. Drop the clause (SECURITY INVOKER) or the "
        "function: " + ", ".join(found)
    )


def test_the_scan_sees_functions():
    """A parse that matched nothing would make the guard above vacuously green."""
    sql = INIT_SQL.read_text()
    assert len(re.findall(r"CREATE (?:OR REPLACE )?FUNCTION", sql)) >= 10
    assert "update_updated_at_column" in sql


def test_the_scan_finds_a_planted_definer():
    sql = INIT_SQL.read_text() + (
        "\nCREATE FUNCTION public.zz_elevated() RETURNS trigger\n"
        "    LANGUAGE plpgsql SECURITY DEFINER\n    AS $$\nBEGIN RETURN NEW; END;\n$$;\n"
    )
    assert security_definer_functions(sql) == ["zz_elevated"]
    invoker = sql.replace("SECURITY DEFINER", "SECURITY INVOKER")
    assert security_definer_functions(invoker) == []
