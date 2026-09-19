"""P1 / M-O2 — guard: no PostgREST filter may be baked into the table arg.

pg_request runs with the SERVICE_KEY (BYPASSRLS) and httpx does NOT
re-encode a filter that's already part of the table/resource string. So a
user-controlled value baked into the table arg (e.g.
``f"chapter_calls?id=eq.{call_id}"``) is injectable — an attacker's
``&status=`` / ``&select=*`` / ``&or=(…)`` / ``&limit=99999`` lands raw and
unencoded, RLS-bypassing. Every filter must ride in ``params=`` so httpx
percent-encodes the value.

That change fixed three named files; that change swept the rest. THIS test is the invariant
that stops the class from coming back — a new baked-filter sink fails CI.

That change hardened the guard so it can't be evaded:
  - scans RECURSIVELY (``rglob``), not just top-level ``server/*.py``, so a sink
    in a subpackage (``scripts/``, etc.) is caught;
  - detects the ``.format()``, ``%``-format, string-concatenation, AND
    interpolated-table forms, not only the literal-table f-string — the same
    injection works via ``"t?c=eq.{}".format(x)``, ``"t?c=eq.%s" % x``,
    ``"t?c=eq." + x``, or ``f"{tbl}?c=eq.{x}"``.

Classification: ADVERSARIAL / regression-guard.
"""

from __future__ import annotations

import pathlib
import re

import pytest

# PostgREST operators that introduce a baked filter value.
_OP = r"(?:eq|neq|in|lt|gt|gte|lte|like|ilike|is|cs|cd|ov|fts|plfts)"
# The injectable core: ``?<col>=<op>.`` inside a string literal. ``[^"']*``
# before the ``?`` also catches an interpolated TABLE name (f"{tbl}?id=eq.{x}").
_FILTER = rf'\?[A-Za-z_]\w*={_OP}\.'

# Every way a user value gets baked in right after ``?<col>=<op>.`` — all
# equally injectable because the value never reaches httpx's ``params=`` encoder:
#  1) f-string (literal or interpolated table):  f"chapter_calls?id=eq.{call_id}"
_BAKED_FSTRING = re.compile(rf'[fF]["\'][^"\']*{_FILTER}\{{')
#  2) str.format():   "chapter_calls?id=eq.{}".format(call_id)
_BAKED_FORMAT = re.compile(rf'["\'][^"\']*{_FILTER}\{{[^"\']*["\']\s*\.\s*format\s*\(')
#  3) %-format:       "chapter_calls?id=eq.%s" % call_id  (string, then % operator)
_BAKED_PERCENT = re.compile(rf'["\'][^"\']*{_FILTER}[^"\']*["\']\s*%\s*[A-Za-z_(\d]')
#  4) concatenation:  "chapter_calls?id=eq." + call_id
_BAKED_CONCAT = re.compile(rf'["\'][^"\']*{_FILTER}["\']\s*\+')

_PATTERNS = (_BAKED_FSTRING, _BAKED_FORMAT, _BAKED_PERCENT, _BAKED_CONCAT)

_SERVER_DIR = pathlib.Path(__file__).resolve().parent.parent


def _is_baked(line: str) -> bool:
    return any(p.search(line) for p in _PATTERNS)


def _production_py_files() -> list[pathlib.Path]:
    """Every production .py under server/, recursively — excluding the test
    suite (whose docstrings legitimately quote baked-filter examples) and
    bytecode caches."""
    out = []
    for path in sorted(_SERVER_DIR.rglob("*.py")):
        parts = set(path.relative_to(_SERVER_DIR).parts)
        if "tests" in parts or "__pycache__" in parts:
            continue
        out.append(path)
    return out


def test_no_baked_filter_supabase_sinks():
    offenders: list[str] = []
    files = _production_py_files()
    assert files, "recursive scan found no production files — the guard is not exercising anything"
    for path in files:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _is_baked(line):
                rel = path.relative_to(_SERVER_DIR)
                offenders.append(f"{rel}:{i}: {line.strip()[:120]}")
    assert not offenders, (
        "Baked PostgREST filter(s) found — route the filter through params= so httpx "
        "percent-encodes it (service-role injection class, that change):\n  " + "\n  ".join(offenders)
    )


# The guard is only as good as its detector. Pin that it catches all three
# injection forms and doesn't false-positive on the safe params= idiom.
@pytest.mark.parametrize(
    "snippet",
    [
        'await pg_request("GET", f"chapter_calls?id=eq.{call_id}")',
        "x = f'agents?agent_id=eq.{aid}'",
        'q = f"{tbl}?id=eq.{x}"',  # interpolated TABLE name
        'p = "chapter_calls?id=eq.{}".format(call_id)',
        'p = "agents?agent_id=eq.{0}".format(aid)',
        'p = "{}?id=eq.{}".format(tbl, x)',  # interpolated table via .format
        'p = "agents?agent_id=eq.%s" % aid',  # %-format
        'url = "chapter_calls?id=eq." + call_id',
        'url = "agents?agent_id=in." + ",".join(ids)',
    ],
)
def test_detector_flags_every_baked_form(snippet: str):
    assert _is_baked(snippet), f"detector missed an injectable sink: {snippet!r}"


@pytest.mark.parametrize(
    "snippet",
    [
        'await pg_request("GET", "agents", params={"agent_id": f"eq.{aid}"})',
        'q = "agents"',
        'params = {"id": "eq." + call_id}',  # value in params is encoded by httpx — safe
        'msg = f"Loaded {n} agents from chapter_calls"',  # no ?col=op. — not a filter
        'pat = "agents?name=ilike.%foo%"',  # literal LIKE wildcard, not %-formatting
        'u = f"GET {url}?page={n}"',  # query param, not a PostgREST filter
    ],
)
def test_detector_ignores_safe_forms(snippet: str):
    assert not _is_baked(snippet), f"detector false-positived on safe code: {snippet!r}"
