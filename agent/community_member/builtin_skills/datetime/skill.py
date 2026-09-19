"""Built-in 'datetime' skill — current date and time.

The simplest possible first-party skill: it declares **no capabilities**, so
it runs the moment the agent loads, with nothing to grant. It exists mostly
as the canonical example of the ``TOOLS`` export contract every skill follows:
a list of ``{name, description, parameters, fn}`` dicts where ``parameters`` is
a JSON Schema and ``fn(args) -> Any`` does the work.
"""

from __future__ import annotations

from datetime import datetime, timezone


def _now(args: dict) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "iso8601": now.isoformat(),
        "date": now.date().isoformat(),
        "time": now.strftime("%H:%M:%S"),
        "timezone": "UTC",
    }


def _today(args: dict) -> dict:
    return {"date": datetime.now(timezone.utc).date().isoformat(), "timezone": "UTC"}


TOOLS = [
    {
        "name": "now",
        "description": "Return the current date and time in UTC (ISO-8601 plus parts).",
        "parameters": {"type": "object", "properties": {}},
        "fn": _now,
    },
    {
        "name": "today",
        "description": "Return today's date (YYYY-MM-DD) in UTC.",
        "parameters": {"type": "object", "properties": {}},
        "fn": _today,
    },
]
