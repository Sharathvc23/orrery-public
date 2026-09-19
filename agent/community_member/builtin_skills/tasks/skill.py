"""Built-in 'tasks' skill — a simple local to-do list.

State lives in ``CONFIG_DIR/tasks.json`` alongside the agent's other local
state (so it moves with COMMUNITY_MEMBER_HOME). First-party + offline; no
capabilities — it only touches its own state file, not the fs.* sandbox.
"""

from __future__ import annotations

import json


def _path():
    from community_member.config import CONFIG_DIR

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR / "tasks.json"


def _load() -> list[dict]:
    p = _path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else []
    except (ValueError, OSError):
        return []


def _save(items: list[dict]) -> None:
    _path().write_text(json.dumps(items, indent=2))


def _add(args: dict) -> dict:
    text = str((args or {}).get("text", "")).strip()
    if not text:
        return {"error": "text is required"}
    items = _load()
    next_id = max((t.get("id", 0) for t in items), default=0) + 1
    items.append({"id": next_id, "text": text, "done": False})
    _save(items)
    return {"added": {"id": next_id, "text": text}}


def _list(args: dict) -> dict:
    include_done = bool((args or {}).get("include_done", False))
    items = _load()
    shown = [t for t in items if include_done or not t.get("done")]
    return {"tasks": shown, "open": sum(1 for t in items if not t.get("done"))}


def _complete(args: dict) -> dict:
    try:
        tid = int((args or {}).get("id"))
    except (TypeError, ValueError):
        return {"error": "id must be an integer"}
    items = _load()
    for t in items:
        if t.get("id") == tid:
            t["done"] = True
            _save(items)
            return {"completed": tid}
    return {"error": f"no task with id {tid}"}


TOOLS = [
    {
        "name": "add_task",
        "description": "Add a task to the to-do list.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "What needs doing."}},
            "required": ["text"],
        },
        "fn": _add,
    },
    {
        "name": "list_tasks",
        "description": "List open tasks (set include_done=true to include completed ones).",
        "parameters": {
            "type": "object",
            "properties": {"include_done": {"type": "boolean"}},
        },
        "fn": _list,
    },
    {
        "name": "complete_task",
        "description": "Mark a task done by its id.",
        "parameters": {
            "type": "object",
            "properties": {"id": {"type": "integer", "description": "The task id from list_tasks."}},
            "required": ["id"],
        },
        "fn": _complete,
    },
]
