"""Built-in 'files' skill — read/write/list files in a private workspace.

Declares ``fs.read`` + ``fs.write``. Neither is in ``HIGH_RISK_CAPABILITIES``
(that set reserves ``fs.any`` — unrestricted filesystem access); these two are
*scoped* by this skill to a single sandbox directory and so run without a
per-call consent prompt once granted.

The sandbox lives at ``CONFIG_DIR / "workspace"`` — the same unified agent
storage root as every other local DB/JSON (see config.CONFIG_DIR), so it moves
with ``COMMUNITY_MEMBER_HOME`` and never escapes to the real home dir. Every
path is resolved and checked with ``Path.is_relative_to`` so ``../`` and
sibling-prefix tricks (``workspace-evil/...``) can't climb out.
"""

from __future__ import annotations

from pathlib import Path

_MAX_READ_CHARS = 8000


def _workspace() -> Path:
    # Derive from the unified config root, NOT a fresh env read — keeps the
    # workspace co-located with the rest of agent storage.
    from community_member.config import CONFIG_DIR

    ws = (CONFIG_DIR / "workspace").resolve()
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def _resolve(rel: str) -> Path:
    """Resolve ``rel`` under the workspace, refusing any escape."""
    ws = _workspace()
    target = (ws / str(rel or "")).resolve()
    if target != ws and not target.is_relative_to(ws):
        raise ValueError("path escapes the agent workspace")
    return target


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(_workspace()))
    except ValueError:
        return str(p)


def _read_file(args: dict) -> dict:
    try:
        p = _resolve((args or {}).get("path", ""))
    except ValueError as exc:
        return {"error": str(exc)}
    if not p.is_file():
        return {"error": f"no such file: {_rel(p)}"}
    text = p.read_text(errors="replace")
    return {
        "path": _rel(p),
        "truncated": len(text) > _MAX_READ_CHARS,
        "content": text[:_MAX_READ_CHARS],
    }


def _write_file(args: dict) -> dict:
    args = args or {}
    try:
        p = _resolve(args.get("path", ""))
    except ValueError as exc:
        return {"error": str(exc)}
    if p.is_dir():
        return {"error": f"{_rel(p)} is a directory"}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(args.get("content", "")))
    return {"ok": True, "path": _rel(p), "bytes": p.stat().st_size}


def _list_dir(args: dict) -> dict:
    try:
        p = _resolve((args or {}).get("path", "."))
    except ValueError as exc:
        return {"error": str(exc)}
    if not p.is_dir():
        return {"error": f"no such directory: {_rel(p)}"}
    entries = sorted(e.name + ("/" if e.is_dir() else "") for e in p.iterdir())
    return {"path": _rel(p) or ".", "entries": entries}


TOOLS = [
    {
        "name": "read_file",
        "description": "Read a text file from the agent's private workspace.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative file path.",
                }
            },
            "required": ["path"],
        },
        "fn": _read_file,
    },
    {
        "name": "write_file",
        "description": "Write text to a file in the agent's private workspace (creates parent dirs).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative file path.",
                },
                "content": {"type": "string", "description": "Text content to write."},
            },
            "required": ["path", "content"],
        },
        "fn": _write_file,
    },
    {
        "name": "list_dir",
        "description": "List entries in a directory inside the agent's private workspace.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative dir (default '.').",
                }
            },
        },
        "fn": _list_dir,
    },
]
