"""Find every environment-variable read in a set of Python files.

Shared by ``test_env_flags_convention.py`` and usable on any path, so the guard
can be pointed at a temporary file to prove it still detects a new violation.

Recognised read forms:

  os.environ.get("NAME", ...)      os.getenv("NAME", ...)
  os.environ["NAME"]              env_flags.security_flag("NAME", default=...)

A name given as a module-level string constant (``os.environ.get(API_KEY_ENV)``)
is resolved to its value, because a scan that reported ``API_KEY_ENV`` would be
describing the variable that holds the name rather than the name itself.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

#: The call that records a security flag's direction of failure at the call site.
SECURITY_FLAG_FUNC = "security_flag"


@dataclass(frozen=True)
class EnvRead:
    name: str
    file: str
    line: int
    func: str
    via_security_flag: bool

    def __str__(self) -> str:
        return f"{self.name} at {self.file}:{self.line} in {self.func}()"


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.reads: list[EnvRead] = []
        self._func: list[str] = []
        self._consts: dict[str, str] = {}

    # ── module-level string constants, so an indirect name resolves ──
    def collect_constants(self, tree: ast.Module) -> None:
        for node in tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets, value = [node.target], node.value
            else:
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                for t in targets:
                    self._consts[t.id] = value.value

    def _name_of(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self._consts.get(node.id)
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._func.append(node.name)
        self.generic_visit(node)
        self._func.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _record(self, node: ast.AST, name: str | None, via_flag: bool) -> None:
        if not name:
            return
        self.reads.append(
            EnvRead(
                name=name,
                file=self.path.name,
                line=getattr(node, "lineno", 0),
                func=self._func[-1] if self._func else "<module>",
                via_security_flag=via_flag,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        attr = getattr(func, "attr", None) or getattr(func, "id", None)
        if attr == SECURITY_FLAG_FUNC and node.args:
            self._record(node, self._name_of(node.args[0]), True)
        elif attr in {"get", "getenv"} and node.args:
            owner = getattr(func, "value", None)
            owner_src = ast.dump(owner)[:80] if owner is not None else ""
            if attr == "getenv" or "environ" in owner_src:
                self._record(node, self._name_of(node.args[0]), False)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        if "environ" in ast.dump(node.value)[:80]:
            self._record(node, self._name_of(node.slice), False)
        self.generic_visit(node)


def scan_file(path: Path) -> list[EnvRead]:
    try:
        tree = ast.parse(path.read_text())
    except (SyntaxError, UnicodeDecodeError):
        return []
    scanner = _Scanner(path)
    scanner.collect_constants(tree)
    scanner.visit(tree)
    return scanner.reads


def scan_tree(root: Path, *, skip: tuple[str, ...] = ()) -> list[EnvRead]:
    reads: list[EnvRead] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in str(path) for part in skip):
            continue
        reads.extend(scan_file(path))
    return reads
