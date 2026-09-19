"""Built-in 'calc' skill — evaluate an arithmetic expression.

Uses a restricted AST walk, NOT Python ``eval`` — only numbers and the basic
arithmetic operators are permitted, so a hostile expression can't call code,
read names, or escape. No capabilities required.
"""

from __future__ import annotations

import ast
import operator

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval(node: ast.AST) -> float:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError("only numbers are allowed")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left, right = _eval(node.left), _eval(node.right)
        if type(node.op) is ast.Pow:
            # Bound the EXPONENT (and base), not the source length — `9**9**9`
            # is a short string but computes an astronomically large int and
            # would spike CPU/memory. Cap before the multiply happens.
            if abs(right) > 1000 or abs(left) > 1e12:
                raise ValueError("exponent or base too large")
        return _BIN_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


def _calc(args: dict) -> dict:
    expr = str((args or {}).get("expression", "")).strip()
    if not expr:
        return {"error": "expression is required"}
    if len(expr) > 500:
        return {"error": "expression too long"}
    try:
        tree = ast.parse(expr, mode="eval")
        result = _eval(tree.body)
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError) as e:
        return {"error": f"could not evaluate: {type(e).__name__}: {e}"}
    return {"expression": expr, "result": result}


TOOLS = [
    {
        "name": "evaluate",
        "description": "Evaluate an arithmetic expression (e.g. '2 + 2 * 10', '(5-1)/2').",
        "parameters": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "The arithmetic expression.",
                }
            },
            "required": ["expression"],
        },
        "fn": _calc,
    },
]
