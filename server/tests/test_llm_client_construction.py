"""One place builds an LLM client, and the AST is what says so.

WHY A GUARD RATHER THAN A CONVENTION. Eleven sites across both trees constructed
``OpenAI(...)`` directly — thirteen constructor calls, because two of them are
ternaries that construct twice. Each one decided its own base_url, its own key
fallback, its own retry count and its own timeout, and they disagreed:

  * an unrecognised provider resolved to ``https://api.openai.com/v1`` while
    still carrying whichever key happened to be set;
  * every site ran the SDK defaults ``max_retries=2`` and ``timeout=600``, so one
    logical call became three HTTP requests and could hold a cycle for ten
    minutes.

Routing those properties through one factory only helps if nothing bypasses it.
A comment saying "use build_client" is not enforcement — the previous tables also
had comments — so this walks the AST of both trees and fails on any ``OpenAI()``
call outside the factory itself. The set of allowed sites is DECLARED, so adding
one is a visible edit to this file rather than an invisible edit to any other.

Duplicated into both suites deliberately: the trees run in separate CI jobs
behind separate path filters, so a guard living on one side would let a
construction land unchecked on the other.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

#: The only functions permitted to construct a client, as ``path::function``.
#: Both entries are the same vendored file; neither is a second implementation.
ALLOWED = {
    "agent/community_member/llm_runtime.py::build_client",
    "server/llm_runtime.py::build_client",
}

#: Trees walked. Tests are excluded: a test may legitimately construct a stub or
#: assert against a real client, and forbidding that would push tests toward
#: mocking the factory instead of exercising it.
TREES = ("agent", "server")


def _constructions() -> list[tuple[str, int, str]]:
    """Every ``OpenAI(...)`` call in the shipped trees, as (file, line, function).

    Resolved from the AST rather than by grep, so a call inside a docstring — the
    resolver's own module quotes the defective line it replaces — is not counted,
    and a call split across lines still is.

    Attributed to the INNERMOST enclosing function. Walking every function and
    asking whether the call is somewhere beneath it reports one call once per
    nesting level, which turns thirteen constructions into seventeen lines and
    names functions that merely contain the one that constructs.
    """
    found: list[tuple[str, int, str]] = []
    for tree_name in TREES:
        for path in sorted((REPO / tree_name).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            if "/tests/" in f"/{rel}" or "/.venv/" in f"/{rel}":
                continue
            try:
                module = ast.parse(path.read_text())
            except SyntaxError:
                continue
            found.extend((rel, line, func) for line, func in _walk(module, "<module>"))
    return found


def _walk(node: ast.AST, enclosing: str) -> list[tuple[int, str]]:
    """Calls under ``node``, each attributed to the nearest function above it."""
    out: list[tuple[int, str]] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_walk(child, child.name))
            continue
        if isinstance(child, ast.Call) and getattr(child.func, "id", None) == "OpenAI":
            out.append((child.lineno, enclosing))
        out.extend(_walk(child, enclosing))
    return out


def test_only_the_resolver_constructs_an_llm_client():
    """Any OpenAI() outside the factory is a site that can drift from it.

    The failure names the file and line, because the fix is to call
    ``llm_runtime.build_client`` there rather than to add the site here.
    """
    offenders = sorted(
        f"{rel}:{line} (in {func})"
        for rel, line, func in _constructions()
        if f"{rel}::{func}" not in ALLOWED
    )
    assert not offenders, (
        "OpenAI() is constructed outside llm_runtime.build_client:\n  "
        + "\n  ".join(offenders)
        + "\nCall build_client instead — the endpoint, the provider-owned key, the "
        "retry cap and the timeout are properties of what it returns, and a direct "
        "construction gets none of them."
    )


def test_the_allowed_list_names_sites_that_exist():
    """A stale entry silently widens the guard.

    An allowed site that no longer constructs anything would sit here looking
    load-bearing, which is how an exemption list stops being reviewed.
    """
    constructed = {f"{rel}::{func}" for rel, _line, func in _constructions()}
    stale = sorted(ALLOWED - constructed)
    assert not stale, f"these allowed sites no longer construct a client: {stale}"


def test_the_factory_caps_retries_and_sets_a_timeout():
    """The reason the sites were centralised, asserted on the object returned.

    Every migrated site previously ran the SDK defaults, so a wedged provider was
    three requests and ten minutes rather than one and sixty seconds.
    """
    import llm_runtime

    client = llm_runtime.build_client(llm_runtime.resolve("ollama"))
    assert client.max_retries == llm_runtime.DEFAULT_MAX_RETRIES == 1
    assert client.timeout == llm_runtime.DEFAULT_TIMEOUT_S == 60.0
    assert client.max_retries != 2, "the SDK default retry count survived"


def test_the_retry_and_timeout_caps_are_overridable(monkeypatch):
    """Per deployment, not per call site."""
    import llm_runtime

    monkeypatch.setenv(llm_runtime.RETRIES_ENV, "4")
    monkeypatch.setenv(llm_runtime.TIMEOUT_ENV, "12.5")
    client = llm_runtime.build_client(llm_runtime.resolve("ollama"))
    assert client.max_retries == 4
    assert client.timeout == 12.5

    monkeypatch.setenv(llm_runtime.RETRIES_ENV, "not-a-number")
    assert llm_runtime.max_retries() == llm_runtime.DEFAULT_MAX_RETRIES
