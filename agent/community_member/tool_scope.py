"""A tool SCOPE, and the minimal schema set it maps to.

WHY, MEASURED. A 26-tool block is 1,957 tokens — 91% of a first chat turn, and
85.9% of a measured ten-turn conversation. The legacy think loop costs 4,268
input tokens per cycle against think_v2's 1,403, and the 3.15x is entirely the
tool block: v1 ships 26 schemas, v2 ships one. That is the whole mechanism, and
it is already proven in this tree — ``planner_llm.plan_from_llm`` sends
``tools=[PROPOSE_ACTIONS_SCHEMA]`` and nothing else. This module generalises it
so a caller names what it needs rather than handing over everything it has.

⚠️ THE RISK IS A CAPABILITY REGRESSION WEARING A COST FIX'S CLOTHES. A scoped
set can omit the tool a turn actually needed, and the failure is invisible: the
model does not report a tool it was never shown, it just answers worse. Three
rules follow, and each is enforced rather than intended.

  THE GRANT-REQUEST TOOL IS ALWAYS PRESENT. Filtering by grant would otherwise
  make an ungranted capability permanently unreachable — the agent could not
  even ask for it, and a user watching it decline would have no path forward.
  ``ALWAYS_AVAILABLE`` is unioned in after every filter, never before, so no
  scope and no grant state can remove it.

  WHAT WAS WITHHELD IS REPORTED, NEVER SILENTLY ABSENT. ``ScopedTools.withheld``
  carries the names and the reason. A caller that drops it is choosing not to
  tell the user, which is a decision someone can see in review; a module that
  never produced it would make that decision for everyone, invisibly.

  A SCOPE NAMES ONLY TOOLS THAT EXIST. An unknown name in a scope means the
  scope silently shrinks as tools are renamed, which is the same failure as
  omitting one. ``unknown_names`` reports it and a test asserts it is empty for
  every registered scope.

Scoping is applied to the autonomous LOOPS first. A driven 20-cycle run
produced no durable output from the full set anyway, so the loops give up
nothing measurable. Interactive chat stays opt-in behind
``LLM_TOOL_SCOPE_CHAT`` — a person mid-conversation is exactly who notices a
missing capability, and exactly who cannot route around it.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ALWAYS_AVAILABLE",
    "REQUEST_GRANT_TOOL",
    "SCOPES",
    "SCOPE_CHAT",
    "SCOPE_FULL",
    "SCOPE_MINIMAL",
    "ScopedTools",
    "chat_scope_enabled",
    "scope_for",
    "select",
    "tool_names",
]

#: The tool a model uses to ask for a capability it does not hold. Always in
#: the set. Its schema is deliberately tiny — two string fields — because it is
#: paid for on every single request that uses any scope.
REQUEST_GRANT_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "request_grant",
        "description": (
            "Ask the user to grant a capability you do not currently hold. Use "
            "this when a task needs a tool that is not available to you."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "capability": {
                    "type": "string",
                    "description": "The capability or tool name being requested.",
                },
                "reason": {
                    "type": "string",
                    "description": "One sentence on why this task needs it.",
                },
            },
            "required": ["capability", "reason"],
        },
    },
}

#: Never removed by a scope or a grant filter.
ALWAYS_AVAILABLE: tuple[str, ...] = ("request_grant",)

SCOPE_FULL = "full"
SCOPE_MINIMAL = "minimal"
SCOPE_CHAT = "chat"

#: scope name -> the tool names it admits. ``SCOPE_FULL`` admits everything and
#: is the unchanged behaviour, kept as a named scope so "no scoping" is a
#: choice a call site states rather than the absence of one.
SCOPES: dict[str, tuple[str, ...] | None] = {
    SCOPE_FULL: None,
    # What an autonomous cycle demonstrably uses: look at the chapter, record
    # something, and ask for more if it needs it. The 20-cycle drive produced
    # no durable output from the other 20-odd tools.
    SCOPE_MINIMAL: (
        "search_chapter",
        "save_note",
    ),
    # A conversational turn plausibly reaches further — reading the chapter and
    # the federation, and acting on intents — but still not into installation,
    # settings or channel wiring, which a person does in the UI.
    SCOPE_CHAT: (
        "search_chapter",
        "search_federation",
        "get_chapter_intelligence",
        "submit_intent",
        "respond_to_intent",
        "list_conversations",
        "start_conversation",
        "save_note",
        "find_peer",
        "my_trust",
    ),
}

#: Opt-in for the interactive path. Unset, empty and unrecognised all read as
#: off, so narrowing a live conversation is never something a typo does.
CHAT_SCOPE_ENV = "LLM_TOOL_SCOPE_CHAT"
_TRUE = {"1", "true", "yes", "on"}


def chat_scope_enabled() -> bool:
    """Whether the interactive chat path narrows its tool block."""
    return os.environ.get(CHAT_SCOPE_ENV, "").strip().lower() in _TRUE


@dataclass(frozen=True)
class ScopedTools:
    """The tools to send, and an account of everything that was not sent."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    #: name -> why it was withheld. Rendered to the user, not just logged.
    withheld: dict[str, str] = field(default_factory=dict)
    #: Names a scope asked for that no available tool provides.
    unknown_names: tuple[str, ...] = ()
    scope: str = SCOPE_FULL

    @property
    def withheld_count(self) -> int:
        return len(self.withheld)

    def summary(self) -> str:
        """One line for a user, or empty when nothing was withheld.

        Phrased as a count plus the reason rather than a list: the list can run
        to twenty names, and a message nobody reads surfaces nothing.
        """
        if not self.withheld:
            return ""
        reasons = sorted({why for why in self.withheld.values()})
        return f"{len(self.withheld)} tools withheld ({', '.join(reasons)})"


def tool_names(tools: Iterable[dict[str, Any]]) -> list[str]:
    """The function names in a tool block, in order, skipping malformed entries."""
    names: list[str] = []
    for tool in tools or []:
        name = ((tool or {}).get("function") or {}).get("name")
        if name:
            names.append(str(name))
    return names


def scope_for(name: str | None) -> str:
    """A registered scope name, or ``SCOPE_FULL``.

    An unrecognised scope widens to full rather than narrowing to empty. A
    typo must not silently strip an agent of every tool — that failure looks
    like the model refusing to act and gives no clue why.
    """
    if name and name in SCOPES:
        return name
    return SCOPE_FULL


def select(
    available: Iterable[dict[str, Any]],
    *,
    scope: str = SCOPE_FULL,
    granted: Iterable[str] | None = None,
) -> ScopedTools:
    """The tool block for ``scope``, filtered by ``granted``.

    ``granted`` of None means "no grant ledger consulted" and filters nothing —
    an agent without a ledger keeps every tool its scope admits. Passing an
    empty collection is different and means "nothing is granted", which leaves
    only :data:`ALWAYS_AVAILABLE`.
    """
    available = list(available or [])
    resolved_scope = scope_for(scope)
    admitted = SCOPES.get(resolved_scope)

    by_name: dict[str, dict[str, Any]] = {}
    for tool in available:
        name = ((tool or {}).get("function") or {}).get("name")
        if name:
            by_name[str(name)] = tool

    withheld: dict[str, str] = {}
    selected: list[dict[str, Any]] = []
    for name, tool in by_name.items():
        if name in ALWAYS_AVAILABLE:
            continue  # unioned in below, so it cannot be filtered out here
        if admitted is not None and name not in admitted:
            withheld[name] = "out of scope"
            continue
        if granted is not None and name not in set(granted):
            withheld[name] = "pending grant"
            continue
        selected.append(tool)

    unknown = ()
    if admitted is not None:
        unknown = tuple(sorted(n for n in admitted if n not in by_name))

    # The grant-request tool goes in last and unconditionally. Prefer the
    # agent's own schema if it ships one, so a deployment can describe its own
    # grant flow, but never leave the capability absent.
    grant_tool = by_name.get("request_grant", REQUEST_GRANT_TOOL)
    selected.append(grant_tool)

    return ScopedTools(
        tools=selected,
        withheld=withheld,
        unknown_names=unknown,
        scope=resolved_scope,
    )
