"""Runtime glue — end-to-end v2 think loop.

This package composes the primitives shipped in:
  * community_member.planner       — typed context buckets
  * community_member.planner_llm   — LLM → Plan
  * community_member.executor      — Plan → gated execution
  * community_member.consent.gate  — per-action decision

into one entry point:

  runtime.think_v2(ctx, llm, *, model, runners, chapter_id) → results

An existing `agent.LocalAgent.think()` (the legacy single-LLM loop)
is left alone for backward compatibility. New code and the Electron
tray UI will opt into `think_v2`.
"""

from community_member.runtime.think_loop import (
    ThinkOutcome,
    make_think_outcome,
    think_v2,
)

__all__ = ["ThinkOutcome", "make_think_outcome", "think_v2"]
