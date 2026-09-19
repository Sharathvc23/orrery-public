"""AG-UI event constructors for the local chat stream.

AG-UI (Agent-User Interaction, https://docs.ag-ui.com) is the open event protocol
that standardises the streaming channel between an agentic backend and a
user-facing app. The member's chat stream speaks AG-UI so the SDK interoperates
with the AG-UI ecosystem (renderers, recorders, middleware) instead of a bespoke
event shape.

This module ships the event types the chat producer needs:

  Run lifecycle  — RunStarted, RunFinished, RunError
  Text message   — TextMessageStart, TextMessageContent, TextMessageEnd
  Tool call      — ToolCallStart, ToolCallArgs, ToolCallEnd, ToolCallResult

Field names are camelCase per the protocol; clients pattern-match on the stable
``type`` strings, so they MUST NOT change. Each event is emitted as one SSE
``data:`` line terminated by a blank line — the shape AG-UI consumers expect.
"""

from __future__ import annotations

import json
import time
import uuid

# Run lifecycle
EVENT_RUN_STARTED = "RunStarted"
EVENT_RUN_FINISHED = "RunFinished"
EVENT_RUN_ERROR = "RunError"
# Text message (assistant tokens)
EVENT_TEXT_MESSAGE_START = "TextMessageStart"
EVENT_TEXT_MESSAGE_CONTENT = "TextMessageContent"
EVENT_TEXT_MESSAGE_END = "TextMessageEnd"
# Tool call
EVENT_TOOL_CALL_START = "ToolCallStart"
EVENT_TOOL_CALL_ARGS = "ToolCallArgs"
EVENT_TOOL_CALL_END = "ToolCallEnd"
EVENT_TOOL_CALL_RESULT = "ToolCallResult"


def _ts() -> int:
    return int(time.time() * 1000)


def new_id() -> str:
    """A fresh opaque id for a run / message / tool call."""
    return uuid.uuid4().hex


def encode_sse(event: dict) -> bytes:
    """Encode one AG-UI event as an SSE ``data:`` line + blank-line terminator."""
    return f"data: {json.dumps(event, default=str)}\n\n".encode()


# ── Run lifecycle ───────────────────────────────────────────────────────


def run_started(*, run_id: str, thread_id: str) -> dict:
    return {"type": EVENT_RUN_STARTED, "runId": run_id, "threadId": thread_id, "timestamp": _ts()}


def run_finished(*, run_id: str) -> dict:
    return {"type": EVENT_RUN_FINISHED, "runId": run_id, "timestamp": _ts()}


def run_error(*, run_id: str, message: str, code: str | None = None) -> dict:
    return {"type": EVENT_RUN_ERROR, "runId": run_id, "message": message[:500], "code": code, "timestamp": _ts()}


# ── Text message ────────────────────────────────────────────────────────


def text_message_start(*, message_id: str, role: str = "assistant") -> dict:
    return {"type": EVENT_TEXT_MESSAGE_START, "messageId": message_id, "role": role, "timestamp": _ts()}


def text_message_content(*, message_id: str, delta: str) -> dict:
    return {"type": EVENT_TEXT_MESSAGE_CONTENT, "messageId": message_id, "delta": delta, "timestamp": _ts()}


def text_message_end(*, message_id: str) -> dict:
    return {"type": EVENT_TEXT_MESSAGE_END, "messageId": message_id, "timestamp": _ts()}


# ── Tool call ───────────────────────────────────────────────────────────


def tool_call_start(*, tool_call_id: str, tool_call_name: str, parent_message_id: str | None = None) -> dict:
    return {
        "type": EVENT_TOOL_CALL_START,
        "toolCallId": tool_call_id,
        "toolCallName": tool_call_name,
        "parentMessageId": parent_message_id,
        "timestamp": _ts(),
    }


def tool_call_args(*, tool_call_id: str, delta: str) -> dict:
    """``delta`` is a (possibly partial) chunk of the tool-call arguments JSON
    string — AG-UI streams arguments as text, parsed by the client on End."""
    return {"type": EVENT_TOOL_CALL_ARGS, "toolCallId": tool_call_id, "delta": delta, "timestamp": _ts()}


def tool_call_end(*, tool_call_id: str) -> dict:
    return {"type": EVENT_TOOL_CALL_END, "toolCallId": tool_call_id, "timestamp": _ts()}


def tool_call_result(*, tool_call_id: str, content: str, role: str = "tool") -> dict:
    return {
        "type": EVENT_TOOL_CALL_RESULT,
        "toolCallId": tool_call_id,
        "content": content,
        "role": role,
        "timestamp": _ts(),
    }
