"""
A2A JSON-RPC 2.0 dispatcher for tasks/* methods.

Wire protocol:
    POST {base_url}/
    Content-Type: application/json
    body: {"jsonrpc":"2.0","id":"1","method":"tasks/send","params":{...}}

Methods implemented in Day 2:
    tasks/send    — create/continue a task, invoke a tool, return the Task
    tasks/get     — fetch a task by id
    tasks/cancel  — request cancellation

Day 3 will add:
    tasks/sendSubscribe  — SSE streaming

Day 2 tool-invocation protocol:
    A `message.parts` list containing a single DataPart of shape
    {"type":"data","data":{"tool":"<name>","args":{...}}} is treated as a
    direct tool invocation. Any other shape returns a typed
    `input-required` task asking the caller for a data part.

    Free-text TextPart routing via LLM is deferred — we don't stub it.
    Returning input-required is the correct A2A signal for "I need a
    different kind of input to continue."
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .cosign import Cosigner

from . import a2a_auth
from .a2a_models import (
    Artifact,
    DataPart,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
    Message,
    Task,
    TaskArtifactUpdateEvent,
    TaskStatusUpdateEvent,
    TextPart,
)
from .task_store import TaskStore

#: The open methods, rendered for a human reading a refusal.
#:
#: ⚠️ DERIVED, NOT TYPED OUT. This sentence was a literal and it went stale the
#: moment ``tasks/cancel`` moved to caller-required: the refusal a caller got
#: for ``tasks/cancel`` named ``tasks/cancel`` as open, in the same string. A
#: refusal that contradicts itself is worse than a terse one — it tells the
#: caller the gate they just hit does not exist. Deriving it from the one
#: declaration in ``a2a_auth.METHOD_ACCESS`` makes that drift unrepresentable.
_OPEN_METHODS_PHRASE = ", ".join(sorted(a2a_auth.OPEN_METHODS))

_NOT_CREATOR_MESSAGE = (
    "task {task_id} was created by a different caller. Ownership is the key that created the "
    "task: continuing it or cancelling it requires signing as that key. It is the creating KEY, "
    f"not a known or trusted party — this runtime holds no registry of peers. Reads ({_OPEN_METHODS_PHRASE}) "
    "remain open."
)

_CALLER_REQUIRED_MESSAGE = (
    "{method} requires a verified caller: sign the request body with Ed25519 and send "
    "X-Agent-ID, X-Agent-Signature, X-Agent-Timestamp and X-Agent-DID-Key. Signing proves "
    "possession of the key you present, which makes the write attributable; it is not an "
    f"allowlist and any well-formed key verifies. Reads ({_OPEN_METHODS_PHRASE}) and both "
    "agent-card paths remain open."
)

#: Current-spec method names mapped to the v0.2 names this handler dispatches on.
#:
#: ⚠️ ONE TABLE, NOT A SECOND LITERAL IN EVERY ARM. The dispatch below is an
#: if-chain; adding the new name to each arm would give two places per method to
#: forget, and the one most easily forgotten is not the dispatch at all — it is
#: ``STREAMING_METHODS``, which decides whether the route streams before the
#: handler is ever reached. A streaming alias missing from that set is routed as
#: non-streaming and fails looking like a protocol bug rather than a wiring one.
#: Deriving the set from this mapping makes that particular mistake unavailable.
#:
#: v0.2 names keep working. The spec renamed the two methods that carry the
#: work — a2a_models.py still says "spec v0.2", which is what we pinned to —
#: and a current client sends only the new names.
METHOD_ALIASES: dict[str, str] = {
    "message/send": "tasks/send",
    "message/stream": "tasks/sendSubscribe",
}


def canonical_method(method: object) -> object:
    """The v0.2 name this handler dispatches on, for any accepted spelling."""
    return METHOD_ALIASES.get(method, method) if isinstance(method, str) else method


_STREAMING_CANONICAL = frozenset({"tasks/sendSubscribe", "tasks/resubscribe"})

#: Every spelling that must be routed as a stream — the canonical names and any
#: alias that resolves to one. Derived, so an alias cannot be added to the table
#: and forgotten here.
STREAMING_METHODS = _STREAMING_CANONICAL | frozenset(
    alias for alias, target in METHOD_ALIASES.items() if target in _STREAMING_CANONICAL
)

# JSON-RPC 2.0 standard error codes + A2A-specific ones.
# Add new codes when a handler actually emits them — do not pre-declare.
ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_TASK_NOT_FOUND = -32001
ERROR_TOOL_NOT_FOUND = -32002
ERROR_TOOL_FAILED = -32003
#: The caller did not prove an identity and the method requires one.
#: Implementation-defined range, following the codes above. The current A2A
#: error vocabulary has no authentication member (a2a-sdk 1.1.2 defines
#: InvalidParams / MethodNotFound / TaskNotFound / UnsupportedOperation and
#: nothing for a missing caller), so this is ours — but it is a JSON-RPC error
#: OBJECT, which is the part that matters: a stock client can read it, and a
#: bare 401 from a layer above the protocol is not something it can surface.
ERROR_CALLER_REQUIRED = -32004
#: The caller is verified but is not the caller that created this task.
#: Distinct from ERROR_CALLER_REQUIRED on purpose: "sign your request" and "that
#: is not yours" are different problems and a client should be able to tell them
#: apart without parsing prose.
ERROR_NOT_TASK_CREATOR = -32005

# Type alias for the tool dispatcher injected from agent.py
ToolDispatcher = Callable[[str, dict[str, Any]], Awaitable[str]]


#: Bytes of CSPRNG material per minted task id. ``secrets.token_urlsafe`` is the
#: same primitive this package already uses for unguessable identifiers
#: (``local_auth`` for the API token, ``owner`` for PKCE verifier and state), so
#: this reuses that choice rather than making a new one. 32 bytes is 256 bits,
#: rendered as 43 URL-safe characters.
TASK_ID_ENTROPY_BYTES = 32


def mint_task_id() -> str:
    """A task id the server chose, for a caller that did not supply one.

    ⚠️ THIS FUNCTION IS WHAT MAKES AN EARLIER DECISION TRUE OR FALSE. ``tasks/get``
    and ``tasks/cancel`` are deliberately OPEN — unauthenticated — and the stated
    reason is that task ids are unguessable. That reasoning was written when ids
    came from callers; the moment the server starts assigning them, this is the
    only thing keeping it true. A counter, a timestamp, a hash of the request, or
    anything else derived from what was sent would make every task on the agent
    enumerable by an anonymous reader.

    So: CSPRNG, no derivation from the request, and an entropy assertion in
    ``tests/test_a2a_server_assigned_task_id.py`` so shortening it later reddens
    a named test instead of quietly re-opening enumeration.
    """
    return secrets.token_urlsafe(TASK_ID_ENTROPY_BYTES)


def resolve_task_id(params: dict[str, Any], incoming: Message) -> str:
    """Which task this send belongs to.

    Same three-tier shape as ``resolve_context_id``, deliberately, so a reader
    who has understood one has understood both:

    1. ``params["id"]`` — the v0.2 caller names its task. Unchanged, and wins.
    2. ``message.taskId`` — a current-spec client CONTINUING a task. Without
       this arm a second turn silently began a new conversation: it returned a
       valid Task and a 200 while the caller believed it was still talking about
       the first one.
    3. Neither: mint, as a first turn does.

    ⚠️ AN UNKNOWN ID CREATES A TASK UNDER THAT ID RATHER THAN BEING REFUSED, and
    that is a decision, not what the code happened to do. It is exactly what
    ``params["id"]`` has always done, and refusing here would mean a caller who
    names a task can create one through arm 1 and not through arm 2 — the same
    request answered two ways depending on which field carried the name. A
    caller naming an id we do not hold is indistinguishable from a caller
    choosing an id, which is the contract a caller-supplied id already has.

    ⚠️ THERE IS NO OWNERSHIP CHECK, AND THIS ARM DOES NOT REMOVE ONE. Any
    verified caller who knows a task id can append a turn to it. That is
    PRE-EXISTING and measurable through arm 1 today: a second caller sending
    ``params["id"]`` for someone else's task is accepted and its message lands
    in that task's history. This arm opens a second door to the same room — it
    widens which CLIENTS can reach the behaviour, not what is possible, since
    both arms require an authenticated caller who already knows the id. Whether
    continuation should require ownership is a separate ruling, reported rather
    than decided here; building an authorization model inside a compatibility
    change is how one gets a bad one.
    """
    supplied = params.get("id")
    if supplied:
        return str(supplied)
    if incoming.taskId:
        return str(incoming.taskId)
    return mint_task_id()


def resolve_context_id(params: dict[str, Any], incoming: Message) -> str:
    """Which conversation this task belongs to.

    ⚠️ A DECISION, NOT A DEFAULT. The current spec uses ``contextId`` to GROUP
    related tasks, so the value carries meaning: two tasks in one conversation
    must share it and two unrelated tasks must not. Filling it with anything
    convenient — the task id, or a fresh mint every time — would satisfy the
    parser and destroy the grouping it exists for.

    Precedence:

    1. ``message.contextId`` from the caller. Same principle as a
       caller-supplied task id: whoever named the thing gets the name they
       chose, and a client continuing a conversation it started is the whole
       reason that field is on the request.
    2. ``sessionId``. Our v0.2 params already carry it and it already means
       "these belong together" in our own model, so mapping it recognises an
       existing concept rather than bolting on a parallel one. Two sends in one
       session therefore share a context without the caller doing anything.
    3. A mint, reusing ``mint_task_id``'s primitive rather than introducing a
       second identifier scheme. A caller who named nothing gets a context of
       its own, which is correct — nothing groups with it yet.
    """
    if incoming.contextId:
        return str(incoming.contextId)
    session_id = params.get("sessionId")
    if session_id:
        return str(session_id)
    return mint_task_id()


#: How many times a task with NO recorded creator has been appended to or
#: cancelled SINCE THIS PROCESS STARTED.
#:
#: ⚠️ THIS COUNTER IS THE WHOLE POINT OF ALLOWING THEM. Tasks created before
#: ownership was recorded carry no creator, and refusing them would break live
#: conversations on volumes that survived the deploy. Allowing them silently
#: would be a fail-open default that never expires on its own — the exact defect
#: class this surface has spent a week closing.
#:
#: ⚠️ AND IT IS THE WRONG NUMBER FOR THE FLIP-TO-DENY RULING. It was written as
#: if it were, and it is not, for three reasons that all point the same way:
#: it is a module-level int, so it RESETS TO 0 ON EVERY PROCESS START and is
#: neither cumulative nor comparable between two readings of a fleet that
#: redeploys; it counts APPENDS TO creatorless tasks, which is a different
#: population from creatorless tasks that EXIST; and its zero is ambiguous in
#: the direction that matters, because a freshly booted process reports 0
#: whether the legacy population is empty or enormous. An operator reading it as
#: "nothing to deny" would be reading a fail-open default as permission to
#: close one.
#:
#: The number the ruling needs is :meth:`TaskStore.census`, which counts records
#: that exist and is recomputed from the replayed log rather than accumulated in
#: memory. Both are published by ``nanda/legacyTaskCensus``, in separately named
#: objects, so neither can be read under the other's name. That flip is still a
#: ruling, not something this module decides.
legacy_tasks_without_creator = 0

#: When this process started, so a reader of the since-boot counter above can
#: tell whether "since boot" is five minutes or five weeks. A counter that
#: silently resets is worse than one that announces it does; this is the
#: announcement.
_PROCESS_BOOTED_AT = datetime.now(UTC).isoformat()


def legacy_task_census(store: TaskStore) -> dict[str, Any]:
    """What this agent can and cannot say about its creatorless tasks.

    Two objects, deliberately not merged into one flat number:

    ``measurement`` is counted from records that exist and survives a restart.
    ``observation`` is what this process happened to see and does not.

    They are separate because their zeros mean opposite things and the ruling
    they feed turns on which zero is being read. Nothing here decides whether
    a caller is known or trusted; a creator is a did:key compared to a did:key,
    and this surface only counts how many tasks have none.
    """
    measured = store.census()
    return {
        "measurement": {
            **measured,
            "durable": True,
            "means": (
                "Tasks this agent's store holds that carry no creator did:key, recounted from the "
                "on-disk log at every read, so a restart does not reset it. This is the exact "
                "population a flip-to-deny would refuse on this agent — not a sample of it. A zero "
                "here is a measured absence: there are no creatorless tasks to deny. "
                "'unreadable_log_lines' is the only way this can understate the file; a task on "
                "such a line is absent from the store and so is outside the ownership check too."
            ),
        },
        "observation": {
            "appends_to_creatorless_tasks_since_boot": legacy_tasks_without_creator,
            "durable": False,
            "process_booted_at": _PROCESS_BOOTED_AT,
            "means": (
                "How many writes to creatorless tasks THIS PROCESS has seen. It resets to 0 on "
                "every start, so a zero here means 'nothing observed since boot' and NOT 'no "
                "creatorless tasks exist'. Read measurement.creatorless_tasks_present for that."
            ),
        },
        "scope": (
            "This agent only. No agent can see another's tasks, so the fleet answer is the sum of "
            "measurement.creatorless_tasks_present across agents, each read separately. Counts "
            "only: this surface never returns task ids, so it answers 'how many' without "
            "disclosing which."
        ),
    }


def _creator_permits(task: Any, caller: Any) -> bool:
    """Whether ``caller`` may write to ``task``.

    Ownership is "the key that created it", nothing more. There is no registry
    of peer keys and no allowlist: a did:key is compared to a did:key. Whether a
    given key is TRUSTED is a different question that this runtime cannot answer
    and must not pretend to.
    """
    global legacy_tasks_without_creator

    creator = getattr(task, "creatorDidKey", None)
    if not creator:
        legacy_tasks_without_creator += 1
        print(
            f"[a2a] task {task.id} has no recorded creator — allowing this write and counting it "
            f"(legacy tasks written to since boot: {legacy_tasks_without_creator})"
        )
        return True
    return bool(caller) and getattr(caller, "did_key", None) == creator


class A2ARPCHandler:
    """Stateful per-process handler wrapping a TaskStore + tool dispatcher."""

    def __init__(
        self,
        store: TaskStore,
        dispatcher: ToolDispatcher,
        cosigner: Cosigner | None = None,
    ) -> None:
        self.store = store
        self.dispatcher = dispatcher
        # Witness (B) side of the co-sign handshake (spec/arp/0.2/cosign-companion.md).
        # When set, this agent will co-sign receipts on which it is the named
        # counterparty. When ``None``, ``nanda/cosignReceipt`` returns a decline
        # (no witness) — the issuer's receipt is simply uncorroborated, not failed.
        self.cosigner = cosigner

    async def handle(self, request_body: dict[str, Any], caller: Any = None) -> dict[str, Any]:
        """Parse the JSON-RPC envelope and route to the right method.

        Always returns a JSON-RPC response dict (never raises). Errors are
        returned in the standard `error` envelope so A2A clients can inspect
        them programmatically.

        ``caller`` is the verified identity from ``a2a_auth.verify_caller``, or
        None for an unauthenticated request. The gate lives HERE rather than in
        the route because the refusal has to be a JSON-RPC error object — a
        middleware 401 arrives from a layer above the protocol and a stock
        client cannot surface it — and because a future direct caller of this
        handler would otherwise bypass the check entirely.
        """
        # Envelope parse
        try:
            req = JSONRPCRequest.model_validate(request_body)
        except Exception as e:
            return _rpc_error(None, ERROR_INVALID_REQUEST, f"Invalid JSON-RPC envelope: {e}")

        params = req.params if isinstance(req.params, dict) else {}
        method = canonical_method(req.method)

        if caller is None and a2a_auth.requires_caller(method):
            return _rpc_error(req.id, ERROR_CALLER_REQUIRED, _CALLER_REQUIRED_MESSAGE.format(method=req.method))

        if method == "tasks/send":
            return await self._tasks_send(req.id, params, caller)
        if method == "tasks/get":
            return self._tasks_get(req.id, params)
        if method == "tasks/cancel":
            return self._tasks_cancel(req.id, params, caller)
        if method == "nanda/cosignReceipt":
            return self._cosign_receipt(req.id, params)
        if method == "nanda/legacyTaskCensus":
            return _rpc_ok(req.id, legacy_task_census(self.store))

        return _rpc_error(req.id, ERROR_METHOD_NOT_FOUND, f"Unknown method: {req.method}")

    # ─── method handlers ────────────────────────────────

    async def _tasks_send(self, rpc_id, params: dict[str, Any], caller: Any = None) -> dict[str, Any]:
        raw_msg = params.get("message")
        if not isinstance(raw_msg, dict):
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing required param: message")
        try:
            incoming = Message.model_validate(raw_msg)
        except Exception as e:
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, f"Invalid message: {e}")

        if incoming.role != "user":
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, "message.role must be 'user' for tasks/send")

        # Resolved AFTER the message is validated, because arm 2 reads it.
        task_id = resolve_task_id(params, incoming)

        # ⚠️ CHECKED BEFORE store.create, WHICH IS WHERE THE APPEND HAPPENS.
        # ``create`` treats a known id as a continuation, so by the time it
        # returns the write has already landed — the ownership question has to
        # be asked while the answer can still change anything.
        existing = self.store.get(task_id)
        if existing is not None and not _creator_permits(existing, caller):
            return _rpc_error(rpc_id, ERROR_NOT_TASK_CREATOR, _NOT_CREATOR_MESSAGE.format(task_id=task_id))

        task = self.store.create(
            task_id=task_id,
            session_id=params.get("sessionId"),
            initial_message=incoming,
            metadata=params.get("metadata"),
            context_id=resolve_context_id(params, incoming),
            creator_did_key=getattr(caller, "did_key", None) or None,
        )

        tool_call = _extract_tool_call(incoming)
        if tool_call is None:
            # No DataPart with tool+args → ask the caller to refine.
            reply = Message(
                role="agent",
                parts=[
                    TextPart(
                        text=(
                            "Send a DataPart with {tool: <name>, args: {...}} to invoke "
                            "an agent tool. Free-text routing lands in a future sprint."
                        )
                    )
                ],
            )
            task = self.store.transition(task_id, "input-required", agent_reply=reply)
            return _rpc_ok(rpc_id, task)

        tool_name, tool_args = tool_call
        try:
            raw_result = await self.dispatcher(tool_name, tool_args)
        except KeyError:
            task = self.store.transition(
                task_id,
                "failed",
                agent_reply=Message(
                    role="agent",
                    parts=[TextPart(text=f"Unknown tool: {tool_name}")],
                ),
            )
            return _rpc_error(
                rpc_id, ERROR_TOOL_NOT_FOUND, f"Unknown tool: {tool_name}", data=task.model_dump(mode="json")
            )
        except Exception as e:
            task = self.store.transition(
                task_id,
                "failed",
                agent_reply=Message(
                    role="agent",
                    parts=[TextPart(text=f"Tool execution failed: {e}")],
                ),
            )
            return _rpc_error(
                rpc_id, ERROR_TOOL_FAILED, f"Tool execution failed: {e}", data=task.model_dump(mode="json")
            )

        # Normalise result into an Artifact. Our tools return JSON strings;
        # A2A clients can treat that as the artifact payload directly.
        artifact = Artifact(
            name=f"tool-result:{tool_name}",
            parts=[DataPart(data={"tool": tool_name, "result": raw_result})],
            lastChunk=True,
        )
        task = self.store.transition(
            task_id,
            "completed",
            artifact=artifact,
            agent_reply=Message(
                role="agent",
                parts=[TextPart(text=f"Invoked {tool_name}.")],
            ),
        )
        return _rpc_ok(rpc_id, task)

    def _tasks_get(self, rpc_id, params: dict[str, Any]) -> dict[str, Any]:
        task_id = params.get("id")
        if not task_id:
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing required param: id")
        task = self.store.get(task_id)
        if task is None:
            return _rpc_error(rpc_id, ERROR_TASK_NOT_FOUND, f"Task not found: {task_id}")
        return _rpc_ok(rpc_id, task)

    def _tasks_cancel(self, rpc_id, params: dict[str, Any], caller: Any = None) -> dict[str, Any]:
        task_id = params.get("id")
        if not task_id:
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing required param: id")
        # Ownership before destruction. `store.cancel` is idempotent but not
        # reversible, so the check cannot live after it.
        existing = self.store.get(task_id)
        if existing is not None and not _creator_permits(existing, caller):
            return _rpc_error(rpc_id, ERROR_NOT_TASK_CREATOR, _NOT_CREATOR_MESSAGE.format(task_id=task_id))
        task = self.store.cancel(task_id)
        if task is None:
            return _rpc_error(rpc_id, ERROR_TASK_NOT_FOUND, f"Task not found: {task_id}")
        return _rpc_ok(rpc_id, task)

    def _cosign_receipt(self, rpc_id, params: dict[str, Any]) -> dict[str, Any]:
        """Witness (B) side of the co-sign handshake (cosign-companion.md §1).

        The issuer sends its **unsigned** receipt; if this agent is the named,
        distinct counterparty, return a ``witness`` entry it can insert before
        finalizing. Otherwise return ``{"witness": null}`` — a successful RPC
        carrying a *decline*, so the issuer's receipt stays valid but
        uncorroborated (§3) rather than the interaction erroring out.

        Only the receipt is malformed-or-missing is a real JSON-RPC error; not
        being the counterparty, or having no cosigner configured, is a decline.
        """
        receipt = params.get("receipt")
        if not isinstance(receipt, dict):
            return _rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing or invalid param: receipt")
        if self.cosigner is None:
            return _rpc_ok(rpc_id, {"witness": None})
        entry = self.cosigner(receipt)
        return _rpc_ok(rpc_id, {"witness": entry})

    # ─── streaming (tasks/sendSubscribe, tasks/resubscribe) ─────

    async def stream(self, request_body: dict[str, Any], caller: Any = None) -> AsyncGenerator[str, None]:
        """Yield SSE-formatted 'data: {...}\\n\\n' lines for streaming methods.

        Protocol:
          - Each event is a JSON-RPC response whose `result` is either
            a TaskStatusUpdateEvent or TaskArtifactUpdateEvent.
          - The terminal event has status.final=true.
          - Any envelope error (bad method, bad params) is emitted as a
            single error response and the stream closes.

        Non-streaming error paths still emit valid SSE so clients reading
        the stream get a typed error, not a broken connection.
        """
        try:
            req = JSONRPCRequest.model_validate(request_body)
        except Exception as e:
            yield _sse_event(_rpc_error(None, ERROR_INVALID_REQUEST, f"Invalid JSON-RPC envelope: {e}"))
            return

        rpc_id = req.id
        params = req.params if isinstance(req.params, dict) else {}
        method = canonical_method(req.method)

        if caller is None and a2a_auth.requires_caller(method):
            # Refused INSIDE the stream, as an SSE frame carrying a JSON-RPC
            # error. A client that has already opened an event stream is not
            # reading a status code any more.
            yield _sse_event(
                _rpc_error(rpc_id, ERROR_CALLER_REQUIRED, _CALLER_REQUIRED_MESSAGE.format(method=req.method))
            )
            return

        if method == "tasks/sendSubscribe":
            async for frame in self._stream_send(rpc_id, params, caller):
                yield frame
            return
        if method == "tasks/resubscribe":
            async for frame in self._stream_resubscribe(rpc_id, params):
                yield frame
            return

        yield _sse_event(_rpc_error(rpc_id, ERROR_METHOD_NOT_FOUND, f"Unknown streaming method: {req.method}"))

    async def _stream_send(self, rpc_id, params: dict[str, Any], caller: Any = None) -> AsyncGenerator[str, None]:
        # Same inversion as the non-streaming send: a streaming send from a
        # current-spec client carries no id either, and every frame it emits
        # names the task, so minting here is what makes those frames addressable.
        raw_msg = params.get("message")
        if not isinstance(raw_msg, dict):
            yield _sse_event(_rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing required param: message"))
            return
        try:
            incoming = Message.model_validate(raw_msg)
        except Exception as e:
            yield _sse_event(_rpc_error(rpc_id, ERROR_INVALID_PARAMS, f"Invalid message: {e}"))
            return

        if incoming.role != "user":
            yield _sse_event(_rpc_error(rpc_id, ERROR_INVALID_PARAMS, "message.role must be 'user'"))
            return

        task_id = resolve_task_id(params, incoming)

        existing = self.store.get(task_id)
        if existing is not None and not _creator_permits(existing, caller):
            yield _sse_event(_rpc_error(rpc_id, ERROR_NOT_TASK_CREATOR, _NOT_CREATOR_MESSAGE.format(task_id=task_id)))
            return

        # ── submitted → working ──
        task = self.store.create(
            task_id=task_id,
            session_id=params.get("sessionId"),
            initial_message=incoming,
            metadata=params.get("metadata"),
            context_id=resolve_context_id(params, incoming),
            creator_did_key=getattr(caller, "did_key", None) or None,
        )
        yield _sse_status(rpc_id, task, final=False)

        # Transition to working immediately so clients see the state move
        task = self.store.transition(task_id, "working")
        yield _sse_status(rpc_id, task, final=False)

        # ── dispatch the tool ──
        tool_call = _extract_tool_call(incoming)
        if tool_call is None:
            reply = Message(
                role="agent",
                parts=[TextPart(text="Send a DataPart with {tool, args} to invoke a tool.")],
            )
            task = self.store.transition(task_id, "input-required", agent_reply=reply)
            yield _sse_status(rpc_id, task, final=True)
            return

        tool_name, tool_args = tool_call
        try:
            raw_result = await self.dispatcher(tool_name, tool_args)
        except KeyError:
            reply = Message(role="agent", parts=[TextPart(text=f"Unknown tool: {tool_name}")])
            task = self.store.transition(task_id, "failed", agent_reply=reply)
            yield _sse_status(rpc_id, task, final=True)
            return
        except Exception as e:
            reply = Message(role="agent", parts=[TextPart(text=f"Tool execution failed: {e}")])
            task = self.store.transition(task_id, "failed", agent_reply=reply)
            yield _sse_status(rpc_id, task, final=True)
            return

        # ── emit artifact, then final completed status ──
        artifact = Artifact(
            name=f"tool-result:{tool_name}",
            parts=[DataPart(data={"tool": tool_name, "result": raw_result})],
            lastChunk=True,
        )
        task = self.store.transition(
            task_id,
            "completed",
            artifact=artifact,
            agent_reply=Message(role="agent", parts=[TextPart(text=f"Invoked {tool_name}.")]),
        )
        yield _sse_artifact(rpc_id, task, artifact)
        yield _sse_status(rpc_id, task, final=True)

    async def _stream_resubscribe(self, rpc_id, params: dict[str, Any]) -> AsyncGenerator[str, None]:
        """Reconnect to an existing task's stream.

        For Day 3 our tasks are synchronous so by the time a resubscribe
        lands the task is almost always terminal. We emit the current
        status (final=true if terminal), plus any artifacts the task
        already accumulated.
        """
        task_id = params.get("id")
        if not task_id:
            yield _sse_event(_rpc_error(rpc_id, ERROR_INVALID_PARAMS, "Missing required param: id"))
            return
        task = self.store.get(task_id)
        if task is None:
            yield _sse_event(_rpc_error(rpc_id, ERROR_TASK_NOT_FOUND, f"Task not found: {task_id}"))
            return

        for art in task.artifacts:
            yield _sse_artifact(rpc_id, task, art)

        is_terminal = task.status.state in ("completed", "canceled", "failed", "input-required")
        yield _sse_status(rpc_id, task, final=is_terminal)


# ─── Helpers ────────────────────────────────────────────


def _extract_tool_call(message: Message) -> tuple[str, dict[str, Any]] | None:
    """Return (tool_name, args) if the message carries a DataPart in the
    documented invocation shape, else None."""
    for part in message.parts:
        if isinstance(part, DataPart):
            data = part.data
            if isinstance(data, dict):
                tool = data.get("tool")
                args = data.get("args", {})
                if isinstance(tool, str) and tool and isinstance(args, dict):
                    return tool, args
    return None


def rpc_error(rpc_id, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Public helper so other modules (e.g. server.py) can emit valid
    JSON-RPC errors for envelope-level problems (e.g. JSON parse failure)."""
    return _rpc_error(rpc_id, code, message, data)


def _rpc_ok(rpc_id, result: Task | dict[str, Any]) -> dict[str, Any]:
    if isinstance(result, Task):
        result = result.model_dump(mode="json", by_alias=True, exclude_none=True)
    return JSONRPCResponse(id=rpc_id, result=result).model_dump(mode="json", by_alias=True, exclude_none=True)


def _rpc_error(rpc_id, code: int, message: str, data: Any = None) -> dict[str, Any]:
    return JSONRPCResponse(
        id=rpc_id,
        error=JSONRPCError(code=code, message=message, data=data),
    ).model_dump(mode="json", by_alias=True, exclude_none=True)


# ─── SSE helpers ────────────────────────────────────────

# Browsers treat an empty line as the end-of-event marker, so every frame
# must end with "\n\n". We keep everything on a single data: line because
# JSON-RPC payloads are self-delimiting.


def _sse_event(payload: dict[str, Any]) -> str:
    """Wrap a JSON-RPC response dict as a single SSE frame."""
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


def _sse_status(rpc_id, task: Any, *, final: bool) -> str:
    """⚠️ TAKES THE TASK, NOT ITS ID, AND THAT IS THE POINT.

    A frame naming a different context from the task it belongs to would be
    worse than a missing field — a client would group it into the wrong
    conversation and nothing would look broken. Reading both values off ONE task
    makes them agree by construction instead of by every call site remembering
    to pass a matching pair.
    """
    event = TaskStatusUpdateEvent(id=task.id, taskId=task.id, contextId=task.contextId, status=task.status, final=final)
    envelope = JSONRPCResponse(id=rpc_id, result=event.model_dump(mode="json", exclude_none=True)).model_dump(
        mode="json", exclude_none=True
    )
    return _sse_event(envelope)


def _sse_artifact(rpc_id, task: Any, artifact: Any) -> str:
    """Task, not id — same reason as ``_sse_status``."""
    event = TaskArtifactUpdateEvent(id=task.id, taskId=task.id, contextId=task.contextId, artifact=artifact)
    envelope = JSONRPCResponse(id=rpc_id, result=event.model_dump(mode="json", exclude_none=True)).model_dump(
        mode="json", exclude_none=True
    )
    return _sse_event(envelope)
