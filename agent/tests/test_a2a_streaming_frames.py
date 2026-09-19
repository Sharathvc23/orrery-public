"""The streaming path we advertise, driven by a client that is not ours.

`supports_streaming` defaults True, so our agent card tells a stock client this
path works. It did not: every frame failed the client's parser on frame one.

⚠️ AND THE REASON WAS BIGGER THAN A MISSING FIELD. A current-spec client reads
`kind` to decide which model a frame is. With `kind` absent it falls back to
guessing from the keys — `taskId` + `final`, then `messageId`, then `id` — and
our frames carried only `id`, so EVERY frame was parsed as a whole Task. The
status frames happened to survive that and were silently misread as Tasks; the
artifact frame, which has no `status`, could not be parsed at all.

So the fix is three additive fields: `contextId`, `taskId` and `kind`. Their
jobs differ, and planting showed it — removing `kind` alone no longer breaks the
status frames, because `taskId` + `final` is enough for the client's fallback to
guess right. `kind` is what saves the ARTIFACT frame, which the fallback has no
rule for. Both are kept: relying on someone else's guessing heuristic when the
spec provides a discriminator is a bet with no upside.

The oracle is not "the first frame parses". It is a stock client consuming the
stream to the end, with each frame arriving as the model it actually is.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid

import pytest

from community_member import a2a_rpc as rpc
from community_member.a2a_auth import CallerIdentity
from community_member.config import Config
from community_member.crypto import generate_ed25519_keypair
from community_member.server import create_app
from community_member.task_store import TaskStore

pytestmark = pytest.mark.no_local_token

PEER = CallerIdentity(agent_id="peer-agent", did_key="did:key:zPeerTest")


class _FakeAgent:
    AGENT_TOOLS = [{"type": "function", "function": {"name": "search_chapter", "description": ""}}]

    async def execute_tool(self, name: str, args: dict) -> str:
        return json.dumps({"tool": name, "args": args})


def _cfg() -> Config:
    c = Config()
    c.agent_id = "streaming-agent"
    c.name = "Streaming"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


@pytest.fixture
def handler(tmp_path):
    async def dispatch(name: str, args: dict) -> str:
        return json.dumps({"tool": name, "args": args})

    return rpc.A2ARPCHandler(store=TaskStore(path=tmp_path / "tasks.jsonl"), dispatcher=dispatch)


async def _frames(handler, params: dict) -> list[dict]:
    envelope = {"jsonrpc": "2.0", "id": "s", "method": "message/stream", "params": params}
    out = []
    async for frame in handler.stream(envelope, caller=PEER):
        out.append(json.loads(frame.split("data: ", 1)[1]))
    return out


def _tool_message() -> dict:
    return {"role": "user", "parts": [{"type": "data", "data": {"tool": "search_chapter", "args": {}}}]}


# ── every frame names its own task's context ─────────────────────────────────


@pytest.mark.asyncio
async def test_every_frame_carries_the_context_of_its_own_task(handler):
    """⚠️ EQUALITY, NOT PRESENCE. A frame naming a DIFFERENT context from the
    task it belongs to would be worse than a missing field: a client would file
    it under the wrong conversation and nothing would look broken."""
    frames = await _frames(handler, {"sessionId": "sess-stream", "message": _tool_message()})
    assert frames, "the stream emitted nothing"

    results = [f["result"] for f in frames if "result" in f]
    assert results, f"the stream emitted only errors: {frames[0]}"

    task_ids = {r["taskId"] for r in results}
    assert len(task_ids) == 1, f"one send produced frames for several tasks: {task_ids}"

    task = await handler.handle({"jsonrpc": "2.0", "id": "g", "method": "tasks/get", "params": {"id": task_ids.pop()}})
    expected = task["result"]["contextId"]
    assert expected, "the task has no context, so the comparison below would be vacuous"
    for r in results:
        assert r["contextId"] == expected, (
            f"a {r.get('kind')} frame names context {r['contextId']!r}, its task has {expected!r}"
        )


@pytest.mark.asyncio
async def test_every_frame_type_the_stream_emits_is_covered(handler):
    """The brief asked for every frame type, not the two found by grep. A
    tool-invoking send exercises both non-error shapes; the third shape a stream
    can emit is a JSON-RPC error envelope, which is not a Task-like frame and is
    asserted separately in the auth suite."""
    frames = await _frames(handler, {"message": _tool_message()})
    kinds = {f["result"]["kind"] for f in frames if "result" in f}
    assert kinds == {"status-update", "artifact-update"}, f"unexpected frame kinds: {kinds}"


@pytest.mark.asyncio
async def test_frames_keep_the_v02_id_alongside_the_current_spec_name(handler):
    """Additive: `id` is what our own client reads and it must not have been
    renamed to `taskId` — that would be a breaking change to a shipped wire
    format, not a compatibility fix."""
    frames = await _frames(handler, {"message": _tool_message()})
    for f in frames:
        r = f.get("result")
        if r:
            assert r["id"] == r["taskId"], "the v0.2 id and the current-spec taskId disagree"


@pytest.mark.asyncio
async def test_the_resubscribe_path_carries_the_context_too(handler):
    """The other streaming entry point, which builds its frames from a stored
    task rather than one it just created."""
    frames = await _frames(handler, {"message": _tool_message()})
    task_id = next(f["result"]["taskId"] for f in frames if "result" in f)

    envelope = {"jsonrpc": "2.0", "id": "r", "method": "tasks/resubscribe", "params": {"id": task_id}}
    resub = [json.loads(f.split("data: ", 1)[1]) async for f in handler.stream(envelope, caller=PEER)]
    results = [f["result"] for f in resub if "result" in f]
    assert results, f"resubscribe emitted only errors: {resub[0]}"
    assert all(r["contextId"] for r in results), "a resubscribe frame carries no context"


# ── the advertisement stays true ─────────────────────────────────────────────


def test_the_card_still_advertises_streaming():
    """The fix is the frames, not the advertisement. Turning `streaming` off
    would make the card honest by removing a capability, which is a product
    decision and not this one."""
    from fastapi.testclient import TestClient

    card = TestClient(create_app(_cfg())).get("/.well-known/agent-card.json").json()
    assert card["capabilities"]["streaming"] is True, (
        "streaming was switched off rather than fixed — that is a product decision, not a repair"
    )


# ── the oracle: a stock client consumes the whole stream ─────────────────────

a2a = pytest.importorskip("a2a", reason="a2a-sdk is the external oracle for the streaming path")


def _drive_stream(part) -> list:
    """Run the unmodified SDK streaming client against us and return its frames."""
    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest  # noqa: F401

    kp = generate_ed25519_keypair()
    events: list = []

    async def run() -> None:
        async def sign(request):
            if request.method == "POST":
                from community_member.a2a_client_v2 import _signed_headers

                signed = _signed_headers(
                    request.content.decode(), "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519"
                )
                for k, v in signed.items():
                    request.headers[k] = v

        app = create_app(_cfg(), agent=_FakeAgent())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://stream.test",
            event_hooks={"request": [sign]},
            timeout=15,
        ) as hx:
            card = await A2ACardResolver(httpx_client=hx, base_url="http://stream.test").get_agent_card()
            assert card.capabilities.streaming, "the card no longer advertises streaming"
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=True)).create(card)
            request = SendMessageRequest(
                message=Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[part])
            )
            async for event in client.send_message(request):
                events.append(event)

    asyncio.run(run())
    return events


def test_a_stock_client_parses_the_whole_stream():
    """⚠️ THE UNIT. Not the first frame — the WHOLE stream, to the final one.

    Before: `ValidationError | 1 validation error for Task / contextId Field
    required`, on frame one, on a path our own card advertises as supported.
    """
    from a2a.types import Part

    events = _drive_stream(Part(text="hello from a stock a2a-sdk client"))
    assert events, "the SDK consumed no frames"
    kinds = [e.WhichOneof("payload") for e in events]
    assert all(k == "status_update" for k in kinds), (
        f"status frames were parsed as {set(kinds)} — a status update read as a whole Task is "
        "wrong even when it does not raise"
    )
    # The SDK's protobuf status frame has no `final` — finality is carried by a
    # terminal state, so that is what the last frame is checked for.
    from a2a.types import TaskState

    terminal = {
        TaskState.TASK_STATE_COMPLETED,
        TaskState.TASK_STATE_FAILED,
        TaskState.TASK_STATE_CANCELED,
        TaskState.TASK_STATE_INPUT_REQUIRED,
    }
    assert events[-1].status_update.status.state in terminal, (
        f"the stream ended on a non-terminal state: {events[-1].status_update.status.state}"
    )
    contexts = {e.status_update.context_id for e in events}
    assert len(contexts) == 1 and contexts.pop(), "the parsed frames disagree about their context"


def test_a_stock_client_parses_an_artifact_frame():
    """The frame that could not be parsed AT ALL before: it has no `status`, so
    the SDK's key-guessing fallback tried it as a Task and failed."""
    from a2a.types import Part
    from google.protobuf import json_format
    from google.protobuf.struct_pb2 import Value

    value = Value()
    json_format.ParseDict({"tool": "search_chapter", "args": {}}, value)
    events = _drive_stream(Part(data=value))

    kinds = [e.WhichOneof("payload") for e in events]
    assert "artifact_update" in kinds, f"no artifact frame reached the client: {kinds}"
    from a2a.types import TaskState

    assert kinds[-1] == "status_update", f"the stream did not end on a status frame: {kinds}"
    assert events[-1].status_update.status.state == TaskState.TASK_STATE_COMPLETED, (
        "the tool stream did not end completed"
    )
    artifact = next(e.artifact_update for e in events if e.WhichOneof("payload") == "artifact_update")
    assert artifact.context_id, "the artifact frame carries no context"
    assert artifact.task_id, "the artifact frame names no task"
