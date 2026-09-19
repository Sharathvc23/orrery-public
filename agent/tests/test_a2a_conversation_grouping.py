"""contextId groups tasks into a conversation; messageId names a message.

The current spec requires both on a reply and our v0.2 models emitted neither,
so a stock client could not parse an answer it had otherwise fully obtained —
discovery, method resolution, auth and task creation all worked.

⚠️ contextId IS A DECISION, NOT A FIELD TO FILL IN. The spec uses it to GROUP
related tasks, so the value carries meaning. Anything convenient — the task id,
a fresh mint every time — satisfies the parser and destroys the grouping. So the
test that matters is the PAIR: two tasks in one conversation share it, two
unrelated tasks do not.

⚠️ AND THE TWO IDENTIFIERS HAVE DIFFERENT REQUIREMENTS ON PURPOSE. A task id is
256 bits of CSPRNG because `tasks/get` is open and the id IS the access control
there. A messageId reaches nothing — no route takes one — so it is a uuid4. That
asymmetry is asserted below so nobody "fixes" it in either direction.
"""

from __future__ import annotations

import json

import pytest

from community_member import a2a_rpc as rpc
from community_member.a2a_auth import CallerIdentity
from community_member.a2a_models import Message
from community_member.task_store import TaskStore

pytestmark = pytest.mark.no_local_token

PEER = CallerIdentity(agent_id="peer-agent", did_key="did:key:zPeerTest")


@pytest.fixture
def handler(tmp_path):
    async def dispatch(name: str, args: dict) -> str:
        return json.dumps({"tool": name, "args": args})

    return rpc.A2ARPCHandler(store=TaskStore(path=tmp_path / "tasks.jsonl"), dispatcher=dispatch)


def _send(params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": "message/send", "params": params}


def _msg(**extra) -> dict:
    return {"role": "user", "parts": [{"type": "text", "text": "hello"}], **extra}


# ── precedence 1: the caller named it ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_caller_supplied_context_id_is_honoured_exactly(handler):
    """A client continuing a conversation it started is the reason the field is
    on the request at all. Re-assigning it would silently split that
    conversation in two."""
    resp = await handler.handle(_send({"message": _msg(contextId="ctx-the-caller-chose")}), caller=PEER)
    assert resp["result"]["contextId"] == "ctx-the-caller-chose"


@pytest.mark.asyncio
async def test_a_caller_supplied_message_id_is_honoured_exactly(handler):
    resp = await handler.handle(_send({"message": _msg(messageId="msg-the-caller-chose")}), caller=PEER)
    assert resp["result"]["history"][0]["messageId"] == "msg-the-caller-chose"


# ── precedence 2 and 3: the pair that is the real test ───────────────────────


@pytest.mark.asyncio
async def test_two_sends_in_one_session_share_a_context(handler):
    """``sessionId`` already meant "these belong together" in our own model, so
    mapping it recognises an existing concept rather than adding a parallel one.
    Two sends in one session group without the caller doing anything."""
    a = await handler.handle(_send({"sessionId": "sess-7", "message": _msg()}), caller=PEER)
    b = await handler.handle(_send({"sessionId": "sess-7", "message": _msg()}), caller=PEER)

    assert a["result"]["contextId"] == b["result"]["contextId"], "two tasks in one session were not grouped"
    assert a["result"]["id"] != b["result"]["id"], "they are the same task, so grouping proves nothing"


@pytest.mark.asyncio
async def test_two_unrelated_sends_do_not_share_a_context(handler):
    """The other half. A constant, or anything derived from something every
    request shares, would pass the test above and make every task on the agent
    look like one conversation."""
    a = await handler.handle(_send({"message": _msg()}), caller=PEER)
    b = await handler.handle(_send({"message": _msg()}), caller=PEER)
    assert a["result"]["contextId"] != b["result"]["contextId"], "unrelated tasks were grouped together"


@pytest.mark.asyncio
async def test_a_context_is_not_just_the_task_id(handler):
    """The laziest way to satisfy the parser, and it destroys the grouping: it
    makes every task its own conversation forever, including tasks that share a
    session.

    Driven with a caller-supplied task id, because that is the case where
    "contextId is the task id" is actually observable. An earlier version of
    this test used a request with no id, where the lazy implementation mints a
    context that happens to differ from the minted task id — so it passed with
    the defect planted and promised more than it checked.
    """
    a = await handler.handle(_send({"id": "t-known", "sessionId": "sess-9", "message": _msg()}), caller=PEER)
    assert a["result"]["id"] == "t-known", "the caller's task id was not honoured; the assertion below is unanchored"
    assert a["result"]["contextId"] != "t-known", "contextId is just the task id — nothing can ever group"
    assert a["result"]["contextId"] == "sess-9", "the session did not decide the context"


@pytest.mark.asyncio
async def test_the_streaming_path_groups_the_same_way(handler):
    frames = [
        f
        async for f in handler.stream(
            {
                "jsonrpc": "2.0",
                "id": "s",
                "method": "message/stream",
                "params": {"sessionId": "sess-s", "message": _msg()},
            },
            caller=PEER,
        )
    ]
    payloads = [json.loads(f.split("data: ", 1)[1]) for f in frames]
    assert all("error" not in p for p in payloads), f"the streaming send failed: {payloads[:1]}"
    task = await handler.handle(
        {"jsonrpc": "2.0", "id": "g", "method": "tasks/get", "params": {"id": payloads[0]["result"]["id"]}}
    )
    assert task["result"]["contextId"] == "sess-s", "the streaming path did not map sessionId to the context"


# ── the two identifiers are deliberately different ───────────────────────────


def test_a_message_id_is_minted_when_absent():
    assert Message(role="user", parts=[]).messageId
    assert Message(role="user", parts=[]).messageId != Message(role="user", parts=[]).messageId


def test_a_message_id_deliberately_does_not_carry_task_id_entropy():
    """⚠️ ASSERTED SO NOBODY "FIXES" IT IN EITHER DIRECTION.

    A task id is 256 bits of CSPRNG because ``tasks/get`` and ``tasks/cancel``
    are open — there the id IS the access control, and guessing one reaches a
    stranger's task. A messageId reaches nothing: no route accepts one.

    Making it a token would imply an unguessability contract that does not
    exist; the point of this test is that the asymmetry is intentional and
    recorded, not that the value is short."""
    message_id = Message(role="user", parts=[]).messageId
    task_id = rpc.mint_task_id()
    assert len(message_id) < len(task_id), (
        "the messageId now carries task-id-sized entropy. If that is deliberate, say why here — "
        "nothing is addressable by a messageId, so it is not an access control."
    )
    assert rpc.TASK_ID_ENTROPY_BYTES >= 16, "the task id's own contract weakened; that one IS load-bearing"


# ── v0.2 callers are unaffected ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_v02_reply_still_carries_the_v02_fields(handler):
    """Additive: ``sessionId`` is the v0.2 field and is untouched. A client
    reading it must not find it replaced by the new one."""
    resp = await handler.handle(_send({"id": "t1", "sessionId": "sess-v02", "message": _msg()}), caller=PEER)
    task = resp["result"]
    assert task["sessionId"] == "sess-v02", "the v0.2 sessionId stopped being emitted"
    assert task["id"] == "t1", "a caller-supplied task id stopped being honoured"
    assert task["contextId"], "the new field is absent, so nothing was added"
