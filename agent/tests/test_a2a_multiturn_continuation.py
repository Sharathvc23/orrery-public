"""A second turn must land on the first turn's task, not start a new one.

The current spec carries continuation as `message.taskId`. We read the task id
from `params["id"]`, which a current-spec client never sets — so every turn
minted a fresh task while the caller believed the conversation was continuing.

⚠️ THE FAILURE RETURNED A VALID TASK AND A 200. Nothing raised. That is the same
shape as the streaming frames that "parsed fine" as whole Task payloads: the
absence of an error was not evidence of correctness. So NOTHING HERE ASSERTS
THAT TURN 2 SUCCEEDS — a test that checked only the reply would pass today, with
the bug. Every assertion is on IDENTITY and HISTORY: the same task id, and both
turns' messages inside it.

⚠️ ON OWNERSHIP: there is none, and this file does not add one. Any verified
caller who knows a task id can append to it. That is pre-existing and reachable
through `params["id"]` today; the test at the bottom pins it as the CURRENT
state so a later ruling inverts a recorded fact rather than discovering one.
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

ALICE = CallerIdentity(agent_id="alice", did_key="did:key:zAlice")
BOB = CallerIdentity(agent_id="bob", did_key="did:key:zBob")


@pytest.fixture
def handler(tmp_path):
    async def dispatch(name: str, args: dict) -> str:
        return json.dumps({"tool": name, "args": args})

    return rpc.A2ARPCHandler(store=TaskStore(path=tmp_path / "tasks.jsonl"), dispatcher=dispatch)


def _env(params: dict, method: str = "message/send") -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": method, "params": params}


def _msg(text: str, **extra) -> dict:
    return {"role": "user", "parts": [{"type": "text", "text": text}], **extra}


def _texts(task: dict) -> list[str]:
    return [p["text"] for m in task["history"] for p in m["parts"] if p.get("text")]


# ── the new arm ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_second_turn_lands_on_the_first_turns_task(handler):
    """⚠️ ASSERTED ON IDENTITY AND HISTORY, NOT ON SUCCESS. Both turns return a
    valid task and a 200 whether or not continuation works; only the id and the
    history tell them apart."""
    first = await handler.handle(_env({"message": _msg("turn one")}), caller=ALICE)
    task_id = first["result"]["id"]

    second = await handler.handle(_env({"message": _msg("turn two", taskId=task_id)}), caller=ALICE)

    assert second["result"]["id"] == task_id, "the second turn started a new task"
    texts = _texts(second["result"])
    assert "turn one" in texts and "turn two" in texts, f"the task does not hold both turns: {texts}"


@pytest.mark.asyncio
async def test_the_streaming_path_continues_the_same_way(handler):
    first = await handler.handle(_env({"message": _msg("turn one")}), caller=ALICE)
    task_id = first["result"]["id"]

    frames = [
        json.loads(f.split("data: ", 1)[1])
        async for f in handler.stream(
            _env({"message": _msg("turn two", taskId=task_id)}, method="message/stream"), caller=ALICE
        )
    ]
    ids = {f["result"]["taskId"] for f in frames if "result" in f}
    assert ids == {task_id}, f"the streaming second turn named {ids}, not the first turn's task"

    got = await handler.handle(_env({"id": task_id}, method="tasks/get"))
    assert "turn one" in _texts(got["result"]) and "turn two" in _texts(got["result"])


# ── the other two arms are unchanged ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_v02_params_id_still_wins(handler):
    """Arm 1. If both are supplied the v0.2 field decides, because that is what
    it did before this arm existed and a v0.2 caller must not change meaning."""
    resp = await handler.handle(
        _env({"id": "chosen-by-params", "message": _msg("hi", taskId="named-by-message")}), caller=ALICE
    )
    assert resp["result"]["id"] == "chosen-by-params"


@pytest.mark.asyncio
async def test_two_turns_without_a_task_id_are_still_two_tasks(handler):
    """Arm 3, and the behaviour this must not disturb: a caller who names
    nothing gets a fresh task each time, exactly as before."""
    a = await handler.handle(_env({"message": _msg("one")}), caller=ALICE)
    b = await handler.handle(_env({"message": _msg("two")}), caller=ALICE)
    assert a["result"]["id"] != b["result"]["id"], "independent sends collapsed into one task"


@pytest.mark.asyncio
async def test_an_unknown_task_id_creates_a_task_under_that_name(handler):
    """A DELIBERATE ANSWER, not whatever the code happened to do. Refusing here
    would mean a caller who names a task can create one through `params["id"]`
    and not through `message.taskId` — the same request answered two ways
    depending on which field carried the name."""
    resp = await handler.handle(_env({"message": _msg("hi", taskId="never-seen-before")}), caller=ALICE)
    assert "error" not in resp, f"a caller-named task id was refused: {resp.get('error')}"
    assert resp["result"]["id"] == "never-seen-before"

    same = await handler.handle(_env({"id": "never-seen-before-2", "message": _msg("hi")}), caller=ALICE)
    assert same["result"]["id"] == "never-seen-before-2", "the two arms disagree about an unknown id"


# ── the ownership gap, pinned as the current state ───────────────────────────


@pytest.mark.asyncio
async def test_a_second_caller_cannot_append_to_a_task_they_did_not_create(handler):
    """⚠️ THE INVERTED PIN. This was
    ``test_any_verified_caller_may_append_to_a_task_they_did_not_create``, and it
    asserted the opposite: that Bob's message landed in Alice's task history. It
    was written to record the CURRENT state so that a ruling requiring ownership
    would invert a recorded fact rather than discover one. This is that
    inversion.

    Signing proved possession of the key a caller claims, never that they were
    the caller who created the task — auth made appends attributable, not
    authorized, and until now the task id was the only capability.
    """
    first = await handler.handle(_env({"message": _msg("alice turn")}), caller=ALICE)
    task_id = first["result"]["id"]

    intruder = await handler.handle(_env({"message": _msg("bob turn", taskId=task_id)}), caller=BOB)
    assert intruder.get("error", {}).get("code") == rpc.ERROR_NOT_TASK_CREATOR, (
        f"a second caller appended to another's task: {intruder}"
    )

    after = await handler.handle(_env({"id": task_id}, method="tasks/get"))
    assert "bob turn" not in _texts(after["result"]), "the refused message reached the history anyway"


@pytest.mark.asyncio
async def test_the_v02_arm_is_closed_too(handler):
    """The companion pin, inverted with it. It existed to show the exposure was
    pre-existing rather than introduced by ``message.taskId``; both arms go
    through one check, so closing one closed both."""
    first = await handler.handle(_env({"id": "alice-task", "message": _msg("alice turn")}), caller=ALICE)
    assert first["result"]["id"] == "alice-task"

    intruder = await handler.handle(_env({"id": "alice-task", "message": _msg("bob turn")}), caller=BOB)
    assert intruder.get("error", {}).get("code") == rpc.ERROR_NOT_TASK_CREATOR


@pytest.mark.asyncio
async def test_the_creator_can_still_continue_their_own_task(handler):
    """DETECTOR VALIDATION. If nothing could append, the refusals above would be
    indistinguishable from a broken continuation path."""
    first = await handler.handle(_env({"message": _msg("turn one")}), caller=ALICE)
    task_id = first["result"]["id"]
    second = await handler.handle(_env({"message": _msg("turn two", taskId=task_id)}), caller=ALICE)
    assert second["result"]["id"] == task_id
    assert "turn two" in _texts(second["result"])


# ── cancel: destructive, so ownership applies ────────────────────────────────


@pytest.mark.asyncio
async def test_a_second_caller_cannot_cancel_another_callers_task(handler):
    first = await handler.handle(_env({"message": _msg("alice turn")}), caller=ALICE)
    task_id = first["result"]["id"]

    refused = await handler.handle(_env({"id": task_id}, method="tasks/cancel"), caller=BOB)
    assert refused.get("error", {}).get("code") == rpc.ERROR_NOT_TASK_CREATOR

    still = await handler.handle(_env({"id": task_id}, method="tasks/get"))
    assert still["result"]["status"]["state"] != "canceled", "the task was cancelled despite the refusal"


@pytest.mark.asyncio
async def test_the_creator_can_cancel_their_own_task(handler):
    first = await handler.handle(_env({"message": _msg("alice turn")}), caller=ALICE)
    task_id = first["result"]["id"]
    ok = await handler.handle(_env({"id": task_id}, method="tasks/cancel"), caller=ALICE)
    assert "error" not in ok, f"the creator could not cancel their own task: {ok.get('error')}"


# ── legacy tasks: allowed, and counted ───────────────────────────────────────


@pytest.mark.asyncio
async def test_a_task_with_no_recorded_creator_is_allowed_and_counted(handler):
    """⚠️ ALLOWED IS THE EASY HALF. Tasks created before ownership was recorded
    live on volumes that survived the deploy, and refusing them would break live
    conversations. Allowing them SILENTLY would be a fail-open default that
    never expires on its own — so each one increments a counter and logs.

    When ``rpc.legacy_tasks_without_creator`` stops moving in practice, the
    population is drained and the default can flip to deny. That flip is a
    ruling, not something this test decides."""
    # Seeded through the STORE, not the handler: a creatorless task cannot be
    # made through the wire any more (a send needs a caller), and the real
    # legacy population is records already on the volume — which is exactly
    # what this is.
    from community_member.a2a_models import Message as StoredMessage

    handler.store.create(
        task_id="legacy",
        session_id=None,
        initial_message=StoredMessage(role="user", parts=[]),
        context_id="legacy-ctx",
    )
    assert handler.store.get("legacy").creatorDidKey is None, "the seeded task recorded a creator"

    before = rpc.legacy_tasks_without_creator
    appended = await handler.handle(_env({"message": _msg("bob appends", taskId="legacy")}), caller=BOB)
    assert "error" not in appended, f"a legacy task refused an append: {appended.get('error')}"
    assert rpc.legacy_tasks_without_creator == before + 1, (
        "the legacy append was allowed but not counted — that is the fail-open default this "
        "counter exists to make visible"
    )


# ── the oracle: a stock client holds a two-turn conversation ─────────────────

a2a = pytest.importorskip("a2a", reason="a2a-sdk is the external oracle for multi-turn")


def _cfg() -> Config:
    c = Config()
    c.agent_id = "multiturn-agent"
    c.name = "MultiTurn"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


def test_a_stock_client_holds_a_two_turn_conversation():
    """⚠️ THE UNIT. The second turn must be THE SAME TASK — not a successful
    second request. Before this change the drive returned two valid tasks with
    different ids and no error at all."""
    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest

    from community_member.a2a_client_v2 import _signed_headers

    kp = generate_ed25519_keypair()
    result: dict = {}

    async def run() -> None:
        async def sign(request):
            if request.method == "POST":
                signed = _signed_headers(
                    request.content.decode(), "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519"
                )
                for k, v in signed.items():
                    request.headers[k] = v

        app = create_app(_cfg())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://turns.test",
            event_hooks={"request": [sign]},
            timeout=15,
        ) as hx:
            card = await A2ACardResolver(httpx_client=hx, base_url="http://turns.test").get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False)).create(card)

            async def turn(message):
                events = []
                async for event in client.send_message(SendMessageRequest(message=message)):
                    events.append(event)
                return events[0]

            first = await turn(Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="turn one")]))
            second = await turn(
                Message(
                    message_id=uuid.uuid4().hex,
                    role=Role.ROLE_USER,
                    parts=[Part(text="turn two")],
                    context_id=first.task.context_id,
                    task_id=first.task.id,
                )
            )
            result["first_id"] = first.task.id
            result["second"] = second.task

    asyncio.run(run())

    assert result["first_id"], "the first turn produced no task"
    second = result["second"]
    assert second.id == result["first_id"], (
        "the stock client's second turn started a NEW task — the conversation silently forked, "
        "which is exactly what this returns a valid Task and a 200 while doing"
    )
    texts = [p.text for m in second.history for p in m.parts if p.text]
    assert "turn one" in texts and "turn two" in texts, f"the task does not hold both turns: {texts}"
    assert second.context_id, "the continued task lost its context"


def test_a_task_record_written_by_the_deployed_code_still_loads(tmp_path):
    """⚠️ THE DEPLOY CONSTRAINT. Task state lives on volumes that survived the
    deploy, so this model reads records written before ``creatorDidKey``
    existed, on every boot. A required field would have made each of them a
    corrupt line that ``_load`` silently skips — data loss disguised as an
    upgrade.

    The record below is the exact serialisation the currently deployed code
    produces: no creator key at all."""
    from community_member.a2a_models import Task
    from community_member.task_store import TaskStore

    deployed_record = {
        "id": "written-before-ownership",
        "sessionId": "s1",
        "contextId": "ctx1",
        "status": {"state": "submitted", "timestamp": "2026-08-29T19:11:45.363691+00:00"},
        "artifacts": [],
        "history": [{"role": "user", "parts": [], "messageId": "abc123"}],
    }

    task = Task.model_validate(deployed_record)
    assert task.id == "written-before-ownership"
    assert task.creatorDidKey is None, "an absent creator must read as absent, not as some default"

    round_tripped = task.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert round_tripped == deployed_record, (
        "a legacy record does not survive a load/save cycle unchanged — the volume would drift"
    )

    path = tmp_path / "volume.jsonl"
    path.write_text(json.dumps(deployed_record) + "\n", encoding="utf-8")
    assert TaskStore(path=path).get("written-before-ownership") is not None, (
        "the store skipped a record the deployed code wrote — _load treats it as corrupt"
    )
