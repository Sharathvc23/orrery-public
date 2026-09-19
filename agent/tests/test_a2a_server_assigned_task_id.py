"""Who names a task, and what that means for who can read it.

Spec v0.2 had the CALLER name the task: `tasks/send` took `params["id"]` and
refused without it. The current spec inverted that — `message/send` carries a
message and no id, and the SERVER assigns identity and returns it.

Making `message/send` resolve to this handler was not enough on its own: the
handler still demanded the parameter the current spec deliberately removed, so a
well-formed current-spec request was rejected on arrival.

⚠️ THAT REJECTION WAS INVISIBLE FOR A WHILE, AND THE REASON IS WORTH KEEPING.
The caller gate sits before dispatch, and `message/send` requires a caller — so
an unauthenticated stock client was refused at auth and never reached the id
check. The gap was hidden behind the wall in front of it, not closed by it. Every
test here that exercises the id path therefore AUTHENTICATES FIRST; otherwise it
would be re-measuring the auth gate and reading that as progress.

⚠️ AND THE MINT IS NOW LOad-BEARING FOR SOMETHING ELSE. `tasks/get` and
`tasks/cancel` are deliberately open, on the stated reasoning that task ids are
unguessable. That was a claim about caller-chosen ids; from here it is a claim
about `mint_task_id`. The entropy test below is what keeps it true.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from community_member import a2a_rpc as rpc
from community_member.a2a_auth import CallerIdentity
from community_member.config import Config
from community_member.crypto import generate_ed25519_keypair
from community_member.server import create_app
from community_member.task_store import TaskStore

pytestmark = pytest.mark.no_local_token

PEER = CallerIdentity(agent_id="peer-agent", did_key="did:key:zPeerTest")


@pytest.fixture
def handler(tmp_path):
    async def dispatch(name: str, args: dict) -> str:
        return json.dumps({"tool": name, "args": args})

    return rpc.A2ARPCHandler(store=TaskStore(path=tmp_path / "tasks.jsonl"), dispatcher=dispatch)


def _send(method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": "rpc-1", "method": method, "params": params}


def _signed_headers_for(body: str, kp: dict) -> dict[str, str]:
    from community_member.a2a_client_v2 import _signed_headers

    return _signed_headers(body, "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519")


def _message(text: str = "hello") -> dict:
    return {"role": "user", "parts": [{"type": "text", "text": text}]}


# ── the v0.2 contract is unchanged ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_caller_supplied_id_is_honoured_exactly(handler):
    """Our own client names its tasks and must keep working byte for byte. A
    server that quietly re-assigned the id would break every caller that holds
    one already."""
    resp = await handler.handle(_send("tasks/send", {"id": "caller-chosen", "message": _message()}), caller=PEER)
    assert resp["result"]["id"] == "caller-chosen"

    got = await handler.handle(_send("tasks/get", {"id": "caller-chosen"}))
    assert got["result"]["id"] == "caller-chosen", "the task is not retrievable under the id its caller chose"


@pytest.mark.asyncio
async def test_a_caller_supplied_id_is_still_honoured_on_the_streaming_path(handler):
    frames = [
        f
        async for f in handler.stream(_send("tasks/sendSubscribe", {"id": "mine", "message": _message()}), caller=PEER)
    ]
    ids = {json.loads(f.split("data: ", 1)[1])["result"]["id"] for f in frames if "result" in f}
    assert ids == {"mine"}, f"the streaming path re-assigned a caller-chosen id: {ids}"


# ── the current-spec path: the server assigns, and says what it assigned ─────


@pytest.mark.asyncio
async def test_a_send_without_an_id_is_answered_not_refused(handler):
    resp = await handler.handle(_send("message/send", {"message": _message()}), caller=PEER)
    assert "error" not in resp, f"a well-formed current-spec request was refused: {resp.get('error')}"
    assert resp["result"]["id"], "the task came back with no id, so the caller cannot address it"


@pytest.mark.asyncio
async def test_the_minted_id_round_trips_through_tasks_get(handler):
    """⚠️ THE ROUND TRIP IS THE GUARD, not that a 200 came back. A caller that
    did not choose the id has no other way to learn it, and every subsequent
    tasks/get, tasks/cancel and tasks/resubscribe needs it — an id that comes
    back but addresses nothing is worse than an error."""
    resp = await handler.handle(_send("message/send", {"message": _message()}), caller=PEER)
    minted = resp["result"]["id"]

    got = await handler.handle(_send("tasks/get", {"id": minted}))
    assert "error" not in got, f"the id the server minted does not address a task: {got.get('error')}"
    assert got["result"]["id"] == minted
    assert got["result"]["status"] == resp["result"]["status"], "the round trip returned a different task"


@pytest.mark.asyncio
async def test_the_streaming_path_mints_too_and_names_it_in_every_frame(handler):
    frames = [f async for f in handler.stream(_send("message/stream", {"message": _message()}), caller=PEER)]
    payloads = [json.loads(f.split("data: ", 1)[1]) for f in frames]
    assert all("error" not in p for p in payloads), f"a current-spec streaming send was refused: {payloads[:1]}"
    ids = {p["result"]["id"] for p in payloads if "result" in p}
    assert len(ids) == 1, f"the stream named more than one task: {ids}"
    minted = ids.pop()
    got = await handler.handle(_send("tasks/get", {"id": minted}))
    assert got["result"]["id"] == minted, "the id the stream named does not address a task"


@pytest.mark.asyncio
async def test_two_sends_without_ids_are_two_different_tasks(handler):
    a = await handler.handle(_send("message/send", {"message": _message("one")}), caller=PEER)
    b = await handler.handle(_send("message/send", {"message": _message("two")}), caller=PEER)
    assert a["result"]["id"] != b["result"]["id"], "two independent sends collapsed into one task"


# ── the entropy the open read paths depend on ────────────────────────────────


def test_the_minted_id_is_unguessable():
    """⚠️ THIS IS WHAT KEEPS AN EARLIER DECISION HONEST. tasks/get is open on the
    stated reasoning that ids are unguessable. A counter, a timestamp, or
    anything derived from the request would make every task on this agent
    enumerable by an anonymous reader.

    Asserted on the property, not on the implementation: enough length to carry
    real entropy, and no two mints alike."""
    assert rpc.TASK_ID_ENTROPY_BYTES >= 16, (
        f"task ids carry only {rpc.TASK_ID_ENTROPY_BYTES * 8} bits; tasks/get is open to anyone who can guess one"
    )
    minted = [rpc.mint_task_id() for _ in range(500)]
    assert len(set(minted)) == 500, "minted task ids repeat"
    shortest = min(len(m) for m in minted)
    assert shortest >= 22, f"minted ids are {shortest} characters — too short to be unguessable"
    assert not any(m.isdigit() for m in minted), "minted ids look sequential"


def test_the_mint_does_not_derive_from_the_request():
    """A mint that hashed the request would be deterministic, and two identical
    requests would collide onto one task — as well as being guessable by anyone
    who can guess the request."""
    assert rpc.mint_task_id() != rpc.mint_task_id()


# ── the oracle: someone else's request shape, authenticated, completing ──────

a2a = pytest.importorskip("a2a", reason="a2a-sdk supplies the current-spec request shape")


def _cfg() -> Config:
    c = Config()
    c.agent_id = "task-id-agent"
    c.name = "TaskId"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


def _sdk_request_body() -> str:
    """The JSON-RPC body the real a2a-sdk puts on the wire for a send.

    Built by the SDK's own client, not hand-written, so the SHAPE is someone
    else's: `message/send`, a `message` object with `kind`/`role`/`parts`, and —
    the point of this unit — NO task id.
    """
    import asyncio
    import uuid

    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest

    captured: list[str] = []

    async def capture() -> None:
        async def tap(request):
            if request.method == "POST":
                captured.append(request.content.decode())

        app = create_app(_cfg())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://shape.test",
            event_hooks={"request": [tap]},
        ) as hx:
            card = await A2ACardResolver(httpx_client=hx, base_url="http://shape.test").get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False)).create(card)
            request = SendMessageRequest(
                message=Message(
                    message_id=uuid.uuid4().hex,
                    role=Role.ROLE_USER,
                    parts=[Part(text="hello from a current-spec request shape")],
                )
            )
            try:
                async for _ in client.send_message(request):
                    pass
            except Exception:  # noqa: BLE001 — we want the BODY, not the outcome
                pass

    asyncio.run(capture())
    assert captured, "the SDK sent no POST — the shape could not be captured"
    return captured[-1]


def test_an_authenticated_current_spec_request_completes():
    """⚠️ THE ONE THAT MATTERS, AND THE ONE IT IS EASIEST TO FAKE.

    An unauthenticated stock client is refused at the caller gate and never
    reaches the id check, so "it is refused" would pass just as well with the id
    bug intact. This one SIGNS, and asserts the request COMPLETES.

    The body is the SDK's own, captured off the wire — it carries a `message`
    and no task id, which is exactly what this handler used to reject.
    """
    body = json.loads(_sdk_request_body())
    assert body["method"] == "message/send"
    assert "id" not in body["params"], "the SDK's own request carries a task id after all"

    envelope = json.dumps(body)
    kp = generate_ed25519_keypair()
    headers = _signed_headers_for(envelope, kp)

    client = TestClient(create_app(_cfg()))
    resp = client.post("/", content=envelope, headers=headers)
    answer = resp.json()

    assert "error" not in answer, (
        f"an authenticated current-spec request was refused: {answer.get('error')}. "
        "If the code is -32004 this test is measuring the auth gate, not the id path."
    )
    minted = answer["result"]["id"]
    assert minted, "the server completed the request but named no task"

    got = client.post("/", json=_send("tasks/get", {"id": minted}))
    assert got.json()["result"]["id"] == minted, "the id returned to a stock-shaped caller does not address a task"


def test_the_stock_sdk_parses_our_reply_into_its_own_task_model():
    """⚠️ THE INVERTED PIN, AND THE FIRST END-TO-END CONVERSATION WITH AN
    OUTSIDE CLIENT.

    This test used to be
    ``test_the_response_shape_the_sdk_cannot_yet_parse_is_recorded``, and it
    asserted the opposite: that our ``Task`` carried no ``contextId`` and our
    history messages no ``messageId``, because the current spec requires both
    and our v0.2 models emitted neither. It was written to fail deliberately the
    moment that was fixed, so that fixing it could not look like a regression.
    This is that inversion.

    The oracle is not "the JSON has the keys" — it is SOMEONE ELSE'S PARSER
    accepting the bytes. The stock a2a-sdk resolves our card, signs, sends, and
    validates the reply into its own protobuf ``Task``. A ValidationError here
    means the reply is unparseable to a real client no matter how the keys look
    to us.
    """
    import asyncio
    import uuid

    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest

    parsed: list = []
    kp = generate_ed25519_keypair()

    async def drive() -> None:
        async def sign(request):
            if request.method == "POST":
                for k, v in _signed_headers_for(request.content.decode(), kp).items():
                    request.headers[k] = v

        app = create_app(_cfg())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://parse.test",
            event_hooks={"request": [sign]},
        ) as hx:
            card = await A2ACardResolver(httpx_client=hx, base_url="http://parse.test").get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False)).create(card)
            request = SendMessageRequest(
                message=Message(
                    message_id=uuid.uuid4().hex,
                    role=Role.ROLE_USER,
                    parts=[Part(text="hello from a stock a2a-sdk client")],
                )
            )
            async for event in client.send_message(request):
                parsed.append(event)

    asyncio.run(drive())

    assert parsed, "the SDK yielded no event — it did not accept the reply"
    event = parsed[0]
    assert event.HasField("task"), "the SDK parsed a reply that carries no task"
    assert event.task.id, "the parsed task has no id"
    assert event.task.context_id, "the parsed task has no contextId — the grouping field is empty"
    assert len(event.task.history) >= 1, "the parsed task has no history"
