"""Can a CURRENT A2A client reach us at all.

Every other A2A test in this repository drives our own client against our own
server, so all of them agreed with each other while a stock client could not
find us. Two things had moved under us:

  discovery  a current client fetches  /.well-known/agent-card.json
             we served only            /.well-known/agent.json
  methods    tasks/send                is now  message/send
             tasks/sendSubscribe       is now  message/stream

`a2a_models.py` still says "spec v0.2". The spec moved; we pinned.

The last test in this file is the one that matters most: its oracle is someone
else's code. The others can only ever confirm that we agree with ourselves.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from fastapi.testclient import TestClient

from community_member import a2a_rpc as rpc
from community_member.config import Config
from community_member.server import create_app

pytestmark = pytest.mark.no_local_token


def _cfg(agent_id: str = "compat-agent") -> Config:
    c = Config()
    c.agent_id = agent_id
    c.name = "Compat"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


@pytest.fixture
def client():
    return TestClient(create_app(_cfg()))


# ── the card is at both paths ────────────────────────────────────────────────

CARD_PATHS = ("/.well-known/agent.json", "/.well-known/agent-card.json")


def test_the_card_is_served_at_both_paths_with_the_same_payload(client):
    """One document, two URLs. The old path is what our own client uses; the new
    one is the only path a current client asks for. Neither may be a redirect —
    whether a v0.2 client follows one is untested here."""
    bodies = {}
    for path in CARD_PATHS:
        r = client.get(path)
        assert r.status_code == 200, f"{path} answered {r.status_code}, not 200"
        bodies[path] = r.json()

    a, b = (bodies[p] for p in CARD_PATHS)
    assert a == b, "the two card paths do not serve the same payload"
    assert a.get("name"), "the card is empty — the comparison above would be vacuous"


def test_both_card_paths_are_reachable_without_a_local_token(client):
    """⚠️ THE FAILURE THIS CATCHES IS A 401, NOT A 404. Every route on this app
    is token-protected unless declared open, so a new route that is merely
    *added* answers 401 and a stock client's discovery fails on the credential
    rather than on the path — which looks like an auth problem and is not."""
    for path in CARD_PATHS:
        assert client.get(path).status_code != 401, f"{path} requires a local token"


# ── the alias table, derived ─────────────────────────────────────────────────


def test_every_alias_reaches_the_same_handler_as_its_v02_name(client):
    """Derived from the mapping, never hand-listed: an entry added to
    METHOD_ALIASES without a test here is impossible."""
    assert rpc.METHOD_ALIASES, "the alias table is empty — this test proves nothing"

    for alias, canonical in rpc.METHOD_ALIASES.items():
        params = {"id": f"t-{uuid.uuid4().hex[:8]}", "message": {"role": "user", "parts": []}}
        by_alias = client.post("/", json={"jsonrpc": "2.0", "id": "a", "method": alias, "params": params})
        params = dict(params, id=f"t-{uuid.uuid4().hex[:8]}")
        by_name = client.post("/", json={"jsonrpc": "2.0", "id": "a", "method": canonical, "params": params})

        assert by_alias.status_code == by_name.status_code, (
            f"{alias!r} and {canonical!r} answered with different status codes"
        )
        for resp, label in ((by_alias, alias), (by_name, canonical)):
            body = resp.text
            assert "Unknown method" not in body and "Unknown streaming method" not in body, (
                f"{label!r} was not routed to a handler: {body[:200]}"
            )


def test_every_streaming_alias_is_also_routed_as_a_stream():
    """⚠️ THE MISTAKE THIS EXISTS FOR. The route decides whether to stream by
    consulting STREAMING_METHODS BEFORE the handler is reached, so a streaming
    alias present in the dispatch and absent from that set is routed as
    non-streaming and fails looking like a protocol bug rather than a wiring
    one. Derived from the mapping so it cannot be forgotten."""
    for alias, canonical in rpc.METHOD_ALIASES.items():
        if canonical in rpc.STREAMING_METHODS:
            assert alias in rpc.STREAMING_METHODS, (
                f"{alias!r} aliases the streaming method {canonical!r} but is not in STREAMING_METHODS"
            )


def test_the_v02_names_still_work(client):
    """Additive only. The old names are what our own client sends today."""
    for method in ("tasks/send", "tasks/get", "tasks/cancel"):
        r = client.post("/", json={"jsonrpc": "2.0", "id": "1", "method": method, "params": {"id": "t-old"}})
        assert "Unknown method" not in r.text, f"{method!r} stopped being dispatched"


def test_canonical_method_leaves_unknown_names_alone():
    """The normaliser must not invent a route for a name nobody defined."""
    assert rpc.canonical_method("tasks/send") == "tasks/send"
    assert rpc.canonical_method("message/send") == "tasks/send"
    assert rpc.canonical_method("nonsense/method") == "nonsense/method"
    assert rpc.canonical_method(None) is None


# ── the oracle that is not us ────────────────────────────────────────────────

a2a = pytest.importorskip("a2a", reason="a2a-sdk is the external oracle; install a2a-sdk to run it")


@pytest.mark.asyncio
async def test_a_stock_a2a_sdk_client_finds_us_and_reaches_a_handler():
    """⚠️ THE ONLY TEST HERE WHOSE ORACLE IS SOMEONE ELSE'S CODE.

    Everything above asserts that we agree with ourselves, which is exactly the
    condition under which none of this was noticed. This one drives the official
    a2a-sdk — its own card resolver, its own default path, its own method names,
    its own wire format — and asserts it gets through discovery and into a
    handler.

    WHAT IT DELIBERATELY DOES NOT ASSERT is a completed conversation. The
    request is answered with a typed A2A error about a missing `id` param,
    because v0.2's `tasks/send` requires a caller-supplied task id and the
    current spec's `message/send` does not carry one. That is a real remaining
    difference and it is not a wiring one — who assigns a task id is protocol
    semantics, not an alias. Recorded here rather than papered over.

    NOTE ON AUTH: this surface performs no caller authentication at all — see
    the reason recorded against ("POST", "/") in local_auth.OPEN_ROUTES. So a
    stock client is NOT stopped at auth; it is served. If that ever changes,
    this test should start failing at the send, and that failure is a correct
    signal rather than a regression.
    """
    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest

    app = create_app(_cfg("stock-client-probe"))
    seen: list[tuple[str, str]] = []

    async def record(request):
        seen.append((request.method, str(request.url)))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://probe.test",
        event_hooks={"request": [record]},
    ) as hx:
        card = await A2ACardResolver(httpx_client=hx, base_url="http://probe.test").get_agent_card()
        assert card.name == "Compat", "the stock client could not resolve our agent card"

        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False)).create(card)
        request = SendMessageRequest(
            message=Message(
                message_id=uuid.uuid4().hex,
                role=Role.ROLE_USER,
                parts=[Part(text="hello from a stock a2a-sdk client")],
            )
        )
        with pytest.raises(Exception) as exc:  # noqa: PT011 — the SDK's own typed error
            async for _ in client.send_message(request):
                pass

    fetched = [url for _, url in seen]
    assert any(u.endswith("/.well-known/agent-card.json") for u in fetched), (
        f"the stock client never fetched the current-spec card path: {fetched}"
    )
    assert any(u.rstrip("/") == "http://probe.test" for u in fetched), (
        f"the stock client never reached the RPC endpoint: {fetched}"
    )
    message = str(exc.value)
    assert "MethodNotFound" not in type(exc.value).__name__, f"the stock client's method was not recognised: {message}"
    assert "requires a verified caller" in message, (
        "expected refusal at the caller gate, meaning the method resolved and the request "
        f"reached the handler; got {type(exc.value).__name__}: {message}"
    )
    assert "Missing required param" not in message, (
        "the request was judged on its params, so it got PAST the caller gate"
    )
