"""Which A2A methods need a caller, enforced and declared.

This surface used to authenticate nobody: `("POST", "/")` was open and its own
recorded reason said so, and an unauthenticated JSON-RPC POST was accepted and
answered on every deployed agent. The line is now drawn per METHOD, because the
route carries both kinds of traffic — a read of a task you already hold the id
of is part of a peer's polling flow, and a send creates work on someone else's
agent and spends their owner's provider credit.

⚠️ BOTH LISTS ARE DERIVED FROM ONE DECLARATION and every dispatchable method is
required to appear in it. The failure that produced this module was a route
DEFAULTING TO OPEN, so a method nobody classified must not quietly inherit that
— it is caller-required, and the test below makes "nobody classified it" a
reported bug rather than a silent default.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import a2a_auth
from community_member import a2a_rpc as rpc
from community_member.config import Config
from community_member.crypto import generate_ed25519_keypair
from community_member.server import create_app

pytestmark = pytest.mark.no_local_token

RPC_PY = Path(rpc.__file__)


def _cfg() -> Config:
    c = Config()
    c.agent_id = "auth-surface-agent"
    c.name = "AuthSurface"
    c.description = "A member"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


@pytest.fixture
def client():
    return TestClient(create_app(_cfg()))


def _envelope(method: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "1",
        "method": method,
        "params": {"id": "t-auth", "message": {"role": "user", "parts": []}},
    }


def _signed_headers_for(payload: str) -> dict[str, str]:
    from community_member.a2a_client_v2 import _signed_headers

    kp = generate_ed25519_keypair()
    return _signed_headers(payload, "peer-agent", kp["private_key"], kp["public_key"], scheme="ed25519")


def _error(response) -> dict:
    body = response.json() if not response.text.startswith("data:") else json.loads(response.text.split("data: ", 1)[1])
    return body.get("error") or {}


# ── the declaration covers everything the dispatch can route ─────────────────


def _dispatchable_methods() -> set[str]:
    """Every method literal the dispatch compares against, read from the source.

    Derived rather than listed: a method added to the if-chain without an access
    class must fail here, which is the whole point of the module.
    """
    tree = ast.parse(RPC_PY.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "method":
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                    found.add(comparator.value)
    return found


def test_every_dispatchable_method_has_a_declared_access_class():
    methods = _dispatchable_methods()
    assert methods, "no dispatch comparisons found — this guard went blind"
    undeclared = sorted(methods - set(a2a_auth.METHOD_ACCESS))
    assert not undeclared, (
        f"these methods are dispatched but not classified in a2a_auth.METHOD_ACCESS: {undeclared}. "
        "An unclassified method is treated as caller-required, so nothing is exposed — but say so "
        "deliberately rather than leaving the next reader to infer it."
    )


# ⚠️ THE RULING, PINNED. Every other test here derives from METHOD_ACCESS, which
# makes them self-consistent and therefore BLIND to the table itself changing —
# move a method between the classes and the derived tests simply check it in the
# other list and stay green. Caught by planting exactly that.
#
# So the decision is written down once, the way the local-API open list already
# is: widening this is a security review, not a test edit. The reasons are the
# ruling's own — a send creates work on someone else's agent and spends their
# owner's provider credit; a read of a task whose id you already hold does not,
# and gating it would break a peer polling a task it was legitimately told about.
EXPECTED_ACCESS = {
    "tasks/get": "open",
    # ⚠️ CANCEL MOVED FROM "open" TO "caller-required", AND THE MOVE WAS A
    # CORRECTION. It was originally grouped with the reads because both take an
    # id you already know — the wrong axis. Cancel is DESTRUCTIVE and, unlike a
    # read, leaves no attribution: with no signature there is nothing to trace
    # afterwards. Verified reachable anonymously on a live agent before the
    # change (a non-existent id returned -32001 rather than a refusal).
    "tasks/cancel": "caller-required",
    "tasks/resubscribe": "open",
    "tasks/send": "caller-required",
    "tasks/sendSubscribe": "caller-required",
    "nanda/cosignReceipt": "caller-required",
    # An operator surface, not a peer one: it takes no task id and answers how
    # many tasks this agent holds. Gated because an inventory size is more than
    # any open read discloses, even though it returns no ids.
    "nanda/legacyTaskCensus": "caller-required",
}


def test_the_access_table_is_exactly_what_was_ruled():
    changed = {
        m: (EXPECTED_ACCESS.get(m), a2a_auth.METHOD_ACCESS.get(m))
        for m in set(EXPECTED_ACCESS) | set(a2a_auth.METHOD_ACCESS)
        if EXPECTED_ACCESS.get(m) != a2a_auth.METHOD_ACCESS.get(m)
    }
    assert not changed, (
        f"the A2A access classes changed (method: was -> now): {changed}. "
        "Opening a method is a security review, not a test edit; closing one can break a "
        "peer's polling flow. Either way, say so deliberately."
    )


def test_the_two_sets_partition_the_declaration():
    assert a2a_auth.OPEN_METHODS | a2a_auth.AUTHENTICATED_METHODS == set(a2a_auth.METHOD_ACCESS)
    assert not (a2a_auth.OPEN_METHODS & a2a_auth.AUTHENTICATED_METHODS)
    assert a2a_auth.AUTHENTICATED_METHODS, "nothing is gated — the surface is open again"


def test_an_unlisted_method_is_caller_required_not_open():
    """The default that the original defect got wrong, asserted directly."""
    assert a2a_auth.requires_caller("tasks/somethingNobodyClassified")
    assert a2a_auth.requires_caller(None)


# ── enforced over the wire, derived from the declaration ─────────────────────


def test_every_open_method_is_still_reachable_unauthenticated(client):
    """Discovery and reads must not have been caught by the gate — breaking
    them would break a legitimate peer's polling flow, which is the cost this
    split exists to avoid."""
    for method in sorted(a2a_auth.OPEN_METHODS):
        r = client.post("/", json=_envelope(method))
        err = _error(r)
        assert err.get("code") != rpc.ERROR_CALLER_REQUIRED, f"{method} was gated; it is declared open"

    for path in ("/.well-known/agent.json", "/.well-known/agent-card.json"):
        assert client.get(path).status_code == 200, f"{path} stopped being reachable"


def test_every_gated_method_is_refused_unauthenticated(client):
    for method in sorted(a2a_auth.AUTHENTICATED_METHODS):
        r = client.post("/", json=_envelope(method))
        err = _error(r)
        assert err.get("code") == rpc.ERROR_CALLER_REQUIRED, (
            f"{method} is declared caller-required and was not refused: {r.text[:200]}"
        )


def test_the_aliases_are_gated_exactly_as_the_names_they_alias(client):
    """A gate applied to the v0.2 name and not its current-spec alias would be
    an open door with a new name on it."""
    for alias, canonical in rpc.METHOD_ALIASES.items():
        r = client.post("/", json=_envelope(alias))
        gated = _error(r).get("code") == rpc.ERROR_CALLER_REQUIRED
        assert gated == a2a_auth.requires_caller(canonical), (
            f"{alias!r} is gated={gated} but its target {canonical!r} "
            f"requires_caller={a2a_auth.requires_caller(canonical)}"
        )


# ── the refusal is a typed JSON-RPC error, not a bare 401 ────────────────────


def test_cancel_is_refused_unauthenticated_while_reads_are_not(client):
    """⚠️ THE CORRECTION, ASSERTED AS A CONTRAST. Cancel moved to the gated side
    and the reads did not, so testing cancel alone would not show that the line
    moved where it was meant to and nowhere else."""
    cancel = client.post("/", json=_envelope("tasks/cancel"))
    assert _error(cancel).get("code") == rpc.ERROR_CALLER_REQUIRED, (
        "anonymous cancel is still reachable — it is destructive and leaves no attribution"
    )
    for read in ("tasks/get", "tasks/resubscribe"):
        r = client.post("/", json=_envelope(read))
        assert _error(r).get("code") != rpc.ERROR_CALLER_REQUIRED, f"{read} was gated with cancel"


def test_the_refusal_is_a_json_rpc_error_object(client):
    """A middleware 401 arrives from a layer above the protocol and a stock
    client cannot surface it. The shape is the deliverable, not the status."""
    r = client.post("/", json=_envelope("tasks/send"))
    assert r.status_code == 200, f"the refusal came back as HTTP {r.status_code}, not a protocol error"
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "1", "the error did not carry the request id back"
    assert body["error"]["code"] == rpc.ERROR_CALLER_REQUIRED
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]
    assert "result" not in body


def test_a_streaming_refusal_arrives_as_an_sse_frame(client):
    """A client that has opened an event stream is not reading a status code any
    more, so the refusal has to be a frame."""
    r = client.post("/", json=_envelope("tasks/sendSubscribe"))
    assert r.text.startswith("data: "), f"the streaming refusal was not an SSE frame: {r.text[:120]}"
    assert _error(r)["code"] == rpc.ERROR_CALLER_REQUIRED


# ── a genuine caller gets through ────────────────────────────────────────────


def test_a_signed_caller_is_admitted(client):
    """DETECTOR VALIDATION for the whole file: if nothing could get through, the
    refusals above would be indistinguishable from a broken endpoint."""
    payload = json.dumps(_envelope("tasks/send"))
    r = client.post("/", content=payload, headers=_signed_headers_for(payload))
    assert _error(r).get("code") != rpc.ERROR_CALLER_REQUIRED, "a correctly signed caller was refused"


@pytest.mark.parametrize(
    "mutate,why",
    [
        (lambda h: {**h, "X-Agent-Signature": "AAAA"}, "a wrong signature"),
        (lambda h: {k: v for k, v in h.items() if k != "X-Agent-Signature"}, "no signature at all"),
        (lambda h: {**h, "X-Agent-Timestamp": "0"}, "a timestamp outside the freshness window"),
        (lambda h: {k: v for k, v in h.items() if k != "X-Agent-DID-Key"}, "no key to verify against"),
        (lambda h: {**h, "X-Agent-Sig-Scheme": "hmac-sha256"}, "a scheme this runtime cannot verify"),
    ],
)
def test_a_caller_that_does_not_verify_is_refused(client, mutate, why):
    """Each of these is a way a caller could look authenticated without being
    verifiable. The HMAC case matters most: this runtime holds no shared secret
    for a peer, so accepting that scheme would accept anything."""
    payload = json.dumps(_envelope("tasks/send"))
    r = client.post("/", content=payload, headers=mutate(_signed_headers_for(payload)))
    assert _error(r).get("code") == rpc.ERROR_CALLER_REQUIRED, f"admitted a caller with {why}"


def test_a_signature_over_different_bytes_is_refused(client):
    """The signature covers the RAW body. Re-serialising a parsed dict produces
    different bytes, so a body that was signed and then altered must not pass."""
    signed_payload = json.dumps(_envelope("tasks/send"))
    headers = _signed_headers_for(signed_payload)
    altered = json.dumps(_envelope("tasks/sendSubscribe"))
    r = client.post("/", content=altered, headers=headers)
    assert _error(r).get("code") == rpc.ERROR_CALLER_REQUIRED, "a signature from a different body was accepted"


# ── the card declares it ─────────────────────────────────────────────────────


def test_the_card_declares_the_scheme_it_actually_enforces(client):
    """A 401 a client can anticipate is a different product from one it
    discovers. Both card paths must carry it."""
    for path in ("/.well-known/agent.json", "/.well-known/agent-card.json"):
        card = client.get(path).json()
        schemes = card.get("securitySchemes") or {}
        assert schemes, f"{path} declares no securitySchemes"
        scheme = next(iter(schemes.values()))
        assert scheme["type"] == "apiKey", "the declared scheme is not the one we enforce"
        assert scheme["in"] == "header"
        assert scheme["name"] == "X-Agent-Signature", (
            "the card names a header other than the one the server actually reads"
        )
        assert card.get("security"), f"{path} declares a scheme but requires nothing"


def test_the_card_publishes_the_per_method_truth_it_enforces(client):
    """The current spec's `security` is card-level and cannot say "reads are
    open", so the exact table goes in the NANDA extension — derived from the
    enforcement table, so the card cannot advertise a policy the handler does
    not apply."""
    card = client.get("/.well-known/agent-card.json").json()
    published = card["x-nanda"]["a2a_method_access"]
    assert published == dict(sorted(a2a_auth.METHOD_ACCESS.items())), (
        "the card's published access table has drifted from the one the handler enforces"
    )
