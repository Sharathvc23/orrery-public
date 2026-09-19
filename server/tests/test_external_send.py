"""Outbound send — the gate, and the four-condition sandbox guarantee.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

🛑 THE CLAIM THIS FILE HAS TO EARN: **this build cannot email a real person.**
That is asserted from several independent directions rather than stated once,
because a single test proves only that one path is closed:

  * the default transport is the sandbox one, and it holds no HTTP client;
  * a real recipient is refused before a transport is even selected;
  * constructing the live transport without the explicit flag raises, so the
    plausible erosion — a future caller building it directly — is covered;
  * the flag is read through ``security_flag(default=False)``, so unset, empty
    and MISSPELLED all mean sandbox;
  * no test in this suite enables live sends, asserted mechanically over the
    source rather than by reviewer discipline.

And the gate: no send happens without an approved, single-use grant naming this
exact message. Driven against the REAL ``governance.consume_operational_approval``
rather than a stub — the integration is the thing under test.
"""

from __future__ import annotations

import pytest

import external_send


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Every test starts from "nobody configured anything"."""
    monkeypatch.delenv(external_send.LIVE_SENDS_FLAG, raising=False)
    monkeypatch.delenv(external_send.API_KEY_ENV, raising=False)
    external_send.reset_sandbox_log()
    yield
    external_send.reset_sandbox_log()


@pytest.fixture
def governed(monkeypatch):
    """The REAL gate over an in-memory approvals table. ``grant(key)`` seeds a
    spendable approval; everything else behaves as production does."""
    import governance

    approvals: list[dict] = []

    async def gov_pg(method, table, params=None, body=None):
        params = params or {}
        if method == "GET":
            want_status = (params.get("status") or "").removeprefix("eq.")
            want_kind = (params.get("kind") or "").removeprefix("eq.")
            return [
                r
                for r in approvals
                if (not want_status or r["status"] == want_status)
                and (not want_kind or r["kind"] == want_kind)
            ]
        if method == "PATCH":
            target = (params.get("id") or "").removeprefix("eq.")
            for r in approvals:
                if r["id"] == target:
                    r.update(body or {})
            return []
        if method == "POST":
            row = {"id": f"appr-{len(approvals) + 1}", "status": "pending", **(body or {})}
            approvals.append(row)
            return [row]
        return []

    governance.init(gov_pg, "test-org")

    def grant(action_key: str) -> dict:
        row = {
            "id": f"grant-{len(approvals) + 1}",
            "kind": external_send.SEND_APPROVAL_KIND,
            "status": "approved",
            "payload": {"action_key": action_key},
        }
        approvals.append(row)
        return row

    return type("G", (), {"grant": staticmethod(grant), "approvals": approvals})


SAFE = "someone@example.com"


def _key(to=SAFE, subject="Hello", body="Body"):
    return external_send.action_key(to, subject, body)


# ── 🛑 the sandbox guarantee ────────────────────────────────────────────────


def test_the_default_transport_is_the_sandbox_one():
    """Condition 3. With nothing configured — the state of every dev machine,
    every test run and every fresh deploy — the resolved transport cannot reach
    the network."""
    assert external_send.live_sends_enabled() is False
    assert isinstance(external_send._transport(), external_send.SandboxTransport)


def test_the_sandbox_transport_contains_no_http_client():
    """It cannot reach the network, rather than choosing not to.

    ⚠️ Checked over the AST, not the text. A substring scan trips on this class's
    own docstring — which says it opens no socket — and, worse, would be equally
    satisfied by a comment claiming so while the code did the opposite. Names
    that appear in prose are not names the code can call.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(external_send.SandboxTransport).lstrip())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)

    forbidden = {"httpx", "requests", "urllib", "socket", "aiohttp", "urlopen"}
    assert not (names & forbidden), f"SandboxTransport can reach {sorted(names & forbidden)}"


@pytest.mark.parametrize("flag", ["", "  ", "ture", "yes-please", "0", "false", "off"])
def test_unset_empty_and_misspelled_all_mean_sandbox(monkeypatch, flag):
    """Condition 1. ``security_flag(default=False)`` means only a recognised
    truthy spelling enables live sends — ``KLAVIYO_LIVE_SENDS=ture`` is a typo,
    not a decision to start emailing people."""
    monkeypatch.setenv(external_send.LIVE_SENDS_FLAG, flag)
    monkeypatch.setenv(external_send.API_KEY_ENV, "pk_live_whatever")
    assert external_send.live_sends_enabled() is False
    assert isinstance(external_send._transport(), external_send.SandboxTransport)


def test_the_flag_alone_does_not_enable_live_sends(monkeypatch):
    """Condition 2. No key -> sandbox, never an unauthenticated attempt against
    the live endpoint."""
    monkeypatch.setenv(external_send.LIVE_SENDS_FLAG, "true")
    assert external_send.live_sends_enabled() is False
    assert isinstance(external_send._transport(), external_send.SandboxTransport)


def test_constructing_the_live_transport_without_the_flag_raises(monkeypatch):
    """ADVERSARIAL — the plausible way this erodes is a future caller building
    the transport directly instead of going through ``_transport``. The check is
    in ``__init__`` so that path refuses too."""
    with pytest.raises(external_send.SendRefused) as exc:
        external_send.KlaviyoTransport("pk_live_realkey")
    assert exc.value.reason == "live_sends_disabled"


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["real.person@gmail.com", "ceo@acme.co", "a@orrery.dev"])
async def test_a_real_address_is_refused_before_any_transport_is_chosen(governed, address):
    """Condition 4, and the one that makes this safe to DEVELOP against. The
    usual sandbox failure is a live key reaching a dev environment; an allowlist
    of addresses that cannot belong to anyone survives that."""
    governed.grant(_key(to=address))
    with pytest.raises(external_send.SendRefused) as exc:
        await external_send.send_external(
            actor_agent_id="a1", to=address, subject="Hello", body="Body"
        )
    assert exc.value.reason == "recipient_not_reserved"
    assert external_send.sandbox_log() == []


@pytest.mark.parametrize(
    "address",
    ["x@example.com", "x@example.org", "x@anything.test", "x@foo.invalid", "x@sub.example.net"],
)
def test_rfc2606_reserved_addresses_are_accepted_as_sandbox_recipients(address):
    assert external_send._is_reserved(address)


@pytest.mark.parametrize("address", ["x@gmail.com", "x@notexample.com", "x@example.company"])
def test_lookalike_domains_are_not_mistaken_for_reserved_ones(address):
    """ADVERSARIAL: ``notexample.com`` and ``example.company`` both contain the
    reserved string. A substring check would let real mail through."""
    assert not external_send._is_reserved(address)


def test_the_suite_wide_guard_blocks_a_live_send_even_when_all_four_conditions_are_defeated(
    monkeypatch,
):
    """🛑 THE LAST RESORT, and the strongest form of the claim.

    Each of the four sandbox conditions is defeatable by a test that sets the
    environment — which is exactly how a suite ends up emailing someone. So
    ``conftest`` replaces the live transport's send for the WHOLE server suite.
    Here every condition is deliberately satisfied: the flag is on, a key is
    present, the resolved transport really is the live one — and the send still
    cannot happen.

    It fails loudly rather than no-opping. A quiet stub would let a test assert a
    successful live send and pass, which is how the guarantee would rot.
    """
    monkeypatch.setenv(external_send.LIVE_SENDS_FLAG, "true")
    monkeypatch.setenv(external_send.API_KEY_ENV, "pk_live_definitely_not_real")

    assert external_send.live_sends_enabled() is True
    transport = external_send._transport()
    assert isinstance(transport, external_send.KlaviyoTransport)

    with pytest.raises(AssertionError, match="LIVE send"):
        transport.send({"to": "victim@gmail.com", "subject": "s", "body": "b", "metric": "m"})


def test_the_live_transport_builds_the_request_it_would_send(monkeypatch):
    """The edge is real and reviewable without being performed: assert on the
    request the transport WOULD build. That is the alternative the guard's own
    error message points a future author to, so it had better exist."""
    import ast
    import pathlib

    # ⚠️ Read the MODULE SOURCE, not the live attribute: the suite-wide guard has
    # already replaced ``KlaviyoTransport.send``, so introspecting the class
    # would inspect the guard. That the guard is what you find there is itself
    # reassuring — it means it really is installed everywhere.
    tree = ast.parse(pathlib.Path(external_send.__file__).read_text())
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "KlaviyoTransport"
    )
    send = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "send")
    src = ast.unparse(send)
    assert "Klaviyo-API-Key" in src
    assert external_send.KLAVIYO_ENDPOINT.startswith("https://")
    assert external_send.KLAVIYO_REVISION, "the API revision must be pinned, not floating"


# ── the gate ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_grant_means_no_send_and_the_caller_is_told_to_wait(governed):
    with pytest.raises(external_send.SendRefused) as exc:
        await external_send.send_external(actor_agent_id="a1", to=SAFE, subject="Hello", body="Body")
    assert exc.value.reason == "pending_approval"
    assert exc.value.approval, "the refusal must name the queued approval to act on"
    assert external_send.sandbox_log() == [], "a send happened without an approval"


@pytest.mark.asyncio
async def test_an_approved_grant_sends_exactly_once(governed):
    """SINGLE-USE. Approve-once-send-forever is the failure PR1's gate exists to
    prevent, and a mailing verb is where it would hurt most."""
    governed.grant(_key())

    first = await external_send.send_external(
        actor_agent_id="a1", to=SAFE, subject="Hello", body="Body"
    )
    assert first["status"] == "sent"
    assert first["live"] is False
    assert len(external_send.sandbox_log()) == 1

    with pytest.raises(external_send.SendRefused) as exc:
        await external_send.send_external(
            actor_agent_id="a1", to=SAFE, subject="Hello", body="Body"
        )
    assert exc.value.reason == "pending_approval"
    assert len(external_send.sandbox_log()) == 1, "the grant was spendable twice"


@pytest.mark.asyncio
async def test_approving_a_message_does_not_approve_a_different_body(governed):
    """ADVERSARIAL. The body is bound by digest, so an approved send cannot be
    re-aimed at different content. Binding only the address would make the grant
    'you may email this person' — a channel, not a message."""
    governed.grant(_key(subject="Hello", body="Body"))

    with pytest.raises(external_send.SendRefused) as exc:
        await external_send.send_external(
            actor_agent_id="a1", to=SAFE, subject="Hello", body="Something else entirely"
        )
    assert exc.value.reason == "pending_approval"
    assert external_send.sandbox_log() == []


@pytest.mark.asyncio
async def test_approving_a_message_does_not_approve_a_different_recipient(governed):
    governed.grant(_key(to="a@example.com"))
    with pytest.raises(external_send.SendRefused):
        await external_send.send_external(
            actor_agent_id="a1", to="b@example.com", subject="Hello", body="Body"
        )
    assert external_send.sandbox_log() == []


@pytest.mark.asyncio
async def test_governance_being_unreachable_refuses_the_send(governed):
    """ADVERSARIAL: a gate that opens when its store is unreachable is worse than
    no gate, because it is trusted."""
    import governance

    async def broken(*a, **kw):
        raise RuntimeError("approvals table unreachable")

    governance.init(broken, "test-org")

    with pytest.raises(external_send.SendRefused):
        await external_send.send_external(actor_agent_id="a1", to=SAFE, subject="H", body="B")
    assert external_send.sandbox_log() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"to": "not-an-address", "subject": "H", "body": "B"}, "recipient_invalid"),
        ({"to": SAFE, "subject": "", "body": "B"}, "subject_required"),
        ({"to": SAFE, "subject": "H", "body": "   "}, "body_required"),
        ({"to": SAFE, "subject": "x" * 301, "body": "B"}, "subject_too_long"),
    ],
)
async def test_a_malformed_message_is_refused_before_it_files_an_approval(governed, kwargs, reason):
    """Order matters: validate, then gate. Otherwise every typo files an approval
    an operator has to read and reject, and the queue becomes noise."""
    with pytest.raises(external_send.SendRefused) as exc:
        await external_send.send_external(actor_agent_id="a1", **kwargs)
    assert exc.value.reason == reason
    assert not governed.approvals, "a malformed message queued an approval"


@pytest.mark.asyncio
async def test_the_send_is_recorded_whichever_transport_ran(governed, monkeypatch):
    """A sandbox send that left no trace would make the drain path unauditable
    exactly where it most needs to be."""
    receipts: list[dict] = []

    async def fake_receipt(actor, to, subject, key, grant, result):
        receipts.append({"to": to, "transport": result.get("transport"), "grant": grant})

    monkeypatch.setattr(external_send, "_receipt", fake_receipt)
    governed.grant(_key())
    await external_send.send_external(actor_agent_id="a1", to=SAFE, subject="Hello", body="Body")

    assert len(receipts) == 1
    assert receipts[0]["transport"] == "sandbox"
    assert receipts[0]["grant"], "the receipt must name the grant that authorised the send"
