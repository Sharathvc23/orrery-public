"""The outbox edge for outbound email — enqueue, drain, and the deferral rule.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

⚠️ THE PROPERTY THIS FILE EXISTS FOR: **a message waiting on an operator must not
be dropped, and must not age.** A 202 is neither success nor failure. Treating it
as success deletes the message; treating it as failure burns the backoff schedule
and eventually purges it — so a message would be discarded precisely because a
human had not answered yet, and the queue would look empty rather than blocked.
Both mistakes are silent, which is why they get their own tests.

The agent holds no API key and talks to no vendor; it posts to the org, which owns
the gate and the credential. A test that reached Klaviyo would be a bug in the
test AND in the design.
"""

from __future__ import annotations

from typing import Any

import pytest

from community_member import external_send_edge, outbox


@pytest.fixture(autouse=True)
def fresh_outbox(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_OUTBOX", str(tmp_path / "outbox.db"))
    outbox.reset_for_test(tmp_path / "outbox.db")
    yield
    outbox.reset_for_test(None)


class _Resp(dict):
    """A response object that carries a status code, like the real client's."""

    def __init__(self, status_code: int, **body: Any) -> None:
        super().__init__(**body)
        self.status_code = status_code


class _OrgClient:
    """Stands in for the org. Records what was posted; never touches a network."""

    def __init__(self, *responses: Any) -> None:
        self._responses = list(responses)
        self.posts: list[tuple[str, dict]] = []

    def _post(self, path: str, body: dict) -> Any:
        self.posts.append((path, body))
        return self._responses.pop(0) if self._responses else _Resp(200, status="sent")


def _enqueue(agent="a1", to="someone@example.com"):
    return external_send_edge.enqueue_email(agent, to=to, subject="Hello", body="Body")


# ── enqueue ─────────────────────────────────────────────────────────────────


def test_the_edge_registers_itself_as_a_drain_handler():
    """Registration rather than an import inside outbox.py: the queue is generic
    durable machinery and must not know that Klaviyo exists."""
    assert external_send_edge.KIND in outbox.DRAIN_HANDLERS


def test_enqueue_queues_without_sending():
    seq = _enqueue()
    assert seq > 0
    assert outbox.pending_count("a1") == 1
    entry = outbox.peek("a1")[0]
    assert entry["kind"] == external_send_edge.KIND
    assert entry["patch"]["to"] == "someone@example.com"


def test_an_unknown_kind_cannot_be_enqueued():
    """Refused at enqueue, not at drain. An entry nothing can handle would sit in
    the queue retrying forever, consuming the backoff schedule and looking from
    the outside like a network problem."""
    with pytest.raises(ValueError, match="unknown outbox kind"):
        outbox.enqueue("a1", {"x": 1}, kind="carrier_pigeon")


# ── drain ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_sent_message_leaves_the_queue():
    _enqueue()
    client = _OrgClient(_Resp(200, status="sent"))
    stats = await outbox.drain("a1", client)
    assert stats["succeeded"] == 1
    assert outbox.pending_count("a1") == 0
    assert client.posts[0][0] == external_send_edge.ENDPOINT


@pytest.mark.asyncio
async def test_a_pending_approval_keeps_the_message_and_does_not_age_it():
    """⚠️ THE LOAD-BEARING TEST. 202 means an operator has not answered yet. The
    message stays, and — the part that is easy to get wrong — its attempt count
    does NOT rise, so the backoff schedule is not consumed by waiting."""
    _enqueue()
    client = _OrgClient(_Resp(202, status="pending_approval", approval_id="appr-1"))

    stats = await outbox.drain("a1", client)

    assert stats["deferred"] == 1
    assert stats["succeeded"] == 0
    assert stats["failed"] == 0, "waiting on a human was recorded as a failure"
    assert outbox.pending_count("a1") == 1, "a message awaiting approval was dropped"
    entry = outbox.peek("a1")[0]
    assert entry["attempts"] == 0, "deferral burned a retry; enough of them would purge the message"


@pytest.mark.asyncio
async def test_a_deferred_message_sends_once_the_operator_approves():
    """The whole point of keeping it: the next drain after approval delivers it."""
    _enqueue()
    client = _OrgClient(_Resp(202, status="pending_approval"), _Resp(200, status="sent"))

    first = await outbox.drain("a1", client)
    assert first["deferred"] == 1
    second = await outbox.drain("a1", client)
    assert second["succeeded"] == 1
    assert outbox.pending_count("a1") == 0


@pytest.mark.asyncio
async def test_a_client_that_hides_the_status_code_still_defers_on_a_pending_body():
    """ADVERSARIAL: belt and braces. A client that returns only the JSON body must
    not turn a pending approval into a delete — the body says so too, so read it."""
    _enqueue()

    class _BodyOnlyClient(_OrgClient):
        def _post(self, path, body):
            self.posts.append((path, body))
            return {"status": "pending_approval"}

    stats = await outbox.drain("a1", _BodyOnlyClient())
    assert stats["deferred"] == 1
    assert outbox.pending_count("a1") == 1


@pytest.mark.asyncio
async def test_a_rejected_message_backs_off_rather_than_deferring():
    """A 422 is the message being wrong, not a human being slow. It must consume
    attempts so it eventually purges instead of retrying forever."""
    _enqueue()
    client = _OrgClient(_Resp(422, detail={"reason": "recipient_invalid"}))

    stats = await outbox.drain("a1", client)

    assert stats["failed"] == 1
    assert stats["deferred"] == 0
    entry = outbox.peek("a1", limit=50)
    assert entry == [] or entry[0]["attempts"] == 1


@pytest.mark.asyncio
async def test_settings_patches_still_drain_exactly_as_before():
    """The dispatcher must not change the path it was generalised out of."""
    calls: list[tuple] = []

    class _SettingsClient:
        def update_settings(self, agent_id, patch):
            calls.append((agent_id, patch))
            return {"ok": True}

    outbox.enqueue("a1", {"theme": "dark"})
    stats = await outbox.drain("a1", _SettingsClient())
    assert stats["succeeded"] == 1
    assert calls == [("a1", {"theme": "dark"})]


@pytest.mark.asyncio
async def test_mixed_kinds_drain_independently_in_one_pass():
    """EDGE: a settings patch and an email in the same queue. Each takes its own
    handler, and one deferring must not hold up the other."""

    class _Both(_OrgClient):
        def update_settings(self, agent_id, patch):
            return {"ok": True}

    outbox.enqueue("a1", {"theme": "dark"})
    _enqueue()

    stats = await outbox.drain("a1", _Both(_Resp(202, status="pending_approval")))
    assert stats["succeeded"] == 1, "the settings patch should still have gone"
    assert stats["deferred"] == 1
    assert outbox.pending_count("a1") == 1


# ── the agent never holds the credential ────────────────────────────────────


def test_the_edge_names_no_vendor_endpoint_and_no_api_key():
    """ADVERSARIAL — the design property most likely to erode, because sending
    directly would be simpler. If the agent ever gains the key, the org's gate
    becomes a remote opinion the agent can proceed past."""
    import ast
    import pathlib

    src = pathlib.Path(external_send_edge.__file__).read_text()
    lowered = ast.unparse(ast.parse(src)).lower()
    for forbidden in ("klaviyo.com", "api_key", "apikey", "authorization", "httpx", "requests"):
        assert forbidden not in lowered, f"the agent-side edge references {forbidden}"


# ── the v1 -> v2 migration, against a REAL v1 database ──────────────────────


@pytest.mark.asyncio
async def test_a_v1_database_gains_the_column_and_its_rows_still_drain(tmp_path, monkeypatch):
    """⚠️ Real agents have an outbox.db written by v1. Asserted by BUILDING one
    with the old schema rather than by trusting ``CREATE TABLE IF NOT EXISTS`` —
    which is a no-op on an existing table, so the column has to be ALTERed in.

    The default matters as much as the column: a v1 row with no kind must drain
    as a settings patch. Falling through a dispatcher that found no handler would
    leave it queued forever, and a silently un-drained queue looks exactly like an
    empty one.
    """
    import sqlite3

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            patch_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt_at INTEGER,
            last_error TEXT,
            next_retry_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta(key, value) VALUES('schema_version', '1');
        INSERT INTO outbox(agent_id, patch_json, created_at, next_retry_at)
            VALUES('a1', '{"theme": "dark"}', 1, 0);
    """)
    conn.commit()
    conn.close()

    monkeypatch.setenv("COMMUNITY_MEMBER_OUTBOX", str(db))
    outbox.reset_for_test(db)

    # The v1 row is visible and defaulted, not skipped.
    entry = outbox.peek("a1")[0]
    assert entry["kind"] == "settings_patch"
    assert entry["patch"] == {"theme": "dark"}

    calls: list[tuple] = []

    class _SettingsClient:
        def update_settings(self, agent_id, patch):
            calls.append((agent_id, patch))
            return {"ok": True}

    stats = await outbox.drain("a1", _SettingsClient())
    assert stats["succeeded"] == 1, "a row written by v1 did not drain after migration"
    assert calls == [("a1", {"theme": "dark"})]

    # ...and the recorded version is corrected, not left claiming v1 forever.
    conn = sqlite3.connect(db)
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    conn.close()
    assert version == "2", "the database still claims schema v1 after being migrated"
