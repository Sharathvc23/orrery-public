"""
Prosecution-grade tests for channels.py — connections + inbound routing.

Every "integration" (wire to Slack / IMAP / SMTP) is stubbed for W4 —
tests cover the routing + validation layer, which is what the signed
mesh + session sandboxing depends on.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import channels


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {"chapter_channel_connections": []}
        self._next_id = 0

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            self._next_id += 1
            body["id"] = body.get("id") or f"conn-{self._next_id}"
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            body.setdefault("updated_at", datetime.now(UTC).isoformat())
            body.setdefault("status", body.get("status") or "active")
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            filters = self._parse_filters(table_or_path, params)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        if method == "DELETE":
            filters = self._parse_filters(table_or_path, params)
            remaining = []
            deleted = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    deleted.append(row)
                else:
                    remaining.append(row)
            self.tables[table] = remaining
            return deleted

        return None

    @staticmethod
    def _parse_filters(path, params):
        out = {}
        if "?" in path:
            _, qs = path.split("?", 1)
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    out[k] = v
        if params:
            for k, v in params.items():
                if k not in ("select", "order", "limit"):
                    out[k] = str(v)
        return out

    def _filter(self, rows, params):
        out = []
        for row in rows:
            ok = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                if not self._match(row, k, v):
                    ok = False
                    break
            if ok:
                out.append(row)
        limit = params.get("limit") if params else None
        if limit:
            out = out[: int(limit)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in str(predicate):
            return row.get(key) == predicate
        op, val = str(predicate).split(".", 1)
        rv = row.get(key)
        if op == "eq":
            return str(rv) == val
        return True


@pytest.fixture
def sb():
    bs = _FakePostgres()
    channels.init(pg_request_fn=bs)
    return bs


# ═══════════════════════════════════════════════════════════════
# validate_connect
# ═══════════════════════════════════════════════════════════════


def test_validate_ok_slack():
    ok, _ = channels.validate_connect("slack", "T12345ABC")
    assert ok is True


def test_validate_ok_email():
    ok, _ = channels.validate_connect("email", "alice@example.com")
    assert ok is True


def test_validate_rejects_unknown_kind():
    ok, reason = channels.validate_connect("mastodon", "foo")
    assert ok is False
    assert "unsupported kind" in reason


def test_validate_rejects_bad_email():
    ok, reason = channels.validate_connect("email", "not-an-email")
    assert ok is False
    assert "email" in reason


def test_validate_rejects_bad_slack_workspace():
    """ADVERSARIAL: Slack team ids always start with T — reject spoofed 'W...' ids."""
    ok, reason = channels.validate_connect("slack", "W12345ABC")
    assert ok is False


def test_validate_rejects_empty_remote_id():
    ok, _ = channels.validate_connect("slack", "")
    assert ok is False


def test_validate_rejects_oversized_remote_id():
    ok, _ = channels.validate_connect("email", "x" * 300 + "@e.com")
    assert ok is False


def test_validate_rejects_oversized_config():
    """ADVERSARIAL: 32 KiB config rejected."""
    huge = {"k": "x" * (32 * 1024)}
    ok, reason = channels.validate_connect("email", "a@b.co", huge)
    assert ok is False
    assert "config too large" in reason


def test_validate_config_must_be_dict():
    ok, _ = channels.validate_connect("email", "a@b.co", "config")  # type: ignore[arg-type]
    assert ok is False


# ═══════════════════════════════════════════════════════════════
# connect / list / get / disconnect
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_connect_creates_row(sb):
    result = await channels.connect(
        agent_id="alice",
        kind="slack",
        remote_id="T12345ABC",
        display_name="Alice's workspace",
    )
    assert result["kind"] == "slack"
    assert result["status"] == "active"
    assert len(sb.tables["chapter_channel_connections"]) == 1


@pytest.mark.asyncio
async def test_connect_upserts_existing(sb):
    await channels.connect("alice", "slack", "T12345ABC", display_name="v1")
    await channels.connect("alice", "slack", "T12345ABC", display_name="v2")
    assert len(sb.tables["chapter_channel_connections"]) == 1
    assert sb.tables["chapter_channel_connections"][0]["display_name"] == "v2"


@pytest.mark.asyncio
async def test_connect_rejects_invalid(sb):
    with pytest.raises(ValueError, match="email"):
        await channels.connect("alice", "email", "garbage")


@pytest.mark.asyncio
async def test_list_connections_filters_by_kind(sb):
    await channels.connect("alice", "slack", "T12345ABC")
    await channels.connect("alice", "email", "alice@e.co")
    await channels.connect("bob", "slack", "T67890XYZ")

    alice_all = await channels.list_connections("alice")
    assert len(alice_all) == 2

    alice_slack = await channels.list_connections("alice", kind="slack")
    assert len(alice_slack) == 1
    assert alice_slack[0]["remote_id"] == "T12345ABC"


@pytest.mark.asyncio
async def test_list_connections_empty_for_unknown(sb):
    assert await channels.list_connections("ghost") == []


@pytest.mark.asyncio
async def test_disconnect_removes_row(sb):
    conn = await channels.connect("alice", "slack", "T12345ABC")
    result = await channels.disconnect(conn["id"], agent_id="alice")
    assert result["status"] == "disconnected"
    assert len(sb.tables["chapter_channel_connections"]) == 0


@pytest.mark.asyncio
async def test_disconnect_refuses_non_owner(sb):
    """ADVERSARIAL: Bob can't disconnect Alice's channel."""
    conn = await channels.connect("alice", "slack", "T12345ABC")
    with pytest.raises(ValueError, match="only the owning agent"):
        await channels.disconnect(conn["id"], agent_id="bob")
    # Row survives.
    assert len(sb.tables["chapter_channel_connections"]) == 1


@pytest.mark.asyncio
async def test_disconnect_unknown_connection(sb):
    with pytest.raises(ValueError, match="not found"):
        await channels.disconnect("ghost-conn", agent_id="alice")


# ═══════════════════════════════════════════════════════════════
# test — stubbed integration check
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_test_updates_last_test_fields(sb):
    conn = await channels.connect("alice", "slack", "T12345ABC")
    result = await channels.test(conn["id"])
    # the stub is NOT a real connectivity check, so it must not claim ok —
    # last_test_ok stays NULL (untested), never a fake True.
    assert result["ok"] is None
    assert result["stub"] is True
    row = sb.tables["chapter_channel_connections"][0]
    assert row["last_test_at"] is not None
    assert row["last_test_ok"] is None


@pytest.mark.asyncio
async def test_test_unknown_connection(sb):
    with pytest.raises(ValueError, match="not found"):
        await channels.test("ghost")


# ═══════════════════════════════════════════════════════════════
# deliver_inbound
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_inbound_routes_to_owning_agent(sb):
    await channels.connect("alice", "slack", "T12345ABC")
    result = await channels.deliver_inbound(
        kind="slack",
        remote_id="T12345ABC",
        payload={"user": "U987", "text": "hi"},
    )
    assert result["delivered"] is True
    assert result["agent_id"] == "alice"
    # Session scope sandboxes the inbound message.
    assert result["session_scope"] == "agent:alice:slack:dm:U987"


@pytest.mark.asyncio
async def test_inbound_no_connection_returns_undelivered(sb):
    result = await channels.deliver_inbound(kind="slack", remote_id="T99999999", payload={"user": "U1", "text": "hi"})
    assert result["delivered"] is False
    assert "no active connection" in result.get("reason", "")


@pytest.mark.asyncio
async def test_inbound_rejects_unknown_kind(sb):
    with pytest.raises(ValueError, match="unsupported kind"):
        await channels.deliver_inbound(kind="mastodon", remote_id="x", payload={})


@pytest.mark.asyncio
async def test_inbound_honors_signature_verifier(sb):
    """ADVERSARIAL: if the verifier returns False, delivery is refused."""
    await channels.connect("alice", "slack", "T12345ABC")
    with pytest.raises(ValueError, match="signature verification"):
        await channels.deliver_inbound(
            kind="slack",
            remote_id="T12345ABC",
            payload={"user": "evil", "text": "forged"},
            verify_signature=lambda _p: False,
        )


@pytest.mark.asyncio
async def test_inbound_rejects_oversized_payload(sb):
    """ADVERSARIAL: 512 KiB payload rejected — keeps the router cheap."""
    await channels.connect("alice", "slack", "T12345ABC")
    payload = {"user": "U1", "text": "x" * (512 * 1024)}
    with pytest.raises(ValueError, match="payload too large"):
        await channels.deliver_inbound(kind="slack", remote_id="T12345ABC", payload=payload)


@pytest.mark.asyncio
async def test_inbound_falls_back_on_missing_sender(sb):
    """EDGE: payload with no 'sender'/'user' still gets a session scope."""
    await channels.connect("alice", "email", "alice@e.co")
    result = await channels.deliver_inbound(kind="email", remote_id="alice@e.co", payload={"subject": "hi"})
    assert result["delivered"] is True
    assert result["session_scope"] == "agent:alice:email:dm:unknown"


# ═══════════════════════════════════════════════════════════════
# send_outbound
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_send_outbound_requires_active_connection(sb):
    conn = await channels.connect("alice", "slack", "T12345ABC")
    # Flip status manually to disabled.
    sb.tables["chapter_channel_connections"][0]["status"] = "disabled"
    with pytest.raises(ValueError, match="disabled"):
        await channels.send_outbound(conn["id"], {"text": "hi"})


@pytest.mark.asyncio
async def test_send_outbound_requires_text(sb):
    conn = await channels.connect("alice", "slack", "T12345ABC")
    with pytest.raises(ValueError, match="'text' field"):
        await channels.send_outbound(conn["id"], {"no_text": "hi"})


@pytest.mark.asyncio
async def test_send_outbound_stub_does_not_claim_success(sb):
    """Outbound send is a W7 stub — it must report the message was NOT delivered
    (ok=False), never a false success, so no caller mistakes a no-op for a send."""
    conn = await channels.connect("alice", "slack", "T12345ABC")
    result = await channels.send_outbound(conn["id"], {"text": "hello world"})
    assert result["stub"] is True
    assert result["ok"] is False
    assert "not implemented" in result["note"].lower()
