"""
Prosecution-grade tests for community_member.channel_receiver.

The thesis: no inbound message reaches the agent without a verified
signature, no timestamp older than 5 minutes is accepted, the audit
log is hash-chained and tamper-evident, and the receiver never
crashes on hostile input.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from community_member import channel_receiver as cr

# ═══════════════════════════════════════════════════════
# verify_slack_signature — Slack v0 spec
# ═══════════════════════════════════════════════════════


def _slack_sign(secret: str, timestamp: str, body: bytes) -> str:
    sig_base = f"v0:{timestamp}:".encode() + body
    return "v0=" + hmac.new(secret.encode(), sig_base, hashlib.sha256).hexdigest()


def test_slack_verify_happy():
    secret = "8f742231b10e8888abcd99yyyzzz85a5"
    ts = "1735689600"
    body = b'{"type":"event_callback","team_id":"T12345"}'
    sig = _slack_sign(secret, ts, body)
    ok, reason = cr.verify_slack_signature(body, ts, sig, secret, now=1735689660)
    assert ok, reason


def test_slack_verify_rejects_forged_signature():
    """ADVERSARIAL: attacker guesses a signature. Refused."""
    body = b'{"team_id":"T12345"}'
    ok, reason = cr.verify_slack_signature(body, "1735689600", "v0=" + "f" * 64, "secret", now=1735689600)
    assert ok is False
    assert "mismatch" in reason


def test_slack_verify_rejects_wrong_secret():
    """ADVERSARIAL: legitimate Slack signature but attacker uses the wrong secret.
    Different secret → different expected sig → mismatch."""
    ts = "1735689600"
    body = b'{"team_id":"T12345"}'
    sig = _slack_sign("RIGHT-SECRET", ts, body)
    ok, _ = cr.verify_slack_signature(body, ts, sig, "WRONG-SECRET", now=1735689600)
    assert ok is False


def test_slack_verify_rejects_replay_outside_window():
    """ADVERSARIAL: attacker replays a 6-minute-old request. Refused."""
    secret = "secret"
    ts = "1735689600"
    body = b'{"team_id":"T12345"}'
    sig = _slack_sign(secret, ts, body)
    # Clock is 6 minutes after ts → outside 300s window
    ok, reason = cr.verify_slack_signature(body, ts, sig, secret, now=1735689600 + 361)
    assert ok is False
    assert "replay window" in reason


def test_slack_verify_rejects_future_timestamp_outside_window():
    """ADVERSARIAL: timestamp 10 minutes in the future. Refused."""
    secret = "secret"
    ts = "1735689600"
    body = b'{"team_id":"T12345"}'
    sig = _slack_sign(secret, ts, body)
    ok, reason = cr.verify_slack_signature(body, ts, sig, secret, now=1735689600 - 600)
    assert ok is False
    assert "replay window" in reason


def test_slack_verify_rejects_malformed_signature():
    ok, reason = cr.verify_slack_signature(b"{}", "1735689600", "not-a-signature", "s", now=1735689600)
    assert ok is False
    assert "malformed" in reason or "missing" in reason


def test_slack_verify_rejects_missing_timestamp():
    ok, _ = cr.verify_slack_signature(b"{}", "", "v0=abc", "s", now=1735689600)
    assert ok is False


def test_slack_verify_rejects_non_numeric_timestamp():
    ok, _ = cr.verify_slack_signature(b"{}", "not-a-number", "v0=abc", "s", now=1735689600)
    assert ok is False


def test_slack_verify_rejects_empty_secret():
    ok, reason = cr.verify_slack_signature(b"{}", "1735689600", "v0=abc", "", now=1735689600)
    assert ok is False
    assert "signing secret" in reason


# ═══════════════════════════════════════════════════════
# verify_generic_hmac
# ═══════════════════════════════════════════════════════


def _generic_sign(secret: str, timestamp: str, body: bytes) -> str:
    sig_base = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode(), sig_base, hashlib.sha256).hexdigest()


def test_generic_verify_happy():
    secret = "shared-secret-for-this-webhook"
    ts = "1735689600"
    body = b'{"from":"alice@example.com","subject":"hi"}'
    sig = _generic_sign(secret, ts, body)
    ok, reason = cr.verify_generic_hmac(body, ts, sig, secret, now=1735689600)
    assert ok, reason


def test_generic_verify_rejects_non_hex_signature():
    ok, reason = cr.verify_generic_hmac(b"{}", "1735689600", "ZZZ", "s", now=1735689600)
    assert ok is False
    assert "64-char hex" in reason


def test_generic_verify_rejects_wrong_length_signature():
    ok, reason = cr.verify_generic_hmac(b"{}", "1735689600", "abc", "s", now=1735689600)
    assert ok is False
    assert "64-char hex" in reason


def test_generic_verify_rejects_forged_signature():
    """ADVERSARIAL: right format, wrong value."""
    ok, _ = cr.verify_generic_hmac(b"{}", "1735689600", "a" * 64, "real-secret", now=1735689600)
    assert ok is False


def test_generic_verify_rejects_replay_outside_window():
    secret = "s"
    ts = "1735689600"
    body = b"{}"
    sig = _generic_sign(secret, ts, body)
    ok, reason = cr.verify_generic_hmac(body, ts, sig, secret, now=1735689600 + 301)
    assert ok is False
    assert "replay window" in reason


def test_generic_verify_rejects_empty_secret():
    ok, reason = cr.verify_generic_hmac(b"{}", "1735689600", "a" * 64, "", now=1735689600)
    assert ok is False
    assert "secret" in reason


# ═══════════════════════════════════════════════════════
# Audit log — hash chain integrity
# ═══════════════════════════════════════════════════════


@pytest.fixture
def inbox_path(tmp_path, monkeypatch):
    path = tmp_path / ".nanda" / "inbox.jsonl"
    monkeypatch.setattr(cr, "INBOX_PATH", path)
    return path


def test_audit_append_creates_file_with_0600(inbox_path):
    sha = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {"text": "hi"}}, "")
    assert inbox_path.exists()
    mode = inbox_path.stat().st_mode & 0o777
    assert mode == 0o600
    assert len(sha) == 64


def test_audit_chain_links_successive_events(inbox_path):
    s1 = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {"n": 1}}, "")
    s2 = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {"n": 2}}, s1)
    events = cr.read_audit(inbox_path)
    assert events[0]["event_sha256"] == s1
    assert events[1]["prev_sha256"] == s1
    assert events[1]["event_sha256"] == s2


def test_verify_chain_clean_log(inbox_path):
    s1 = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {}}, "")
    cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {}}, s1)
    ok, broken = cr.verify_audit_chain(inbox_path)
    assert ok is True
    assert broken == -1


def test_verify_chain_detects_tampered_body(inbox_path):
    """ADVERSARIAL: attacker edits a body field post-hoc."""
    s1 = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {"text": "original"}}, "")
    cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {"text": "two"}}, s1)

    # Tamper: rewrite the file with the body changed but sha unchanged.
    lines = inbox_path.read_text().splitlines()
    first = json.loads(lines[0])
    first["body"] = {"text": "tampered"}
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    inbox_path.write_text("\n".join(lines) + "\n")

    ok, broken = cr.verify_audit_chain(inbox_path)
    assert ok is False
    assert broken == 0


def test_verify_chain_detects_broken_prev_link(inbox_path):
    s1 = cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {}}, "")
    cr.append_audit(inbox_path, {"kind": "slack", "remote_id": "T1", "body": {}}, s1)

    # Tamper with the second row's prev_sha256
    lines = inbox_path.read_text().splitlines()
    second = json.loads(lines[1])
    second["prev_sha256"] = "0" * 64
    # Regenerate event_sha256 so row-level check passes but chain-level fails
    payload = {k: second.get(k) for k in ("kind", "remote_id", "sender", "body", "received_at", "session_scope")}
    payload["prev_sha256"] = second["prev_sha256"]
    second["event_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[1] = json.dumps(second, sort_keys=True, separators=(",", ":"))
    inbox_path.write_text("\n".join(lines) + "\n")

    ok, broken = cr.verify_audit_chain(inbox_path)
    assert ok is False
    assert broken == 1


def test_read_audit_survives_empty_file(inbox_path):
    assert cr.read_audit(inbox_path) == []


def test_read_audit_skips_malformed_lines(inbox_path):
    inbox_path.parent.mkdir(exist_ok=True, parents=True)
    inbox_path.write_text(
        json.dumps({"kind": "slack", "event_sha256": "abc"}, sort_keys=True, separators=(",", ":"))
        + "\n"
        + "not-json\n"
        + json.dumps({"kind": "email", "event_sha256": "def"}, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    events = cr.read_audit(inbox_path)
    assert len(events) == 2
    assert {e["kind"] for e in events} == {"slack", "email"}


# ═══════════════════════════════════════════════════════
# FastAPI integration — the wire
# ═══════════════════════════════════════════════════════


def _fixed_time() -> float:
    return 1735689600.0


def _secret_resolver(mapping: dict[tuple[str, str], str]):
    return lambda kind, remote: mapping.get((kind, remote), "")


@pytest.fixture
def app(inbox_path):
    secrets = {
        ("slack", "T12345"): "slack-signing-secret",
        ("generic", "test-hook"): "generic-secret",
        ("email", "alice@example.com"): "email-secret",
    }
    return cr.build_app(
        inbox_path=inbox_path,
        secret_resolver=_secret_resolver(secrets),
        now_fn=_fixed_time,
    )


@pytest.fixture
def client(app):
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["inbox_size"] == 0


def test_slack_url_verification_handshake_with_valid_sig(client, inbox_path):
    ts = str(int(_fixed_time()))
    body = json.dumps({"type": "url_verification", "challenge": "abc123", "team_id": "T12345"}).encode()
    sig = _slack_sign("slack-signing-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={
            "X-Slack-Request-Timestamp": ts,
            "X-Slack-Signature": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"challenge": "abc123"}
    # Handshake must not be written to the inbox — it's not an event
    assert cr.read_audit(inbox_path) == []


def test_slack_url_verification_refuses_without_valid_sig(client):
    body = json.dumps({"type": "url_verification", "challenge": "x", "team_id": "T12345"}).encode()
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={
            "X-Slack-Request-Timestamp": str(int(_fixed_time())),
            "X-Slack-Signature": "v0=" + "f" * 64,
        },
    )
    assert resp.status_code == 401


def test_slack_event_valid_is_queued_and_audited(client, inbox_path):
    ts = str(int(_fixed_time()))
    body = json.dumps(
        {
            "type": "event_callback",
            "team_id": "T12345",
            "event": {"user": "U999", "text": "hello agent"},
        }
    ).encode()
    sig = _slack_sign("slack-signing-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["queued"] is True
    assert len(payload["event_sha256"]) == 64

    # Audit log got the entry
    events = cr.read_audit(inbox_path)
    assert len(events) == 1
    assert events[0]["kind"] == "slack"
    assert events[0]["sender"] == "U999"
    assert events[0]["session_scope"] == "agent:channel:slack:dm:U999"
    # Chain verifies
    ok, _ = cr.verify_audit_chain(inbox_path)
    assert ok


def test_slack_event_refuses_missing_team_id(client):
    ts = str(int(_fixed_time()))
    body = json.dumps({"type": "event_callback", "event": {"user": "U1"}}).encode()
    sig = _slack_sign("slack-signing-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 400


def test_slack_event_refuses_forged_signature(client, inbox_path):
    ts = str(int(_fixed_time()))
    body = json.dumps({"type": "event_callback", "team_id": "T12345", "event": {}}).encode()
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": "v0=" + "a" * 64},
    )
    assert resp.status_code == 401
    # Nothing queued, nothing in the audit log
    assert cr.read_audit(inbox_path) == []


def test_slack_event_refuses_replay(client):
    ts = str(int(_fixed_time()) - 1000)  # ~16 min old
    body = json.dumps({"type": "event_callback", "team_id": "T12345", "event": {}}).encode()
    sig = _slack_sign("slack-signing-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 401


def test_slack_event_refuses_oversized_payload(client):
    # >256 KiB body
    big = b"{" + b"x" * (300 * 1024) + b"}"
    resp = client.post(
        "/channels/slack/webhook",
        content=big,
        headers={
            "X-Slack-Request-Timestamp": "0",
            "X-Slack-Signature": "v0=abc",
        },
    )
    assert resp.status_code == 413


def test_slack_event_refuses_invalid_json(client):
    ts = str(int(_fixed_time()))
    body = b"{not valid json"
    sig = _slack_sign("slack-signing-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 400


def test_generic_webhook_happy(client, inbox_path):
    ts = str(int(_fixed_time()))
    body = json.dumps({"from": "alice@example.com", "text": "hi"}).encode()
    sig = _generic_sign("generic-secret", ts, body)
    resp = client.post(
        "/channels/generic/webhook",
        content=body,
        headers={
            "X-Nanda-Timestamp": ts,
            "X-Nanda-Signature": sig,
            "X-Nanda-Remote-Id": "test-hook",
        },
    )
    assert resp.status_code == 200
    events = cr.read_audit(inbox_path)
    assert len(events) == 1
    assert events[0]["kind"] == "generic"


def test_generic_webhook_refuses_missing_remote_id_header(client):
    ts = str(int(_fixed_time()))
    body = b"{}"
    sig = _generic_sign("generic-secret", ts, body)
    resp = client.post(
        "/channels/generic/webhook",
        content=body,
        headers={"X-Nanda-Timestamp": ts, "X-Nanda-Signature": sig},
    )
    assert resp.status_code == 400


def test_generic_webhook_refuses_forged_signature(client):
    ts = str(int(_fixed_time()))
    body = b'{"from":"x"}'
    resp = client.post(
        "/channels/generic/webhook",
        content=body,
        headers={
            "X-Nanda-Timestamp": ts,
            "X-Nanda-Signature": "a" * 64,
            "X-Nanda-Remote-Id": "test-hook",
        },
    )
    assert resp.status_code == 401


def test_email_webhook_happy(client, inbox_path):
    ts = str(int(_fixed_time()))
    body = json.dumps({"from": "bob@example.com", "subject": "agenda"}).encode()
    sig = _generic_sign("email-secret", ts, body)
    resp = client.post(
        "/channels/email/webhook",
        content=body,
        headers={
            "X-Nanda-Timestamp": ts,
            "X-Nanda-Signature": sig,
            "X-Nanda-Remote-Id": "alice@example.com",
        },
    )
    assert resp.status_code == 200
    events = cr.read_audit(inbox_path)
    assert events[0]["kind"] == "email"
    assert events[0]["session_scope"] == "agent:channel:email:dm:bob@example.com"


def test_discord_webhook_rejects_without_signature(client):
    """Discord webhook now verifies signatures — missing signature → 401 not 501."""
    resp = client.post("/channels/discord/webhook", json={"type": 1})
    assert resp.status_code == 401


def test_full_inbox_drain_cycle(inbox_path):
    """HAPPY: multiple events enqueue and drain in order with chained hashes."""
    import asyncio

    async def run():
        inbox = cr.Inbox()
        await cr._ingest(inbox, inbox_path, "slack", "T1", "U1", {"n": 1}, "s:1")
        await cr._ingest(inbox, inbox_path, "slack", "T1", "U1", {"n": 2}, "s:2")
        await cr._ingest(inbox, inbox_path, "slack", "T1", "U1", {"n": 3}, "s:3")
        drained = inbox.drain_nowait()
        return drained

    result = asyncio.run(run())
    assert [item.body["n"] for item in result] == [1, 2, 3]
    # Full chain intact across three events
    ok, _ = cr.verify_audit_chain(inbox_path)
    assert ok is True


def test_inbox_size_reflects_queue_depth():
    import asyncio

    async def run():
        inbox = cr.Inbox()
        assert inbox.size == 0
        await inbox.put(cr.InboxItem("slack", "T1", "U1", {}, "s", "x"))
        await inbox.put(cr.InboxItem("slack", "T1", "U1", {}, "s", "y"))
        return inbox.size

    size = asyncio.run(run())
    assert size == 2


def test_inbox_drain_empties_queue():
    import asyncio

    async def run():
        inbox = cr.Inbox()
        for i in range(5):
            await inbox.put(cr.InboxItem("slack", "T1", "U1", {}, "s", f"sha{i}"))
        drained = inbox.drain_nowait()
        return drained, inbox.size

    items, size = asyncio.run(run())
    assert len(items) == 5
    assert size == 0


def test_secret_resolver_returns_empty_for_unknown_remote(client, inbox_path):
    """ADVERSARIAL: attacker sends a valid-looking payload but the remote_id
    isn't registered with any secret. Refused (empty secret → signature check fails)."""
    ts = str(int(_fixed_time()))
    body = json.dumps({"team_id": "T99999"}).encode()
    sig = _slack_sign("some-secret", ts, body)
    resp = client.post(
        "/channels/slack/webhook",
        content=body,
        headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
    )
    assert resp.status_code == 401
