"""
Prosecution-grade tests for chapter_audit.py + chapter_auth.py.

The enterprise/private-chapter primitives: immutable audit ledger with
hash chain, and SSO/allowlist bindings. These modules must refuse
tampering, oversize payloads, and unauthorized writes.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import chapter_audit
import chapter_auth


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "chapter_audit_events": [],
            "chapter_sso_configs": [],
            "chapter_federation_allowlist": [],
        }
        self._next = 0

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            self._next += 1
            body.setdefault("id", f"ev-{self._next}")
            body.setdefault("occurred_at", datetime.now(UTC).isoformat())
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            body.setdefault("updated_at", datetime.now(UTC).isoformat())
            body.setdefault("outcome", body.get("outcome") or "ok")
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            filters = self._parse(table_or_path, params)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        if method == "DELETE":
            filters = self._parse(table_or_path, params)
            keep: list[dict] = []
            removed: list[dict] = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    removed.append(row)
                else:
                    keep.append(row)
            self.tables[table] = keep
            return removed

        return None

    @staticmethod
    def _parse(path, params):
        out: dict[str, str] = {}
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
        order = params.get("order") if params else None
        if order:
            key = order.split(",")[0].split(".")[0]
            reverse = "desc" in order
            out.sort(key=lambda r: r.get(key) or "", reverse=reverse)
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
        if op == "gte":
            return (rv or "") >= val
        return True


@pytest.fixture
def sb():
    bs = _FakePostgres()
    chapter_audit.init(pg_request_fn=bs)
    chapter_auth.init(pg_request_fn=bs)
    return bs


# ═══════════════════════════════════════════════════════════════
# chapter_audit — hash chain + append
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_record_creates_event(sb):
    result = await chapter_audit.record(
        chapter_id="bayarea",
        action="skill.publish",
        actor_agent_id="alice",
        target_type="skill",
        target_id="file-ops@1.0.0",
    )
    assert result["action"] == "skill.publish"
    assert result["outcome"] == "ok"
    assert len(result["event_sha256"]) == 64


@pytest.mark.asyncio
async def test_record_chains_events(sb):
    a = await chapter_audit.record("bayarea", "skill.publish", actor_agent_id="alice")
    b = await chapter_audit.record("bayarea", "skill.publish", actor_agent_id="alice")
    assert b["prev_sha256"] == a["event_sha256"]


@pytest.mark.asyncio
async def test_record_first_event_has_no_prev(sb):
    a = await chapter_audit.record("bayarea", "chapter.bootstrap")
    assert a["prev_sha256"] in (None, "")


@pytest.mark.asyncio
async def test_record_rejects_missing_action(sb):
    with pytest.raises(ValueError, match="action is required"):
        await chapter_audit.record("bayarea", "")


@pytest.mark.asyncio
async def test_record_rejects_oversized_action(sb):
    with pytest.raises(ValueError, match="action too long"):
        await chapter_audit.record("bayarea", "x" * 100)


@pytest.mark.asyncio
async def test_record_rejects_unknown_outcome(sb):
    """ADVERSARIAL: caller passes 'success' instead of 'ok' — reject."""
    with pytest.raises(ValueError, match="outcome"):
        await chapter_audit.record("bayarea", "x", outcome="success")


@pytest.mark.asyncio
async def test_record_rejects_oversized_detail(sb):
    """ADVERSARIAL: 64 KiB detail blob rejected."""
    detail = {"payload": "x" * (64 * 1024)}
    with pytest.raises(ValueError, match="detail too large"):
        await chapter_audit.record("bayarea", "x", detail=detail)


# ═══════════════════════════════════════════════════════════════
# canonical_event + sha256 — pure layer
# ═══════════════════════════════════════════════════════════════


def test_canonical_event_is_deterministic():
    """HAPPY: same event → same canonical string regardless of dict order."""
    a = {"chapter_id": "x", "action": "y", "detail": {"b": 1, "a": 2}, "occurred_at": "now"}
    b = {"action": "y", "detail": {"a": 2, "b": 1}, "occurred_at": "now", "chapter_id": "x"}
    assert chapter_audit.canonical_event(a) == chapter_audit.canonical_event(b)


def test_sha256_changes_on_detail_mutation():
    """ADVERSARIAL: any field change → different sha256."""
    base = {"chapter_id": "x", "action": "y", "detail": {}, "occurred_at": "now"}
    mutated = {**base, "detail": {"tampered": True}}
    assert chapter_audit.sha256_of(base) != chapter_audit.sha256_of(mutated)


# ═══════════════════════════════════════════════════════════════
# verify_chain — tamper detection
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_verify_chain_ok_for_unchanged_log(sb):
    await chapter_audit.record("bayarea", "skill.publish", actor_agent_id="alice")
    await chapter_audit.record("bayarea", "member.register", actor_agent_id="bob")
    await chapter_audit.record("bayarea", "skill.revoke", actor_agent_id="alice")

    result = await chapter_audit.verify_chain("bayarea")
    assert result["ok"] is True
    assert result["length"] == 3


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_detail(sb):
    """ADVERSARIAL: a privileged attacker edits a detail field. The chain breaks."""
    await chapter_audit.record("bayarea", "skill.publish", actor_agent_id="alice")
    await chapter_audit.record("bayarea", "member.delete", actor_agent_id="mallory", detail={"who": "alice"})
    # Tamper with the middle event's detail.
    sb.tables["chapter_audit_events"][1]["detail"] = {"who": "innocent"}

    result = await chapter_audit.verify_chain("bayarea")
    assert result["ok"] is False
    assert "first_broken_at" in result


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_prev_sha(sb):
    """ADVERSARIAL: attacker alters prev_sha256 to disconnect the chain."""
    await chapter_audit.record("bayarea", "a")
    await chapter_audit.record("bayarea", "b")
    sb.tables["chapter_audit_events"][1]["prev_sha256"] = "0" * 64
    result = await chapter_audit.verify_chain("bayarea")
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_verify_chain_empty_log_ok(sb):
    result = await chapter_audit.verify_chain("bayarea")
    assert result["ok"] is True
    assert result["length"] == 0


# ═══════════════════════════════════════════════════════════════
# list_events + export_jsonl
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_list_events_filters_by_action(sb):
    await chapter_audit.record("bayarea", "skill.publish", actor_agent_id="alice")
    await chapter_audit.record("bayarea", "member.register", actor_agent_id="bob")
    publishes = await chapter_audit.list_events("bayarea", action="skill.publish")
    assert len(publishes) == 1
    assert publishes[0]["actor_agent_id"] == "alice"


@pytest.mark.asyncio
async def test_export_jsonl_returns_strings_in_chronological_order(sb):
    await chapter_audit.record("bayarea", "a")
    await chapter_audit.record("bayarea", "b")
    lines = await chapter_audit.export_jsonl("bayarea")
    assert len(lines) == 2
    assert all(isinstance(line, str) for line in lines)
    # First inserted → first line.
    import json as _json

    assert _json.loads(lines[0])["action"] == "a"
    assert _json.loads(lines[1])["action"] == "b"


# ═══════════════════════════════════════════════════════════════
# chapter_auth — SSO config
# ═══════════════════════════════════════════════════════════════


def test_validate_issuer_url_rejects_http():
    ok, reason = chapter_auth.validate_issuer_url("http://idp.example.com")
    assert ok is False
    assert "https" in reason


def test_validate_issuer_url_rejects_bare_host():
    ok, _ = chapter_auth.validate_issuer_url("https://idp")
    assert ok is False


def test_validate_issuer_url_accepts_well_formed():
    ok, _ = chapter_auth.validate_issuer_url("https://dev.okta.com/oauth2/default")
    assert ok is True


def test_validate_provider_rejects_unknown():
    ok, _ = chapter_auth.validate_provider("ping_identity")
    assert ok is False


def test_validate_provider_accepts_known():
    for pid in ["okta", "azure_ad", "google_workspace", "generic_oidc"]:
        ok, _ = chapter_auth.validate_provider(pid)
        assert ok is True


@pytest.mark.asyncio
async def test_set_sso_config_creates_row(sb):
    result = await chapter_auth.set_sso_config(
        chapter_id="acme",
        provider="okta",
        issuer_url="https://acme.okta.com/oauth2/default",
        client_id="0oa123",
    )
    assert result["provider"] == "okta"
    assert sb.tables["chapter_sso_configs"][0]["chapter_id"] == "acme"


@pytest.mark.asyncio
async def test_set_sso_config_upserts(sb):
    await chapter_auth.set_sso_config("acme", "okta", "https://a.okta.com", "c1")
    await chapter_auth.set_sso_config("acme", "okta", "https://b.okta.com", "c2")
    assert len(sb.tables["chapter_sso_configs"]) == 1
    assert sb.tables["chapter_sso_configs"][0]["client_id"] == "c2"


@pytest.mark.asyncio
async def test_set_sso_config_rejects_bad_issuer(sb):
    with pytest.raises(ValueError, match="https"):
        await chapter_auth.set_sso_config(
            chapter_id="acme",
            provider="okta",
            issuer_url="http://acme.okta.com",
            client_id="c1",
        )


@pytest.mark.asyncio
async def test_set_sso_config_rejects_empty_client_id(sb):
    with pytest.raises(ValueError, match="client_id"):
        await chapter_auth.set_sso_config(
            "acme",
            "okta",
            "https://acme.okta.com",
            "",
        )


@pytest.mark.asyncio
async def test_clear_sso_config(sb):
    await chapter_auth.set_sso_config("acme", "okta", "https://x.okta.com", "c1")
    result = await chapter_auth.clear_sso_config("acme")
    assert result["sso"] == "disabled"
    assert sb.tables["chapter_sso_configs"] == []


# ═══════════════════════════════════════════════════════════════
# Federation allowlist — default-deny for private chapters
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_add_allowlist_peer(sb):
    result = await chapter_auth.add_federation_peer(
        chapter_id="acme",
        peer_chapter_id="partner-b",
        added_by_agent_id="admin",
        reason="B2B mesh collab",
    )
    assert result["peer_chapter_id"] == "partner-b"


@pytest.mark.asyncio
async def test_add_allowlist_refuses_self(sb):
    with pytest.raises(ValueError, match="itself"):
        await chapter_auth.add_federation_peer("acme", "acme", "admin")


@pytest.mark.asyncio
async def test_is_peer_allowed_empty_allowlist_open(sb):
    """HAPPY: empty allowlist = public chapter default = everyone allowed."""
    assert await chapter_auth.is_peer_allowed("acme", "anyone") is True


@pytest.mark.asyncio
async def test_is_peer_allowed_populated_allowlist_default_deny(sb):
    """ADVERSARIAL: once a single entry is added, unlisted peers refused."""
    await chapter_auth.add_federation_peer("acme", "trusted-partner", "admin")
    assert await chapter_auth.is_peer_allowed("acme", "trusted-partner") is True
    assert await chapter_auth.is_peer_allowed("acme", "random-chapter") is False


@pytest.mark.asyncio
async def test_remove_allowlist_peer(sb):
    await chapter_auth.add_federation_peer("acme", "partner", "admin")
    assert await chapter_auth.is_peer_allowed("acme", "partner") is True
    await chapter_auth.remove_federation_peer("acme", "partner")
    # Now the allowlist is empty again — public default.
    assert await chapter_auth.is_peer_allowed("acme", "partner") is True


@pytest.mark.asyncio
async def test_list_allowlist(sb):
    await chapter_auth.add_federation_peer("acme", "p1", "admin")
    await chapter_auth.add_federation_peer("acme", "p2", "admin")
    all_peers = await chapter_auth.list_federation_allowlist("acme")
    assert {p["peer_chapter_id"] for p in all_peers} == {"p1", "p2"}


def test_valid_providers_exported():
    providers = chapter_auth.valid_providers()
    assert len(providers) >= 4
    ids = {p["id"] for p in providers}
    assert "okta" in ids
    assert "azure_ad" in ids
