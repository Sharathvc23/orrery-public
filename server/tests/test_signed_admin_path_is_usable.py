"""The signed did:key admin path works on the routes that re-authorize.

These eight routes had never been exercised over the signed path, so their role
gate was unproven rather than merely broken. Verification is not idempotent —
``verify_request`` spends the request's (agent_id, nonce) in the replay store —
and ``_authorize_role`` called it a SECOND time on a request the middleware had
already verified. The second call saw its own nonce and returned
``nonce_replay``: a legitimately signed admin was told its request was a replay
of itself, and only the shared static ``X-Admin-Token`` still worked.

Every test here asserts BOTH halves. Proving the door opens without proving it
still stops anyone would replace a broken gate with an absent one, so each route
is driven three ways:

  signed ADMIN      -> must NOT be 401; must never be nonce_replay
  signed NON-ADMIN  -> must be 403 naming the ROLE, never nonce_replay
  unauthenticated   -> must be 401

The middle case is the one that matters: before this change a non-admin was also
refused, but for the wrong reason, and a gate that refuses everyone including its
operator is indistinguishable from one that works until you look at why.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import (
    register_test_admin_member,
    register_test_regular_member,
    reset_chapter_agent_module,
)

ADMIN = "signed-admin-carol"
MEMBER = "ordinary-dave"

#: (method, path, payload) for every route whose handler re-authorizes.
#: DELETE /api/members/{id} is included: its non-self branch delegates to
#: admin_remove_member, which calls _authorize_admin.
REAUTHORIZING_ROUTES = [
    ("POST", "/api/invites", {"max_uses": 1, "ttl_days": 7}),
    ("POST", "/api/invites/", {"max_uses": 1, "ttl_days": 7}),
    ("POST", "/api/invites/tok-does-not-exist/revoke", {}),
    ("POST", "/api/approvals/appr-1/approve", {"approver_agent_id": ADMIN, "reason": "ok"}),
    ("POST", "/api/approvals/appr-1/reject", {"approver_agent_id": ADMIN, "reason": "no"}),
    ("POST", "/api/org/join-policy", {"policy": "invite"}),
    ("POST", "/api/admin/trust/decay-sweep", {}),
    ("DELETE", "/api/members/some-other-member", None),
]

IDS = [f"{m}:{p}" for m, p, _ in REAUTHORIZING_ROUTES]


@pytest.fixture
def stack(monkeypatch, tmp_path):
    import sys

    token = "c" * 64
    mod = reset_chapter_agent_module(
        monkeypatch, agent_id="TEST-signed-admin-chapter", chapter_admin_token=token
    )
    sys.modules.pop("admin", None)
    import admin as admin_mod

    admin_mod.init()
    mod.members.clear()

    # ⚠️ The org config file is resolved relative to the SERVER DIRECTORY, not
    # CHAPTER_HOME, so it survives the per-test temp home and the process. The
    # join-policy route below writes it, and a persisted "invite" policy makes
    # every later registration in this worktree require an invite — which is how
    # this suite silently broke three registration tests in a full run before the
    # redirect. Point it at tmp_path so the write stays inside the test.
    monkeypatch.setattr(mod, "_ORG_CONFIG_PATH", tmp_path / ".org" / "org-config.json")

    admin = register_test_admin_member(mod, agent_id=ADMIN, name="Carol")
    member = register_test_regular_member(mod, agent_id=MEMBER, name="Dave")
    register_test_regular_member(mod, agent_id="some-other-member", name="Target")

    # governance resolves chapter_role from its own store; point it at the
    # in-memory roster the fixtures populate so the ROLE branch is real.
    import governance

    async def role_of(agent_id: str) -> str:
        return (mod.members.get(agent_id) or {}).get("chapter_role", "member")

    monkeypatch.setattr(governance, "get_chapter_role", role_of)
    return mod, admin, member, TestClient(mod.app), token


def _send(client, signer, method, path, payload):
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    headers = signer(method=method, url_path=path, body=body)
    if payload is not None:
        headers["Content-Type"] = "application/json"
    return client.request(method, path, content=body or None, headers=headers)


@pytest.mark.parametrize(("method", "path", "payload"), REAUTHORIZING_ROUTES, ids=IDS)
def test_a_signed_admin_is_not_refused_as_a_replay_of_itself(stack, method, path, payload):
    """The regression. Whatever the handler goes on to do — 404 on a missing
    approval, 503 on an unwired store — it must be the HANDLER answering, not the
    auth layer rejecting the admin's own nonce."""
    _mod, admin, _member, client, _token = stack
    resp = _send(client, admin["signer"], method, path, payload)

    assert "nonce_replay" not in resp.text, (
        f"{method} {path}: signed admin refused as a replay of its own request — "
        f"HTTP {resp.status_code} {resp.text[:200]}"
    )
    assert resp.status_code != 401, (
        f"{method} {path}: signed admin got 401 {resp.text[:200]}"
    )
    assert resp.status_code != 403, (
        f"{method} {path}: signed admin refused by the role gate {resp.text[:200]}"
    )


@pytest.mark.parametrize(("method", "path", "payload"), REAUTHORIZING_ROUTES, ids=IDS)
def test_a_signed_NON_admin_is_refused_for_its_ROLE(stack, method, path, payload):
    """Without this the fix above is satisfied by removing the gate entirely.
    An ordinary member signs correctly — so the refusal must name the role, not
    the signature."""
    _mod, _admin, member, client, _token = stack
    resp = _send(client, member["signer"], method, path, payload)

    assert resp.status_code == 403, (
        f"{method} {path}: an ordinary member was not refused — HTTP {resp.status_code} {resp.text[:200]}"
    )
    assert "nonce_replay" not in resp.text, (
        f"{method} {path}: refused for the wrong reason (replay, not role): {resp.text[:200]}"
    )
    assert "role" in resp.text.lower(), (
        f"{method} {path}: refusal does not name the role: {resp.text[:200]}"
    )


@pytest.mark.parametrize(("method", "path", "payload"), REAUTHORIZING_ROUTES, ids=IDS)
def test_an_unauthenticated_request_is_still_refused(stack, method, path, payload):
    _mod, _admin, _member, client, _token = stack
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    resp = client.request(method, path, content=body or None, headers={"Content-Type": "application/json"})
    assert resp.status_code in (401, 403), (
        f"{method} {path}: unauthenticated request was not refused — HTTP {resp.status_code} {resp.text[:200]}"
    )


#: DELETE /api/members/{id} is absent by design: it is an ALIAS, and the
#: canonical operator path is DELETE /admin/api/members/{id}, which is an open
#: path at the gate and takes the bearer there. Asserted below rather than
#: assumed, because "there is another way in" is the whole justification.
BEARER_ROUTES = [r for r in REAUTHORIZING_ROUTES if r[0] == "POST"]


@pytest.mark.parametrize(
    ("method", "path", "payload"), BEARER_ROUTES, ids=[f"{m}:{p}" for m, p, _ in BEARER_ROUTES]
)
def test_the_bearer_break_glass_still_reaches_the_handler(stack, method, path, payload):
    """The operator's recovery credential. POST /api/admin/trust/decay-sweep was
    reachable by NEITHER credential — signed requests died as replays and the
    bearer was 401'd at the gate because the path was not on the admin-bearer
    list. Dead, not degraded."""
    _mod, _admin, _member, client, token = stack
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    resp = client.request(
        method, path, content=body or None,
        headers={"X-Admin-Token": token, "Content-Type": "application/json"},
    )
    assert resp.status_code != 401, (
        f"{method} {path}: valid admin bearer rejected at the gate — HTTP {resp.status_code} {resp.text[:200]}"
    )


def test_the_member_delete_ALIAS_has_a_working_canonical_operator_path(stack):
    """DELETE /api/members/{id} does not take a bearer, and that is acceptable
    only because the canonical path does. If this ever stops being true, the
    alias's missing break-glass becomes a real gap."""
    _mod, _admin, _member, client, token = stack
    resp = client.delete(
        "/admin/api/members/some-other-member", headers={"X-Admin-Token": token}
    )
    assert resp.status_code != 401, (
        f"the canonical operator delete rejected a valid bearer: HTTP {resp.status_code} {resp.text[:200]}"
    )


def test_the_replay_guard_itself_still_works(stack):
    """The fix must not have been "stop checking". A genuinely REPLAYED request —
    same signature, same nonce, sent twice — must still be refused."""
    _mod, admin, _member, client, _token = stack
    body = json.dumps({"max_uses": 1, "ttl_days": 7}, separators=(",", ":"))
    headers = admin["signer"](method="POST", url_path="/api/invites", body=body)
    headers["Content-Type"] = "application/json"

    first = client.post("/api/invites", content=body, headers=headers)
    replay = client.post("/api/invites", content=body, headers=dict(headers))

    assert "nonce_replay" not in first.text, f"the FIRST request was called a replay: {first.text[:200]}"
    assert replay.status_code == 401 and "nonce_replay" in replay.text, (
        f"a genuine replay was accepted: HTTP {replay.status_code} {replay.text[:200]}"
    )


def test_dsar_delete_the_same_bug_wearing_a_different_reason(stack):
    """GDPR erasure. It was in the same double-verify set and failed with
    ``invalid_signature`` rather than ``nonce_replay``, which is why the sweep
    first reported it UNCONFIRMED.

    The difference is the query string. v0.3 signs ``METHOD:url_path`` where
    url_path is the request-line path INCLUDING the query; the middleware
    verified against that, and ``_authorize_role``'s second call passed
    ``request.url.path`` — the BARE path — so it rebuilt a different canonical
    string and rejected the signature it had just accepted. Routes without a
    query string reported the spent nonce instead. One root cause, two symptoms,
    and the second is more misleading: it accuses the client of signing wrongly.

    Measured on the unfixed tree: signed admin -> 401 invalid_signature, bearer
    -> 401 missing_agent_id. Erasure was reachable by NO credential.
    """
    _mod, admin, _member, client, token = stack
    path = "/api/dsar/delete?subject_did=did:key:zVICTIM"

    headers = admin["signer"](method="POST", url_path=path, body="")
    signed = client.post(path, headers=headers)
    assert signed.status_code != 401, f"signed admin still refused: {signed.text[:200]}"
    assert "invalid_signature" not in signed.text and "nonce_replay" not in signed.text, signed.text[:200]
    # Reaches the handler's own irreversibility guard — the handler answering,
    # not the auth layer.
    assert "confirm" in signed.text, f"unexpected response: {signed.text[:200]}"

    bearer = client.post(path, headers={"X-Admin-Token": token})
    assert bearer.status_code != 401, f"operator break-glass still refused: {bearer.text[:200]}"
