"""Every 401 reason the middleware puts on the wire is in the spec's closed set.

``spec/0.5/signing.md`` step 5: "Any verification failure: HTTP 401 with
``{"error": "<specific reason>"}``. Reasons MUST be from the closed set." The
set is thirteen strings and v0.5 added exactly one (``method_binding_required``).
A string outside it is a conformance defect, and it is also how a membership
oracle re-opens by accident: the TOFU-eligibility fix answered a refused
unknown id with ``unknown_agent`` while an unknown id without a DID header
already got ``no_stored_key`` — two words for one fact, one of them foreign.

The set is READ from the umbrella's spec text when ``NANDA_SPEC_DIR`` names
a checkout, so this test cannot drift from the document it enforces; the
pinned copy below is what runs everywhere else, and the two are asserted
equal whenever both exist.

Held two ways. (1) Statically: every ``return False, agent_id, "<reason>"``
in ``auth_verify.verify_request`` and every reason string the middleware
compares against is in the set. (2) Over HTTP: a battery of real failures on
a gated read — no id, no signature, unknown id with and without a DID header,
a stored key with the wrong DID, a stored key with a bad signature, an
expired timestamp, a replayed nonce, a v0.2 signature on a mutation, an
unknown scheme, a malformed DID, a valid signature from a non-member — each
lands as 401 with a ``detail`` in the set.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import build_v03_signed_headers

#: spec/0.5/signing.md step 5, verbatim. Twelve from v0.3 plus method_binding_required.
PINNED_CLOSED_SET = frozenset(
    {
        "missing_agent_id",
        "missing_signature",
        "missing_timestamp",
        "missing_nonce",
        "unknown_sig_scheme",
        "invalid_timestamp",
        "expired_timestamp",
        "invalid_did_key",
        "key_mismatch",
        "no_stored_key",
        "nonce_replay",
        "invalid_signature",
        "method_binding_required",
    }
)

#: Reasons `verify_request` returns that never reach the wire as a 401 detail:
#: successes, and the operator-facing word the middleware translates before
#: answering (see chapter_agent: `wire_reason`).
INTERNAL_ONLY = frozenset(
    {
        "verified",
        "tofu_accepted",
        "not_a_member",
        # federation_signing's verdict for a peer read with no X-Org-Origin;
        # the middleware only logs it and never answers a 401 with it.
        "missing_origin",
    }
)

#: A checkout of the NANDA Chapter Protocol umbrella, if one is available:
#: point ``NANDA_SPEC_DIR`` at its root and the set is read from
#: ``spec/0.5/signing.md`` there instead of the pinned copy.
SPEC_DIR = os.environ.get("NANDA_SPEC_DIR", "")


def _closed_set_from_spec() -> frozenset[str] | None:
    if not SPEC_DIR:
        return None
    spec = Path(SPEC_DIR) / "spec" / "0.5" / "signing.md"
    if not spec.exists():
        return None
    text = spec.read_text()
    m = re.search(r"Reasons MUST be from the closed set:\s*(.+?)\.\s*\n", text)
    if not m:
        return None
    return frozenset(re.findall(r"`([a-z_]+)`", m.group(1)))


def closed_set() -> frozenset[str]:
    from_spec = _closed_set_from_spec()
    if from_spec is not None:
        assert from_spec == PINNED_CLOSED_SET, (
            f"the pinned copy drifted from spec/0.5/signing.md: "
            f"spec-only={sorted(from_spec - PINNED_CLOSED_SET)} pinned-only={sorted(PINNED_CLOSED_SET - from_spec)}"
        )
        return from_spec
    return PINNED_CLOSED_SET


# ── (1) static: every literal the code can return or compare ─────────


def _source(name: str) -> str:
    return (Path(__file__).resolve().parents[1] / name).read_text()


def test_every_reason_verify_request_returns_is_in_the_set():
    src = _source("auth_verify.py")
    body = src[src.index("def verify_request(") :]
    body = body[: body.index("\ndef ", 10)]
    returned = set(re.findall(r'return (?:False|True), [a-z_]+, "([a-z_]+)"', body))
    assert returned, "no reason literals found — the scan pattern no longer matches verify_request"
    foreign = returned - closed_set() - INTERNAL_ONLY
    assert not foreign, f"verify_request returns reasons outside spec/0.5's closed set: {sorted(foreign)}"


def test_every_reason_the_middleware_names_is_in_the_set():
    src = _source("chapter_agent.py")
    start = src.index("async def auth_middleware(")
    body = src[start : src.index("\n@app.", start)]
    named = set(
        re.findall(
            r'"(missing_[a-z_]+|invalid_[a-z_]+|expired_[a-z_]+|no_stored_key|key_mismatch|nonce_replay|unknown_[a-z_]+|method_binding_required|not_a_member|tofu_accepted|verified)"',
            body,
        )
    )
    foreign = named - closed_set() - INTERNAL_ONLY
    assert not foreign, f"the middleware names reasons outside the closed set: {sorted(foreign)}"


# ── (2) over HTTP: a battery of real failures ────────────────────────


@pytest.fixture
def stack(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-closed-set-org")
    monkeypatch.setenv("AGENT_NAME", "Closed Set Org")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    for name in ("auth_verify", "chapter_agent"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("chapter_agent")

    async def _no_db(*_a, **_k):
        return []

    monkeypatch.setattr(mod, "pg_request", _no_db)
    mod.members.clear()
    import auth_verify
    import sovereign_identity

    member = sovereign_identity.generate_ed25519_keypair("TEST-member")
    auth_verify.store_agent_key("TEST-member", "", "", ed25519_pubkey=member["public_key"])
    mod.members["TEST-member"] = {"agent_id": "TEST-member", "name": "Member", "skills": [], "origin": "sovereign"}
    return mod, TestClient(mod.app), member


PATH = "/api/members"


def _v03(agent_id, kp, *, did=False, method="GET", path=PATH, body="", **over):
    import sovereign_identity

    h = build_v03_signed_headers(
        body=body, agent_id=agent_id, private_key_b64=kp["private_key"], method=method, url_path=path
    )
    if did:
        h["X-Agent-DID-Key"] = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    h.update(over)
    return h


def _failures(mod, client, member):
    import sovereign_identity

    stranger = sovereign_identity.generate_ed25519_keypair("TEST-stranger")
    wrong = sovereign_identity.generate_ed25519_keypair("TEST-member")
    cases = {
        "no agent id": {},
        "no signature": {"X-Agent-ID": "TEST-member"},
        "unknown id, DID header": _v03("TEST-stranger", stranger, did=True),
        "unknown id, no DID header": _v03("TEST-stranger", stranger),
        "stored key, wrong DID": _v03("TEST-member", wrong, did=True),
        "stored key, bad signature": _v03("TEST-member", wrong),
        "expired timestamp": {**_v03("TEST-member", member), "X-Agent-Timestamp": str(int(time.time()) - 3600)},
        "unknown scheme": {**_v03("TEST-member", member), "X-Agent-Sig-Scheme": "rot13"},
        "malformed DID": _v03("TEST-stranger", stranger, **{"X-Agent-DID-Key": "did:key:not-a-key"}),
    }
    out = {}
    for name, headers in cases.items():
        r = client.get(PATH, headers=headers)
        out[name] = (r.status_code, (r.json() or {}).get("detail"))
    # replayed nonce: the same signed headers twice
    h = _v03("TEST-member", member)
    assert client.get(PATH, headers=h).status_code == 200
    r = client.get(PATH, headers=h)
    out["replayed nonce"] = (r.status_code, r.json().get("detail"))
    # v0.2 on a mutation
    ts = str(int(time.time()))
    body = '{"intent_text":"x","requester_agent_id":"TEST-member","intent_tags":[]}'
    sig = sovereign_identity.ed25519_sign(f"{body}:TEST-member:{ts}", member["private_key"])
    r = client.post(
        "/api/intents",
        content=body,
        headers={
            "X-Agent-ID": "TEST-member",
            "X-Agent-Signature": sig,
            "X-Agent-Timestamp": ts,
            "X-Agent-Sig-Scheme": "ed25519",
            "content-type": "application/json",
        },
    )
    out["v0.2 on a mutation"] = (r.status_code, r.json().get("detail"))
    # valid signature, key on file, not a member
    import auth_verify

    pinned = sovereign_identity.generate_ed25519_keypair("TEST-pinned-not-member")
    auth_verify.store_agent_key("TEST-pinned-not-member", "", "", ed25519_pubkey=pinned["public_key"])
    r = client.get(PATH, headers=_v03("TEST-pinned-not-member", pinned))
    out["valid signature, not a member"] = (r.status_code, r.json().get("detail"))
    return out


def test_ADVERSARIAL_every_wire_reason_is_in_the_closed_set(stack):
    mod, client, member = stack
    results = _failures(mod, client, member)
    allowed = closed_set()
    bad = {k: v for k, v in results.items() if v[0] != 401 or v[1] not in allowed}
    assert not bad, f"401 details outside the closed set (or not 401): {bad}"


def test_ADVERSARIAL_an_unknown_id_reads_the_same_with_or_without_a_did_header(stack):
    mod, client, member = stack
    results = _failures(mod, client, member)
    assert results["unknown id, DID header"] == results["unknown id, no DID header"] == (401, "no_stored_key")
    assert results["valid signature, not a member"] == (401, "no_stored_key")
    assert results["stored key, wrong DID"] == (401, "key_mismatch")
    assert results["stored key, bad signature"] == (401, "invalid_signature")
