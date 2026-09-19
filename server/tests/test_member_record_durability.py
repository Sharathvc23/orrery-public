"""Member fields that MUST survive a restart, and the readers that fail open
without them.

``load_persisted_members`` reconstructs ``members[]`` from Postgres on every
boot. Three fields it did not carry — ``endpoint``, ``public_key``, ``origin`` —
were therefore empty for every member on every boot, and every reader of them
degraded SILENTLY rather than failing:

  * ``register_member``'s the key-change guard key-change guard reads ``existing["public_key"]``
    and only fires when it is non-empty. ``/api/members`` is open-pathed, so on
    a restarted org an UNAUTHENTICATED re-registration replaced the victim's
    auth key outright — full account takeover, after which the legitimate key
    got ``key_mismatch``.
  * ``register_member``'s origin-immutability guard reads ``existing["origin"]``
    the same way, so the sovereign/openclaw trust origin was re-writable by the
    same open POST.
  * ``cosign_broker.resolve_member_endpoint`` matches the counterparty's did:key
    against ``public_key`` BEFORE it reads ``endpoint``, so every brokered
    co-sign resolved to None and degraded to a valid-but-UNCORROBORATED receipt
    — indistinguishable from "the counterparty declined".
  * ``agent_logic``'s ``@handle`` A2A forward reads ``endpoint`` and falls
    through to the virtual sub-agent without it, so a message addressed to a
    real member agent was answered by this org's LLM impersonating it.
  * ``identity._self_served_card_url`` / ``_member_catalog_entry`` read
    ``endpoint`` and omit the member from the AI catalog without it (visible —
    The resolvable-card rule counts it in ``omittedMembers`` — but wrong).

Recovering ``public_key`` from ``agent_facts.provider.did`` then introduced the
inverse of the same defect, because that column holds the key REGISTRATION was
handed and ``/api/members/rotate`` never writes back to it: a member who rotated
K1 → K2 was hydrated with K1 on the next boot and the key they revoked signed
successfully. Section 4 drives the loader over ``member_key_rotations``, which
held the attested current key all along and which nothing read.

These are in-process tests of the loader and of each reader against the record
the loader builds. They are deliberately NOT the whole story: a suite whose
setup and assertion live in one process cannot detect a property that only
fails across two, and that is exactly how this field went unnoticed. The
across-a-real-restart assertion is ``scripts/restart_durability_probe.py``,
which boots a real server against real Postgres, restarts it for real, and
carries its own proof that the row was written AND that the restart happened.

THE LAST SECTION OF THIS FILE IS THE EXACT OPPOSITE, AND DELIBERATELY SO.
A profile-only re-registration wiped ``endpoint`` from the RUNNING process while
the durable row kept it — so the member was catalog-omitted, unresolvable to the
co-sign broker and A2A-impersonated until something restarted the org, at which
point the loader healed it from Postgres. **A restart-based test cannot detect a
defect that a restart repairs.** If the failure window is "until the next
restart", the assertion has to live entirely inside ONE process; restarting
anywhere in it destroys the evidence. Those tests therefore never boot, never
reload, and never call ``load_persisted_members`` after the re-registration.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time

os.environ.setdefault("AGENT_ID", "durability-test-org")
os.environ.setdefault("AGENT_NAME", "Durability Test Org")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402
import cosign_broker  # noqa: E402
import member_listing  # noqa: E402
import sm_bridge_adapter  # noqa: E402
import sovereign_identity  # noqa: E402
from routes import identity  # noqa: E402

_ED = "A" * 43 + "="  # 44-char, '='-padded → ed25519-shaped (decodes to 32 bytes)
_DID = sovereign_identity.build_did_key_from_ed25519(_ED)
_OTHER_ED = "B" * 43 + "="
_ENDPOINT = "https://member-runtime.example"
# A PUBLIC-routable literal, so the SSRF guard runs for real and passes on its
# own merits. Never connected to — the transport seam replaces the socket.
_PUBLIC_ENDPOINT = "https://93.184.216.34/a2a"
_ORG = chapter_agent.AGENT_ID


def _row(**over) -> dict:
    """A row shaped exactly as `_persist_member_to_db` writes one."""
    config = {
        "parent_chapter": _ORG,
        "voice": "helpful",
        "personality": "",
        "virtual": False,
        "registered_via": "api",
        "endpoint": _ENDPOINT,
    }
    config.update(over.pop("config", {}))
    row = {
        "agent_id": "mallory-target",
        "name": "Mallory Target",
        "description": "",
        "skills": [],
        "profile_type": "member",
        "origin": "sovereign",
        "agent_facts": {"provider": {"did": _DID}},
        "config": config,
    }
    row.update(over)
    return row


class _Postgres:
    """Returns a fixed row list for GET; records POST/PATCH bodies.

    Table-aware for `member_key_rotations` specifically: the loader reads it as
    well as `agents`, and a fake that answered every GET with the same rows
    would hand agent rows to the rotation walk. They would be discarded (no
    `old_public_key` matches), so the tests would still pass — while asserting
    against an input the server can never receive.
    """

    def __init__(self, rows, rotations=None):
        self.rows = rows
        self.rotations = rotations or []
        self.posts: list[tuple[str, dict]] = []

    async def __call__(self, method, table, params=None, body=None, **kw):
        if method == "GET":
            return self.rotations if table == "member_key_rotations" else self.rows
        if method == "POST":
            self.posts.append((table, body))
            return [{"id": "x"}]
        return None


@pytest.fixture
def loaded(monkeypatch):
    """Run the REAL loader over a realistic row and hand back the record."""
    monkeypatch.setattr(chapter_agent, "pg_request", _Postgres([_row()]))
    monkeypatch.setattr(chapter_agent, "members", {})
    return chapter_agent.members


# ══════════════════════════════════════════════════════════════════════
# 1. Registration WRITES the fields
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_persist_writes_endpoint_into_config(monkeypatch):  # HAPPY
    """The endpoint reaches the durable row. Without this the loader has
    nothing to hydrate FROM, and a hydration test alone would pass against a
    row that never carried the field."""
    pg = _Postgres([])
    monkeypatch.setattr(chapter_agent, "pg_request", pg)
    await chapter_agent._persist_member_to_db(
        "alice", {"name": "Alice", "endpoint": _ENDPOINT, "public_key": _ED}, "sovereign"
    )
    _, body = pg.posts[0]
    assert body["config"]["endpoint"] == _ENDPOINT
    assert body["origin"] == "sovereign"
    assert body["agent_facts"]["provider"]["did"] == _DID


@pytest.mark.asyncio
async def test_persist_writes_empty_endpoint_not_none(monkeypatch):  # EDGE
    """A member with no endpoint stores ``""``, not ``None`` — the loader's
    consumers all treat the field as a string."""
    pg = _Postgres([])
    monkeypatch.setattr(chapter_agent, "pg_request", pg)
    await chapter_agent._persist_member_to_db("alice", {"name": "Alice", "endpoint": None}, "sovereign")
    _, body = pg.posts[0]
    assert body["config"]["endpoint"] == ""


@pytest.mark.asyncio
async def test_persist_upserts_on_the_natural_key_and_merges_config(monkeypatch):  # HAPPY
    """The durable half of the re-registration round trip.

    `agents` has a surrogate `id` primary key and a separate unique on
    `agent_id`. A member row never carries `id`, so upserting on the PRIMARY KEY
    generated a fresh uuid, never tripped ON CONFLICT, and died on
    `agents_agent_id_key` — every re-registration's write was DROPPED and
    outboxed into a conflict that never resolved.

    Repairing that alone would have been worse than leaving it: registration
    rebuilds `config` from its own fields, so a landing write DELETES the keys
    other writers own — measured, it destroyed `listing` consent and the
    host39 publication record. The two must ship together, and this asserts
    both halves of the same call.
    """
    calls: list[dict] = []

    async def _pg(method, table, params=None, body=None, on_conflict=None, merge_jsonb=None):
        if method == "POST":
            calls.append({"on_conflict": on_conflict, "merge_jsonb": merge_jsonb})
            return [{"id": "x"}]
        return None

    monkeypatch.setattr(chapter_agent, "pg_request", _pg)
    await chapter_agent._persist_member_to_db("alice", {"name": "Alice", "endpoint": _ENDPOINT}, "sovereign")
    assert calls, "no upsert was attempted"
    assert calls[0]["on_conflict"] == ["agent_id"], "keyed on the surrogate PK — the write would be dropped"
    assert calls[0]["merge_jsonb"] == ["config", "agent_facts"], (
        "a shared jsonb column is REPLACED, not merged — `config` loses listing consent + host39, "
        "and `agent_facts` loses the key-provenance marker `_pin_member_key` wrote"
    )


# ══════════════════════════════════════════════════════════════════════
# 2. The loader HYDRATES them back
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_loader_hydrates_endpoint_public_key_and_origin(loaded):  # HAPPY
    await chapter_agent.load_persisted_members()
    m = loaded["mallory-target"]
    assert m["endpoint"] == _ENDPOINT
    assert m["public_key"] == _ED
    assert m["origin"] == "sovereign"


@pytest.mark.asyncio
async def test_loader_tolerates_rows_predating_the_fields(monkeypatch):  # EDGE
    """Rows written before this change carry no config.endpoint, no origin and
    no agent_facts. They must load with empty strings, not raise — the fields
    are then exactly as absent as they were before, which is the pre-existing
    behaviour and not a new failure."""
    old = _row(origin=None, agent_facts=None)
    old["config"].pop("endpoint")
    monkeypatch.setattr(chapter_agent, "pg_request", _Postgres([old]))
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    m = chapter_agent.members["mallory-target"]
    assert (m["endpoint"], m["public_key"], m["origin"]) == ("", "", "")


@pytest.mark.asyncio
async def test_loader_refuses_non_ed25519_did_material(monkeypatch):  # ADVERSARIAL
    """A legacy HMAC pubkey riding in ``provider.did`` cannot verify an Ed25519
    signature, so it must NOT be seeded into ``public_key``. Seeding it would
    arm the guard with a value no rotation could ever match, locking the
    member out instead of protecting them."""
    monkeypatch.setattr(
        chapter_agent, "pg_request", _Postgres([_row(agent_facts={"provider": {"did": "did:key:not-base64!!"}})])
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == ""


# ══════════════════════════════════════════════════════════════════════
# 3. Every reader, driven against the record the loader built
#
# The two `register_member` GUARDS (key-change, origin-immutability) are
# asserted through the real handler in `test_member_reregistration_key_guard.py`
# — that is their home, and restating their conditions here would only assert
# my restatement of them.
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_cosign_resolves_the_counterparty_after_a_restore(loaded):  # HAPPY
    """The silently-degrading reader. It matches on ``public_key`` BEFORE it
    reads ``endpoint``, so BOTH fields have to be restored — persisting the
    endpoint alone leaves this returning None and every brokered co-sign
    degrading to an uncorroborated receipt."""
    await chapter_agent.load_persisted_members()
    assert cosign_broker.resolve_member_endpoint(_DID, loaded) == _ENDPOINT


@pytest.mark.asyncio
async def test_cosign_still_declines_an_unregistered_counterparty(loaded):  # ADVERSARIAL
    """The SSRF property this resolver exists for is unchanged: a did that is
    not a registered member still resolves to None and makes no outbound call."""
    await chapter_agent.load_persisted_members()
    assert cosign_broker.resolve_member_endpoint(sovereign_identity.build_did_key_from_ed25519(_OTHER_ED), loaded) is None


@pytest.mark.asyncio
async def test_a2a_forward_branch_is_taken_after_a_restore(loaded):  # HAPPY
    """``agent_logic`` forwards to the member's endpoint when it is set and
    otherwise falls through to the virtual sub-agent — the ORG's LLM answering
    AS the member. The branch is the truthiness of this field."""
    await chapter_agent.load_persisted_members()
    assert loaded["mallory-target"].get("endpoint"), "would have fallen through to LLM impersonation"


@pytest.mark.asyncio
async def test_catalog_stops_omitting_a_restored_member(loaded):  # HAPPY
    """The already-broken-but-visible pair: with no endpoint both return None
    and the resolvable-card rule counts the member in ``omittedMembers``."""
    await chapter_agent.load_persisted_members()
    m = loaded["mallory-target"]
    assert identity._self_served_card_url(m) == f"{_ENDPOINT}/.well-known/agent.json"
    entry = identity._member_catalog_entry("mallory-target", m)
    assert entry is not None and entry["url"] == f"{_ENDPOINT}/.well-known/agent.json"


@pytest.mark.asyncio
async def test_readers_are_asserted_against_the_pre_fix_record_too(loaded):  # ADVERSARIAL
    """The negative control. Strip the two fields back to their pre-fix state
    and assert every reader degrades exactly as reported — so a future change
    that neuters these tests (by making the readers indifferent to the fields)
    fails here instead of passing quietly."""
    await chapter_agent.load_persisted_members()
    m = loaded["mallory-target"]
    m["endpoint"] = ""
    m["public_key"] = ""
    m["origin"] = ""

    assert cosign_broker.resolve_member_endpoint(_DID, loaded) is None  # degrades to uncorroborated
    assert not m.get("endpoint")  # A2A falls through to LLM impersonation
    assert identity._self_served_card_url(m) is None
    assert identity._member_catalog_entry("mallory-target", m) is None  # counted in omittedMembers
    assert not m.get("public_key")  # The key-change guard key-change guard is a no-op
    assert not m.get("origin")  # origin-immutability guard is a no-op


# ══════════════════════════════════════════════════════════════════════
# 3b. The seam between hydration and its consumers (R5, R6)
#
# These belong to the ACROSS-A-RESTART regime (rule six), so unlike the section BELOW
# they DO drive the loader — that is the point of them.
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_a_loader_rebuilt_member_completes_a_brokered_cosign(loaded):  # HAPPY
    """R5: relay -> witness on a member the LOADER reconstructed.

    `test_cosign_broker.py` already covers the relay against a hand-built member
    registry. What was never asserted is the SEAM: that the record
    `load_persisted_members` produces is actually sufficient to complete a
    brokered co-sign. That join is where the degradation lived — the resolver
    reads `public_key` BEFORE `endpoint`, so a hydration that restores only one
    of them leaves every co-sign silently uncorroborated.

    The SSRF guard is NOT weakened, stubbed, or bypassed here. The member's
    endpoint is a PUBLIC-routable literal, so `_is_safe_relay_url` runs on it
    for real and passes on its own merits; only the socket is replaced, through
    the `post` seam `relay_cosign` already exposes for this purpose. The
    assertions below re-prove the guard still refuses internal targets in the
    same run, so "it relayed" can never mean "it relays anywhere".

    What this does NOT establish: `_default_post` — the real HTTP transport —
    is never exercised, so TLS, timeouts, non-200 handling and connect-to-the-
    pinned-IP are out of scope here. Those are covered by
    `test_cosign_broker.py`'s `_default_post` tests.
    """
    monkeypatch_row = _row(config={"endpoint": _PUBLIC_ENDPOINT})
    chapter_agent.pg_request = _Postgres([monkeypatch_row])
    await chapter_agent.load_persisted_members()
    m = loaded["mallory-target"]
    assert m["endpoint"] == _PUBLIC_ENDPOINT and m["public_key"] == _ED, "hydration incomplete — nothing below is meaningful"

    # The guard runs for real on the hydrated endpoint...
    assert cosign_broker._is_safe_relay_url(_PUBLIC_ENDPOINT.rstrip("/") + "/") is True
    # ...and still refuses every internal target, in this same run.
    for internal in ("http://127.0.0.1:9/", "http://169.254.169.254/", "http://10.0.0.5/"):
        assert cosign_broker._is_safe_relay_url(internal) is False, f"SSRF guard weakened for {internal}"

    calls: list[str] = []

    async def _post(url, body, timeout):
        calls.append(url)
        assert body["method"] == "nanda/cosignReceipt"
        return {"result": {"witness": {"witness_did": _DID, "signature": "SIG-FROM-B"}}}

    receipt = {"receipt_id": "r5", "action": {"kind": "test", "counterparty_did": _DID}}
    entry = await cosign_broker.relay_cosign(receipt, members=loaded, post=_post)

    assert entry == {"witness_did": _DID, "signature": "SIG-FROM-B"}
    assert calls == [_PUBLIC_ENDPOINT.rstrip("/") + "/"]


@pytest.mark.asyncio
async def test_an_unregistered_counterparty_still_declines_without_calling(loaded):  # ADVERSARIAL
    """The fail-safe half of the above. Without this, the happy path could be
    satisfied by a broker that relays to anybody."""
    await chapter_agent.load_persisted_members()
    calls: list[str] = []

    async def _post(url, body, timeout):
        calls.append(url)
        return {"result": {"witness": {"witness_did": "x", "signature": "y"}}}

    bogus = {"receipt_id": "r5b", "action": {"kind": "test", "counterparty_did": "did:key:zUnknownParty"}}
    assert await cosign_broker.relay_cosign(bogus, members=loaded, post=_post) is None
    assert calls == [], "made an outbound call for an unregistered counterparty"


def test_the_sm_bridge_converter_never_emits_member_key_material():  # ADVERSARIAL — R6
    """R6: `sm_bridge_adapter` spreads the WHOLE member dict into its converter
    (`{"agent_id": mid, **member}`), and before the descriptor-listing fix `public_key` hydrated to ""
    — so the descriptor-listing fix changed what that spread carries on every restarted org.

    `to_sm()` builds SmAgentFacts from named fields only, so the spread is a
    local convenience that never reaches serialisation. Measured over the wire
    across a real restart: the key appeared on none of 19 surfaces, including
    `/sm-bridge/index`, `/sm-bridge/resolve` and `/sm-bridge/deltas`. This pins
    that at the seam so a future field-forwarding change cannot quietly turn the
    spread into a disclosure.
    """
    convert = sm_bridge_adapter.make_chapter_converter(
        agent_id="test-org", agent_name="Test Org", public_url="https://org.example", members={}
    )
    if convert is None:
        pytest.skip("sm-bridge not installed")

    facts = convert.to_sm({"agent_id": "m1", "name": "M", "skills": ["s"], "public_key": _ED, "endpoint": _ENDPOINT})
    blob = facts.model_dump_json() if hasattr(facts, "model_dump_json") else json.dumps(facts, default=str)
    assert _ED not in blob, "the member's public key reached the sm-bridge wire representation"
    assert _ED.rstrip("=") not in blob


# ══════════════════════════════════════════════════════════════════════
# 4. A ROTATED key must survive the restart too
#
# The descriptor-listing fix made the loader recover a member's key from `agent_facts.provider.did`.
# That is the key registration was handed — and `POST /api/members/rotate`
# never writes back to it. So a member who rotated K1 → K2 was hydrated with
# K1 on the next boot, `reload_member_keys` put K1 back into the auth store,
# and the key they REVOKED signed successfully while their current one got
# `key_mismatch`. The window is "until the next redeploy", which on a live org
# is not a window at all.
#
# The record was already durable: `member_key_rotations` holds every accepted
# rotation, written only after the superseded key verified a signed attestation
# naming this chapter. Nothing read it. These tests drive the loader against
# that table and re-verify each link, because a row trusted merely for being in
# the database would make a Postgres INSERT into an account takeover.
# ══════════════════════════════════════════════════════════════════════

_SK1, _SK2 = SigningKey.generate(), SigningKey.generate()
_K1 = base64.b64encode(bytes(_SK1.verify_key)).decode()
_K2 = base64.b64encode(bytes(_SK2.verify_key)).decode()
_DID_K1 = sovereign_identity.build_did_key_from_ed25519(_K1)


def _rotation(old_sk, old_key: str, new_key: str, *, chapter: str = _ORG, agent: str = "mallory-target") -> dict:
    """A `member_key_rotations` row as `accept_rotation` writes one."""
    ts, nonce = int(time.time()), f"n-{new_key[:6]}"
    canonical = f"ROTATE:{chapter}:{agent}:{new_key}:{ts}:{nonce}"
    attestation = {
        "kind": "rotation",
        "scheme": "ed25519",
        "chapter_id": chapter,
        "agent_id": agent,
        "new_public_key_b64": new_key,
        "timestamp": ts,
        "nonce": nonce,
        "signature": base64.b64encode(old_sk.sign(canonical.encode()).signature).decode(),
    }
    return {
        "agent_id": agent,
        "old_public_key": old_key,
        "new_public_key": new_key,
        "attestation": attestation,
    }


@pytest.fixture
def rotated(monkeypatch):
    """A member registered with K1 who has rotated to K2, then restarted."""
    pg = _Postgres(
        [_row(agent_facts={"provider": {"did": _DID_K1}})],
        rotations=[_rotation(_SK1, _K1, _K2)],
    )
    monkeypatch.setattr(chapter_agent, "pg_request", pg)
    monkeypatch.setattr(chapter_agent, "members", {})
    auth_verify._agent_keys.clear()
    yield chapter_agent.members
    auth_verify._agent_keys.clear()


@pytest.mark.asyncio
async def test_the_loader_advances_a_rotated_member_to_the_current_key(rotated):  # THE REGRESSION
    await chapter_agent.load_persisted_members()
    assert rotated["mallory-target"]["public_key"] == _K2, "hydrated the key the member REVOKED"


@pytest.mark.asyncio
async def test_the_auth_store_gets_the_current_key_not_the_revoked_one(rotated):  # THE REGRESSION
    """`reload_member_keys` runs AFTER the loader and read `agent_facts`
    unconditionally, so it had the last word and undid the walk. Signed-request
    verification reads `ed25519_pubkey` — this is the slot that decides whether
    the member can still sign at all."""
    await chapter_agent.load_persisted_members()
    auth_verify.load_keys_from_members(chapter_agent.members)
    await chapter_agent.reload_member_keys()
    assert auth_verify._agent_keys["mallory-target"]["ed25519_pubkey"] == _K2


@pytest.mark.asyncio
async def test_the_guard_now_refuses_the_revoked_key(rotated):  # ADVERSARIAL
    """The consequence at the surface that matters. With K1 hydrated, a
    re-registration presenting K1 looked like an IDEMPOTENT same-key update and
    was accepted — so the revoked key was silently readopted without any
    attestation. It must now be refused like any other key change."""
    await chapter_agent.load_persisted_members()
    result = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="mallory-target", name="Mallory Target", origin="sovereign", public_key=_K1
        )
    )
    assert getattr(result, "status_code", 200) == 403
    assert json.loads(bytes(result.body))["error"] == "key_change_requires_rotation"


@pytest.mark.asyncio
async def test_an_unsigned_row_moves_nothing(monkeypatch):  # ADVERSARIAL
    """The property that makes reading the audit table safe. Anything able to
    INSERT into `member_key_rotations` would otherwise be able to move any
    member's auth key on the next restart — a database write promoted to an
    account takeover. Each link is re-verified against the key it supersedes."""
    forged = _rotation(_SK1, _K1, _K2)
    forged["attestation"]["signature"] = base64.b64encode(b"\x00" * 64).decode()
    monkeypatch.setattr(
        chapter_agent,
        "pg_request",
        _Postgres([_row(agent_facts={"provider": {"did": _DID_K1}})], rotations=[forged]),
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == _K1


@pytest.mark.asyncio
async def test_a_row_naming_another_chapter_moves_nothing(monkeypatch):  # ADVERSARIAL
    """The query filters on `chapter_id`, so this row cannot arrive in
    production — which is the reason to assert it here rather than to skip it.
    The filter is one `eq.` away from being dropped in a refactor, and the
    signature check is what makes that harmless: a shared database must not let
    a rotation accepted by another org move a key on this one."""
    monkeypatch.setattr(
        chapter_agent,
        "pg_request",
        _Postgres(
            [_row(agent_facts={"provider": {"did": _DID_K1}})],
            rotations=[_rotation(_SK1, _K1, _K2, chapter="some-other-org")],
        ),
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == _K1


@pytest.mark.asyncio
async def test_a_member_with_no_did_takes_the_attested_key(monkeypatch):  # HAPPY
    """The population the walk exists for beyond rotation: a key established by
    TOFU header, or an HMAC pubkey that is not did:key material, leaves
    `agent_facts` empty — and `public_key` empty is the guard as a NO-OP.
    A member who has ever rotated has an attested key here regardless of how
    their first one was established."""
    monkeypatch.setattr(
        chapter_agent,
        "pg_request",
        _Postgres([_row(agent_facts=None)], rotations=[_rotation(_SK1, _K1, _K2)]),
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == _K2


@pytest.mark.asyncio
async def test_a_registration_ahead_of_the_audit_table_is_kept(monkeypatch):  # EDGE
    """Why the walk starts at `agent_facts` instead of taking the newest row.
    A same-key re-registration rewrites `agent_facts` and writes NO rotation
    row, so the column can legitimately be ahead of the table. A key that
    appears nowhere in the chain is left exactly as registration recorded it."""
    unrelated = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    monkeypatch.setattr(
        chapter_agent,
        "pg_request",
        _Postgres(
            [_row(agent_facts={"provider": {"did": sovereign_identity.build_did_key_from_ed25519(unrelated)}})],
            rotations=[_rotation(_SK1, _K1, _K2)],
        ),
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == unrelated


@pytest.mark.asyncio
async def test_a_rotation_cycle_terminates(monkeypatch):  # EDGE
    """Nothing forbids K1 → K2 → K1: the table's only constraint is that a row's
    old and new keys differ. The walk must land somewhere rather than spin at
    boot, which is a hang with no error message."""
    monkeypatch.setattr(
        chapter_agent,
        "pg_request",
        _Postgres(
            [_row(agent_facts={"provider": {"did": _DID_K1}})],
            rotations=[_rotation(_SK1, _K1, _K2), _rotation(_SK2, _K2, _K1)],
        ),
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await asyncio.wait_for(chapter_agent.load_persisted_members(), timeout=10)
    assert chapter_agent.members["mallory-target"]["public_key"] in (_K1, _K2)


@pytest.mark.asyncio
async def test_an_unreadable_audit_table_leaves_the_registered_key(monkeypatch):  # EDGE
    """Deliberately NOT fail-closed. Refusing to hydrate any key when the audit
    table is unreachable would turn one unreadable table into the guard
    being a no-op for every member of the org — strictly worse than the state a
    moment earlier. It degrades to exactly the previous behaviour, and says so."""

    class _Broken(_Postgres):
        async def __call__(self, method, table, params=None, body=None, **kw):
            if table == "member_key_rotations":
                raise RuntimeError("PostgREST 503")
            return await super().__call__(method, table, params, body, **kw)

    monkeypatch.setattr(
        chapter_agent, "pg_request", _Broken([_row(agent_facts={"provider": {"did": _DID_K1}})])
    )
    monkeypatch.setattr(chapter_agent, "members", {})
    await chapter_agent.load_persisted_members()
    assert chapter_agent.members["mallory-target"]["public_key"] == _K1


# ══════════════════════════════════════════════════════════════════════
# 5. The inverse: a defect a RESTART REPAIRS — asserted inside ONE process
#
# Everything above is about state that must survive a boot. This section is the
# opposite failure, and it needs the opposite discipline. A profile-only
# re-registration wiped `endpoint` from the live `members[]` map while the row
# in Postgres still held it, so the member silently lost its catalog entry, its
# co-sign resolvability and its A2A delivery — until the next restart, when
# `load_persisted_members` put the value back.
#
# Restarting is the REPAIR, so no restart-based assertion can see this. These
# tests deliberately never boot, never reload, and never call
# `load_persisted_members` after the re-registration. If a future edit adds a
# reload in here to "make it realistic", it silently stops testing anything.
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def live(monkeypatch):
    """A single running process: an empty registry, no loader, no Postgres."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    async def _noop_pg(*_a, **_k):
        return None

    monkeypatch.setattr(chapter_agent, "pg_request", _noop_pg)
    auth_verify._agent_keys.clear()
    yield chapter_agent.members
    auth_verify._agent_keys.clear()


async def _register(**over):
    body = {"agent_id": "live-member", "name": "Live Member", "origin": "sovereign"}
    body.update(over)
    return await chapter_agent.register_member(chapter_agent.MemberRegistration(**body))


@pytest.mark.asyncio
async def test_profile_only_reregistration_keeps_the_endpoint(live):  # THE REGRESSION
    """The live defect. `MemberRegistration.endpoint` defaults to "", so a
    re-registration that simply does not mention the endpoint used to overwrite
    it with "" in the running process."""
    await _register(endpoint=_ENDPOINT, public_key=_ED)
    assert live["live-member"]["endpoint"] == _ENDPOINT, "setup failed — nothing to lose below"

    await _register(name="Renamed")  # no endpoint, no key — the ordinary path

    assert live["live-member"]["endpoint"] == _ENDPOINT
    assert live["live-member"]["name"] == "Renamed", "the profile update itself must still apply"


@pytest.mark.asyncio
async def test_the_three_readers_still_work_after_a_reregistration(live):  # HAPPY
    """The consequence, not just the field: assert what actually broke for the
    member during that window."""
    await _register(endpoint=_ENDPOINT, public_key=_ED)
    await _register(name="Renamed")

    m = live["live-member"]
    assert cosign_broker.resolve_member_endpoint(_DID, live) == _ENDPOINT  # co-sign resolvable
    assert m.get("endpoint")  # A2A forwards instead of the LLM impersonating
    assert identity._member_catalog_entry("live-member", m) is not None  # not catalog-omitted


@pytest.mark.asyncio
async def test_an_explicit_new_endpoint_still_replaces_the_old_one(live):  # EDGE
    """The fallback must not freeze the field — a member re-registering WITH an
    endpoint still changes it. A guard that made the endpoint immutable would
    pass the test above and be its own bug."""
    await _register(endpoint=_ENDPOINT, public_key=_ED)
    await _register(endpoint="https://moved.example", public_key=_ED)
    assert live["live-member"]["endpoint"] == "https://moved.example"


@pytest.mark.asyncio
async def test_the_fallback_mirrors_public_key_exactly(live):  # EDGE
    """`endpoint` now behaves as `public_key` does on the very next line: an
    omitted field preserves the stored value. Asserted together so the two
    cannot drift apart again — the defect was that they already had."""
    await _register(endpoint=_ENDPOINT, public_key=_ED)
    await _register(name="Renamed")
    m = live["live-member"]
    assert (m["endpoint"], m["public_key"]) == (_ENDPOINT, _ED)


def test_this_section_never_restarts():  # ADVERSARIAL — guards the rule itself
    """Rule seven, enforced mechanically rather than by comment. A restart is
    the REPAIR for these defects, so any reload inside this section would make
    its tests pass regardless of the fix.

    Scans from the section marker to END OF FILE, subtracting only this
    function's own body (which necessarily names what it forbids). An earlier
    version truncated at this function's NAME instead, which silently stopped
    covering anything added below it — and tests were added below it. A guard
    whose coverage depends on where the next author appends is not a guard.
    """
    import inspect
    import re

    src = inspect.getsource(sys.modules[__name__])
    section = src.split("# 4. The inverse:", 1)[1]
    section = section.replace(inspect.getsource(test_this_section_never_restarts), "")
    for banned in ("load_persisted_members", "reload_member_keys", "importlib.reload"):
        assert not re.search(rf"\b{re.escape(banned)}\s*\(", section), (
            f"{banned}() appears in the single-process section — a restart there "
            "repairs the very defect these tests exist to catch, so they would "
            "pass with the fix reverted"
        )


@pytest.mark.asyncio
async def test_reregistration_keeps_keys_other_writers_own(live):  # THE REGRESSION
    """`members[]` used to be REPLACED wholesale on re-registration, deleting
    every key registration does not own — the Listing consent, the host39
    publication record, `is_demo`, `profile_type`. A consenting member silently
    dropped out of the LIVE Listing until the next restart rehydrated them.

    Within-process by necessity: the restart is the repair, so a test that
    reloads here would pass with the merge reverted."""
    await _register(endpoint=_ENDPOINT, public_key=_ED)
    m = live["live-member"]
    # Keys written by OTHER writers: the listing route and the host39 admin route.
    m[member_listing.CONSENT_KEY] = {"listed": True, "agent_url": _ENDPOINT}
    m[chapter_agent.HOST39_PUBLISHED_AT] = "2026-08-10T00:00:00Z"
    m["is_demo"] = True
    m["profile_type"] = "founder"

    await _register(name="Renamed")  # the ordinary path

    m = live["live-member"]
    assert m[member_listing.CONSENT_KEY] == {"listed": True, "agent_url": _ENDPOINT}
    assert m[chapter_agent.HOST39_PUBLISHED_AT] == "2026-08-10T00:00:00Z"
    assert m["is_demo"] is True
    assert m["profile_type"] == "founder"
    assert m["name"] == "Renamed", "the profile update itself must still apply"


@pytest.mark.asyncio
async def test_reregistration_keeps_description_and_skills(live):  # THE REGRESSION
    """Same omitted-means-keep shape as `endpoint` and `public_key`. Invisible
    while the upsert was broken; a durable loss of member-authored profile data
    the moment it was repaired."""
    await _register(endpoint=_ENDPOINT, public_key=_ED, description="orig desc", skills=["a", "b"])
    await _register(name="Renamed")
    m = live["live-member"]
    assert m["description"] == "orig desc"
    assert m["skills"] == ["a", "b"]


@pytest.mark.asyncio
async def test_explicit_values_still_replace_description_and_skills(live):  # EDGE
    """The converse, carried across from that change: a fix that FROZE these fields
    would pass the two tests above and be its own bug."""
    await _register(endpoint=_ENDPOINT, public_key=_ED, description="orig desc", skills=["a", "b"])
    await _register(description="new desc", skills=["z"])
    m = live["live-member"]
    assert m["description"] == "new desc"
    assert m["skills"] == ["z"]
