"""How a member's key came to be theirs — and why that has to be recorded.

A public key carries no evidence of its own provenance, and the ways one gets
established here are not equally strong:

  * ``rotated``              — the superseded key SIGNED for its successor.
    The only attested one; the evidence is the `member_key_rotations` chain the
    loader walks, not a marker anybody wrote next to the key.
  * ``registered``           — supplied at first registration. First claim wins.
  * ``pinned_registration``  — adopted for an EXISTING member who had none.
  * ``pinned_tofu_header``   — the same, established from ``X-Agent-DID-Key``.

The last two are this module's subject. They exist because the key-change
guard only fires on a NON-EMPTY stored key, so a member with none was not
protected by it at all: every re-registration could set a different key, forever,
silently, and after every restart. A pin does not make that safe — **whoever
claims first still wins** — it makes it happen ONCE, durably, with an audit row
naming who claimed it and when.

The alternative considered and rejected was to refuse: a member whose key cannot
be established would be locked out of their own account with no way back, since
they can neither re-register (refused) nor rotate (``/api/members/rotate``
answers ``no stored key for this agent``). The binding rule is **never a refusal
without a recovery path**, so every decline below leaves the member exactly as
they were rather than worse.

Revocation is in here for the same reason: it is the one operation that must
REMOVE a key durably, and it is the case where a pin and the rotation chain both
have to yield to an operator.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time

os.environ.setdefault("AGENT_ID", "provenance-test-org")
os.environ.setdefault("AGENT_NAME", "Provenance Test Org")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402
import sovereign_identity  # noqa: E402

_ORG = chapter_agent.AGENT_ID
_K1 = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
_K2 = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
_DID1 = sovereign_identity.build_did_key_from_ed25519(_K1)
_HMAC = "legacy-hmac-secret-not-ed25519"
_AID = "keyless-member"


class _Store:
    """An `agents` table with one row, plus the rotation audit table.

    PATCH updates the row in place and returns it — matching `pg_store`, whose
    UPDATE ... RETURNING yields nothing when the WHERE matches no row. That
    detail is the whole reason a pin cannot create a member, so the fake has to
    reproduce it rather than accept every write.
    """

    def __init__(self, row: dict | None = None, rotations: list[dict] | None = None):
        self.rows = [row] if row else []
        self.rotations = rotations or []
        self.rotations_readable = True
        self.patches: list[dict] = []
        self.posts: list[dict] = []

    async def __call__(self, method, table, params=None, body=None, on_conflict=None, merge_jsonb=None):
        if table == "member_key_rotations":
            if not self.rotations_readable:
                raise RuntimeError("PostgREST 503")
            return list(self.rotations)
        if method == "GET":
            return list(self.rows)
        if method == "PATCH":
            if not self.rows:
                return []
            self.patches.append(dict(body or {}))
            self.rows[0].update(body or {})
            return list(self.rows)
        if method == "POST":
            self.posts.append(dict(body or {}))
            return [{"id": "x"}]
        return None

    @property
    def facts(self) -> dict:
        return (self.rows[0].get("agent_facts") if self.rows else {}) or {}

    @property
    def provenance(self) -> dict:
        return self.facts.get(chapter_agent.KEY_PROVENANCE) or {}


def _member_row(**over) -> dict:
    row = {
        "agent_id": _AID,
        "name": "Keyless Member",
        "origin": "sovereign",
        "agent_facts": {},
        "config": {"parent_chapter": _ORG},
    }
    row.update(over)
    return row


async def _drain() -> None:
    """Let the fire-and-forget writers finish.

    Registration and TOFU both schedule their durable writes with
    `asyncio.create_task` so a Postgres hiccup cannot fail the caller's request.
    Asserting without draining would test the scheduling, not the write.
    """
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


def _rotation_row(old: str, new: str) -> dict:
    """A rotation row whose signature is DELIBERATELY absent.

    Every assertion that uses this one is about whether history EXISTS — which
    is what makes a member recoverable from the chain and therefore not a pin
    candidate. The walk itself refuses to advance across it, and that is
    correct: `_signed_rotation` is what a test needs when the chain must move.
    """
    return {"agent_id": _AID, "old_public_key": old, "new_public_key": new, "attestation": {}}


def _signed_rotation(old_sk: SigningKey, new_key: str, *, agent: str = _AID) -> dict:
    """A rotation row the loader will actually WALK — signed by the key it
    supersedes, exactly as `accept_rotation` writes one. Precedence assertions
    need this: a chain that cannot be verified cannot outrank anything."""
    old_key = base64.b64encode(bytes(old_sk.verify_key)).decode()
    ts, nonce = int(time.time()), f"n-{new_key[:6]}"
    canonical = f"ROTATE:{_ORG}:{agent}:{new_key}:{ts}:{nonce}"
    return {
        "agent_id": agent,
        "old_public_key": old_key,
        "new_public_key": new_key,
        "attestation": {
            "kind": "rotation",
            "scheme": "ed25519",
            "chapter_id": _ORG,
            "agent_id": agent,
            "new_public_key_b64": new_key,
            "timestamp": ts,
            "nonce": nonce,
            "signature": base64.b64encode(old_sk.sign(canonical.encode()).signature).decode(),
        },
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")
    auth_verify._agent_keys.clear()
    yield
    auth_verify._agent_keys.clear()


# ══════════════════════════════════════════════════════════════════════
# B — a key established by TOFU HEADER must be written down
#
# `store_did_key` files it in `_agent_keys`, which is in-memory and empty on
# every boot. Nothing wrote it anywhere else, so a member whose key was only
# ever established this way had NO durable key: the loader hydrated
# `public_key=""`, the guard is a no-op on an empty key, and the identity
# was re-claimable by an unauthenticated POST after every restart, indefinitely.
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_a_tofu_header_key_is_persisted(monkeypatch):  # HAPPY
    store = _Store(_member_row())
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    auth_verify.store_did_key(_AID, _DID1)

    await chapter_agent._on_tofu_established(_AID, {"X-Agent-DID-Key": _DID1}, method="GET", path="/api/x")
    await _drain()

    assert store.facts["provider"]["did"] == _DID1, "the key the server ACCEPTED was never written down"
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_PINNED_TOFU_HEADER
    assert store.provenance["attested"] is False, "a pinned key must never read as an attested one"


@pytest.mark.asyncio
async def test_a_tofu_key_for_an_unknown_agent_creates_nothing(monkeypatch):  # ADVERSARIAL
    """A pin must never CREATE a member. Otherwise an unauthenticated signed
    request against any agent_id at all becomes a registration."""
    store = _Store()  # no row
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    auth_verify.store_did_key(_AID, _DID1)

    await chapter_agent._on_tofu_established(_AID, {"X-Agent-DID-Key": _DID1}, method="GET", path="/api/x")
    await _drain()

    assert store.rows == []
    assert store.patches == []


@pytest.mark.asyncio
async def test_a_pin_never_displaces_a_key_already_on_file(monkeypatch):  # ADVERSARIAL
    """Replacing a key on file is a ROTATION and goes through the attested path.
    If a pin could overwrite one, it would be the takeover with an audit row
    attached rather than a fix for it."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    assert await chapter_agent._pin_member_key(_AID, _K2, source="pinned_registration") is False
    assert store.facts["provider"]["did"] == _DID1


@pytest.mark.asyncio
async def test_a_member_with_rotation_history_is_not_pinned(monkeypatch):  # ADVERSARIAL
    """The narrowing that keeps a pin from ever competing with evidence. A member
    who has rotated has an ATTESTED key in `member_key_rotations` and recovers
    from there; pinning a claim over it would let an unauthenticated
    caller displace a key that was cryptographically proven."""
    store = _Store(_member_row(), rotations=[_rotation_row(_K1, _K2)])
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    assert await chapter_agent._pin_member_key(_AID, _K1, source="pinned_registration") is False
    assert store.patches == []


@pytest.mark.asyncio
async def test_unreadable_rotation_history_declines_the_pin(monkeypatch):  # ADVERSARIAL
    """Unknown is treated as "yes, there is history". Declining leaves the member
    exactly where they were; pinning on a guess could bury a recoverable key."""
    store = _Store(_member_row())
    store.rotations_readable = False
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    assert await chapter_agent._pin_member_key(_AID, _K1, source="pinned_registration") is False


@pytest.mark.asyncio
async def test_legacy_hmac_material_is_not_pinned(monkeypatch):  # EDGE
    """An HMAC pubkey has no did:key form and could not verify an Ed25519
    signature. Recording it would arm the guard with a value no rotation
    could ever match — a lockout dressed as protection."""
    store = _Store(_member_row())
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    assert await chapter_agent._pin_member_key(_AID, _HMAC, source="pinned_registration") is False
    assert store.patches == []


# ══════════════════════════════════════════════════════════════════════
# C2 — pin on first claim at registration, and the residual it leaves
# ══════════════════════════════════════════════════════════════════════


async def _register(**over):
    body = {"agent_id": _AID, "name": "Keyless Member", "origin": "sovereign"}
    body.update(over)
    return await chapter_agent.register_member(chapter_agent.MemberRegistration(**body))


@pytest.mark.asyncio
async def test_the_first_claim_on_a_keyless_member_is_pinned(monkeypatch):  # HAPPY
    store = _Store(_member_row())
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    chapter_agent.members[_AID] = {"name": "Keyless Member", "origin": "sovereign", "public_key": ""}

    await _register(public_key=_K1)
    await _drain()

    assert store.facts["provider"]["did"] == _DID1
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_PINNED_REGISTRATION


@pytest.mark.asyncio
async def test_the_pin_still_guards_the_member_after_a_restart(monkeypatch):  # THE POINT
    """Where the whole thing is decided. The in-process assertion below passes
    even with no pin at all — `register_member` sets the in-memory key either
    way. What the pin changes is the state a RESTART rebuilds from: without it
    the loader hydrates `public_key=""` again and the next unauthenticated POST
    sets whatever key it likes, which is the same hole reopening on every boot,
    forever."""
    store = _Store(_member_row())
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    chapter_agent.members[_AID] = {"name": "Keyless Member", "origin": "sovereign", "public_key": ""}
    await _register(public_key=_K1)
    await _drain()

    chapter_agent.members.clear()
    await chapter_agent.load_persisted_members()

    assert chapter_agent.members[_AID]["public_key"] == _K1, "the claim did not survive the boot"
    result = await _register(public_key=_K2)
    assert getattr(result, "status_code", 200) == 403


@pytest.mark.asyncio
async def test_a_second_different_key_is_then_refused(monkeypatch):  # THE POINT
    """What the pin buys within one process. Before it, EVERY re-registration
    could set a different key — the guard reads `existing["public_key"]` and does
    nothing when it is empty. One claim fills it, and the next claimant meets the
    guard."""
    store = _Store(_member_row())
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    chapter_agent.members[_AID] = {"name": "Keyless Member", "origin": "sovereign", "public_key": ""}

    await _register(public_key=_K1)
    await _drain()
    result = await _register(public_key=_K2)

    assert getattr(result, "status_code", 200) == 403
    assert json.loads(bytes(result.body))["error"] == "key_change_requires_rotation"


@pytest.mark.asyncio
async def test_a_first_registration_is_registered_not_pinned(monkeypatch):  # EDGE
    """A member registering for the first time is not a pin: there is no prior
    record to claim. Marking it `pinned` would inflate the count of keys nobody
    proved and make the marker useless for the audit it exists for."""
    store = _Store()
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    await chapter_agent._persist_member_to_db(
        _AID, {"name": "M", "public_key": _K1}, "sovereign", key_source=chapter_agent.KEY_SOURCE_REGISTERED
    )

    facts = store.posts[0]["agent_facts"]
    assert facts["provider"]["did"] == _DID1
    assert facts[chapter_agent.KEY_PROVENANCE]["source"] == chapter_agent.KEY_SOURCE_REGISTERED


@pytest.mark.asyncio
async def test_a_reregistration_does_not_restamp_provenance(monkeypatch):  # ADVERSARIAL
    """A pinned member's own profile update must not upgrade their key's story.
    Two halves make that hold: registration passes no `key_source`, and
    `agent_facts` MERGES on conflict — a replace would delete the marker this
    writer never supplied."""
    store = _Store()
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    calls: list[dict] = []

    async def _pg(method, table, params=None, body=None, on_conflict=None, merge_jsonb=None):
        if method == "POST" and table == "agents":
            calls.append({"body": body, "merge_jsonb": merge_jsonb})
        return await store(method, table, params, body, on_conflict, merge_jsonb)

    monkeypatch.setattr(chapter_agent, "pg_request", _pg)
    await chapter_agent._persist_member_to_db(_AID, {"name": "M", "public_key": _K1}, "sovereign")

    assert chapter_agent.KEY_PROVENANCE not in calls[0]["body"]["agent_facts"]
    assert "agent_facts" in (calls[0]["merge_jsonb"] or []), "a replace here erases the pin marker"


# ══════════════════════════════════════════════════════════════════════
# Revocation — the one operation that must REMOVE a key durably
#
# The endpoint nulled `ed25519_pubkey`, `public_key` and `signing_secret`:
# three columns that do not exist on `agents`. The UPDATE failed, `pg_request`
# swallowed it, and the response said `revoked: true` while the durable key sat
# untouched in `agent_facts.provider.did` — so the next redeploy handed the
# member back the key an operator had just revoked, in a flow whose first
# documented use case is "compromised key suspected".
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def as_admin(monkeypatch):
    async def _ok(_request):
        return True, {"path": "bearer", "agent_id": "operator"}, None

    monkeypatch.setattr(chapter_agent, "_authorize_admin", _ok)


@pytest.mark.asyncio
async def test_revocation_clears_the_durable_key(as_admin, monkeypatch):  # THE REGRESSION
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    response = await chapter_agent.admin_revoke_key(_AID, None)

    assert store.facts.get("provider", {}).get("did") in (None, "")
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_REVOKED
    assert json.loads(bytes(response.body))["durable"] is True


@pytest.mark.asyncio
async def test_a_revoked_key_does_not_come_back_on_the_next_boot(as_admin, monkeypatch):  # THE REGRESSION
    """The interaction, and the reason revocation needs a marker rather than
    just an empty column. An operator can clear `provider.did` but CANNOT delete
    the member's rotation history — so a loader that walks the chain would take
    its tail and re-establish the very key that was revoked."""
    store = _Store(
        _member_row(agent_facts={"provider": {"did": _DID1}}),
        rotations=[_rotation_row(_K2, _K1)],
    )
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await chapter_agent.admin_revoke_key(_AID, None)

    chapter_agent.members.clear()
    await chapter_agent.load_persisted_members()

    assert chapter_agent.members[_AID]["public_key"] == "", "the revoked key was resurrected from the chain"


@pytest.mark.asyncio
async def test_a_revocation_that_does_not_persist_says_so(as_admin, monkeypatch):  # EDGE
    """The old response asserted success for a write that never landed. An
    operator acting on a suspected compromise needs to know the difference
    between "cleared here" and "cleared for good"."""
    store = _Store()  # no row → PATCH matches nothing, exactly as SQL would
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    response = await chapter_agent.admin_revoke_key(_AID, None)

    assert json.loads(bytes(response.body))["durable"] is False


@pytest.mark.asyncio
async def test_a_pin_after_a_revocation_is_allowed_and_flagged(as_admin, monkeypatch):  # EDGE
    """Allowed, because `admin_revoke_key` documents the recovery as "the agent
    re-registers with a fresh keypair" — refusing would break the operator's own
    path back and leave the member permanently unguarded, a refusal with no
    recovery. Flagged, because after a revoke the identity goes to whoever
    claims first, and that is exactly when an operator wants to see it."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await chapter_agent.admin_revoke_key(_AID, None)

    assert await chapter_agent._pin_member_key(_AID, _K2, source="pinned_tofu_header") is True
    assert store.provenance["after_revocation"] is True
    assert store.provenance["attested"] is False


# ══════════════════════════════════════════════════════════════════════
# Revoke-with-successor — closing the race instead of auditing it
#
# A bare revocation leaves the member unclaimed, and the first-claim pin pins the FIRST claim:
# so from the moment an operator revokes, the legitimate member is racing
# whoever else is watching. Naming the successor in the same act means there is
# nothing to race for — the key is on file, and every other claimant meets the
# the key-change guard immediately.
#
# It lets an operator INSTALL a key rather than merely deny one, which is
# impersonation rather than denial — a new power if they did not already have
# it. They do, by three measured paths (revoke→TOFU-claim, revoke→open
# re-registration, DELETE→re-register), each needing only the admin token and
# the open registration path, each ending with the operator's key in the auth
# store after a reboot. This makes that act atomic, labelled and audited
# instead of a race an operator wins by going first.
#
# PRECEDENCE is the safety property: rotation > operator vouch > first-claim
# pin. Each block below asserts one edge of that ordering.
# ══════════════════════════════════════════════════════════════════════


async def _revoke_with(successor: str | None):
    body = {"successor_public_key": successor} if successor is not None else None
    return await chapter_agent.admin_revoke_key(_AID, None, body)


@pytest.mark.asyncio
async def test_the_successor_is_on_file_immediately(as_admin, monkeypatch):  # HAPPY
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    response = await _revoke_with(_K2)

    assert json.loads(bytes(response.body))["successor_preauthorized"] is True
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_OPERATOR_VOUCHED
    assert store.provenance["attested"] is False, "an operator's word is not the superseded key's signature"
    assert store.provenance["vouched_by"] == "operator", "the vouching party must be legible in the data"
    assert chapter_agent.members[_AID]["public_key"] == _K2, "not protected until the next boot"
    assert auth_verify._agent_keys[_AID]["ed25519_pubkey"] == _K2


@pytest.mark.asyncio
async def test_the_successor_survives_a_restart(as_admin, monkeypatch):  # THE REGRESSION SHAPE
    """The shape that has bitten three times — rotation, revocation, and the
    TOFU key were all state that lived in one process and was rebuilt from a
    source nobody re-checked. A pre-authorisation that only holds until the next
    redeploy would reopen the exact race it closes, and the operator would have
    been told it was closed."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await _revoke_with(_K2)

    chapter_agent.members.clear()
    auth_verify._agent_keys.clear()
    await chapter_agent.load_persisted_members()
    auth_verify.load_keys_from_members(chapter_agent.members)
    await chapter_agent.reload_member_keys()

    assert chapter_agent.members[_AID]["public_key"] == _K2
    assert auth_verify._agent_keys[_AID]["ed25519_pubkey"] == _K2


@pytest.mark.asyncio
async def test_no_one_else_can_claim_a_preauthorized_member(as_admin, monkeypatch):  # THE POINT
    """The race, closed. Without a successor this same POST wins the vacancy."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await _revoke_with(_K2)

    result = await _register(public_key=_K1)

    assert getattr(result, "status_code", 200) == 403
    assert json.loads(bytes(result.body))["error"] == "key_change_requires_rotation"


@pytest.mark.asyncio
async def test_a_vouch_beats_a_first_claim_pin(as_admin, monkeypatch):  # PRECEDENCE 2 > 3
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await _revoke_with(_K2)

    assert await chapter_agent._pin_member_key(_AID, _K1, source="pinned_tofu_header") is False
    assert store.facts["provider"]["did"] == sovereign_identity.build_did_key_from_ed25519(_K2)
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_OPERATOR_VOUCHED


@pytest.mark.asyncio
async def test_a_rotation_from_the_vouched_key_beats_the_vouch(as_admin, monkeypatch):  # PRECEDENCE 1 > 2
    """The edge that matters most. An operator's assertion must not outrank a
    signature from the key it names: once the member rotates AWAY from the
    vouched key, the attested chain is what the loader follows."""
    successor_sk = SigningKey.generate()
    successor = base64.b64encode(bytes(successor_sk.verify_key)).decode()
    successor_next = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    await _revoke_with(successor)
    store.rotations = [_signed_rotation(successor_sk, successor_next)]

    chapter_agent.members.clear()
    await chapter_agent.load_persisted_members()

    assert chapter_agent.members[_AID]["public_key"] == successor_next


@pytest.mark.asyncio
async def test_a_vouch_is_not_undone_by_the_chain_it_replaces(as_admin, monkeypatch):  # THE REGRESSION SHAPE
    """The other half of precedence, and the shape that has bitten three times.

    Revoking cannot delete a member's rotation history, so a member who had
    rotated K1 → K2 still has a chain whose tail is the key just revoked. If the
    loader walked it, the next boot would hand back exactly the key the operator
    replaced — a revocation undone by a restart, which is the supersession walk's resurrection
    arriving through the new path.

    Note what is NOT claimed here: an operator CAN move a rotated member's key.
    That is what revocation is for. What they cannot do is have it silently
    reverted — or outrank a rotation performed FROM the key they named, which is
    the test above."""
    member_sk = SigningKey.generate()
    rotated_to = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    registered_did = sovereign_identity.build_did_key_from_ed25519(
        base64.b64encode(bytes(member_sk.verify_key)).decode()
    )
    store = _Store(
        _member_row(agent_facts={"provider": {"did": registered_did}}),
        rotations=[_signed_rotation(member_sk, rotated_to)],
    )
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    vouched = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    await _revoke_with(vouched)

    chapter_agent.members.clear()
    await chapter_agent.load_persisted_members()

    assert chapter_agent.members[_AID]["public_key"] == vouched
    assert chapter_agent.members[_AID]["public_key"] != rotated_to, "the revoked key came back from the chain"


@pytest.mark.asyncio
async def test_a_wrong_successor_still_has_a_way_back(as_admin, monkeypatch):  # THE RECOVERY PATH
    """The binding constraint, asserted rather than asserted-about. If an
    operator pre-authorises a key the member does not hold, the member can
    neither claim (the guard refuses a different key) nor rotate (they cannot
    sign for the installed one). The way back is a second revocation, which
    reopens the claim — operator-mediated, but it EXISTS, and this is what
    proves it exists before the feature ships rather than after."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)
    wrong = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
    await _revoke_with(wrong)
    assert getattr(await _register(public_key=_K1), "status_code", 200) == 403  # stranded

    await _revoke_with(None)  # the way back
    chapter_agent.members.clear()
    await chapter_agent.load_persisted_members()

    assert chapter_agent.members[_AID]["public_key"] == ""
    assert getattr(await _register(public_key=_K1), "status_code", 200) == 200


@pytest.mark.asyncio
async def test_a_malformed_successor_installs_nothing(as_admin, monkeypatch):  # ADVERSARIAL
    """A typo must not install a key nobody holds — that is the lockout the
    recovery path above exists to survive, and it is cheaper to refuse the
    operator than to strand the member. Refusing the OPERATOR is not the refusal
    the standing rule forbids: they retry, and nothing about the member moved."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    response = await _revoke_with("not-a-key")

    assert response.status_code == 400
    assert store.facts["provider"]["did"] == _DID1, "the member's key moved on a rejected request"
    assert store.patches == []


@pytest.mark.asyncio
async def test_a_bare_revocation_still_behaves_exactly_as_before(as_admin, monkeypatch):  # EDGE
    """The body is optional and the old call shape is untouched — an operator
    who wants denial rather than replacement still gets denial."""
    store = _Store(_member_row(agent_facts={"provider": {"did": _DID1}}))
    monkeypatch.setattr(chapter_agent, "pg_request", store)

    response = await _revoke_with(None)

    body = json.loads(bytes(response.body))
    assert (body["revoked"], body["durable"], body["successor_preauthorized"]) == (True, True, False)
    assert store.provenance["source"] == chapter_agent.KEY_SOURCE_REVOKED
