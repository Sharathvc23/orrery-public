"""sm-federation §4 — the guarantee, not the endpoint.

A feed that returns signed pages but cannot prove a subscriber saw every entry is
the unsigned snapshot with extra steps. So the load-bearing tests here are not
"the endpoint responds" — they are three failures a subscriber MUST be able to
detect, each proven by planting that specific failure into a page and checking
what a real subscriber (``sm_federation.read_intelligence``, the published seam)
says about it:

  C1  a DROPPED entry      → chain_break / non_contiguous_seq
  C2  a REORDERED entry    → chain_break
  C3  a RESTARTED sequence → head_rewind

C3 is why this feature owns a table. A restarted feed is signed correctly and
chains correctly from its own new genesis, so it verifies as a flawless FIRST
sync while every entry the subscriber held has silently ceased to exist. Only a
head the subscriber already accepted distinguishes "extended" from "replaced" —
which is what ``expected_head`` is, and what sm-federation 0.5.0 made normative
after the conformance suite found the reference seam could not detect a rewind at
all through 0.4.2.

⚠️ **A bare ``ok`` over a reseeded sequence is the silent reseed**, and that is
the failure this whole feature exists to make impossible. C3 therefore
accepts exactly two outcomes — the page verifies against the pinned head, or it
fails ``head_rewind`` — and asserts explicitly that a bare ``ok`` is NOT one of
them.

**Plant discipline:** every planted break is read back out of the
mutated page before anything is asserted about it, AND the revert is confirmed —
an unreverted plant ships. A plant that silently failed to apply looks exactly
like a guard that fired.

Classification: DURABILITY (D1-D3) · COMPLETENESS (C1-C3) · POLICY (P1-P3, the
three boot-ensure cases) · WIRE (W1-W3).
"""

from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import sm_federation
from fastapi.testclient import TestClient
from sm_feed import Identity

import federation_feed

_PUBLIC_URL = "https://feed-org.example"
_GENERATED_AT = "2026-08-09T00:00:00+00:00"


# ── An in-process stand-in for the durable table ───────────────────────────
#
# Rows, not objects: it stores what the column set stores and hands back what a
# SELECT hands back, so append/read go through the same serialisation the real
# table does. `restart()` drops every in-memory handle while KEEPING the rows —
# which is exactly what a process restart does to a durable log, and is the only
# way to test that the chain continues rather than reseeding.
class FakeTable:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def __call__(self, method: str, table: str, params: dict | None = None, body: Any = None):
        assert table == "federation_feed_entries", table
        if method == "POST":
            row = dict(body)
            if any(r["entry_hash"] == row["entry_hash"] for r in self.rows):
                raise RuntimeError("duplicate entry_hash — the UNIQUE index would have refused this")
            self.rows.append(row)
            return row
        params = params or {}
        rows = [r for r in self.rows if r["feed_id"] == params.get("feed_id", "").removeprefix("eq.")]
        if "seq" in params:
            rows = [r for r in rows if r["seq"] > int(params["seq"].removeprefix("gt."))]
        rows.sort(key=lambda r: r["seq"], reverse=params.get("order") == "seq.desc")
        return rows[: params["limit"]] if params.get("limit") else rows

    def restart(self) -> None:
        """Everything volatile is gone; the rows remain. What a redeploy does."""
        self.rows = [json.loads(json.dumps(r)) for r in self.rows]


@pytest.fixture
def identity() -> Identity:
    return Identity.from_seed(bytes(range(32)))


@pytest.fixture
def table() -> FakeTable:
    return FakeTable()


def _envelope(n: int, *, epoch: int = 0) -> dict[str, Any]:
    """``epoch`` distinguishes a republished entry from the one it replaced.

    It exists because the plant-confirmation check caught this test being
    vacuous: republishing the SAME envelopes at the same ``issued_at`` after a
    wipe produces byte-identical entries with identical hashes, i.e. not a
    reseeded feed at all but the same feed, shorter. C3 would still have gone red
    — on head_seq alone — and would have been asserting the wrong thing.
    """
    return sm_federation.build_intelligence_envelope(
        community_id="feed-org",
        community_name="Feed Org",
        generated_at=f"2026-08-0{9 + epoch}T00:0{n}:00+00:00",
        skill_graph={"python": n + 1 + epoch},
        member_count=n,
    )


async def _append_n(table: FakeTable, identity: Identity, n: int, *, epoch: int = 0) -> list[dict[str, Any]]:
    return [
        await federation_feed.append_envelope(
            table, identity, _envelope(i, epoch=epoch), issued_at=f"2026-08-0{9 + epoch}T00:0{i}:00+00:00"
        )
        for i in range(n)
    ]


# ── plant discipline ───────────────────────────────────────────────────────


def _plant(description: str, landed: bool) -> None:
    assert landed, (
        f"PLANT DID NOT LAND: {description} — the assertion that follows would have "
        "passed for the wrong reason, which is indistinguishable from the guard working"
    )


# ---------------------------------------------------------------------------
# D1-D3 — the log is durable and gap-free, which is the whole of step 1
# ---------------------------------------------------------------------------


async def test_D1_the_sequence_continues_across_a_restart(table: FakeTable, identity: Identity) -> None:
    """THE THAT CHANGE TEST — and be precise about which restart this is.

    The old in-memory delta store reseeded from a wall clock on every restart;
    this log must not. What is demonstrated here is a STORE-level restart: every
    in-memory handle is dropped and the chain is rebuilt from the persisted rows,
    so the next append continues at the durable tip. That proves the rows and the
    chain outlive the process that wrote them.

    It does NOT prove a rebooting server re-derives its state from them — that is
    a PROCESS-level restart, asserted by conformance/federation/test_feed_restart.py,
    which currently skips on every deployment because its harness does not enter
    the app's lifespan. Do not read this test as covering that one.
    """
    await _append_n(table, identity, 3)
    before = [r["seq"] for r in table.rows]

    table.restart()
    fourth = await federation_feed.append_envelope(table, identity, _envelope(3), issued_at="2026-08-09T00:03:00+00:00")

    assert before == [0, 1, 2]
    assert fourth["seq"] == 3, "the sequence RESEEDED across the restart — this is exactly that change"
    assert fourth["prev_hash"] == table.rows[2]["entry_hash"], "the chain did not continue from the durable tip"


async def test_D2_the_chain_links_every_entry_to_its_predecessor(table: FakeTable, identity: Identity) -> None:
    entries = await _append_n(table, identity, 4)

    assert entries[0]["prev_hash"] is None, "genesis must not claim a predecessor"
    for earlier, later in zip(entries, entries[1:]):
        assert later["prev_hash"] == earlier["entry_hash"]
        assert later["seq"] == earlier["seq"] + 1


async def test_D3_an_unpersisted_append_raises_rather_than_forking_the_chain(identity: Identity) -> None:
    """pg_request returns a quiet None when no database is configured. Signing an
    entry that was never stored would let the next append reuse its seq and fork
    the chain — two different entries at one sequence number, both correctly
    signed, which is unrecoverable rather than merely wrong."""

    async def never_persists(method, table, params=None, body=None):
        return [] if method == "GET" else None

    with pytest.raises(RuntimeError, match="not persisted"):
        await federation_feed.append_envelope(never_persists, identity, _envelope(0), issued_at=_GENERATED_AT)


# ---------------------------------------------------------------------------
# C1-C3 — what a SUBSCRIBER can detect. The point of the whole unit.
# ---------------------------------------------------------------------------


async def test_C1_a_dropped_entry_is_detected(table: FakeTable, identity: Identity) -> None:
    await _append_n(table, identity, 4)
    page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)

    ok, reason, _, _ = sm_federation.read_intelligence(page)
    assert ok, f"the unmodified page must verify first, else the plant proves nothing: {reason}"

    tampered = copy.deepcopy(page)
    removed = tampered["entries"].pop(2)
    _plant("entry seq=2 removed from the page", len(tampered["entries"]) == 3 and removed["seq"] == 2)

    ok, reason, envelopes, _ = sm_federation.read_intelligence(tampered)

    assert not ok, "a subscriber accepted a page with an entry removed"
    assert "chain_break" in reason or "non_contiguous" in reason, reason
    assert envelopes == [], "a page that failed verification must yield no intelligence"

    # Confirm the revert: an unreverted plant would make every later assertion in
    # this module run against a mutilated page.
    ok_again, _, _, _ = sm_federation.read_intelligence(page)
    assert ok_again, "the original page did not survive the plant — the mutation was not isolated"


async def test_C2_a_reordered_entry_is_detected(table: FakeTable, identity: Identity) -> None:
    """Every entry is individually authentic and unmodified here — only their
    ORDER changed. A per-entry signature check passes; the chain is what fails."""
    await _append_n(table, identity, 4)
    page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)

    tampered = copy.deepcopy(page)
    tampered["entries"][1], tampered["entries"][2] = tampered["entries"][2], tampered["entries"][1]
    _plant(
        "entries at seq 1 and 2 swapped, both otherwise untouched",
        [e["seq"] for e in tampered["entries"]] == [0, 2, 1, 3],
    )
    for e in tampered["entries"]:
        ok, _ = __import__("sm_feed").verify_entry(e)
        assert ok, "the plant must leave every entry individually valid, or it proves the wrong thing"

    ok, reason, envelopes, _ = sm_federation.read_intelligence(tampered)

    assert not ok, "a subscriber accepted reordered entries"
    assert "chain_break" in reason, reason
    assert envelopes == []

    ok_again, _, _, _ = sm_federation.read_intelligence(page)
    assert ok_again, "the original page did not survive the plant"


async def test_C3_a_restarted_sequence_is_detected_and_never_a_bare_ok(
    table: FakeTable, identity: Identity
) -> None:
    """THE ONE THAT NEEDED A DATABASE, and the one 0.4.2 could not see.

    The publisher's store is wiped and it republishes from seq 0. Every entry is
    correctly signed. The chain is internally perfect. A from-genesis read
    verifies as a flawless FIRST sync — and every entry the subscriber held has
    ceased to exist.

    Two outcomes are acceptable and they are not the same thing: the page verifies
    against the head the subscriber pinned (nothing was replaced), or it is
    REFUSED BY NAME. A bare `ok` over a reseeded sequence is the silent reseed,
    and that is the whole failure this feature exists to prevent.
    """
    await _append_n(table, identity, 3)
    first_page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)
    ok, _, _, cursor = sm_federation.read_intelligence(first_page)
    assert ok and cursor is not None
    pinned_head = cursor["head"]

    # The plant: the publisher lost its durable log and started over with
    # different content. This is the in-memory store's behaviour, reproduced.
    table.rows.clear()
    await _append_n(table, identity, 2, epoch=1)
    _plant(
        "publisher's log wiped and republished from seq 0 with DIFFERENT content",
        [r["seq"] for r in table.rows] == [0, 1]
        and table.rows[0]["entry_hash"] != first_page["entries"][0]["entry_hash"],
    )

    reseeded = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)

    # Without the pinned head this is indistinguishable from a first sync — which
    # is precisely the defect 0.5.0 fixed, asserted here so the reason a
    # subscriber MUST pass expected_head is visible rather than folklore.
    naive_ok, naive_reason, naive_envelopes, _ = sm_federation.read_intelligence(reseeded)
    assert naive_ok, "a from-genesis read of a reseeded feed is internally valid — that is the trap"
    assert naive_reason == "ok", naive_reason
    assert len(naive_envelopes) == 2, "and it hands over intelligence, which is why the trap matters"

    ok, reason, envelopes, _ = sm_federation.read_intelligence(reseeded, expected_head=pinned_head)

    assert not ok, (
        "A SUBSCRIBER HOLDING A PINNED HEAD ACCEPTED A RESEEDED FEED. This is the silent "
        "reseed — a bare ok over a sequence that was replaced rather than extended."
    )
    assert reason == "head_rewind", reason
    assert envelopes == [], "a page that failed verification must yield no intelligence"


async def test_C3c_a_reseed_that_grew_PAST_the_pinned_head_is_still_caught(
    table: FakeTable, identity: Identity
) -> None:
    """The reseed that the head check alone does NOT catch, and why the chain and
    the head are both needed.

    If the publisher restarts and republishes MORE entries than the subscriber
    held, the new head is *ahead* of the pinned one — a head may advance, so rule
    6 is satisfied and `head_rewind` never fires. What catches it is the other
    half: the subscriber pulls `?since=<its cursor>` and the entry it gets back
    does not chain to the hash it holds. Neither check subsumes the other, and a
    test that only exercised the shorter-reseed case would leave this one
    unmeasured while looking complete.
    """
    await _append_n(table, identity, 3)
    first = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)
    _, _, _, cursor = sm_federation.read_intelligence(first)

    table.rows.clear()
    await _append_n(table, identity, 5, epoch=1)
    _plant(
        "log wiped and republished LONGER than the subscriber held (5 > 3)",
        [r["seq"] for r in table.rows] == [0, 1, 2, 3, 4]
        and table.rows[0]["entry_hash"] != first["entries"][0]["entry_hash"],
    )

    # Exactly what a real subscriber does next: ask for what is new after its cursor.
    nxt = await federation_feed.build_page(table, identity, since=cursor["seq"], generated_at=_GENERATED_AT)

    # Rule 6 cannot fire here, and that is the whole point of this case: a head
    # may advance, and this one did. Asserted on the wire rather than by calling
    # the check in isolation — an earlier version of this test called
    # read_intelligence with only expected_head and read its failure as "rule 6
    # is satisfied", which was wrong: that call fails on the CHAIN, because a
    # mid-feed page with no expected_prev_hash cannot chain to nothing. It would
    # have recorded the right verdict for the wrong reason.
    assert nxt["head"]["seq"] > cursor["head"]["seq"], "the reseeded head must be AHEAD, or this is the C3 case again"

    ok, reason, envelopes, _ = sm_federation.read_intelligence(
        nxt, expected_prev_hash=cursor["entry_hash"], expected_head=cursor["head"]
    )

    assert not ok, "a subscriber accepted a feed that had been replaced under it"
    assert "chain_break" in reason, reason
    assert envelopes == []


async def test_C3b_omitting_expected_head_is_reported_not_silently_weaker(
    table: FakeTable, identity: Identity
) -> None:
    """0.5.0's other half: continuing a subscription WITHOUT a pinned head still
    returns ok, but `reason` says the rewind class was undetectable rather than
    reporting a bare "ok" for a weaker check than the caller thinks they ran."""
    await _append_n(table, identity, 3)
    page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)
    _, _, _, cursor = sm_federation.read_intelligence(page)

    await _append_n(table, identity, 1)
    nxt = await federation_feed.build_page(table, identity, since=cursor["seq"], generated_at=_GENERATED_AT)

    ok, reason, _, _ = sm_federation.read_intelligence(nxt, expected_prev_hash=cursor["entry_hash"])

    assert ok
    assert reason == sm_federation.REWIND_UNDETECTABLE, reason


# ---------------------------------------------------------------------------
# W1-W3 — the wire: cursors, partial pages, and the identity link
# ---------------------------------------------------------------------------


async def test_W1_since_returns_only_what_is_new_and_still_verifies(table: FakeTable, identity: Identity) -> None:
    await _append_n(table, identity, 5)
    page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)
    _, _, first_envelopes, cursor = sm_federation.read_intelligence(page)
    assert len(first_envelopes) == 5

    await _append_n(table, identity, 1)
    delta = await federation_feed.build_page(table, identity, since=cursor["seq"], generated_at=_GENERATED_AT)

    ok, reason, envelopes, _ = sm_federation.read_intelligence(
        delta, expected_prev_hash=cursor["entry_hash"], expected_head=cursor["head"]
    )
    assert ok, reason
    assert len(envelopes) == 1, "?since must return only the new entries, not the whole log"
    assert [e["seq"] for e in delta["entries"]] == [5]


async def test_W2_a_capped_page_declares_itself_partial(table: FakeTable, identity: Identity, monkeypatch) -> None:
    """A bounded body is conformant ONLY if the head runs ahead and the page says
    so. Truncating a strict page would be indistinguishable from a dropped
    entry — the exact failure C1 asserts a subscriber must catch."""
    monkeypatch.setattr(federation_feed, "PAGE_LIMIT", 2)
    await _append_n(table, identity, 5)

    page = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)

    assert page["version"] == "feed-page/0.2", "a capped page must declare the partial version"
    assert len(page["entries"]) == 2
    assert page["head"]["seq"] == 4, "the head must remain the feed's CURRENT head, not the page's last entry"
    ok, reason, _, cursor = sm_federation.read_intelligence(page)
    assert ok, reason
    assert cursor["complete_to_head"] is False


async def test_W3_feed_id_is_the_did_key_of_the_org_signing_key(identity: Identity) -> None:
    """The feed must be attributable to the node a peer discovered. feed_id is the
    did:key of the SAME Ed25519 key /.well-known/did.json publishes as
    publicKeyMultibase, so the link is checkable rather than asserted."""
    import sovereign_identity

    kp = {"private_key": bytes(range(32)), "public_key": b""}
    built = federation_feed.feed_identity(kp)
    assert built is not None
    assert built.did == identity.did

    import base64

    import nacl.signing

    pub = base64.b64encode(bytes(nacl.signing.SigningKey(bytes(range(32))).verify_key)).decode()
    assert sovereign_identity.build_did_key_from_ed25519(pub) == built.did, (
        "the feed publishes a different did:key than did.json does — two identities for one key"
    )


async def test_W4_feed_identity_never_invents_a_key(identity: Identity) -> None:
    """The public-discovery rule on a third surface: no key means no feed, never a minted one."""
    assert federation_feed.feed_identity(None) is None
    assert federation_feed.feed_identity({}) is None
    assert federation_feed.feed_identity({"private_key": b"short"}) is None


# ---------------------------------------------------------------------------
# P1-P3 — the boot ensure's three cases, which are NOT the same
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_availability():
    yield
    federation_feed.reset_for_tests(False, "reset")


async def test_P1_successful_ensure_turns_the_feed_on() -> None:
    ran: list[str] = []

    async def ddl_ok(sql: str) -> None:
        ran.append(sql)

    assert await federation_feed.ensure_schema(ddl_ok, has_database=True) is True
    assert federation_feed.is_available() is True
    assert "federation_feed_entries" in ran[0], "the ensure must run the real migration DDL"


async def test_P2_permission_denied_degrades_loudly_and_does_NOT_raise(capsys) -> None:
    """THE CASE THAT MUST NOT RAISE. Plenty of self-hosted deployments run the app
    under a least-privilege role with no DDL rights. Turning a working install
    into a non-booting one to add an OPTIONAL federation surface is strictly worse
    than the surface being absent."""

    class InsufficientPrivilegeError(Exception):
        sqlstate = "42501"

    async def ddl_denied(sql: str) -> None:
        raise InsufficientPrivilegeError("permission denied for schema public")

    result = await federation_feed.ensure_schema(ddl_denied, has_database=True)

    assert result is False
    assert federation_feed.is_available() is False
    out = capsys.readouterr().out
    assert "PERMISSION DENIED" in out, "the degrade must be loud enough for an operator to see"
    assert "CREATE on schema public" in out, "it must name the grant an operator would need"


async def test_P3_any_other_ddl_failure_raises(capsys) -> None:
    """A real misconfiguration — unreachable database, syntax error, half-migrated
    schema — is loud, per execute_ddl's contract. Only the privilege case is
    special-cased, and only because it is a legitimate deployment posture."""

    async def ddl_broken(sql: str) -> None:
        raise RuntimeError("relation does not exist")

    with pytest.raises(RuntimeError, match="relation does not exist"):
        await federation_feed.ensure_schema(ddl_broken, has_database=True)
    assert federation_feed.is_available() is False


async def test_P4_no_database_is_section_2_only_not_an_error() -> None:
    async def ddl_never(sql: str) -> None:
        raise AssertionError("must not attempt DDL without a database")

    assert await federation_feed.ensure_schema(ddl_never, has_database=False) is False
    assert federation_feed.is_available() is False


async def test_P5_feed_url_is_gated_on_the_TABLE_not_on_DATABASE_URL() -> None:
    """The distinction the whole degrade policy rests on: an org whose role could
    not create the table HAS a database and still cannot honour completeness."""
    federation_feed.reset_for_tests(False, "role lacks CREATE")
    assert federation_feed.feed_url(_PUBLIC_URL) == ""

    federation_feed.reset_for_tests(True, "")
    assert federation_feed.feed_url(_PUBLIC_URL) == f"{_PUBLIC_URL}{federation_feed.FEED_PATH}"
    assert federation_feed.feed_url("") == "", "no public URL means no resolvable feed"


# ---------------------------------------------------------------------------
# The envelope and the served surface
# ---------------------------------------------------------------------------


def test_E1_the_envelope_is_a_valid_federation_intel_document() -> None:
    """Orrery's summary is chapter-shaped; §3 is community-shaped. The rename is
    the substance, and fields with no slot are DROPPED rather than smuggled — the
    schema is closed, so an extra key would fail validation, correctly."""
    summary = {
        "chapter_id": "feed-org",
        "chapter_name": "Feed Org",
        "skill_graph": {"python": 5, "rust": 2},
        "skill_gaps": ["ml"],
        "trending_topics": ["agents"],
        "recommendations": ["talk to bayarea"],
        "patterns": ["dropped: no slot in §3"],
        "member_count": 12,
        "active_member_count": 7,
        "last_reflected": "2026-08-09T00:00:00Z",
        "policy_snapshot": [{"dropped": True}],
    }

    env = federation_feed.envelope_from_summary(summary, generated_at=_GENERATED_AT)

    ok, reason = sm_federation.validate_envelope(env)
    assert ok, reason
    assert env["community_id"] == "feed-org" and env["community_name"] == "Feed Org"
    assert env["active_member_count"] == 7, "0.3.0 added this slot after measuring a real emitter"
    for dropped in ("patterns", "last_reflected", "policy_snapshot", "chapter_id"):
        assert dropped not in env


class _App:
    """A running app with the feed available and a key, built once per test."""

    def __init__(self, monkeypatch, available: bool = True):
        monkeypatch.setenv("AGENT_ID", "TEST-feed-org")
        monkeypatch.setenv("AGENT_NAME", "Feed Org")
        sys.modules.pop("chapter_agent", None)
        self.mod = importlib.import_module("chapter_agent")
        monkeypatch.setattr(self.mod, "PUBLIC_URL", _PUBLIC_URL)
        federation_feed.reset_for_tests(available, "" if available else "test")
        self.client = TestClient(self.mod.app)


def test_S1_the_feed_path_is_open_and_declared_open() -> None:
    import auth_verify

    assert federation_feed.FEED_PATH in auth_verify.OPEN_PATHS
    assert auth_verify.is_open_path("GET", federation_feed.FEED_PATH) is True
    assert auth_verify.requires_auth("GET", federation_feed.FEED_PATH) is False


def test_S2_an_unavailable_feed_answers_501_and_says_which_reason(monkeypatch) -> None:
    """Not 404: the surface exists in this runtime, this deployment cannot serve
    it, and a peer should only get here by ignoring a descriptor that already
    said so."""
    app = _App(monkeypatch, available=False)

    resp = app.client.get(federation_feed.FEED_PATH)

    assert resp.status_code == 501
    assert resp.json()["error"] == "federation_feed_unavailable"
    assert "§2-only" in resp.json()["hint"]


def test_S3_descriptor_and_feed_agree_in_both_directions(monkeypatch) -> None:
    """The cross-field rule, checked on the wire rather than trusted to the
    builder: feed_url present ⇔ federation/0.1#4 claimed. sm-federation 0.4.0
    enforces it in the JSON Schema; this asserts Orrery lands on the right side of
    it in BOTH deployment states."""
    app = _App(monkeypatch, available=False)
    off = app.client.get("/.well-known/agent-community.json").json()
    assert "feed_url" not in off
    assert sm_federation.section_token("4") not in off.get("capabilities", [])
    assert sm_federation.section_token("2") in off["capabilities"], "§2 is always true of a node serving this"
    ok, reason = sm_federation.validate_descriptor(off)
    assert ok, reason

    federation_feed.reset_for_tests(True, "")
    on = app.client.get("/.well-known/agent-community.json").json()
    assert on["feed_url"] == f"{_PUBLIC_URL}{federation_feed.FEED_PATH}"
    assert sm_federation.section_token("4") in on["capabilities"], "#4 must be DERIVED once feed_url is set"
    ok, reason = sm_federation.validate_descriptor(on)
    assert ok, reason


def test_S4_feed_url_is_never_the_unsigned_snapshot(monkeypatch) -> None:
    """THE INVERSION OF test_H1. Its original purpose was to stop exactly the
    shortcut that exists now that a feed is expected: pointing feed_url at an
    existing unsigned surface satisfies the schema and breaks §4's guarantee.
    /api/knowledge/summary is a full, unsigned, cursorless snapshot — the v0.1
    model §4 replaced — and it must never become the feed."""
    app = _App(monkeypatch, available=True)

    doc = app.client.get("/.well-known/agent-community.json").json()

    assert doc["feed_url"].endswith(federation_feed.FEED_PATH)
    assert "/api/knowledge/summary" not in doc["feed_url"]
    assert app.client.get("/api/knowledge/summary").status_code != 404, (
        "the unsigned snapshot still exists for Orrery's own peers — it is simply not the feed"
    )


def test_M1_init_sql_and_the_migration_declare_the_same_table() -> None:
    """infra/init.sql (fresh installs) and infra/migrations/0005 (existing ones)
    are two copies of one table, and the migrations README requires both to
    change together. Nothing compared them, so this does.

    Compared on the column set and the indexes rather than byte-for-byte: the two
    files legitimately differ in commentary and the migration carries the long
    rationale. What must not differ is what an install ends up with — otherwise
    fresh and existing installs disagree about their own schema, which is the
    defect the README exists to prevent.
    """
    repo = Path(__file__).resolve().parents[2]
    init_sql = (repo / "infra" / "init.sql").read_text(encoding="utf-8")
    migration = (repo / "infra" / "migrations" / "0005_federation_feed.sql").read_text(encoding="utf-8")

    def columns(sql: str) -> set[str]:
        body = sql.split("CREATE TABLE IF NOT EXISTS public.federation_feed_entries")[1].split(");")[0]
        out = set()
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("--") or line.startswith("PRIMARY KEY") or line.startswith("("):
                continue
            out.add(line.split()[0].strip(","))
        return out

    assert columns(init_sql) == columns(migration), "init.sql and 0005 declare different columns"
    for index in ("federation_feed_entries_hash_uq", "federation_feed_entries_seq_idx"):
        assert index in init_sql and index in migration, f"{index} is missing from one of the two files"
    assert "CREATE TABLE IF NOT EXISTS" in migration, "the migration must be idempotent — it is re-run at boot"


def test_M2_the_boot_ensure_runs_the_migration_file_itself() -> None:
    """Not a third copy of the DDL. The ensure reads the file that ships to
    operators, so "what boot creates" and "what the migration creates" cannot
    drift into two answers."""
    migration = (Path(__file__).resolve().parents[2] / "infra" / "migrations" / "0005_federation_feed.sql").read_text(
        encoding="utf-8"
    )

    assert federation_feed.ddl() == migration


def test_M3_the_server_image_ships_the_migration_the_boot_ensure_reads() -> None:
    """The boot ensure reads infra/migrations/0005 from the filesystem, so that
    directory must be IN the image or the ensure cannot run.

    It was not. The first CI run of this feature failed the server container's
    healthcheck for exactly this reason — an optional feature bricking a boot,
    the third door into the failure the degrade policy exists to close. The
    Dockerfile now copies it and this asserts that, rather than leaving the next
    module that reads a repo file at boot to rediscover it in CI.
    """
    dockerfile = (Path(__file__).resolve().parents[2] / "infra" / "Dockerfile.server").read_text(encoding="utf-8")

    assert "COPY infra/migrations/" in dockerfile, (
        "the server image does not ship infra/migrations/, so the boot ensure cannot read its own DDL"
    )


async def test_M4_an_unreadable_ddl_degrades_rather_than_bricking_the_boot(monkeypatch, capsys) -> None:
    """Belt and braces for M3. Even with the image fixed, a packaging fault must
    not be able to stop a server booting — it is not a fault in the operator's
    database and there is nothing they could do about it."""
    monkeypatch.setattr(federation_feed, "_DDL_PATH", Path("/nonexistent/0005.sql"))

    async def ddl_never(sql: str) -> None:
        raise AssertionError("must not attempt DDL it could not read")

    assert await federation_feed.ensure_schema(ddl_never, has_database=True) is False
    assert federation_feed.is_available() is False
    assert "packaging fault" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# PR1-PR4 — the PRODUCER. Without it the endpoint is an empty page forever.
# ---------------------------------------------------------------------------


async def test_PR1_a_node_with_no_producer_serves_a_feed_nobody_can_subscribe_to(
    table: FakeTable, identity: Identity
) -> None:
    """The defect the feed-restart conformance work's suite caught in this PR, kept as a regression.

    An empty feed has no entries and no head, so `read_intelligence` returns a
    None cursor — a subscriber cannot even obtain a starting point, let alone
    detect anything. Building the endpoint and the log without wiring anything
    that APPENDS produces a §4 surface that is conformant in shape and useless in
    fact, and every test that only exercised append-then-read would have passed.
    """
    empty = await federation_feed.build_page(table, identity, since=None, generated_at=_GENERATED_AT)

    ok, _, _, cursor = sm_federation.read_intelligence(empty)
    assert ok, "an empty feed is still a valid feed"
    assert cursor is None, "and it yields no cursor — which is why a producer is not optional"


async def test_PR2_publish_appends_the_current_intelligence(table: FakeTable) -> None:
    kp = {"private_key": bytes(range(32)), "public_key": b""}
    federation_feed.reset_for_tests(True, "")

    entry = await federation_feed.publish_if_changed(
        table, kp, {"chapter_id": "org", "chapter_name": "Org", "skill_graph": {"python": 3}},
        generated_at=_GENERATED_AT,
    )

    assert entry is not None and entry["seq"] == 0
    ok, reason = sm_federation.validate_envelope(entry["payload"])
    assert ok, reason


async def test_PR3_an_unchanged_snapshot_appends_nothing(table: FakeTable) -> None:
    """Content-deduped, and `generated_at` is excluded from the comparison.

    Otherwise every reflection cycle and every restart would append an identical
    snapshot under a new timestamp, and a subscriber would re-verify a chain of
    duplicates to learn nothing — burying the entries that do matter under the
    ones that do not.
    """
    kp = {"private_key": bytes(range(32)), "public_key": b""}
    federation_feed.reset_for_tests(True, "")
    summary = {"chapter_id": "org", "chapter_name": "Org", "skill_graph": {"python": 3}}

    first = await federation_feed.publish_if_changed(table, kp, summary, generated_at="2026-08-09T00:00:00+00:00")
    again = await federation_feed.publish_if_changed(table, kp, summary, generated_at="2026-08-09T06:00:00+00:00")
    changed = await federation_feed.publish_if_changed(
        table, kp, {**summary, "skill_graph": {"python": 4}}, generated_at="2026-08-09T12:00:00+00:00"
    )

    assert first is not None
    assert again is None, "an unchanged snapshot at a later timestamp must not append"
    assert changed is not None and changed["seq"] == 1
    assert len(table.rows) == 2


async def test_PR4_publish_is_a_no_op_without_a_feed_or_a_key(table: FakeTable, capsys) -> None:
    """DECLINED, not RESCUED — and the difference is the whole assertion.

    `publish_if_changed` ends in a broad `except Exception` so that publishing can
    never fail a boot or a reflection cycle. That net also MASKS the guards in
    front of it: remove the "no key" check and execution runs on to
    `identity.did`, raises AttributeError, and the handler converts it into the
    same `return None` the guard would have produced. Identical return, identical
    empty table — the guard's removal is invisible.

    So each case asserts it was declined by its own guard, evidenced by the
    absence of the handler's "publish skipped" line. Found by
    test_federation_feed_guards.py's G4, which reported this guard as deletable
    with the whole suite still green.
    """
    kp = {"private_key": bytes(range(32)), "public_key": b""}
    summary = {"chapter_id": "org", "chapter_name": "Org"}

    federation_feed.reset_for_tests(False, "degraded")
    assert await federation_feed.publish_if_changed(table, kp, summary, generated_at=_GENERATED_AT) is None
    assert "publish skipped" not in capsys.readouterr().out, (
        "the no-feed case was rescued by the catch-all instead of declined by its guard"
    )

    federation_feed.reset_for_tests(True, "")
    assert await federation_feed.publish_if_changed(table, None, summary, generated_at=_GENERATED_AT) is None
    assert "publish skipped" not in capsys.readouterr().out, (
        "the no-key case was rescued by the catch-all instead of declined by its guard"
    )
    assert table.rows == [], "neither case may write to the log"


async def test_PR5_a_failing_publish_never_propagates(table: FakeTable, capsys) -> None:
    """THE THIRD BRICKED BOOT, kept as a regression.

    An earlier version promised in its docstring that publishing never raises
    into its caller, and did not keep it: called at boot before
    `federation_intelligence.init()` had run, it built an envelope with an empty
    `community_id`, `validate_envelope` rejected it, and the ValueError took the
    server down. One call site had a try/except and the other did not — which is
    why the guarantee now lives in the function.
    """
    kp = {"private_key": bytes(range(32)), "public_key": b""}
    federation_feed.reset_for_tests(True, "")

    # Exactly the boot-order bug: an uninitialised intelligence module yields an
    # empty community_id, which the published validator correctly rejects.
    result = await federation_feed.publish_if_changed(
        table, kp, {"chapter_id": "", "chapter_name": ""}, generated_at=_GENERATED_AT
    )

    assert result is None, "an invalid envelope must be skipped, not raised"
    assert table.rows == [], "and nothing may enter the chain"
    assert "publish skipped" in capsys.readouterr().out


async def test_PR6_a_store_failure_is_skipped_not_raised(capsys) -> None:
    federation_feed.reset_for_tests(True, "")

    async def broken(method, table, params=None, body=None):
        raise RuntimeError("database went away")

    result = await federation_feed.publish_if_changed(
        broken, {"private_key": bytes(range(32)), "public_key": b""},
        {"chapter_id": "org", "chapter_name": "Org"}, generated_at=_GENERATED_AT,
    )

    assert result is None
    assert "publish skipped" in capsys.readouterr().out


async def test_P6_an_unreachable_database_defers_rather_than_failing(capsys) -> None:
    """The policy case that had NO TEST until the presence layer found it.

    A database that is configured but unreachable is case 1's absence, not case
    3's failure: without this branch a database that is merely down turns a server
    which currently boots (degraded — pg_request returns a quiet None) into one
    that does not boot at all. It was implemented, reported, and reviewed, and the
    only thing exercising it was the conformance suite booting without a database
    — which asserts nothing about it. G2 in test_federation_feed_guards.py caught
    the guard as present-but-unreached on its first run.
    """

    async def unreachable() -> bool:
        return False

    async def ddl_never(sql: str) -> None:
        raise AssertionError("no DDL may be attempted against an unreachable database")

    result = await federation_feed.ensure_schema(ddl_never, has_database=True, db_reachable=unreachable)

    assert result is False
    assert federation_feed.is_available() is False
    out = capsys.readouterr().out
    assert "unreachable" in out
    assert "deferring" in out, "the operator must be told this is deferred, not broken"


def test_P7_a_tip_with_no_usable_payload_counts_as_changed() -> None:
    """If the chain tip carries something that is not an envelope, there is
    nothing to compare against — so publish rather than silently skip. Suppressing
    an append on an uninterpretable tip would let one bad row freeze the feed."""
    envelope = sm_federation.build_intelligence_envelope(
        community_id="org", community_name="Org", generated_at=_GENERATED_AT
    )

    assert federation_feed._payload_differs(None, envelope) is True, "an empty feed always differs"
    assert federation_feed._payload_differs({"payload": None}, envelope) is True
    assert federation_feed._payload_differs({"payload": "not-an-object"}, envelope) is True
    assert federation_feed._payload_differs({"payload": dict(envelope)}, envelope) is False


def test_P8_permission_denied_is_recognised_by_SQLSTATE_not_only_by_message() -> None:
    """The primary discriminator, exercised on its own.

    asyncpg carries `sqlstate == '42501'`; the string fallback exists only because
    this module must not assume a driver. Every earlier test raised an exception
    whose MESSAGE also said "permission denied", so the fallback covered for the
    SQLSTATE branch and it was never independently exercised — G4 reported it as
    deletable with the suite still green. A driver that reports the code without
    that wording would have fallen through to `raise` and bricked a boot.
    """

    class DriverError(Exception):
        sqlstate = "42501"

    assert federation_feed._is_permission_denied(DriverError("relation cannot be created here")) is True
    assert federation_feed._is_permission_denied(RuntimeError("permission denied for schema public")) is True
    assert federation_feed._is_permission_denied(RuntimeError("syntax error at or near")) is False


async def test_P2b_a_refused_ddl_with_the_table_already_present_keeps_section_4(capsys) -> None:
    """Postgres refuses CREATE TABLE IF NOT EXISTS for want of CREATE on the
    schema EVEN WHEN THE TABLE EXISTS, so a least-privilege role is refused on
    every boot whether or not the ensure had anything to do. Degrading on that
    alone would disable a working surface over a statement whose only possible
    effect had already been achieved."""

    class InsufficientPrivilegeError(Exception):
        sqlstate = "42501"

    async def ddl_denied(sql: str) -> None:
        raise InsufficientPrivilegeError("permission denied for schema public")

    async def log_is_readable() -> bool:
        return True

    result = await federation_feed.ensure_schema(
        ddl_denied, has_database=True, feed_readable=log_is_readable
    )

    assert result is True
    assert federation_feed.is_available() is True
    out = capsys.readouterr().out
    assert "already present and readable" in out
    assert "PERMISSION DENIED" not in out, "a surface that works must not report a degrade"


async def test_P2c_a_refused_ddl_with_the_table_absent_still_degrades(capsys) -> None:
    """The presence check must not turn the degrade into a no-op: an absent log
    is still §2-only, and the message still names what an operator would do."""

    class InsufficientPrivilegeError(Exception):
        sqlstate = "42501"

    async def ddl_denied(sql: str) -> None:
        raise InsufficientPrivilegeError("permission denied for schema public")

    async def log_is_absent() -> bool:
        return False

    result = await federation_feed.ensure_schema(
        ddl_denied, has_database=True, feed_readable=log_is_absent
    )

    assert result is False
    assert federation_feed.is_available() is False
    out = capsys.readouterr().out
    assert "PERMISSION DENIED" in out
    assert "0005_federation_feed.sql" in out
