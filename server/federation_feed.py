"""sm-federation §4 — the signed, completeness-verifiable intelligence feed.

Orrery served the §2 node descriptor and nothing else of the profile, so a
peer could discover this org and **subscribe to nothing**. This is the other half:
each intelligence envelope is appended to a signed, hash-chained ``sm-feed``, and a
peer pulls ``?since=<cursor>`` and verifies what it gets rather than trusting it.

**THE GUARANTEE IS THE POINT, NOT THE ENDPOINT.** A feed that returns signed pages
but cannot prove a subscriber saw every entry is the unsigned snapshot with extra
steps — which is precisely what Orrery does today at ``GET /api/knowledge/summary``:
a full, unsigned, cursorless snapshot, the v0.1 model §4 replaced. Three failures
must be detectable by the subscriber, and all three are asserted in
``tests/test_federation_feed.py`` by planting them:

  * a **dropped** entry      → ``chain_break`` / ``non_contiguous_seq``
  * a **reordered** entry    → ``chain_break``
  * a **restarted sequence** → ``head_rewind``

The third is the one this module exists for, and it is the only one that is a
property of the *store* rather than of the wire format. A restarted feed is signed
correctly and chains correctly from its own new genesis: it verifies as a flawless
FIRST sync while every entry the subscriber held has silently ceased to exist.
Only a head the subscriber already accepted can tell "extended" from "replaced" —
so the log has to be durable, and that is why this module owns a table.

⚠️ NOT THE SAME LOG AS sm-bridge's DELTA STORE. ``sm_bridge_adapter`` keeps an
in-memory member-delta store reseeded from a wall-clock base on every
restart, and ``server/constraints.txt`` refuses sm-bridge's ``[feed]`` extra for
exactly that reason. That refusal is still correct and is unrelated to this file:
different payload (member deltas vs intelligence envelopes), different store,
different contract (monotonic vs gapless). This org now runs **two** logs — one
durable and chained, one deliberately gapped and which must NOT be chained.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import sm_federation
from sm_feed import FeedLog, Identity

#: Path the descriptor advertises as ``feed_url``. Proposed by the conformance
#: suite (``conformance/federation/claims.json``) before either half was built, so
#: the two meet without a second negotiation.
FEED_PATH = "/api/federation/intelligence/feed"

#: Entries per page. A page whose head runs ahead of its last entry is a
#: conformant partial page (``feed-page/0.2``); the subscriber sees the head is
#: further on and comes back. This is the sanctioned way to cap a body — not
#: truncation, which would look like a dropped entry.
PAGE_LIMIT = 200

_DDL_PATH = Path(__file__).resolve().parents[1] / "infra" / "migrations" / "0005_federation_feed.sql"

# Set once, at boot, by ensure_schema(). The descriptor gates `feed_url` on THIS,
# not on DATABASE_URL: an org whose role cannot create the table has a database
# and still cannot honour completeness, and advertising §4 there would be a claim
# the node cannot keep.
_available = False
_unavailable_reason = "boot ensure has not run"


def is_available() -> bool:
    """Whether this node can honour §4 — i.e. the durable log actually exists."""
    return _available


def unavailable_reason() -> str:
    return _unavailable_reason


def _set_state(available: bool, reason: str) -> None:
    global _available, _unavailable_reason
    _available, _unavailable_reason = available, reason


def ddl() -> str:
    """The table DDL, read from the migration file that ships to operators.

    One source, deliberately. If this module carried its own copy of the CREATE
    TABLE, a fresh install (init.sql), an existing install (the migration) and a
    boot ensure would be three statements that nothing compares — and they would
    drift the first time a column was added.
    """
    return _DDL_PATH.read_text(encoding="utf-8")


# ── Boot ensure — three cases, and they are not the same ────────────────────


async def ensure_schema(
    execute_ddl: Callable[[str], Any],
    *,
    has_database: bool,
    db_reachable: Callable[[], Any] | None = None,
    feed_readable: Callable[[], Any] | None = None,
) -> bool:
    """Create the feed table if absent. Returns whether §4 is available.

    **The failure policy differs from ``pg_store.execute_ddl``'s stated contract,
    on purpose.** That contract — a failed ensure must RAISE so a missing table is
    never silent — is right for a table the runtime REQUIRES. This one is
    optional: without it the node is honestly §2-only, and the descriptor says so
    by construction because ``build_node_descriptor`` derives the §4 token from
    ``feed_url``. Orrery is self-hosted by strangers, and deployments that run the
    app under a least-privilege role with no DDL rights are normal. **Turning
    someone's working install into a non-booting one in order to add an optional
    federation surface is strictly worse than the surface being absent.**

    So:

    1. **created (or already present)** → §4 on.
    2. **refused for want of privilege** (SQLSTATE 42501 / "permission denied")
       → check whether the table is already there before concluding anything.
       Postgres refuses ``CREATE TABLE IF NOT EXISTS`` for want of CREATE on the
       schema **even when the table exists**, so a role with no DDL rights is
       refused on every boot whether or not the ensure had anything to do. If
       ``feed_readable`` reports the log present, §4 is on and the refusal was
       immaterial. Only if it is absent does the node DEGRADE to §2-only, loudly,
       naming the grant an operator would need. Not an error: it is a legitimate
       deployment posture.
    3. **any other DDL failure** → RAISE. A syntax error or a half-migrated
       schema is a real misconfiguration and ``execute_ddl``'s reasoning applies
       unchanged.

    ⚠️ **A database that is CONFIGURED BUT UNREACHABLE is case 1's absence, not
    case 3's failure**, and it is checked before any DDL is attempted. Without
    that, `DATABASE_URL` pointing at a database that is down would turn a server
    which currently boots (degraded — `pg_request` returns a quiet None) into one
    that does not boot at all: the same brick, arriving through a different door
    than the privilege refusal. This is not an improvisation on the ruling —
    ``pg_store.db_reachable``'s own docstring already specifies it: *"Used by the
    boot schema-ensure so an unreachable DB defers the ensure rather than
    crashing startup, while a reachable-but-failing DDL still raises."* Like
    ``execute_ddl`` itself, it had no callers until now.
    """
    if not has_database:
        _set_state(False, "no DATABASE_URL — a feed with no durable store cannot honour completeness")
        print(
            "[federation-feed] no DATABASE_URL: this node is sm-federation §2-only "
            "(descriptor). §4 needs a durable log; feed_url will be absent and the "
            "descriptor will not claim federation/0.1#4."
        )
        return False

    if db_reachable is not None and not await db_reachable():
        _set_state(False, "DATABASE_URL is set but the database is unreachable — the ensure is deferred, not failed")
        print(
            "[federation-feed] database configured but unreachable: deferring the schema ensure and "
            "running sm-federation §2-only for this boot. feed_url will be absent. The rest of the "
            "server already degrades under an unreachable database; refusing to start over an OPTIONAL "
            "federation surface would be strictly worse. Restart once the database is reachable.",
            flush=True,
        )
        return False

    try:
        statement = ddl()
    except OSError as exc:
        # The DDL file is not readable — a PACKAGING failure, not a failure of the
        # operator's database, so it must not stop the server booting either.
        # This is not hypothetical: infra/ was absent from the server image, so
        # the first CI run of this feature failed the container healthcheck. The
        # image now ships infra/migrations/ and a test asserts it, but the policy
        # belongs here too — a third door into "an optional feature bricked the
        # boot" is exactly what the other two branches exist to close.
        _set_state(False, f"feed DDL unreadable ({exc}) — the runtime is packaged without it")
        print(
            f"[federation-feed] cannot read {_DDL_PATH}: {exc}. Running sm-federation §2-only. "
            "This is a packaging fault in this build, not a problem with your database — the "
            "image must ship infra/migrations/. NOT raising: an optional federation surface "
            "must never stop a working install from booting.",
            flush=True,
        )
        return False

    try:
        await execute_ddl(statement)
    except Exception as exc:  # noqa: BLE001 — re-raised below unless it is case 2
        if not _is_permission_denied(exc):
            raise
        if feed_readable is not None and await feed_readable():
            # The role cannot run DDL and did not need to: the log is present and
            # readable, which is the capability §4 actually requires. Reporting
            # this as a degrade would disable a working surface over a statement
            # whose only possible effect was already achieved.
            _set_state(True, "")
            print(
                "[federation-feed] DDL refused for want of privilege, and not needed: "
                "public.federation_feed_entries is already present and readable. "
                f"sm-federation §4 available at {FEED_PATH}.",
                flush=True,
            )
            return True
        _set_state(False, f"insufficient privilege to create the feed table: {exc}")
        print(
            "[federation-feed] PERMISSION DENIED creating public.federation_feed_entries. "
            "This node is DEGRADING to sm-federation §2-only (node descriptor); it is "
            "still fully operational and its descriptor is honest — feed_url is absent, "
            "so it does not claim federation/0.1#4. The table is absent too: this node "
            "checked before degrading. To enable §4, either apply "
            "infra/migrations/0005_federation_feed.sql as a privileged user, or grant "
            "the app's role CREATE on schema public — the first is enough, since the "
            "role needs no DDL once the table exists. Restart either way. NOT raising: "
            "an optional federation surface must never stop a working install from "
            "booting.",
            flush=True,
        )
        return False

    _set_state(True, "")
    print(f"[federation-feed] durable log ready — sm-federation §4 available at {FEED_PATH}")
    return True


def _is_permission_denied(exc: BaseException) -> bool:
    """Case 2 vs case 3, decided on the driver's SQLSTATE where there is one.

    asyncpg raises ``InsufficientPrivilegeError`` carrying ``sqlstate == '42501'``.
    The string fallback exists because this module must not assume a driver: the
    consequence of getting this wrong is either a bricked boot (case 3 misread as
    2 is safe; 2 misread as 3 is not) so it errs toward degrading.
    """
    if getattr(exc, "sqlstate", None) == "42501":
        return True
    return "permission denied" in str(exc).lower() or "insufficientprivilege" in type(exc).__name__.lower()


# ── Identity ────────────────────────────────────────────────────────────────


def feed_identity(keypair: dict[str, Any] | None) -> Identity | None:
    """An sm-feed identity over the org's EXISTING Ed25519 key — never a new one.

    ``feed_id`` is therefore the did:key of the same key ``/.well-known/did.json``
    publishes as ``publicKeyMultibase``, so a peer that resolved our DID can check
    that the feed it is reading belongs to the node it discovered. Two identities
    would make that link unverifiable — the drift class that change's ``did`` field
    already had to close once.

    Returns None when the org has no key: signing is impossible and inventing a
    key on a read path is the public-discovery rule.
    """
    if not keypair:
        return None
    seed = keypair.get("private_key")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        return None
    return Identity.from_seed(bytes(seed))


# ── The durable log ─────────────────────────────────────────────────────────
#
# sm_feed.FeedLog is a pure function over an entry list and says so: "Persistence
# is a consumer concern, deliberately not baked in: back the entry list with your
# own store (a table keyed by seq)." These helpers are that store. Nothing here
# re-implements chaining or signing — the entries go in and come out whole,
# because the signature covers the entry as a document and rebuilding one from
# columns would mean the bytes we stored and the bytes a peer verifies are two
# different things.


async def _rows(pg_request: Callable[..., Any], **params: Any) -> list[dict[str, Any]]:
    rows = await pg_request("GET", "federation_feed_entries", params)
    return list(rows or []) if isinstance(rows, list) else []


def _entry_of(row: dict[str, Any]) -> dict[str, Any]:
    entry = row.get("entry")
    return json.loads(entry) if isinstance(entry, str) else dict(entry or {})


async def head_entry(pg_request: Callable[..., Any], feed_id: str) -> dict[str, Any] | None:
    """The current last entry, or None for an empty feed."""
    rows = await _rows(pg_request, feed_id=f"eq.{feed_id}", order="seq.desc", limit=1)
    return _entry_of(rows[0]) if rows else None


async def append_envelope(
    pg_request: Callable[..., Any], identity: Identity, envelope: dict[str, Any], *, issued_at: str
) -> dict[str, Any]:
    """Append one §3 envelope as a signed entry, chained to the durable head.

    The chain tip is read from the TABLE, not from memory — that read is the whole
    reason this survives a restart. ``publish_intelligence`` validates the envelope
    before it enters the chain, so a malformed payload is never signed into a log
    that cannot be edited afterwards.
    """
    tip = await head_entry(pg_request, identity.did)
    log = FeedLog(identity, [tip] if tip else [])
    entry = sm_federation.publish_intelligence(log, envelope, issued_at=issued_at)

    written = await pg_request(
        "POST",
        "federation_feed_entries",
        None,
        {
            "seq": entry["seq"],
            "feed_id": entry["feed_id"],
            "prev_hash": entry["prev_hash"],
            "entry_hash": entry["entry_hash"],
            "issued_at": entry["issued_at"],
            "entry": json.dumps(entry),
        },
    )
    if written is None:
        # pg_request returns a quiet None when no database is configured, and
        # raises DatabaseError when a configured one fails. A None here
        # means we signed an entry that was never stored — the next append would
        # reuse its seq and fork the chain. Loud, because the alternative is a
        # feed that silently disagrees with itself.
        raise RuntimeError("federation feed append was not persisted — refusing to advance an unstored chain")
    return entry


async def build_page(
    pg_request: Callable[..., Any], identity: Identity, *, since: int | None, generated_at: str
) -> dict[str, Any]:
    """A ``feed-page`` for a subscriber whose cursor is ``since``.

    Loads the entries after the cursor plus the true head, and lets ``FeedLog``
    decide the page version: a page whose head runs ahead of its last entry is
    ``feed-page/0.2`` and tells the subscriber to come back. Truncating without
    that would be indistinguishable from a dropped entry — the failure this
    endpoint exists to make detectable.
    """
    params: dict[str, Any] = {"feed_id": f"eq.{identity.did}", "order": "seq.asc", "limit": PAGE_LIMIT}
    if since is not None:
        params["seq"] = f"gt.{since}"
    entries = [_entry_of(r) for r in await _rows(pg_request, **params)]

    tip = await head_entry(pg_request, identity.did)
    if tip is not None and (not entries or entries[-1]["seq"] != tip["seq"]):
        # FeedLog reads its head off the last element, so the true tip has to be
        # in the list. `limit` then truncates the page back to PAGE_LIMIT and the
        # head correctly runs ahead of it.
        entries.append(tip)

    return FeedLog(identity, entries).page(since, generated_at=generated_at, limit=PAGE_LIMIT)


# ── §3 envelope, from the signals Orrery already computes ───────────────────


def envelope_from_summary(summary: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    """Map ``federation_intelligence.get_our_summary()`` onto a §3 envelope.

    Built with the PUBLISHED builder, so the wire shape has one definition. The
    rename is the substance of the mapping and is not cosmetic: Orrery's document
    is chapter-shaped (``chapter_id``/``chapter_name``, no ``type``, no
    ``version``, no ``generated_at``) and a federation envelope is
    community-shaped. Fields Orrery computes that the envelope has no slot for
    (``patterns``, ``last_reflected``, ``policy_snapshot``) are DROPPED rather
    than smuggled: §3 is aggregate-only and the schema is closed, so an extra key
    would fail validation — correctly.
    """
    return sm_federation.build_intelligence_envelope(
        community_id=str(summary.get("chapter_id") or ""),
        community_name=str(summary.get("chapter_name") or ""),
        generated_at=generated_at,
        skill_graph={k: int(v) for k, v in (summary.get("skill_graph") or {}).items() if isinstance(v, int)},
        skill_gaps=[s for s in (summary.get("skill_gaps") or []) if isinstance(s, str)],
        trending_topics=[s for s in (summary.get("trending_topics") or []) if isinstance(s, str)],
        recommendations=[s for s in (summary.get("recommendations") or []) if isinstance(s, str)],
        member_count=int(summary.get("member_count") or 0),
        active_member_count=int(summary.get("active_member_count") or 0),
    )


def _payload_differs(tip: dict[str, Any] | None, envelope: dict[str, Any]) -> bool:
    """Whether this envelope says anything new.

    ``generated_at`` is excluded: it changes on every build, so comparing it
    would append an identical snapshot on every reflection cycle and every
    restart. An append-only log that grows without new information makes a
    subscriber re-verify a chain of duplicates to learn nothing, and buries the
    entries that do matter.
    """
    if tip is None:
        return True
    prior = tip.get("payload")
    if not isinstance(prior, dict):
        return True
    drop = lambda d: {k: v for k, v in d.items() if k != "generated_at"}  # noqa: E731
    return drop(prior) != drop(envelope)


async def publish_if_changed(
    pg_request: Callable[..., Any],
    keypair: dict[str, Any] | None,
    summary: dict[str, Any],
    *,
    generated_at: str,
) -> dict[str, Any] | None:
    """Append the current intelligence to the feed, if it says anything new.

    THE PRODUCER. Without it the endpoint serves an empty page forever and a peer
    subscribes to nothing — which is the state this feature was built to end, and
    which the conformance suite caught: a feed with no entries yields no cursor,
    so a subscriber cannot even begin.

    Returns the appended entry, or None when there was nothing to say, no key, or
    no durable log.

    ⚠️ **NEVER RAISES INTO ITS CALLER, and that is enforced here rather than left
    to each call site to remember.** An earlier version made this promise in the
    docstring and did not keep it: called at boot before
    ``federation_intelligence.init()`` had run, it built an envelope with an empty
    ``community_id``, ``validate_envelope`` rejected it, and the ValueError took
    the whole server down — a third instance of an optional federation surface
    stopping a working install from booting. One call site had a try/except and
    the other did not, which is exactly why the guarantee belongs in the function.
    Publishing intelligence is not worth failing a boot or a reflection cycle
    over, and the endpoint reports the feed's real state either way.
    """
    if not _available:
        return None
    identity = feed_identity(keypair)
    if identity is None:
        return None

    try:
        envelope = envelope_from_summary(summary, generated_at=generated_at)
        tip = await head_entry(pg_request, identity.did)
        if not _payload_differs(tip, envelope):
            return None
        return await append_envelope(pg_request, identity, envelope, issued_at=generated_at)
    except Exception as exc:  # noqa: BLE001 — see the docstring: this must not propagate
        print(f"[federation-feed] publish skipped: {exc}", flush=True)
        return None


def feed_url(public_url: str) -> str:
    """The advertised feed URL, or "" when this node cannot honour §4.

    Returning "" is what keeps the descriptor honest without any extra logic at
    the call site: ``build_node_descriptor`` derives ``federation/0.1#4`` from a
    non-empty ``feed_url``, so no feed means no claim, and the two cannot
    disagree.
    """
    if not (_available and public_url):
        return ""
    return f"{public_url.rstrip('/')}{FEED_PATH}"


def reset_for_tests(available: bool = False, reason: str = "reset") -> None:
    """Test seam. The boot flag is module state; a test that flips it must be
    able to put it back, or it leaks into every later test in the process."""
    _set_state(available, reason)

