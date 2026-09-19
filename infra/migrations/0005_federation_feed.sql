-- 0005 — the durable, gap-free federation intelligence feed (sm-federation §4)
--
-- WHY A TABLE AT ALL, stated because "keep it in memory" is the obvious
-- alternative and it cannot work. A subscriber verifies completeness with
-- `expected_prev_hash` (each entry links to its predecessor) and detects a
-- restarted sequence with `expected_head` (the head it last accepted). Both
-- properties are about what survives a restart. An in-memory log CAN chain
-- perfectly; it simply ceases to exist, and a feed that comes back from seq 0
-- is signed correctly, chains correctly from its own new genesis, and verifies
-- as a flawless FIRST sync — while every entry the subscriber held has silently
-- stopped existing. That is the exact failure `sm_bridge_adapter._monotonic_base_seq()`
-- lives with deliberately for the MEMBER-DELTA store (wall-clock ms, gaps are
-- fine there because that contract is monotonic, not gapless), and it is why
-- server/constraints.txt refuses sm-bridge's [feed] extra. THIS IS A DIFFERENT
-- LOG: intelligence envelopes, not member deltas. The refusal stands for that
-- store and does not apply here.
--
-- Append-only by construction: no UPDATE and no DELETE path exists in the
-- server, and `entry_hash` is UNIQUE so a replayed append collides rather than
-- forking the chain.
--
-- Idempotent: safe to re-run. This file is also executed as a boot-time ensure
-- (server/federation_feed.py), so an existing install picks the table up without
-- an operator running psql — with one deliberate exception: if the app's role
-- lacks CREATE, the ensure DEGRADES the node to §2-only and does NOT raise.
-- Bricking a working install to add an optional federation surface is worse than
-- the surface being absent.

CREATE TABLE IF NOT EXISTS public.federation_feed_entries (
    -- The feed's own sequence. NOT a bigserial: `seq` is chain state, derived
    -- from the previous entry, not from a generator the database owns. A
    -- sequence would keep counting across a TRUNCATE and, worse, would let the
    -- log and the chain disagree about what "next" means.
    seq          bigint NOT NULL,

    -- did:key of the publishing org, from the same Ed25519 key /.well-known/did.json
    -- publishes. One row-set per feed; the PK is (feed_id, seq) so an org that
    -- ever rotates identity starts a new chain rather than continuing another's.
    feed_id      text   NOT NULL,

    prev_hash    text,                      -- NULL only at genesis
    entry_hash   text   NOT NULL,
    issued_at    timestamptz NOT NULL,

    -- The signed `feed-entry/0.1` exactly as sm-feed produced it. Stored whole
    -- because the signature covers the entry as a document: re-assembling it
    -- from columns would make the stored bytes and the verified bytes two
    -- different things, and only one of them is the one a peer checks.
    entry        jsonb  NOT NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (feed_id, seq)
);

-- A replayed or duplicated append must collide, not fork the chain.
CREATE UNIQUE INDEX IF NOT EXISTS federation_feed_entries_hash_uq
    ON public.federation_feed_entries (entry_hash);

-- The read path is "everything after this cursor, in order".
CREATE INDEX IF NOT EXISTS federation_feed_entries_seq_idx
    ON public.federation_feed_entries (feed_id, seq);
