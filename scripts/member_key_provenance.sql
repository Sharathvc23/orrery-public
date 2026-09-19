-- Member key provenance — how many members does the key-change guard
-- actually protect, and for how many can a key still be established?
--
-- READ-ONLY over your data. The only object it creates is one TEMP view, which
-- lives in this psql session and disappears with it. Safe on a live org.
--
--   psql "$DATABASE_URL" -v chapter=boston-chapter -f scripts/member_key_provenance.sql
--
-- Omit -v chapter to report every org in the database:
--
--   psql "$DATABASE_URL" -v chapter=% -f scripts/member_key_provenance.sql
--
-- WHY THIS EXISTS
-- ---------------
-- `load_persisted_members` rebuilds `members[]` on every boot and recovers each
-- member's Ed25519 public key from ONE place: `agent_facts.provider.did`. Two
-- readers key off the result and both fail open when it is empty — the key-change guard
-- key-change guard (so an unauthenticated POST /api/members can replace the
-- member's auth key) and `cosign_broker.resolve_member_endpoint` (so brokered
-- co-sign degrades to an uncorroborated receipt). See the descriptor-listing fix.
--
-- Three keys are NEVER written to that column, so the members below are not a
-- migration artefact — they are produced by paths that still run today:
--   * a key established by TOFU header (X-Agent-DID-Key on a signed request)
--     lives only in `auth_verify._agent_keys`, which is in-memory;
--   * a legacy HMAC public key is not did:key material and is skipped;
--   * a ROTATED key is written to `member_key_rotations` and never back to
--     `agent_facts`, so the loader restores the REVOKED key
--     (class `rotated_did_mismatch`).
--
-- The filter below mirrors `load_persisted_members` exactly — `status=active`
-- AND `config->>'parent_chapter'`. Counting the whole table instead would
-- overcount by every member of every other org sharing the database.

\set ON_ERROR_STOP on
\if :{?chapter}
\else
\set chapter '%'
\endif

CREATE TEMP VIEW member_key_provenance AS
WITH loaded AS (
    SELECT
        a.agent_id,
        a.config ->> 'parent_chapter'                    AS chapter,
        a.origin,
        a.created_at,
        a.agent_facts -> 'provider' ->> 'did'            AS did
    FROM public.agents a
    WHERE a.status = 'active'
      AND a.config ->> 'parent_chapter' LIKE :'chapter'
),
keyed AS (
    SELECT
        l.*,
        -- Mirrors sovereign_identity.pubkey_from_provider_did: the W3C
        -- multicodec form new writes emit, or the legacy legacy carrier when
        -- its payload is 32 bytes of base64. Anything else yields no key —
        -- including an HMAC pubkey riding in the field.
        CASE
            WHEN l.did ~ '^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$' THEN 'w3c'
            WHEN l.did ~ '^did:key:[A-Za-z0-9+/]{43}=$'           THEN 'legacy'
            ELSE NULL
        END AS did_form
    FROM loaded l
),
-- The rotation audit table is the one durable record of a member key that the
-- loader does not read. Every row was written only after the OLD key verified a
-- signed attestation naming this chapter (member_rotation._verify_attestation),
-- so it is attested provenance, not a self-asserted claim.
rot AS (
    SELECT
        r.agent_id,
        count(*)                                                     AS rotations,
        max(r.recorded_at)                                           AS last_rotation,
        (array_agg(r.new_public_key ORDER BY r.recorded_at DESC))[1] AS newest_key,
        (array_agg(r.new_did_key    ORDER BY r.recorded_at DESC))[1] AS newest_did
    FROM public.member_key_rotations r
    WHERE r.chapter_id LIKE :'chapter'
    GROUP BY r.agent_id
),
classified AS (
    SELECT
        k.*,
        r.rotations,
        r.last_rotation,
        CASE
            -- No key recoverable at boot. The guard is a no-op: an
            -- unauthenticated re-registration sets whatever key it likes.
            WHEN k.did_form IS NULL AND r.agent_id IS NULL THEN 'unguarded_unrecoverable'
            -- Same hole today, but `member_key_rotations` holds an ATTESTED key
            -- for this member — a loader that read it would close it with no
            -- migration and no refusal.
            WHEN k.did_form IS NULL                        THEN 'unguarded_recoverable'
            -- A key IS recovered, but the member has rotated since and the
            -- rotation never reached `agent_facts`. The loader restores a key
            -- the member revoked; their current one gets `key_mismatch`.
            --
            -- Compared in BOTH carriers because the two columns disagree on
            -- form: `agent_facts.provider.did` is the W3C multibase did for new
            -- writes and the legacy `did:key:{raw-b64}` for old ones, while
            -- `new_did_key` is whatever the client sent alongside the raw key.
            WHEN r.agent_id IS NOT NULL
                 AND k.did IS DISTINCT FROM r.newest_did
                 AND k.did IS DISTINCT FROM 'did:key:' || r.newest_key
                                                           THEN 'rotated_did_mismatch'
            ELSE 'guarded'
        END AS class
    FROM keyed k
    LEFT JOIN rot r ON r.agent_id = k.agent_id
)
SELECT * FROM classified;


SELECT
    chapter,
    class,
    origin,
    count(*)                                         AS members,
    min(created_at)::date                            AS oldest_row,
    max(created_at)::date                            AS newest_row,
    count(*) FILTER (WHERE rotations IS NOT NULL)    AS with_rotation_history
FROM member_key_provenance
GROUP BY ROLLUP (chapter, class, origin)
ORDER BY chapter NULLS LAST, class NULLS LAST, origin NULLS LAST;

-- The per-member list behind the counts. Names only — no key material is
-- selected, so the output is safe to paste into an issue.
SELECT
    chapter,
    class,
    agent_id,
    origin,
    created_at::date AS registered,
    coalesce(rotations, 0) AS rotations,
    last_rotation::date
FROM member_key_provenance
WHERE class <> 'guarded'
ORDER BY class, chapter, agent_id;
