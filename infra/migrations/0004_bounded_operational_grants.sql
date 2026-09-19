-- 0004 — bounded operational grants
--
-- Single-use exact-key grants are correct and stay: they are what stops
-- "approve once, send forever". But they were the ONLY option, so 50 sends
-- meant 50 approvals and 50 retries of one send meant 50 more. The two
-- available states were "approve every action" or "no gate", and a team of
-- five routes around that.
--
-- This adds ONE middle option: "approve up to N actions matching this scope,
-- until this time". Bounded on every axis, and every bound is NOT NULL —
-- a bounded grant with an optional cap is an unbounded grant with extra steps.
--
-- Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS public.operational_grants (
    grant_id     text PRIMARY KEY,
    chapter_id   text NOT NULL,
    kind         text NOT NULL,
    -- A prefix, optionally ending in a single '*'. Never NULL and never bare
    -- '*': a scope that matches everything is not a scope.
    scope        text NOT NULL CHECK (length(scope) > 0 AND scope <> '*'),
    cap          integer NOT NULL CHECK (cap > 0),
    consumed     integer NOT NULL DEFAULT 0 CHECK (consumed >= 0),
    expires_at   timestamp with time zone NOT NULL,
    revoked_at   timestamp with time zone,
    created_by   text NOT NULL,
    created_at   timestamp with time zone NOT NULL DEFAULT now(),
    -- The cap is enforced by the database, not only by the code that reads it.
    CONSTRAINT operational_grants_cap_not_exceeded CHECK (consumed <= cap)
);

CREATE INDEX IF NOT EXISTS operational_grants_live_idx
    ON public.operational_grants (chapter_id, kind, expires_at)
    WHERE revoked_at IS NULL;

-- Per-consumption audit. The point of a bound is that an operator can watch it
-- being spent, so every ATTEMPT is recorded — including the ones that were not
-- charged, because an uncharged retry storm is exactly what someone would want
-- to see.
CREATE TABLE IF NOT EXISTS public.operational_grant_consumptions (
    id             bigserial PRIMARY KEY,
    grant_id       text NOT NULL REFERENCES public.operational_grants(grant_id) ON DELETE CASCADE,
    chapter_id     text NOT NULL,
    kind           text NOT NULL,
    action_key     text NOT NULL,
    actor_agent_id text NOT NULL,
    charged        boolean NOT NULL,
    remaining      integer NOT NULL,
    consumed_at    timestamp with time zone NOT NULL DEFAULT now()
);

-- RETRY SEMANTICS, ENFORCED BY THE DATABASE RATHER THAN BY CONVENTION.
-- The cap counts DISTINCT ACTIONS, not attempts: at most one CHARGED row may
-- exist per (grant, action_key). A retry of a byte-identical action — the
-- crash-after-send-before-record case — is therefore idempotent and free.
-- This unique index is what makes that true under concurrency; two racing
-- retries cannot both charge.
CREATE UNIQUE INDEX IF NOT EXISTS operational_grant_consumptions_charged_once_idx
    ON public.operational_grant_consumptions (grant_id, action_key)
    WHERE charged;

CREATE INDEX IF NOT EXISTS operational_grant_consumptions_audit_idx
    ON public.operational_grant_consumptions (chapter_id, consumed_at DESC);


-- Atomic consumption. A cap enforced by SELECT-then-UPDATE is not a cap: four
-- agents acting at once would each read `consumed` before any of them wrote it.
-- The conditional UPDATE below is a single statement, so Postgres serialises
-- the increment and the (cap - consumed) check together.
CREATE OR REPLACE FUNCTION public.consume_operational_grant(
    _chapter_id text,
    _kind text,
    _action_key text,
    _actor text,
    _now timestamp with time zone
) RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    _grant   public.operational_grants%ROWTYPE;
    _already boolean;
    _updated public.operational_grants%ROWTYPE;
BEGIN
    -- Oldest-expiring live grant whose scope covers this action. Oldest-first
    -- so a grant about to lapse is spent before one with time left, rather
    -- than leaving a nearly-expired grant unused.
    SELECT * INTO _grant
      FROM public.operational_grants g
     WHERE g.chapter_id = _chapter_id
       AND g.kind = _kind
       AND g.revoked_at IS NULL
       AND g.expires_at > _now
       AND g.consumed < g.cap
       AND (
             (right(g.scope, 1) = '*' AND _action_key LIKE (left(g.scope, length(g.scope) - 1) || '%'))
             OR g.scope = _action_key
           )
     ORDER BY g.expires_at ASC
     LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('authorized', false, 'reason', 'no_matching_grant');
    END IF;

    -- Already charged for this exact action under this grant? Then this is a
    -- retry of the same action, not a new one. Record the attempt, charge
    -- nothing.
    SELECT EXISTS (
        SELECT 1 FROM public.operational_grant_consumptions c
         WHERE c.grant_id = _grant.grant_id AND c.action_key = _action_key AND c.charged
    ) INTO _already;

    IF _already THEN
        INSERT INTO public.operational_grant_consumptions
            (grant_id, chapter_id, kind, action_key, actor_agent_id, charged, remaining)
        VALUES (_grant.grant_id, _chapter_id, _kind, _action_key, _actor, false,
                _grant.cap - _grant.consumed);
        RETURN jsonb_build_object(
            'authorized', true, 'grant_id', _grant.grant_id, 'charged', false,
            'remaining', _grant.cap - _grant.consumed, 'reason', 'retry_of_charged_action'
        );
    END IF;

    -- The atomic step. `consumed < cap` inside the UPDATE means the check and
    -- the increment cannot be separated by another transaction.
    UPDATE public.operational_grants
       SET consumed = consumed + 1
     WHERE grant_id = _grant.grant_id
       AND revoked_at IS NULL
       AND expires_at > _now
       AND consumed < cap
    RETURNING * INTO _updated;

    IF NOT FOUND THEN
        -- Lost the race, or revoked/expired between the SELECT and here.
        RETURN jsonb_build_object('authorized', false, 'reason', 'grant_exhausted_or_revoked');
    END IF;

    INSERT INTO public.operational_grant_consumptions
        (grant_id, chapter_id, kind, action_key, actor_agent_id, charged, remaining)
    VALUES (_updated.grant_id, _chapter_id, _kind, _action_key, _actor, true,
            _updated.cap - _updated.consumed);

    RETURN jsonb_build_object(
        'authorized', true, 'grant_id', _updated.grant_id, 'charged', true,
        'remaining', _updated.cap - _updated.consumed
    );
END;
$$;
