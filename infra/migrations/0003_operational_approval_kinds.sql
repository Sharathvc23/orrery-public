-- 0003 — allow the operational approval kinds
--
-- PR1 added send_external / record_write / external_fetch to the Python
-- APPROVAL_KINDS set and did NOT update this constraint, so Postgres rejected
-- every operational INSERT. `pg_request` swallowed the violation, `propose()`
-- returned None, and the caller reported "pending_approval" with a null id.
--
-- The verb was correctly refused, never queued, therefore never approvable,
-- therefore never able to succeed. The org could do no service work at all,
-- and every layer looked like it was working.
--
-- init.sql alone does not fix this: it runs only at first database
-- initialisation, so a deployed org keeps the old constraint forever. That
-- divergence is the same class as the enumeration closure.
--
-- Idempotent: safe to re-run.

ALTER TABLE public.pending_approvals
    DROP CONSTRAINT IF EXISTS pending_approvals_kind_check;

ALTER TABLE public.pending_approvals
    ADD CONSTRAINT pending_approvals_kind_check
    CHECK (kind = ANY (ARRAY[
        -- social (unchanged)
        'introduction'::text,
        'cross_chapter_intent'::text,
        'cross_chapter_message'::text,
        'event_proposal'::text,
        'member_admission'::text,
        'role_promotion'::text,
        'call_cross_post'::text,
        'broadcast'::text,
        -- operational (PR1)
        'send_external'::text,
        'record_write'::text,
        'external_fetch'::text
    ]));
