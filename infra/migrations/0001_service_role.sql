-- 0001 — allow chapter_role = 'service'
--
-- `infra/init.sql` runs only when a database is first initialised, so editing
-- the constraint there fixes FRESH installs and does nothing for a database
-- that already exists. Every deployed org needs this applied by hand.
--
-- Without it the `service` role is not merely unused — every INSERT or UPDATE
-- setting chapter_role='service' is rejected by the CHECK constraint, so the
-- role reads as implemented in the code and fails at the database.
--
-- Idempotent: safe to re-run.

ALTER TABLE public.agents
    DROP CONSTRAINT IF EXISTS agents_chapter_role_check;

ALTER TABLE public.agents
    ADD CONSTRAINT agents_chapter_role_check
    CHECK (chapter_role = ANY (ARRAY[
        'leader'::text,
        'advisor'::text,
        'mentor'::text,
        'member'::text,
        'admin'::text,
        'service'::text
    ]));
