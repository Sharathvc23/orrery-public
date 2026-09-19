-- 0010 — no function runs with the table owner's privileges
--
-- init.sql declared thirteen SECURITY DEFINER functions. A function marked
-- DEFINER executes with the privileges of the role that created it — the
-- superuser that ran init.sql — instead of the caller's, so any flaw in its
-- body is a flaw with full table-owner access, and the application role's
-- least-privilege grants (0006) do not apply inside it. Seven of the thirteen
-- served only the tables 0009 dropped and went with them. Of the six that
-- remained, five were orphans of an earlier hosting platform: never reached
-- by any trigger or any code path in this repository, one would fail on
-- auth.uid() (a function that does not exist here), and one — the trigger
-- that auto-joined every new profile to a hard-coded organisation id — would
-- have violated a foreign key the first time anything inserted a profile. The
-- sixth, update_updated_at_column, is a generic updated_at bump on five live
-- triggers; it touches no table and needs no elevation, so it is kept as
-- SECURITY INVOKER.
--
-- After this file (and 0009) there is no SECURITY DEFINER function in the
-- schema, and tests/test_init_sql_has_no_security_definer.py holds that for
-- fresh installs.
--
-- Independent of 0009: everything here uses IF EXISTS, and the seven DEFINER
-- functions 0009 removes are not touched here — applying 0010 before 0009 is
-- safe, and 0009 then removes the rest. Apply as the superuser:
--
--   psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0010_no_security_definer.sql

-- The trigger first: it is the only reference to the function it calls.
DROP TRIGGER IF EXISTS on_profile_created_join_bay_area ON public.profiles;

DROP FUNCTION IF EXISTS public.auto_join_bay_area_chapter();
DROP FUNCTION IF EXISTS public.get_chapter_role(uuid, uuid);
DROP FUNCTION IF EXISTS public.handle_new_user();
DROP FUNCTION IF EXISTS public.is_chapter_admin(uuid, uuid);
DROP FUNCTION IF EXISTS public.update_last_active();

-- Kept, without the elevation. ALTER FUNCTION on a missing function raises,
-- so this is guarded for a database that never had it.
DO $$
BEGIN
    IF to_regprocedure('public.update_updated_at_column()') IS NOT NULL THEN
        ALTER FUNCTION public.update_updated_at_column() SECURITY INVOKER;
    END IF;
END
$$;
