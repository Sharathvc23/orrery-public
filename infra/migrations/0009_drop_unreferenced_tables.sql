-- 0009 — drop the tables nothing reads
--
-- infra/init.sql created 112 tables. Forty-five of them were referenced by no
-- non-test source anywhere in this repository — server, agent, smb_host,
-- smb_signup, index, mcp_server, scripts — nor by any migration, nor by the
-- seed, nor by any export format. They are the fossil of the product this
-- codebase was before it became an agent-native org (a startup-community
-- platform: pitches, polls, sponsors, research teams, role permissions),
-- and every self-hoster has been creating them on first boot.
-- Re-derived at the time of this migration by grepping every CREATE TABLE
-- name against the non-test tree, then confirmed against a live catalog:
-- no view reads them, no live table's trigger reaches them, and the one
-- foreign key from a live table (chapters.template_id → chapter_templates)
-- and the two triggers on `chapters` that populated them are dropped here
-- with them. The eight functions that existed only to serve them go too.
--
-- THIS MIGRATION DROPS ONLY WHAT IS EMPTY, AND SAYS SO BY NAME. A table with
-- rows in a live org is a finding, not something a migration deletes: every
-- table is counted first, and if ANY of them holds a row the migration raises
-- naming each such table with its count and drops NOTHING. The operator then
-- decides — export, migrate, or delete by hand — and re-runs. A table that is
-- already absent is skipped, so a re-run is safe.
--
-- Fresh installs: init.sql no longer creates these, so this file has nothing
-- to do there and exits cleanly. Existing installs: apply as the superuser
-- (the application role has no DROP), the same way as 0006:
--
--   psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f infra/migrations/0009_drop_unreferenced_tables.sql
--
-- Compatibility, stated per the release rule: none of these tables is named
-- by a migration (0001–0008), the seed, the agent export/import format, the
-- DSAR export, or the backup guide, so no artifact changes shape. A database
-- created by this repository's public releases has never had a code path that
-- writes to them; the counts guard is for a database older than that.

DO $$
DECLARE
    dead_tables text[] := ARRAY[
        'admin_resources',
        'agent_calendar_connections',
        'agent_poll_votes',
        'agent_polls',
        'call_responses',
        'chapter_committees',
        'chapter_governance_roles',
        'chapter_leaders',
        'chapter_partnerships',
        'chapter_speakers',
        'chapter_sponsors',
        'chapter_templates',
        'committee_members',
        'demo_day_startups',
        'event_rsvps',
        'expertise_tags',
        'investor_interests',
        'invitations',
        'member_expertise_tags',
        'member_looking_for',
        'member_offering',
        'notification_preferences',
        'notifications',
        'poll_options',
        'poll_votes_anonymous',
        'research_team_members',
        'research_teams',
        'research_topics',
        'resource_access_log',
        'role_permissions',
        'skill_endorsements',
        'sponsorship_tiers',
        'startup_evaluations',
        'startup_investment_interests',
        'startup_investor_matches',
        'startup_pitches',
        'startup_teams',
        'startup_updates',
        'startup_whitepapers',
        'team_documents',
        'team_milestones',
        'template_event_types',
        'template_governance_roles',
        'template_research_teams',
        'user_roles'
    ];
    t text;
    n bigint;
    occupied text[] := ARRAY[]::text[];
BEGIN
    -- Count first, all of them, before anything is dropped.
    FOREACH t IN ARRAY dead_tables LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            EXECUTE format('SELECT count(*) FROM public.%I', t) INTO n;
            IF n > 0 THEN
                occupied := occupied || (t || ' (' || n || ' rows)');
            END IF;
        END IF;
    END LOOP;

    IF array_length(occupied, 1) > 0 THEN
        RAISE EXCEPTION '0009 refused: these tables hold rows and nothing in the code reads them — decide what the data is before dropping: %',
            array_to_string(occupied, ', ')
            USING HINT = 'export or delete the rows by hand, then re-run; this migration drops only empty tables';
    END IF;

    -- The live table `chapters` carried a foreign key into chapter_templates and
    -- two triggers whose only job was to populate the tables dropped below.
    EXECUTE 'DROP TRIGGER IF EXISTS apply_template_on_chapter_create ON public.chapters';
    EXECUTE 'DROP TRIGGER IF EXISTS setup_chapter_after_create ON public.chapters';
    EXECUTE 'ALTER TABLE IF EXISTS public.chapters DROP CONSTRAINT IF EXISTS chapters_template_id_fkey';

    FOREACH t IN ARRAY dead_tables LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            -- CASCADE reaches only the foreign keys among the dead tables
            -- themselves: no live table depends on any of them once the
            -- chapters constraint above is gone (verified against the catalog).
            EXECUTE format('DROP TABLE public.%I CASCADE', t);
            RAISE NOTICE '0009: dropped empty table %', t;
        END IF;
    END LOOP;

    -- Functions that served only the dropped tables. Signatures as created by
    -- init.sql; IF EXISTS makes the re-run safe.
    DROP FUNCTION IF EXISTS public.apply_chapter_template();
    DROP FUNCTION IF EXISTS public.setup_chapter_from_template();
    DROP FUNCTION IF EXISTS public.has_permission(uuid, public.permission_type, uuid, uuid, uuid);
    DROP FUNCTION IF EXISTS public.has_role(uuid, public.app_role);
    DROP FUNCTION IF EXISTS public.is_team_lead(uuid, uuid);
    DROP FUNCTION IF EXISTS public.handle_new_user_notifications();
    DROP FUNCTION IF EXISTS public.update_endorsement_count();
    DROP FUNCTION IF EXISTS public._bump_call_response_count();

    -- Two enum types whose only column was on a dropped table (user_roles.role,
    -- role_permissions.permission) and whose only other use was in the two
    -- functions above. Verified against the catalog: zero columns, zero
    -- functions reference them once the drops above have run.
    DROP TYPE IF EXISTS public.permission_type;
    DROP TYPE IF EXISTS public.app_role;
END
$$;
