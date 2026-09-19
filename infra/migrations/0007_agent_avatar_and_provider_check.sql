-- 0007 — give the agent its own avatar, and let the CHECK accept every provider
--        the resolver knows
--
-- Both halves are the same defect seen twice: onboarding writes a value the
-- schema refuses, `pg_request` swallows the refusal, and `advance()` reports
-- success anyway. Measured against a database loaded from init.sql:
--
--   step 0 with an avatar_url  -> column "avatar_url" of relation "agents" does
--                                 not exist. The PATCH carries name + bio +
--                                 avatar in ONE body, so the unknown column
--                                 took the other two with it: the row kept its
--                                 old name and an empty description while the
--                                 wizard advanced.
--   step 2 with "Local (Ollama)" -> violates agents_llm_provider_check. The
--                                 column kept its DEFAULT 'xai', so the member
--                                 ran a REMOTE provider they never chose.
--
-- The companion change makes onboarding's writes strict, so from then on a
-- refused write surfaces instead of being logged and stepped over. THIS
-- MIGRATION MUST BE APPLIED FIRST: strict writes against the old schema turn
-- both of the above from a silent loss into a hard failure of the wizard.
--
-- Idempotent: safe to re-run.


-- (a) agents.avatar_url — the AGENT's avatar, not the person's.
--
-- `profiles.avatar_url` already exists and stays. The two rows describe
-- different subjects: `agents` carries `profile_id`, so one person's profile
-- may back several agents, and the picture a member gives their agent is not
-- the picture of the member.
--
-- ⚠️ TWO JOINED TABLES NOW CARRY A SAME-NAMED COLUMN. Every current reader was
-- checked before adding this, and none of them is ambiguous: `surfaces.py`
-- selects `avatar_url` from `profiles` explicitly in both places, and the
-- in-memory member registry (`chapter_agent.load_persisted_agents`) is built
-- field-by-field from a select list that does not name the column. No path
-- merges an agent row and a profile row into one dict. `tests/
-- test_avatar_provenance.py` pins that, so a later `select=*` or row merge
-- fails a test instead of silently swapping one face for the other.

ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS avatar_url text;


-- (b) agents_llm_provider_check — widened to the resolver's registry.
--
-- The constraint named five providers; `llm_runtime.PROVIDERS` knows seven, and
-- onboarding offers "Local (Ollama)". Local-first is the express default, so
-- the wizard is the side that was right and the constraint is the side that was
-- narrow.
--
-- 'custom' is kept and is NOT in the registry: `llm_runtime.resolve('custom')`
-- raises LLMNotConfigured, so a member recorded as 'custom' cannot start today.
-- Dropping it from the CHECK would additionally make any UPDATE to such a row
-- fail, converting a member who cannot run into a row nobody can repair. It is
-- declared as a legacy value in `llm_runtime.LEGACY_PROVIDER_VALUES` so the
-- registry-vs-CHECK guard records the gap rather than tolerating it silently.
--
-- `agent_api_keys_provider_check` is DELIBERATELY NOT widened. That table holds
-- a credential, and the three local providers take none — `build_client` sends
-- a placeholder that never leaves the machine. A local row there would be
-- meaningless on its face and harmful in effect: `load_sessions` treats the
-- presence of a stored key row as branch 2 of its precedence chain, so a local
-- provider carrying a key would start claiming to be a bring-your-own-key
-- member. It stays at the four remote providers plus 'custom'.

ALTER TABLE public.agents
    DROP CONSTRAINT IF EXISTS agents_llm_provider_check;

ALTER TABLE public.agents
    ADD CONSTRAINT agents_llm_provider_check
    CHECK ((llm_provider = ANY (ARRAY[
        -- remote (unchanged)
        'xai'::text,
        'openai'::text,
        'anthropic'::text,
        'groq'::text,
        -- local — reachable without leaving the machine, and take no credential
        'ollama'::text,
        'llama_cpp'::text,
        'mlx_lm'::text,
        -- legacy: accepted by this constraint, NOT resolvable by llm_runtime
        'custom'::text
    ])));
