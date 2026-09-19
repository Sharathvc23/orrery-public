-- Orrery — agent-native schema (lean).
-- public tables only; NO Supabase RLS/auth/storage/realtime, NO PostgREST roles.
-- Regenerate: boot the db, strip RLS + dead-feature tables, pg_dump --schema=public.
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;

--
-- PostgreSQL database dump
--


-- Dumped from database version 15.17 (Debian 15.17-1.pgdg12+1)
-- Dumped by pg_dump version 15.17 (Debian 15.17-1.pgdg12+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- CREATE SCHEMA public;  -- exists by default


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: bump_chapter_skill_stats(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.bump_chapter_skill_stats() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_TABLE_NAME = 'chapter_skill_installs' THEN
    IF TG_OP = 'INSERT' THEN
      UPDATE chapter_skills
        SET install_count = install_count + 1,
            updated_at = now()
        WHERE id = NEW.skill_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'chapter_skill_reviews' THEN
    UPDATE chapter_skills s
      SET avg_rating = (
            SELECT avg(rating)::real
              FROM chapter_skill_reviews
              WHERE skill_id = s.id
          ),
          review_count = (
            SELECT count(*)
              FROM chapter_skill_reviews
              WHERE skill_id = s.id
          ),
          updated_at = now()
      WHERE s.id = COALESCE(NEW.skill_id, OLD.skill_id);
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;


--
-- Name: consume_org_invite(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.consume_org_invite(p_token text, p_agent_id text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE _ok boolean;
BEGIN
    UPDATE org_invites
       SET uses = uses + 1,
           redeemed_by = redeemed_by || to_jsonb(p_agent_id)
     WHERE token = p_token
       AND status = 'active'
       AND uses < max_uses
       AND expires_at > now()
    RETURNING true INTO _ok;
    RETURN coalesce(_ok, false);
END $$;


--
-- Name: expire_chapter_calls(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expire_chapter_calls() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE chapter_calls
    SET status = 'expired'
    WHERE status = 'open' AND expires_at < now();
END;
$$;


--
-- Name: FUNCTION expire_chapter_calls(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.expire_chapter_calls() IS 'Call periodically from think_scan_calls. Moves stale open calls to expired.';


--
-- Name: expire_pending_approvals(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expire_pending_approvals() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE pending_approvals
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at < now();
  UPDATE chapter_role_nominations
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at < now();
END;
$$;


--
-- Name: FUNCTION expire_pending_approvals(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.expire_pending_approvals() IS 'Call periodically (from think_approvals_sweep). Moves stale pending items to expired.';


--
-- Name: match_projections(extensions.vector, double precision, integer, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.match_projections(query_embedding extensions.vector, match_threshold double precision DEFAULT 0.3, match_count integer DEFAULT 20, exclude_agent_id text DEFAULT ''::text, filter_chapter_id text DEFAULT ''::text) RETURNS TABLE(agent_id text, chapter_agent_id text, projection_data jsonb, similarity double precision)
    LANGUAGE plpgsql STABLE
    SET search_path TO 'public', 'extensions'
    AS $$
BEGIN
  RETURN QUERY
  SELECT
    ap.agent_id,
    ap.chapter_agent_id,
    ap.projection_data,
    (1 - (ap.embedding <=> query_embedding))::float AS similarity
  FROM agent_projections ap
  WHERE ap.embedding IS NOT NULL
    AND ap.agent_id != exclude_agent_id
    AND (filter_chapter_id = '' OR ap.chapter_agent_id = filter_chapter_id)
    AND (1 - (ap.embedding <=> query_embedding)) > match_threshold
  ORDER BY ap.embedding <=> query_embedding ASC
  LIMIT match_count;
END;
$$;


--
-- Name: replay_scores_all(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.replay_scores_all() RETURNS TABLE(agent_id text, replayed numeric)
    LANGUAGE sql STABLE
    AS $$
  SELECT agent_id, SUM(delta) AS replayed
  FROM trust_events
  GROUP BY agent_id;
$$;


--
-- Name: touch_agent_settings_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_agent_settings_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


--
-- Name: touch_channel_connections_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_channel_connections_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


--
-- Name: touch_chapter_sso_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.touch_chapter_sso_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


--
-- Name: trust_events_apply_delta(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trust_events_apply_delta() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE agents
     SET trust_score = COALESCE(trust_score, 0) + NEW.delta
   WHERE agent_id = NEW.agent_id;
  RETURN NEW;
END;
$$;


--
-- Name: update_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER
    SET search_path TO 'public'
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_action_outcomes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_action_outcomes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    action_id text NOT NULL,
    action_type text NOT NULL,
    agent_id text,
    signal text NOT NULL,
    quality_score double precision DEFAULT 0,
    feedback_data jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_action_outcomes_signal_check CHECK ((signal = ANY (ARRAY['positive'::text, 'negative'::text, 'rsvp'::text, 'skip'::text])))
);


--
-- Name: agent_activity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_activity (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    chapter_name text NOT NULL,
    member_agent_id text,
    member_name text,
    conversation_id text NOT NULL,
    user_message_snippet text NOT NULL,
    agent_response_snippet text NOT NULL,
    is_cross_chapter boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    profile_id uuid NOT NULL,
    provider text NOT NULL,
    api_key_encrypted text NOT NULL,
    base_url text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_api_keys_provider_check CHECK ((provider = ANY (ARRAY['xai'::text, 'openai'::text, 'anthropic'::text, 'groq'::text, 'custom'::text])))
);


--
-- Name: agent_authority_scope; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_authority_scope (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id text NOT NULL,
    action_kind text NOT NULL,
    allowed boolean DEFAULT false NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by text,
    CONSTRAINT agent_authority_scope_action_kind_check CHECK ((action_kind = ANY (ARRAY['submit_intent'::text, 'respond_to_intent'::text, 'submit_call'::text, 'respond_to_call'::text, 'update_projection'::text, 'rsvp_event'::text, 'accept_meeting'::text, 'start_conversation'::text, 'cross_chapter_message'::text, 'publish_public_note'::text, 'save_private_note'::text])))
);


--
-- Name: agent_authority_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_authority_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id text NOT NULL,
    action_kind text NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_kind text NOT NULL,
    count integer DEFAULT 0 NOT NULL,
    CONSTRAINT agent_authority_usage_window_kind_check CHECK ((window_kind = ANY (ARRAY['day'::text, 'week'::text])))
);


--
-- Name: agent_conversation_threads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_conversation_threads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    from_agent_id text NOT NULL,
    to_agent_id text NOT NULL,
    chapter_agent_id text NOT NULL,
    status text DEFAULT 'active'::text,
    topic text DEFAULT ''::text,
    messages jsonb DEFAULT '[]'::jsonb,
    message_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_conversation_threads_status_check CHECK ((status = ANY (ARRAY['active'::text, 'completed'::text, 'declined'::text])))
);


--
-- Name: agent_conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_conversations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    conversation_id text NOT NULL,
    title text DEFAULT 'New Conversation'::text,
    messages jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_digests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_digests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    title text NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    content_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    highlights text[] DEFAULT '{}'::text[],
    a2ui_surface jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    title text NOT NULL,
    description text,
    event_type text DEFAULT 'workshop'::text,
    proposed_by_agent text,
    proposed_reason text,
    suggested_speakers text[] DEFAULT '{}'::text[],
    suggested_date timestamp with time zone,
    status text DEFAULT 'proposed'::text,
    rsvp_count integer DEFAULT 0,
    a2ui_surface jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_events_event_type_check CHECK ((event_type = ANY (ARRAY['workshop'::text, 'meetup'::text, 'hackathon'::text, 'talk'::text, 'panel'::text, 'social'::text, 'demo_day'::text]))),
    CONSTRAINT agent_events_status_check CHECK ((status = ANY (ARRAY['proposed'::text, 'approved'::text, 'scheduled'::text, 'completed'::text, 'cancelled'::text])))
);


--
-- Name: agent_evolution_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_evolution_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    agent_id text NOT NULL,
    old_skills text[] DEFAULT '{}'::text[],
    new_skill text NOT NULL,
    personality_addition text DEFAULT ''::text,
    trigger_activity text DEFAULT ''::text,
    activity_score double precision DEFAULT 0,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_facts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_facts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    facts jsonb DEFAULT '{}'::jsonb NOT NULL,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_intent_responses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_intent_responses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent_id uuid,
    responder_agent_id text NOT NULL,
    responder_chapter_id text NOT NULL,
    response text,
    counter_text text,
    consented_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_intent_responses_response_check CHECK ((response = ANY (ARRAY['accept'::text, 'decline'::text, 'counter'::text, 'pending'::text])))
);


--
-- Name: agent_intents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_intents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    requester_agent_id text NOT NULL,
    intent_text text NOT NULL,
    intent_tags text[] DEFAULT '{}'::text[],
    status text DEFAULT 'active'::text,
    matches_found integer DEFAULT 0,
    match_details jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_intents_status_check CHECK ((status = ANY (ARRAY['active'::text, 'matched'::text, 'fulfilled'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: agent_knowledge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_knowledge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    knowledge_type text NOT NULL,
    knowledge_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    confidence double precision DEFAULT 0.5,
    updated_at timestamp with time zone DEFAULT now(),
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_member_activity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_member_activity (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    agent_id text NOT NULL,
    activity_type text NOT NULL,
    activity_data jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_memory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_memory (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    memory_type text NOT NULL,
    memory_key text NOT NULL,
    memory_value jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone DEFAULT (now() + '7 days'::interval)
);


--
-- Name: agent_private_memory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_private_memory (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    owner_id uuid NOT NULL,
    agent_id text NOT NULL,
    memory_type text NOT NULL,
    memory_key text NOT NULL,
    memory_value jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.agent_private_memory FORCE ROW LEVEL SECURITY;


--
-- Name: agent_projections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_projections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id text NOT NULL,
    chapter_agent_id text NOT NULL,
    projection_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    visibility_settings jsonb DEFAULT '{"default": "public"}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    embedding extensions.vector(384)
);


--
-- Name: agent_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id text NOT NULL,
    chapter_agent_id text NOT NULL,
    session_state text DEFAULT 'active'::text,
    last_action_at timestamp with time zone DEFAULT now(),
    thought_count integer DEFAULT 0,
    tool_calls integer DEFAULT 0,
    memory_entries integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT agent_sessions_session_state_check CHECK ((session_state = ANY (ARRAY['active'::text, 'idle'::text, 'stopped'::text])))
);


--
-- Name: agent_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_settings (
    agent_id text NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    onboarding_completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_thoughts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_thoughts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_agent_id text NOT NULL,
    chapter_name text NOT NULL,
    member_agent_id text,
    member_name text,
    thought_type text NOT NULL,
    thought_text text NOT NULL,
    a2ui_surface jsonb,
    targets jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    profile_id uuid,
    agent_id text NOT NULL,
    chapter_id uuid,
    name text NOT NULL,
    description text DEFAULT ''::text,
    avatar_url text,
    skills text[] DEFAULT '{}'::text[],
    status text DEFAULT 'pending'::text,
    llm_provider text DEFAULT 'xai'::text,
    llm_model text DEFAULT 'grok-3-mini'::text,
    nest_registered boolean DEFAULT false,
    nest_endpoint text,
    agent_facts jsonb DEFAULT '{}'::jsonb,
    config jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    profile_type text DEFAULT 'member'::text,
    interests text[] DEFAULT '{}'::text[],
    reputation jsonb DEFAULT '{"votes": 0, "events": 0, "sprints": 0, "contributions": 0, "introductions": 0}'::jsonb,
    availability text DEFAULT 'active'::text,
    github_data jsonb,
    linkedin_url text,
    chapter_role text DEFAULT 'member'::text,
    onboarding_step integer DEFAULT 0,
    onboarding_completed_at timestamp with time zone,
    last_thought_at timestamp with time zone,
    thought_count integer DEFAULT 0,
    conversation_count integer DEFAULT 0,
    trust_score real DEFAULT 0.0,
    origin text DEFAULT 'sovereign'::text NOT NULL,
    CONSTRAINT agents_availability_check CHECK ((availability = ANY (ARRAY['active'::text, 'part-time'::text, 'observer'::text, 'inactive'::text]))),
    CONSTRAINT agents_chapter_role_check CHECK ((chapter_role = ANY (ARRAY['leader'::text, 'advisor'::text, 'mentor'::text, 'member'::text, 'admin'::text, 'service'::text]))),
    CONSTRAINT agents_llm_provider_check CHECK ((llm_provider = ANY (ARRAY['xai'::text, 'openai'::text, 'anthropic'::text, 'groq'::text, 'ollama'::text, 'llama_cpp'::text, 'mlx_lm'::text, 'custom'::text]))),
    CONSTRAINT agents_origin_check CHECK ((origin = ANY (ARRAY['sovereign'::text, 'openclaw'::text, 'openclaw_sandboxed'::text]))),
    CONSTRAINT agents_profile_type_check CHECK ((profile_type = ANY (ARRAY['founder'::text, 'developer'::text, 'investor'::text, 'mentor'::text, 'researcher'::text, 'leader'::text, 'member'::text]))),
    CONSTRAINT agents_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'inactive'::text]))),
    CONSTRAINT agents_trust_score_check CHECK (((trust_score >= (0.0)::double precision) AND (trust_score <= (100.0)::double precision)))
);


--
-- Name: COLUMN agents.trust_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agents.trust_score IS 'Computed trust score (0-100). Aggregates reputation + nominations + tenure. Used by auto_promote feature flag.';


--
-- Name: COLUMN agents.origin; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agents.origin IS 'Endpoint runtime type. sovereign=community-member SDK (full capabilities), openclaw=third-party via ClawHub skill (reduced trust), openclaw_sandboxed=OpenClaw inside an explicit sandbox workspace.';


--
-- Name: arp_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.arp_receipts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    receipt_id text NOT NULL,
    issuer_did text NOT NULL,
    principal_did text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    arp_version text NOT NULL,
    action_category text NOT NULL,
    action_outcome text NOT NULL,
    human_summary text NOT NULL,
    amount_currency text,
    amount_cents bigint,
    counterparty_did text,
    previous_receipt_hash text,
    chain_link text NOT NULL,
    receipt_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE arp_receipts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.arp_receipts IS 'ARP v0.1 Agency Receipts. See spec/arp/0.1/spec.md §10.2.';


--
-- Name: broadcast_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.broadcast_log (
    id bigint NOT NULL,
    broadcast_id uuid NOT NULL,
    chapter_id text NOT NULL,
    sender_agent_id text NOT NULL,
    audience text NOT NULL,
    title text NOT NULL,
    total_peers integer DEFAULT 0 NOT NULL,
    succeeded integer DEFAULT 0 NOT NULL,
    failed integer DEFAULT 0 NOT NULL,
    peer_results jsonb DEFAULT '[]'::jsonb NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT broadcast_log_audience_check CHECK ((audience = ANY (ARRAY['local'::text, 'federation'::text, 'all'::text])))
);


--
-- Name: TABLE broadcast_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.broadcast_log IS 'Send-side delivery audit for chapter broadcasts. Distinct from event_log: event_log stores the canonical event; this table stores per-peer fanout results.';


--
-- Name: broadcast_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.broadcast_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: broadcast_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.broadcast_log_id_seq OWNED BY public.broadcast_log.id;


--
-- Name: chapter_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    actor_agent_id text,
    action text NOT NULL,
    target_type text,
    target_id text,
    outcome text DEFAULT 'ok'::text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    prev_sha256 text,
    event_sha256 text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_audit_events_outcome_check CHECK ((outcome = ANY (ARRAY['ok'::text, 'fail'::text, 'denied'::text])))
);


--
-- Name: chapter_channel_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_channel_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id text NOT NULL,
    kind text NOT NULL,
    remote_id text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    last_test_at timestamp with time zone,
    last_test_ok boolean,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_channel_connections_kind_check CHECK ((kind = ANY (ARRAY['slack'::text, 'email'::text, 'discord'::text, 'webhook'::text]))),
    CONSTRAINT chapter_channel_connections_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'disabled'::text, 'error'::text])))
);


--
-- Name: chapter_federation_allowlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_federation_allowlist (
    chapter_id text NOT NULL,
    peer_chapter_id text NOT NULL,
    added_by_agent_id text NOT NULL,
    reason text,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chapter_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_keys (
    chapter_id text NOT NULL,
    secret_b64 text NOT NULL,
    public_b64 text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chapter_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_members (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_members_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'moderator'::text, 'member'::text])))
);


--
-- Name: chapter_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_policy (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    key text NOT NULL,
    value jsonb NOT NULL,
    baseline jsonb NOT NULL,
    value_type text DEFAULT 'float'::text NOT NULL,
    auto_tuned boolean DEFAULT false NOT NULL,
    pinned_by text,
    pinned_reason text,
    pinned_at timestamp with time zone,
    last_updated timestamp with time zone DEFAULT now() NOT NULL,
    last_tune_reason text,
    last_tune_outcome_window_days integer,
    last_tune_sample_size integer,
    CONSTRAINT chapter_policy_value_type_check CHECK ((value_type = ANY (ARRAY['float'::text, 'int'::text, 'bool'::text, 'string'::text])))
);


--
-- Name: chapter_policy_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_policy_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    key text NOT NULL,
    old_value jsonb,
    new_value jsonb,
    reason text NOT NULL,
    actor text,
    outcome_window_days integer,
    sample_size integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chapter_role_nominations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_role_nominations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nominee_agent_id text NOT NULL,
    nominator_agent_id text NOT NULL,
    chapter_id text NOT NULL,
    target_role text NOT NULL,
    reason text,
    status text DEFAULT 'pending'::text NOT NULL,
    resolved_by text,
    resolved_at timestamp with time zone,
    resolution_note text,
    endorsements jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '30 days'::interval) NOT NULL,
    CONSTRAINT chapter_role_nominations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'expired'::text, 'withdrawn'::text]))),
    CONSTRAINT chapter_role_nominations_target_role_check CHECK ((target_role = ANY (ARRAY['advisor'::text, 'leader'::text])))
);


--
-- Name: chapter_skill_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_skill_attestations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    skill_id text NOT NULL,
    skill_version text NOT NULL,
    content_sha256 text NOT NULL,
    attestor_did text NOT NULL,
    attestor_agent_id text NOT NULL,
    trust_tier_at_attest text NOT NULL,
    attestation_sig text NOT NULL,
    created_unix bigint NOT NULL,
    note_markdown text DEFAULT ''::text NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_skill_attestations_trust_tier_at_attest_check CHECK ((trust_tier_at_attest = ANY (ARRAY['trusted'::text, 'leader'::text])))
);


--
-- Name: TABLE chapter_skill_attestations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.chapter_skill_attestations IS 'Trusted-tier advisor attestations on published skills. Ed25519-signed. A live (non-revoked) attestation makes the skill eligible to mint revenue events (skill_use_events + skill_revenue_ledger).';


--
-- Name: chapter_skill_installs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_skill_installs (
    agent_id text NOT NULL,
    skill_id text NOT NULL,
    installed_at timestamp with time zone DEFAULT now() NOT NULL,
    installed_version text NOT NULL,
    uninstalled_at timestamp with time zone
);


--
-- Name: chapter_skill_reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_skill_reviews (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    skill_id text NOT NULL,
    reviewer_agent_id text NOT NULL,
    rating integer NOT NULL,
    review_text text DEFAULT ''::text NOT NULL,
    signed_install_proof text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_skill_reviews_rating_check CHECK (((rating >= 1) AND (rating <= 5)))
);


--
-- Name: chapter_skills; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_skills (
    id text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    author_did text NOT NULL,
    author_agent_id text,
    description text DEFAULT ''::text NOT NULL,
    readme_markdown text DEFAULT ''::text NOT NULL,
    capabilities text[] DEFAULT '{}'::text[] NOT NULL,
    manifest jsonb NOT NULL,
    content_sha256 text NOT NULL,
    signature text NOT NULL,
    signing_key_did text NOT NULL,
    package_url text,
    trust_score real DEFAULT 0 NOT NULL,
    install_count integer DEFAULT 0 NOT NULL,
    avg_rating real,
    review_count integer DEFAULT 0 NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason text,
    revoked_by_agent_id text,
    chapter_id text DEFAULT 'public'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_skills_name_format CHECK ((name ~ '^[a-z][a-z0-9-]*$'::text)),
    CONSTRAINT chapter_skills_version_format CHECK ((version ~ '^[0-9]+\.[0-9]+\.[0-9]+'::text))
);


--
-- Name: chapter_sso_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapter_sso_configs (
    chapter_id text NOT NULL,
    provider text NOT NULL,
    issuer_url text NOT NULL,
    client_id text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    enforce_sso boolean DEFAULT false NOT NULL,
    last_verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chapter_sso_configs_provider_check CHECK ((provider = ANY (ARRAY['okta'::text, 'azure_ad'::text, 'google_workspace'::text, 'generic_oidc'::text])))
);


--
-- Name: chapters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chapters (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    description text,
    type text NOT NULL,
    region text,
    country text,
    city text,
    logo_url text,
    website_url text,
    lead_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    template_id uuid,
    whatsapp_url text,
    linkedin_url text,
    luma_url text,
    membership_form_url text,
    hero_image_url text,
    stat_events_count integer DEFAULT 0,
    stat_communities_count integer DEFAULT 0,
    stat_partners_count integer DEFAULT 0,
    hero_heading text,
    hero_description text,
    hero_cta_url text,
    hero_cta_label text,
    CONSTRAINT chapters_type_check CHECK ((type = ANY (ARRAY['global'::text, 'domestic'::text])))
);


--
-- Name: chronicles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chronicles (
    principal_did text NOT NULL,
    chronicle_date date NOT NULL,
    parent_chapter text NOT NULL,
    narrative text NOT NULL,
    stats jsonb NOT NULL,
    sources jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE chronicles; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.chronicles IS 'ARP-derived first-person daily Chronicle per agent. Agent-level public flag in agents.config.chronicle_public.';


--
-- Name: comments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.comments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    entity_type text NOT NULL,
    entity_id uuid NOT NULL,
    content text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT comments_content_length CHECK (((char_length(content) >= 1) AND (char_length(content) <= 2000))),
    CONSTRAINT comments_entity_type_check CHECK ((entity_type = ANY (ARRAY['event'::text, 'group'::text])))
);


--
-- Name: connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    requester_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT connections_check CHECK ((requester_id <> recipient_id)),
    CONSTRAINT connections_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'rejected'::text])))
);


--
-- Name: endorsements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endorsements (
    id bigint NOT NULL,
    chapter_id text NOT NULL,
    endorser_agent_id text NOT NULL,
    endorser_did text NOT NULL,
    endorsee_agent_id text NOT NULL,
    endorser_pubkey_b64 text NOT NULL,
    signature_b64 text NOT NULL,
    note_markdown text,
    created_unix bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason text,
    CONSTRAINT endorsements_no_self CHECK ((endorser_agent_id <> endorsee_agent_id))
);


--
-- Name: endorsements_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endorsements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endorsements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endorsements_id_seq OWNED BY public.endorsements.id;


--
-- Name: event_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_log (
    id bigint NOT NULL,
    event_type text NOT NULL,
    publisher_agent_id text NOT NULL,
    payload jsonb NOT NULL,
    trace text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE event_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.event_log IS 'Append-only event ledger. SSE resume buffer + audit trail. EB-1.';


--
-- Name: event_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_log_id_seq OWNED BY public.event_log.id;


--
-- Name: event_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    subscriber_agent_id text NOT NULL,
    subscriber_did_key text NOT NULL,
    topics text[] NOT NULL,
    filters jsonb DEFAULT '{}'::jsonb NOT NULL,
    delivery text DEFAULT 'stream'::text NOT NULL,
    webhook_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '30 days'::interval) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT event_subscriptions_delivery_check CHECK ((delivery = ANY (ARRAY['stream'::text, 'webhook'::text]))),
    CONSTRAINT event_subscriptions_topics_nonempty CHECK ((array_length(topics, 1) >= 1)),
    CONSTRAINT event_subscriptions_webhook_https CHECK (((delivery <> 'webhook'::text) OR (webhook_url ~~ 'https://%'::text)))
);


--
-- Name: TABLE event_subscriptions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.event_subscriptions IS 'Pub/sub subscription registry — chapter→subscriber. EB-1 of the event-bus series.';


--
-- Name: federation_inbound_seen; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_inbound_seen (
    id bigint NOT NULL,
    origin_chapter_id text NOT NULL,
    broadcast_id text NOT NULL,
    seen_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE federation_inbound_seen; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.federation_inbound_seen IS 'Persistent, restart-surviving dedup of inbound federated broadcasts. One row per accepted (origin_chapter_id, broadcast_id).';


--
-- Name: federation_inbound_seen_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.federation_inbound_seen_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: federation_inbound_seen_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.federation_inbound_seen_id_seq OWNED BY public.federation_inbound_seen.id;


--
-- Name: federation_knowledge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_knowledge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_chapter_id text NOT NULL,
    receiving_chapter_id text NOT NULL,
    knowledge_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    confidence double precision DEFAULT 0.6,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: federation_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_policy (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    peer_chapter_id text NOT NULL,
    peer_endpoint text,
    state text DEFAULT 'unknown'::text NOT NULL,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    backoff_seconds integer DEFAULT 360 NOT NULL,
    max_backoff_seconds integer DEFAULT 3600 NOT NULL,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    last_probe_at timestamp with time zone,
    last_error text,
    blocked_by text,
    blocked_reason text,
    blocked_at timestamp with time zone,
    pinned_did text,
    pinned_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_policy_state_check CHECK ((state = ANY (ARRAY['online'::text, 'degraded'::text, 'quarantined'::text, 'blocked'::text, 'unknown'::text])))
);


--
-- Name: federation_policy_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_policy_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    peer_chapter_id text NOT NULL,
    event text NOT NULL,
    old_state text,
    new_state text,
    detail text,
    actor text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: federation_probe_due; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.federation_probe_due AS
 SELECT federation_policy.id,
    federation_policy.chapter_id,
    federation_policy.peer_chapter_id,
    federation_policy.peer_endpoint,
    federation_policy.state,
    federation_policy.consecutive_failures,
    federation_policy.backoff_seconds,
    federation_policy.max_backoff_seconds,
    federation_policy.last_success_at,
    federation_policy.last_failure_at,
    federation_policy.last_probe_at,
    federation_policy.last_error,
    federation_policy.blocked_by,
    federation_policy.blocked_reason,
    federation_policy.blocked_at,
    federation_policy.created_at,
    federation_policy.updated_at
   FROM public.federation_policy
  WHERE ((federation_policy.state = 'quarantined'::text) AND ((federation_policy.last_probe_at IS NULL) OR (federation_policy.last_probe_at < (now() - '00:30:00'::interval))) AND (federation_policy.blocked_by IS NULL));


--
-- Name: VIEW federation_probe_due; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.federation_probe_due IS 'Quarantined peers due for auto-recovery probe — read by think_federation_probe every cycle.';


--
-- Name: group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_members (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    interest_category text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_description_length CHECK (((description IS NULL) OR ((char_length(description) >= 10) AND (char_length(description) <= 1000)))),
    CONSTRAINT groups_name_length CHECK (((char_length(name) >= 3) AND (char_length(name) <= 100)))
);


--
-- Name: pending_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_approvals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    proposer_agent_id text NOT NULL,
    target_agent_id text,
    chapter_id text NOT NULL,
    peer_chapter_id text,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    approved_by text,
    approved_at timestamp with time zone,
    rejection_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '72:00:00'::interval) NOT NULL,
    executed_at timestamp with time zone,
    confidence real DEFAULT 0.5,
    CONSTRAINT pending_approvals_confidence_check CHECK (((confidence >= (0.0)::double precision) AND (confidence <= (1.0)::double precision))),
    CONSTRAINT pending_approvals_kind_check CHECK ((kind = ANY (ARRAY['introduction'::text, 'cross_chapter_intent'::text, 'cross_chapter_message'::text, 'event_proposal'::text, 'member_admission'::text, 'role_promotion'::text, 'call_cross_post'::text, 'broadcast'::text, 'send_external'::text, 'record_write'::text, 'external_fetch'::text]))),
    CONSTRAINT pending_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'expired'::text, 'executed'::text])))
);


--
-- Name: leader_dashboard; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.leader_dashboard AS
 WITH pending_per_kind AS (
         SELECT pending_approvals.chapter_id,
            pending_approvals.kind,
            (count(*))::integer AS n
           FROM public.pending_approvals
          WHERE (pending_approvals.status = 'pending'::text)
          GROUP BY pending_approvals.chapter_id, pending_approvals.kind
        )
 SELECT a.chapter_id,
    (count(*) FILTER (WHERE (a.status = 'pending'::text)))::integer AS pending_count,
    (count(*) FILTER (WHERE ((a.status = 'pending'::text) AND (a.expires_at < (now() + '12:00:00'::interval)))))::integer AS expiring_soon_count,
    (count(*) FILTER (WHERE ((a.status = 'approved'::text) AND (a.approved_at > (now() - '24:00:00'::interval)))))::integer AS approved_last_24h,
    (count(*) FILTER (WHERE ((a.status = 'rejected'::text) AND (a.approved_at > (now() - '24:00:00'::interval)))))::integer AS rejected_last_24h,
    ( SELECT COALESCE(jsonb_object_agg(k.kind, k.n), '{}'::jsonb) AS "coalesce"
           FROM pending_per_kind k
          WHERE (k.chapter_id = a.chapter_id)) AS pending_by_kind
   FROM public.pending_approvals a
  GROUP BY a.chapter_id;


--
-- Name: VIEW leader_dashboard; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.leader_dashboard IS 'Aggregate counts for the leader-only /page/approvals surface.';


--
-- Name: member_key_rotations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.member_key_rotations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    agent_id text NOT NULL,
    old_public_key text NOT NULL,
    new_public_key text NOT NULL,
    new_did_key text,
    attestation jsonb NOT NULL,
    nonce text NOT NULL,
    client_timestamp bigint NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT member_key_rotations_check CHECK ((old_public_key <> new_public_key))
);


--
-- Name: TABLE member_key_rotations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.member_key_rotations IS 'Hash-adjacent audit of sovereign member key rotations. Append-only by convention — no UPDATE or DELETE RLS policy grants access to clients.';


--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sender_id uuid NOT NULL,
    recipient_id uuid NOT NULL,
    content text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    read_at timestamp with time zone,
    image_url text
);


--
-- Name: org_invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_invites (
    token text NOT NULL,
    created_by text NOT NULL,
    max_uses integer DEFAULT 1 NOT NULL,
    uses integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    redeemed_by jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT org_invites_max_uses_check CHECK ((max_uses >= 1)),
    CONSTRAINT org_invites_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text]))),
    CONSTRAINT org_invites_uses_check CHECK ((uses >= 0))
);


--
-- Name: TABLE org_invites; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.org_invites IS 'Invite tokens for the invite join policy. Single-use by default; consumed via an atomic conditional UPDATE.';


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.profiles (
    id uuid NOT NULL,
    full_name text NOT NULL,
    bio text,
    avatar_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    approved boolean DEFAULT false,
    skills text[],
    location text,
    is_public boolean DEFAULT true NOT NULL,
    linkedin_url text,
    github_url text,
    title text,
    contact_email text,
    contact_phone text,
    contact_public boolean DEFAULT false NOT NULL,
    onboarding_completed boolean DEFAULT false NOT NULL,
    referred_by uuid,
    interests text[],
    profession text,
    company text,
    endorsement_count integer DEFAULT 0 NOT NULL,
    last_active_at timestamp with time zone DEFAULT now(),
    CONSTRAINT check_bio_length CHECK (((bio IS NULL) OR (char_length(bio) <= 500))),
    CONSTRAINT check_email_format CHECK (((contact_email IS NULL) OR (contact_email = ''::text) OR (contact_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'::text))),
    CONSTRAINT check_github_url_format CHECK (((github_url IS NULL) OR (github_url = ''::text) OR (github_url ~* '^https?://'::text))),
    CONSTRAINT check_linkedin_url_format CHECK (((linkedin_url IS NULL) OR (linkedin_url = ''::text) OR (linkedin_url ~* '^https?://'::text))),
    CONSTRAINT check_location_length CHECK (((location IS NULL) OR (char_length(location) <= 100))),
    CONSTRAINT check_name_length CHECK (((char_length(full_name) >= 2) AND (char_length(full_name) <= 100))),
    CONSTRAINT check_phone_format CHECK (((contact_phone IS NULL) OR (contact_phone = ''::text) OR (contact_phone ~ '^[\d\s\-\+\(\)]+$'::text))),
    CONSTRAINT check_phone_length CHECK (((contact_phone IS NULL) OR (char_length(contact_phone) <= 20))),
    CONSTRAINT check_skills_count CHECK (((skills IS NULL) OR (array_length(skills, 1) <= 20))),
    CONSTRAINT check_title_length CHECK (((title IS NULL) OR (char_length(title) <= 100)))
);


--
-- Name: profiles_safe; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.profiles_safe WITH (security_invoker='true') AS
 SELECT profiles.id,
    profiles.full_name,
    profiles.bio,
    profiles.avatar_url,
    profiles.title,
    profiles.location,
    profiles.linkedin_url,
    profiles.github_url,
    profiles.skills,
    profiles.interests,
    profiles.profession,
    profiles.company,
        CASE
            WHEN (profiles.contact_public = true) THEN profiles.contact_email
            ELSE NULL::text
        END AS contact_email,
        CASE
            WHEN (profiles.contact_public = true) THEN profiles.contact_phone
            ELSE NULL::text
        END AS contact_phone,
    profiles.is_public,
    profiles.approved,
    profiles.contact_public,
    profiles.onboarding_completed,
    profiles.endorsement_count,
    profiles.last_active_at,
    profiles.created_at,
    profiles.updated_at
   FROM public.profiles
  WHERE ((profiles.is_public = true) AND (profiles.approved = true));


--
-- Name: skill_revenue_ledger; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.skill_revenue_ledger (
    id bigint NOT NULL,
    use_event_id uuid NOT NULL,
    beneficiary_did text NOT NULL,
    beneficiary_role text NOT NULL,
    amount_cents bigint NOT NULL,
    currency text DEFAULT 'TEST_USD'::text NOT NULL,
    stripe_transfer_id text,
    settled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT skill_revenue_ledger_amount_cents_check CHECK ((amount_cents >= 0)),
    CONSTRAINT skill_revenue_ledger_beneficiary_role_check CHECK ((beneficiary_role = ANY (ARRAY['author'::text, 'advisor'::text, 'chapter'::text])))
);


--
-- Name: TABLE skill_revenue_ledger; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.skill_revenue_ledger IS 'Revenue split ledger. Rows are inserted atomically with their parent use_event. Integer cents only. Sum of rows per use_event equals the event gross_cents (enforced by skill_revenue.record_skill_use).';


--
-- Name: skill_revenue_ledger_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.skill_revenue_ledger_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: skill_revenue_ledger_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.skill_revenue_ledger_id_seq OWNED BY public.skill_revenue_ledger.id;


--
-- Name: skill_use_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.skill_use_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chapter_id text NOT NULL,
    skill_id text NOT NULL,
    skill_version text NOT NULL,
    used_by_agent_id text NOT NULL,
    used_by_did text,
    tool_name text NOT NULL,
    gross_cents bigint NOT NULL,
    attestor_count integer NOT NULL,
    success boolean DEFAULT true NOT NULL,
    duration_ms integer,
    idempotency_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT skill_use_events_attestor_count_check CHECK ((attestor_count >= 1)),
    CONSTRAINT skill_use_events_gross_cents_check CHECK ((gross_cents > 0))
);


--
-- Name: TABLE skill_use_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.skill_use_events IS 'One row per attested-skill tool invocation. idempotency_key prevents replay. Unattested skills do not write rows (attested-only earns per Phase A locked decision).';


--
-- Name: trust_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trust_events (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    event_type text NOT NULL,
    source_agent_id text,
    source_event_id text,
    delta numeric(6,3) NOT NULL,
    reason text,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT trust_events_no_self CHECK (((source_agent_id IS NULL) OR (source_agent_id <> agent_id)))
);


--
-- Name: trust_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.trust_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: trust_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.trust_events_id_seq OWNED BY public.trust_events.id;


--
-- Name: broadcast_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.broadcast_log ALTER COLUMN id SET DEFAULT nextval('public.broadcast_log_id_seq'::regclass);


--
-- Name: endorsements id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endorsements ALTER COLUMN id SET DEFAULT nextval('public.endorsements_id_seq'::regclass);


--
-- Name: event_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_log ALTER COLUMN id SET DEFAULT nextval('public.event_log_id_seq'::regclass);


--
-- Name: federation_inbound_seen id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_seen ALTER COLUMN id SET DEFAULT nextval('public.federation_inbound_seen_id_seq'::regclass);


--
-- Name: skill_revenue_ledger id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skill_revenue_ledger ALTER COLUMN id SET DEFAULT nextval('public.skill_revenue_ledger_id_seq'::regclass);


--
-- Name: trust_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_events ALTER COLUMN id SET DEFAULT nextval('public.trust_events_id_seq'::regclass);


--
-- Name: agent_action_outcomes agent_action_outcomes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_outcomes
    ADD CONSTRAINT agent_action_outcomes_pkey PRIMARY KEY (id);


--
-- Name: agent_activity agent_activity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_activity
    ADD CONSTRAINT agent_activity_pkey PRIMARY KEY (id);


--
-- Name: agent_api_keys agent_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_pkey PRIMARY KEY (id);


--
-- Name: agent_api_keys agent_api_keys_profile_id_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_profile_id_provider_key UNIQUE (profile_id, provider);


--
-- Name: agent_authority_scope agent_authority_scope_agent_id_action_kind_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_authority_scope
    ADD CONSTRAINT agent_authority_scope_agent_id_action_kind_key UNIQUE (agent_id, action_kind);


--
-- Name: agent_authority_scope agent_authority_scope_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_authority_scope
    ADD CONSTRAINT agent_authority_scope_pkey PRIMARY KEY (id);


--
-- Name: agent_authority_usage agent_authority_usage_agent_id_action_kind_window_kind_wind_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_authority_usage
    ADD CONSTRAINT agent_authority_usage_agent_id_action_kind_window_kind_wind_key UNIQUE (agent_id, action_kind, window_kind, window_start);


--
-- Name: agent_authority_usage agent_authority_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_authority_usage
    ADD CONSTRAINT agent_authority_usage_pkey PRIMARY KEY (id);


--
-- Name: agent_conversation_threads agent_conversation_threads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversation_threads
    ADD CONSTRAINT agent_conversation_threads_pkey PRIMARY KEY (id);


--
-- Name: agent_conversations agent_conversations_agent_id_conversation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_agent_id_conversation_id_key UNIQUE (agent_id, conversation_id);


--
-- Name: agent_conversations agent_conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_pkey PRIMARY KEY (id);


--
-- Name: agent_digests agent_digests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_digests
    ADD CONSTRAINT agent_digests_pkey PRIMARY KEY (id);


--
-- Name: agent_events agent_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_events
    ADD CONSTRAINT agent_events_pkey PRIMARY KEY (id);


--
-- Name: agent_evolution_log agent_evolution_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_evolution_log
    ADD CONSTRAINT agent_evolution_log_pkey PRIMARY KEY (id);


--
-- Name: agent_facts agent_facts_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_facts
    ADD CONSTRAINT agent_facts_agent_id_key UNIQUE (agent_id);


--
-- Name: agent_facts agent_facts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_facts
    ADD CONSTRAINT agent_facts_pkey PRIMARY KEY (id);


--
-- Name: agent_intent_responses agent_intent_responses_intent_id_responder_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_intent_responses
    ADD CONSTRAINT agent_intent_responses_intent_id_responder_agent_id_key UNIQUE (intent_id, responder_agent_id);


--
-- Name: agent_intent_responses agent_intent_responses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_intent_responses
    ADD CONSTRAINT agent_intent_responses_pkey PRIMARY KEY (id);


--
-- Name: agent_intents agent_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_intents
    ADD CONSTRAINT agent_intents_pkey PRIMARY KEY (id);


--
-- Name: agent_knowledge agent_knowledge_chapter_agent_id_knowledge_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_knowledge
    ADD CONSTRAINT agent_knowledge_chapter_agent_id_knowledge_type_key UNIQUE (chapter_agent_id, knowledge_type);


--
-- Name: agent_knowledge agent_knowledge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_knowledge
    ADD CONSTRAINT agent_knowledge_pkey PRIMARY KEY (id);


--
-- Name: agent_member_activity agent_member_activity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_member_activity
    ADD CONSTRAINT agent_member_activity_pkey PRIMARY KEY (id);


--
-- Name: agent_memory agent_memory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_memory
    ADD CONSTRAINT agent_memory_pkey PRIMARY KEY (id);


--
-- Name: agent_private_memory agent_private_memory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_private_memory
    ADD CONSTRAINT agent_private_memory_pkey PRIMARY KEY (id);


--
-- Name: agent_projections agent_projections_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_projections
    ADD CONSTRAINT agent_projections_agent_id_key UNIQUE (agent_id);


--
-- Name: agent_projections agent_projections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_projections
    ADD CONSTRAINT agent_projections_pkey PRIMARY KEY (id);


--
-- Name: agent_sessions agent_sessions_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_sessions
    ADD CONSTRAINT agent_sessions_agent_id_key UNIQUE (agent_id);


--
-- Name: agent_sessions agent_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_sessions
    ADD CONSTRAINT agent_sessions_pkey PRIMARY KEY (id);


--
-- Name: agent_settings agent_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_settings
    ADD CONSTRAINT agent_settings_pkey PRIMARY KEY (agent_id);


--
-- Name: agent_thoughts agent_thoughts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_thoughts
    ADD CONSTRAINT agent_thoughts_pkey PRIMARY KEY (id);


--
-- Name: agents agents_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_agent_id_key UNIQUE (agent_id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: arp_receipts arp_receipts_issuer_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arp_receipts
    ADD CONSTRAINT arp_receipts_issuer_id_unique UNIQUE (issuer_did, receipt_id);


--
-- Name: arp_receipts arp_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arp_receipts
    ADD CONSTRAINT arp_receipts_pkey PRIMARY KEY (id);


--
-- Name: broadcast_log broadcast_log_chapter_id_broadcast_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.broadcast_log
    ADD CONSTRAINT broadcast_log_chapter_id_broadcast_id_key UNIQUE (chapter_id, broadcast_id);


--
-- Name: broadcast_log broadcast_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.broadcast_log
    ADD CONSTRAINT broadcast_log_pkey PRIMARY KEY (id);


--
-- Name: chapter_audit_events chapter_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_audit_events
    ADD CONSTRAINT chapter_audit_events_pkey PRIMARY KEY (id);


--
-- Name: chapter_channel_connections chapter_channel_connections_agent_id_kind_remote_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_channel_connections
    ADD CONSTRAINT chapter_channel_connections_agent_id_kind_remote_id_key UNIQUE (agent_id, kind, remote_id);


--
-- Name: chapter_channel_connections chapter_channel_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_channel_connections
    ADD CONSTRAINT chapter_channel_connections_pkey PRIMARY KEY (id);


--
-- Name: chapter_federation_allowlist chapter_federation_allowlist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_federation_allowlist
    ADD CONSTRAINT chapter_federation_allowlist_pkey PRIMARY KEY (chapter_id, peer_chapter_id);


--
-- Name: chapter_keys chapter_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_keys
    ADD CONSTRAINT chapter_keys_pkey PRIMARY KEY (chapter_id);


--
-- Name: chapter_members chapter_members_chapter_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_members
    ADD CONSTRAINT chapter_members_chapter_id_user_id_key UNIQUE (chapter_id, user_id);


--
-- Name: chapter_members chapter_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_members
    ADD CONSTRAINT chapter_members_pkey PRIMARY KEY (id);


--
-- Name: chapter_policy chapter_policy_chapter_id_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_policy
    ADD CONSTRAINT chapter_policy_chapter_id_key_key UNIQUE (chapter_id, key);


--
-- Name: chapter_policy_history chapter_policy_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_policy_history
    ADD CONSTRAINT chapter_policy_history_pkey PRIMARY KEY (id);


--
-- Name: chapter_policy chapter_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_policy
    ADD CONSTRAINT chapter_policy_pkey PRIMARY KEY (id);


--
-- Name: chapter_role_nominations chapter_role_nominations_nominee_agent_id_chapter_id_target_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_role_nominations
    ADD CONSTRAINT chapter_role_nominations_nominee_agent_id_chapter_id_target_key UNIQUE (nominee_agent_id, chapter_id, target_role, status) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: chapter_role_nominations chapter_role_nominations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_role_nominations
    ADD CONSTRAINT chapter_role_nominations_pkey PRIMARY KEY (id);


--
-- Name: chapter_skill_attestations chapter_skill_attestations_chapter_id_skill_id_skill_versio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_attestations
    ADD CONSTRAINT chapter_skill_attestations_chapter_id_skill_id_skill_versio_key UNIQUE (chapter_id, skill_id, skill_version, attestor_did);


--
-- Name: chapter_skill_attestations chapter_skill_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_attestations
    ADD CONSTRAINT chapter_skill_attestations_pkey PRIMARY KEY (id);


--
-- Name: chapter_skill_installs chapter_skill_installs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_installs
    ADD CONSTRAINT chapter_skill_installs_pkey PRIMARY KEY (agent_id, skill_id);


--
-- Name: chapter_skill_reviews chapter_skill_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_reviews
    ADD CONSTRAINT chapter_skill_reviews_pkey PRIMARY KEY (id);


--
-- Name: chapter_skill_reviews chapter_skill_reviews_skill_id_reviewer_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_reviews
    ADD CONSTRAINT chapter_skill_reviews_skill_id_reviewer_agent_id_key UNIQUE (skill_id, reviewer_agent_id);


--
-- Name: chapter_skills chapter_skills_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skills
    ADD CONSTRAINT chapter_skills_pkey PRIMARY KEY (id);


--
-- Name: chapter_sso_configs chapter_sso_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_sso_configs
    ADD CONSTRAINT chapter_sso_configs_pkey PRIMARY KEY (chapter_id);


--
-- Name: chapters chapters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapters
    ADD CONSTRAINT chapters_pkey PRIMARY KEY (id);


--
-- Name: chapters chapters_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapters
    ADD CONSTRAINT chapters_slug_key UNIQUE (slug);


--
-- Name: chronicles chronicles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chronicles
    ADD CONSTRAINT chronicles_pkey PRIMARY KEY (principal_did, chronicle_date);


--
-- Name: comments comments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);


--
-- Name: connections connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);


--
-- Name: connections connections_requester_id_recipient_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_requester_id_recipient_id_key UNIQUE (requester_id, recipient_id);


--
-- Name: endorsements endorsements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endorsements
    ADD CONSTRAINT endorsements_pkey PRIMARY KEY (id);


--
-- Name: endorsements endorsements_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endorsements
    ADD CONSTRAINT endorsements_unique_pair UNIQUE (endorser_agent_id, endorsee_agent_id);


--
-- Name: event_log event_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_log
    ADD CONSTRAINT event_log_pkey PRIMARY KEY (id);


--
-- Name: event_subscriptions event_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_subscriptions
    ADD CONSTRAINT event_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: federation_inbound_seen federation_inbound_seen_origin_chapter_id_broadcast_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_seen
    ADD CONSTRAINT federation_inbound_seen_origin_chapter_id_broadcast_id_key UNIQUE (origin_chapter_id, broadcast_id);


--
-- Name: federation_inbound_seen federation_inbound_seen_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_seen
    ADD CONSTRAINT federation_inbound_seen_pkey PRIMARY KEY (id);


--
-- Name: federation_knowledge federation_knowledge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_knowledge
    ADD CONSTRAINT federation_knowledge_pkey PRIMARY KEY (id);


--
-- Name: federation_knowledge federation_knowledge_source_chapter_id_receiving_chapter_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_knowledge
    ADD CONSTRAINT federation_knowledge_source_chapter_id_receiving_chapter_id_key UNIQUE (source_chapter_id, receiving_chapter_id);


--
-- Name: federation_policy federation_policy_chapter_id_peer_chapter_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_policy
    ADD CONSTRAINT federation_policy_chapter_id_peer_chapter_id_key UNIQUE (chapter_id, peer_chapter_id);


--
-- Name: federation_policy_history federation_policy_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_policy_history
    ADD CONSTRAINT federation_policy_history_pkey PRIMARY KEY (id);


--
-- Name: federation_policy federation_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_policy
    ADD CONSTRAINT federation_policy_pkey PRIMARY KEY (id);


--
-- Name: group_members group_members_group_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_group_id_user_id_key UNIQUE (group_id, user_id);


--
-- Name: group_members group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_pkey PRIMARY KEY (id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: member_key_rotations member_key_rotations_chapter_id_nonce_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.member_key_rotations
    ADD CONSTRAINT member_key_rotations_chapter_id_nonce_key UNIQUE (chapter_id, nonce);


--
-- Name: member_key_rotations member_key_rotations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.member_key_rotations
    ADD CONSTRAINT member_key_rotations_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);


--
-- Name: org_invites org_invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_invites
    ADD CONSTRAINT org_invites_pkey PRIMARY KEY (token);


--
-- Name: pending_approvals pending_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_approvals
    ADD CONSTRAINT pending_approvals_pkey PRIMARY KEY (id);


--
-- Name: profiles profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (id);


--
-- Name: skill_revenue_ledger skill_revenue_ledger_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skill_revenue_ledger
    ADD CONSTRAINT skill_revenue_ledger_pkey PRIMARY KEY (id);


--
-- Name: skill_use_events skill_use_events_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skill_use_events
    ADD CONSTRAINT skill_use_events_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: skill_use_events skill_use_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skill_use_events
    ADD CONSTRAINT skill_use_events_pkey PRIMARY KEY (id);


--
-- Name: trust_events trust_events_idempotent; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_events
    ADD CONSTRAINT trust_events_idempotent UNIQUE (agent_id, event_type, source_event_id);


--
-- Name: trust_events trust_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_events
    ADD CONSTRAINT trust_events_pkey PRIMARY KEY (id);


--
-- Name: event_log_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_log_created_idx ON public.event_log USING btree (created_at DESC);


--
-- Name: event_log_publisher_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_log_publisher_idx ON public.event_log USING btree (publisher_agent_id, created_at DESC);


--
-- Name: event_log_type_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_log_type_id_idx ON public.event_log USING btree (event_type, id DESC);


--
-- Name: event_subscriptions_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_subscriptions_expires_idx ON public.event_subscriptions USING btree (expires_at) WHERE (active = true);


--
-- Name: event_subscriptions_subscriber_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_subscriptions_subscriber_idx ON public.event_subscriptions USING btree (subscriber_agent_id, active);


--
-- Name: event_subscriptions_topics_gin_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_subscriptions_topics_gin_idx ON public.event_subscriptions USING gin (topics);


--
-- Name: idx_agent_activity_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_activity_chapter ON public.agent_activity USING btree (chapter_agent_id);


--
-- Name: idx_agent_activity_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_activity_created ON public.agent_activity USING btree (created_at DESC);


--
-- Name: idx_agent_convos_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_convos_agent ON public.agent_conversations USING btree (agent_id);


--
-- Name: idx_agent_convos_convo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_convos_convo_id ON public.agent_conversations USING btree (conversation_id);


--
-- Name: idx_agent_keys_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_keys_profile ON public.agent_api_keys USING btree (profile_id);


--
-- Name: idx_agent_memory_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_memory_expiry ON public.agent_memory USING btree (expires_at);


--
-- Name: idx_agent_memory_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_memory_lookup ON public.agent_memory USING btree (chapter_agent_id, memory_type, memory_key);


--
-- Name: idx_agent_settings_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_settings_updated ON public.agent_settings USING btree (updated_at DESC);


--
-- Name: idx_agent_thoughts_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_thoughts_chapter ON public.agent_thoughts USING btree (chapter_agent_id);


--
-- Name: idx_agent_thoughts_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_thoughts_created ON public.agent_thoughts USING btree (created_at DESC);


--
-- Name: idx_agent_thoughts_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_thoughts_type ON public.agent_thoughts USING btree (thought_type);


--
-- Name: idx_agents_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_agent_id ON public.agents USING btree (agent_id);


--
-- Name: idx_agents_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_chapter ON public.agents USING btree (chapter_id);


--
-- Name: idx_agents_origin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_origin ON public.agents USING btree (origin) WHERE (origin <> 'sovereign'::text);


--
-- Name: idx_agents_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_profile ON public.agents USING btree (profile_id);


--
-- Name: idx_agents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_status ON public.agents USING btree (status);


--
-- Name: idx_arp_receipts_chain_link; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_arp_receipts_chain_link ON public.arp_receipts USING btree (chain_link);


--
-- Name: idx_arp_receipts_issuer_did; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_arp_receipts_issuer_did ON public.arp_receipts USING btree (issuer_did, issued_at DESC);


--
-- Name: idx_arp_receipts_principal_did; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_arp_receipts_principal_did ON public.arp_receipts USING btree (principal_did, issued_at DESC);


--
-- Name: idx_attest_by_attestor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attest_by_attestor ON public.chapter_skill_attestations USING btree (attestor_did) WHERE (revoked_at IS NULL);


--
-- Name: idx_attest_live_by_skill; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attest_live_by_skill ON public.chapter_skill_attestations USING btree (chapter_id, skill_id, skill_version) WHERE (revoked_at IS NULL);


--
-- Name: idx_authority_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authority_agent ON public.agent_authority_scope USING btree (agent_id, action_kind);


--
-- Name: idx_authority_usage_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authority_usage_lookup ON public.agent_authority_usage USING btree (agent_id, action_kind, window_kind, window_start DESC);


--
-- Name: idx_broadcast_log_broadcast_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_broadcast_log_broadcast_id ON public.broadcast_log USING btree (broadcast_id);


--
-- Name: idx_broadcast_log_chapter_sent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_broadcast_log_chapter_sent ON public.broadcast_log USING btree (chapter_id, sent_at DESC);


--
-- Name: idx_channel_conns_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channel_conns_agent ON public.chapter_channel_connections USING btree (agent_id, kind);


--
-- Name: idx_channel_conns_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_channel_conns_kind ON public.chapter_channel_connections USING btree (kind, status);


--
-- Name: idx_chapter_allowlist_peer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_allowlist_peer ON public.chapter_federation_allowlist USING btree (peer_chapter_id);


--
-- Name: idx_chapter_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_audit_action ON public.chapter_audit_events USING btree (action, occurred_at DESC);


--
-- Name: idx_chapter_audit_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_audit_actor ON public.chapter_audit_events USING btree (actor_agent_id, occurred_at DESC);


--
-- Name: idx_chapter_audit_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_audit_chapter ON public.chapter_audit_events USING btree (chapter_id, occurred_at DESC);


--
-- Name: idx_chapter_skill_installs_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skill_installs_agent ON public.chapter_skill_installs USING btree (agent_id) WHERE (uninstalled_at IS NULL);


--
-- Name: idx_chapter_skill_installs_skill; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skill_installs_skill ON public.chapter_skill_installs USING btree (skill_id, installed_at DESC);


--
-- Name: idx_chapter_skill_reviews_skill; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skill_reviews_skill ON public.chapter_skill_reviews USING btree (skill_id, created_at DESC);


--
-- Name: idx_chapter_skills_author; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skills_author ON public.chapter_skills USING btree (author_did);


--
-- Name: idx_chapter_skills_capabilities; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skills_capabilities ON public.chapter_skills USING gin (capabilities);


--
-- Name: idx_chapter_skills_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skills_chapter ON public.chapter_skills USING btree (chapter_id, created_at DESC);


--
-- Name: idx_chapter_skills_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skills_name ON public.chapter_skills USING btree (name);


--
-- Name: idx_chapter_skills_trust_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chapter_skills_trust_active ON public.chapter_skills USING btree (trust_score DESC) WHERE (revoked_at IS NULL);


--
-- Name: idx_chronicles_parent_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chronicles_parent_chapter ON public.chronicles USING btree (parent_chapter, chronicle_date DESC);


--
-- Name: idx_chronicles_principal_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chronicles_principal_recent ON public.chronicles USING btree (principal_did, chronicle_date DESC);


--
-- Name: idx_comments_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_comments_entity ON public.comments USING btree (entity_type, entity_id);


--
-- Name: idx_comments_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_comments_user ON public.comments USING btree (user_id);


--
-- Name: idx_connections_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_recipient ON public.connections USING btree (recipient_id);


--
-- Name: idx_connections_requester; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_requester ON public.connections USING btree (requester_id);


--
-- Name: idx_connections_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_status ON public.connections USING btree (status);


--
-- Name: idx_conv_threads_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conv_threads_chapter ON public.agent_conversation_threads USING btree (chapter_agent_id, status);


--
-- Name: idx_conv_threads_from; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conv_threads_from ON public.agent_conversation_threads USING btree (from_agent_id);


--
-- Name: idx_conv_threads_to; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conv_threads_to ON public.agent_conversation_threads USING btree (to_agent_id);


--
-- Name: idx_endorsements_endorsee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endorsements_endorsee ON public.endorsements USING btree (endorsee_agent_id, created_at DESC);


--
-- Name: idx_endorsements_endorser; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endorsements_endorser ON public.endorsements USING btree (endorser_agent_id, created_at DESC);


--
-- Name: idx_endorsements_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endorsements_live ON public.endorsements USING btree (endorsee_agent_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_evolution_log_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evolution_log_agent ON public.agent_evolution_log USING btree (agent_id, created_at DESC);


--
-- Name: idx_federation_inbound_seen_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_federation_inbound_seen_lookup ON public.federation_inbound_seen USING btree (origin_chapter_id, broadcast_id);


--
-- Name: idx_federation_knowledge_receiver; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_federation_knowledge_receiver ON public.federation_knowledge USING btree (receiving_chapter_id);


--
-- Name: idx_fedpolicy_chapter_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fedpolicy_chapter_state ON public.federation_policy USING btree (chapter_id, state);


--
-- Name: idx_fedpolicy_history_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fedpolicy_history_recent ON public.federation_policy_history USING btree (chapter_id, peer_chapter_id, created_at DESC);


--
-- Name: idx_fedpolicy_next_probe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fedpolicy_next_probe ON public.federation_policy USING btree (chapter_id, last_probe_at) WHERE (state = ANY (ARRAY['quarantined'::text, 'degraded'::text]));


--
-- Name: idx_intent_responses_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_responses_intent ON public.agent_intent_responses USING btree (intent_id);


--
-- Name: idx_intent_responses_responder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_responses_responder ON public.agent_intent_responses USING btree (responder_agent_id);


--
-- Name: idx_intents_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_chapter ON public.agent_intents USING btree (chapter_agent_id, status);


--
-- Name: idx_intents_requester; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_requester ON public.agent_intents USING btree (requester_agent_id);


--
-- Name: idx_ledger_by_beneficiary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ledger_by_beneficiary ON public.skill_revenue_ledger USING btree (beneficiary_did, created_at DESC);


--
-- Name: idx_ledger_by_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ledger_by_event ON public.skill_revenue_ledger USING btree (use_event_id);


--
-- Name: idx_member_activity_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_member_activity_agent ON public.agent_member_activity USING btree (agent_id, created_at DESC);


--
-- Name: idx_member_activity_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_member_activity_chapter ON public.agent_member_activity USING btree (chapter_agent_id, created_at DESC);


--
-- Name: idx_messages_image_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_image_url ON public.messages USING btree (image_url) WHERE (image_url IS NOT NULL);


--
-- Name: idx_nominations_chapter_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_nominations_chapter_status ON public.chapter_role_nominations USING btree (chapter_id, status, created_at DESC);


--
-- Name: idx_nominations_nominee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_nominations_nominee ON public.chapter_role_nominations USING btree (nominee_agent_id, status);


--
-- Name: idx_org_invites_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_invites_created_by ON public.org_invites USING btree (created_by, created_at DESC);


--
-- Name: idx_outcomes_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_outcomes_action ON public.agent_action_outcomes USING btree (action_id);


--
-- Name: idx_outcomes_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_outcomes_chapter ON public.agent_action_outcomes USING btree (chapter_agent_id, action_type);


--
-- Name: idx_pending_approvals_chapter_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_approvals_chapter_status ON public.pending_approvals USING btree (chapter_id, status, created_at DESC);


--
-- Name: idx_pending_approvals_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_approvals_expires ON public.pending_approvals USING btree (expires_at) WHERE (status = 'pending'::text);


--
-- Name: idx_pending_approvals_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_approvals_kind ON public.pending_approvals USING btree (chapter_id, kind, status);


--
-- Name: idx_policy_chapter_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_chapter_key ON public.chapter_policy USING btree (chapter_id, key);


--
-- Name: idx_policy_history_chapter_key_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_history_chapter_key_time ON public.chapter_policy_history USING btree (chapter_id, key, created_at DESC);


--
-- Name: idx_policy_tunable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_policy_tunable ON public.chapter_policy USING btree (chapter_id) WHERE ((auto_tuned = true) AND (pinned_by IS NULL));


--
-- Name: idx_private_memory_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_private_memory_agent ON public.agent_private_memory USING btree (agent_id, memory_type);


--
-- Name: idx_private_memory_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_private_memory_owner ON public.agent_private_memory USING btree (owner_id);


--
-- Name: idx_profiles_approved; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_approved ON public.profiles USING btree (approved);


--
-- Name: idx_profiles_endorsement_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_endorsement_count ON public.profiles USING btree (endorsement_count DESC);


--
-- Name: idx_profiles_interests; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_interests ON public.profiles USING gin (interests);


--
-- Name: idx_profiles_location; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_location ON public.profiles USING btree (location);


--
-- Name: idx_profiles_profession; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_profession ON public.profiles USING btree (profession);


--
-- Name: idx_profiles_skills; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_profiles_skills ON public.profiles USING gin (skills);


--
-- Name: idx_projections_chapter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projections_chapter ON public.agent_projections USING btree (chapter_agent_id);


--
-- Name: idx_projections_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projections_embedding ON public.agent_projections USING hnsw (embedding extensions.vector_cosine_ops);


--
-- Name: idx_rotations_chapter_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rotations_chapter_agent_time ON public.member_key_rotations USING btree (chapter_id, agent_id, recorded_at DESC);


--
-- Name: idx_trust_events_agent_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trust_events_agent_recent ON public.trust_events USING btree (agent_id, occurred_at DESC);


--
-- Name: idx_trust_events_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trust_events_source ON public.trust_events USING btree (source_agent_id, occurred_at DESC) WHERE (source_agent_id IS NOT NULL);


--
-- Name: idx_trust_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trust_events_type ON public.trust_events USING btree (event_type, occurred_at DESC);


--
-- Name: idx_use_events_by_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_use_events_by_agent ON public.skill_use_events USING btree (used_by_agent_id, created_at DESC);


--
-- Name: idx_use_events_by_skill; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_use_events_by_skill ON public.skill_use_events USING btree (chapter_id, skill_id, skill_version, created_at DESC);


--
-- Name: agent_api_keys agent_api_keys_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_api_keys_updated_at BEFORE UPDATE ON public.agent_api_keys FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: agent_conversations agent_conversations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_conversations_updated_at BEFORE UPDATE ON public.agent_conversations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: agent_facts agent_facts_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_facts_updated_at BEFORE UPDATE ON public.agent_facts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: agents agents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agents_updated_at BEFORE UPDATE ON public.agents FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: chapter_skill_installs trg_bump_install_count; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_bump_install_count AFTER INSERT ON public.chapter_skill_installs FOR EACH ROW EXECUTE FUNCTION public.bump_chapter_skill_stats();


--
-- Name: chapter_skill_reviews trg_bump_review_stats; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_bump_review_stats AFTER INSERT OR DELETE OR UPDATE ON public.chapter_skill_reviews FOR EACH ROW EXECUTE FUNCTION public.bump_chapter_skill_stats();


--
-- Name: agent_settings trg_touch_agent_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_touch_agent_settings_updated_at BEFORE UPDATE ON public.agent_settings FOR EACH ROW EXECUTE FUNCTION public.touch_agent_settings_updated_at();


--
-- Name: chapter_channel_connections trg_touch_channel_connections_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_touch_channel_connections_updated_at BEFORE UPDATE ON public.chapter_channel_connections FOR EACH ROW EXECUTE FUNCTION public.touch_channel_connections_updated_at();


--
-- Name: chapter_sso_configs trg_touch_chapter_sso_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_touch_chapter_sso_updated_at BEFORE UPDATE ON public.chapter_sso_configs FOR EACH ROW EXECUTE FUNCTION public.touch_chapter_sso_updated_at();


--
-- Name: trust_events trust_events_after_insert; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trust_events_after_insert AFTER INSERT ON public.trust_events FOR EACH ROW EXECUTE FUNCTION public.trust_events_apply_delta();


--
-- Name: chapters update_chapters_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_chapters_updated_at BEFORE UPDATE ON public.chapters FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: comments update_comments_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_comments_updated_at BEFORE UPDATE ON public.comments FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: connections update_connections_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_connections_updated_at BEFORE UPDATE ON public.connections FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: groups update_groups_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON public.groups FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: profiles update_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: agent_conversations agent_conversations_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_facts agent_facts_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_facts
    ADD CONSTRAINT agent_facts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_intent_responses agent_intent_responses_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_intent_responses
    ADD CONSTRAINT agent_intent_responses_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.agent_intents(id) ON DELETE CASCADE;


--
-- Name: chapter_members chapter_members_chapter_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_members
    ADD CONSTRAINT chapter_members_chapter_id_fkey FOREIGN KEY (chapter_id) REFERENCES public.chapters(id) ON DELETE CASCADE;


--
-- Name: chapter_members chapter_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_members
    ADD CONSTRAINT chapter_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: chapter_skill_installs chapter_skill_installs_skill_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_installs
    ADD CONSTRAINT chapter_skill_installs_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.chapter_skills(id) ON DELETE CASCADE;


--
-- Name: chapter_skill_reviews chapter_skill_reviews_skill_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapter_skill_reviews
    ADD CONSTRAINT chapter_skill_reviews_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.chapter_skills(id) ON DELETE CASCADE;


--
-- Name: chapters chapters_lead_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chapters
    ADD CONSTRAINT chapters_lead_id_fkey FOREIGN KEY (lead_id) REFERENCES public.profiles(id);


--
-- Name: connections connections_recipient_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: connections connections_requester_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES public.profiles(id) ON DELETE CASCADE;


--
-- Name: group_members group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: profiles profiles_referred_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles
    ADD CONSTRAINT profiles_referred_by_fkey FOREIGN KEY (referred_by) REFERENCES public.profiles(id);


--
-- Name: skill_revenue_ledger skill_revenue_ledger_use_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skill_revenue_ledger
    ADD CONSTRAINT skill_revenue_ledger_use_event_id_fkey FOREIGN KEY (use_event_id) REFERENCES public.skill_use_events(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--




-- ── CRM service verb (PR6): contacts, deals, interaction history ──────────
-- An ORG-SIDE record type, not a SaaS mirror. Every row carries chapter_id and
-- every query filters on it; a CRM that leaks across orgs is the advisor-
-- earnings hole in a different table.
CREATE TABLE IF NOT EXISTS public.crm_contacts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chapter_id  text NOT NULL,
    name        text NOT NULL,
    email       text,
    org         text,
    stage       text NOT NULL DEFAULT 'lead'
                CHECK (stage IN ('lead','qualified','customer','churned')),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_chapter ON public.crm_contacts(chapter_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS public.crm_deals (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chapter_id   text NOT NULL,
    contact_id   text NOT NULL,
    title        text NOT NULL,
    -- Integer MINOR units. Never a float: a deal value that drifts by a
    -- rounding step is a number nobody can reconcile against an invoice.
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency     text NOT NULL DEFAULT 'USD' CHECK (currency IN ('USD','EUR','GBP')),
    stage        text NOT NULL DEFAULT 'open' CHECK (stage IN ('open','won','lost')),
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_crm_deals_chapter ON public.crm_deals(chapter_id, updated_at DESC);

-- Append-only by construction: there is no update or delete verb for
-- interactions, because an edited history is not a history.
CREATE TABLE IF NOT EXISTS public.crm_interactions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chapter_id  text NOT NULL,
    contact_id  text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('call','email','meeting','note')),
    summary     text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_crm_interactions_contact ON public.crm_interactions(chapter_id, contact_id, occurred_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════
-- PR8 — durable per-agent memory for UNATTENDED SERVICE AGENTS
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Distinct from `agent_memory` above, and deliberately a separate table rather
-- than a column added to it. That one is keyed by `chapter_agent_id` — the
-- CHAPTER's own short-term dedup cache, with no per-agent scope at all. `dsar.py`
-- already records the consequence: "no per-member/subject column, so there is no
-- member-scoped agent_memory row to export or delete". Overloading it would
-- inherit that gap; this table carries `agent_id` from the start and is therefore
-- answerable to a DSAR request.
--
-- SCOPED ON TWO AXES. `chapter_id` keeps orgs apart; `agent_id` keeps the four
-- service agents apart from each other. Both are in the uniqueness constraint and
-- both are filtered on every read — an agent that can read a sibling's cursors can
-- steer it, and memory is replayed into future context, so cross-agent reach is a
-- steering primitive, not just a privacy leak.
CREATE TABLE IF NOT EXISTS public.service_agent_memory (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chapter_id   text NOT NULL,
    agent_id     text NOT NULL,
    memory_type  text NOT NULL
                 CHECK (memory_type IN ('cursor','dedup','note')),
    memory_key   text NOT NULL,
    memory_value jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- NULL means NO EXPIRY, and that is the considered departure from the
    -- chapter-side shape, which defaults to now() + 7 days. A cursor that
    -- silently expires makes an agent reprocess or skip a window with no error
    -- anywhere — the silent-wrong-answer class this program keeps finding. TTL
    -- is opt-in per entry: correct for `dedup`, wrong for `cursor`.
    expires_at   timestamptz
);

-- The upsert target. Remembering the same key twice is an update, not a second
-- row; an agent that accumulates duplicate cursors has no cursor.
CREATE UNIQUE INDEX IF NOT EXISTS uq_service_agent_memory_key
    ON public.service_agent_memory(chapter_id, agent_id, memory_type, memory_key);
CREATE INDEX IF NOT EXISTS idx_service_agent_memory_scope
    ON public.service_agent_memory(chapter_id, agent_id, updated_at DESC);

--
-- Name: agent_schedule; Type: TABLE; Schema: public (PR5 durable scheduler)
--

CREATE TABLE IF NOT EXISTS public.agent_schedule (
    agent_id             text PRIMARY KEY,
    next_run_at          timestamp with time zone NOT NULL DEFAULT now(),
    consecutive_failures integer NOT NULL DEFAULT 0,
    paused_reason        text,
    updated_at           timestamp with time zone NOT NULL DEFAULT now()
);

-- The scheduler's only hot query: "not paused, and due". Partial index because
-- paused rows are never selected and should not sit in the index.
CREATE INDEX IF NOT EXISTS agent_schedule_due_idx
    ON public.agent_schedule (next_run_at)
    WHERE paused_reason IS NULL;


--
-- Bounded operational grants
--

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

-- ── sm-federation §4 — the durable intelligence feed ────────────────────────
-- Mirrors infra/migrations/0005_federation_feed.sql, which carries this to
-- databases that already exist. Both must change together; the module that
-- ensures it at boot (server/federation_feed.py) reads the migration file, so
-- this copy and that one are compared by server/tests/test_federation_feed.py
-- rather than trusted to stay in step.
CREATE TABLE IF NOT EXISTS public.federation_feed_entries (
    seq          bigint NOT NULL,
    feed_id      text   NOT NULL,
    prev_hash    text,
    entry_hash   text   NOT NULL,
    issued_at    timestamptz NOT NULL,
    entry        jsonb  NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (feed_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS federation_feed_entries_hash_uq
    ON public.federation_feed_entries (entry_hash);
CREATE INDEX IF NOT EXISTS federation_feed_entries_seq_idx
    ON public.federation_feed_entries (feed_id, seq);

CREATE TABLE IF NOT EXISTS public.rate_limit_buckets (
    scope      text        NOT NULL PRIMARY KEY,
    buckets    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    saved_at   timestamptz NOT NULL DEFAULT now()
);
