-- 0002 — durable per-agent scheduling (PR5)
--
-- Holds the next run time per agent so a restart RESUMES a schedule instead of
-- re-deciding it. An in-process `asyncio.sleep` loses this on every restart,
-- which also re-synchronises the whole fleet to the same instant.
--
-- next_run_at is NOT NULL with a now() default: a freshly-inserted row is
-- immediately due. A nullable column would need NULLS FIRST ordering, and the
-- direct-Postgres layer's `_order` silently drops a `nullsfirst` suffix while
-- Postgres sorts NULLs LAST under ASC — never-run agents would have queued at
-- the back while the code read as if they were at the front.
--
-- paused_reason NOT NULL means "stopped, needs a human". It is the terminal
-- half of the retry discipline: a permanent failure must not be rescheduled at
-- any delay, because no delay makes a revoked key valid.
--
-- Idempotent: safe to re-run.

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
