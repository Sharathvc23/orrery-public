"""A cycle that could not have a different answer does not pay for one.

Measured before the change, driving twenty real think cycles and hashing the
request bodies:

    requests issued : 20
    distinct bodies : 1

PlannerContext is built from static config plus the skill catalogue, so the loop
rebuilds and re-sends an identical request forever by construction.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from community_member import llm_skip
from community_member.planner import PlannerContext, SemiTrustedContext, TrustedContext
from community_member.runtime.think_loop import think_v2

REPO = Path(__file__).resolve().parents[2]


# ── a fake provider that records every request body ──────────────────────────


class _Msg:
    tool_calls: list = []
    content = "no plan"


class _Choice:
    message = _Msg()


class _Resp:
    choices = [_Choice()]
    usage = None


class RecordingLLM:
    def __init__(self) -> None:
        self.bodies: list[str] = []
        outer = self

        class _Completions:
            def create(self, **kwargs):
                outer.bodies.append(
                    hashlib.sha256(json.dumps(kwargs, sort_keys=True, default=str).encode()).hexdigest()
                )
                return _Resp()

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


def _ctx(task: str = "Review the chapter and act on anything pending.") -> PlannerContext:
    return PlannerContext(
        user_task=task,
        trusted=TrustedContext(items=("you are the principal",)),
        semi_trusted=(),
        untrusted=(),
    )


def _cycles(llm, n: int, *, inputs, ctx=None):
    for _ in range(n):
        think_v2(
            ctx or _ctx(),
            llm,
            model="grok-3-mini",
            chapter_id="local:did:key:zTest",
            skip_inputs=inputs,
        )


@pytest.fixture(autouse=True)
def _clean_memo(monkeypatch):
    """One memo per test. A memo surviving into the next test would make a pass
    depend on execution order, which is the shape of a guard that stops guarding."""
    llm_skip.memo_store().clear()
    monkeypatch.delenv(llm_skip.SKIP_ENABLED_ENV, raising=False)
    monkeypatch.delenv(llm_skip.SKIP_MAX_AGE_ENV, raising=False)
    yield
    llm_skip.memo_store().clear()


# ── the saving ───────────────────────────────────────────────────────────────


def test_twenty_identical_cycles_issue_one_request(tmp_path):
    llm = RecordingLLM()
    _cycles(llm, 20, inputs=llm_skip.SkipInputs())

    assert len(llm.bodies) == 1, f"{len(llm.bodies)} requests were issued, not 1"
    assert len(set(llm.bodies)) == 1


def test_twenty_identical_consent_prompts_issue_one_request(tmp_path):
    """The with-proposal variant: the same consent question, repeated."""
    ctx = PlannerContext(
        user_task="A pending intent needs your approval.",
        trusted=TrustedContext(items=("chapter intent: publish the weekly note",)),
        semi_trusted=(SemiTrustedContext(source="chapter", items=("intent-42 awaiting approval",)),),
        untrusted=(),
    )
    llm = RecordingLLM()
    _cycles(llm, 20, inputs=llm_skip.SkipInputs(), ctx=ctx)

    assert len(llm.bodies) == 1, f"{len(llm.bodies)} requests were issued, not 1"


def test_the_flag_is_the_rollback_and_it_works(monkeypatch):
    """LLM_SKIP_ENABLED=0 returns the loop to twenty requests.

    Read per call rather than cached, so the rollback does not need a restart.
    """
    monkeypatch.setenv(llm_skip.SKIP_ENABLED_ENV, "0")
    llm = RecordingLLM()
    _cycles(llm, 20, inputs=llm_skip.SkipInputs())

    assert len(llm.bodies) == 20, f"the flag did not disable skipping: {len(llm.bodies)} requests"


def test_no_skip_inputs_means_no_skip():
    """The unsafe case requires no argument, so it must be the one that pays.

    A caller that cannot say what its external state is cannot be given a safe
    skip — defaulting it on would make the wedge the easy path.
    """
    llm = RecordingLLM()
    _cycles(llm, 5, inputs=None)
    assert len(llm.bodies) == 5


# ── the key releases when the answer could differ ────────────────────────────


def test_a_changed_prompt_releases_the_skip():
    llm = RecordingLLM()
    inputs = llm_skip.SkipInputs()
    _cycles(llm, 3, inputs=inputs)
    assert len(llm.bodies) == 1

    _cycles(llm, 3, inputs=inputs, ctx=_ctx("Something else entirely."))
    assert len(llm.bodies) == 2, "a different prompt was answered from the memo"


def test_a_pending_intent_injected_mid_run_releases_the_skip():
    """The case the watermark exists for, from the prompt side."""
    llm = RecordingLLM()
    inputs = llm_skip.SkipInputs()
    _cycles(llm, 5, inputs=inputs)
    assert len(llm.bodies) == 1

    with_intent = PlannerContext(
        user_task="Review the chapter and act on anything pending.",
        trusted=TrustedContext(items=("you are the principal",)),
        semi_trusted=(SemiTrustedContext(source="chapter", items=("intent-99 awaiting approval",)),),
        untrusted=(),
    )
    _cycles(llm, 1, inputs=inputs, ctx=with_intent)
    assert len(llm.bodies) == 2, "a newly pending intent was answered from the memo"


def test_a_drained_inbox_message_releases_the_skip():
    """State that changes the outcome without changing one byte of the prompt."""
    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs(inbox_drained=0))
    assert len(llm.bodies) == 1

    _cycles(llm, 1, inputs=llm_skip.SkipInputs(inbox_drained=1))
    assert len(llm.bodies) == 2, "a drained inbound message did not release the skip"


def test_a_different_model_is_not_answered_from_the_memo():
    """model is on the wire, so it is in the key."""
    llm = RecordingLLM()
    inputs = llm_skip.SkipInputs()
    _cycles(llm, 3, inputs=inputs)
    assert len(llm.bodies) == 1

    think_v2(_ctx(), llm, model="a-different-model", chapter_id="local:x", skip_inputs=inputs)
    assert len(llm.bodies) == 2, "a different model was answered from another model's reply"


def test_the_forced_refresh_bounds_a_wedged_skip(monkeypatch):
    """LLM_SKIP_MAX_AGE_S caps how long a memo can be served.

    Bounded is not the same as absent, which is why this is asserted rather than
    argued: with the age at zero every cycle is a real call.
    """
    monkeypatch.setenv(llm_skip.SKIP_MAX_AGE_ENV, "0")
    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs())
    assert len(llm.bodies) == 5, "a zero max age still served memos"


# ── the graduation counter must keep advancing ───────────────────────────────


def _graduation_db(tmp_path: Path) -> Path:
    db = tmp_path / "graduations.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE graduations ("
            "device_did TEXT NOT NULL, capability TEXT NOT NULL, scope TEXT NOT NULL, "
            "context_sha256 TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'observing', "
            "graduated_at TEXT, revoked_at TEXT, "
            "PRIMARY KEY (device_did, capability, scope, context_sha256))"
        )
    return db


def test_a_graduation_promotion_releases_the_skip(tmp_path):
    """⚠️ Capability graduation promotes after five approvals, and the promotion
    is an UPDATE IN PLACE — the row count and the maximum rowid both hold steady
    across it.

    A rowid watermark would therefore not move on exactly the transition that
    changes what the agent may do without changing what it would ask. If skipping
    hid that, this unit would silently alter the consent model, so it is asserted
    directly rather than inferred from the design.
    """
    db = _graduation_db(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO graduations (device_did, capability, scope, context_sha256, state) "
            "VALUES ('did:key:z1', 'web.fetch', 'scope-a', 'ctx-1', 'observing')"
        )

    before_rows = llm_skip.graduation_watermark(db)

    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs(graduation_db=db))
    assert len(llm.bodies) == 1

    # the promotion: an in-place UPDATE, no new row
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE graduations SET state='graduated', graduated_at='2026-08-24T00:00:00Z'")
        count_after = conn.execute("SELECT COUNT(*), MAX(rowid) FROM graduations").fetchone()

    assert count_after == (1, 1), "the promotion changed the row count or rowid; re-check this test"
    assert llm_skip.graduation_watermark(db) != before_rows, (
        "the watermark did not move across an in-place promotion — a rowid watermark would not have"
    )

    _cycles(llm, 1, inputs=llm_skip.SkipInputs(graduation_db=db))
    assert len(llm.bodies) == 2, "a capability graduation was hidden behind a skip"


def test_a_revocation_releases_the_skip(tmp_path):
    """Also an in-place update, and it narrows what the agent may do."""
    db = _graduation_db(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO graduations (device_did, capability, scope, context_sha256, state, graduated_at) "
            "VALUES ('did:key:z1', 'web.fetch', 'scope-a', 'ctx-1', 'graduated', '2026-08-01T00:00:00Z')"
        )

    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs(graduation_db=db))
    assert len(llm.bodies) == 1

    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE graduations SET state='revoked', revoked_at='2026-08-24T00:00:00Z'")

    _cycles(llm, 1, inputs=llm_skip.SkipInputs(graduation_db=db))
    assert len(llm.bodies) == 2, "a revocation was hidden behind a skip"


def test_a_consent_event_releases_the_skip(tmp_path):
    db = tmp_path / "consent.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE consent_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "chapter_id TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, "
            "occurred_at TEXT NOT NULL, event_sha256 TEXT NOT NULL UNIQUE)"
        )

    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs(consent_db=db))
    assert len(llm.bodies) == 1

    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO consent_events (chapter_id, action, outcome, occurred_at, event_sha256) "
            "VALUES ('local:x', 'approve', 'approved', '2026-08-24T00:00:00Z', 'sha-1')"
        )

    _cycles(llm, 1, inputs=llm_skip.SkipInputs(consent_db=db))
    assert len(llm.bodies) == 2, "a consent approval was hidden behind a skip"


def test_an_unreadable_store_is_not_read_as_an_empty_one(tmp_path):
    """Zero is a real state. Folding an error into it produces a wrong skip."""
    assert llm_skip.consent_watermark(tmp_path / "nope.db") == "absent"

    broken = tmp_path / "broken.db"
    broken.write_text("this is not a database")
    mark = llm_skip.consent_watermark(broken)
    assert mark.startswith("unreadable:"), mark
    assert mark != "absent"


# ── the key itself ───────────────────────────────────────────────────────────


def test_canonical_is_stable_across_pythonhashseed():
    """Two processes with different seeds must agree, or the skip is intermittent.

    Run in subprocesses rather than by monkeypatching, because PYTHONHASHSEED is
    read by the interpreter at startup and setting it in-process proves nothing.
    """
    script = textwrap.dedent(
        """
        import sys
        sys.path.insert(0, sys.argv[1])
        from community_member import llm_skip
        from community_member.planner import PlannerContext, SemiTrustedContext, TrustedContext

        ctx = PlannerContext(
            user_task="stable?",
            trusted=TrustedContext(items=("a", "b")),
            semi_trusted=(SemiTrustedContext(source="chapter", items=("x", "y")),),
            untrusted=(),
        )
        print(llm_skip.plan_key(ctx, model="m", max_tokens=800, inputs=llm_skip.SkipInputs()))
        """
    )
    keys = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", script, str(REPO / "agent")],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        keys.add(out.stdout.strip())
    assert len(keys) == 1, f"the key varies with PYTHONHASHSEED: {keys}"


def test_reordering_bundles_changes_the_key():
    """Order is preserved, not sorted: the prompt indexes items [S0], [S1], so
    reordering changes what the model sees and must change the key."""
    a = PlannerContext(
        user_task="t",
        trusted=TrustedContext(),
        semi_trusted=(
            SemiTrustedContext(source="one", items=("x",)),
            SemiTrustedContext(source="two", items=("y",)),
        ),
        untrusted=(),
    )
    b = PlannerContext(
        user_task="t",
        trusted=TrustedContext(),
        semi_trusted=(
            SemiTrustedContext(source="two", items=("y",)),
            SemiTrustedContext(source="one", items=("x",)),
        ),
        untrusted=(),
    )
    inputs = llm_skip.SkipInputs()
    assert llm_skip.plan_key(a, model="m", max_tokens=1, inputs=inputs) != llm_skip.plan_key(
        b, model="m", max_tokens=1, inputs=inputs
    )


def test_the_key_covers_the_rendered_prompt_by_construction():
    """The coverage guarantee, asserted rather than argued.

    The stated risk is an input reaching the prompt without reaching the key. An
    enumeration of fields would close that only until the next field is added, so
    canonical() embeds the rendered prompt verbatim — anything _render_context
    emits is in the key because it is in that string.
    """
    from community_member.planner_llm import _render_context

    ctx = _ctx()
    rendered = _render_context(ctx)
    # canonical() is JSON, so the prompt is carried escaped — decode rather than
    # substring-matching, which would pass or fail on escaping rather than on
    # whether the prompt is actually covered.
    carried = json.loads(llm_skip.canonical(ctx))
    assert carried["rendered"] == rendered, "the rendered prompt is not carried in the key material"

    # and a change only visible in the rendered output still moves the key
    inputs = llm_skip.SkipInputs()
    before = llm_skip.plan_key(ctx, model="m", max_tokens=1, inputs=inputs)
    after = llm_skip.plan_key(ctx, model="m", max_tokens=1, inputs=inputs, rendered=rendered + "\nNEW SECTION")
    assert before != after


def test_the_plan_key_is_not_the_context_sha256(tmp_path):
    """⚠️ context_sha256 exists for graduation scoping. Overloading it would
    couple two values that must be free to diverge."""
    from community_member import habits

    ctx = _ctx()
    key = llm_skip.plan_key(ctx, model="m", max_tokens=800, inputs=llm_skip.SkipInputs())

    # whatever context_sha256 is derived from, it is not this
    assert key != hashlib.sha256(ctx.user_task.encode()).hexdigest()
    assert "context_sha256" not in llm_skip.canonical(ctx)
    assert habits is not None  # the module exists; the two values live apart


# ── the skip is counted ──────────────────────────────────────────────────────


def test_every_skip_is_counted_with_its_reason(tmp_path, monkeypatch):
    """A skip that is not counted cannot be defended, and a regression in it
    cannot be seen. The meter was sequenced ahead of this unit for that reason."""
    from community_member import llm_meter

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    llm_meter.reset()

    llm = RecordingLLM()
    _cycles(llm, 20, inputs=llm_skip.SkipInputs())

    snapshot = llm_meter.spend()
    totals = snapshot["totals"]
    assert len(llm.bodies) == 1
    assert totals["calls_skipped"] == 19, f"19 skips expected, meter says {totals['calls_skipped']}"
    assert llm_skip.SKIP_REASON in totals["skip_reason"], totals["skip_reason"]
    assert totals["skip_reason"][llm_skip.SKIP_REASON] == 19
    # calls_made is NOT asserted here: the real call is metered by the provider
    # call site, which this fake never reaches. Asserting it would be asserting
    # another unit's behaviour through this one.


def test_a_skip_streak_is_observable(tmp_path):
    """The wedge is bounded at six hours, and bounded is not absent — so the
    streak has to be readable rather than the skip being silent."""
    llm = RecordingLLM()
    _cycles(llm, 12, inputs=llm_skip.SkipInputs())

    memo = llm_skip.memo_store().peek()
    assert memo is not None
    assert memo.streak == 11, f"the streak did not track the skips: {memo.streak}"


def test_a_meter_failure_does_not_stop_a_cycle(monkeypatch):
    """Telemetry must not be able to break the thing it measures."""
    from community_member import llm_meter

    def _boom(**kwargs):
        raise RuntimeError("meter is down")

    monkeypatch.setattr(llm_meter, "record_skip", _boom)
    llm = RecordingLLM()
    _cycles(llm, 5, inputs=llm_skip.SkipInputs())
    assert len(llm.bodies) == 1, "a broken meter changed the skip behaviour"


def test_two_callers_do_not_serve_each_other_a_memo():
    """A memo belongs to an agent, not to the process.

    Found by the existing agent suite rather than by design: with a module-global
    memo, a newly constructed agent inherited the previous one's answers, and two
    agents in one process would serve each other's outcome whenever their prompts
    and watermarks agreed. Each caller owns its store.
    """
    inputs_a = llm_skip.SkipInputs(store=llm_skip.MemoStore())
    inputs_b = llm_skip.SkipInputs(store=llm_skip.MemoStore())

    llm_a, llm_b = RecordingLLM(), RecordingLLM()
    _cycles(llm_a, 3, inputs=inputs_a)
    assert len(llm_a.bodies) == 1

    # identical prompt and watermark, different caller: it must still pay once
    _cycles(llm_b, 3, inputs=inputs_b)
    assert len(llm_b.bodies) == 1, "the second caller was served the first caller's memo"
