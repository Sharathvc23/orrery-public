"""The watermark gate: what releases it, what does not, and what it costs when wrong.

The gate suppresses an LLM call when a think type's prompt inputs are unchanged
since its last successful run. Every assertion below is written against the way
this fails badly rather than the way it works: a gate that never releases is
silent, and silence looks exactly like a quiet org.

Two hazards get their own tests because each has already cost something.

  A WATERMARK THAT DOES NOT MOVE. A watermark specified elsewhere in this
  codebase as ``max(rowid)`` held steady across the transitions it existed to
  catch, because those rows are written ON CONFLICT DO UPDATE and a promotion
  changes neither the count nor the maximum. So the tests here PLANT A STALE
  WATERMARK and assert the gate releases, rather than reasoning that it would.

  CANONICALISATION THAT IS NOT SORTED. Set iteration over strings depends on
  ``PYTHONHASHSEED``, which is read at interpreter start. Two processes would
  then disagree about the watermark for identical inputs and a redeploy would
  silently invalidate every one of them. That is driven in SUBPROCESSES with
  three seeds, because it cannot be exercised from inside one interpreter.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

import llm_elide


class FakeMemory:
    """Stands in for chapter_helpers.remember / recent_memories.

    Newest-first, like the real ``recent_memories`` ordering, because the gate
    depends on the latest row winning.
    """

    def __init__(self) -> None:
        self.rows: dict[str, list[str]] = {}
        self.reads = 0

    async def remember(self, memory_type: str, memory_key: str, value: dict | None = None) -> None:
        self.rows.setdefault(memory_type, []).insert(0, memory_key)

    async def recent_memories(self, memory_type: str, limit: int = 10) -> list[str]:
        self.reads += 1
        return self.rows.get(memory_type, [])[:limit]


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("LLM_ELIDE_ENABLED", "1")


# ── the flag ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_by_default_and_reads_nothing(monkeypatch):
    """Off unless asked for, and off means it does not even look.

    Asserting the read count matters: a gate that queries the memory table
    while disabled would add a round trip per cycle to every deployment that
    never opted in.
    """
    monkeypatch.delenv("LLM_ELIDE_ENABLED", raising=False)
    mem = FakeMemory()
    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "elide disabled"
    assert mem.reads == 0


@pytest.mark.asyncio
async def test_unrecognised_flag_value_reads_as_off(monkeypatch):
    """A typo is not a decision. 'ture' must not enable elision."""
    monkeypatch.setenv("LLM_ELIDE_ENABLED", "ture")
    mem = FakeMemory()
    run, _ = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert llm_elide.elide_enabled() is False


@pytest.mark.asyncio
async def test_disabled_does_not_record(monkeypatch):
    monkeypatch.delenv("LLM_ELIDE_ENABLED", raising=False)
    mem = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem.remember)
    assert mem.rows == {}


# ── release and suppress ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_first_run_is_never_suppressed(enabled):
    mem = FakeMemory()
    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "no previous run recorded"


@pytest.mark.asyncio
async def test_unchanged_inputs_suppress(enabled):
    mem = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem.remember)
    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is False
    assert why == "inputs unchanged"


@pytest.mark.asyncio
async def test_changed_inputs_release(enabled):
    mem = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem.remember)
    run, why = await llm_elide.should_run("insight", "def", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "inputs changed"


@pytest.mark.asyncio
async def test_a_planted_stale_watermark_releases_at_the_floor(enabled):
    """Planted, not reasoned about.

    A watermark recorded 25 hours ago with inputs still identical must release:
    the floor is what turns a wrong watermark into one stale window instead of
    permanent silence.
    """
    mem = FakeMemory()
    long_ago = datetime.now(UTC) - timedelta(hours=25)
    await llm_elide.record_run("insight", "abc", remember=mem.remember, now=long_ago)

    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "24h floor elapsed"

    # And just inside the window it still suppresses, so the floor is a floor
    # rather than an always-run.
    recent = datetime.now(UTC) - timedelta(hours=23)
    mem2 = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem2.remember, now=recent)
    run2, why2 = await llm_elide.should_run("insight", "abc", recent_memories=mem2.recent_memories)
    assert run2 is False
    assert why2 == "inputs unchanged"


@pytest.mark.asyncio
async def test_the_latest_recorded_run_wins(enabled):
    """agent_memory is INSERT-only, so several rows accumulate per type.

    ``recent_memories`` orders newest first; the gate must compare against the
    newest, not the first ever written.
    """
    mem = FakeMemory()
    await llm_elide.record_run("insight", "old", remember=mem.remember)
    await llm_elide.record_run("insight", "new", remember=mem.remember)
    run, why = await llm_elide.should_run("insight", "new", recent_memories=mem.recent_memories)
    assert (run, why) == (False, "inputs unchanged")


@pytest.mark.asyncio
async def test_types_do_not_share_a_watermark(enabled):
    """Each type keys its own row. One type's stability must not silence another."""
    mem = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem.remember)
    run, why = await llm_elide.should_run("introduction_propose", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "no previous run recorded"


# ── failure directions ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_expired_watermark_runs_rather_than_suppresses(enabled):
    """Rows expire after 7 days. An expired row reads as absent, so the type runs.

    The failure direction is a redundant call, never a suppressed one.
    """
    mem = FakeMemory()
    await llm_elide.record_run("insight", "abc", remember=mem.remember)
    mem.rows.clear()  # what expiry looks like through recent_memories
    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert why == "no previous run recorded"


@pytest.mark.asyncio
async def test_a_memory_read_failure_runs(enabled):
    """A database hiccup must not suppress a cycle."""

    async def broken(_type, _limit=10):
        raise RuntimeError("pg down")

    run, why = await llm_elide.should_run("insight", "abc", recent_memories=broken)
    assert run is True
    assert "watermark read failed" in why


@pytest.mark.asyncio
async def test_a_malformed_recorded_row_runs(enabled):
    """A key with no parseable timestamp cannot be floor-checked, so it runs."""
    mem = FakeMemory()
    mem.rows["elide_wm:insight"] = ["abc|not-a-timestamp"]
    run, why = await llm_elide.should_run("insight", "abc", recent_memories=mem.recent_memories)
    assert run is True
    assert "no usable timestamp" in why


@pytest.mark.asyncio
async def test_a_record_failure_is_survivable(enabled):
    """Failing to record costs a redundant call next cycle, not an exception."""

    async def broken(_type, _key, _value=None):
        raise RuntimeError("pg down")

    await llm_elide.record_run("insight", "abc", remember=broken)


@pytest.mark.asyncio
async def test_the_recorded_key_fits_the_column(enabled):
    """memory_key is truncated to 200 characters by remember().

    A digest plus an ISO timestamp must fit with room to spare, or truncation
    would corrupt the timestamp and every run would read as malformed.
    """
    mem = FakeMemory()
    await llm_elide.record_run("insight", "a" * 64, remember=mem.remember)
    assert len(mem.rows["elide_wm:insight"][0]) < 200


# ── canonicalisation ────────────────────────────────────────────────


def test_sets_are_sorted_not_iterated():
    assert llm_elide.canonical({"s": {"b", "a", "c"}}) == llm_elide.canonical({"s": {"c", "a", "b"}})


def test_dict_key_order_does_not_matter():
    assert llm_elide.watermark(a=1, b=2) == llm_elide.watermark(b=2, a=1)


def test_sequence_order_does_matter():
    """A reordered member list is a different prompt, so a different watermark."""
    assert llm_elide.watermark(m=[1, 2]) != llm_elide.watermark(m=[2, 1])


def test_a_changed_value_changes_the_watermark():
    assert llm_elide.watermark(members=["a"]) != llm_elide.watermark(members=["a", "b"])


def test_nested_sets_are_sorted_too():
    left = llm_elide.canonical({"outer": [{"inner": {"z", "a"}}]})
    right = llm_elide.canonical({"outer": [{"inner": {"a", "z"}}]})
    assert left == right


_SEED_SCRIPT = """
import sys
sys.path.insert(0, %r)
import llm_elide
print(llm_elide.watermark(
    skills={"python", "rust", "go", "haskell", "ocaml", "elixir"},
    federation=["bay", "boston", "london"],
    members={"b": 2, "a": 1},
))
"""


def test_watermark_is_stable_across_pythonhashseed(tmp_path):
    """Driven in subprocesses across three seeds.

    PYTHONHASHSEED is read at interpreter start, so this cannot be exercised
    from inside a single test process. If it regressed, every redeploy would
    invalidate every watermark and the saving would vanish with no signal — the
    gate would still look correct in a one-process test.
    """
    import pathlib

    here = str(pathlib.Path(llm_elide.__file__).resolve().parent)
    script = tmp_path / "seeded.py"
    script.write_text(_SEED_SCRIPT % here)

    digests = set()
    for seed in ("0", "1", "42424"):
        out = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
            check=True,
        )
        digests.add(out.stdout.strip())

    assert len(digests) == 1, f"watermark differs by PYTHONHASHSEED: {digests}"
    assert digests.pop()
