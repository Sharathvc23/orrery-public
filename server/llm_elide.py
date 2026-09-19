"""Skip a think type whose prompt inputs have not changed since it last ran.

THE MEASUREMENT THIS ANSWERS. A driven 720-tick day against a stateful database
issued 486 LLM calls and 188,658 input tokens for an org where nothing changed,
identically at 5, 50 and 200 members — so the spend is driven by the clock, not
by load. 121 of the 486 repeated a prompt already sent that day and one prompt
went out 60 times byte-identically. ``think_introduction_propose`` alone was
115,320 of the 188,658 input tokens, re-serialising the same member list every
24 minutes for a list that changes about once a day.

HOW THE WATERMARK IS BUILT, AND WHY NOT AN AGGREGATE. A watermark here is a
hash of EXACTLY THE VALUES THAT REACH THE PROMPT, canonicalised. It is not a
row count, not a ``max(rowid)``, and not a table digest.

That is a deliberate correction of a mistake already made once in this
codebase: a watermark specified as ``max(rowid)`` over a table whose rows are
written ``ON CONFLICT DO UPDATE`` held steady across exactly the transitions it
existed to catch, because a promotion and a revocation are both IN-PLACE
updates that change neither the row count nor the maximum rowid. Hashing the
serialised content sidesteps the whole class: whatever a row's write path is,
if the value reaches the prompt it reaches the hash, and if it does not reach
the prompt then eliding on it unchanged is correct by construction.

CANONICALISATION IS SORTED, NOT DICT ORDER. Two processes started with
different ``PYTHONHASHSEED`` must produce the same watermark for the same
inputs, or a redeploy silently invalidates every watermark and the saving
disappears without any signal. ``canonical`` sorts keys and sorts any set it is
handed. ``test_llm_elide.py`` drives three seeds in subprocesses, because the
seed is read at interpreter start and cannot be changed from inside a test.

THE 24-HOUR FLOOR IS KEPT. An unchanged watermark suppresses a type for at most
``FLOOR_HOURS``; after that it runs regardless. Every type still refreshes once
per window, so a stuck watermark costs one stale window rather than silence.

STORAGE. ``agent_memory``, through ``chapter_helpers.remember`` /
``recent_memories`` — the table the dedup memories already use. Note for the
next reader: that is NOT the table the 24h digest gate reads. That gate queries
``agent_digests`` directly and is untouched here.

Rows are INSERT-only and expire after 7 days, which has two consequences worth
stating rather than discovering. The latest row wins, because
``recent_memories`` orders by ``created_at`` descending. And an expired
watermark reads as "no previous run", so the type runs — the failure direction
is a redundant call, never a suppressed one.

FLAG. ``LLM_ELIDE_ENABLED`` — off unless explicitly enabled. Unset and empty
are the same, and an unrecognised value reads as "no decision" and keeps the
default rather than silently enabling.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = [
    "FLOOR_HOURS",
    "canonical",
    "elide_enabled",
    "record_run",
    "should_run",
    "watermark",
]

#: Every type still runs at least once per this window, however stable its
#: inputs. The floor is the reason a wrong watermark is a stale window rather
#: than a permanent silence.
FLOOR_HOURS = 24

#: Separates the digest from the timestamp inside one memory_key. Both facts
#: are stored in the key rather than split across key and value because
#: ``recent_memories`` selects only ``memory_key`` — reading the value back
#: would need a second query shape, and the two facts must not be able to
#: disagree about which run they describe.
_SEP = "|"

_MEMORY_TYPE_PREFIX = "elide_wm"

_TRUE = {"1", "true", "yes", "on"}


def elide_enabled() -> bool:
    """Whether elision is on. Unset, empty and unrecognised all read as off."""
    return os.environ.get("LLM_ELIDE_ENABLED", "").strip().lower() in _TRUE


def canonical(value: Any) -> str:
    """A deterministic string for ``value``, stable across processes.

    Sets are sorted rather than iterated: set iteration order depends on
    ``PYTHONHASHSEED`` for strings, so hashing an unsorted set would produce a
    different watermark in every process. Dict keys are sorted for the same
    reason. Everything else is rendered by ``json.dumps`` with sorted keys and
    no incidental whitespace.
    """
    return json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"), default=str)


def _normalise(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(_normalise(v) for v in value)
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        # Order is preserved for sequences: a reordered member list is a
        # different prompt, so it must be a different watermark.
        return [_normalise(v) for v in value]
    return value


def watermark(**parts: Any) -> str:
    """A hex digest over the named prompt inputs.

    Callers pass exactly what their prompt serialises, by name. Naming the
    parts rather than passing a tuple keeps the watermark legible in a test
    failure and makes an added input visible in the diff.
    """
    return hashlib.sha256(canonical(parts).encode("utf-8")).hexdigest()


def _encode(digest: str, when: datetime) -> str:
    return f"{digest}{_SEP}{when.isoformat()}"


def _decode(raw: str) -> tuple[str, datetime | None]:
    digest, _, ts = raw.partition(_SEP)
    if not ts:
        return digest, None
    try:
        return digest, datetime.fromisoformat(ts)
    except ValueError:
        # A malformed timestamp means the floor cannot be evaluated, so the
        # caller must fall through to running. Returning None says exactly that.
        return digest, None


async def should_run(
    think_type: str,
    current: str,
    *,
    recent_memories: Any,
    now: datetime | None = None,
    floor_hours: int = FLOOR_HOURS,
) -> tuple[bool, str]:
    """Whether ``think_type`` should run, and the reason.

    Returns ``(True, reason)`` when the inputs changed, when nothing was ever
    recorded, or when the floor has elapsed. The reason string is returned
    rather than logged here so the caller can print it in its own voice and a
    test can assert on which branch fired.

    Elision is off unless ``LLM_ELIDE_ENABLED`` is set, and this function says
    so first: with the flag off it never even reads the memory table, so
    enabling the flag is the only thing that changes behaviour.
    """
    if not elide_enabled():
        return True, "elide disabled"

    try:
        rows = await recent_memories(f"{_MEMORY_TYPE_PREFIX}:{think_type}", 1)
    except Exception as exc:  # noqa: BLE001 — a memory read must never wedge a cycle
        return True, f"watermark read failed ({type(exc).__name__})"

    if not rows:
        return True, "no previous run recorded"

    previous, when = _decode(str(rows[0]))
    moment = now or datetime.now(UTC)
    if when is not None:
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if moment - when >= timedelta(hours=floor_hours):
            return True, f"{floor_hours}h floor elapsed"
    else:
        return True, "recorded run carried no usable timestamp"

    if previous != current:
        return True, "inputs changed"
    return False, "inputs unchanged"


async def record_run(
    think_type: str,
    current: str,
    *,
    remember: Any,
    now: datetime | None = None,
) -> None:
    """Record a SUCCESSFUL run's watermark.

    Called only after the work completed. Recording before the call would let a
    failed cycle suppress its own retry for a whole window, which converts a
    transient provider error into a day of silence.
    """
    if not elide_enabled():
        return
    try:
        await remember(
            f"{_MEMORY_TYPE_PREFIX}:{think_type}",
            _encode(current, now or datetime.now(UTC)),
        )
    except Exception as exc:  # noqa: BLE001 — failing to record costs a redundant call, nothing more
        print(f"  elide: could not record watermark for {think_type}: {type(exc).__name__}")
