"""Don't re-send a prompt when nothing that could change the answer has changed.

MEASURED, not assumed. Twenty real think cycles were driven and the request
bodies hashed:

    requests issued : 20
    distinct bodies : 1

``PlannerContext`` is built from static config plus the skill catalogue, so the
loop rebuilds and re-sends an identical request forever by construction. On a
five-minute cycle that is 287 of 288 daily calls per agent.

WHAT MAKES THE FINGERPRINT HONEST. A key computed only from the prompt would
skip cycles whose OUTCOME would have differed — a consent approval, a capability
graduation, or a drained inbox message changes what the cycle should do without
changing a byte of what it would send. So the key is

    plan_key = sha256(canonical(ctx) || request_shape || watermark)

and ``watermark`` covers exactly that state.

THE COVERAGE GUARANTEE, AND WHY IT IS NOT AN ENUMERATION. The stated risk for
this change is an input that reaches the prompt without reaching the key, which
wedges the loop into answering from a stale memo. An enumeration of what
``_render_context`` serialises would close that only until the next field is
added to it. Instead ``canonical`` embeds the RENDERED PROMPT ITSELF, verbatim,
alongside the structured fields. Anything that reaches the prompt is therefore in
the key by construction: a new field cannot be added to ``_render_context``
without changing its output, and changing its output changes the key. The
structured fields are carried too, so the key stays legible and its stability is
testable — but they are not what the guarantee rests on.

For the record, what ``_render_context`` serialises today: ``user_task``;
``trusted.items``; for each ``semi_trusted`` bundle its ``source`` and ``items``;
for each ``untrusted`` bundle its ``source`` and ``items``. All four are covered
structurally as well as through the rendered string.

BOUNDED, AND OBSERVABLE. ``LLM_SKIP_MAX_AGE_S`` forces a real call after six
hours, which caps a wedged skip at four calls per day per agent rather than
zero — bounded is not the same as absent, so every skip is counted through the
meter with its reason, and a skip streak is readable from the counters rather
than being silent.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_MAX_AGE_S",
    "SKIP_ENABLED_ENV",
    "SKIP_MAX_AGE_ENV",
    "Memo",
    "MemoStore",
    "SkipInputs",
    "canonical",
    "consent_watermark",
    "graduation_watermark",
    "memo_store",
    "plan_key",
    "skip_enabled",
    "skip_max_age_s",
    "watermark",
]

SKIP_ENABLED_ENV = "LLM_SKIP_ENABLED"
SKIP_MAX_AGE_ENV = "LLM_SKIP_MAX_AGE_S"

# Six hours. A wedged skip is bounded at four real calls per day per agent.
DEFAULT_MAX_AGE_S = 21600

# The reason string recorded on the meter for every skip this module causes.
SKIP_REASON = "unchanged_context"


def skip_enabled() -> bool:
    """Whether skipping is on. Default on; ``0`` is the rollback.

    Read per call rather than cached, so the flag can be flipped on a running
    agent without a restart — a rollback that needs a redeploy is not a rollback
    during an incident.
    """
    raw = os.environ.get(SKIP_ENABLED_ENV)
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def skip_max_age_s() -> int:
    """Seconds after which a real call is forced regardless of the key."""
    raw = (os.environ.get(SKIP_MAX_AGE_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_AGE_S
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_AGE_S
    # A non-positive age means "never skip", which is a legitimate setting and
    # is not silently rewritten into the default.
    return max(value, 0)


def canonical(ctx: Any, *, rendered: str | None = None) -> str:
    """A stable serialisation of everything the context puts on the wire.

    Sorted keys, so two processes started with different PYTHONHASHSEED produce
    the same string for the same context — a key that depended on dict iteration
    order would skip on one process and not on another, which is worse than not
    skipping at all because it is intermittent.

    Sequence ORDER is preserved, not sorted: the prompt renders bundles in list
    order and indexes items ``[S0]``, ``[S1]``, so reordering them changes what
    the model sees and must change the key.

    ``rendered`` is the exact output of ``planner_llm._render_context``. It is
    included verbatim, which is what makes the key cover the prompt by
    construction rather than by an enumeration that can fall behind.
    """
    if rendered is None:
        from community_member.planner_llm import _render_context

        rendered = _render_context(ctx)

    structured = {
        "user_task": getattr(ctx, "user_task", ""),
        "trusted": list(getattr(getattr(ctx, "trusted", None), "items", ()) or ()),
        "semi_trusted": [
            {"source": getattr(b, "source", ""), "items": list(getattr(b, "items", ()) or ())}
            for b in (getattr(ctx, "semi_trusted", ()) or ())
        ],
        "untrusted": [
            {"source": getattr(b, "source", ""), "items": list(getattr(b, "items", ()) or ())}
            for b in (getattr(ctx, "untrusted", ()) or ())
        ],
        # The guarantee. Listed last so a reader sees the structured view first
        # and the coverage anchor immediately after it.
        "rendered": rendered,
    }
    return json.dumps(structured, sort_keys=True, ensure_ascii=False, default=str)


def consent_watermark(db_path: str | Path | None) -> str:
    """How far the consent ledger has advanced.

    ``consent_events`` is append-only with an AUTOINCREMENT id, so ids are never
    reused and ``max(id)`` alone is a sound watermark. The count is carried too
    so a truncated-and-refilled ledger cannot present the same watermark.
    """
    return _table_watermark(db_path, "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM consent_events")


def graduation_watermark(db_path: str | Path | None) -> str:
    """How far capability graduation has advanced.

    NOT max(rowid), and the difference matters. ``graduations`` rows are written
    with ``ON CONFLICT ... DO UPDATE``: an observation promotes a row to
    ``graduated`` and a revocation flips it to ``revoked``, both IN PLACE. Neither
    changes the row count or the maximum rowid, so a rowid watermark would hold
    steady across exactly the transitions this watermark exists to catch — the
    ones that change a cycle's correct outcome without changing its prompt.

    Counting per state, plus the latest transition timestamps, moves on inserts,
    promotions and revocations alike.
    """
    return _table_watermark(
        db_path,
        "SELECT COUNT(*), "
        "SUM(CASE WHEN state = 'graduated' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN state = 'revoked' THEN 1 ELSE 0 END), "
        "COALESCE(MAX(graduated_at), ''), "
        "COALESCE(MAX(revoked_at), '') "
        "FROM graduations",
    )


def _table_watermark(db_path: str | Path | None, query: str) -> str:
    """Run one aggregate against a store, or report that it is unreadable.

    An unreadable store yields a DISTINCT marker rather than a zero. Zero is a
    real state — an empty ledger — and folding an error into it would let a
    transient database problem look like "nothing has happened", which is the
    reading that produces a wrong skip.
    """
    if not db_path:
        return "absent"
    path = Path(db_path)
    if not path.exists():
        return "absent"
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0) as conn:
            row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        return f"unreadable:{type(exc).__name__}"
    return "|".join("" if v is None else str(v) for v in row)


@dataclass(frozen=True)
class SkipInputs:
    """What a caller must supply for a skip to be safe.

    Every field is state that can change a cycle's outcome without changing its
    prompt. A caller that cannot supply one passes nothing and gets no skip:
    skipping is opt-in per call site, because an unwatermarked skip is exactly
    the wedge this design is guarding against, and defaulting it on would make
    the unsafe case the easy one.
    """

    consent_db: str | Path | None = None
    graduation_db: str | Path | None = None
    # Monotonic count of inbound messages the agent has drained. Changes the
    # agent's state without touching the planner prompt.
    inbox_drained: int = 0
    # Anything else a call site knows can change the outcome. Sorted into the
    # key, so callers may add without ordering concerns.
    extra: dict[str, Any] = field(default_factory=dict)
    # The memo this caller's outcomes live in. A MEMO BELONGS TO AN AGENT, NOT
    # TO THE PROCESS: two agents in one process share a module-global store, so
    # one could be served the other's outcome whenever their prompts and
    # watermarks agreed — and a newly constructed agent would inherit the
    # previous one's answers, which is the same bug seen from the other side.
    # Callers that own an agent pass their own; the module default exists for
    # single-agent callers and for tests.
    store: Any = None


def watermark(inputs: SkipInputs | None) -> str:
    """The external state a cycle's outcome depends on but its prompt does not."""
    if inputs is None:
        return "none"
    parts = {
        "consent": consent_watermark(inputs.consent_db),
        "graduation": graduation_watermark(inputs.graduation_db),
        "inbox_drained": int(inputs.inbox_drained),
        "extra": inputs.extra,
    }
    return json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)


def plan_key(
    ctx: Any,
    *,
    model: str,
    max_tokens: int,
    inputs: SkipInputs | None,
    rendered: str | None = None,
) -> str:
    """The fingerprint of one planning request and everything that could change it.

    ``model`` and ``max_tokens`` are in the key because they are on the wire: the
    same context asked of a different model is a different request, and a memo
    keyed only on the context would answer it from the wrong model's reply.
    """
    material = "\x1f".join(
        [
            canonical(ctx, rendered=rendered),
            f"model={model}",
            f"max_tokens={int(max_tokens)}",
            watermark(inputs),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class Memo:
    """One remembered outcome and when the call that produced it was made."""

    key: str
    value: Any
    made_at: float
    # How many consecutive skips this memo has served. A wedge is a streak that
    # keeps growing, so the streak is the signal that makes one observable.
    streak: int = 0


class MemoStore:
    """Per-process memo of the last real planning call.

    One entry, not a cache: the loop asks the same question repeatedly, so a
    second entry would only ever be the previous question's answer, and keeping
    it would widen the window in which a stale reply can be served.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._memo: Memo | None = None

    def get(self, key: str, *, max_age_s: int, now: float | None = None) -> Memo | None:
        """The memo for ``key`` if it is still young enough, else None."""
        if max_age_s <= 0:
            return None
        stamp = time.monotonic() if now is None else now
        with self._lock:
            memo = self._memo
            if memo is None or memo.key != key:
                return None
            if stamp - memo.made_at >= max_age_s:
                return None
            memo.streak += 1
            return memo

    def put(self, key: str, value: Any, *, now: float | None = None) -> None:
        stamp = time.monotonic() if now is None else now
        with self._lock:
            self._memo = Memo(key=key, value=value, made_at=stamp, streak=0)

    def clear(self) -> None:
        with self._lock:
            self._memo = None

    def peek(self) -> Memo | None:
        with self._lock:
            return self._memo


_STORE = MemoStore()


def memo_store() -> MemoStore:
    """The process-wide memo. Exposed so tests can clear it between cases."""
    return _STORE
