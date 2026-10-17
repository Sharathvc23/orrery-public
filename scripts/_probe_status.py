#!/usr/bin/env python3
"""Tell a card that is NOT THERE apart from a host that is NOT YET AWAKE.

Measured 2026-10-16, on the first real run after the canaries were armed:
``catalog_canary`` reported three advertised entries as failures —
``regentix-head-of-sales``, ``regentix-cto`` and ``astrocity-executive-director``,
every one HTTP 502. Re-probed by hand minutes later, every one returned 200,
twice, with no intervention in between. They were idle containers waking up.

That is a FALSE RED, and it is the same defect as the false greens this canary
was built to remove: the check's result did not depend on the condition it
claims to check. It claims "this org advertises a URL nothing backs"; what it
had actually observed was "this host had not served a request in a while". A
monitor that cries wolf every six hours gets muted, and a muted monitor and a
sleeping one fail identically.

The distinction the canary was missing:

* **404 / 410** — the card is NOT THERE. The real condition. No retry: waiting
  does not make an unpublished card appear, and a retry would only slow down the
  one outcome that is already correct.
* **502 / 503 / 504, and any transport-level failure** — the host is present and
  NOT READY. A cold start is not a missing card. Retried, and reported as a
  failure only once it PERSISTS.
* anything else — unclassified, reported as-is rather than guessed at.

Three things this deliberately does NOT do:

1. It does not swallow a persistent not-ready. ``probe`` retries and then
   returns the not-ready verdict, and the canary still exits 1 on it. Absorbing
   a real outage into a pass would replace the false red with a false green,
   which is the trade this module exists to refuse.
2. It does not retry quietly. A host that only ever answers on the second
   attempt is degraded, and a retry that leaves no trace in the log is a signal
   deleted. ``attempts`` is returned so the caller can say so on the way past.
3. It does not hand the operator one remediation for both diagnoses. The
   failure text for an absent card says to publish one; that is WRONG ADVICE for
   a 502, where the card exists and the service is the problem. See
   ``remediation_for``.

Stdlib only, and the retry loop lives HERE rather than in the canary so that the
classification, the number of attempts and the backoff can all be driven by a
test: ``doc-guards`` installs nothing but pytest, so a guard that needs ``httpx``
is a guard that job cannot run. For the same reason transport failures are
classified by exception CLASS NAME walked up the MRO — ``httpx.TransportError``
is the right predicate and cannot be imported here.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Iterable, NamedTuple

OK = "ok"
ABSENT = "absent"
NOT_READY = "not-ready"
OTHER = "other"

#: The card is not there. A real finding, immediately.
ABSENT_STATUSES = frozenset({404, 410})

#: A gateway speaking for a host that is not serving yet. Not a missing card.
NOT_READY_STATUSES = frozenset({502, 503, 504})

#: Walked up the exception's MRO by name. ``httpx.TransportError`` covers
#: ConnectError, ConnectTimeout, ReadTimeout, ReadError, PoolTimeout,
#: RemoteProtocolError and the rest; ``TimeoutException`` is named separately so
#: this keeps working if that hierarchy is ever flattened.
NOT_READY_EXCEPTIONS = frozenset({"TransportError", "TimeoutException"})

#: One attempt plus two retries. Chosen against the measured condition: a
#: Railway cold start serves within a few seconds, so a third failure ~7s in is
#: evidence of something that is not a cold start.
ATTEMPTS = 3

#: Waited AFTER attempt 1 and attempt 2 respectively. Short on purpose — this
#: runs over every entry of every org inside a 15-minute job, and a backoff long
#: enough to outlast a real outage would just be a slower red.
BACKOFF_SECONDS = (2.0, 5.0)


class ProbeResult(NamedTuple):
    """What one probe actually observed, including how hard it had to try."""

    verdict: str
    status: int | None
    attempts: int
    #: Set only when the final attempt raised; "" when a status came back.
    trouble: str
    #: The final response, passed through so a caller can read the body without
    #: a second request. ``None`` when every attempt raised.
    response: Any = None

    @property
    def woke(self) -> bool:
        """Resolved, but not on the first attempt — a cold start, by definition."""
        return self.verdict == OK and self.attempts > 1

    def describe(self) -> str:
        """The observation, in the terms a reader needs to act on it."""
        if self.status is None:
            return f"{self.trouble} after {self.attempts} attempt(s)"
        if self.verdict == NOT_READY:
            return f"HTTP {self.status} on all {self.attempts} attempt(s)"
        return f"HTTP {self.status}"


def classify(*, status: int | None = None, exc: BaseException | None = None) -> str:
    """Name what was observed. Never guesses: unknown is ``OTHER``, not ``OK``."""
    if exc is not None:
        return NOT_READY if _exception_is_not_ready(exc) else OTHER
    if status == 200:
        return OK
    if status in ABSENT_STATUSES:
        return ABSENT
    if status in NOT_READY_STATUSES:
        return NOT_READY
    return OTHER


def _exception_is_not_ready(exc: BaseException) -> bool:
    """True for a transport-level failure, decided by class name up the MRO.

    A ``ValueError`` from our own code must NOT be read as a cold start — that
    would retry a bug three times and then report it as someone else's outage.
    """
    return any(cls.__name__ in NOT_READY_EXCEPTIONS for cls in type(exc).__mro__)


def describe_exception(exc: BaseException) -> str:
    """Short, non-leaking rendering of a transport failure."""
    return f"{type(exc).__name__}: {exc}".strip().rstrip(":").strip()


def backoff_for(attempt: int) -> float:
    """Seconds to wait after ``attempt`` (1-based). Clamped to the last step."""
    if attempt < 1:
        return 0.0
    index = min(attempt, len(BACKOFF_SECONDS)) - 1
    return BACKOFF_SECONDS[index]


def probe(
    get: Callable[[str], Any],
    url: str,
    *,
    max_attempts: int = ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> ProbeResult:
    """GET ``url``, retrying ONLY a not-ready host, and report what happened.

    ``get`` is injected rather than a client being built here: this module must
    import without ``httpx``, and a test needs to drive the loop without a
    network. ``sleep`` likewise, so the backoff is asserted rather than waited.

    Returns the LAST observation. A not-ready that survives every attempt comes
    back as not-ready — the caller fails on it. Nothing here converts a
    persistent outage into a pass.
    """
    result: ProbeResult | None = None
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            response = get(url)
        except Exception as exc:  # noqa: BLE001 — classified, never swallowed
            result = ProbeResult(classify(exc=exc), None, attempt, describe_exception(exc))
        else:
            status = getattr(response, "status_code", None)
            result = ProbeResult(classify(status=status), status, attempt, "", response)
        if result.verdict != NOT_READY:
            return result
        if attempt < max_attempts:
            sleep(backoff_for(attempt))
    assert result is not None  # the loop runs at least once
    return result


#: Keyed by verdict so an operator reading a red run is told to do the thing that
#: matches what was MEASURED. The absent text is the original one; the not-ready
#: text exists because sending it to someone whose host 502'd — "publish the
#: missing card" — is advice for a condition that is not the one they have.
_REMEDIATION = {
    ABSENT: (
        "The catalog is advertising URLs nothing backs. Either publish the missing cards "
        "(scripts/publish_host39_card.py --record-on-org) or the entries should be omitted "
        "— see the resolvable-card rule."
    ),
    NOT_READY: (
        "These hosts ANSWERED — a gateway or transport error, not a 404 — so the cards are "
        "not missing and publishing one would fix nothing. Each was retried "
        f"{ATTEMPTS} time(s) in total and never served, so this is no longer a cold start: check the "
        "agent service's deploy and logs. Do NOT run publish_host39_card.py for these."
    ),
    OTHER: (
        "An unclassified status or transport failure: neither a 404 (card absent) nor a "
        "502/503/504 (host waking). Read the status above before acting — it is being "
        "reported rather than sorted into whichever bucket was nearest."
    ),
}


def remediation_for(verdicts: Iterable[str]) -> list[str]:
    """The advice for the verdicts actually observed, in a stable order.

    Only what was measured: a run with nothing but cold starts must not also
    print the publish-the-card paragraph, because that paragraph is the one that
    sent an operator looking for a missing card during the 2026-10-16 incident.
    """
    seen = set(verdicts)
    return [_REMEDIATION[v] for v in (ABSENT, NOT_READY, OTHER) if v in seen]
