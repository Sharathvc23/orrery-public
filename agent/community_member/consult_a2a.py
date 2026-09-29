"""Drive a consultation against real sibling agents over A2A.

:func:`consult.gather` takes an ``ask`` callable so the decision logic can be
tested without a network. This is the adapter that makes ``ask`` talk to actual
peers — each consult becomes an A2A call whose result is co-signed by the
counterparty, so an answer in the verdict is attributable to the agent that gave
it rather than to whoever assembled the verdict.

The distinction that has to survive the adapter
-----------------------------------------------
``send_task_recorded`` raises :class:`ActionSucceededUnreceipted` when the peer
**did** answer and the receipt stage failed afterwards. Mapping that to
"unreachable" would record the opposite of what happened: an answer that exists,
logged as a peer that never replied.

So three outcomes stay apart, and each means something different to a reader of
the verdict:

``sent``
    answered, and the answer is co-signed.

``unreceipted``
    answered, with nothing signed to show for it. The position is deliberately
    **not** counted — an unattributable answer in a verdict is exactly the kind
    of claim the receipts exist to prevent — but the peer is recorded as having
    responded, because "we could not get a receipt" and "they ignored us" are
    different facts about the org's own plumbing.

``unreachable``
    no answer at all.

Why an unreceipted answer is not a vote
---------------------------------------
Counting it would let a verdict rest on positions nobody can later attribute,
and the failure would be invisible: the tally would look the same either way.
Recording it as silence with a distinct reason keeps the loss legible — a
verdict computed from four of five, where the fifth answered but went
unreceipted, says so.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

__all__ = ["PeerReply", "a2a_asker"]

# The tool a sibling exposes to answer a consultation. Matches the skill-tool
# dispatch shape the runtime already uses: {tool: <name>, args: {...}}.
CONSULT_TOOL = "consult"


@dataclass(frozen=True)
class PeerReply:
    """Shaped like ``delegated_call.CallReport`` — what ``gather`` consumes."""

    outcome: str  # sent | unreceipted | unreachable
    counterparty_did: str | None = None
    result: dict[str, Any] | None = None
    receipt_id: str | None = None
    error: str | None = None


def a2a_asker(
    *,
    client_for: Callable[[str], Any],
    question: str,
    sk_bytes: bytes,
    agency_log: Any,
    tool: str = CONSULT_TOOL,
    label_for: Callable[[str], str] | None = None,
) -> Callable[[str], PeerReply]:
    """Build the ``ask`` callable :func:`consult.gather` drives.

    ``client_for(peer_did)`` returns a ``GoogleA2AClient`` pointed at that peer.
    Injected rather than constructed here so a test can supply a fake without a
    socket, and so connection policy stays with the caller that owns it.

    Never raises. Every failure becomes a ``PeerReply`` with a reason, because
    ``gather``'s contract is that every peer is accounted for — an adapter that
    threw would take the whole consultation down with one bad peer.
    """
    from .a2a_client_v2 import A2AClientError, ActionSucceededUnreceipted

    def ask(peer_did: str) -> PeerReply:
        label = label_for(peer_did) if label_for else peer_did
        try:
            client = client_for(peer_did)
        except Exception as exc:  # noqa: BLE001 - a peer we cannot reach is data
            return PeerReply(outcome="unreachable", counterparty_did=peer_did, error=f"no client: {exc}")

        try:
            result = client.send_task_recorded(
                tool,
                {"question": question},
                counterparty_did=peer_did,
                counterparty_label=label,
                sk_bytes=sk_bytes,
                agency_log=agency_log,
                category="data_shared",
                cosign=True,
            )
        except ActionSucceededUnreceipted as exc:
            # The peer answered. Only the receipt is missing, and saying
            # "unreachable" here would record the opposite of what happened.
            log.warning("consult of %s succeeded but went unreceipted", peer_did)
            return PeerReply(
                outcome="unreceipted",
                counterparty_did=peer_did,
                result=getattr(exc, "result", None),
                error="answered, but no receipt was produced",
            )
        except A2AClientError as exc:
            return PeerReply(outcome="unreachable", counterparty_did=peer_did, error=f"a2a error: {exc}")
        except Exception as exc:  # noqa: BLE001 - transport, timeout, anything
            return PeerReply(
                outcome="unreachable", counterparty_did=peer_did, error=f"{type(exc).__name__}: {str(exc)[:80]}"
            )

        return PeerReply(
            outcome="sent",
            counterparty_did=peer_did,
            result=_position_of(result),
            receipt_id=(result or {}).get("receipt_id"),
        )

    return ask


def _position_of(result: dict[str, Any] | None) -> dict[str, Any]:
    """Pull the answer out of whatever shape the peer replied in.

    A peer that replies without a position is not coerced into one — ``gather``
    records that as silence rather than counting a vote nobody cast.
    """
    if not isinstance(result, dict):
        return {}
    for key in ("position", "answer", "verdict"):
        if result.get(key):
            return {"position": str(result[key]), "rationale": str(result.get("rationale", ""))}
    return {}
