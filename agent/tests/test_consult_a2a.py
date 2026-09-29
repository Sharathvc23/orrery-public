"""Driving a consultation over A2A — the distinctions that must survive.

⚠️ THE MISLABEL THIS PREVENTS. ``send_task_recorded`` raises
``ActionSucceededUnreceipted`` when the peer **did** answer and only the receipt
stage failed. Mapping that to "unreachable" records the opposite of what
happened: an answer that exists, logged as a peer that never replied.

Three outcomes stay apart because each means something different to a reader of
the verdict — answered-and-signed, answered-with-nothing-to-show, and no answer.
"""

from __future__ import annotations

import pytest

from community_member.consult import gather
from community_member.consult_a2a import a2a_asker


class _Client:
    def __init__(self, behaviour):
        self._behaviour = behaviour

    def send_task_recorded(self, tool, args, **kwargs):
        return self._behaviour(tool, args, kwargs)


def _asker(behaviour, **kw):
    return a2a_asker(
        client_for=lambda _did: _Client(behaviour),
        question="book?",
        sk_bytes=b"\x00" * 32,
        agency_log=object(),
        **kw,
    )


# ── the three outcomes ──────────────────────────────────────────────────────


def test_a_cosigned_answer_is_sent():
    ask = _asker(lambda t, a, k: {"position": "book", "rationale": "free", "receipt_id": "r1"})

    reply = ask("did:key:zA")

    assert reply.outcome == "sent"
    assert reply.result == {"position": "book", "rationale": "free"}
    assert reply.receipt_id == "r1"


def test_an_answer_that_went_unreceipted_is_not_called_unreachable():
    """The load-bearing one. The peer answered; only the receipt failed."""
    from community_member.a2a_client_v2 import ActionSucceededUnreceipted

    def behaviour(t, a, k):
        raise ActionSucceededUnreceipted("attempt-1", {"position": "book"}, RuntimeError("log down"))

    reply = _asker(behaviour)("did:key:zA")

    assert reply.outcome == "unreceipted", "an answer that exists was recorded as a peer that never replied"
    assert reply.result == {"position": "book"}


def test_a_transport_failure_is_unreachable():
    def behaviour(t, a, k):
        raise TimeoutError("gone")

    reply = _asker(behaviour)("did:key:zA")

    assert reply.outcome == "unreachable"
    assert "TimeoutError" in reply.error


def test_a_client_that_cannot_be_built_is_unreachable_not_a_crash():
    ask = a2a_asker(
        client_for=lambda _did: (_ for _ in ()).throw(ValueError("no card")),
        question="book?",
        sk_bytes=b"\x00" * 32,
        agency_log=object(),
    )

    assert ask("did:key:zA").outcome == "unreachable"


# ── what reaches the verdict ────────────────────────────────────────────────


def test_an_unreceipted_answer_is_not_counted_as_a_vote():
    """Counting it would let a verdict rest on positions nobody can attribute,
    and the tally would look identical either way."""
    from community_member.a2a_client_v2 import ActionSucceededUnreceipted

    def behaviour(t, a, k):
        raise ActionSucceededUnreceipted("a1", {"position": "book"}, RuntimeError("x"))

    consultation = gather("book?", ["did:key:zA"], _asker(behaviour))

    assert consultation.answers == (), "an unattributable answer was counted"
    assert consultation.silent[0].reason == "unreceipted"


def test_the_consultation_still_accounts_for_every_peer():
    from community_member.a2a_client_v2 import ActionSucceededUnreceipted

    def behaviour(t, a, k):
        # Distinct behaviour per call, in order.
        behaviour.n = getattr(behaviour, "n", 0) + 1
        if behaviour.n == 1:
            return {"position": "book", "receipt_id": "r1"}
        if behaviour.n == 2:
            raise ActionSucceededUnreceipted("a", {"position": "decline"}, RuntimeError())
        raise ConnectionError("down")

    peers = ["did:key:zA", "did:key:zB", "did:key:zC"]
    consultation = gather("book?", peers, _asker(behaviour))

    assert consultation.asked == 3
    assert len(consultation.answers) == 1
    # The adapter returns a PeerReply whose outcome gather() records verbatim,
    # so the reasons are the outcomes themselves rather than exception text.
    assert {s.reason for s in consultation.silent} == {"unreceipted", "unreachable"}


def test_a_peer_answering_without_a_position_is_not_coerced_into_one():
    ask = _asker(lambda t, a, k: {"rationale": "unsure", "receipt_id": "r1"})

    consultation = gather("book?", ["did:key:zA"], ask)

    assert consultation.answers == ()
    assert consultation.silent[0].reason == "answered without a position"


@pytest.mark.parametrize("key", ["position", "answer", "verdict"])
def test_the_common_reply_shapes_are_read(key):
    ask = _asker(lambda t, a, k: {key: "book", "receipt_id": "r1"})
    assert ask("did:key:zA").result["position"] == "book"
