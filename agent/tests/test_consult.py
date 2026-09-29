"""Intra-org consultation — the verdict must be checkable, not merely signed.

⚠️ THE PROPERTY THIS PROTECTS. A signature proves a payload is untampered. It
says nothing about whether the conclusion follows from the evidence. If a
verdict's outcome cannot be re-derived from the answers it names, a reader is
trusting the signer's arithmetic, and a signer that miscounts — or lies — looks
exactly like one that did not.

The load-bearing test is ``test_control_a_verdict_that_lies_about_its_own_answers``.

The second thing under test is that the verdict does not overclaim. Five agents
sharing a model, a prompt and an operator are one opinion with five signatures;
counting distinct keys is not counting distinct minds, and the payload has to
say so rather than let a reader infer consensus.
"""

from __future__ import annotations

import pytest

from community_member.consult import (
    Answer,
    build_verdict,
    evidence_digest,
    from_consultation,
    gather,
    majority,
    recompute,
    unanimous,
)


def _answers(*positions: str) -> list[Answer]:
    return [Answer(agent_did=f"did:key:z6Mk{i}", position=p, rationale=f"because {p}") for i, p in enumerate(positions)]


# ── the rules ───────────────────────────────────────────────────────────────


def test_majority_picks_the_shared_position():
    outcome, tally = majority(_answers("book", "book", "decline"))
    assert outcome == "book"
    assert tally == {"book": 2, "decline": 1}


def test_a_tie_is_refused_rather_than_broken():
    """Breaking a tie silently makes the verdict depend on answer ordering,
    which nothing in the receipts records — so two verifiers recomputing the
    same evidence could legitimately disagree."""
    outcome, _ = majority(_answers("book", "decline"))
    assert outcome == "tied"


def test_unanimous_requires_everyone():
    assert unanimous(_answers("book", "book"))[0] == "book"
    assert unanimous(_answers("book", "decline"))[0] == "not_unanimous"


def test_no_answers_is_its_own_outcome_not_a_default():
    """Nobody answering is a distinct state from everybody agreeing."""
    assert majority([])[0] == "no_answers"
    assert unanimous([])[0] == "no_answers"


def test_an_unknown_rule_is_refused_at_build_time():
    with pytest.raises(ValueError, match="unknown rule"):
        build_verdict("go?", _answers("book"), rule="vibes")


# ── recomputation is the point ──────────────────────────────────────────────


def test_a_genuine_verdict_recomputes():
    verdict = build_verdict("book the table?", _answers("book", "book", "decline"))
    agrees, detail = recompute(verdict.as_payload())
    assert agrees, detail


def test_control_a_verdict_that_lies_about_its_own_answers():
    """The whole reason recomputation exists.

    The payload is internally inconsistent: it records two 'decline' answers and
    claims the org decided to book. A signature over this proves only that
    nobody edited the lie afterwards.
    """
    payload = build_verdict("book?", _answers("decline", "decline")).as_payload()
    payload["outcome"] = "book"

    agrees, detail = recompute(payload)

    assert not agrees, "a verdict contradicting its own answers was accepted"
    assert "claims 'book'" in detail


def test_control_an_answer_removed_after_the_fact_is_caught():
    """Drop the dissent and the outcome no longer follows from what remains."""
    verdict = build_verdict("book?", _answers("book", "decline", "decline"))
    payload = verdict.as_payload()
    payload["answers"] = [a for a in payload["answers"] if a["position"] != "book"]

    agrees, _ = recompute(payload)
    assert not agrees


def test_control_a_doctored_tally_is_caught():
    payload = build_verdict("book?", _answers("book", "decline")).as_payload()
    payload["outcome"] = "book"
    payload["tally"] = {"book": 99}

    assert not recompute(payload)[0]


def test_control_an_unknown_rule_cannot_be_recomputed():
    """A verdict naming a rule the verifier does not have is not a pass."""
    payload = build_verdict("book?", _answers("book")).as_payload()
    payload["rule"] = "whatever-the-signer-felt"

    agrees, detail = recompute(payload)
    assert not agrees
    assert "nothing can be recomputed" in detail


# ── the verdict does not overclaim ──────────────────────────────────────────


def test_the_payload_states_what_it_does_not_establish():
    payload = build_verdict("book?", _answers("book", "book")).as_payload()

    assert payload["not_established"], "a verdict with no stated limits reads as proof"
    assert any("correct" in n for n in payload["not_established"])
    assert any("distinct minds" in n for n in payload["not_established"])


def test_distinct_signers_counts_keys_not_opinions():
    """Two answers from one agent are one signer, however many times it spoke."""
    twice = [Answer(agent_did="did:key:z6MkA", position="book"), Answer(agent_did="did:key:z6MkA", position="book")]

    verdict = build_verdict("book?", twice)

    assert verdict.independent_counterparties == 1, "one agent answering twice was counted as corroboration"


# ── the evidence digest ─────────────────────────────────────────────────────


def test_the_digest_is_stable_and_changes_with_the_answers():
    a = build_verdict("book?", _answers("book", "decline"))
    b = build_verdict("book?", _answers("book", "decline"))
    c = build_verdict("book?", _answers("book", "book"))

    assert evidence_digest(a) == evidence_digest(b)
    assert evidence_digest(a) != evidence_digest(c)


# ── gathering: every peer is accounted for ──────────────────────────────────


class _Report:
    """Shaped like delegated_call.CallReport, which is what gather() consumes."""

    def __init__(self, outcome="sent", counterparty_did=None, result=None, receipt_id="r1"):
        self.outcome = outcome
        self.counterparty_did = counterparty_did
        self.result = result
        self.receipt_id = receipt_id


def test_every_peer_lands_in_answers_or_silent():
    """The invariant that stops a non-answer from disappearing."""
    peers = ["did:key:zA", "did:key:zB", "did:key:zC", "did:key:zD"]

    def ask(peer):
        if peer == "did:key:zA":
            return _Report(result={"position": "book"}, counterparty_did=peer)
        if peer == "did:key:zB":
            return _Report(outcome="refused")
        if peer == "did:key:zC":
            raise ConnectionError("no route")
        return _Report(outcome="unreceipted")

    consultation = gather("book?", peers, ask)

    assert consultation.asked == len(peers)
    assert len(consultation.answers) == 1
    assert len(consultation.silent) == 3


def test_control_silence_is_carried_into_the_verdict():
    """A verdict over three of ten is a different claim from three of three.

    If silence is dropped, a reader given only the answers cannot tell which
    they are looking at — and an org could ask ten and report the three that
    agreed.
    """
    consultation = gather(
        "book?",
        ["did:key:zA", "did:key:zB"],
        lambda p: (
            _Report(result={"position": "book"}, counterparty_did=p)
            if p == "did:key:zA"
            else _Report(outcome="refused")
        ),
    )
    payload = from_consultation(consultation).as_payload()

    assert payload["asked"] == 2
    assert len(payload["answers"]) == 1
    assert payload["silent"] == [{"agent_did": "did:key:zB", "reason": "refused"}], (
        "a peer that was asked and declined vanished from the verdict"
    )


def test_an_unreachable_peer_does_not_abort_the_consultation():
    """Nine of ten answering is a result. Aborting would discard it."""
    peers = [f"did:key:z{i}" for i in range(10)]

    def ask(peer):
        if peer == "did:key:z3":
            raise TimeoutError("gone")
        return _Report(result={"position": "book"}, counterparty_did=peer)

    consultation = gather("book?", peers, ask)

    assert len(consultation.answers) == 9
    assert consultation.silent[0].reason.startswith("unreachable")
    assert consultation.response_rate == 0.9


def test_an_answer_with_no_position_is_silence_not_a_vote():
    """A reply that says nothing must not be counted as agreement."""
    consultation = gather("book?", ["did:key:zA"], lambda p: _Report(result={"rationale": "hmm"}))

    assert consultation.answers == ()
    assert consultation.silent[0].reason == "answered without a position"


def test_the_reasons_for_silence_stay_distinguishable():
    """`refused` and `unreceipted` are different facts: one is a peer declining,
    the other an action that happened with no receipt to show for it."""
    consultation = gather(
        "book?",
        ["did:key:zA", "did:key:zB"],
        lambda p: _Report(outcome="refused" if p == "did:key:zA" else "unreceipted"),
    )

    assert {s.reason for s in consultation.silent} == {"refused", "unreceipted"}


def test_a_gathered_verdict_still_recomputes():
    consultation = gather(
        "book?",
        ["did:key:zA", "did:key:zB"],
        lambda p: _Report(result={"position": "book"}, counterparty_did=p),
    )
    agrees, detail = recompute(from_consultation(consultation).as_payload())
    assert agrees, detail
