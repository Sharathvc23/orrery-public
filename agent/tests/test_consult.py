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
