"""Intra-org consultation: ask the colleagues, then sign one verdict.

An org reaching a decision by asking its own agents is only interesting if the
answer can be checked afterwards. So the unit of evidence here is not the
verdict — it is the **set of consult receipts the verdict was computed from**,
plus a rule anyone can re-run over them.

The verdict is recomputable
---------------------------
A signed verdict on its own asks a reader to trust the signer's arithmetic. This
one carries the receipts it consumed and the name of the rule applied, and
:func:`recompute` re-derives the outcome from those receipts alone. A verifier
who disagrees with the recomputed answer has caught something; a verifier who
agrees has checked the org's work rather than taken its word.

That is the same shape the estate uses elsewhere — sm-parc's reputation is
recomputable from receipts, and sm-city's rating agent publishes a leaderboard
anyone can re-derive offline. A verdict nobody can recompute is an assertion
wearing a signature.

What a verdict establishes
--------------------------
That these agents were asked this question, that each answer is attributable to
a key, and that the stated rule applied to those answers yields this outcome.

What it does not
----------------
That the answers are *correct*. Consulting five agents that share a model, a
prompt and an operator is one opinion with five signatures on it — correlated
counsel looks identical to consensus from outside, and nothing in a receipt
distinguishes them. ``independent_counterparties`` counts distinct signers; it
does not count distinct minds, and the verdict says so rather than implying
otherwise.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "Answer",
    "Consultation",
    "Silent",
    "gather",
    "RULES",
    "Verdict",
    "build_verdict",
    "evidence_digest",
    "from_consultation",
    "majority",
    "recompute",
    "unanimous",
]

CATEGORY = "decision_made"


@dataclass(frozen=True)
class Answer:
    """One agent's reply, and the receipt that makes it attributable."""

    agent_did: str
    position: str
    rationale: str = ""
    receipt_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_did": self.agent_did,
            "position": self.position,
            "rationale": self.rationale,
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True)
class Silent:
    """An agent that was asked and did not answer, and why.

    Recorded rather than dropped. A consultation that only lists the agents who
    replied lets an org ask ten and report the three that agreed, and the
    omission is invisible afterwards — nothing in a set of receipts reveals a
    receipt that was never created. Silence is evidence about the consultation;
    losing it changes what the verdict means.
    """

    agent_did: str
    reason: str  # refused | unreachable | unreceipted | malformed

    def as_dict(self) -> dict[str, Any]:
        return {"agent_did": self.agent_did, "reason": self.reason}


@dataclass(frozen=True)
class Consultation:
    """Everyone asked, split into those who answered and those who did not."""

    question: str
    answers: tuple[Answer, ...]
    silent: tuple[Silent, ...] = ()

    @property
    def asked(self) -> int:
        return len(self.answers) + len(self.silent)

    @property
    def response_rate(self) -> float:
        return len(self.answers) / self.asked if self.asked else 0.0


@dataclass(frozen=True)
class Verdict:
    """What the org concluded, and everything needed to check it."""

    question: str
    rule: str
    outcome: str
    answers: tuple[Answer, ...]
    tally: dict[str, int] = field(default_factory=dict)
    silent: tuple[Silent, ...] = ()

    @property
    def independent_counterparties(self) -> int:
        """Distinct signers. **Not** distinct minds — see the module docstring."""
        return len({a.agent_did for a in self.answers})

    def as_payload(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "rule": self.rule,
            "outcome": self.outcome,
            "tally": dict(self.tally),
            "answers": [a.as_dict() for a in self.answers],
            # Who was asked and did not answer, and why. A verdict computed over
            # three of ten agents is a different claim from one computed over
            # three of three, and a reader given only the answers cannot tell
            # which they are looking at.
            "silent": [s.as_dict() for s in self.silent],
            "asked": len(self.answers) + len(self.silent),
            "distinct_signers": self.independent_counterparties,
            # Carried in the payload rather than left to a reader's judgement:
            # a verdict that does not say what it fails to establish will be
            # read as establishing more than it does.
            "not_established": [
                "that the answers are correct",
                "that the signers reasoned independently — distinct keys are not "
                "distinct minds, and agents sharing a model, prompt and operator "
                "produce one opinion with several signatures",
            ],
        }


# ── rules ───────────────────────────────────────────────────────────────────


def majority(answers: Sequence[Answer]) -> tuple[str, dict[str, int]]:
    """The position most answers share; ties are refused rather than broken.

    A rule that silently picks a winner from a tie makes the verdict depend on
    answer ordering, which nothing in the receipts records — so two verifiers
    recomputing the same evidence could disagree.
    """
    tally: dict[str, int] = {}
    for answer in answers:
        tally[answer.position] = tally.get(answer.position, 0) + 1
    if not tally:
        return "no_answers", tally
    top = max(tally.values())
    leaders = sorted(p for p, n in tally.items() if n == top)
    return (leaders[0] if len(leaders) == 1 else "tied"), tally


def unanimous(answers: Sequence[Answer]) -> tuple[str, dict[str, int]]:
    """One position, held by everyone asked, or no outcome at all."""
    tally: dict[str, int] = {}
    for answer in answers:
        tally[answer.position] = tally.get(answer.position, 0) + 1
    if not tally:
        return "no_answers", tally
    return (next(iter(tally)) if len(tally) == 1 else "not_unanimous"), tally


RULES = {"majority": majority, "unanimous": unanimous}


# ── building and re-deriving ────────────────────────────────────────────────


def build_verdict(
    question: str,
    answers: Sequence[Answer],
    *,
    rule: str = "majority",
    silent: Sequence[Silent] = (),
) -> Verdict:
    if rule not in RULES:
        raise ValueError(f"unknown rule {rule!r}; known: {', '.join(sorted(RULES))}")
    outcome, tally = RULES[rule](answers)
    return Verdict(
        question=question,
        rule=rule,
        outcome=outcome,
        answers=tuple(answers),
        tally=tally,
        silent=tuple(silent),
    )


def from_consultation(consultation: Consultation, *, rule: str = "majority") -> Verdict:
    """Build a verdict that carries the whole consultation, silence included."""
    return build_verdict(consultation.question, consultation.answers, rule=rule, silent=consultation.silent)


def gather(question: str, peers: Sequence[str], ask: Callable[[str], Any]) -> Consultation:
    """Ask every peer, and account for every one of them.

    ``ask(peer_did)`` performs the call and returns whatever the transport
    produces — here, an object shaped like ``delegated_call.CallReport``. Every
    peer lands in exactly one of ``answers`` or ``silent``; the invariant
    ``asked == len(answers) + len(silent)`` is what stops a non-answer from
    quietly disappearing.

    A raised exception is a *reason*, not a crash. An org whose consultation
    aborts because one colleague was unreachable has learned nothing, and
    treating the outcome as "no verdict" when nine of ten answered would be its
    own distortion.
    """
    answers: list[Answer] = []
    silent: list[Silent] = []

    for peer in peers:
        try:
            report = ask(peer)
        except Exception as exc:  # noqa: BLE001 - an unreachable peer is data
            silent.append(Silent(agent_did=peer, reason=f"unreachable: {str(exc)[:80]}"))
            continue

        outcome = getattr(report, "outcome", None)
        if outcome != "sent":
            # `refused` and `unreceipted` are meaningfully different from an
            # error, and from each other: one is a peer declining, the other an
            # action that happened with no receipt to show for it.
            silent.append(Silent(agent_did=peer, reason=str(outcome or "malformed")))
            continue

        position = ((report.result or {}) if hasattr(report, "result") else {}).get("position")
        if not position:
            silent.append(Silent(agent_did=peer, reason="answered without a position"))
            continue

        answers.append(
            Answer(
                agent_did=getattr(report, "counterparty_did", None) or peer,
                position=str(position),
                rationale=str((report.result or {}).get("rationale", "")),
                receipt_id=getattr(report, "receipt_id", None),
            )
        )

    return Consultation(question=question, answers=tuple(answers), silent=tuple(silent))


def recompute(payload: dict[str, Any]) -> tuple[bool, str]:
    """Re-derive the outcome from the payload's own answers.

    Returns ``(agrees, detail)``. This is what makes the verdict checkable
    rather than merely signed: a reader runs the named rule over the recorded
    answers and compares. A signature proves the payload is untampered; this
    proves the conclusion follows from it.
    """
    rule = payload.get("rule", "")
    if rule not in RULES:
        return False, f"unknown rule {rule!r} — nothing can be recomputed"

    answers = [
        Answer(
            agent_did=a.get("agent_did", ""),
            position=a.get("position", ""),
            rationale=a.get("rationale", ""),
            receipt_id=a.get("receipt_id"),
        )
        for a in payload.get("answers", [])
    ]
    outcome, tally = RULES[rule](answers)
    claimed = payload.get("outcome")
    if outcome != claimed:
        return False, f"rule {rule!r} over these answers yields {outcome!r}, payload claims {claimed!r}"
    if payload.get("tally") and payload["tally"] != tally:
        return False, f"tally disagrees: recomputed {tally}, payload claims {payload['tally']}"
    return True, f"rule {rule!r} over {len(answers)} answer(s) yields {outcome!r}"


def evidence_digest(verdict: Verdict) -> str:
    """A stable digest over the answers a verdict consumed.

    Lets a receipt commit to its inputs without embedding them twice, and makes
    an answer added or removed after the fact detectable.
    """
    canonical = json.dumps([a.as_dict() for a in verdict.answers], sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
