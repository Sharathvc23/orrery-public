"""Consent subsystem — hash-chained local audit, signed consent records, per-action gate.

Port of chapter-runtime's chapter_audit.py pattern, scoped to a single device.
Each action the agent proposes to take on the owner's behalf lands here, and
every row is linked to the previous one by sha256, so a row EDITED in place is
detectable by `verify_chain()`, whose `ok` reports exactly that: the chain is
internally consistent.

`ok` does not report authenticity. `sha256_of` is public, so a row APPENDED by
something other than `record()` can carry a correct hash and leave the chain
consistent; what it cannot carry is a valid Ed25519 signature. That question has
its own answer, `verify_chain()["authenticated"]`, true only when the ledger is
keyed and every row is signed, and None when there is no key to check against.
"""

from community_member.consent.gate import (
    ActionRequest,
    ConsentDecision,
    ConsentRequired,
    Provenance,
    check_and_record,
    evaluate,
    record_decision,
)
from community_member.consent.ledger import (
    canonical_event,
    init,
    record,
    sha256_of,
    verify_chain,
)

__all__ = [
    "ActionRequest",
    "ConsentDecision",
    "ConsentRequired",
    "Provenance",
    "canonical_event",
    "check_and_record",
    "evaluate",
    "init",
    "record",
    "record_decision",
    "sha256_of",
    "verify_chain",
]
