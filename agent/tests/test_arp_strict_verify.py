"""Phase 1 — the member can STRICT-verify any receipt, not just its own signature.

Before this, ``community_member.arp`` exposed only ``verify_receipt_signature``
(signature-only). That makes the member depend on its chapter to answer "is this
counterparty's receipt actually valid?" — re-centralizing the trust ARP exists to
decentralize. ``verify_receipt`` closes that asymmetry: schema + signature + hash
chain, the SAME canonical pipeline the chapter runs on ingest.

Classification:
  HAPPY        — own valid receipt verifies
  HAPPY        — a COUNTERPARTY's receipt (different key) verifies (the point)
  ADVERSARIAL  — tampered body fails at the signature stage
  FAILURE      — schema-invalid receipt fails at the schema stage
  EDGE         — chained receipt: verifies with prior, fails strict without it
"""

from __future__ import annotations

import hashlib
import os
import tempfile

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-arp-strict-tests-do-not-use"),
)

from community_member.arp import (
    build_receipt,
    did_from_private_key,
    receipt_chain_link,
    sign_receipt,
    verify_receipt,
)

# 32-byte Ed25519 seeds, derived so length is unambiguous.
ISSUER_SK = hashlib.sha256(b"member-strict-verify-issuer").digest()
OTHER_SK = hashlib.sha256(b"counterparty-different-agent").digest()


def _signed_receipt(sk: bytes, **kw) -> dict:
    did = did_from_private_key(sk)
    r = build_receipt(
        action={"category": "message_sent", "human_summary": "hi", "outcome": "completed"},
        issuer_did=did,
        principal_did=did,
        issued_at="2026-06-07T00:00:00Z",
        **kw,
    )
    return sign_receipt(r, sk)


def test_own_valid_receipt_verifies_strict() -> None:
    res = verify_receipt(_signed_receipt(ISSUER_SK))
    assert res.ok and res.stage == "accepted"


def test_counterparty_receipt_verifies_strict() -> None:
    # The member did NOT sign this — a different agent did. The member must be
    # able to verify it independently. This is the whole asymmetry fix.
    res = verify_receipt(_signed_receipt(OTHER_SK))
    assert res.ok and res.stage == "accepted"


def test_tampered_body_fails_at_signature_stage() -> None:
    r = _signed_receipt(ISSUER_SK)
    r["action"]["human_summary"] = "tampered after signing"
    res = verify_receipt(r)
    assert not res.ok and res.stage == "signature"


def test_schema_invalid_receipt_fails_at_schema_stage() -> None:
    r = _signed_receipt(ISSUER_SK)
    del r["issuer_did"]  # required by schema
    res = verify_receipt(r)
    assert not res.ok and res.stage == "schema"


def test_chained_receipt_verifies_with_prior_and_fails_without() -> None:
    genesis = _signed_receipt(ISSUER_SK)
    link = receipt_chain_link(genesis)
    second = _signed_receipt(ISSUER_SK, previous_receipt_hash=link)

    # strict mode without the prior cannot evaluate the chain → fail
    res_no_prior = verify_receipt(second, mode="strict")
    assert not res_no_prior.ok and res_no_prior.stage == "hash_chain"

    # supply the prior keyed by hash → chain verifies
    res_with_prior = verify_receipt(second, mode="strict", prior_receipts={link: genesis})
    assert res_with_prior.ok and res_with_prior.stage == "accepted"
