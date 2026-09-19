"""Portable Agent Reputation Credential (PARC) for the sovereign agent — sm-parc.

A PARC is a signed, offline-verifiable credential over the agent's *receipt-backed*
reputation: it wraps the nanda-rep scores + behavioral Merkle root computed from
the agent's Agency Log (whose receipts are co-signed by counterparties via
sm-arp). The credential travels with the agent across orgs — reputation you own,
not a score locked inside one server.

Built on sm-parc (``build_reputation_credential`` / ``verify_credential_proof``);
we never reimplement the credential envelope. Unlike the conformance badge, this
is built **on-demand from the local ledger** — the agent already has the data, so
``GET /.well-known/reputation.json`` can compute + sign + serve it live.

Self-issued is sound here: the trust is in the co-signed receipts the scores
derive from (corroborated nanda-rep/0.2), not in the issuer's say-so.
"""

from __future__ import annotations

from typing import Any

DEFAULT_METHOD = "nanda-rep/0.2"


def build_self_credential(
    config,
    *,
    as_of: str,
    valid_from: str,
    valid_until: str,
    method: str = DEFAULT_METHOD,
    ledger_uri: str | None = None,
    receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build + sign this agent's PARC from its local Agency Log.

    Raises ValueError if there's no usable identity/signing key. The scores
    come straight from the receipt ledger — nothing is fabricated. Pass
    ``receipts`` to sign over exactly that snapshot instead of re-reading the
    log (selective disclosure pairs this credential with inclusion proofs built
    from the same snapshot — see ``receipt_disclosure``).
    """
    if not config.public_key:
        raise ValueError("no local identity yet; cannot build a reputation credential")

    from sm_parc import build_reputation_credential

    from . import config as config_mod
    from .arp import AgencyLog
    from .conformance_badge import signing_key32
    from .crypto import build_did_key
    from .ledger import export_ledger

    sk = signing_key32(config)
    if sk is None:
        raise ValueError("agent has no 32-byte Ed25519 signing key; cannot sign a credential")

    did = build_did_key(config.public_key)
    log = AgencyLog(home=config_mod.CONFIG_DIR)
    ledger = export_ledger(log, subject_did=did, as_of=as_of, method=method, inline=False, receipts=receipts)

    return build_reputation_credential(
        ledger=ledger,
        issuer_sk=sk,
        issuer_did=did,
        valid_from=valid_from,
        valid_until=valid_until,
        ledger_uri=ledger_uri,
    )


def verify_credential(vc: dict[str, Any]) -> bool:
    """Verify a PARC's proof (sm-parc). True iff the signature checks out."""
    from sm_parc import verify_credential_proof

    return verify_credential_proof(vc)


__all__ = ["build_self_credential", "verify_credential"]
