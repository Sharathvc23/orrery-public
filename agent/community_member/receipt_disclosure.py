"""Selective disclosure of Agency Log receipts — sm-parc inclusion proofs.

As the Agency Log grows, handing a verifier the whole history is neither private
nor scalable. The agent's PARC already commits the ledger as a signed
``behavioral_merkle_root``; this module reveals only chosen receipts, each with a
Merkle inclusion proof that folds up to that root — the verifier confirms every
disclosed receipt is committed under the signed credential **without seeing the
rest of the ledger**, fully offline (no fetch back to the discloser).

Thin downstream adapter over sm-parc's published disclosure surface
(``inclusion_proof`` / ``verify_inclusion``) per
``docs/integrations/STELLARMINDS.md`` — the proof math lives upstream. The bundle
pairs the credential and the proofs from ONE ledger snapshot, so the proofs
verify against the root the credential signs by construction.

NOTE: this walks the VRP behavioral tree (plain SHA-256, odd leaf duplicated),
NOT the RFC 6962 checkpoint tree in ``_merkle/`` (domain-separated, odd node
promoted). Different commitments, never interchanged — see STELLARMINDS.md.
"""

from __future__ import annotations

from typing import Any

# Must match the export_ledger default the PARC is built over: the proofs are
# valid only for the exact receipt set committed by the credential's root.
LEDGER_LIMIT = 10_000


def build_disclosure(
    config,
    *,
    receipt_ids: list[str],
    as_of: str,
    valid_from: str,
    valid_until: str,
    ledger_uri: str | None = None,
) -> dict[str, Any]:
    """Build a self-contained disclosure bundle from the local Agency Log.

    Returns ``{"credential": <signed PARC>, "disclosed": [{"receipt", "proof"}, …]}``
    — everything a verifier needs, offline. Credential and proofs are built from
    the same log snapshot, so each proof folds up to the credential's
    ``behavioral_merkle_root``.

    Raises ValueError if ``receipt_ids`` is empty, any id is not in the Agency
    Log, or the agent has no identity/signing key.
    """
    from sm_parc import inclusion_proof

    from . import config as config_mod
    from .arp import AgencyLog
    from .reputation_credential import build_self_credential

    ids = list(dict.fromkeys(receipt_ids))
    if not ids:
        raise ValueError("no receipt_ids given; nothing to disclose")

    log = AgencyLog(home=config_mod.CONFIG_DIR)
    receipts = log.list_recent(limit=LEDGER_LIMIT)
    by_id = {r.get("receipt_id"): r for r in receipts}
    missing = [rid for rid in ids if rid not in by_id]
    if missing:
        raise ValueError(f"receipts not in the agency log: {', '.join(missing)}")

    credential = build_self_credential(
        config,
        as_of=as_of,
        valid_from=valid_from,
        valid_until=valid_until,
        ledger_uri=ledger_uri,
        receipts=receipts,
    )
    disclosed = [{"receipt": by_id[rid], "proof": dict(inclusion_proof(receipts, receipt=by_id[rid]))} for rid in ids]
    return {"credential": credential, "disclosed": disclosed}


def inspect_disclosure(bundle: dict[str, Any]) -> dict[str, Any]:
    """Report a bundle's internal consistency, without deciding whether to trust it.

    Returns ``{"credential_ok", "issuer", "receipts": [{"receipt_id", "included"}, …]}``.
    There is deliberately no ``ok`` key: these checks cannot establish who issued
    the bundle. ``credential_ok`` means the credential's Ed25519 proof verifies
    under the ``did:key`` named in the credential itself, and ``included`` means a
    receipt folds up its inclusion path to the root that same credential signs.
    A credential, a root and a set of receipts all produced by one keypair satisfy
    both regardless of whose keypair it was.

    Use :func:`verify_disclosure` to decide whether a bundle came from a
    particular issuer. This function is for inspecting structure — for example
    checking a bundle this process just built.

    Malformed input is reported, never raised.
    """
    from sm_parc import verify_credential_proof, verify_inclusion

    if not isinstance(bundle, dict):
        return {"credential_ok": False, "issuer": None, "receipts": []}

    credential = bundle.get("credential")
    try:
        credential_ok = isinstance(credential, dict) and verify_credential_proof(credential)
    except (KeyError, TypeError, ValueError):
        credential_ok = False

    issuer = None
    root = None
    if isinstance(credential, dict):
        raw_issuer = credential.get("issuer")
        issuer = raw_issuer if isinstance(raw_issuer, str) else None
        subject = credential.get("credentialSubject")
        if isinstance(subject, dict):
            root = subject.get("behavioral_merkle_root")

    receipts: list[dict[str, Any]] = []
    disclosed = bundle.get("disclosed")
    for item in disclosed if isinstance(disclosed, list) else []:
        receipt = item.get("receipt") if isinstance(item, dict) else None
        proof = item.get("proof") if isinstance(item, dict) else None
        included = False
        if isinstance(receipt, dict) and isinstance(proof, dict) and isinstance(root, str):
            try:
                included = verify_inclusion(receipt, proof, root)  # type: ignore[arg-type]
            except (KeyError, TypeError, ValueError):
                included = False
        receipts.append(
            {
                "receipt_id": receipt.get("receipt_id") if isinstance(receipt, dict) else None,
                "included": included,
            }
        )

    return {"credential_ok": credential_ok, "issuer": issuer, "receipts": receipts}


def verify_disclosure(bundle: dict[str, Any], *, expected_issuer: str) -> dict[str, Any]:
    """Verify a disclosure bundle against an issuer the caller already trusts.

    ``expected_issuer`` is a ``did:key`` the caller obtained independently of the
    bundle — for example by building it from the org's own
    ``/.well-known/did.json`` (see ``docs/VERIFY_A_RECEIPT.md``). It is required
    rather than optional because the other two checks cannot supply it: the
    credential's proof verifies under the ``did:key`` written inside the
    credential, so a bundle whose credential, Merkle root and receipts were all
    produced by a single keypair passes them whoever holds that keypair.
    Comparing the credential's ``issuer`` against an independently obtained
    ``did:key`` is what binds the bundle to one org.

    Three checks, all offline once ``expected_issuer`` is in hand:

      1. ``credential.issuer`` equals ``expected_issuer``
      2. the credential's Ed25519 proof verifies
      3. every disclosed receipt folds up its inclusion path to
         ``credential.credentialSubject.behavioral_merkle_root``

    Returns ``{"ok", "issuer_ok", "credential_ok", "issuer", "receipts"}``. ``ok``
    is True iff all three checks pass and at least one receipt is disclosed.
    Malformed input is reported, never raised.
    """
    result = inspect_disclosure(bundle)
    issuer_ok = isinstance(expected_issuer, str) and bool(expected_issuer) and result["issuer"] == expected_issuer
    receipts = result["receipts"]
    result["issuer_ok"] = issuer_ok
    result["ok"] = issuer_ok and result["credential_ok"] and bool(receipts) and all(r["included"] for r in receipts)
    return result


__all__ = ["LEDGER_LIMIT", "build_disclosure", "inspect_disclosure", "verify_disclosure"]
