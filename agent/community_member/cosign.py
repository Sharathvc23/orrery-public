"""Counterparty co-signing for ARP interaction receipts.

Implements the live co-sign handshake specified in
``spec/arp/0.2/cosign-companion.md`` (Option A, inline). When an agent records
an interaction, the receipt's counterparty co-signs it — producing the
``evidence.witness_signatures`` entry that ``nanda-rep/0.2`` (VRP 0.3 §A)
requires before the receipt builds reputation. Without this, every receipt is
self-declared and scores **zero** under the corroborated method.

Two sides, both pure (no transport here — the A2A round-trip is injected):

* **Witness (B):** :func:`make_witness` co-signs a receipt **iff B is the named,
  distinct counterparty** (§2) — it never attests an interaction it wasn't part
  of, and it signs only the deterministic corroboration payload, never arbitrary
  bytes handed to it.
* **Issuer (A):** :func:`attach_corroboration` / :func:`attach_entry` insert the
  witness entry into the *unsigned* receipt and verify it actually corroborates
  before the issuer finalizes its own signature (insertion-before-finalize, §1).
  A counterparty that declines, is offline, or returns a bad signature yields a
  **valid but uncorroborated** receipt — never an error, never a blocked
  interaction (§3). A non-corroborating entry is rolled back so it cannot
  pollute the receipt or the issuer's signature.

The corroboration payload and signature verification are **not** redefined here:
both come from the published, drift-guarded verifier in :mod:`sm_arp.vrp`
(``cosign_receipt`` / ``is_corroborated``), which is the same code a chapter or
any third party uses to recompute corroboration. This module only orchestrates
*when* and *whether* an entry is produced and kept.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sm_arp.vrp import cosign_receipt, did_key_from_pubkey, is_corroborated

# A WitnessFetcher takes the issuer's UNSIGNED receipt and returns the
# counterparty's witness entry (``{"witness_did", "signature"}``) or ``None`` to
# decline. It owns the transport (e.g. an A2A round-trip to the counterparty) and
# MUST NOT raise — a transport failure is a decline, not an error.
WitnessFetcher = Callable[[dict[str, Any]], dict[str, Any] | None]

# A Cosigner is the witness (B) side bound to B's key: given a receipt, return an
# entry if B will co-sign, else ``None``. See :func:`make_cosigner`.
Cosigner = Callable[[dict[str, Any]], dict[str, Any] | None]


def _own_did(sk_bytes: bytes) -> str:
    """did:key for this signing seed, derived the SAME way the verifier expects
    (``sm_arp.vrp.did_key_from_pubkey``) so the witness entry binds to the identity
    ``is_corroborated`` checks against."""
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return did_key_from_pubkey(pub)


def make_witness(receipt: dict[str, Any], *, sk_bytes: bytes, own_did: str | None = None) -> dict[str, Any] | None:
    """Witness (B) side: co-sign ``receipt`` iff B is its distinct counterparty.

    Returns the ``{"witness_did", "signature"}`` entry, or ``None`` to **decline**
    — B is not the named counterparty, or the receipt names B as both issuer and
    counterparty (self-corroboration, forbidden by VRP 0.3 §A.1). Declining is a
    normal outcome (§3), not an error.

    B signs only the canonical corroboration payload derived from the receipt
    (via ``cosign_receipt``), so a caller cannot trick B into signing chosen
    bytes — B attests *this interaction's content*, with its own key.
    """
    own_did = own_did or _own_did(sk_bytes)
    action = receipt.get("action")
    if not isinstance(action, dict):
        return None
    counterparty = action.get("counterparty_did")
    issuer = receipt.get("issuer_did")
    # Attest only interactions where you ARE the counterparty, and only when that
    # counterparty is distinct from the issuer (a self-co-signed receipt earns
    # nothing under §A and must not be minted).
    if not issuer or counterparty != own_did or counterparty == issuer:
        return None
    return cosign_receipt(receipt, signing_key_bytes=sk_bytes, witness_did=own_did)


def make_cosigner(sk_bytes: bytes) -> Cosigner:
    """Bind :func:`make_witness` to a signing seed once (e.g. at server wiring),
    yielding the callable the A2A handler invokes per ``nanda/cosignReceipt``."""
    own_did = _own_did(sk_bytes)

    def cosign(receipt: dict[str, Any]) -> dict[str, Any] | None:
        return make_witness(receipt, sk_bytes=sk_bytes, own_did=own_did)

    return cosign


def attach_entry(receipt: dict[str, Any], entry: dict[str, Any] | None) -> bool:
    """Issuer (A) side: insert a counterparty witness ``entry`` into the UNSIGNED
    ``receipt`` in place, keeping it **only if it genuinely corroborates** (§A).

    Returns ``True`` iff the receipt is now corroborated. A ``None``, malformed,
    forged, or wrong-signer entry is **rolled back** — the receipt is left exactly
    as clean as it was (no empty ``evidence``/``witness_signatures`` residue), so
    the issuer's subsequent signature is taken over an uncorroborated-but-valid
    receipt (§3). Idempotent insertion order is preserved for the happy path.
    """
    if not isinstance(entry, dict):
        return False
    evidence = receipt.setdefault("evidence", {})
    if not isinstance(evidence, dict):  # defensive: never corrupt a non-dict evidence
        receipt.pop("evidence", None)
        return False
    witnesses = evidence.setdefault("witness_signatures", [])
    if not isinstance(witnesses, list):
        evidence["witness_signatures"] = witnesses = []
    witnesses.append(entry)
    if is_corroborated(receipt):
        return True
    # Non-corroborating: undo, leaving no trace that could alter the signed bytes.
    witnesses.pop()
    if not witnesses:
        evidence.pop("witness_signatures", None)
    if not evidence:
        receipt.pop("evidence", None)
    return False


def attach_corroboration(receipt: dict[str, Any], fetcher: WitnessFetcher) -> bool:
    """Issuer (A) side: obtain the counterparty witness for the UNSIGNED ``receipt``
    via ``fetcher`` (the injected transport) and attach it if it corroborates.

    Returns ``True`` iff the receipt is now corroborated. Any fetcher failure is
    swallowed and treated as a decline — the interaction never fails because the
    counterparty would not, or could not, co-sign (§3).
    """
    try:
        entry = fetcher(receipt)
    except Exception:
        # A transport/counterparty failure can only LOWER the score (uncorroborated),
        # never block the action or raise (§3, §F integrity-degrades-safe).
        return False
    return attach_entry(receipt, entry)
