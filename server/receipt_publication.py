"""Publicly verifiable receipt disclosure.

Orrery's claim is that a receipt can be verified by a third party "offline,
without trusting a vendor". Audited 2026-08-02, no outsider could verify one:
``GET /api/receipts`` is 401 (correctly — receipts are private), and the
selective-disclosure path is agent-local and writes to a file. The claim rested
on our own CI probes. This module closes that: an operator explicitly publishes a
bundle, and anyone can fetch and verify it with PyPI ``sm-arp`` and no Orrery code.

WHAT IS PUBLISHED, AND WHAT IS NOT
    Only receipts the ORG itself issued about its OWN actions, and only the ones
    an operator named. Nothing is published as a side effect of anything else,
    and ``/api/receipts`` is untouched. Publishing an org receipt sidesteps
    member privacy entirely: no member's history is involved.

PUBLICATION STATE IS REAL, NOT INFERRED
    Written at publish time into ``agent_settings.settings.published_disclosures``.
    "The org has publication enabled" would be a fact about the ORG; whether THIS
    bundle was published is a different fact. That distinction is the resolvable-card rule's lesson,
    where a catalog advertised a URL for every member because the org had a card
    base configured, and 18 of 24 entries 404'd.

⚠️ THE VERIFYING KEY IS NOT IN THE BUNDLE, DELIBERATELY
    If a bundle carried the key that verifies it, a forger would supply both and
    it would verify perfectly. That is theatre. The bundle carries the issuer's
    ``did:key`` as a CLAIM, and the verifier's job is to check that claim against
    the org's ``/.well-known/did.json`` — fetched from the host they are auditing,
    which they chose, not from anything the bundle told them.

    For the same reason this bundle does NOT carry a link to that did document.
    A forger who could name the did-document URL could point it at a host they
    control, and the check would pass against the wrong authority. The URL has to
    come from outside the artifact, so it is omitted rather than supplied.

    Once ``issuer_did`` is confirmed to be the org's, the Ed25519 key is derived
    from the did:key itself (``sm_arp.pubkey_from_did``) — did:key is
    self-certifying, so no key material has to be transported at all.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

BUNDLE_VERSION = "1"
SETTINGS_KEY = "published_disclosures"
MEDIA_TYPE = "application/json"

PostgresRequest = Callable[..., Awaitable[Any]]


class PublicationError(RuntimeError):
    """A publish request that must be refused rather than partially honoured."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ── Publication state ────────────────────────────────────────────────────────


async def load_publications(pg_request: PostgresRequest, agent_id: str) -> dict[str, dict]:
    """Every published disclosure for this org, keyed by publication id."""
    rows = await pg_request(
        "GET", "agent_settings", params={"agent_id": f"eq.{agent_id}", "select": "settings"}
    )
    if not rows:
        return {}
    settings = (rows[0] or {}).get("settings") or {}
    published = settings.get(SETTINGS_KEY) or {}
    return published if isinstance(published, dict) else {}


async def record_publication(
    pg_request: PostgresRequest, agent_id: str, publication_id: str, receipt_ids: list[str]
) -> dict:
    """Write the publication record. Raises if the write did not land.

    An in-memory-only record would make the public URL 404 after the next
    restart while the operator believed the bundle was published — the same
    shape as a silently-reverted catalog record.
    """
    rows = await pg_request(
        "GET", "agent_settings", params={"agent_id": f"eq.{agent_id}", "select": "settings"}
    )
    settings = ((rows or [{}])[0] or {}).get("settings") or {}
    published = settings.get(SETTINGS_KEY) or {}
    record = {"receipt_ids": receipt_ids, "published_at": _now()}
    published[publication_id] = record
    settings[SETTINGS_KEY] = published

    if rows:
        stored = await pg_request(
            "PATCH", "agent_settings", params={"agent_id": f"eq.{agent_id}"}, body={"settings": settings}
        )
    else:
        stored = await pg_request(
            "POST", "agent_settings", body={"agent_id": agent_id, "settings": settings}
        )
    if stored is None:
        raise PublicationError(
            f"publication record for {publication_id!r} could not be persisted; "
            f"nothing was published"
        )
    return record


# ── Bundle assembly ──────────────────────────────────────────────────────────


def build_bundle(
    *,
    publication_id: str,
    published_at: str,
    receipt_ids: list[str],
    issuer_log: list[dict],
    issuer_did: str,
    sk_bytes: bytes,
) -> dict:
    """Assemble the public bundle: a signed Merkle checkpoint + inclusion proofs.

    The checkpoint commits to the WHOLE issuer log, so a proof shows the receipt
    sits in the same tree the org signed — disclosing a few receipts without
    revealing the rest, which is what selective disclosure is for.

    Raises PublicationError if a named receipt is not in the log, or was not
    issued by this org. Publishing someone else's receipt from our surface would
    lend it our authority.
    """
    import arp as arp_mod
    import merkle

    by_id = {r.get("receipt_id"): (i, r) for i, r in enumerate(issuer_log)}
    leaves = arp_mod.checkpoint_leaves(issuer_log)

    disclosed = []
    for rid in receipt_ids:
        if rid not in by_id:
            raise PublicationError(f"receipt {rid!r} is not in this org's Issuer Log")
        idx, receipt = by_id[rid]
        if receipt.get("issuer_did") != issuer_did:
            raise PublicationError(
                f"receipt {rid!r} was issued by {receipt.get('issuer_did')!r}, not by this org "
                f"({issuer_did!r}); refusing to publish another issuer's receipt"
            )
        disclosed.append(
            {
                "receipt": receipt,
                "leaf_index": idx,
                "proof": [p.hex() for p in merkle.inclusion_proof(leaves, idx)],
            }
        )

    checkpoint = arp_mod.build_checkpoint(issuer_log, sk_bytes=sk_bytes, signer_did=issuer_did)
    return {
        "bundle_version": BUNDLE_VERSION,
        "publication_id": publication_id,
        "published_at": published_at,
        # A CLAIM about who issued these, to be checked against the org's
        # /.well-known/did.json — see the module docstring. No key material and no
        # did-document URL is carried here, on purpose.
        "issuer_did": issuer_did,
        "checkpoint": checkpoint,
        "disclosed": disclosed,
        "how_to_verify": (
            "Do NOT take issuer_did on faith and do NOT look for a key in this file. "
            "Fetch https://<the org you are auditing>/.well-known/did.json, build "
            "did:key:<verificationMethod[0].publicKeyMultibase>, and require it to equal "
            "issuer_did. Then sm_arp.verify_receipt() each disclosed receipt, and check "
            "each RFC 6962 inclusion proof against checkpoint.payload.merkle_root. "
            "See docs/VERIFY_A_RECEIPT.md."
        ),
    }


def bundle_json(bundle: dict) -> str:
    return json.dumps(bundle, indent=2, sort_keys=True)
