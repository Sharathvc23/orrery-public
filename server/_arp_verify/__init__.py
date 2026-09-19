"""ARP v0.1 conformance harness -- vendored copy for the chapter runtime.

VERBATIM COPY of ``conformance/arp/__init__.py`` (from the repo root)
with one change: ``SCHEMA_ROOT`` points at the local ``./schemas/``
folder (per-version subdirs ``0.1/`` and ``0.2/``), shipped in the chapter
image via ``COPY _arp_verify`` (the whole dir, schemas included).

Why vendoring instead of dynamic import: the server image is built
from ``server/`` as the Docker context, so ``conformance/`` (which
lives at the repo root) doesn't ship with the runtime. Importing
``conformance.arp`` at server startup crashes the deploy. The server
is intentionally self-contained; cross-package imports from
``conformance/`` violate that boundary.

Drift discipline: this file MUST stay in lockstep with
``conformance/arp/__init__.py``. Any change to one must also land in
the other.

Public entry points:

    verify_receipt(receipt: dict, *, mode: str = "strict") -> VerificationResult

Loads JSON Schemas with $ref resolution, validates the receipt envelope,
verifies the Ed25519 signature against canonicalized bytes, and (when
``previous_receipt_hash`` is present) the caller can verify the hash chain
via ``compute_chain_link(prior_receipt)``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_ROOT = Path(__file__).resolve().parent / "schemas"
SUPPORTED_VERSIONS = ("0.1", "0.2")

# Categories that, in arp/0.2, MUST carry a strict-verifying authority chain
# (spec/arp/0.2/spec.md §0.4). Unenforced in arp/0.1.
HIGH_STAKES_CATEGORIES = frozenset(
    {"purchase", "payment_sent", "payment_received", "commitment_entered"}
)


def _instant(value: object) -> datetime | None:
    """An RFC 3339 timestamp as an aware instant, or ``None`` if unreadable.

    ⚠️ THIS EXISTS BECAUSE COMPARING RFC 3339 TIMESTAMPS AS STRINGS IS WRONG.
    The authority-expiry check was ``issued_at > grant_expires_at`` on the raw
    strings, which is only correct when both sides are Zulu at identical
    precision. RFC 3339 also permits a numeric offset, and the schema asks for
    ``format: date-time`` — which, with no ``format_checker`` installed on the
    validator, asserts nothing at all. So the SAME INSTANT written two legal ways
    produced two different verdicts: ``2026-08-13T20:00:00Z`` was correctly
    refused while ``2026-08-14T01:00:00+05:00`` — the identical moment — passed a
    high-stakes authority gate.

    ``None`` is returned rather than raising so the caller decides the fail
    direction; on an authority gate that direction is REFUSAL (see
    :func:`verify_authority`).

    ``Z`` is normalised by hand instead of relying on
    ``datetime.fromisoformat``: this module is vendored into a distribution
    supporting Python 3.10, and 3.10's parser rejects the ``Z`` suffix. A naive
    timestamp (no offset at all) is NOT RFC 3339 and is deliberately unreadable
    here rather than silently assumed to be UTC.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


# ── public types ───────────────────────────────────────────────────


@dataclass
class VerificationResult:
    """Outcome of verifying one receipt.

    The ``stage`` field names the stage at which verification reached a
    decision — useful for asserting against negative-vector expectations
    (e.g., expect ``schema`` failure for a malformed receipt rather than
    a ``signature`` failure).
    """

    ok: bool
    stage: str  # one of: schema, signature, authority, hash_chain, accepted
    detail: str

    @classmethod
    def accepted(cls) -> VerificationResult:
        return cls(ok=True, stage="accepted", detail="receipt verifies")


# ── schema loading + ref resolution ────────────────────────────────


def _load_registry(schema_dir: Path) -> Registry:
    """Build a referencing.Registry that resolves one version's ARP schema $refs.

    Schemas reference each other by relative filename (action.schema.json,
    common.schema.json, etc.). The registry maps each filename onto its
    canonical $id so cross-file $refs resolve cleanly. One registry per version
    keeps the bare-filename aliases from colliding across versions (0.1 and 0.2
    both have an ``action.schema.json``).
    """
    registry: Registry = Registry()
    for path in sorted(schema_dir.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        # The $id is the canonical IRI; we also alias the bare filename so
        # in-file $refs like {"$ref": "action.schema.json"} resolve.
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        registry = registry.with_resource(uri=schema["$id"], resource=resource)
        registry = registry.with_resource(uri=path.name, resource=resource)
    return registry


def _build_validator(version: str) -> Draft202012Validator:
    schema_dir = SCHEMA_ROOT / version
    receipt_schema = json.loads((schema_dir / "receipt.schema.json").read_text())
    return Draft202012Validator(receipt_schema, registry=_load_registry(schema_dir))


# One validator per supported major.minor, built once at import.
_VALIDATORS: dict[str, Draft202012Validator] = {v: _build_validator(v) for v in SUPPORTED_VERSIONS}


def _validator_for(version_field: object) -> Draft202012Validator | None:
    """Resolve the validator for a receipt's ``version`` field ("arp/0.2").

    Returns None for any unknown/unsupported version — the verifier treats that
    as a schema failure rather than silently accepting (chapters reject unknown
    majors; the conformance suite must too).
    """
    if not isinstance(version_field, str):
        return None
    return _VALIDATORS.get(version_field.rsplit("/", 1)[-1])


# ── core verification ──────────────────────────────────────────────


def _canonical_bytes_for_signing(receipt: dict[str, Any]) -> bytes:
    """JCS-canonical bytes of the receipt with the signature field removed."""
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return jcs.canonicalize(body)


def _pubkey_from_did(did_key: str) -> Ed25519PublicKey:
    """Decode a did:key string into an Ed25519PublicKey.

    Expects the multibase-z-base58btc form over multicodec 0xed01 || pubkey32.
    """
    import base58

    if not did_key.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID method: {did_key!r}")
    body = did_key[len("did:key:z") :]
    decoded = base58.b58decode(body)
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ValueError("Not a did:key Ed25519 record")
    pubkey32 = decoded[2:]
    return Ed25519PublicKey.from_public_bytes(pubkey32)


def verify_signature(receipt: dict[str, Any]) -> VerificationResult:
    """Verify the Ed25519 signature over canonical bytes (no schema check)."""
    sig_b64 = receipt.get("signature", "")
    issuer_did = receipt.get("issuer_did", "")
    if not sig_b64 or not issuer_did:
        return VerificationResult(False, "signature", "missing signature or issuer_did")
    try:
        pubkey = _pubkey_from_did(issuer_did)
    except Exception as e:
        return VerificationResult(False, "signature", f"invalid issuer_did: {e}")

    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception as e:
        return VerificationResult(False, "signature", f"signature base64 decode failed: {e}")

    if len(sig_bytes) != 64:
        return VerificationResult(False, "signature", f"signature length {len(sig_bytes)} ≠ 64")

    canonical = _canonical_bytes_for_signing(receipt)
    try:
        pubkey.verify(sig_bytes, canonical)
    except InvalidSignature:
        return VerificationResult(False, "signature", "Ed25519 verification failed")
    return VerificationResult.accepted()


def validate_schema(receipt: dict[str, Any]) -> VerificationResult:
    """Run the receipt against the JSON Schema for its declared version.

    The ``version`` field selects the schema set (arp/0.1 → schema/arp/0.1,
    arp/0.2 → schema/arp/0.2). An unknown version is a schema failure.
    """
    validator = _validator_for(receipt.get("version"))
    if validator is None:
        return VerificationResult(
            False, "schema", f"unknown or unsupported ARP version {receipt.get('version')!r}"
        )
    errors = list(validator.iter_errors(receipt))
    if errors:
        first = errors[0]
        detail = f"{first.message} at {list(first.absolute_path)}"
        return VerificationResult(False, "schema", detail)
    return VerificationResult.accepted()


def verify_authority(
    receipt: dict[str, Any],
    *,
    authority_grants: dict[str, dict[str, Any]] | None = None,
) -> VerificationResult:
    """arp/0.2 authority rules (spec §0.3, §0.4). No-op for arp/0.1.

    1. An ``authority_granted`` / ``authority_revoked`` receipt MUST be
       principal-emitted: ``principal_did == issuer_did`` (only the principal
       authorizes their own agent; the chapter may not self-grant).
    2. A high-stakes action receipt MUST carry an ``action.granted_by_receipt_id``
       that resolves (via ``authority_grants``, keyed by receipt_id) to an
       ``authority_granted`` receipt emitted by THIS receipt's principal, whose
       ``granted_scope`` covers the action's category and whose
       ``grant_expires_at`` is not before this action's ``issued_at``.

    Revocation is intentionally NOT checked here — it needs the chapter's
    revocation set; the resolving caller enforces it (the suite covers the
    grant-shape rules that are pure).
    """
    if receipt.get("version") != "arp/0.2":
        return VerificationResult.accepted()

    action = receipt.get("action") or {}
    category = action.get("category")

    if category in ("authority_granted", "authority_revoked"):
        if receipt.get("principal_did") != receipt.get("issuer_did"):
            return VerificationResult(
                False, "authority", f"{category} must be principal-emitted (principal_did == issuer_did)"
            )
        return VerificationResult.accepted()

    if category in HIGH_STAKES_CATEGORIES:
        grant_id = action.get("granted_by_receipt_id")
        if not grant_id:
            return VerificationResult(
                False, "authority", f"high-stakes category {category!r} requires granted_by_receipt_id"
            )
        grant = (authority_grants or {}).get(grant_id)
        if grant is None:
            return VerificationResult(False, "authority", f"authority grant {grant_id} not found")
        gaction = grant.get("action") or {}
        if gaction.get("category") != "authority_granted":
            return VerificationResult(False, "authority", "referenced grant is not an authority_granted receipt")
        principal = receipt.get("principal_did")
        if grant.get("principal_did") != principal or grant.get("issuer_did") != principal:
            return VerificationResult(False, "authority", "grant was not emitted by this receipt's principal")
        payload = gaction.get("machine_payload") or {}
        scope = payload.get("granted_scope") or []
        if category not in scope and "*" not in scope:
            return VerificationResult(False, "authority", f"grant scope does not cover {category!r}")
        expires_at = payload.get("grant_expires_at")
        if expires_at is not None:
            # INSTANTS, not strings — see _instant for why the string compare was
            # wrong. An absent grant_expires_at still means "no expiry"; that is
            # the principal's choice to make and is unchanged here.
            expiry = _instant(expires_at)
            issued = _instant(receipt.get("issued_at"))
            # ⚠️ FAIL DIRECTION IS REFUSAL, DELIBERATELY. An expiry we cannot read
            # is an expiry we cannot honour, and this gate guards high-stakes
            # categories. Before this, an unparseable value was *accepted*:
            # grant_expires_at="never" passed, because any string starting with a
            # letter sorts after one starting with a digit. Treating unreadable as
            # unexpired hands out a perpetual grant to whoever writes the worst
            # timestamp.
            if expiry is None or issued is None:
                which = "grant_expires_at" if expiry is None else "issued_at"
                return VerificationResult(
                    False,
                    "authority",
                    f"{which} is not a readable RFC 3339 instant; an expiry that cannot be "
                    "read cannot be honoured",
                )
            if issued > expiry:
                return VerificationResult(False, "authority", "authority grant expired before this action")

    return VerificationResult.accepted()


def verify_receipt(
    receipt: dict[str, Any],
    *,
    mode: str = "strict",
    prior_receipts: dict[str, dict[str, Any]] | None = None,
    authority_grants: dict[str, dict[str, Any]] | None = None,
) -> VerificationResult:
    """Top-level verification pipeline.

    Order:
      1. Schema validation
      2. Signature verification
      3. Hash chain verification (if previous_receipt_hash present AND
         a matching prior receipt is supplied via ``prior_receipts`` keyed
         by hash)
      4. Authority rules (arp/0.2 only): principal-emitted grants + required
         authority chain for high-stakes categories, resolved via
         ``authority_grants`` (keyed by receipt_id). See :func:`verify_authority`.

    ``prior_receipts`` is an optional mapping from previous_receipt_hash
    value to the prior canonicalized receipt. If the receipt declares a
    previous_receipt_hash but no matching prior is provided, this is
    treated as ``hash_chain`` failure in ``strict`` mode and as
    ``accepted`` in ``tolerant`` mode (the verifier acknowledges the
    chain claim cannot be evaluated without the prior).
    """
    schema_res = validate_schema(receipt)
    if not schema_res.ok:
        return schema_res

    sig_res = verify_signature(receipt)
    if not sig_res.ok:
        return sig_res

    auth_res = verify_authority(receipt, authority_grants=authority_grants)
    if not auth_res.ok:
        return auth_res

    prev_hash = receipt.get("previous_receipt_hash")
    if prev_hash:
        if prior_receipts is None or prev_hash not in prior_receipts:
            if mode == "strict":
                return VerificationResult(
                    False,
                    "hash_chain",
                    f"previous_receipt_hash {prev_hash} not satisfied by any provided prior",
                )
            return VerificationResult(
                True,
                "accepted",
                "chain claim recorded; prior not provided (tolerant mode)",
            )
        prior = prior_receipts[prev_hash]
        recomputed = compute_chain_link(prior)
        if recomputed != prev_hash:
            return VerificationResult(
                False,
                "hash_chain",
                f"declared {prev_hash} does not match recomputed {recomputed}",
            )

    return VerificationResult.accepted()


def compute_chain_link(prior_receipt: dict[str, Any]) -> str:
    """sha256: hash of the full canonical receipt INCLUDING signature.

    This is the value the next receipt's ``previous_receipt_hash`` MUST
    equal to form a valid chain.
    """
    canonical = jcs.canonicalize(prior_receipt)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"


# ── module exports ─────────────────────────────────────────────────


__all__ = [
    "HIGH_STAKES_CATEGORIES",
    "VerificationResult",
    "compute_chain_link",
    "validate_schema",
    "verify_authority",
    "verify_receipt",
    "verify_signature",
]
