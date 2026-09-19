"""Chapter-side compliance VC issuance via sm-locp.

Wraps sm-locp's VCGenerator with the chapter's identity so chapter code
can mint W3C Verifiable Credentials (ComplianceCredential variant) for
actions falling under known regulatory regimes. The VCs are emitted
alongside ARP receipts; they answer a different question.

  - ARP receipt:        "What action did the agent take, signed by whom?"
                        (the chapter's own evidence primitive)
  - ComplianceCredential: "Did this action satisfy regulation X?"
                        (sm-locp's evidence primitive, W3C VC v1, anyone
                         can verify with the issuer's public key)

Architecture per ``docs/integrations/STELLARMINDS.md``:

  - sm-locp is UPSTREAM. We do NOT modify it.
  - This module is a thin downstream adapter: chapter passes its
    identity + an attestation payload, sm-locp produces the signed VC.
  - The chapter stores the resulting VC inline in the arp_receipts
    row's machine_payload.compliance_attestations[] — no new table
    needed for v0.1 (a dedicated table is a future migration if/when
    we want a list-all-VCs surface independent of receipts).

Public API:

  init(chapter_id, private_key_b64)
      Initialize the module with the chapter's identity. Called once
      at chapter startup AFTER sovereign_identity has resolved the
      chapter's Ed25519 keypair.

  emit_compliance_attestation(
      *,
      subject_did,             # the agent the credential is about
      rule_id,                 # regulation rule identifier
      status,                  # compliant | violated | unknown
      confidence,              # 0.0 - 1.0
      evaluation_state=None,   # facts that supported the conclusion
      agency=None,             # regulatory body (e.g. "FAA", "EPA")
      cfr_reference=None,      # citation
      ttl_seconds=None,        # credential validity window
  ) -> dict
      Mint a signed W3C ComplianceCredential. Returns the credential
      as a dict (per sm-locp's to_dict() output). Returns empty dict
      on failure — never raises into business logic.

What's NOT in this v0.1:

  - Automatic rule evaluation via MRR theories. v0.1 expects the
    caller to provide the (rule_id, status, confidence) tuple
    explicitly. Future PRs add chapter-specific regime providers
    that build DefeasibleTheory instances and let the chapter
    auto-evaluate actions against rules.
  - Compliance VC revocation via W3C StatusList2021. sm-locp supports
    it; we just don't expose it yet.
  - A dedicated compliance_credentials Postgres table. v0.1 stores
    VCs inline in arp_receipts.machine_payload.compliance_attestations
    so the list query is "all attestations for this receipt" without
    a join. A future migration extracts them to their own table when
    cross-receipt queries become useful.
"""

from __future__ import annotations

from typing import Any

# Module-level state, set by init() at server startup.
_chapter_id: str = ""
_vc_generator: Any | None = None  # sm_locp.VCGenerator instance


def init(chapter_id: str, private_key_b64: str, *, default_ttl_seconds: int = 300) -> None:
    """Initialize the compliance module with the chapter's identity.

    ``private_key_b64`` is a base64-encoded Ed25519 32-byte private key
    (same shape as ``sovereign_identity._ed25519_keypairs[chapter_id]``).
    ``default_ttl_seconds`` is the credential TTL when callers don't
    specify one (300s = 5 min, matching sm-locp's default).

    On failure (missing sm-locp install, malformed key), logs a clear
    error and leaves _vc_generator=None — emit_compliance_attestation
    becomes a no-op rather than crashing the chapter.
    """
    global _chapter_id, _vc_generator
    _chapter_id = chapter_id

    try:
        # Derive did:key from the server's identity. sm-locp expects
        # the issuer DID upfront and uses it on every credential.
        import base64

        from sm_locp.vc_generator import VCGenerator

        import sovereign_identity

        # Decode + re-derive did:key the same way the rest of the server does.
        # The keypair store uses raw bytes; convert to base64 for sm-locp.
        try:
            kp = sovereign_identity._ed25519_keypairs.get(chapter_id)
            if kp and isinstance(kp.get("public_key"), bytes):
                public_b64 = base64.b64encode(kp["public_key"]).decode()
                issuer_did = sovereign_identity.build_did_key_from_ed25519(public_b64)
            else:
                # Fall back to a deterministic did:key derived from chapter_id
                # if we couldn't reach sovereign_identity. Tests sometimes hit
                # this path before the server has fully booted.
                issuer_did = f"did:key:z{chapter_id}"
        except Exception:
            issuer_did = f"did:key:z{chapter_id}"

        _vc_generator = VCGenerator(
            issuer_did=issuer_did,
            private_key_b64=private_key_b64,
            default_ttl_seconds=default_ttl_seconds,
        )
    except ImportError as e:
        # sm-locp not available in this environment. Compliance
        # attestation becomes a no-op; server continues to work.
        print(f"[compliance] sm-locp not installed, compliance VCs disabled: {e}")
        _vc_generator = None
    except Exception as e:  # noqa: BLE001
        print(f"[compliance] init failed, compliance VCs disabled: {e}")
        _vc_generator = None


def is_initialized() -> bool:
    """True iff the module has a working VCGenerator. Endpoints can
    check this before attempting to emit, to surface a clean error
    rather than the no-op path."""
    return _vc_generator is not None


def emit_compliance_attestation(
    *,
    subject_did: str,
    rule_id: str,
    status: str,
    confidence: float,
    evaluation_state: dict[str, Any] | None = None,
    agency: str = "",
    cfr_reference: str = "",
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Mint a signed W3C ComplianceCredential.

    Returns the credential as a dict (sm-locp ``ComplianceCredential.to_dict()``
    output). The dict is suitable for JSON serialization into
    arp_receipts.machine_payload.compliance_attestations or any other
    storage surface.

    Fire-and-forget: returns an empty dict if the module isn't
    initialized OR if VC generation raises. Compliance VC failure must
    not wedge the underlying chapter action.

    Args:
        subject_did: The agent the credential is about (the principal of
                     the underlying ARP receipt). Usually the same did:key
                     as receipt.principal_did.
        rule_id: Regulation rule identifier. Free-form string the
                 chapter defines (e.g. "CCPA-1798.105-deletion",
                 "GDPR-Art-7-consent").
        status: One of "compliant", "violated", "unknown", "not_applicable".
                Free-form — sm-locp accepts any non-empty string.
        confidence: 0.0 to 1.0. How confident the evaluation is.
        evaluation_state: Dict of facts that supported the conclusion.
                          Carried verbatim into credentialSubject.evaluation_state.
        agency: Regulatory body that issued the rule (e.g. "EU-COMM",
                "FTC", "FAA"). Carried into credentialSubject.agency.
        cfr_reference: Citation string (e.g. "16 CFR 314.4(b)").
        ttl_seconds: Credential validity window in seconds. Defaults to
                     the value passed to init().
    """
    if _vc_generator is None:
        return {}
    if not subject_did or not rule_id or not status:
        return {}

    try:
        from sm_locp.vc_generator import ComplianceCredentialSubject

        subject = ComplianceCredentialSubject(
            id=subject_did,
            rule_id=rule_id,
            status=status,
            confidence=max(0.0, min(1.0, float(confidence))),
            evaluation_state=evaluation_state or {},
            agency=agency,
            cfr_reference=cfr_reference,
        )

        credential = _vc_generator.generate(
            subject,
            ttl_seconds=ttl_seconds,
        )
        return credential.to_dict()
    except Exception as e:  # noqa: BLE001 — telemetry must never raise
        print(f"[compliance] generate failed for rule_id={rule_id}: {e}")
        return {}


def reset() -> None:
    """Reset module-level state for tests. Idempotent."""
    global _chapter_id, _vc_generator
    _chapter_id = ""
    _vc_generator = None


__all__ = [
    "init",
    "is_initialized",
    "emit_compliance_attestation",
    "reset",
]
