"""Boot-time conformance badge for the ORG HOST — live out of the box.

At startup the server runs the signing-conformance checks that map onto its
own real primitives and signs a badge over the honest result:

* PASSED — checks executed against the server's actual functions:
  did:key derivation (``sovereign_identity.build_did_key_from_ed25519``),
  the adversarial multibase-drift case, and the deterministic Ed25519
  sign-roundtrip (``sovereign_identity.ed25519_sign``), all over the canonical
  ``vectors/signing/`` corpus (shipped into the image; drift-guarded at the
  repo root).
* SKIPPED — the two client-side canonical-string checks
  (``test_canonical_string_v02``/``v03``). The org host implements the VERIFY
  side of those strings (``auth_verify``), not the client builder, so counting
  them as passed would be a lie; they are recorded in ``skipped_vectors`` by
  name. The verify side is exercised by the repo's own suites in CI.
* The payload is labelled **self-attested** (``extensions``): the signature
  proves who produced the badge and that it is untampered, and the counts came
  from a real in-process run — no third party witnessed it.
* A boot badge never clobbers an existing badge that still verifies — an
  operator-generated badge wins until it is removed or stops verifying.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Extension keys are reverse-DNS namespaced per the sm-conformance badge schema.
SELF_ATTESTATION_EXTENSIONS = {
    "org.orrery.attestation": "self-attested",
    "org.orrery.witness": "none",
    "org.orrery.generator": "boot-self-check",
    # the badge is SIGNED, so whatever it says about accepted versions is
    # a cryptographic claim. Listing a major without saying where it applies is
    # how the original defect read: the badge attested "0.2" while the signing
    # path refused v0.2-signed mutations, so a peer that trusted the badge and
    # signed a write at v0.2 got a 401 it had no reason to expect. The majors
    # below are honest for a v0.5 chapter — v0.2 IS accepted, on reads and the
    # A2A interop surface — and this extension carries the scope the
    # `protocol_versions` list structurally cannot.
    "org.orrery.v02_scheme_scope": (
        "reads + A2A interop only; mutating requests rejected with 401 method_binding_required "
        "(spec/0.5/signing.md)"
    ),
}

PASSED_CHECKS = [
    "test_did_key_derivation",
    "test_did_key_adversarial_drift_rejected",
    "test_sign_roundtrip_v02",
]
# Client-side canonical builders the org host does not implement (it verifies
# them in auth_verify); honestly skipped, never faked.
SKIPPED_CHECKS = [
    "test_canonical_string_v02",
    "test_canonical_string_v03",
]


def vectors_dir() -> Path | None:
    """The canonical signing-vector corpus: ``<repo-or-image root>/vectors/signing``.

    Resolves to ``/app/vectors/signing`` in the Docker image (Dockerfile.server
    copies it) and ``../vectors/signing`` in a repo checkout. None if absent —
    a badge is never minted without the corpus it claims to pin.
    """
    root = Path(__file__).resolve().parent.parent / "vectors" / "signing"
    return root if root.is_dir() else None


def run_self_checks(corpus: Path) -> tuple[int, int, list[str]]:
    """Run the server-applicable signing-conformance checks against the org's
    own primitives. Returns (passed, failed, failed_names) over PASSED_CHECKS;
    a failing check is a truthful count, not an exception."""
    import sovereign_identity

    did_vectors = json.loads((corpus / "did-key-derivations.json").read_text(encoding="utf-8"))
    v02 = json.loads((corpus / "ed25519-canonical-strings.json").read_text(encoding="utf-8"))

    failed: list[str] = []

    def check(name: str, fn) -> None:
        try:
            fn()
        except Exception:
            failed.append(name)

    def _derive(pubkey32: bytes) -> str:
        return sovereign_identity.build_did_key_from_ed25519(base64.b64encode(pubkey32).decode())

    def did_key_derivation() -> None:
        for case in did_vectors["cases"]:
            got = _derive(bytes.fromhex(case["input"]["pubkey32_hex"]))
            assert got == case["expected"]["did_key"], case["id"]

    def did_key_adversarial() -> None:
        for case in did_vectors.get("adversarial_cases", []):
            got = _derive(bytes.fromhex(case["input"]["pubkey32_hex"]))
            assert got == case["expected"]["conforming_did_key"], case["id"]
            assert got != case["expected"]["must_not_equal"], case["id"]

    def sign_roundtrip() -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        seed = bytes.fromhex(v02["signing_key"]["private_key32_hex"])
        pub = bytes.fromhex(v02["signing_key"]["public_key32_hex"])
        verifier = Ed25519PublicKey.from_public_bytes(pub)
        for case in v02["cases"]:
            # The vector's expected canonical string, signed by the server's
            # own signer — deterministic per RFC 8032, must match exactly.
            canonical = case["expected"]["canonical_string"]
            sig_b64 = sovereign_identity.ed25519_sign(canonical, base64.b64encode(seed).decode())
            assert sig_b64 == case["expected"]["signature_b64"], case["id"]
            verifier.verify(base64.b64decode(sig_b64), canonical.encode())

    for name, fn in zip(PASSED_CHECKS, [did_key_derivation, did_key_adversarial, sign_roundtrip]):
        check(name, fn)

    return len(PASSED_CHECKS) - len(failed), len(failed), failed


def _org_seed(agent_id: str) -> bytes | None:
    """The org's 32-byte Ed25519 seed, or None before the keypair exists."""
    import sovereign_identity

    kp = sovereign_identity._ed25519_keypairs.get(agent_id)
    sk = (kp or {}).get("private_key")
    return sk if isinstance(sk, bytes) and len(sk) == 32 else None


def ensure_boot_badge(agent_id: str, badge_path: Path) -> Path | None:
    """Generate + sign the org's boot badge unless a verifying one exists.

    Call AFTER ensure_chapter_keypair so the signing key is durable. Returns
    the written path or None (existing valid badge kept / no key / no corpus /
    failure — all logged loudly). Never raises: badge problems must not stop
    the org from serving.
    """
    try:
        from sm_conformance.badge import build_badge, compute_suite_digest, verify_envelope

        if badge_path.exists():
            try:
                verify_envelope(json.loads(badge_path.read_text(encoding="utf-8")))
                return None  # operator (or prior boot) badge still verifies — never clobber
            except Exception as e:
                print(f"[conformance][WARN] existing org badge does not verify ({type(e).__name__}: {e}) — regenerating")

        seed = _org_seed(agent_id)
        if seed is None:
            print("[conformance][ERROR] org has no Ed25519 keypair — cannot sign a boot badge")
            return None
        corpus = vectors_dir()
        if corpus is None:
            print("[conformance][ERROR] vectors/signing corpus not found — cannot pin a suite_digest; no badge")
            return None

        passed, failed_count, failed_names = run_self_checks(corpus)
        if failed_count:
            print(f"[conformance][ERROR] org boot self-checks FAILED: {failed_names} — badge will say so honestly")
        badge = build_badge(
            # "chapter" is this runtime's established badge name (the
            # .nanda/conformance.json contract + test_api_ergonomics assert
            # it) — impl-vocab renames never touch wire/artifact identifiers.
            "chapter",
            signing_key32=seed,
            suite_digest=compute_suite_digest(corpus),
            # A v0.5 chapter (spec/0.5/signing.md) — it enforces the one
            # normative delta, rejecting v0.2-signed mutations. 0.2/0.3/0.4
            # remain accepted within the scope stated in
            # SELF_ATTESTATION_EXTENSIONS["org.orrery.v02_scheme_scope"], so
            # they stay listed: dropping a major this org really does accept
            # would be as dishonest as the omission the advertised-version correction was filed for.
            protocol_versions=["0.5", "0.4", "0.3", "0.2"],
            completed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            passed=passed,
            failed=failed_count,
            skipped=len(SKIPPED_CHECKS),
            skipped_vectors=list(SKIPPED_CHECKS),
            extensions=SELF_ATTESTATION_EXTENSIONS,
        )
        verify_envelope(badge)  # never publish what we can't verify offline
        badge_path.parent.mkdir(parents=True, exist_ok=True)
        badge_path.write_text(json.dumps(badge, indent=2), encoding="utf-8")
        print(
            f"[conformance] org boot badge written ({passed} passed / {failed_count} failed / "
            f"{len(SKIPPED_CHECKS)} skipped client-side checks, self-attested): {badge_path}"
        )
        return badge_path
    except Exception as e:
        print(f"[conformance][ERROR] org boot badge generation failed ({type(e).__name__}: {e}) — badge stays absent")
        return None


__all__: list[Any] = ["ensure_boot_badge", "run_self_checks", "vectors_dir"]
