"""Boot-time conformance badge — live out of the box, honestly.

At startup the agent runs the client signing-conformance checks IN-PROCESS
against its own signing code — the same five checks, over the same vector
corpus, that ``conformance/client/test_signing_conformance.py`` runs through
the member-sdk adapter in CI — and signs a badge over the real counts.

Honesty contract, extending ``conformance_badge.py``'s:

* The checks execute the runtime's actual functions (``crypto.build_did_key``,
  ``auth.canonical_string_v02/v03``, ``crypto.ed25519_sign_message``) — the
  exact delegation the member-sdk conformance adapter uses. No copies, no
  fabricated counts: a runtime that drifts from the spec fails its own boot
  checks and the badge says so.
* ``suite_digest`` is computed from the embedded corpus
  (``_conformance_vectors/``), which is a byte-for-byte mirror of the
  canonical ``vectors/signing/`` locked by a drift-guard test — so the digest
  equals the canonical corpus digest.
* The payload is explicitly labelled **self-attested**: the signature proves
  who produced the badge and that it is untampered, and the counts came from
  a real in-process run — but no third party witnessed it. Third-party
  witnessing is what a countersigned badge (sm-conformance ``countersign``)
  would add; this is not that.
* A boot badge never clobbers an existing badge that still verifies — an
  operator-generated badge (scripts/gen_conformance_badge.py) wins until it
  is removed or stops verifying.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

# Extension keys are reverse-DNS namespaced per the sm-conformance badge schema.
SELF_ATTESTATION_EXTENSIONS = {
    "org.orrery.attestation": "self-attested",
    "org.orrery.witness": "none",
    "org.orrery.generator": "boot-self-check",
}

# The five checks mirror conformance/client/test_signing_conformance.py by
# name; counts are per-check so a boot badge reads identically to a badge
# generated from a real pytest run of that suite.
CHECK_NAMES = [
    "test_did_key_derivation",
    "test_did_key_adversarial_drift_rejected",
    "test_canonical_string_v02",
    "test_sign_roundtrip_v02",
    "test_canonical_string_v03",
]


def vectors_dir() -> Path:
    """Filesystem path of the embedded signing-vector corpus."""
    return Path(str(resources.files("community_member") / "_conformance_vectors"))


def _load(name: str) -> dict[str, Any]:
    import json

    return json.loads((vectors_dir() / name).read_text(encoding="utf-8"))


def run_self_checks() -> tuple[int, int, list[str]]:
    """Run the five signing-conformance checks against this runtime's own code.

    Returns (passed, failed, failed_names). Never raises on a failing check —
    a failure is a truthful count, not an exception.
    """
    from . import auth, crypto

    failed: list[str] = []

    def check(name: str, fn) -> None:
        try:
            fn()
        except Exception:
            failed.append(name)

    did_vectors = _load("did-key-derivations.json")
    v02 = _load("ed25519-canonical-strings.json")
    v03 = _load("canonical-strings-v03.json")

    def _derive(pubkey32: bytes) -> str:
        return crypto.build_did_key(base64.b64encode(pubkey32).decode())

    def did_key_derivation() -> None:
        for case in did_vectors["cases"]:
            got = _derive(bytes.fromhex(case["input"]["pubkey32_hex"]))
            assert got == case["expected"]["did_key"], case["id"]

    def did_key_adversarial() -> None:
        for case in did_vectors.get("adversarial_cases", []):
            got = _derive(bytes.fromhex(case["input"]["pubkey32_hex"]))
            assert got == case["expected"]["conforming_did_key"], case["id"]
            assert got != case["expected"]["must_not_equal"], case["id"]

    def canonical_v02() -> None:
        for case in v02["cases"]:
            i = case["input"]
            got = auth.canonical_string_v02(i["body"], i["agent_id"], i["timestamp"])
            assert got == case["expected"]["canonical_string"], case["id"]

    def sign_roundtrip_v02() -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        seed = bytes.fromhex(v02["signing_key"]["private_key32_hex"])
        pub = bytes.fromhex(v02["signing_key"]["public_key32_hex"])
        verifier = Ed25519PublicKey.from_public_bytes(pub)
        for case in v02["cases"]:
            i = case["input"]
            canonical = auth.canonical_string_v02(i["body"], i["agent_id"], i["timestamp"])
            sig_b64 = crypto.ed25519_sign_message(canonical, base64.b64encode(seed).decode())
            assert sig_b64 == case["expected"]["signature_b64"], case["id"]
            verifier.verify(base64.b64decode(sig_b64), canonical.encode())

    def canonical_v03() -> None:
        for case in v03["cases"]:
            i = case["input"]
            got = auth.canonical_string_v03(
                i["method"], i["url_path"], i["body"], i["agent_id"], i["timestamp"], i["nonce"]
            )
            assert got == case["expected"]["canonical_string"], case["id"]

    for name, fn in zip(
        CHECK_NAMES,
        [did_key_derivation, did_key_adversarial, canonical_v02, sign_roundtrip_v02, canonical_v03],
    ):
        check(name, fn)

    return len(CHECK_NAMES) - len(failed), len(failed), failed


def ensure_boot_badge(config) -> Path | None:
    """Generate + sign the boot badge unless a verifying badge already exists.

    Returns the written path, or None when nothing was written (existing valid
    badge kept, no signing key yet, or generation failed — all logged loudly).
    Never raises: a badge problem must not stop the agent from serving.
    """
    from .conformance_badge import (
        build_self_badge,
        load_badge,
        signing_key32,
        verify_badge,
        write_badge,
    )

    existing = load_badge()
    if existing is not None:
        try:
            verify_badge(existing)
            return None  # operator (or prior boot) badge still verifies — never clobber
        except Exception as e:
            print(f"[conformance][WARN] existing badge does not verify ({type(e).__name__}: {e}) — regenerating")

    if signing_key32(config) is None:
        print(
            "[conformance][ERROR] no 32-byte Ed25519 signing key — cannot sign a boot badge; "
            "/.well-known/conformance.json stays 404"
        )
        return None

    try:
        from sm_conformance.badge import compute_suite_digest

        passed, failed_count, failed_names = run_self_checks()
        if failed_count:
            print(f"[conformance][ERROR] boot self-checks FAILED: {failed_names} — badge will say so honestly")
        badge = build_self_badge(
            config,
            suite_digest=compute_suite_digest(vectors_dir()),
            protocol_versions=["0.3", "0.2"],
            passed=passed,
            failed=failed_count,
            completed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            extensions=SELF_ATTESTATION_EXTENSIONS,
        )
        verify_badge(badge)  # never publish what we can't verify offline
        path = write_badge(badge)
        print(f"[conformance] boot badge written ({passed} passed / {failed_count} failed, self-attested): {path}")
        return path
    except Exception as e:
        print(
            f"[conformance][ERROR] boot badge generation failed ({type(e).__name__}: {e}) — "
            "/.well-known/conformance.json stays 404"
        )
        return None
