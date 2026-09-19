"""Self-contained reference implementation of the v0.2 client signing spec.

This adapter is the executable form of ``spec/0.2/signing.md`` and
``spec/0.2/did-key.md``. It depends only on standard library plus
``cryptography`` and ``base58`` — no other runtime, no external
repository — so it can run in CI without cross-repo checkout.

Roles:

- **Source of truth in code form.** When the prose spec says ``canonical
  = body:agent_id:timestamp``, this adapter computes that. When the prose
  spec says ``did:key:z<base58btc(0xed01||pubkey)>``, this adapter
  produces that.
- **CI baseline.** Every PR runs the conformance suite against this
  adapter. If a vector or test contradicts the spec, this adapter fails
  the suite immediately, before any runtime is even considered.
- **Drift sentinel.** If a future runtime adapter passes but this adapter
  fails, the spec and the vectors have drifted from each other. The fix
  is to update the prose spec or the vectors, never to weaken this
  adapter.

Runtime adapters (``member-sdk``, ``openclaw-skill``, future SDKs in
other languages) are tested separately and need not be available for
this adapter to run.
"""

from __future__ import annotations

import base64

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ED25519_MULTICODEC_PREFIX = b"\xed\x01"


class SpecReferenceAdapter:
    """Pure-Python reference implementation of the v0.2 signing spec.

    Implements every operation the conformance suite asserts. Tests
    against this adapter MUST pass at all times — failures indicate the
    spec, the vectors, or this adapter has drifted from the others.
    """

    name = "spec-reference"
    runtime_path = __file__

    def derive_did_key(self, pubkey32: bytes) -> str:
        if len(pubkey32) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
        prefixed = ED25519_MULTICODEC_PREFIX + pubkey32
        encoded = base58.b58encode(prefixed).decode()
        return f"did:key:z{encoded}"

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        return f"{body}:{agent_id}:{timestamp}"

    def sign(self, private_key32: bytes, canonical: str) -> str:
        if len(private_key32) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
        priv = Ed25519PrivateKey.from_private_bytes(private_key32)
        return base64.b64encode(priv.sign(canonical.encode())).decode()

    def compose_headers(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        signature_b64: str,
    ) -> dict[str, str]:
        return {
            "X-Agent-ID": agent_id,
            "X-Agent-DID-Key": did_key,
            "X-Agent-Sig-Scheme": "ed25519",
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Signature": signature_b64,
        }

    # ------------------------------------------------------------------
    # the org protocol v0.3 — adds method, url_path, and a
    # per-request nonce to the canonical string. Same Ed25519 key, same
    # did:key derivation. v0.2 methods above continue to apply when an
    # implementation negotiates `ed25519` instead of `ed25519+nonce`.
    # ------------------------------------------------------------------

    def canonical_string_v03(
        self,
        method: str,
        url_path: str,
        body: str,
        agent_id: str,
        timestamp: str,
        nonce: str,
    ) -> str:
        return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"

    def compose_headers_v03(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> dict[str, str]:
        return {
            "X-Agent-ID": agent_id,
            "X-Agent-DID-Key": did_key,
            "X-Agent-Sig-Scheme": "ed25519+nonce",
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature_b64,
        }
