"""Adapter contract that every runtime's signing helper must satisfy.

A conformant runtime exposes the four v0.2 operations below plus the two v0.3
operations (``canonical_string_v03`` / ``compose_headers_v03``) further down —
six in total. The conformance suite calls into the adapter and asserts the
outputs against the spec's test vectors. Implementations of this Protocol live
alongside this file; selection is by the ``--adapter`` pytest CLI flag.

The v0.2 core is intentionally narrow:

- ``derive_did_key`` is a pure function: 32-byte public key in, did:key
  string out. No side effects, no time, no I/O.

- ``canonical_string`` is a pure function: body, agent_id, timestamp in,
  canonical string out. The canonical string is what the adapter would
  sign; tests verify it matches the spec's positional format
  ``body:agent_id:timestamp``.

- ``sign`` produces a base64-encoded Ed25519 signature for a canonical
  string given a 32-byte private seed. Verifying signatures is *not* part
  of the adapter contract — that is the chapter's job.

- ``compose_headers`` returns the dictionary the runtime would attach to a
  request. Header names, casing, and values are checked against
  ``spec/0.2/signing.md``.

A conforming runtime that implements its signing internally (e.g. the
member-sdk's ``sign_request_body`` does everything in one call) MUST
expose these pure operations to the adapter so the conformance suite
verifies the runtime's own canonical/headers, not a reimplemented copy.
"""

from __future__ import annotations

from typing import Protocol


class SigningAdapter(Protocol):
    """Uniform interface for testing any runtime's signing helper."""

    name: str
    """Short, human-readable identifier — appears in conformance reports."""

    runtime_path: str
    """Filesystem path the adapter was constructed against — for traceability."""

    def derive_did_key(self, pubkey32: bytes) -> str:
        """32-byte Ed25519 public key → ``did:key:z<base58btc(0xed01||pubkey)>``."""
        ...

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        """Return the exact string the adapter would Ed25519-sign for this request."""
        ...

    def sign(self, private_key32: bytes, canonical: str) -> str:
        """Standard-base64 Ed25519 signature over ``canonical`` using ``private_key32``."""
        ...

    def compose_headers(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        signature_b64: str,
    ) -> dict[str, str]:
        """Return the header dict the runtime would attach to a signed request."""
        ...

    # ------------------------------------------------------------------
    # the org protocol v0.3 contract — adds method, url_path, and
    # a per-request nonce to the canonical string. Adapters that have
    # not been migrated to v0.3 may inherit a `NotImplemented` default
    # (see `base_v03_default` in spec_reference.py and runtime adapters)
    # — those tests will skip rather than fail.
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
        """Return the exact string the adapter would Ed25519-sign for a v0.3 request."""
        ...

    def compose_headers_v03(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> dict[str, str]:
        """Return the v0.3 header dict (includes X-Agent-Nonce + ed25519+nonce scheme)."""
        ...
