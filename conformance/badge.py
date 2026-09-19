"""Conformance-badge mechanism — consumed from the sm-conformance primitive.

This module no longer reimplements the badge envelope. It re-exports the signing,
canonical-encoding, did:key, and verification primitives from ``sm_conformance``
(the published toolkit, `Sharathvc23/sm-conformance`), and keeps only the
suite-local glue: the default vector corpus this repo pins, and the
server-run provenance keys. Importing rather than forking is what guarantees the
repo's badges and the public primitive cannot diverge — the canonical
encoding (RFC 8785 JCS) and load-bearing schema validation are the primitive's,
not a copy that drifts.
"""

from __future__ import annotations

from pathlib import Path

from sm_conformance.badge import (
    SUITE_CODE_DIGEST_KEY,
    CanonicalizationError,
    VerificationError,
    canonical_json,
    derive_did_key,
    load_signing_key,
    parse_did_key,
    sign_envelope,
    verify_envelope,
)
from sm_conformance.badge import (
    compute_code_digest as _compute_code_digest,
)
from sm_conformance.badge import (
    compute_suite_digest as _compute_suite_digest,
)

DEFAULT_VECTORS_ROOT = Path(__file__).resolve().parent.parent / "vectors"
# The server suite is BEHAVIORAL: its pass/fail lives in these test modules, not in
# vectors, so suite_digest (corpus-only) does not pin what decides the result. The
# server badge therefore also carries a code_digest over this dir (sm-conformance §8).
DEFAULT_SERVER_CODE_ROOT = Path(__file__).resolve().parent / "server"

# Suite-local provenance keys recording *what* a badge attests (server-suite run
# against a live chapter vs. an offline client signing-suite run). Namespaced per
# the extensionsObject contract; a verifier MUST preserve and MUST NOT fail on them.
RUN_SURFACE_KEY = "conformance.run.surface"
SERVER_TARGET_KEY = "conformance.server.target"
# The vector subtree-scope this badge's suite_digest covers (a key in SUITE_SCOPES).
# A namespaced extension, not a top-level payload field, because the badge envelope
# schema is strict (additionalProperties: false) and extensions is its sanctioned
# home for verifier-preserved metadata.
SUITE_SCOPE_KEY = "conformance.suite.scope"


def compute_suite_digest(vectors_root: Path = DEFAULT_VECTORS_ROOT) -> str:
    """Pin a badge to this repo's vector corpus, via sm-conformance."""
    return _compute_suite_digest(vectors_root)


# Each runtime badge's suite exercises only a NARROW slice of the corpus, not the
# whole tree: the client signing-suite reads only ``vectors/signing/``; the server
# suite reads only ``vectors/trust/``. Pinning the whole-tree digest meant any
# vector add ANYWHERE (e.g. the ``vectors/arp`` cosign vectors) invalidated every
# badge and forced a credentialed re-sign for a corpus the suite never touches.
# Scoping the digest to the subtree(s) a suite actually exercises keeps the pin
# honest AND quiet. The mapping is guarded by ``conformance/test_suite_scope.py`` —
# a suite that grows to read another subtree fails that test until its scope (and
# badge) are updated, so a badge can never silently go stale-but-green.
SUITE_SCOPES: dict[str, tuple[str, ...]] = {
    "signing": ("signing",),  # client signing-suite — member-sdk, openclaw-skill
    "trust": ("trust",),  # server suite — chapter (also pins a code_digest; behavioral)
}


def scoped_suite_digest(scope: str, vectors_root: Path = DEFAULT_VECTORS_ROOT) -> str:
    """``suite_digest`` over only the subtree(s) the named ``scope`` exercises.

    For a single-subtree scope this is exactly :func:`compute_suite_digest` over
    that subtree. For a multi-subtree scope the per-subtree digests are folded in
    declared order, so the result is deterministic and independent of filesystem
    traversal order. Raises ``ValueError`` on an unknown scope — an unknown scope
    must never silently fall back to a whole-tree or empty digest."""
    subtrees = SUITE_SCOPES.get(scope)
    if not subtrees:
        raise ValueError(f"unknown suite scope {scope!r}; known: {sorted(SUITE_SCOPES)}")
    if len(subtrees) == 1:
        return compute_suite_digest(vectors_root / subtrees[0])
    import hashlib

    h = hashlib.sha256()
    for name in subtrees:  # declared order — stable regardless of rglob order
        h.update(name.encode("utf-8"))
        h.update(b"\x00")
        h.update(compute_suite_digest(vectors_root / name).encode("utf-8"))
        h.update(b"\x00")
    return f"sha256:{h.hexdigest()}"


def server_run_extensions(chapter_url: str) -> dict[str, str]:
    """Provenance for a server-suite badge: surface, target chapter, and the digest
    of the server test CODE (which is what actually decides the run, since the
    server suite is behavioral, not vector-driven)."""
    return {
        RUN_SURFACE_KEY: "server",
        SERVER_TARGET_KEY: chapter_url.rstrip("/"),
        SUITE_CODE_DIGEST_KEY: _compute_code_digest(DEFAULT_SERVER_CODE_ROOT),
    }


__all__ = [
    "DEFAULT_SERVER_CODE_ROOT",
    "DEFAULT_VECTORS_ROOT",
    "RUN_SURFACE_KEY",
    "SERVER_TARGET_KEY",
    "SUITE_CODE_DIGEST_KEY",
    "SUITE_SCOPES",
    "SUITE_SCOPE_KEY",
    "CanonicalizationError",
    "VerificationError",
    "canonical_json",
    "compute_suite_digest",
    "derive_did_key",
    "load_signing_key",
    "parse_did_key",
    "scoped_suite_digest",
    "server_run_extensions",
    "sign_envelope",
    "verify_envelope",
]
