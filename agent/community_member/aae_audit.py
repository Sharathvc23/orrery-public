"""AAE chain + checkpoint export for the sm-attest-auditor drill.

``sm-attest-auditor`` is the React forensic workbench for envelope chains: a
forward chain-walk following ``predecessor_hash`` links, and a reverse drill
from a checkpoint envelope via Merkle inclusion proofs. It is substrate-neutral
and takes a pre-fetched ``AuditableEnvelope[]`` — this module produces that
input from the agent's own sm-aae chain (``consent/aae_emit.py``), so the
"was it authorized?" history is drillable offline: the auditor never calls back
to the agent.

Mapping (thin adapter per ``docs/integrations/STELLARMINDS.md``):

- Each stored envelope is exported through the existing verify-gated
  ``aae_export.aae_envelope_to_attestation_event`` (a tampered envelope drops
  out of the export — the drill then shows the broken link), plus the two
  auditor chain fields: ``envelope_hash`` (``sm_aae.envelope_hash``, the value
  a successor's ``prev_hash`` commits to) and ``predecessor_hash``.
- The checkpoint envelope commits the whole chain: leaves are the envelopes'
  canonical hashes, folded into a Merkle root the auditor's verifier
  reproduces. NOTE: the auditor folds ``SHA-256(left || right)`` over raw
  bytes WITHOUT the RFC 6962 domain-separation prefixes (its
  "rfc6962-sha256" label notwithstanding — flagged upstream), so the tree
  here is the plain-concat construction, odd node duplicated. This is a
  DISPLAY commitment for the drill; the cryptographic trust stays on the
  per-envelope Ed25519 signatures, verified Python-side at export.

Signature verification happens HERE (the auditor v0.1 treats proof blocks as
opaque); what ships is already-verified, self-contained evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

MERKLE_METHOD = "sha256-concat"


def _fold_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def _merkle_root(leaves_hex: list[str]) -> str:
    """Plain-concat Merkle root over hex leaf hashes (odd node duplicated) —
    the construction whose inclusion paths fold correctly under the auditor's
    ``verifyMerkleInclusion``. Empty chain has no root; callers guard."""
    level = [bytes.fromhex(h) for h in leaves_hex]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        level = [_fold_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def _inclusion_path(leaves_hex: list[str], index: int) -> list[dict[str, str]]:
    """Sibling path (leaf → root) for ``leaves_hex[index]``, in the auditor's
    ``{hash, position}`` shape — ``position`` is where the SIBLING sits."""
    path: list[dict[str, str]] = []
    level = [bytes.fromhex(h) for h in leaves_hex]
    i = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        sibling = i ^ 1
        path.append({"hash": level[sibling].hex(), "position": "left" if i % 2 else "right"})
        level = [_fold_pair(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return path


def export_auditable_envelopes(
    *,
    tenant: str,
    agent_id: str | None = None,
    public: bool = False,
) -> list[dict[str, Any]]:
    """The agent's AAE chain as auditor-ready ``AuditableEnvelope`` dicts,
    genesis-first. Verify-gated: an envelope that fails ``verify_envelope``
    exports nothing — the drill's chain-walk then halts at the gap, which is
    exactly the tamper signal the auditor exists to surface."""
    from sm_aae import envelope_hash

    from .aae_export import aae_envelope_to_attestation_event
    from .consent import aae_emit

    out: list[dict[str, Any]] = []
    for env in aae_emit.list_envelopes(agent_id):
        event = aae_envelope_to_attestation_event(env, tenant=tenant, public=public)
        if not event:
            continue  # tampered/malformed stored envelope: leaves a visible gap
        event["envelope_hash"] = envelope_hash(env)
        if env.get("prev_hash"):
            event["predecessor_hash"] = env["prev_hash"]
        out.append(event)
    return out


def build_checkpoint_envelope(
    envelopes: list[dict[str, Any]],
    *,
    tenant: str,
    scope_key: str,
    as_of: str | None = None,
    public: bool = False,
) -> dict[str, Any] | None:
    """A ``type:"checkpoint"`` envelope committing ``envelopes`` (the output of
    :func:`export_auditable_envelopes`, genesis-first). None for an empty chain.

    The checkpoint joins the chain (``predecessor_hash`` = the tip's hash) so
    the auditor's reverse drill walks from it back to genesis; its Merkle root
    commits every envelope's canonical hash, and ``predecessor_hashes`` carries
    the leaf list so the drill is fully self-contained offline.
    """
    if not envelopes:
        return None
    leaves = [str(e["envelope_hash"]) for e in envelopes]
    stamp = as_of or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    actor = dict(envelopes[-1]["actor"])
    body: dict[str, Any] = {
        "v": 1,
        "ts": stamp,
        "tenant": tenant,
        "actor": actor,
        "topic": "sdk.checkpoint.aae-chain",
        "type": "checkpoint",
        "classification": "public" if public else "internal",
        "payload": {
            "subject": actor,
            "checkpoint_subject": {
                "scope": "agent",
                "scope_key": scope_key,
                "as_of_ts": stamp,
                "covered_envelopes_count": len(leaves),
            },
            "merkle_root": _merkle_root(leaves),
            "merkle_inclusion_proof_method": MERKLE_METHOD,
            "predecessor_hashes": leaves,
        },
        "lifecycle": "anchored",
        "predecessor_hash": leaves[-1],
    }
    # A stable identity for the checkpoint node itself (nothing chains onto it,
    # but the auditor keys the walk by envelope_hash).
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    body["id"] = digest
    body["envelope_hash"] = digest
    return body


def inclusion_proof(
    envelopes: list[dict[str, Any]],
    leaf_hash: str,
) -> dict[str, Any] | None:
    """The auditor-shaped ``MerkleInclusionProof`` for one envelope of the
    chain — ``{leafHash, siblings, expectedRoot}`` — or None when ``leaf_hash``
    is not in the chain. Folds to the checkpoint's ``merkle_root`` under the
    auditor's plain-concat verifier."""
    leaves = [str(e["envelope_hash"]) for e in envelopes]
    if leaf_hash not in leaves:
        return None
    return {
        "leafHash": leaf_hash,
        "siblings": _inclusion_path(leaves, leaves.index(leaf_hash)),
        "expectedRoot": _merkle_root(leaves),
    }


__all__ = [
    "MERKLE_METHOD",
    "build_checkpoint_envelope",
    "export_auditable_envelopes",
    "inclusion_proof",
]
