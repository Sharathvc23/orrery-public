"""Adapter for orrery's drop-in skill at ``skill/``.

The skill's ``helpers/sign_request.py`` implements the v0.2 + v0.3 client
signing contract directly. This adapter wraps the helper's pure-function
primitives so the conformance suite verifies orrery's SHIPPED skill against
the same committed vectors the reference adapter is verified against.

Resolution order:

1. ``OPENCLAW_SKILL_PATH`` environment variable.
2. ``skill/`` at the repo root (orrery's drop-in skill — the default).
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _resolve_skill_path() -> Path:
    env_path = os.environ.get("OPENCLAW_SKILL_PATH")
    if env_path:
        return Path(env_path).resolve()
    # Orrery ships the drop-in skill at the repo root `skill/`; its
    # helpers/sign_request.py implements the v0.2 + v0.3 signing operations this
    # adapter wraps.
    return REPO_ROOT / "skill"


class OpenClawSkillAdapter:
    """Wraps ``openclaw-skill/helpers/sign_request.py`` (v0.2-conformant)."""

    def __init__(self, skill_path: Path | None = None) -> None:
        path = (skill_path or _resolve_skill_path()).resolve()
        helper = path / "helpers" / "sign_request.py"
        if not helper.exists():
            raise FileNotFoundError(
                f"openclaw-skill helper not found at {helper}. "
                f"Set OPENCLAW_SKILL_PATH or run from a full repo checkout "
                f"(the drop-in skill lives at skill/)."
            )
        helpers_dir = str(path / "helpers")
        if helpers_dir not in sys.path:
            sys.path.insert(0, helpers_dir)
        self._sign_request = importlib.import_module("sign_request")
        self.runtime_path = str(path)
        self.name = "openclaw-skill"

    def derive_did_key(self, pubkey32: bytes) -> str:
        # Calls the helper's _build_did_key directly; spec-conformant
        # base58btc encoding per spec/0.2/did-key.md.
        return self._sign_request._build_did_key(pubkey32)

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        # Delegate to the helper's own canonical function — the same one
        # _signed_headers() calls — so the suite verifies the runtime, not a copy.
        return self._sign_request.canonical_string_v02(body, agent_id, timestamp)

    def sign(self, private_key32: bytes, canonical: str) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if len(private_key32) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
        priv = Ed25519PrivateKey.from_private_bytes(private_key32)
        # Delegate the signing primitive (sign + base64 encoding) to the helper.
        return self._sign_request.ed25519_sign(priv, canonical)

    def compose_headers(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        signature_b64: str,
    ) -> dict[str, str]:
        return self._sign_request.compose_signed_headers_v02(
            agent_id, did_key, timestamp, signature_b64
        )

    # the org protocol v0.3 — see spec/0.3/signing.md. Both the canonical
    # string and the header set delegate to the helper, the single source of
    # truth _signed_headers() itself routes through.

    def canonical_string_v03(
        self,
        method: str,
        url_path: str,
        body: str,
        agent_id: str,
        timestamp: str,
        nonce: str,
    ) -> str:
        return self._sign_request.canonical_string_v03(
            method, url_path, body, agent_id, timestamp, nonce
        )

    def compose_headers_v03(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> dict[str, str]:
        return self._sign_request.compose_signed_headers_v03(
            agent_id, did_key, timestamp, nonce, signature_b64
        )
