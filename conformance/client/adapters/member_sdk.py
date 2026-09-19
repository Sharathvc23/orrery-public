"""Adapter for the member-sdk runtime — the agent package in ``agent/``.

The agent package (``community_member``) is the canonical reference
implementation. Its signing helpers live at ``community_member/auth.py`` and
``community_member/crypto.py``; this adapter delegates the pure operations the
conformance suite needs.

The package root is added to ``sys.path``; it defaults to the repo's ``agent/``
directory, or to ``$COMMUNITY_MEMBER_PATH`` when that env var is set.
"""

from __future__ import annotations

import base64
import importlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SDK_PATH = REPO_ROOT / "agent"


def _resolve_sdk_path() -> Path:
    env_path = os.environ.get("COMMUNITY_MEMBER_PATH")
    if env_path:
        return Path(env_path).resolve()
    return DEFAULT_SDK_PATH.resolve()


class MemberSDKAdapter:
    """Wraps ``community_member.auth`` + ``community_member.crypto``."""

    def __init__(self, sdk_path: Path | None = None) -> None:
        path = (sdk_path or _resolve_sdk_path()).resolve()
        if not (path / "community_member" / "auth.py").exists():
            raise FileNotFoundError(
                f"member-sdk not found at {path}. "
                f"Set COMMUNITY_MEMBER_PATH or migrate via MIGRATION.md Stage 2."
            )
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
        self._auth = importlib.import_module("community_member.auth")
        self._crypto = importlib.import_module("community_member.crypto")
        self.runtime_path = str(path)
        self.name = "member-sdk"

    def derive_did_key(self, pubkey32: bytes) -> str:
        if len(pubkey32) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
        return self._crypto.build_did_key(base64.b64encode(pubkey32).decode())

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        # Delegate to the SDK's own canonical function — the same one
        # sign_request_body() calls — so the suite verifies the runtime, not a copy.
        return self._auth.canonical_string_v02(body, agent_id, timestamp)

    def sign(self, private_key32: bytes, canonical: str) -> str:
        if len(private_key32) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
        priv_b64 = base64.b64encode(private_key32).decode()
        return self._crypto.ed25519_sign_message(canonical, priv_b64)

    def compose_headers(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        signature_b64: str,
    ) -> dict[str, str]:
        # Delegate to the SDK's own header composer (same one sign_request_body uses).
        return self._auth.compose_signed_headers_v02(agent_id, did_key, timestamp, signature_b64)

    # the org protocol v0.3 — see spec/0.3/signing.md. Both the canonical
    # string and the header set delegate to community_member.auth, the single
    # source of truth sign_request_body() itself routes through.

    def canonical_string_v03(
        self,
        method: str,
        url_path: str,
        body: str,
        agent_id: str,
        timestamp: str,
        nonce: str,
    ) -> str:
        return self._auth.canonical_string_v03(method, url_path, body, agent_id, timestamp, nonce)

    def compose_headers_v03(
        self,
        agent_id: str,
        did_key: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> dict[str, str]:
        return self._auth.compose_signed_headers_v03(
            agent_id, did_key, timestamp, nonce, signature_b64
        )
