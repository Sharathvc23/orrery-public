"""Channel signing secrets — agent-local, owner-only.

Per-connection secrets the inbound :mod:`channel_receiver` uses to verify
webhooks: a Slack signing secret, a generic/email HMAC secret, or a Discord
application public key. They are stored ONLY on the member's machine
(``~/.community-member/channel_secrets.json``, mode 0600) and are **never sent
to the chapter** — in the W11 topology the platform posts to the member agent's
own ``:7778`` receiver directly, so the secret must live where the receiver's
``secret_resolver`` runs.

Storage follows the same 0600-JSON pattern as ``trusted_chapters.json``. Moving
these into the encrypted keystore vault is a future hardening; today the file
holds shared-with-the-platform verification secrets (not the agent's identity
key, which stays in the keystore).
"""

from __future__ import annotations

import json

from .config import CONFIG_DIR

SECRETS_FILE = CONFIG_DIR / "channel_secrets.json"


def _load() -> dict[str, str]:
    if SECRETS_FILE.exists():
        try:
            data = json.loads(SECRETS_FILE.read_text())
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError, ValueError):
            return {}
    return {}


def _save(secrets: dict[str, str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_FILE.write_text(json.dumps(secrets, indent=2, sort_keys=True))
    SECRETS_FILE.chmod(0o600)


def _key(kind: str, remote_id: str) -> str:
    return f"{kind}:{remote_id}"


def set_secret(kind: str, remote_id: str, secret: str) -> None:
    """Store (or replace) the verification secret for one connection."""
    secrets = _load()
    secrets[_key(kind, remote_id)] = secret
    _save(secrets)


def remove_secret(kind: str, remote_id: str) -> None:
    secrets = _load()
    if secrets.pop(_key(kind, remote_id), None) is not None:
        _save(secrets)


def get_secret(kind: str, remote_id: str) -> str:
    """Resolver for ``channel_receiver.build_app``: ``(kind, remote_id) → secret``
    (``""`` if unknown, which the receiver treats as reject).

    Discord verifies the app public key over the raw body *before* it can parse
    ``remote_id``, so the receiver calls this with ``remote_id=""``; a kind-only
    lookup then returns the stored secret for that kind (a member has one
    Discord app key).
    """
    secrets = _load()
    exact = secrets.get(_key(kind, remote_id))
    if exact:
        return exact
    if not remote_id:
        prefix = f"{kind}:"
        for k, v in secrets.items():
            if k.startswith(prefix):
                return v
    return ""


def has_any() -> bool:
    """True if at least one channel connection has a stored secret — the signal
    the entrypoints use to decide whether to start the :7778 receiver."""
    return bool(_load())
