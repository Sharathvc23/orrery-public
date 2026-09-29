"""Claim this agent's own name on a NANDA Index v3.

WHY NOT ``index_registrar``
---------------------------
That module registers a tenant on an Index **v2**, which is account-based: it
authenticates with ``INDEX_ACCOUNT_EMAIL`` and ``INDEX_ACCOUNT_PASSWORD`` and
creates a row on behalf of whoever holds those credentials.

v3 has no accounts. Its ``key`` anchor admits exactly
``urn:ai:key:<subject_key>`` and paths beneath it, where ``subject_key`` *is*
this agent's Ed25519 public key. The name is the key, so the only party who can
register it is the party holding it — and the registration is a signature over
the intent, not a login.

That makes these two different operations, not two transports for one operation.
An operator cannot register an agent on v3 "on its behalf": doing so under a key
the operator generated registers a *different identity that happens to be named
after* the agent. Hence a sibling module rather than a branch inside the other.

One key, three views
--------------------
The key this signs with is the one ``auth`` already signs requests with and the
one ``arp`` derives ``did:key`` from for receipts. So the name in the index, the
DID on the agent card, and the issuer on every receipt are one key in three
encodings — not three assertions that happen to agree.

Renewal, and why it is conditional
----------------------------------
A v3 record expires and **revocation is non-renewal**, so an agent that stops
renewing correctly disappears from discovery. Re-registering on start is
therefore the intended lifecycle. Doing it *unconditionally* is not: a restart
loop would write a run of entries into a log that cannot be edited. So this
resolves first and writes only when the index has nothing current, or when the
record is close enough to lapsing to be worth replacing.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any, Callable

log = logging.getLogger(__name__)

__all__ = [
    "AGENT_CARD_MEDIA_TYPE",
    "DEFAULT_RENEW_WITHIN_SECONDS",
    "IndexV3Error",
    "ensure_registered",
    "key_urn",
    "register",
    "sign_intent",
    "subject_key_of",
]

# SPEC/pointer-record.md §4 of nanda-index-v3. A v1 signature uses a different
# context string and will not verify against a v2 challenge.
INTENT_CONTEXT = b"nanda-index-v3/intent-v2:"
INTENT_FIELDS = (
    "id", "subject_key", "next_hop", "media_type",
    "nonce", "audience", "not_after", "prev",
)

_URN_KEY_PREFIX = "urn:ai:key:"

AGENT_CARD_MEDIA_TYPE = "application/a2a-agent-card+json"

DEFAULT_RENEW_WITHIN_SECONDS = 12 * 60 * 60


class IndexV3Error(Exception):
    """The index refused, or answered something this client cannot act on."""


def _seed(private_key_b64: str) -> bytes:
    """The 32-byte Ed25519 seed, as ``config.private_key`` stores it."""
    return base64.b64decode(private_key_b64)


def subject_key_of(private_key_b64: str) -> str:
    """Multibase ``u`` (base64url, unpadded) over the raw public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = (
        Ed25519PrivateKey.from_private_bytes(_seed(private_key_b64))
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return "u" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def key_urn(subject_key: str, path: str = "") -> str:
    """The only id space a ``key`` registration may claim for this key."""
    base = _URN_KEY_PREFIX + subject_key
    return f"{base}/{path}" if path else base


def sign_intent(private_key_b64: str, challenge: dict[str, Any]) -> str:
    """Sign the registration intent the challenge names.

    The signature covers the id, subject key, next hop, media type and nonce
    together — not the nonce alone. Signing a bare nonce would leave the index
    free to substitute the pointer target: the subject would have proved it was
    present, not that it asked for *this* destination.

    Fields the challenge does not carry are omitted rather than sent as null.
    Under JCS an absent key and a null one canonicalize to different bytes, so
    inventing a null signs something the index never issued.
    """
    import jcs
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = {k: challenge[k] for k in INTENT_FIELDS if k in challenge}
    signature = Ed25519PrivateKey.from_private_bytes(_seed(private_key_b64)).sign(
        INTENT_CONTEXT + jcs.canonicalize(body)
    )
    return base64.b64encode(signature).decode("ascii")


def register(
    *,
    index_url: str,
    private_key_b64: str,
    next_hop: str,
    path: str = "agent",
    media_type: str = AGENT_CARD_MEDIA_TYPE,
    timeout: float = 15.0,
    http: Any | None = None,
) -> dict[str, Any]:
    """Two round trips: ask for a challenge, then prove control of the key."""
    import httpx

    client = http or httpx
    base = index_url.rstrip("/")
    subject_key = subject_key_of(private_key_b64)
    agent_id = key_urn(subject_key, path)

    started = client.post(
        f"{base}/v1/register",
        json={
            "id": agent_id, "subject_key": subject_key, "next_hop": next_hop,
            "media_type": media_type, "anchor_type": "key",
        },
        timeout=timeout,
    )
    if started.status_code >= 400:
        raise IndexV3Error(f"/v1/register refused ({started.status_code}): {started.text}")

    challenge = started.json().get("challenge")
    if not challenge:
        raise IndexV3Error(f"/v1/register returned no challenge: {started.text}")

    proved = client.post(
        f"{base}/v1/prove",
        json={
            "challenge_id": challenge["challenge_id"],
            "response": {"subject_sig": sign_intent(private_key_b64, challenge)},
        },
        timeout=timeout,
    )
    if proved.status_code >= 400:
        raise IndexV3Error(f"/v1/prove refused ({proved.status_code}): {proved.text}")

    result = proved.json()
    if "record" not in result:
        raise IndexV3Error(f"/v1/prove returned no record: {proved.text}")
    return result


def ensure_registered(
    *,
    index_url: str,
    private_key_b64: str,
    next_hop: str,
    path: str = "agent",
    media_type: str = AGENT_CARD_MEDIA_TYPE,
    renew_within: float = DEFAULT_RENEW_WITHIN_SECONDS,
    now: Callable[[], datetime] | None = None,
    timeout: float = 15.0,
    http: Any | None = None,
) -> dict[str, Any]:
    """Register only if the index has nothing current for this name.

    Returns ``{"action": "registered"|"renewed"|"current"|"unreachable"|"failed", ...}``.

    Never raises for an unreachable or refusing index. An agent that cannot
    reach discovery should still serve the peers that already know where it is;
    turning someone else's outage into ours is the worse failure.
    """
    import httpx

    client = http or httpx
    clock = now or (lambda: datetime.now(timezone.utc))
    base = index_url.rstrip("/")
    agent_id = key_urn(subject_key_of(private_key_b64), path)

    try:
        found = client.get(f"{base}/v1/resolve", params={"id": agent_id}, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - an unreachable index is not our failure
        log.warning("index v3 unreachable at %s: %s", base, exc)
        return {"action": "unreachable", "id": agent_id, "detail": str(exc)[:200]}

    if found.status_code == 200:
        record = found.json().get("record", {})
        raw = record.get("expires_at", "")
        try:
            expires = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            expires = None
        if expires is not None and (expires - clock()).total_seconds() > renew_within:
            return {"action": "current", "id": agent_id,
                    "seq": record.get("seq"), "expires_at": raw}
        action = "renewed"
    elif found.status_code == 404:
        # "never registered" and "lapsed" both land here, and the fix is the same.
        action = "registered"
    else:
        log.warning("index v3 resolve returned %s for %s", found.status_code, agent_id)
        return {"action": "failed", "id": agent_id,
                "detail": f"resolve returned {found.status_code}"}

    try:
        result = register(
            index_url=base, private_key_b64=private_key_b64, next_hop=next_hop,
            path=path, media_type=media_type, timeout=timeout, http=client,
        )
    except IndexV3Error as exc:
        log.warning("index v3 registration failed for %s: %s", agent_id, exc)
        return {"action": "failed", "id": agent_id, "detail": str(exc)[:300]}

    return {"action": action, "id": agent_id, "seq": result["record"]["seq"],
            "expires_at": result["record"]["expires_at"]}
