"""Platform uninstall events — the half of the platform-uninstall work that needs no partner account.

⚠️ WHAT THIS IS AND IS NOT. The platform-uninstall work is blocked on a Square partner account, and the
OAuth/install leg stays blocked: there is no provider SDK here, no partner
credential, and ``platform_install.py`` keeps refusing honestly. But the platform-uninstall work names
the uninstall webhook as the load-bearing half —

    "Businesses do not notify registries when they change vendors; they stop
    using the old one."

— and a receiver for that event is generic. It became buildable only once the owner-attested rework
gave the event somewhere to land: before there was a lifecycle, there was no
state to transition to.

⚠️⚠️ AN UNINSTALL PRODUCES ``suspended``, NEVER ``revoked``, and the reasoning is
the one the owner-attested rework already committed to:

  - ``revoked`` means THE OWNER WITHDREW. ``owner_attested`` exists precisely so
    a runtime's word is never reported as the owner's. An uninstall is observed
    by the PLATFORM as a side effect of its own billing; the owner asserted
    nothing. Recording it as a revocation would attribute a withdrawal to
    someone who never made one — the same plausible-wrong-answer failure in a
    third costume.
  - ``revoked`` is TERMINAL. A business that switches POS and later comes back
    would need fresh consent because of an event it never performed.
  - ``suspended`` is reversible, honest, and still tells a caller not to
    transact, which is the actual requirement: a stale endpoint is worse than a
    missing one.

The recorded authority is therefore THE PLATFORM, not the owner did, and the
answer stays ``owner_attested: false``.

⚠️ FAIL CLOSED, AND MIND WHICH WAY. An unverified webhook must transition
NOTHING: an attacker who could suspend arbitrary listings with an unsigned POST
would hold a denial-of-listing primitive over every business served. So the
signature is required, the secret is required (unset ≡ empty ≡ whitespace ≡ not
configured), there is no default, and a failing request changes no state and
says so.

⚠️ THE OPPOSITE FAILURE IS REAL AND IS NOT SOLVED HERE. A webhook we never
receive — endpoint unreachable, secret rotated, platform retries exhausted —
leaves a departed business listed ``active`` forever, which is exactly the stale
endpoint the draft calls more dangerous than a missing one. Closing that needs
reconciliation against the platform's API, which needs the account this unit
does not have. It is recorded in docs/HARDENING.md rather than papered over: this
receiver is best-effort notification, not a guarantee of freshness.

⚠️ THE WIRE SHAPE IS AN ASSUMPTION, LABELLED AS ONE. ``hmac-sha256`` over the RAW
body with a constant-time compare is the common denominator across Shopify, Wix
and Square, but each spells the header and encoding differently. So verification
is INJECTED — the same seam as ``owner.make_bound_domain_control_verifier`` — and
:func:`make_hmac_verifier` is one implementation of it, not the contract. A real
provider's scheme plugs in without touching the receiver.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import owner

__all__ = [
    "APPLIED",
    "EVENT_LEDGER_FILE",
    "MAX_EVENT_AGE_SECONDS",
    "NO_TRANSITION",
    "ALREADY_APPLIED",
    "REFUSED",
    "PlatformEventError",
    "UninstallEvent",
    "WebhookOutcome",
    "make_hmac_verifier",
    "parse_uninstall_event",
    "receive_uninstall",
    "webhook_secret",
]

# Outcomes. Deliberately four, not "ok / error": a duplicate delivery and a
# forged one are different facts, and collapsing them would either make honest
# retries look like attacks or make attacks look like retries.
APPLIED = "applied"
ALREADY_APPLIED = "already_applied"
NO_TRANSITION = "no_transition"
REFUSED = "refused"

EVENT_LEDGER_FILE = "platform_events.json"

# Anything older than this is refused as a replay. Generous enough for a
# platform's retry schedule, short enough that a captured request is not a
# permanent suspend primitive.
MAX_EVENT_AGE_SECONDS = 15 * 60

# The ledger is a rolling window, not an audit log: it only has to be long enough
# that a platform's retries land inside it.
_LEDGER_LIMIT = 512


class PlatformEventError(ValueError):
    """Configuration is missing or empty — refuse, never fall through."""


def webhook_secret(platform: str, env: dict[str, str] | None = None) -> str:
    """The shared secret for ``platform``, or refuse.

    ⚠️ FAIL CLOSED. Unset, empty and whitespace-only are the SAME error, and
    there is no default. A blank secret is a deployment that looks configured
    while accepting an HMAC anyone can compute over a known-empty key.
    """
    if not platform or not platform.strip():
        raise PlatformEventError("a platform name is required")
    source = os.environ if env is None else env
    var = f"ORRERY_PLATFORM_WEBHOOK_SECRET_{platform.strip().upper()}"
    raw = (source.get(var) or "").strip()
    if not raw:
        raise PlatformEventError(
            f"{var} is not set (or is empty) — refusing to accept {platform} webhooks. "
            "An unverified uninstall event would let anyone suspend this listing."
        )
    return raw


def make_hmac_verifier(secret: str, *, digest: str = "sha256", encoding: str = "hex") -> Any:
    """An HMAC-over-raw-body verifier: ``verify(raw_body, signature) -> bool``.

    ⚠️ RAW BODY, not re-serialised JSON: re-encoding changes bytes (key order,
    spacing, unicode escapes) and the signature is over what was actually sent.
    Comparison is constant-time.

    One implementation of the injected contract, not the contract itself — see
    the module note on why the wire shape is an assumption.
    """
    if not secret or not secret.strip():
        raise PlatformEventError("refusing to build a verifier over an empty secret")
    if digest not in {"sha256", "sha512"}:
        raise PlatformEventError(f"unsupported digest {digest!r}")
    if encoding not in {"hex", "base64"}:
        raise PlatformEventError(f"unsupported encoding {encoding!r}")

    # Resolved once at construction: the encoding is fixed for the life of the
    # verifier, so branching per request bought nothing — and it kept the config
    # comparison on the same line as the signature, where a constant-time-compare
    # guard cannot tell the two apart.
    hexed = encoding == "hex"
    algorithm = getattr(hashlib, digest)

    def verify(raw_body: bytes, signature: str) -> bool:
        if not isinstance(raw_body, bytes | bytearray) or not signature:
            return False
        mac = hmac.new(secret.encode(), bytes(raw_body), algorithm)
        expected = mac.hexdigest() if hexed else base64.b64encode(mac.digest()).decode()
        try:
            return hmac.compare_digest(expected, signature.strip())
        except Exception:  # noqa: BLE001 — a non-comparable signature is a failed one
            return False

    return verify


@dataclass(frozen=True)
class UninstallEvent:
    """A parsed uninstall notification.

    ⚠️ The field names are the ASSUMED common shape, not any platform's contract.
    A real integration maps its own payload into this before the receiver sees
    it; that mapping is where provider specifics belong.
    """

    platform: str
    event_id: str
    occurred_at: str
    subject: str | None = None
    raw: dict[str, Any] | None = None


def parse_uninstall_event(platform: str, raw_body: bytes) -> UninstallEvent:
    """Parse the assumed payload. Raises on anything unusable — a malformed
    event must not be guessed at, because the guess would transition state."""
    try:
        payload = json.loads(bytes(raw_body))
    except Exception as e:  # noqa: BLE001
        raise PlatformEventError(f"webhook body is not decodable JSON: {e}") from e
    if not isinstance(payload, dict):
        raise PlatformEventError("webhook body is not a JSON object")
    event_id = str(payload.get("event_id") or payload.get("id") or "").strip()
    if not event_id:
        raise PlatformEventError("event has no id — replay protection is impossible without one")
    occurred_at = str(payload.get("occurred_at") or payload.get("created_at") or "").strip()
    if not occurred_at:
        raise PlatformEventError("event has no timestamp — freshness cannot be checked without one")
    return UninstallEvent(
        platform=platform,
        event_id=event_id,
        occurred_at=occurred_at,
        subject=(str(payload.get("subject")) if payload.get("subject") else None),
        raw=payload,
    )


@dataclass(frozen=True)
class WebhookOutcome:
    """What the receiver did, and why. ``state_changed`` is the fact that matters."""

    outcome: str
    reason: str
    state_changed: bool = False
    lifecycle: owner.LifecycleAnswer | None = None

    @property
    def ok(self) -> bool:
        """Whether the platform should consider the event delivered.

        ⚠️ True for ALREADY_APPLIED and NO_TRANSITION as well as APPLIED: a
        platform retries on failure, so answering "not ok" to a duplicate it
        already sent would produce a retry storm over an event we handled
        correctly the first time.
        """
        return self.outcome != REFUSED


def _ledger_path(home: Path) -> Path:
    return Path(home) / EVENT_LEDGER_FILE


def _seen_events(home: Path) -> list[str]:
    path = _ledger_path(home)
    if not path.exists():
        return []
    try:
        loaded = json.loads(path.read_text())
    except Exception:  # noqa: BLE001 — an unreadable ledger is an empty one
        return []
    return [str(x) for x in loaded] if isinstance(loaded, list) else []


def _record_event(home: Path, key: str) -> None:
    seen = [k for k in _seen_events(home) if k != key]
    seen.append(key)
    path = _ledger_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(seen[-_LEDGER_LIMIT:], indent=2))


def _fresh(occurred_at: str, *, now: datetime | None = None) -> bool:
    try:
        stamp = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001 — an unparseable timestamp is not fresh
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return abs(reference - stamp) <= timedelta(seconds=MAX_EVENT_AGE_SECONDS)


def receive_uninstall(
    home: Path,
    platform: str,
    raw_body: bytes,
    signature: str,
    *,
    verifier: Any = None,
    env: dict[str, str] | None = None,
    now: datetime | None = None,
) -> WebhookOutcome:
    """Verify an uninstall webhook and, if it holds up, SUSPEND the listing.

    Nothing else happens: no outbound call, no re-registration, no index write.
    The only effect is the local lifecycle transition, through the owner-attested rework's own API
    rather than a parallel state store.

    ``verifier`` is injected. Omitted, an HMAC-SHA256-over-raw-body verifier is
    built from the configured secret — and if no secret is configured, the whole
    request is refused rather than accepted unverified.
    """
    # 1. Signature FIRST. Nothing is parsed, looked up or written before the
    #    bytes are proven, so an unverified request cannot even probe for the
    #    existence of a binding.
    if verifier is None:
        try:
            verifier = make_hmac_verifier(webhook_secret(platform, env=env))
        except PlatformEventError as e:
            return WebhookOutcome(REFUSED, f"not_configured: {e}")
    try:
        verified = bool(verifier(bytes(raw_body), signature))
    except Exception as e:  # noqa: BLE001 — a broken verifier must not pass
        return WebhookOutcome(REFUSED, f"verifier_error: {e}")
    if not verified:
        return WebhookOutcome(REFUSED, "invalid_signature")

    # 2. Parse only what was verified.
    try:
        event = parse_uninstall_event(platform, raw_body)
    except PlatformEventError as e:
        return WebhookOutcome(REFUSED, f"malformed_event: {e}")

    # 3. Freshness, then replay. A correctly-signed but stale request is a
    #    captured one: without this, a single observed webhook is a permanent
    #    suspend primitive.
    if not _fresh(event.occurred_at, now=now):
        return WebhookOutcome(REFUSED, f"stale_event: {event.occurred_at} is outside the freshness window")

    key = f"{event.platform}:{event.event_id}"
    if key in _seen_events(home):
        # ⚠️ NOT a refusal. Platforms retry, and answering "not ok" to a
        # duplicate would produce a retry storm over an event already handled.
        # It changes nothing, and says which of the two it is.
        return WebhookOutcome(
            ALREADY_APPLIED,
            "this event was already processed",
            lifecycle=owner.resolve_lifecycle(owner.load_binding(home)),
        )

    # 4. Transition — suspended, authority = the platform, never attested.
    try:
        answer = owner.suspend_listing(
            home,
            reason=f"{platform} reported the app was uninstalled",
            authority=f"platform:{platform}",
        )
    except owner.LifecycleError as e:
        # A revoked listing is terminal and the owner's withdrawal outranks a
        # vendor's billing event. Recorded so the retry stops, not refused.
        _record_event(home, key)
        return WebhookOutcome(NO_TRANSITION, f"lifecycle_refused: {e}")

    _record_event(home, key)
    return WebhookOutcome(
        APPLIED,
        f"listing suspended following a {platform} uninstall",
        state_changed=answer.state == owner.LIFECYCLE_SUSPENDED,
        lifecycle=answer,
    )
