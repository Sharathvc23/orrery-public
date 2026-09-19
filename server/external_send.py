"""Outbound email to a non-member, through Klaviyo — gated, and sandboxed by default.

⚠️ WHY THIS IS SERVER-SIDE WHEN THE QUEUE IS AGENT-SIDE.
The durable queue lives in the agent (``community_member/outbox.py``) and that is
the right place for it — the agent is what goes offline. But the *gate* is here,
because ``governance.consume_operational_approval`` is here, and PR1 is explicit
that the gate belongs immediately before the side effect rather than at planning
time. If the agent held the Klaviyo key and performed the HTTP call itself, the
approval would be a remote opinion it could simply proceed past: an agent that
ignored the refusal would send anyway, and nothing structural would stop it.

So the org performs the send and the agent never holds the API key. The agent
enqueues, drains, and asks; the org decides and acts. An agent that skips the ask
has no way to reach Klaviyo at all, which is a much stronger property than an
agent that is asked politely not to.

═══ 🛑 SANDBOX BY DEFAULT. THIS BUILD CANNOT EMAIL A REAL PERSON. ═══

Four independent conditions, each sufficient on its own to prevent a live send,
so no single mistake — a leaked key, a wrong flag, a copy-pasted address, a test
that forgets to patch something — produces one:

  1. ``KLAVIYO_LIVE_SENDS`` must be explicitly true. Read through
     ``env_flags.security_flag(default=False)``, so unset, empty and misspelled
     all mean sandbox. This is the flag that exists solely to be off.
  2. An API key must be present. Absent -> sandbox, never an unauthenticated
     attempt against the live endpoint.
  3. ``_transport()`` resolves to ``SandboxTransport`` unless BOTH hold. The
     sandbox transport contains no HTTP client and imports none — it cannot open
     a socket, rather than choosing not to.
  4. In sandbox the recipient MUST be an RFC 2606 / RFC 6761 reserved address
     (``example.com``, ``.test``, ``.invalid``, …). A real address is refused
     before any transport is selected, so even a sandbox misconfiguration cannot
     be pointed at a person.

Condition 4 is the one that makes this safe to *develop* against rather than
merely safe to deploy: the usual sandbox failure is a live key finding its way
into a dev environment, and an allowlist of addresses that cannot belong to
anyone survives that.

═══ THE COST GAP, STATED RATHER THAN IMPLIED ═══

A Klaviyo send is **billable**, and per PR1's own table "spending money or quota
against a paid API" is NOT yet a distinct approval kind. So this verb is gated as
an *outbound message* (``send_external``) and is genuinely gated as one — but the
spend dimension is not separately expressible today. An operator approving a send
is approving its cost implicitly. Recorded here rather than discovered later; it
is additive when a cost kind arrives.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Protocol

import env_flags

#: PR1's kind for anything leaving the org toward a non-member recipient.
SEND_APPROVAL_KIND = "send_external"

LIVE_SENDS_FLAG = "KLAVIYO_LIVE_SENDS"
API_KEY_ENV = "KLAVIYO_API_KEY"
KLAVIYO_ENDPOINT = "https://a.klaviyo.com/api/events/"
KLAVIYO_REVISION = "2024-10-15"

#: Addresses reserved by RFC 2606 / RFC 6761 — guaranteed never to belong to a
#: real person. The sandbox recipient allowlist, not a convention.
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org", "localhost"})
RESERVED_TLDS = ("*.test", "*.example", "*.invalid", "*.localhost")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$|^[^@\s]+@localhost$")


class SendRefused(Exception):
    """A send that will not happen. Carries a machine-readable reason so a caller
    can distinguish "fix the address" from "wait for approval" from "retry"."""

    def __init__(self, reason: str, detail: str = "", *, approval: dict | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason
        self.approval = approval


class Transport(Protocol):
    name: str

    def send(self, message: dict[str, Any]) -> dict[str, Any]: ...


class SandboxTransport:
    """Records the send and returns. Opens no socket — and cannot.

    ⚠️ This class deliberately imports no HTTP client, so "the sandbox
    accidentally sent something" is not a reachable state rather than an
    unlikely one. The recorded sends are readable by tests through
    ``sandbox_log()``, which is what makes the drain path assertable end to end
    without a network.
    """

    name = "sandbox"

    def send(self, message: dict[str, Any]) -> dict[str, Any]:
        _SANDBOX_LOG.append(message)
        print(f"[ExternalSend] SANDBOX send to {message['to']} — no network call was made")
        return {"transport": "sandbox", "delivered": False, "recorded": True}


class KlaviyoTransport:
    """The real edge. Constructing it asserts the live conditions itself.

    The check is in ``__init__`` rather than only in ``_transport`` so that a
    future caller who constructs it directly — the plausible way this guarantee
    erodes — hits the same refusal.
    """

    name = "klaviyo"

    def __init__(self, api_key: str) -> None:
        if not env_flags.security_flag(LIVE_SENDS_FLAG, default=False):
            raise SendRefused(
                "live_sends_disabled",
                f"{LIVE_SENDS_FLAG} is not enabled; refusing to construct a live transport",
            )
        if not api_key:
            raise SendRefused("no_api_key", "a live transport requires an API key")
        self._api_key = api_key

    def send(self, message: dict[str, Any]) -> dict[str, Any]:
        import httpx

        payload = {
            "data": {
                "type": "event",
                "attributes": {
                    "properties": {"subject": message["subject"], "body": message["body"]},
                    "metric": {"data": {"type": "metric", "attributes": {"name": message["metric"]}}},
                    "profile": {"data": {"type": "profile", "attributes": {"email": message["to"]}}},
                },
            }
        }
        resp = httpx.post(
            KLAVIYO_ENDPOINT,
            json=payload,
            headers={
                "Authorization": f"Klaviyo-API-Key {self._api_key}",
                "revision": KLAVIYO_REVISION,
                "content-type": "application/json",
            },
            timeout=15.0,
        )
        if resp.status_code >= 400:
            raise SendRefused("upstream_error", f"klaviyo returned {resp.status_code}: {resp.text[:200]}")
        return {"transport": "klaviyo", "delivered": True, "status": resp.status_code}


_SANDBOX_LOG: list[dict[str, Any]] = []


def sandbox_log() -> list[dict[str, Any]]:
    """Everything the sandbox transport has 'sent'. Test-visible by design."""
    return list(_SANDBOX_LOG)


def reset_sandbox_log() -> None:
    _SANDBOX_LOG.clear()


def live_sends_enabled() -> bool:
    """Both conditions, together. Neither alone enables a live send."""
    return bool(env_flags.security_flag(LIVE_SENDS_FLAG, default=False) and os.environ.get(API_KEY_ENV))


def _transport() -> Transport:
    if not live_sends_enabled():
        return SandboxTransport()
    return KlaviyoTransport(os.environ.get(API_KEY_ENV, ""))


def _is_reserved(address: str) -> bool:
    """True only for domains IANA reserves, so they cannot belong to a person.

    ⚠️ Suffix-matched with a leading dot, never by substring. ``notexample.com``
    and ``example.company`` both contain a reserved string, and a naive ``in``
    check would route real mail to a real inbox — the exact mistake this
    allowlist exists to prevent.
    """
    domain = address.rsplit("@", 1)[-1].lower().rstrip(".")
    reserved = set(RESERVED_DOMAINS) | {pat[2:] for pat in RESERVED_TLDS}
    return any(domain == r or domain.endswith("." + r) for r in reserved)


def _require_recipient(to: Any) -> str:
    if not isinstance(to, str) or not _EMAIL_RE.match(to.strip()):
        # Refused, not normalised — a "cleaned" address is how a message reaches
        # someone other than the person intended.
        raise SendRefused("recipient_invalid", "recipient is not a valid email address")
    address = to.strip()
    if not live_sends_enabled() and not _is_reserved(address):
        raise SendRefused(
            "recipient_not_reserved",
            f"{address} is a real address and live sends are disabled; sandbox "
            f"recipients must be RFC 2606 reserved (example.com, *.test, *.invalid)",
        )
    return address


def _require_text(value: Any, field: str, *, maxlen: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SendRefused(f"{field}_required", f"{field} must be a non-empty string")
    v = value.strip()
    if len(v) > maxlen:
        raise SendRefused(f"{field}_too_long", f"{field} exceeds {maxlen} characters")
    return v


def action_key(to: str, subject: str, body: str) -> str:
    """What the operator is approving: this message, to this recipient.

    ⚠️ The BODY is bound, via digest. Binding only the address would make the
    grant "you may email this person", and an approved send could then carry any
    content at all — the operator would have approved a channel rather than a
    message. The digest keeps the key bounded while still making a changed body
    a different action.
    """
    digest = hashlib.sha256("\n".join([subject, body]).encode()).hexdigest()[:16]
    return f"send_external:klaviyo:{to}:{digest}"


async def send_external(
    *, actor_agent_id: str, to: Any, subject: Any, body: Any, metric: str = "Orrery Agent Message"
) -> dict[str, Any]:
    """Send one message to a non-member, if an operator has approved this exact one.

    Order is load-bearing: validate, then gate, then send. Validating first means
    a malformed request never files an approval an operator would have to read
    and reject. Gating immediately before the transport call means there is no
    step between the decision and the effect.
    """
    address = _require_recipient(to)
    subject_text = _require_text(subject, "subject", maxlen=300)
    body_text = _require_text(body, "body", maxlen=20_000)
    key = action_key(address, subject_text, body_text)

    try:
        import governance
    except Exception as e:  # noqa: BLE001
        raise SendRefused("governance_unavailable", f"cannot gate this send: {e}") from e

    try:
        grant = await governance.consume_operational_approval(
            SEND_APPROVAL_KIND,
            actor_agent_id=actor_agent_id,
            action_key=key,
            payload={"to": address, "subject": subject_text, "channel": "klaviyo"},
        )
    except governance.OperationalApprovalRequired as e:
        # NOT an error. The message is queued for a human, and the caller must
        # keep it rather than dropping or retrying it.
        raise SendRefused(
            "pending_approval",
            e.reason,
            approval=e.approval,
        ) from e

    transport = _transport()
    message = {"to": address, "subject": subject_text, "body": body_text, "metric": metric}
    result = transport.send(message)

    await _receipt(actor_agent_id, address, subject_text, key, grant, result)
    return {
        "status": "sent",
        "transport": transport.name,
        "live": transport.name != "sandbox",
        "action_key": key,
        "approval_id": (grant or {}).get("id"),
        "result": result,
    }


async def _receipt(
    actor: str, to: str, subject: str, key: str, grant: dict | None, result: dict[str, Any]
) -> None:
    """The send is recorded whether it went to Klaviyo or to the sandbox, and the
    receipt says which. A sandbox send that left no trace would make the drain
    path unauditable exactly where it most needs to be."""
    try:
        import arp

        await arp.emit_chapter_action(
            principal_did=actor,
            category="external_message_sent",
            human_summary=f"Sent {subject!r} to {to} via {result.get('transport')}",
            machine_payload={
                "to": to,
                "subject": subject,
                "action_key": key,
                "approval_id": (grant or {}).get("id"),
                "transport": result.get("transport"),
                "delivered": result.get("delivered"),
            },
        )
    except Exception as e:  # noqa: BLE001
        print(f"[ExternalSend] receipt emission failed: {type(e).__name__}: {e}")
