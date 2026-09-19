"""Delivering a booking to the business that has to act on it.

A booking that nobody receives is worse for the business than no booking at all:
the customer believes it happened and holds a signed receipt saying so. The
booking skill recorded a row and signed a receipt and told nobody, so this
module is the delivery half.

Two things are deliberately separate here:

* WHERE to deliver — a contact channel, captured when the business is claimed
  and stored with the tenant. ``parse_contact`` decides what a contact string
  is from its own shape rather than from a caller-supplied type, so a channel
  cannot be mislabelled into a sender that cannot reach it.
* HOW to deliver — a ``Sender``. One is shipped: ``WebhookSender``, which needs
  no provider credential and therefore cannot be blocked on a human obtaining
  one. Email is a channel this module can already represent and cannot yet
  deliver, and it says so by name rather than accepting the address and
  discarding the booking.

NO SENDER IS NOT SUCCESS. ``deliver`` returns a result whose ``delivered`` is
False and whose ``reason`` names the channel that had no sender. The caller is
expected to surface that rather than drop it; a notification path that quietly
does nothing is the failure this module exists to remove, and reporting success
for it would reintroduce it one layer up.

The calendar representation is an ``.ics`` VEVENT built from the booking itself,
so it carries the same provider and datetime the receipt does. It exists because
a business already has a calendar, and an attachment it can open beats a format
it has to integrate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

# A contact is one of these. The kind is derived from the string, never passed
# in: a caller that could label an address would be able to route a booking to a
# sender that cannot reach it, which is the silent-drop this module prevents.
CONTACT_WEBHOOK = "webhook"
CONTACT_EMAIL = "email"

# Deliberately narrow. An address that does not match is refused at the claim
# call, where a human is present to correct it, rather than at the first booking.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")

# The default duration of a booked slot in the calendar representation. This is
# NOT an availability model and does not gate anything: an .ics event needs an
# end, and a business that wants a different length changes it in its own
# calendar. Conflict detection uses the exact datetime, not this window.
ICS_DEFAULT_MINUTES = 60


class ContactError(ValueError):
    """A contact string that names no channel this stack can represent."""


@dataclass(frozen=True)
class Contact:
    """Where a booking for this business is delivered."""

    kind: str
    target: str

    def redacted(self) -> str:
        """The channel named without republishing the address.

        Refusals and warnings travel to callers this host does not authenticate,
        so they name the kind and not the target.
        """
        return self.kind


def parse_contact(raw: str | None) -> Contact:
    """Classify a contact string by its shape.

    An ``https`` URL is a webhook; anything matching a mail address is email.
    Everything else raises, including an ``http`` URL: a booking carries a
    customer's name and time, and sending it in clear text to an address the
    business typed once is not a default worth having.
    """
    value = (raw or "").strip()
    if not value:
        raise ContactError("no contact was given, so a booking could not reach this business")
    lowered = value.lower()
    if lowered.startswith("https://"):
        return Contact(CONTACT_WEBHOOK, value)
    if lowered.startswith("http://"):
        raise ContactError(
            "a plain http webhook is refused: a booking carries a customer's name and time, "
            "so the delivery URL must be https"
        )
    if _EMAIL.match(value):
        return Contact(CONTACT_EMAIL, value)
    raise ContactError(
        f"{value!r} is neither an https webhook URL nor an email address, so it names no channel "
        f"a booking can be delivered on"
    )


@dataclass(frozen=True)
class Delivery:
    """What happened when a booking was handed to a sender.

    ``delivered`` False is a reportable outcome, not an exception: the booking
    and its receipt already exist and must not be destroyed by a delivery
    problem. The caller surfaces ``reason``.
    """

    delivered: bool
    channel: str
    reason: str = ""


class Sender(Protocol):
    """Delivers one booking on one channel."""

    kind: str

    def send(self, contact: Contact, booking: dict[str, Any], ics: str) -> Delivery: ...


class WebhookSender:
    """Posts the booking and its calendar event to the business's own URL.

    Shipped because it needs no provider account: a business that can receive a
    webhook can be reached today, with no credential and no human step in
    between. Failures are returned rather than raised — see ``Delivery``.
    """

    kind = CONTACT_WEBHOOK

    def __init__(self, *, timeout: float = 10.0, post: Any = None) -> None:
        self._timeout = timeout
        # Injected for tests. Production passes nothing and httpx is imported at
        # call time, so importing this module costs no network stack.
        self._post = post

    def send(self, contact: Contact, booking: dict[str, Any], ics: str) -> Delivery:
        payload = {"type": "booking.created", "booking": booking, "ics": ics}
        post = self._post
        if post is None:
            import httpx

            def post(url: str, json: dict[str, Any]) -> Any:  # noqa: D401 — thin adapter
                return httpx.post(url, json=json, timeout=self._timeout)

        try:
            response = post(contact.target, payload)
        except Exception as exc:  # noqa: BLE001 — an undeliverable booking is reported, never raised
            return Delivery(False, self.kind, f"webhook post failed ({type(exc).__name__})")
        status = int(getattr(response, "status_code", 0) or 0)
        if 200 <= status < 300:
            return Delivery(True, self.kind)
        return Delivery(False, self.kind, f"webhook returned HTTP {status}")


def default_senders() -> dict[str, Sender]:
    """The senders this build can actually deliver on.

    Email is absent on purpose. Representing an email contact and having no way
    to send to it is the honest state, and ``deliver`` names it; adding a stub
    that reported success would be the defect this module removes.
    """
    return {CONTACT_WEBHOOK: WebhookSender()}


def build_ics(booking: dict[str, Any], *, business_name: str = "", uid: str = "") -> str:
    """A single-event calendar for this booking.

    Built from the booking, so the provider and datetime it carries are the ones
    the receipt was signed over. A datetime the calendar format cannot express
    raises rather than emitting an event at a time nobody booked.
    """
    start = _ics_stamp(str(booking.get("datetime", "")))
    end = _ics_stamp(str(booking.get("datetime", "")), plus_minutes=ICS_DEFAULT_MINUTES)
    provider = str(booking.get("provider", ""))
    service = str(booking.get("service", ""))
    summary = f"{service} — {provider}" if service else provider
    identifier = uid or f"booking-{booking.get('id', 0)}@{provider or 'unknown'}"
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//orrery//booking//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:{_escape(identifier)}",
        f"DTSTAMP:{_ics_stamp(datetime.now(timezone.utc).isoformat())}",
        f"DTSTART:{start}",
        f"DTEND:{end}",
        f"SUMMARY:{_escape(summary)}",
        f"DESCRIPTION:{_escape(str(booking.get('notes', '')))}",
        f"ORGANIZER;CN={_escape(business_name or provider)}:mailto:noreply@invalid",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n"


def _ics_stamp(value: str, *, plus_minutes: int = 0) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("the booking carries no datetime, so no calendar event can be built for it")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"the booking datetime {text!r} is not an ISO-8601 timestamp, so no calendar event can be built for it"
        ) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc) + timedelta(minutes=plus_minutes)
    return moment.strftime("%Y%m%dT%H%M%SZ")


def _escape(text: str) -> str:
    """RFC 5545 text escaping, so a comma or a newline cannot end the property."""
    return text.replace("\\", "\\\\").replace(";", r"\;").replace(",", r"\,").replace("\n", r"\n")


def deliver(
    booking: dict[str, Any],
    contact: Contact | None,
    *,
    business_name: str = "",
    senders: dict[str, Sender] | None = None,
) -> Delivery:
    """Hand one booking to the sender for its channel.

    Never raises. The booking and its receipt already exist by the time this
    runs, and a delivery problem must not destroy either — so every outcome is a
    ``Delivery``, and the absence of a sender is one of them rather than a quiet
    success.
    """
    if contact is None:
        return Delivery(False, "none", "no contact channel is recorded for this business")
    table = default_senders() if senders is None else senders
    sender = table.get(contact.kind)
    if sender is None:
        return Delivery(
            False,
            contact.kind,
            f"no sender is configured for the {contact.kind} channel, so this booking was not delivered",
        )
    try:
        ics = build_ics(booking, business_name=business_name)
    except ValueError as exc:
        return Delivery(False, contact.kind, str(exc))
    return sender.send(contact, booking, ics)
