"""Built-in 'booking' skill — book an appointment + emit a signed ARP receipt.

This is the SMB "operate" stage of the demo loop: the agent performs a concrete
business action (booking an appointment) and, because it holds the principal's
signing key, mints a signed ``appointment_booked`` ARP receipt into the local
Agency Log for it. The booking is the side effect; the receipt is the
accountable, independently-verifiable record that the action happened.

State lives in ``CONFIG_DIR/bookings.json`` (same convention as the ``tasks``
skill, so it moves with ``COMMUNITY_MEMBER_HOME``). The receipt lands in the
Agency Log SQLite under the same config dir and, when the agent is joined to a
chapter, is also pushed to the chapter's Issuer Log.

A keyless agent (no identity, or an identity with no stored/valid Ed25519 seed)
is still a valid agent — it books the appointment and returns a clear note that
the receipt was skipped, rather than crashing.

ORDERING (write-ahead): for an agent that CAN sign, a ``pending`` attempt is
written to the Agency Log BEFORE the booking is recorded, the booking is
written, and only then is the ``appointment_booked`` receipt signed and the
attempt finalized ``succeeded`` with its id. Two earlier orderings were both
wrong in one direction each:

* receipt AFTER booking left a durable booking behind whenever the Agency Log
  write failed — the caller saw an error while the booking stayed on disk, so
  a retry wrote a second one;
* receipt BEFORE booking (the previous fix) signed a receipt saying
  ``completed`` for a booking that had not been written yet, so a failing
  store write left a receipt attesting an appointment that does not exist.

The attempt row gives the first ordering's guarantee without the second's
over-claim: an unwritable log refuses at ``begin_action`` and nothing is
booked; a store write that fails finalizes the attempt ``failed`` and no
receipt is signed; a receipt stage that fails after the booking is written
finalizes the attempt ``succeeded`` with no receipt id — the booking stands,
is reported, and the owed receipt is visible in
``AgencyLog.unresolved_actions``. A process that dies in between leaves the
``pending`` row for ``reconcile_orphans`` to mark ``unknown`` at the next
start. The slot is the attempt's ``action_ref``, so a retry of a slot that was
already booked is refused before anything is written. A keyless agent is
unaffected: it has no receipt to owe and still books.

CONCURRENCY: the store is a read-modify-write over one JSON file, and the SMB
host serves bookings from a threadpool, so same-store calls genuinely interleave.
They are serialized on a per-store lock and the file is replaced atomically.
Without both, concurrent bookings silently lost writes — three at once was
enough to lose one — and two writers truncating and filling the same file
interleaved into invalid JSON.

DAMAGE IS NOT EMPTINESS: a store that exists but does not parse raises
``BookingStoreUnreadable`` rather than reading as zero bookings. Reporting it as
empty is what turned a lost write into lost data — the agent read back nothing
while customers held valid receipts, ids restarted and collided across receipts,
and the next write replaced the damaged file. A store that is not there is still
empty; that is the first booking, and it stays cheap.

The lock is per-process. Two processes sharing one home would still interleave;
the atomic replace keeps the file parseable in that case, but a lost update is
still possible. Cross-process locking is the same deferred concern recorded in
``task_store``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

# Absolute, not relative: the skill loader executes this file as a standalone
# module with no parent package, so a relative import fails there and the skill
# registers no tools at all. The package is importable either way.
from community_member.builtin_skills.booking import notify


def _home_dir(home: Path | None) -> Path:
    """Resolve the directory bookings + the receipt log live under.

    ``home`` is the per-tenant ``COMMUNITY_MEMBER_HOME`` when a specific tenant
    invokes the skill (B2a isolation). ``None`` falls back to the process-global
    ``CONFIG_DIR`` — the unchanged single-agent behavior the built-in tool uses.
    """
    if home is not None:
        d = Path(home)
    else:
        from community_member.config import CONFIG_DIR

        d = CONFIG_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(home: Path | None = None):
    return _home_dir(home) / "bookings.json"


class BookingStoreUnreadable(RuntimeError):
    """The booking store exists but is not a readable list of bookings.

    Distinct from an empty store, which is a file that is not there. Callers
    that treat the two the same overwrite the damaged file with a fresh one on
    the next write, which is how the surviving bookings were lost.
    """


def _load(home: Path | None = None) -> list[dict]:
    """Return the stored bookings, or raise if the store cannot be read.

    A store that exists but does not parse is DAMAGE, and this used to report it
    as emptiness: the whole body was ``except (ValueError, OSError): return []``.
    Every consequence of the concurrency defect followed from that rather than
    from the lost write itself —

      * the agent read back zero bookings while customers held valid signed
        receipts for them, and nothing anywhere said the file was broken;
      * ``next_id`` was computed from an empty list, so ids restarted at 1 and
        collided across receipts — booking_id 1 appeared in twelve distinct
        signed receipts, after which no receipt identified a booking;
      * the next successful write replaced the damaged file, destroying both the
        surviving rows and the evidence.

    Refusing keeps the file exactly as it is, so whatever survived can be
    recovered by hand. A missing file is still an empty store — that case is
    genuinely empty and must stay cheap, because it is every first booking.

    OSError is no longer swallowed either: a store that cannot be read for
    permission or I/O reasons is not an empty one.
    """
    p = _path(home)
    if not p.exists():
        return []

    raw = p.read_text()  # OSError propagates: unreadable is not empty
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise BookingStoreUnreadable(
            f"{p} is not valid JSON ({exc}). It has NOT been modified — the "
            f"bookings it still holds can be recovered from it. Move it aside to "
            f"start a fresh store."
        ) from exc

    if not isinstance(data, list):
        raise BookingStoreUnreadable(
            f"{p} holds {type(data).__name__}, not a list of bookings. It has NOT "
            f"been modified. Move it aside to start a fresh store."
        )
    return data


def _save(items: list[dict], home: Path | None = None) -> None:
    """Replace the store atomically.

    A plain ``write_text`` truncates the file and then fills it, so two writers
    overlapping in that window interleave into something that is not valid JSON
    — measured at 18 of 60 trials with four concurrent writers. Building a
    sibling temp file and renaming it means a reader sees either the whole
    previous store or the whole new one, and never a mixture.

    The temp name carries the thread id as well as the pid: two THREADS sharing
    one temp name reproduce the identical interleaving one level down, which is
    exactly what the first version of this function did.
    """
    path = _path(home)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps(items, indent=2))
    tmp.replace(path)  # atomic swap


# One lock per booking store. Keyed by the resolved directory, so two callers
# with the same home share a lock and two tenants never contend.
_store_locks: dict[str, threading.Lock] = {}
_store_locks_guard = threading.Lock()


def _lock_for(home: Path | None) -> threading.Lock:
    key = str(_home_dir(home))
    with _store_locks_guard:
        lock = _store_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _store_locks[key] = lock
        return lock


class _Signer:
    """What a signing agent needs to attempt + receipt a booking: its seed, its
    Agency Log and its chapter URL. ``None`` from :func:`_signer_for` means the
    agent is keyless and books without either."""

    def __init__(self, seed: bytes, log: Any, chapter_url: str | None) -> None:
        self.seed = seed
        self.log = log
        self.chapter_url = chapter_url


def _signer_for(home: Path | None) -> tuple[Any | None, str | None]:
    """Resolve the signing context, or the reason the agent cannot sign.

    Returns ``(signer, None)`` for an agent with a usable Ed25519 seed, or
    ``(None, reason)`` for the keyless case. Never raises for keyless — a
    keyless agent is a valid agent (it just can't sign).

    ``home`` scopes the identity, signing key, and Agency Log to a single
    tenant; ``None`` uses the process-global config dir (single-agent path).
    """
    import base64

    from community_member import arp, keystore
    from community_member.config import Config

    cfg = Config.load(home=home)
    if not cfg.agent_id:
        return None, "no agent identity — set up an identity to emit signed receipts"

    priv_b64 = keystore.load_private_key(cfg.agent_id, dir=cfg._home)
    if not priv_b64:
        return None, "no signing key for this identity — receipt not emitted"

    try:
        seed = base64.b64decode(priv_b64)
    except (ValueError, TypeError):
        return None, "signing key is not valid base64 — receipt not emitted"
    if len(seed) != 32:
        return None, "signing key is not a 32-byte Ed25519 seed — receipt not emitted"

    return _Signer(seed, arp.AgencyLog(cfg.home), cfg.chapter_url), None


def _slot_ref(provider: str, datetime_: str) -> str:
    """The attempt's ``action_ref``: the booked slot, folded like :func:`_slot_conflict`."""
    return f"{provider.strip().lower()}@{datetime_.strip()}"


def _emit_receipt(booking: dict, signer: Any) -> dict[str, Any]:
    """Sign + persist an ``appointment_booked`` receipt for a booking that has
    been WRITTEN. Raises on a log or push failure; the caller records the owed
    receipt against the attempt."""
    from community_member import arp

    receipt = arp.emit(
        {
            "category": "appointment_booked",
            "outcome": "completed",
            "human_summary": (f"Booked {booking['service']} with {booking['provider']} at {booking['datetime']}"),
            "machine_payload": {
                "service": booking["service"],
                "provider": booking["provider"],
                "datetime": booking["datetime"],
                "notes": booking["notes"],
                "booking_id": booking["id"],
            },
        },
        signer.seed,
        agency_log=signer.log,
        chapter_url=signer.chapter_url,
        push=bool(signer.chapter_url),
    )
    return {"receipt_id": receipt["receipt_id"]}


def book_appointment(
    args: dict,
    *,
    home: Path | None = None,
    contact: notify.Contact | None = None,
    business_name: str = "",
) -> dict:
    """Core booking logic, scoped to ``home`` (a tenant's ``COMMUNITY_MEMBER_HOME``).

    ``home=None`` uses the process-global config dir — the single-agent path the
    built-in ``book_appointment`` tool exposes. A per-tenant caller
    (``AgentContext.book_appointment``) passes its own home so the booking and
    the signed receipt land only in that tenant's stores.

    ``contact`` is where the business receives this booking. It is supplied by
    the caller that knows the business — the host reads it from the tenant it
    provisioned — and the result always reports what happened to the delivery in
    ``delivered``/``delivery_note``, including the case where no contact was
    given at all.
    """
    args = args or {}
    service = str(args.get("service", "")).strip()
    provider = str(args.get("provider", "")).strip()
    datetime_ = str(args.get("datetime", "")).strip()
    notes = str(args.get("notes", "")).strip()

    missing = [k for k, v in (("service", service), ("provider", provider), ("datetime", datetime_)) if not v]
    if missing:
        return {"error": f"missing required field(s): {', '.join(missing)}"}

    signer, keyless_reason = _signer_for(home)

    with _lock_for(home):
        items = _load(home)

        # Refused before anything is signed or stored. The slot check reads the
        # store under the same lock the write takes, so two concurrent bookings
        # of one slot cannot both pass it — checking outside the lock would let
        # the second read a store the first had not yet appended to.
        clash = _slot_conflict(items, provider, datetime_)
        if clash is not None:
            return {
                "error": (f"{provider} is already booked at {datetime_} (booking {clash['id']}). Choose another time."),
                "conflict_with": clash["id"],
            }

        next_id = max((b.get("id", 0) for b in items), default=0) + 1
        booking = {
            "id": next_id,
            "service": service,
            "provider": provider,
            "datetime": datetime_,
            "notes": notes,
        }
        summary = f"Booked {service} with {provider} at {datetime_}"

        # Write-ahead: the attempt is recorded BEFORE the booking. If this
        # raises — the Agency Log is unwritable — nothing is booked, which is
        # the moment to find that out. A keyless agent has no log to owe a
        # receipt to and books without an attempt row.
        attempt_id: str | None = None
        if signer is not None:
            from community_member.arp import DuplicateActionError, did_from_private_key

            try:
                attempt_id = signer.log.begin_action(
                    issuer_did=did_from_private_key(signer.seed),
                    category="appointment_booked",
                    summary=summary,
                    action_ref=_slot_ref(provider, datetime_),
                    detail={"booking_id": next_id, "service": service, "provider": provider, "datetime": datetime_},
                )
            except DuplicateActionError as dup:
                # The slot's last attempt succeeded or is unresolved: the store
                # may not show it (a crash before _save, a store moved aside),
                # but the log does, and booking it again would be a second one.
                return {
                    "error": (
                        f"{provider} at {datetime_} already has a booking attempt in state "
                        f"{dup.attempt['state']!r} (attempt {dup.attempt['attempt_id']}). Resolve it first."
                    ),
                    "conflict_with_attempt": dup.attempt["attempt_id"],
                }

        try:
            items.append(booking)
            _save(items, home)
        except BaseException as e:
            if attempt_id is not None:
                signer.log.finalize_action(attempt_id, "failed", detail={"error": f"{type(e).__name__}: {e}"})
            raise

        # The booking exists from here on. The receipt attests it; if the
        # receipt stage fails the booking is NOT rolled back and NOT hidden —
        # the attempt is finalized succeeded with no receipt id, and the
        # result says a receipt is owed.
        receipt: dict[str, Any]
        if signer is None:
            receipt = {"skipped": keyless_reason or "keyless"}
        else:
            try:
                receipt = _emit_receipt(booking, signer)
            except Exception as e:
                signer.log.finalize_action(
                    attempt_id, "succeeded", receipt_id=None, detail={"receipt_error": f"{type(e).__name__}: {e}"}
                )
                receipt = {
                    "skipped": (
                        f"booked, but the receipt was not recorded ({type(e).__name__}: {e}); "
                        f"attempt {attempt_id} is owed one"
                    ),
                    "attempt_id": attempt_id,
                }
            else:
                signer.log.finalize_action(attempt_id, "succeeded", receipt_id=receipt["receipt_id"])

    out: dict[str, Any] = {"booked": booking}
    if "receipt_id" in receipt:
        out["receipt_id"] = receipt["receipt_id"]
    else:
        out["receipt_id"] = None
        out["receipt_note"] = receipt["skipped"]
        if "attempt_id" in receipt:
            out["attempt_id"] = receipt["attempt_id"]

    # Delivery runs AFTER the booking is recorded and outside the lock, and
    # never raises: the booking and its receipt already exist, and a business
    # that cannot be reached right now must not cost the customer a booking they
    # hold a signed receipt for. The outcome is reported either way — an
    # undelivered booking that reported success is the defect this path exists
    # to remove.
    delivery = notify.deliver(booking, contact, business_name=business_name)
    out["delivered"] = delivery.delivered
    out["delivery_channel"] = delivery.channel
    if not delivery.delivered:
        out["delivery_note"] = delivery.reason
    return out


def _slot_conflict(items: list[dict[str, Any]], provider: str, datetime_: str) -> dict[str, Any] | None:
    """The existing booking that already holds this provider's slot, if any.

    Compared on the exact ``(provider, datetime)`` pair the caller sent, folded
    for case and surrounding space so that "Moon Bakery" and "moon bakery " are
    one provider. This is not an availability model: it does not know opening
    hours, staff or duration, and it refuses only an exact repeat of a slot that
    is already taken.
    """
    want = (provider.strip().lower(), datetime_.strip())
    for existing in items:
        if not isinstance(existing, dict):
            continue
        have = (str(existing.get("provider", "")).strip().lower(), str(existing.get("datetime", "")).strip())
        if have == want:
            return existing
    return None


TOOLS = [
    {
        "name": "book_appointment",
        "description": (
            "Book an appointment with a service provider and emit a signed appointment_booked ARP receipt for it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "What is being booked (e.g. 'haircut')."},
                "provider": {"type": "string", "description": "Who it is with (business or person)."},
                "datetime": {"type": "string", "description": "When, e.g. an ISO-8601 timestamp."},
                "notes": {"type": "string", "description": "Optional free-form notes."},
            },
            "required": ["service", "provider", "datetime"],
        },
        "fn": book_appointment,
    },
]
