"""Build A2UI v0.9 surfaces from the local Agency Log.

The chapter (org server) has its own ``/page/today`` and
``/page/chronicle`` surface builders in ``server/surfaces.py``. This
module is the **sovereign / offline-first** counterpart: it reads from
the principal's local ``AgencyLog`` SQLite store and produces the same
A2UI shape (the *today* surface — ``build_today_surface_from_log``), so
the existing renderer in ``packages/a2ui-react/`` can paint it without
changes. The chronicle surface has no member-side builder yet; only the
today surface is implemented here.

Why a separate module: the chapter and the member SDK have different
data-access primitives (Postgres vs SQLite) and slightly different
visibility postures (chapter sees all receipts written to its Issuer
Log; member SDK sees only what's been pushed to its local log). Keeping
the two surface builders distinct avoids accidental cross-imports.

The wire shape is intentionally identical: a v0.9 A2UI surface envelope
with ``createSurface`` + ``updateComponents``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .arp import AgencyLog

_CATEGORY_DISPLAY: dict[str, str] = {
    "purchase": "Purchases",
    "payment_sent": "Payments sent",
    "payment_received": "Payments received",
    "message_sent": "Messages sent",
    "message_received": "Messages received",
    "decision_made": "Decisions",
    "data_shared": "Data shared",
    "appointment_booked": "Appointments",
    "appointment_cancelled": "Cancellations",
    "subscription_changed": "Subscriptions",
    "record_filed": "Records filed",
    "account_created": "Accounts opened",
    "account_closed": "Accounts closed",
    "attestation_issued": "Attestations issued",
    "attestation_received": "Attestations received",
    "commitment_entered": "Commitments entered",
    "commitment_fulfilled": "Commitments fulfilled",
    "commitment_breached": "Commitments breached",
    "vote_cast": "Votes",
    "other": "Other",
}


def _filter_today_utc(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only receipts whose issued_at falls inside the current UTC day.

    The Chronicle and Today views are both UTC-day-anchored — matches the
    chapter's heartbeat-loop boundary check so views are consistent across
    the local SDK and the chapter without time-zone reconciliation.
    """
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    return [r for r in receipts if isinstance(r.get("issued_at"), str) and r["issued_at"].startswith(today)]


def _money_label(currency: str | None, cents: int | None) -> str:
    if not isinstance(cents, int) or not currency:
        return ""
    sign = "-" if cents < 0 else "+"
    return f"{sign}{currency} {abs(cents) / 100.0:,.2f}"


# ── A2UI v0.9 helpers (inlined; avoids cross-package import) ───────


def _text(component_id: str, text: str, usage_hint: str = "body") -> dict[str, Any]:
    return {
        "id": component_id,
        "component": "Text",
        "text": text,
        "usageHint": usage_hint,
    }


def _card(component_id: str, child_id: str) -> dict[str, Any]:
    return {"id": component_id, "component": "Card", "child": child_id}


def _column(component_id: str, children: list[str]) -> dict[str, Any]:
    return {"id": component_id, "component": "Column", "children": children}


def _surface(surface_id: str, components: list[dict[str, Any]], root: str) -> dict[str, Any]:
    return {
        "createSurface": {"surfaceId": surface_id},
        "updateComponents": {
            "surfaceId": surface_id,
            "root": root,
            "components": components,
        },
        "version": "0.9",
    }


# ── Public surface builders ────────────────────────────────────────


def build_today_surface_from_log(log: AgencyLog, *, limit: int = 500) -> dict[str, Any]:
    """Build the A2UI v0.9 surface for today's receipts in the local log.

    ``limit`` bounds how many recent receipts we examine; receipts outside
    today's UTC day are filtered out after that bound. The default is
    generous enough that a normal agent's day comfortably fits.

    Empty-log days render a "quiet day" surface — the same UX shape as
    the chapter-side builder.
    """
    raw = log.list_recent(limit=limit)
    today_receipts = _filter_today_utc(raw)

    today_label = datetime.now(UTC).strftime("%A, %B %d, %Y")
    components: list[dict[str, Any]] = [
        _card("c", "root"),
        _column("root", ["title", "subtitle", "summary"]),
        _text("title", "Today", "h1"),
        _text("subtitle", today_label, "body"),
    ]

    if not today_receipts:
        components.append(
            _text(
                "summary",
                "Your local Agency Log is quiet today — no recorded actions yet.",
                "body",
            )
        )
        return _surface("today-local", components, "c")

    # Group by category
    grouped: dict[str, list[dict[str, Any]]] = {}
    for r in today_receipts:
        cat = (r.get("action") or {}).get("category", "other")
        grouped.setdefault(cat, []).append(r)

    # Patch the column children to include section refs
    components[1] = _column(
        "root",
        ["title", "subtitle", "summary"] + [f"section-{c}" for c in grouped],
    )
    components.append(
        _text(
            "summary",
            f"{len(today_receipts)} recorded action{'s' if len(today_receipts) != 1 else ''} "
            f"across {len(grouped)} categor{'ies' if len(grouped) != 1 else 'y'}.",
            "body",
        )
    )

    for cat, rows in grouped.items():
        section_id = f"section-{cat}"
        head_id = f"{section_id}-h"
        title_id = f"{section_id}-title"
        list_id = f"{section_id}-list"
        section_label = _CATEGORY_DISPLAY.get(cat, cat.replace("_", " ").title())
        items: list[str] = []
        for r in rows:
            action = r.get("action") or {}
            summary = action.get("human_summary") or "(no summary)"
            amount = action.get("amount") or {}
            amount_label = _money_label(amount.get("currency"), amount.get("cents"))
            line = f"• {summary}" + (f"  {amount_label}" if amount_label else "")
            items.append(line)
        components.append(_card(section_id, head_id))
        components.append(_column(head_id, [title_id, list_id]))
        components.append(_text(title_id, f"{section_label} ({len(rows)})", "h3"))
        components.append(_text(list_id, "\n".join(items), "body"))

    return _surface("today-local", components, "c")


__all__ = [
    "build_today_surface_from_log",
]
