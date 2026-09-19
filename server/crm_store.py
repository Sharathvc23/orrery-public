"""CRM as an ORG-SIDE RECORD TYPE — contacts, deals, interaction history.

Deliberately not a SaaS connector. A connector would mean two sources of truth
to reconcile and someone else's auth model inherited wholesale; the org already
has Postgres, signed receipts and a consent surface, so the record lives here
and every mutation is accountable by the same machinery as everything else.

⚠️ DETERMINISTIC. There is no LLM anywhere in this module's write path, and
that is a design bias for the whole service-verb program: the model proposes and
drafts, it never triggers or mutates. A record write is a verb, not a judgement.
Nothing here reads a model output, and nothing here decides what to write — the
caller supplies fields, this module validates and persists them.

⚠️ EVERY MUTATION IS GOVERNED — see ``_gate`` below. The 2026-08-05 spike
measured that all eight approval kinds were social and that ``pending_approvals``
stayed at 0 across a full run with four service agents; PR1 closed that by
registering three verb-shaped operational kinds. A durable write to a store the
operator is accountable for is ``record_write``, so this module consumes that gate
rather than carrying one of its own. There is exactly one gate in the org, and a
second implementation would be a second policy pretending to be the same one.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

_pg_request: Callable[..., Awaitable] | None = None
_agent_id: str = ""

#: The operational approval kind every mutation here routes through.
#:
#: ``record_write``, not a ``crm_write`` of our own. PR1 deliberately made the
#: kinds VERB-shaped — "any durable write to a store the operator is accountable
#: for" — because a kind per integration means a governance change for every
#: integration, and integrations that ship before their kind does are the exact
#: failure being prevented. A CRM row is that verb; it does not need its own.
CRM_APPROVAL_KIND = "record_write"

CONTACT_STAGES = ("lead", "qualified", "customer", "churned")
DEAL_STAGES = ("open", "won", "lost")
INTERACTION_KINDS = ("call", "email", "meeting", "note")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def init(pg_request: Callable[..., Awaitable], agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


def _now() -> str:
    return datetime.now(UTC).isoformat()


class CrmError(ValueError):
    """A rejected write. Carries a machine-readable reason, never a free-text
    blob — a caller that cannot branch on the reason ends up retrying blindly."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


# ── validation: deterministic, total, and refusing rather than coercing ─────


def _require_text(value: Any, field: str, *, maxlen: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CrmError(f"{field}_required", f"{field} must be a non-empty string")
    v = value.strip()
    if len(v) > maxlen:
        raise CrmError(f"{field}_too_long", f"{field} exceeds {maxlen} characters")
    return v


def _require_choice(value: Any, field: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise CrmError(f"{field}_invalid", f"{field} must be one of {list(allowed)}")
    return str(value)


def _optional_email(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _EMAIL_RE.match(value.strip()):
        # Refused, not normalised. A silently "cleaned" contact address is how a
        # record ends up addressing someone other than the person intended.
        raise CrmError("email_invalid", "email is not a valid address")
    return value.strip()


def _require_amount(value: Any) -> int:
    """Minor units (cents), integer only.

    Floats are refused rather than rounded: a deal value that drifts by a
    rounding step is a number no one can reconcile against an invoice, and the
    caller — not this module — is the one who knows the intended precision.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise CrmError("amount_invalid", "amount_minor must be an integer in minor units")
    if value < 0:
        raise CrmError("amount_negative", "amount_minor must not be negative")
    return value


# ── the governance choke point ──────────────────────────────────────────────


def _action_key(action: str, *parts: Any) -> str:
    """The specific action within the kind, exactly as PR1 matches it.

    Readable rather than a digest, because an operator approves what they can
    read — an opaque hash in the queue is a decision nobody can actually make.
    Every value that changes what happens is in the key: an approval to move
    deal D to ``won`` is not an approval to move it to ``lost``, and an approval
    for a 500.00 deal is not an approval for 500,000.00. Free text is folded to
    a short digest instead of being inlined, so a 2000-character note cannot
    push an unbounded string into the key.
    """
    return ":".join(["crm", action, *(str(p) for p in parts)])


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


async def _gate(action: str, action_key: str, payload: dict[str, Any], actor_agent_id: str) -> dict[str, Any]:
    """Consume an operational approval, or report that the write must wait.

    Returns ``{"status": "approved", ...}`` — and ONLY then may the caller apply
    the write — or ``{"status": "pending", ...}``, which the caller must return
    without mutating anything.

    ⚠️ This delegates to ``governance.consume_operational_approval`` rather than
    deciding anything itself. That matters: PR1's gate CONSUMES the grant as it
    authorises, single-use, so an approval cannot become a standing licence. A
    local re-implementation that merely checked for an approved row would leave
    the grant spendable again and turn one operator decision into unlimited
    writes — the precise failure PR1 documents itself as preventing.

    FAIL-CLOSED. Governance being unimportable or unreachable refuses the write.
    An earlier revision of this module let a mutation proceed as "ungoverned"
    when no operational kind existed, and recorded that in the receipt; that change
    ended that world, and keeping the branch now would be a bypass that any
    failure of the governance store could induce.
    """
    try:
        import governance
    except Exception as e:  # noqa: BLE001
        raise CrmError("governance_unavailable", f"cannot govern this write: {e}") from e

    try:
        row = await governance.consume_operational_approval(
            CRM_APPROVAL_KIND,
            actor_agent_id=actor_agent_id,
            action_key=action_key,
            payload={"crm_action": action, **payload},
        )
    except governance.OperationalApprovalRequired as e:
        approval = e.approval or {}
        return {
            "gated": True,
            "status": "pending",
            "kind": CRM_APPROVAL_KIND,
            "action_key": action_key,
            "approval_id": approval.get("id"),
            "reason": e.reason,
        }
    return {
        "gated": True,
        "status": "approved",
        "kind": CRM_APPROVAL_KIND,
        "action_key": action_key,
        "approval_id": (row or {}).get("id"),
    }


async def _receipt(action: str, summary: str, payload: dict[str, Any], gate: dict[str, Any]) -> None:
    """Emit the signed receipt for a mutation. Fire-and-forget, like every other
    receipt path here — telemetry must not wedge a business action — but the
    GOVERNANCE STATUS travels inside it, so a reader can always tell whether a
    given record change was approved, pending, or applied ungoverned."""
    try:
        import arp

        await arp.emit_chapter_action(
            principal_did=await _principal_did(),
            category="record_filed",
            human_summary=summary,
            machine_payload={"crm_action": action, "governance": gate, **payload},
        )
    except Exception as e:  # noqa: BLE001
        print(f"[CRM] receipt emission failed for {action}: {type(e).__name__}: {e}")


async def _principal_did() -> str:
    try:
        import arp

        return await arp.resolve_member_did(_agent_id)
    except Exception:  # noqa: BLE001
        return _agent_id


async def _insert(table: str, body: dict[str, Any]) -> dict[str, Any]:
    if _pg_request is None:
        raise CrmError("no_database", "CRM storage requires Postgres")
    resp = await _pg_request("POST", table, body=body)
    if isinstance(resp, list) and resp:
        return dict(resp[0])
    if isinstance(resp, dict):
        return resp
    raise CrmError("write_failed", f"insert into {table} returned no row")


# ── the verbs ───────────────────────────────────────────────────────────────


async def create_contact(
    *, actor_agent_id: str, name: str, email: Any = None, org: Any = None, stage: str = "lead"
) -> dict[str, Any]:
    """Create a contact. Deterministic: validate, gate, persist, receipt."""
    fields = {
        "name": _require_text(name, "name"),
        "email": _optional_email(email),
        "org": _require_text(org, "org") if org not in (None, "") else None,
        "stage": _require_choice(stage, "stage", CONTACT_STAGES),
    }
    gate = await _gate(
        "create_contact",
        _action_key("create_contact", fields["email"] or fields["name"]),
        fields,
        actor_agent_id,
    )
    if gate["status"] == "pending":
        return {"status": "pending_approval", "governance": gate}

    row = await _insert(
        "crm_contacts",
        {**fields, "chapter_id": _agent_id, "created_by": actor_agent_id, "created_at": _now(), "updated_at": _now()},
    )
    await _receipt("create_contact", f"Filed CRM contact {fields['name']}", {"contact_id": row.get("id")}, gate)
    return {"status": "created", "contact": row, "governance": gate}


async def update_contact_stage(*, actor_agent_id: str, contact_id: str, stage: str) -> dict[str, Any]:
    """Move a contact between lifecycle stages."""
    new_stage = _require_choice(stage, "stage", CONTACT_STAGES)
    gate = await _gate(
        "update_contact_stage",
        _action_key("update_contact_stage", contact_id, new_stage),
        {"contact_id": contact_id, "stage": new_stage},
        actor_agent_id,
    )
    if gate["status"] == "pending":
        return {"status": "pending_approval", "governance": gate}

    if _pg_request is None:
        raise CrmError("no_database", "CRM storage requires Postgres")
    await _pg_request(
        "PATCH",
        "crm_contacts",
        params={"id": f"eq.{contact_id}", "chapter_id": f"eq.{_agent_id}"},
        body={"stage": new_stage, "updated_at": _now()},
    )
    await _receipt(
        "update_contact_stage",
        f"Moved CRM contact {contact_id} to {new_stage}",
        {"contact_id": contact_id, "stage": new_stage},
        gate,
    )
    return {"status": "updated", "contact_id": contact_id, "stage": new_stage, "governance": gate}


async def create_deal(
    *, actor_agent_id: str, contact_id: str, title: str, amount_minor: Any, currency: str = "USD"
) -> dict[str, Any]:
    """Open a deal against a contact. Amounts are integer minor units."""
    fields = {
        "contact_id": _require_text(contact_id, "contact_id"),
        "title": _require_text(title, "title"),
        "amount_minor": _require_amount(amount_minor),
        "currency": _require_choice(
            currency.upper() if isinstance(currency, str) else currency, "currency", ("USD", "EUR", "GBP")
        ),
        "stage": "open",
    }
    gate = await _gate(
        "create_deal",
        _action_key("create_deal", fields["contact_id"], fields["amount_minor"], fields["currency"]),
        fields,
        actor_agent_id,
    )
    if gate["status"] == "pending":
        return {"status": "pending_approval", "governance": gate}

    row = await _insert(
        "crm_deals",
        {**fields, "chapter_id": _agent_id, "created_by": actor_agent_id, "created_at": _now(), "updated_at": _now()},
    )
    await _receipt("create_deal", f"Opened CRM deal {fields['title']}", {"deal_id": row.get("id")}, gate)
    return {"status": "created", "deal": row, "governance": gate}


async def set_deal_stage(*, actor_agent_id: str, deal_id: str, stage: str) -> dict[str, Any]:
    """Close a deal won or lost, or reopen it."""
    new_stage = _require_choice(stage, "stage", DEAL_STAGES)
    gate = await _gate(
        "set_deal_stage",
        _action_key("set_deal_stage", deal_id, new_stage),
        {"deal_id": deal_id, "stage": new_stage},
        actor_agent_id,
    )
    if gate["status"] == "pending":
        return {"status": "pending_approval", "governance": gate}

    if _pg_request is None:
        raise CrmError("no_database", "CRM storage requires Postgres")
    await _pg_request(
        "PATCH",
        "crm_deals",
        params={"id": f"eq.{deal_id}", "chapter_id": f"eq.{_agent_id}"},
        body={"stage": new_stage, "updated_at": _now()},
    )
    await _receipt(
        "set_deal_stage", f"Set CRM deal {deal_id} to {new_stage}", {"deal_id": deal_id, "stage": new_stage}, gate
    )
    return {"status": "updated", "deal_id": deal_id, "stage": new_stage, "governance": gate}


async def log_interaction(
    *, actor_agent_id: str, contact_id: str, kind: str, summary: str, occurred_at: Any = None
) -> dict[str, Any]:
    """Append to a contact's interaction history. Append-only by construction —
    there is no update or delete verb, because an edited history is not a
    history."""
    fields = {
        "contact_id": _require_text(contact_id, "contact_id"),
        "kind": _require_choice(kind, "kind", INTERACTION_KINDS),
        "summary": _require_text(summary, "summary", maxlen=2000),
        "occurred_at": occurred_at if isinstance(occurred_at, str) and occurred_at else _now(),
    }
    gate = await _gate(
        "log_interaction",
        _action_key("log_interaction", fields["contact_id"], fields["kind"], _digest(fields["summary"])),
        fields,
        actor_agent_id,
    )
    if gate["status"] == "pending":
        return {"status": "pending_approval", "governance": gate}

    row = await _insert(
        "crm_interactions",
        {**fields, "chapter_id": _agent_id, "created_by": actor_agent_id, "created_at": _now()},
    )
    await _receipt(
        "log_interaction",
        f"Logged {fields['kind']} with CRM contact {fields['contact_id']}",
        {"interaction_id": row.get("id")},
        gate,
    )
    return {"status": "created", "interaction": row, "governance": gate}


# ── reads (no gate: reads are not mutations) ────────────────────────────────


async def list_contacts(*, stage: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if _pg_request is None:
        return []
    params: dict[str, Any] = {
        "chapter_id": f"eq.{_agent_id}",
        "order": "updated_at.desc",
        "limit": str(max(1, min(limit, 500))),
    }
    if stage:
        params["stage"] = f"eq.{_require_choice(stage, 'stage', CONTACT_STAGES)}"
    rows = await _pg_request("GET", "crm_contacts", params=params)
    return list(rows) if isinstance(rows, list) else []


async def contact_history(contact_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    if _pg_request is None:
        return []
    rows = await _pg_request(
        "GET",
        "crm_interactions",
        params={
            "chapter_id": f"eq.{_agent_id}",
            "contact_id": f"eq.{contact_id}",
            "order": "occurred_at.desc",
            "limit": str(max(1, min(limit, 500))),
        },
    )
    return list(rows) if isinstance(rows, list) else []
