"""Built-in 'crm' skill — file CRM records THROUGH the org.

⚠️ THIS SKILL DELIBERATELY HOLDS NO STATE. Every other built-in that writes
(``booking``, ``tasks``) keeps a local JSON file under ``COMMUNITY_MEMBER_HOME``.
This one does not, and the difference is the point: a CRM record is an ORG
record, not an agent's private note. Keeping a local copy would create a second
source of truth that nothing reconciles, and the org side is where the receipt,
the consent surface and the governance gate already live. Every write here is
behind the org's ``record_write`` operational approval (PR1/that change), so a call that
returns ``pending_approval`` has written nothing — that is a normal outcome, not
an error, and the distinction has to survive all the way to the user.

So the skill is a thin, deterministic caller of the org's ``/api/crm/*`` verbs.
It builds no records of its own and makes no judgements — it passes the caller's
fields through and returns what the org decided. There is no LLM in this path.

A keyless or unjoined agent gets a clear refusal rather than a crash: without a
chapter URL there is no org to write through, and a CRM write is not something
to fake locally and reconcile later.
"""

from __future__ import annotations

from pathlib import Path


def _client(home: Path | None):
    """Build a signed org client, or return an error dict explaining why not.

    Returns ``(client, error)`` — exactly one is None. A tuple rather than an
    exception because a keyless or unjoined agent is a VALID agent that simply
    cannot write org records, and the caller should see a reason, not a stack
    trace.
    """
    from community_member.a2a_client import A2AClient
    from community_member.config import Config

    cfg = Config.load(home=home)
    if not cfg.chapter_url:
        return None, {
            "error": "not_joined",
            "detail": "CRM records are written through your org — join a chapter first.",
        }
    if not cfg.agent_id or not cfg.private_key:
        return None, {
            "error": "no_signing_identity",
            "detail": "org records are filed under a signed identity — run `community-member init`.",
        }
    return A2AClient(cfg.chapter_url, agent_id=cfg.agent_id, private_key=cfg.private_key), None


def _post(path: str, body: dict, home: Path | None) -> dict:
    client, err = _client(home)
    if err:
        return err
    try:
        return client._post(path, body)
    except Exception as e:  # noqa: BLE001 — an unreachable org is a reportable outcome
        return {"error": "org_unreachable", "detail": f"{type(e).__name__}: {e}"}


def _get(path: str, home: Path | None) -> dict:
    client, err = _client(home)
    if err:
        return err
    try:
        return client._get(path)
    except Exception as e:  # noqa: BLE001
        return {"error": "org_unreachable", "detail": f"{type(e).__name__}: {e}"}


def add_contact(args: dict, *, home: Path | None = None) -> dict:
    """Create a contact. Fields pass through unchanged — the org validates."""
    return _post(
        "/api/crm/contacts",
        {
            "name": args.get("name", ""),
            "email": args.get("email"),
            "org": args.get("org"),
            "stage": args.get("stage", "lead"),
        },
        home,
    )


def set_contact_stage(args: dict, *, home: Path | None = None) -> dict:
    return _post(f"/api/crm/contacts/{args.get('contact_id', '')}/stage", {"stage": args.get("stage", "")}, home)


def add_deal(args: dict, *, home: Path | None = None) -> dict:
    """Open a deal. ``amount_minor`` is an INTEGER in minor units (cents) — the
    org refuses a float rather than rounding, because only the caller knows the
    intended precision."""
    return _post(
        "/api/crm/deals",
        {
            "contact_id": args.get("contact_id", ""),
            "title": args.get("title", ""),
            "amount_minor": args.get("amount_minor"),
            "currency": args.get("currency", "USD"),
        },
        home,
    )


def set_deal_stage(args: dict, *, home: Path | None = None) -> dict:
    return _post(f"/api/crm/deals/{args.get('deal_id', '')}/stage", {"stage": args.get("stage", "")}, home)


def log_interaction(args: dict, *, home: Path | None = None) -> dict:
    """Append to a contact's history. Append-only: there is no edit verb."""
    return _post(
        "/api/crm/interactions",
        {
            "contact_id": args.get("contact_id", ""),
            "kind": args.get("kind", "note"),
            "summary": args.get("summary", ""),
            "occurred_at": args.get("occurred_at"),
        },
        home,
    )


def list_contacts(args: dict, *, home: Path | None = None) -> dict:
    q = f"?stage={args['stage']}" if args.get("stage") else ""
    return _get(f"/api/crm/contacts{q}", home)


def contact_history(args: dict, *, home: Path | None = None) -> dict:
    return _get(f"/api/crm/contacts/{args.get('contact_id', '')}/history", home)


_STAGE_DESC = "One of: lead, qualified, customer, churned."

#: Appended to EVERY mutating tool description.
#:
#: ⚠️ Load-bearing for honesty, not decoration. A CRM write is an operational
#: action behind the org's `record_write` approval, so the ordinary outcome is
#: `pending_approval` — accepted, nothing written. A description that says "files
#: a contact" full stop invites the model to report the record as filed and then
#: reference an id that does not exist. It has to be told that a call can succeed
#: without the write happening, and that the two are different results.
_APPROVAL_NOTE = (
    " Requires operator approval: if no approval is waiting, this returns "
    "status='pending_approval' and NOTHING IS WRITTEN — report it as awaiting "
    "approval, never as done, and do not retry it in a loop."
)

TOOLS = [
    {
        "name": "add_contact",
        "description": "File a new CRM contact with the org. Emits a signed receipt for the write." + _APPROVAL_NOTE,
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Contact's name."},
                "email": {"type": "string", "description": "Optional email address."},
                "org": {"type": "string", "description": "Optional company or organisation."},
                "stage": {"type": "string", "description": _STAGE_DESC},
            },
            "required": ["name"],
        },
        "fn": add_contact,
    },
    {
        "name": "set_contact_stage",
        "description": "Move a CRM contact to a different lifecycle stage." + _APPROVAL_NOTE,
        "parameters": {
            "type": "object",
            "properties": {
                "contact_id": {"type": "string", "description": "The contact's id."},
                "stage": {"type": "string", "description": _STAGE_DESC},
            },
            "required": ["contact_id", "stage"],
        },
        "fn": set_contact_stage,
    },
    {
        "name": "add_deal",
        "description": "Open a CRM deal against a contact. Amount is an integer in minor units (cents)."
        + _APPROVAL_NOTE,
        "parameters": {
            "type": "object",
            "properties": {
                "contact_id": {"type": "string", "description": "The contact this deal belongs to."},
                "title": {"type": "string", "description": "What the deal is for."},
                "amount_minor": {"type": "integer", "description": "Value in MINOR units (cents). Integer only."},
                "currency": {"type": "string", "description": "USD, EUR or GBP."},
            },
            "required": ["contact_id", "title", "amount_minor"],
        },
        "fn": add_deal,
    },
    {
        "name": "set_deal_stage",
        "description": "Mark a CRM deal open, won or lost." + _APPROVAL_NOTE,
        "parameters": {
            "type": "object",
            "properties": {
                "deal_id": {"type": "string", "description": "The deal's id."},
                "stage": {"type": "string", "description": "One of: open, won, lost."},
            },
            "required": ["deal_id", "stage"],
        },
        "fn": set_deal_stage,
    },
    {
        "name": "log_interaction",
        "description": "Append a call, email, meeting or note to a contact's history. Append-only." + _APPROVAL_NOTE,
        "parameters": {
            "type": "object",
            "properties": {
                "contact_id": {"type": "string", "description": "The contact."},
                "kind": {"type": "string", "description": "One of: call, email, meeting, note."},
                "summary": {"type": "string", "description": "What happened."},
                "occurred_at": {"type": "string", "description": "Optional ISO-8601 time; defaults to now."},
            },
            "required": ["contact_id", "kind", "summary"],
        },
        "fn": log_interaction,
    },
    {
        "name": "list_contacts",
        "description": "List CRM contacts for this org, newest first.",
        "parameters": {
            "type": "object",
            "properties": {"stage": {"type": "string", "description": f"Optional filter. {_STAGE_DESC}"}},
        },
        "fn": list_contacts,
    },
    {
        "name": "contact_history",
        "description": "Read a CRM contact's interaction history, newest first.",
        "parameters": {
            "type": "object",
            "properties": {"contact_id": {"type": "string", "description": "The contact."}},
            "required": ["contact_id"],
        },
        "fn": contact_history,
    },
]
