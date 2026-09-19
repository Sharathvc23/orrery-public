"""DSAR — Data Subject Access Requests + cascading deletion.

Implements the chapter-side endpoints for CCPA/CPRA/GDPR-style data
subject rights:

  GET /api/dsar/export?subject_did=<did:key:z...>
      Returns a JSON archive of every record the chapter holds about
      that data subject across all tables. Admin-gated (no random
      strangers can dump arbitrary subjects).

  POST /api/dsar/delete?subject_did=<did:key:z...>
      Cascades deletion across every table holding records keyed by
      that DID. Admin-gated AND requires explicit ``confirm=true``
      query param to prevent accidental mass-delete via misclick.

  GET /api/dsar/inventory
      Returns the list of (table_name, field_name, count) triples
      describing what chapter data IS scoped to data subjects. Helps
      operators draft Privacy Policy disclosures that match reality.

Architecture:

  - This module lives in chapter/ but does no Postgres coupling
    itself — endpoints in chapter_agent.py inject a pg_request
    callable.
  - The module catalogs which tables/fields hold subject-scoped data
    in one place (DSAR_DATA_INVENTORY). Adding a new table that holds
    PII MUST update this catalog so DSAR export + delete continue to
    cover every surface.
  - Deletion is best-effort + reports per-table outcomes. A single
    table failure does not abort the cascade — the caller gets a
    summary so they know what landed and what didn't.

What this v0.1 covers:

  - arp_receipts (subject = principal_did)
  - chapter_audit_events (subject = actor_agent_id)
  - chronicles (subject = principal_did)
  - agents (subject = agent_id, resolved from the DID via agent_facts)
  - agent_intents (subject = requester_agent_id), agent_action_outcomes +
    trust_events (subject = agent_id)
  - chapter_role_nominations (subject = nominee_agent_id)

What's NOT covered (schema-limited — see that change):

  - agent_memory: this is the CHAPTER agent's short-term dedup cache, keyed by
    ``chapter_agent_id`` (the chapter itself) with NO per-member/subject column,
    so there is no member-scoped agent_memory row to export or delete. Deleting
    real per-member rows would need a subject column added to agent_memory. This
    module never silently claims to have deleted it.
  - External integrations (Slack channels, email, etc.) where the
    subject's data lives in third-party systems — the chapter can't
    delete those, only the integration receipt that records the
    interaction.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

# Each entry: (table, primary_subject_field, secondary_subject_field_or_none, agent_id_field_or_none)
# - primary: the field whose value equals the subject's did:key
# - secondary: when a row mentions the subject as counterparty / target
# - agent_id_field: when the table keys on agent_id (not did:key);
#   resolver translates did:key → agent_id via the agents table.
DSAR_DATA_INVENTORY: list[tuple[str, str | None, str | None, str | None]] = [
    # (table, did_field, secondary_did_field, agent_id_field)
    ("arp_receipts", "principal_did", None, None),
    ("chronicles", "principal_did", None, None),
    ("chapter_audit_events", None, None, "actor_agent_id"),
    ("agents", None, None, "agent_id"),
    # the table is `agent_intents` (init.sql:997) and the member is its
    # `requester_agent_id` — the old ("intents", ..., "agent_id") matched neither
    # a real table nor a real column, so intents were never exported/deleted.
    ("agent_intents", None, None, "requester_agent_id"),
    ("agent_action_outcomes", None, None, "agent_id"),
    # trust_events keys the subject on `agent_id`; there is no
    # `subject_agent_id` column (init.sql:2863).
    ("trust_events", None, None, "agent_id"),
    ("chapter_role_nominations", None, None, "nominee_agent_id"),
]


async def _resolve_agent_id_from_did(
    pg_request: Callable[..., Awaitable[Any]],
    subject_did: str,
) -> str | None:
    """Map a did:key to the chapter's agent_id, if the subject is a
    registered chapter member. Returns None if no agent matches —
    the subject may only have records in receipt/audit tables that
    use did:key directly, not in the agent-keyed tables.

    That change: the member DID lives in ``agent_facts->'provider'->>'did'`` — there is NO
    ``agents.did_key`` column, so the old ``did_key=eq.<did>`` query errored,
    pg_request returned None, and EVERY agent-keyed table was skipped (the member's
    agents row, audit events, intents, outcomes, trust_events, nominations were
    never exported/deleted). pg_store can't filter on a jsonb path, so we fetch
    member facts and match in Python — the same idiom ``reload_member_keys`` uses.
    Errors are NOT swallowed: a DB failure during a GDPR erasure must surface (a
    silent None here would under-delete and falsely report success)."""
    if not subject_did or not subject_did.startswith("did:key:"):
        return None
    rows = await pg_request(
        "GET",
        "agents",
        params={
            "agent_facts": "not.is.null",
            "select": "agent_id,agent_facts",
            "limit": "10000",
        },
    )
    for row in rows or []:
        facts = row.get("agent_facts")
        if isinstance(facts, dict):
            did = (facts.get("provider") or {}).get("did") or ""
            if did == subject_did:
                return row.get("agent_id") or None
    return None


async def export_subject_data(
    pg_request: Callable[..., Awaitable[Any]],
    subject_did: str,
    *,
    max_rows_per_table: int = 10000,
) -> dict[str, Any]:
    """Build a complete data archive for the subject.

    Returns:
        {
          "subject_did": "did:key:z...",
          "resolved_agent_id": "<agent_id or None>",
          "exported_at": "2026-05-22T...",
          "tables": {
            "<table_name>": {
              "count": N,
              "rows": [...]
            },
            ...
          }
        }

    Per-table queries are bounded by ``max_rows_per_table`` to keep the
    response size reasonable; a real production export for a heavy
    subject would stream. The cap defaults to 10K which covers >99% of
    real subjects.
    """
    from datetime import UTC, datetime

    resolved_agent_id = await _resolve_agent_id_from_did(pg_request, subject_did)
    tables: dict[str, dict[str, Any]] = {}

    for table, primary_did, secondary_did, agent_field in DSAR_DATA_INVENTORY:
        table_rows: list[dict] = []
        # did:key-keyed table
        if primary_did:
            try:
                rows = await pg_request(
                    "GET",
                    table,
                    params={
                        primary_did: f"eq.{subject_did}",
                        "limit": str(max_rows_per_table),
                    },
                )
                if rows and isinstance(rows, list):
                    table_rows.extend(rows)
            except Exception:  # noqa: BLE001
                pass
        if secondary_did:
            try:
                rows = await pg_request(
                    "GET",
                    table,
                    params={
                        secondary_did: f"eq.{subject_did}",
                        "limit": str(max_rows_per_table),
                    },
                )
                if rows and isinstance(rows, list):
                    table_rows.extend(rows)
            except Exception:  # noqa: BLE001
                pass
        # agent_id-keyed table — only if we resolved the DID to an agent_id
        if agent_field and resolved_agent_id:
            try:
                rows = await pg_request(
                    "GET",
                    table,
                    params={
                        agent_field: f"eq.{resolved_agent_id}",
                        "limit": str(max_rows_per_table),
                    },
                )
                if rows and isinstance(rows, list):
                    table_rows.extend(rows)
            except Exception:  # noqa: BLE001
                pass

        # Deduplicate by id if present
        seen_ids: set[str] = set()
        deduped: list[dict] = []
        for r in table_rows:
            rid = str(r.get("id") or r.get("receipt_id") or "")
            if rid and rid in seen_ids:
                continue
            seen_ids.add(rid)
            deduped.append(r)

        tables[table] = {"count": len(deduped), "rows": deduped}

    return {
        "subject_did": subject_did,
        "resolved_agent_id": resolved_agent_id,
        "exported_at": datetime.now(UTC).isoformat(),
        "tables": tables,
        "inventory": [
            {"table": t, "did_field": p, "secondary_did_field": s, "agent_id_field": a}
            for t, p, s, a in DSAR_DATA_INVENTORY
        ],
    }


async def delete_subject_data(
    pg_request: Callable[..., Awaitable[Any]],
    subject_did: str,
) -> dict[str, Any]:
    """Cascading deletion across every catalogued table.

    Returns per-table {"deleted": int, "error": str | None} so the
    caller knows precisely what landed. A single table failure does
    NOT abort the cascade.

    The chapter's emit of an ``authority_revoked`` receipt for this
    subject is the caller's responsibility (compliance: the deletion
    itself is an evidenced event)."""
    resolved_agent_id = await _resolve_agent_id_from_did(pg_request, subject_did)
    results: dict[str, dict[str, Any]] = {}

    for table, primary_did, secondary_did, agent_field in DSAR_DATA_INVENTORY:
        deleted = 0
        error: str | None = None

        # Best-effort delete by did:key
        if primary_did:
            try:
                resp = await pg_request(
                    "DELETE",
                    table,
                    params={primary_did: f"eq.{subject_did}"},
                )
                if isinstance(resp, list):
                    deleted += len(resp)
            except Exception as e:  # noqa: BLE001
                error = str(e)[:200]
        if secondary_did:
            try:
                resp = await pg_request(
                    "DELETE",
                    table,
                    params={secondary_did: f"eq.{subject_did}"},
                )
                if isinstance(resp, list):
                    deleted += len(resp)
            except Exception as e:  # noqa: BLE001
                error = (error + "; " if error else "") + str(e)[:200]
        if agent_field and resolved_agent_id:
            try:
                resp = await pg_request(
                    "DELETE",
                    table,
                    params={agent_field: f"eq.{resolved_agent_id}"},
                )
                if isinstance(resp, list):
                    deleted += len(resp)
            except Exception as e:  # noqa: BLE001
                error = (error + "; " if error else "") + str(e)[:200]

        results[table] = {"deleted": deleted, "error": error}

    return {
        "subject_did": subject_did,
        "resolved_agent_id": resolved_agent_id,
        "tables": results,
        "total_deleted": sum(r["deleted"] for r in results.values()),
    }


def inventory() -> list[dict[str, Any]]:
    """Public catalog of which tables/fields are scoped to data subjects.

    Useful for the operator to draft a Privacy Policy that matches
    reality. Returns the same shape used in export_subject_data's
    'inventory' field."""
    return [
        {"table": t, "did_field": p, "secondary_did_field": s, "agent_id_field": a}
        for t, p, s, a in DSAR_DATA_INVENTORY
    ]


__all__ = [
    "DSAR_DATA_INVENTORY",
    "export_subject_data",
    "delete_subject_data",
    "inventory",
]
