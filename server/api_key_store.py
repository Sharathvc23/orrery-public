"""Reading member LLM provider keys out of ``agent_api_keys`` (AUDIT_HARSH C1).

The column is named ``api_key_encrypted`` but nothing ever encrypted it: both
runtimes read ``row["api_key_encrypted"]`` and passed the value straight to the
provider client. The name asserted a property the storage did not have, which is
how the audit found it.

These keys are bring-your-own-key member credentials. A leak costs the member
their own provider spend — real, and strictly less severe than the chapter
signing key in ``sovereign_identity``, which is org identity and forges receipts.
Both live in the same database, so both are sealed by the same mechanism
(``secret_sealing``, AES-256-GCM under ``ORRERY_KEY_SECRET``).

Nothing in this repository WRITES ``agent_api_keys`` — rows are provisioned out
of band. So the read path here does two things:

- Unseals ``enc.v1:``-prefixed values, and passes legacy plaintext through, so a
  provisioner can start writing sealed values without a flag day.
- Seals existing plaintext rows in place on read, once ``ORRERY_KEY_SECRET`` is
  available. Without this, sealing would apply only to rows written after the
  provisioner is updated, and every key already in the table would stay in the
  clear behind code that reads as fixed.

The returned rows carry the plaintext under ``api_key``, not under
``api_key_encrypted``, so a call site cannot repeat the original mistake of
treating an at-rest field as if it were usable material.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import secret_sealing

PostgresRequest = Callable[..., Awaitable[Any]]

TABLE = "agent_api_keys"
_SELECT = "profile_id,provider,api_key_encrypted,base_url"


def _subject(profile_id: str, provider: str) -> str:
    return f"the LLM provider key for profile {profile_id} ({provider})"


async def load_api_keys(pg_request: PostgresRequest, *, unreadable: set[str] | None = None) -> list[dict]:
    """Fetch every member LLM key, unsealed and keyed as ``api_key``.

    Rows whose stored value cannot be unsealed are DROPPED with a log line rather
    than raising: one member's unreadable key must not stop the org from starting
    every other member's runtime. A dropped row means that member gets no runtime.

    ⚠️ DROPPED IS NOT THE SAME AS ABSENT, and the caller now has to be able to
    tell. It used to be "the same observable state as having no key configured",
    which was true only while no-key meant no-runtime. A member with no key can
    now fall through to a local provider or an environment credential — so if a
    dropped row still looked like an absent one, a member whose own key became
    unreadable would quietly start spending someone else's. Pass ``unreadable``
    to receive the profile ids that were dropped.
    """
    rows = await pg_request("GET", TABLE, params={"select": _SELECT})
    if not rows:
        return []

    out: list[dict] = []
    for row in rows:
        profile_id = row.get("profile_id", "")
        provider = row.get("provider", "")
        stored = row.get("api_key_encrypted") or ""
        if not profile_id or not stored:
            continue
        try:
            plaintext = secret_sealing.unseal(stored)
        except Exception as e:  # noqa: BLE001 — drop one row, never the whole load
            print(
                f"[api_key_store][ERROR] could not read {_subject(profile_id, provider)} "
                f"({type(e).__name__}: {e}) — skipping this member's runtime"
            )
            if unreadable is not None:
                unreadable.add(profile_id)
            continue
        out.append(
            {
                "profile_id": profile_id,
                "provider": provider,
                "base_url": row.get("base_url", ""),
                "api_key": plaintext,
                "_stored": stored,
            }
        )

    await _seal_plaintext_rows_in_place(pg_request, out)
    for row in out:
        row.pop("_stored", None)
    return out


async def _seal_plaintext_rows_in_place(pg_request: PostgresRequest, rows: list[dict]) -> None:
    """Re-store any legacy plaintext key sealed, leaving the key itself unchanged.

    Runs only when ``ORRERY_KEY_SECRET`` is set (``needs_migration``). A failed
    UPDATE is logged and retried on the next load rather than raised — the keys
    are already in memory and the runtimes work; what is at stake is the at-rest
    form, not availability.
    """
    for row in rows:
        if not secret_sealing.needs_migration(row["_stored"]):
            continue
        profile_id, provider = row["profile_id"], row["provider"]
        sealed = secret_sealing.seal(row["api_key"], subject=_subject(profile_id, provider))
        result = await pg_request(
            "PATCH",
            TABLE,
            params={"profile_id": f"eq.{profile_id}", "provider": f"eq.{provider}"},
            body={"api_key_encrypted": sealed},
        )
        if result is None:
            print(
                f"[api_key_store][ERROR] {_subject(profile_id, provider)} is stored in PLAINTEXT and "
                "the seal-in-place UPDATE failed — still readable to anyone with database access. "
                "Retrying on next load."
            )
            continue
        print(f"[api_key_store] sealed {_subject(profile_id, provider)} in place (was plaintext at rest)")


#: Providers the ``agent_api_keys`` CHECK constraint accepts. The registry in
#: ``llm_runtime`` knows seven; this table was created knowing five. Writing a
#: provider the constraint rejects is an INSERT that fails at the database and
#: is easy to swallow into "saved", which is how a Python set and a CHECK
#: constraint drift apart. Callers ask before writing.
WRITABLE_PROVIDERS = frozenset({"xai", "openai", "anthropic", "groq", "custom"})


def writable(provider: str) -> bool:
    """Whether ``provider`` can be stored in this table at all."""
    return provider.strip().lower() in WRITABLE_PROVIDERS


async def save_api_key(
    pg_request: PostgresRequest,
    *,
    profile_id: str,
    provider: str,
    api_key: str,
    base_url: str = "",
) -> bool:
    """Store one member's provider key, SEALED. Returns whether it was written.

    ⚠️ THE FIRST WRITER THIS TABLE HAS. Until now rows were provisioned out of
    band, and the consequence was that the provider an operator chose during
    onboarding went into a different store from the one the runtime reads — so
    the choice was recorded, displayed, and never executed.

    Sealed here rather than by the caller, so there is one place that decides
    what at-rest looks like and no path that can write the key in the clear by
    forgetting to. The value is never logged: a failure names the profile and
    the provider, never the credential.

    Refuses a provider the CHECK constraint would reject rather than sending an
    INSERT that fails at the database, because that failure is reported as a
    generic write error and reads like an outage instead of a vocabulary
    mismatch.
    """
    name = provider.strip().lower()
    if not profile_id or not name or not api_key:
        return False
    if not writable(name):
        print(
            f"[api_key_store] refusing to store a key for provider {name!r}: the table accepts "
            f"only {', '.join(sorted(WRITABLE_PROVIDERS))}. The key was NOT saved."
        )
        return False

    sealed = secret_sealing.seal(api_key, subject=_subject(profile_id, name))
    body = {
        "profile_id": profile_id,
        "provider": name,
        "api_key_encrypted": sealed,
        "base_url": base_url or None,
    }
    existing = await pg_request(
        "GET", TABLE, params={"profile_id": f"eq.{profile_id}", "provider": f"eq.{name}", "select": "profile_id"}
    )
    if existing:
        await pg_request(
            "PATCH", TABLE, params={"profile_id": f"eq.{profile_id}", "provider": f"eq.{name}"}, body=body
        )
    else:
        await pg_request("POST", TABLE, body=body)
    return True
