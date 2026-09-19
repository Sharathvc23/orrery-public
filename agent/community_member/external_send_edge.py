"""The outbox edge for outbound email — enqueue here, drain to the org.

⚠️ THIS MODULE HOLDS NO API KEY AND TALKS TO NO VENDOR. It posts to the org's
``/api/send/external``; the org holds the Klaviyo credential and runs PR1's
``send_external`` gate immediately before the transport call. That split is the
security property, not an implementation detail: an agent that skipped the ask
would have nothing to send *with*, whereas an agent holding the key could ignore
a refusal and send anyway. The gate has to sit on the side that owns the effect.

⚠️ A PENDING APPROVAL IS NOT A FAILURE, and the whole reason ``DeferEntry``
exists. Treating a 202 as an error would burn the message's backoff schedule and
eventually purge it — a message waiting on a human would be discarded precisely
because a human had not answered yet, and the queue would look empty rather than
blocked. Deferred entries stay queued, unaged, until the operator decides.
"""

from __future__ import annotations

from typing import Any

from community_member import outbox

KIND = "external_send"
ENDPOINT = "/api/send/external"


def enqueue_email(agent_id: str, *, to: str, subject: str, body: str, metric: str | None = None) -> int:
    """Queue one outbound message. Returns the outbox sequence.

    Nothing is sent here and nothing is validated beyond shape — the org is the
    single authority on whether a message may go out, and a second validator on
    this side would be a second answer to that question. Queueing is deliberately
    cheap: the decision happens at drain time, against the gate.
    """
    if not to or not subject or not body:
        raise ValueError("enqueue_email requires to, subject and body")
    payload: dict[str, Any] = {"to": to, "subject": subject, "body": body}
    if metric:
        payload["metric"] = metric
    return outbox.enqueue(agent_id, payload, kind=KIND)


def _drain_external_send(agent_id: str, entry: dict[str, Any], client: Any) -> None:
    """Hand one queued message to the org.

    Outcomes, and why each maps as it does:
      * 200 -> return. The row is deleted by the caller; the org has it now.
      * 202 -> ``DeferEntry``. Waiting on an operator, keep the message intact.
      * anything else -> raise. Normal failure, backoff applies.
    """
    resp = client._post(ENDPOINT, entry["patch"])
    status = _status_of(resp, client)

    if status == 202:
        raise outbox.DeferEntry(f"awaiting operator approval for {entry['patch'].get('to')}")
    if status is not None and status >= 400:
        raise RuntimeError(f"org refused the send: HTTP {status} {str(resp)[:200]}")
    if isinstance(resp, dict) and resp.get("status") == "pending_approval":
        # Belt and braces: a client that discards the status code must not turn a
        # pending approval into a delete. The body says so too, so read that.
        raise outbox.DeferEntry(f"awaiting operator approval for {entry['patch'].get('to')}")


def _status_of(resp: Any, client: Any) -> int | None:
    """Best-effort HTTP status for a client that may or may not expose one.

    ⚠️ Returns None when it genuinely cannot tell, and the caller then falls back
    to reading the body. Guessing 200 here would silently convert an unknown
    outcome into "delivered" and delete the row.
    """
    for source in (resp, getattr(client, "last_response", None)):
        code = getattr(source, "status_code", None)
        if isinstance(code, int):
            return code
    if isinstance(resp, dict):
        code = resp.get("status_code")
        if isinstance(code, int):
            return code
    return None


outbox.register_drain_handler(KIND, _drain_external_send)
