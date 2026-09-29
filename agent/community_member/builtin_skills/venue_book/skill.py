"""Book a table at a real venue, over A2A, with the other side present.

Why this exists beside ``booking``
----------------------------------
``builtin_skills/booking`` writes a booking to the agent's own store and signs a
receipt for it. Nothing is asked and nothing can refuse: there was no other
side. This skill talks to one — a venue that holds its own calendar, enforces
its own rules, and signs its own receipt — so a booking here is an agreement
between two parties rather than a note an agent wrote to itself.

The agent still signs its own ``appointment_booked`` receipt when the booking
confirms. That is deliberate and it is the point: **two independent signatures
over the same slot**, folded identically on both sides, so a verifier can pair
them without trusting either party's account of which booking it was.

Who the venue thinks is calling
-------------------------------
The venue distinguishes a caller that merely holds a shared secret from one that
is an index-resolvable identity, and says which in every response. This skill sends
**one** credential per request — the signature when the agent has a key, a token
otherwise — and **reports the venue's own assessment back verbatim** rather than
claiming an identity on the agent's behalf.

Sending both does not work, which had to be measured rather than assumed:
``CallerCheck.identify`` takes the signature branch whenever any signature header
is present and then fails closed if the key does not resolve in the index, so a
token sent alongside is never read. When a signed attempt is refused for exactly
that reason and a token exists, the skill retries with the token and marks the
result ``fell_back_to_token`` — because booking as an anonymous secret-holder is
a weaker claim than booking as an identified key, and a result that hid which one
happened would destroy the distinction the venue exists to preserve.

What a confirmed booking here establishes, and what it does not
--------------------------------------------------------------
That this agent asked, that the venue recorded a hold against a named slot, that
every principal the booking names consented, and that both sides signed. Not
that a table physically exists, not that anyone will arrive, and not that the
venue is who its card says it is — that is the index's job and the card's, not
this skill's.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CATEGORY_BOOKED = "appointment_booked"
DEFAULT_TIMEOUT = 20.0

#: The venue's JSON-RPC error code for "you need a credential". Recognised so a
#: refusal for want of authorisation is reported as that, and not as the venue
#: being broken — a caller that cannot tell them apart retries the wrong one.
UNAUTHORISED = -32004


def _venue_url(explicit: str | None = None) -> str:
    """Where the venue is.

    Explicit argument first, then ``VENUE_URL``. No default: an agent that
    silently books against a venue nobody chose is worse than one that says it
    does not know where to book.
    """
    url = (explicit or os.environ.get("VENUE_URL", "")).strip().rstrip("/")
    if not url:
        raise ValueError(
            "no venue: pass venue_url, or set VENUE_URL. Discovery through the "
            "index is the intended route once the venue is registered there."
        )
    return url


def _home() -> Path | None:
    raw = os.environ.get("COMMUNITY_MEMBER_HOME", "").strip()
    return Path(raw) if raw else None


def _credentials() -> tuple[str | None, str | None, str | None, str | None]:
    """``(agent_id, private_key, public_key, token)`` — whatever this agent has.

    All four may be absent. A keyless agent with no token can still read
    availability, which the venue leaves open, and will be refused a write —
    correctly, and with a reason it can report.
    """
    token = os.environ.get("VENUE_TOKEN", "").strip() or None
    try:
        from community_member import keystore
        from community_member.config import Config

        cfg = Config.load(home=_home())
        if not cfg.agent_id:
            return None, None, None, token
        private = keystore.load_private_key(cfg.agent_id, dir=cfg._home) or None
        return cfg.agent_id, private, cfg.public_key or None, token
    except Exception:
        # A credential this skill cannot assemble is a credential it does not
        # send. It is never a reason to fail the call: the venue decides.
        return None, None, None, token


def _rpc(venue_url: str, intent: dict[str, Any], *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """One A2A ``message/send`` carrying an intent, with whatever credential we hold.

    Returns the venue's parsed answer, or a dict carrying ``refused`` — never
    raising for a refusal. A refusal is the venue's answer and belongs in the
    result the LLM reads, not in a traceback.
    """
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": f"venue-book-{abs(hash(json.dumps(intent, sort_keys=True))) % 10**10}",
                    "parts": [{"kind": "text", "text": json.dumps(intent, sort_keys=True)}],
                }
            },
        },
        sort_keys=True,
    )

    agent_id, private_key, public_key, token = _credentials()

    unsignable: str | None = None

    def attempt(signed: bool) -> dict[str, Any]:
        nonlocal unsignable
        headers = {"Content-Type": "application/json"}
        if signed and agent_id and private_key:
            from community_member.a2a_client_v2 import _signed_headers

            try:
                headers = _signed_headers(body, agent_id, private_key, public_key)
            except Exception as exc:
                # A key this agent cannot sign with is a misconfiguration, not a
                # reason to take the whole call down. Recorded and reported, so
                # it cannot look like the venue's fault.
                unsignable = f"{type(exc).__name__}: {exc}"[:160]
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
        elif token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(venue_url + "/", data=body.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                envelope = json.loads(response.read(1_000_000).decode())
        except urllib.error.HTTPError as exc:
            return {"refused": True, "reason": f"HTTP {exc.code}", "detail": exc.read(400).decode(errors="replace")}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return {"refused": True, "reason": f"{type(exc).__name__}", "detail": str(exc)[:200]}

        if "error" in envelope:
            error = envelope["error"] or {}
            return {
                "refused": True,
                "reason": "needs a credential" if error.get("code") == UNAUTHORISED else "venue refused",
                "code": error.get("code"),
                "detail": str(error.get("message"))[:300],
            }

        try:
            text = envelope["result"]["artifacts"][0]["parts"][0]["text"]
            return json.loads(text)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            return {"refused": True, "reason": "unreadable answer", "detail": f"{type(exc).__name__}: {exc}"[:200]}

    # ONE credential per request, and the signature first when we have a key.
    #
    # Measured, after a comment here claimed otherwise: the venue does NOT pick
    # the stronger of two credentials. `CallerCheck.identify` takes the
    # signature branch whenever ANY signature header is present, and then fails
    # closed if the key does not resolve in the index — so sending a token
    # alongside a signature does not help, it just never gets read.
    answer = attempt(signed=True)
    if unsignable and not answer.get("refused"):
        answer = {
            **answer,
            "signing_failed": unsignable,
            "identity_not_used": "this agent could not sign with its configured key",
        }
    unregistered = (
        answer.get("refused")
        and answer.get("code") == UNAUTHORISED
        and "no index record resolves" in str(answer.get("detail", ""))
    )
    if unregistered and token:
        # Fall back, and SAY SO. Booking as an anonymous token-holder is a
        # weaker claim than booking as an identified key, and a result that hid
        # which one happened would make the two indistinguishable afterwards —
        # which is the distinction the venue exists to preserve.
        answer = attempt(signed=False)
        if not answer.get("refused"):
            answer = {
                **answer,
                "fell_back_to_token": True,
                "identity_not_used": "this agent's key does not resolve in the index the venue checks",
            }
    return answer


def _slot_ref(resource: str, start: str) -> str:
    """The slot, folded EXACTLY the way the venue folds it.

    ``sha256(f"{resource}\\x00{start}")`` — byte-for-byte the venue's
    ``calendar.slot_ref``, NUL separator included.

    This must match or the whole two-signature design is decorative. Measured,
    after getting it wrong: the first version copied the local ``booking``
    skill's ``provider@datetime`` fold, so the agent signed
    ``lunch-table-4@2026-12-20T12:30:00Z`` while the venue signed
    ``73cc32ff…``. Both receipts verified, both described the same booking, and
    nothing could pair them — which is precisely the failure a verifier could
    not detect from either receipt alone.

    A test pins the two implementations together; the venue's fold is the one
    that moves only with the venue.
    """
    import hashlib

    return hashlib.sha256(f"{resource}\x00{start}".encode()).hexdigest()


def _emit_receipt(resource: str, start: str, principals: list[str], venue_did: str | None) -> dict[str, Any]:
    """The agent's own signature over a booking the venue has confirmed.

    Returns ``{"receipt_id": …}`` or ``{"unsigned": reason}``. A keyless agent
    is a valid agent: it books, and it says plainly that it could not sign.
    """
    import base64

    from community_member import arp, keystore
    from community_member.config import Config

    cfg = Config.load(home=_home())
    if not cfg.agent_id:
        return {"unsigned": "no agent identity"}
    private = keystore.load_private_key(cfg.agent_id, dir=cfg._home)
    if not private:
        return {"unsigned": "no signing key for this identity"}
    try:
        seed = base64.b64decode(private)
    except (ValueError, TypeError):
        return {"unsigned": "signing key is not valid base64"}
    if len(seed) != 32:
        return {"unsigned": "signing key is not a 32-byte Ed25519 seed"}

    summary = f"Booked {resource} at {start} for {len(principals)} principal(s)."
    receipt = arp.emit(
        action={
            "category": CATEGORY_BOOKED,
            "human_summary": summary[:280],
            "outcome": "completed",
            "machine_payload": {
                "slot_ref": _slot_ref(resource, start),
                "resource": resource,
                "start": start,
                "principals": list(principals),
                "counterparty_did": venue_did,
            },
        },
        sk_bytes=seed,
        agency_log=arp.AgencyLog(cfg.home),
        chapter_url=cfg.chapter_url or None,
        push=bool(cfg.chapter_url),
    )
    return {"receipt_id": receipt.get("receipt_id")}


# ── the tools ───────────────────────────────────────────────────────────────


def check_availability(resource: str, times: list[str] | str, venue_url: str | None = None) -> str:
    """Which of the proposed times are open. A read; no credential needed."""
    proposed = [times] if isinstance(times, str) else list(times or [])
    if not proposed:
        return json.dumps({"error": "give one or more times"})
    answer = _rpc(_venue_url(venue_url), {"skill": "venue.availability", "resource": resource, "start": proposed})
    return json.dumps(answer, sort_keys=True)


def hold_table(
    resource: str,
    start: str,
    principals: list[str] | str,
    party: str | None = None,
    venue_url: str | None = None,
) -> str:
    """Take a slot pending agreement from every principal the booking names.

    Re-sending an identical request returns the same hold, so a retry after a
    dropped answer cannot become a second booking. The result carries the
    venue's assessment of who called, which may be ``caller_authenticated:
    false``; that is a real fact about the booking, not a warning to ignore.
    """
    named = [principals] if isinstance(principals, str) else list(principals or [])
    if not named:
        return json.dumps({"error": "a booking must name at least one principal"})
    answer = _rpc(
        _venue_url(venue_url),
        {
            "skill": "venue.hold",
            "resource": resource,
            "start": start,
            "party": party or named[0],
            "principals": named,
        },
    )
    return json.dumps(answer, sort_keys=True)


def agree(hold_id: str, principal: str, venue_url: str | None = None) -> str:
    """Record one principal's agreement; the venue confirms once all have.

    When the venue reports ``confirmed``, this agent signs its own receipt over
    the same slot — so the booking ends with two independent signatures rather
    than one party's word.
    """
    url = _venue_url(venue_url)
    answer = _rpc(url, {"skill": "venue.consent", "hold_id": hold_id, "principal": principal})
    if answer.get("state") != "confirmed":
        return json.dumps(answer, sort_keys=True)

    venue_did = None
    try:
        with urllib.request.urlopen(url + "/.well-known/agent-card.json", timeout=DEFAULT_TIMEOUT) as response:
            venue_did = (json.loads(response.read(200_000).decode()).get("x-nanda") or {}).get("did")
    except Exception:
        # The counterparty's did is evidence, not a precondition. A booking that
        # confirmed still confirmed if the card could not be re-read.
        venue_did = None

    return json.dumps(
        {
            **answer,
            "our_receipt": _emit_receipt(
                answer.get("resource", ""), answer.get("start", ""), answer.get("principals") or [], venue_did
            ),
        },
        sort_keys=True,
    )


TOOLS = [
    {
        "name": "check_availability",
        "description": (
            "Ask a venue which of several proposed times are open for a table. A read — no credential needed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "resource": {"type": "string", "description": "Which table, e.g. 'table-7'."},
                "times": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Candidate slot starts, ISO-8601 UTC.",
                },
                "venue_url": {"type": "string", "description": "The venue's base URL. Defaults to VENUE_URL."},
            },
            "required": ["resource", "times"],
        },
        "fn": check_availability,
    },
    {
        "name": "hold_table",
        "description": (
            "Take a slot at a venue, pending agreement from every principal the booking names. "
            "Re-sending the same request returns the same hold rather than a second booking."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "resource": {"type": "string", "description": "Which table."},
                "start": {"type": "string", "description": "Slot start, ISO-8601 UTC."},
                "principals": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The did:key of everyone whose consent the booking needs.",
                },
                "party": {"type": "string", "description": "Who is asking. Must be among principals."},
                "venue_url": {"type": "string", "description": "The venue's base URL. Defaults to VENUE_URL."},
            },
            "required": ["resource", "start", "principals"],
        },
        "fn": hold_table,
    },
    {
        "name": "agree",
        "description": (
            "Record one principal's agreement to a held booking. The venue confirms once every principal "
            "has agreed, and this agent then signs its own receipt over the same slot."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "hold_id": {"type": "string", "description": "The hold to agree to."},
                "principal": {"type": "string", "description": "The did:key agreeing."},
                "venue_url": {"type": "string", "description": "The venue's base URL. Defaults to VENUE_URL."},
            },
            "required": ["hold_id", "principal"],
        },
        "fn": agree,
    },
]
