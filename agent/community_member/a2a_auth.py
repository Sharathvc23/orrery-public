"""Who may call which A2A method, and how a caller proves who they are.

⚠️ THIS SURFACE USED TO AUTHENTICATE NOBODY. ``("POST", "/")`` was declared open
in ``local_auth.OPEN_ROUTES`` and its own recorded reason said the endpoint
"performs no caller authentication of its own". An unauthenticated JSON-RPC POST
was accepted and answered — verified against a running agent, not inferred.

THE LINE IS DRAWN BY METHOD, NOT BY ROUTE, because the route carries both kinds
of traffic. A read of a task whose id you already hold discloses little and is
part of a legitimate peer's polling flow. **A send creates work on someone
else's agent, and once a provider key is configured it spends their money.**
That is the line, and it is the only one that matters here.

⚠️ ``tasks/get`` AND ``tasks/resubscribe`` STAY OPEN, AND THAT IS A DECISION,
NOT AN OVERSIGHT. They take a caller-supplied task id, so leaving them open
accepts that anyone holding an id can read that task — including the
``creatorDidKey`` recorded on it, which an open read discloses. Task ids are
unguessable and gating reads would break a peer polling a task it was
legitimately told about. Do not "fix" this without replacing the polling flow it
serves.

This paragraph named ``tasks/cancel`` among them until the ruling below moved
cancel to caller-required, and it is left visible rather than silently swapped
because the same stale sentence had been copied into the refusal message and
into the served agent card, where it told strangers cancel was open while the
gate refused them. ``METHOD_ACCESS`` below is the only statement of this that
anything should read.

WHAT A VERIFIED CALLER IS, STATED PRECISELY so nothing downstream assumes more:
the caller signs ``{body}:{agent_id}:{timestamp}`` with Ed25519 and supplies the
public key to check it against. That proves **possession of the key they claim**
— an attributable, stable identity. It does NOT prove the identity is known to
us, trusted by us, or authorised for anything: this runtime holds no registry of
peer keys to check one against. It converts anonymous work into attributable
work, which is what the ruling asked for; it is not an allowlist and must not be
described as one.

Freshness, not replay-proofing: a timestamp window bounds how long a captured
request stays usable, matching the org protocol's v0.2 scheme, which is also
method-unbound. A nonce store would close replay inside the window and is new
durable state — deliberately not added here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

__all__ = [
    "AUTHENTICATED_METHODS",
    "CallerIdentity",
    "MAX_CLOCK_SKEW_S",
    "METHOD_ACCESS",
    "OPEN_METHODS",
    "Access",
    "requires_caller",
    "verify_caller",
]


class Access:
    """The two access classes. A string enum would invite a third by typo."""

    OPEN = "open"
    CALLER_REQUIRED = "caller-required"


#: ⚠️ THE ONE DECLARATION. Both sets below are derived from it, so a method
#: cannot be added to one and forgotten in the other — and an UNLISTED method
#: is caller-required, not open, because a route defaulting to open is the exact
#: failure this module exists to close. ``tests/test_a2a_surface_auth.py``
#: asserts every dispatchable method appears here, so "unlisted" is a bug the
#: suite reports rather than a silent default anyone relies on.
METHOD_ACCESS: dict[str, str] = {
    # Reads. Open — see the module docstring for why this is a decision.
    "tasks/get": Access.OPEN,
    "tasks/resubscribe": Access.OPEN,
    # ⚠️ CANCEL WAS OPEN AND THAT WAS WRONG. It was grouped with the reads
    # because both "take an id you already know", but that is the wrong axis.
    # Cancel is DESTRUCTIVE, and unlike a read it leaves NO ATTRIBUTION — with
    # no signature there is nothing to trace afterwards. Reading a task you were
    # told about and destroying it are not the same act.
    # Do not "restore consistency" by moving it back next to the reads.
    "tasks/cancel": Access.CALLER_REQUIRED,
    # Work-creating. A send runs the agent's tools and spends the owner's
    # provider credit.
    "tasks/send": Access.CALLER_REQUIRED,
    "tasks/sendSubscribe": Access.CALLER_REQUIRED,
    # Co-signing binds this agent's key to someone else's receipt. That is an
    # assertion in the owner's name and belongs on the same side of the line.
    "nanda/cosignReceipt": Access.CALLER_REQUIRED,
    # ⚠️ A COUNT IS NOT A READ IN THE SENSE THE OPEN READS ARE. ``tasks/get`` is
    # open because it takes an id the caller already holds and discloses only
    # that one task. This method takes NO id and answers "how many tasks does
    # this agent hold" — an inventory size for anyone who asks, and across the
    # fleet a map of where the work is. It returns no task ids and never will,
    # but "how many" is still more than a caller who was told about one task
    # was ever given. It is caller-required.
    "nanda/legacyTaskCensus": Access.CALLER_REQUIRED,
}

OPEN_METHODS = frozenset(m for m, access in METHOD_ACCESS.items() if access == Access.OPEN)
AUTHENTICATED_METHODS = frozenset(m for m, access in METHOD_ACCESS.items() if access == Access.CALLER_REQUIRED)

#: How far a caller's clock may be from ours before the request is stale.
MAX_CLOCK_SKEW_S = 300


def requires_caller(method: object) -> bool:
    """Whether ``method`` may only be invoked by a verified caller.

    Unknown methods answer True. An unrecognised name reaching here means the
    dispatch grew a method nobody classified, and refusing it is recoverable —
    serving it is the defect that produced this module.
    """
    if not isinstance(method, str):
        return True
    return METHOD_ACCESS.get(method, Access.CALLER_REQUIRED) == Access.CALLER_REQUIRED


@dataclass(frozen=True)
class CallerIdentity:
    """A caller who proved possession of the key they present. Nothing more."""

    agent_id: str
    did_key: str = ""


def _public_key_from_headers(headers: dict[str, str]) -> str:
    """The caller's Ed25519 public key, base64, from whichever header carries it."""
    lower = {k.lower(): v for k, v in headers.items()}
    direct = (lower.get("x-agent-public-key") or "").strip()
    if direct:
        return direct
    did = (lower.get("x-agent-did-key") or "").strip()
    if not did:
        return ""
    # did:key:z<base58btc(0xed01 || pubkey)> — reverse the derivation rather
    # than trusting a second, separately-supplied copy of the same key.
    try:
        import base64

        import base58

        decoded = base58.b58decode(did.removeprefix("did:key:").lstrip("z"))
        if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
            return ""
        return base64.b64encode(decoded[2:]).decode()
    except Exception:
        return ""


def verify_caller(headers: dict[str, str], body: str, *, now: float | None = None) -> CallerIdentity | None:
    """The caller this request proves, or None.

    ``body`` must be the RAW request body the signature was computed over —
    re-serialising a parsed dict produces different bytes and a signature that
    cannot verify.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    agent_id = (lower.get("x-agent-id") or "").strip()
    signature = (lower.get("x-agent-signature") or "").strip()
    timestamp = (lower.get("x-agent-timestamp") or "").strip()
    if not (agent_id and signature and timestamp):
        return None

    scheme = (lower.get("x-agent-sig-scheme") or "ed25519").strip().lower()
    if scheme != "ed25519":
        # HMAC verification needs the shared secret, which this runtime does not
        # hold for a peer. Refusing is honest; pretending would accept anything.
        return None

    try:
        sent_at = int(timestamp)
    except ValueError:
        return None
    if abs((time.time() if now is None else now) - sent_at) > MAX_CLOCK_SKEW_S:
        return None

    public_key = _public_key_from_headers(headers)
    if not public_key:
        return None

    from .crypto import ed25519_available

    if not ed25519_available():
        return None

    import base64

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    message = f"{body}:{agent_id}:{timestamp}"
    try:
        VerifyKey(base64.b64decode(public_key)).verify(message.encode(), base64.b64decode(signature))
    except (BadSignatureError, ValueError, TypeError):
        return None

    return CallerIdentity(agent_id=agent_id, did_key=(lower.get("x-agent-did-key") or "").strip())
