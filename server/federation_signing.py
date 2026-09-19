"""Server-to-server (chapter↔chapter) signing for federation broadcasts.

The federation broadcast inbox trusted a plaintext ``X-Chapter-Origin`` header
and a no-op outbound signer, so any allowlisted-or-spoofed peer could fabricate
broadcasts under another chapter's name. This module adds real Ed25519 signing.

**Trust model (B).** The receiver discovers the *sending* peer's Ed25519 public
key from the peer's published ``/.well-known/did.json``, anchored to the
operator-added federation **allowlist endpoint** (the peer must already be in the
local federation registry with an endpoint). No manual key-registration UI; the
trust anchor is the allowlist entry the operator created out-of-band, and the key
is the one the chapter already publishes.

**Cutover: COMPLETE — default ON since 2026-07-20.** Outbound broadcasts are
always signed; inbound signatures are always verified and failures are always
logged. A failed/absent signature *rejects* the broadcast unless
``FEDERATION_ENFORCE_SIGNED_BROADCASTS`` is explicitly set to a falsey value.

This defaulted OFF during the warn-then-enforce window, so that shipping the fix
did not break un-upgraded peers. That window closed on 2026-07-20 when the live
mesh cut over. The default stayed OFF for ten days afterwards, which meant any
deployment that did not set the variable ran with no enforcement at all while
``.env.example`` said ``true`` — a security default that failed OPEN and read as
a decision nobody made (C9, AUDIT_HARSH.md). Flipping it is a no-op for the live
mesh, which sets the variable explicitly, and protects fresh deploys that don't.

**Replay protection.** The signature covers a timestamp + nonce as well
as the body, and the receiver rejects a broadcast whose signed timestamp is
outside a freshness window (``FEDERATION_BROADCAST_MAX_AGE_S``, default 300s).
This survives a receiver restart — unlike the in-memory dedup ring — so a
captured valid broadcast can't be replayed later. Because the timestamp is
signed, an attacker can't refresh it. A older peer that signs the body only
still verifies (``ok_legacy``) but gains no replay protection until it upgrades.

**Signed bodyless reads.** The same scheme authorizes a peer's GET of a
route that is no longer public — today the member directory. ``sign_request`` /
``verify_peer_request`` sign a canonical descriptor of the request line instead
of a body. That leg is fail-closed and always requires the signed timestamp: it
is an authorization decision, not the broadcast cutover's advisory warn mode.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any

import jcs

import env_flags
import sovereign_identity

CHAPTER_DID_HEADER = "X-Chapter-DID"
CHAPTER_SIG_HEADER = "X-Chapter-Signature"
# The sending peer declares its chapter_id here (the broadcast inbox has always
# used this header); the signature is what actually proves the claim.
CHAPTER_ORIGIN_HEADER = "X-Chapter-Origin"
# a signed timestamp + nonce give replay protection that survives a
# receiver restart (the in-memory dedup ring does not). Both are part of the
# signed material, so an attacker can't refresh a stale captured broadcast.
CHAPTER_TS_HEADER = "X-Chapter-Timestamp"
CHAPTER_NONCE_HEADER = "X-Chapter-Nonce"

DEFAULT_BROADCAST_MAX_AGE_S = 300.0

# An injectable async GET: url -> parsed-JSON dict | None. Default fetches the
# peer's did.json over HTTP; tests inject a fake.
HttpGet = Callable[[str], Awaitable[dict[str, Any] | None]]


def enforcement_enabled() -> bool:
    """Whether a bad/absent S2S signature should REJECT the broadcast (fail-closed).

    Default **ON** since the cutover completed (2026-07-20). It defaulted OFF for
    the warn-then-enforce window; that window is closed, and leaving the code
    default permissive meant a deployment that simply never set the variable ran
    with no signed-federation enforcement while ``.env.example`` advertised
    ``true`` (C9). Unset, empty and unrecognised all read as enforcing — see
    ``env_flags.security_flag``. An operator re-opens the warn-only window by
    setting an explicit falsey value.
    """
    return env_flags.security_flag("FEDERATION_ENFORCE_SIGNED_BROADCASTS", default=True)


def _canonical(body: dict[str, Any]) -> str:
    """JCS (RFC 8785) canonical JSON of the body — deterministic across the wire
    so signer and verifier compute byte-identical bytes regardless of key order
    or serializer."""
    return jcs.canonicalize(body).decode("utf-8")


def _signed_material(body: dict[str, Any], ts: str, nonce: str) -> str:
    """The exact bytes signed/verified: timestamp + nonce + canonical body.
    Binding ts/nonce into the signature means a captured broadcast can't be
    made fresh by editing the timestamp header."""
    return f"{ts}\n{nonce}\n{_canonical(body)}"


def _max_age_s() -> float:
    """Freshness window for an inbound broadcast's signed timestamp (seconds).
    Overridable via FEDERATION_BROADCAST_MAX_AGE_S."""
    raw = os.environ.get("FEDERATION_BROADCAST_MAX_AGE_S", "").strip()
    if not raw:
        return DEFAULT_BROADCAST_MAX_AGE_S
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_BROADCAST_MAX_AGE_S


class OutboundUnsigned(RuntimeError):
    """This chapter was asked to sign outbound federation traffic and cannot.

    H4: ``sign_outbound``/``sign_request`` used to return ``{}`` here, and the
    caller sent the request anyway. That is a fail-OPEN on the emit path, and it
    is invisible from our side: OUR logs look clean and the failure surfaces as a
    rejection on the PEER's box, if the peer enforces at all. A first-boot or
    misconfigured deployment would emit every federation message unsigned and
    nothing local would say so.

    Refusing costs us nothing — an unsigned federation message is worthless to
    us, since the receiving side's enforcement is the only thing that would have
    given it weight. So the emit path fails closed. That is a different decision
    from what we ACCEPT (H9), where refusing costs a legitimate peer its
    membership; outbound and inbound are separate questions and get separate
    directions.
    """


def sign_outbound(
    chapter_id: str,
    body: dict[str, Any],
    *,
    now: float | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Signature headers for an outbound broadcast body.

    RAISES :class:`OutboundUnsigned` if this chapter has no Ed25519 keypair —
    it never returns ``{}`` so a caller cannot accidentally send unsigned (H4).

    The signature covers a timestamp + nonce as well as the body, so the
    receiver can reject stale replays. ``now``/``nonce`` are injectable for
    deterministic tests."""
    kp = sovereign_identity._ed25519_keypairs.get(chapter_id)
    if not kp:
        raise OutboundUnsigned(
            f"refusing to emit unsigned federation traffic: chapter {chapter_id!r} has no "
            f"Ed25519 keypair loaded. ensure_chapter_keypair() must complete before any "
            f"federation operation (see H6)."
        )
    sk_b64 = base64.b64encode(kp["private_key"]).decode()
    pk_b64 = base64.b64encode(kp["public_key"]).decode()
    ts = str(int(now if now is not None else time.time()))
    nonce = nonce or secrets.token_hex(16)
    sig = sovereign_identity.ed25519_sign(_signed_material(body, ts, nonce), sk_b64)
    return {
        CHAPTER_DID_HEADER: sovereign_identity.build_did_key_from_ed25519(pk_b64),
        CHAPTER_SIG_HEADER: sig,
        CHAPTER_TS_HEADER: ts,
        CHAPTER_NONCE_HEADER: nonce,
    }


def request_descriptor(method: str, url_path: str, origin: str) -> dict[str, str]:
    """The canonical stand-in body for a *bodyless* S2S request.

    A signed GET has no body to sign, so both sides build this descriptor from
    the request line and sign/verify it with the same machinery as a broadcast
    body. Binding method + url_path means a captured signature cannot be moved
    to another route or method; binding the origin means it cannot be replayed
    under another chapter's name.
    """
    return {"method": method.upper(), "path": url_path, "origin": origin}


def sign_request(chapter_id: str, method: str, url_path: str) -> dict[str, str]:
    """Signature headers for an outbound bodyless S2S request.

    RAISES :class:`OutboundUnsigned` when this chapter has no Ed25519 keypair,
    for the reason on that class: sending unsigned and letting the receiver
    decide is a failure we cannot see (H4).
    """
    headers = sign_outbound(chapter_id, request_descriptor(method, url_path, chapter_id))
    return {**headers, CHAPTER_ORIGIN_HEADER: chapter_id}


async def verify_peer_request(
    method: str,
    url_path: str,
    headers: dict[str, str],
    federation: dict[str, Any],
    http_get: HttpGet | None = None,
    *,
    now: float | None = None,
) -> tuple[bool, str, str]:
    """Authorize an inbound bodyless S2S request from a federation peer.

    Returns ``(authorized, sender, reason)``. Unlike the broadcast inbox this is
    an *authorization* decision, not a warn-then-enforce advisory: it is always
    fail-closed, and it always demands replay protection (a signed timestamp),
    because the only peers that sign a request at all are already running this
    code. Freshness (``FEDERATION_BROADCAST_MAX_AGE_S``, default 300s) bounds
    replay; re-playing a peer's own signed read within that window discloses
    nothing the peer was not already authorized to read.

    The sender is taken from ``X-Chapter-Origin`` but proven by the signature —
    the claimed origin must be in our federation registry, and the verification
    key comes from that peer's pin/attested DID (or, absent a pin, its did.json
    at the operator-anchored allowlist endpoint).
    """
    sender = headers.get(CHAPTER_ORIGIN_HEADER) or headers.get(CHAPTER_ORIGIN_HEADER.lower(), "")
    if not sender:
        return False, "", "missing_origin"
    sig = headers.get(CHAPTER_SIG_HEADER) or headers.get(CHAPTER_SIG_HEADER.lower(), "")
    if not sig:
        return False, sender, "missing_signature"
    entry = (federation or {}).get(sender)
    if not entry:
        return False, sender, "unknown_peer"
    pinned_did, pin_lookup_failed = await pinned_did_for(sender, entry)
    if pin_lookup_failed:
        # F5, same rule as the broadcast inbox: we could not determine whether a
        # pin exists, so we must not silently downgrade to endpoint trust.
        return False, sender, "pin_lookup_failed"
    valid, reason = await verify_inbound(
        request_descriptor(method, url_path, sender),
        headers,
        str(entry.get("endpoint") or ""),
        http_get,
        now=now,
        require_replay_protection=True,
        pinned_did=pinned_did,
    )
    return valid, sender, reason


async def _default_get(url: str) -> dict[str, Any] | None:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        return resp.json() if resp.status_code == 200 else None
    except Exception:  # noqa: BLE001 — a peer we can't reach is just "unverifiable"
        return None


async def pinned_did_for(sender: str, federation_entry: dict[str, Any] | None) -> tuple[str | None, bool]:
    """Resolve the sender's did:key for signature verification.

    Returns ``(did, lookup_failed)``:

    - ``did`` — the PERSISTENT pin (federation_policy.pinned_did — TOFU, survives
      restarts) when present, else the in-memory attested DID from the current
      discovery cycle, else None (the legacy did.json fetch path).
    - ``lookup_failed`` — True ONLY when the persistent-pin DB read RAISED, i.e.
      we could not determine whether a pin exists. A missing pin / pre-migration
      schema is NOT a failure (returns False); only an actual read error is.

    Why the second value exists (F5): on a DB error the old code swallowed the
    exception and returned None, which ``verify_inbound`` treats as "no pin →
    verify against the endpoint's did.json". That silently downgrades a pinned
    peer to endpoint trust — precisely the circular-trust hole the pin closes,
    and inducible by anyone who can make the DB read fail. The caller MUST treat
    ``lookup_failed`` as unverifiable under enforcement (fail closed) rather than
    fall back. Never raises — the uncertainty is signalled, not thrown."""
    lookup_failed = False
    try:
        import federation_policy

        row = await federation_policy.get_peer_policy(sender)
        pin = (row or {}).get("pinned_did")
        if pin:
            return str(pin), False
    except Exception:
        lookup_failed = True
    did = (federation_entry or {}).get("did")
    return (str(did) if did else None), lookup_failed


async def fetch_peer_pubkey(endpoint: str, http_get: HttpGet | None = None) -> str | None:
    """The peer's Ed25519 public key (base64) from ``{endpoint}/.well-known/did.json``,
    or None if unreachable / no key. The endpoint comes from the federation
    allowlist (operator-anchored)."""
    if not endpoint:
        return None
    url = endpoint.rstrip("/") + "/.well-known/did.json"
    doc = await (http_get or _default_get)(url)
    if not isinstance(doc, dict):
        return None
    for vm in doc.get("verificationMethod") or []:
        if not isinstance(vm, dict):
            continue
        # prefer the W3C publicKeyMultibase (what standard tooling and
        # upgraded peers serve); the multicodec parser rejects junk. Legacy
        # publicKeyBase64 stays readable one transition window (drop at 1.0).
        mb = vm.get("publicKeyMultibase")
        if isinstance(mb, str) and mb.startswith("z"):
            import sovereign_identity

            pk = sovereign_identity.extract_ed25519_pubkey_from_did_key(f"did:key:{mb}")
            if pk:
                return pk
        if vm.get("publicKeyBase64"):
            return str(vm["publicKeyBase64"])
    return None


async def verify_inbound(
    body: dict[str, Any],
    headers: dict[str, str],
    peer_endpoint: str,
    http_get: HttpGet | None = None,
    *,
    now: float | None = None,
    max_age_s: float | None = None,
    require_replay_protection: bool = False,
    pinned_did: str | None = None,
) -> tuple[bool, str]:
    """Verify a broadcast's S2S signature against the peer's published key.

    Returns ``(valid, reason)``. Reasons: ``ok``, ``ok_pinned``, ``ok_legacy``,
    ``ok_legacy_pinned``, ``missing_signature``, ``peer_key_unavailable``,
    ``pinned_did_invalid``, ``invalid_signature``, ``invalid_timestamp``,
    ``stale_timestamp``, ``missing_timestamp``. Never raises — an unverifiable
    peer is a ``False`` result the caller logs (and rejects only under
    enforcement).

    **Key source.** When ``pinned_did`` is given (the peer's TOFU-pinned or
    attested did:key), the verification key is derived FROM THE DID ITSELF —
    no network fetch, no trust in the endpoint. This closes the circular hole
    where a cheating registry supplies both the endpoint and, via that
    endpoint's did.json, the key the signature is checked against. A pin is
    authoritative: if it doesn't decode, verification fails
    (``pinned_did_invalid``) rather than falling back to the endpoint's
    did.json — falling back would let an attacker escape the pin by breaking
    it. Without a pin, the legacy did.json fetch anchored to the operator
    allowlist endpoint still applies.

    When the peer sends a timestamp, the signature is verified over
    timestamp+nonce+body and rejected if the timestamp is outside the freshness
    window — this rejects a captured broadcast replayed after a receiver restart
    once the window passes.

    ``require_replay_protection`` (set it to the enforcement flag) governs the
    legacy path: a older peer that signs the body only (no timestamp) has NO
    replay protection. Under enforcement that is unacceptable — the captured
    bytes would replay forever — so we reject it (``missing_timestamp``). Under
    warn-mode (default) it still verifies as ``ok_legacy`` so honest un-upgraded
    peers aren't broken during the cutover.
    """
    sig = headers.get(CHAPTER_SIG_HEADER) or headers.get(CHAPTER_SIG_HEADER.lower(), "")
    if not sig:
        return False, "missing_signature"
    if pinned_did:
        pubkey = sovereign_identity.extract_ed25519_pubkey_from_did_key(pinned_did)
        if not pubkey:
            return False, "pinned_did_invalid"
        ok_suffix = "_pinned"
    else:
        pubkey = await fetch_peer_pubkey(peer_endpoint, http_get)
        if not pubkey:
            return False, "peer_key_unavailable"
        ok_suffix = ""

    ts = headers.get(CHAPTER_TS_HEADER) or headers.get(CHAPTER_TS_HEADER.lower(), "")
    nonce = headers.get(CHAPTER_NONCE_HEADER) or headers.get(CHAPTER_NONCE_HEADER.lower(), "")
    if ts:
        try:
            ts_int = int(ts)
        except (ValueError, TypeError):
            return False, "invalid_timestamp"
        current = now if now is not None else time.time()
        window = max_age_s if max_age_s is not None else _max_age_s()
        if abs(current - ts_int) > window:
            return False, "stale_timestamp"
        if sovereign_identity.ed25519_verify(_signed_material(body, ts, nonce), sig, pubkey):
            return True, "ok" + ok_suffix
        return False, "invalid_signature"

    # Legacy peer (older): body-only signature, no replay protection. Under
    # enforcement this is unacceptable — without a signed timestamp the bytes
    # replay forever — so reject it rather than accept an unprotected broadcast.
    if require_replay_protection:
        return False, "missing_timestamp"
    if sovereign_identity.ed25519_verify(_canonical(body), sig, pubkey):
        return True, "ok_legacy" + ok_suffix
    return False, "invalid_signature"
