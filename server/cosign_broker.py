"""Chapter-brokered co-sign relay — cosign-companion.md §4 (Option C).

Reduced-tier members (e.g. an ``openclaw-skill`` client with no receiving A2A
server of their own) cannot host the inline co-sign seam of §1, so they cannot
obtain the counterparty ``evidence.witness_signatures`` entry that
``nanda-rep/0.2`` (VRP 0.3 §A) requires before a receipt builds reputation.
This module lets the chapter **broker** that exchange:

1. The issuer (A) sends its UNSIGNED receipt to the chapter.
2. The chapter resolves the counterparty (B) named in
   ``action.counterparty_did`` to a **registered member's** A2A endpoint and
   relays the receipt to B's ``nanda/cosignReceipt`` method.
3. The chapter returns B's ``{witness_did, signature}`` entry **unchanged**;
   the issuer inserts it and finalizes per §1 step 4.

The chapter is a **transport relay only**. It NEVER signs as the witness — the
returned ``witness_did`` is B's own ``did:key`` and the signature is produced by
B's key. Because Ed25519 signing is deterministic over the fixed corroboration
payload (VRP 0.3 §A.3), the entry relayed here is **byte-identical** to the one
B would produce inline; a verifier recomputes and checks it under
``counterparty_did`` exactly as in §1 and cannot — need not — tell the paths
apart. The broker adds no entropy and no authority.

**Fail-safe, like the inline path (§3).** A counterparty that is not a
registered member, has no reachable endpoint, declines, is offline, or returns
garbage yields ``None`` — a VALID but UNCORROBORATED receipt for the issuer,
never an error and never a blocked interaction. Integrity degrades safe: the
absence of a witness can only lower a score, never inflate one (§F).

**SSRF guard.** The chapter only ever relays to an endpoint it already
registered for a known member; an unresolvable ``counterparty_did`` declines
*without* any outbound call. The broker cannot be steered to fetch an arbitrary
URL.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlparse

import sovereign_identity

# Carrier-grade NAT (RFC 6598) is not flagged by ``ipaddress.is_private`` but is
# internal-only routing space, so exclude it explicitly.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_public_addr(ip_str: str) -> bool:
    """True iff ``ip_str`` is a routable, non-internal address. Any loopback /
    private / link-local / reserved / multicast / unspecified / CGNAT address
    fails."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.version == 4 and addr in _CGNAT:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolve_and_pin(url: str) -> tuple[str, str, int, str] | None:
    """Resolve ``url``'s host ONCE and return ``(scheme, host, port, pinned_ip)``
    if EVERY resolved address is public, else None.

    This is the anti-DNS-rebinding primitive: the caller connects to the
    returned ``pinned_ip`` literal (no second resolution), so the address that
    was validated is exactly the address connected to. A member's ``endpoint``
    is self-asserted at registration, so a self-registered attacker could
    otherwise point the broker at cloud metadata (169.254.169.254), localhost,
    or the LAN — and, worse, pass a public IP at check time then rebind the
    hostname to a private IP before httpx re-resolves at connect time. Pinning
    the IP closes that window; TLS/SNI/cert verification still targets ``host``.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return None
    if not infos:
        return None
    pinned_ip = ""
    for info in infos:
        ip_str = str(info[4][0])
        if not _is_public_addr(ip_str):
            return None  # ANY internal address in the set fails closed
        if not pinned_ip:
            pinned_ip = ip_str
    if not pinned_ip:
        return None
    return parsed.scheme, host, port, pinned_ip


def _is_safe_relay_url(url: str) -> bool:
    """True iff ``url`` is an http(s) URL whose host resolves ONLY to routable,
    non-internal addresses — the fast pre-check for the outbound relay. The
    authoritative anti-rebinding guard is ``_resolve_and_pin`` inside the
    transport, which connects to the pinned IP it validated."""
    return _resolve_and_pin(url) is not None

# An async transport: given B's A2A root URL and a JSON-RPC body, return the
# parsed JSON-RPC response dict, or None on ANY failure (timeout, non-200,
# connection error, bad JSON). Injected so the relay logic is testable without
# real HTTP. The default is :func:`_default_post`.
Transport = Callable[[str, dict[str, Any], float], Awaitable[dict[str, Any] | None]]


def resolve_member_endpoint(counterparty_did: str, members: Mapping[str, dict[str, Any]]) -> str | None:
    """Return the A2A endpoint of the registered member whose Ed25519 key derives
    to ``counterparty_did``, or ``None`` if no such member (or no endpoint) exists.

    Resolution is over the chapter's own registry only — this is the SSRF guard:
    a ``counterparty_did`` that is not a registered member resolves to ``None``
    and the relay declines without ever making an outbound call. Non-Ed25519
    key material (legacy HMAC slots) cannot produce a ``did:key`` and is skipped.
    """
    for member in members.values():
        if not isinstance(member, dict):
            continue
        pubkey = member.get("public_key") or ""
        # A 44-char base64 string ending in '=' is the Ed25519 32-byte pubkey
        # shape (same heuristic the registration path uses); anything else can't
        # be turned into the did:key the verifier checks against.
        if not (len(pubkey) == 44 and pubkey.endswith("=")):
            continue
        # try_ variant: the length heuristic doesn't prove valid base64, and the
        # strict builder raises on non-Ed25519 input (R4). None never
        # matches a did:key string, so junk material is skipped, not fatal.
        if sovereign_identity.try_build_did_key_from_ed25519(pubkey) == counterparty_did:
            return member.get("endpoint") or None
    return None


async def relay_cosign(
    receipt: dict[str, Any],
    *,
    members: Mapping[str, dict[str, Any]],
    post: Transport | None = None,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Relay ``receipt`` to its counterparty and return the witness entry, or
    ``None`` to decline (§3 fail-safe).

    Pure transport: the returned entry is whatever B produced, unchanged. The
    chapter never signs, never re-derives, never mutates the entry — it only
    carried the bytes (§4 brokered-path equivalence). ``None`` is returned for
    every non-corroborating outcome (no counterparty named, counterparty not a
    registered member, endpoint unreachable, B declined, malformed reply) so the
    issuer falls back to a valid-but-uncorroborated receipt.
    """
    post = post or _default_post

    action = receipt.get("action")
    if not isinstance(action, dict):
        return None
    counterparty_did = action.get("counterparty_did")
    if not counterparty_did:
        return None

    endpoint = resolve_member_endpoint(counterparty_did, members)
    if not endpoint:
        # Not a registered member / no endpoint → decline. No outbound call.
        return None

    relay_url = endpoint.rstrip("/") + "/"
    if not _is_safe_relay_url(relay_url):
        # SSRF guard: a member's endpoint is self-asserted, so never relay to an
        # internal / loopback / link-local target. Decline (fail-safe, §3) with
        # no outbound call.
        return None

    rpc_body = {
        "jsonrpc": "2.0",
        "id": "cosign-broker",
        "method": "nanda/cosignReceipt",
        "params": {"receipt": receipt},
    }
    result = await post(relay_url, rpc_body, timeout)
    if not isinstance(result, dict):
        return None
    # JSON-RPC success envelope: {"result": {"witness": entry|null}}. An error
    # envelope (no "result") or any other shape is a decline.
    inner = result.get("result")
    entry = inner.get("witness") if isinstance(inner, dict) else None
    return entry if isinstance(entry, dict) else None


async def _default_post(url: str, body: dict[str, Any], timeout: float) -> dict[str, Any] | None:
    """Real transport: POST a JSON-RPC body to B's A2A root, return parsed JSON.

    SSRF-hardened against DNS rebinding: the host is resolved ONCE and validated
    (``_resolve_and_pin``), then the TCP connection is pinned to that exact IP
    via a custom network backend — httpx never re-resolves the hostname, so the
    address validated is the address connected to. Crucially, the request URL
    keeps the HOSTNAME, so TLS SNI + certificate verification still target the
    hostname (only the connect target is pinned); connecting to the raw IP would
    trade SSRF for a MITM-able channel.

    Returns ``None`` on any transport-level failure (unsafe/unresolvable target,
    connection error, timeout, non-200 status, undecodable body) — the relay
    treats every such case as a decline (§3), so a flaky or offline (or unsafe)
    counterparty never raises into the issuer's interaction.
    """
    pinned = _resolve_and_pin(url)
    if pinned is None:
        return None  # unsafe / unresolvable → decline, no outbound connection
    _scheme, _host, _port, pinned_ip = pinned

    import httpcore
    import httpx

    class _PinnedBackend(httpcore.AnyIOBackend):
        """Connects every TCP stream to the pre-validated ``pinned_ip`` instead
        of re-resolving the host. httpcore still passes the original hostname to
        ``start_tls`` as ``server_hostname``, so cert verification is unchanged."""

        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[override]
            return await super().connect_tcp(
                pinned_ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
            )

    try:
        pool = httpcore.AsyncConnectionPool(network_backend=_PinnedBackend())
        transport = httpx.AsyncHTTPTransport()
        transport._pool = pool  # inject the pinning backend
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
            resp = await client.post(url, json=body)  # hostname URL → TLS verifies vs hostname
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None
