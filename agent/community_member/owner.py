"""Owner principal — the party that AUTHORISES this agent's public listing.

Why this module exists
---------------------
Before it, the agent had exactly one key: its own ``did:key``. That key signs the
agent card, the ARP receipts, and the wire. It is also the key the runtime holds
in memory for its whole life. If the same key "authorised" the agent's listing,
the grantor and the grantee would be one key — a self-delegation loop with no
external anchor. ``sm-dat`` SPEC O1 names this as the one precondition a grant
verifier cannot check for itself, and ``sm_authority``'s own opening docstring
says the same: the point is to establish that a grant's ``grantor_did`` is
controlled by the real principal, **not by the agent**.

⚠️ Verification does NOT catch it. Orrery's vendored DAT verifier accepts a grant
whose grantor is its own grantee: ``_dat`` checks delegation continuity only
*across* hops (a child's grantor must be the parent's grantee), and a single
self-granted DAT has no hop, so nothing looks. Measured, not assumed —
``verify_counterparty_dat`` returns ``ok=True, stage='accepted'`` for one. So the
separation is enforced HERE, as an explicit refusal at the gate, with its own
named test. ``_dat`` is deliberately untouched: it is in byte-for-byte lockstep
with ``conformance/dat`` and changing it would break that guard.

What the separation does and does not buy
-----------------------------------------
Honest scope, because "a different key" on its own is cargo cult:

  IT BUYS  (1) an anchor a verifier can check that is not self-referential — the
           listing traces to a Google/Microsoft subject, not to the agent's own
           assertion; (2) the ability to rotate or re-mint the agent identity
           without losing ownership, and to withdraw consent without touching
           the agent key; (3) keeping the authorising key out of the
           long-running, LLM-connected, org-connected process — the runtime
           never loads it, because it is never stored (see below).

  IT DOES NOT BUY  protection against a compromised desktop. Someone with the
           machine and the recovery phrases has both principals. This module
           does not claim otherwise, and neither should the UI.

The owner private key is NEVER PERSISTED
----------------------------------------
It is derived from its own fresh BIP39 phrase, used once to sign the grant, and
dropped. It is not written to ``config.json``, not written to the agent state,
and not put in the keystore vault — so "the runtime never loads it" is a
property of the filesystem, not of a naming convention. The cost is real and
stated in the UI: re-consenting (renewal, a new scope) means re-entering the
phrase. Withdrawing consent does not — deleting the local binding is enough,
and the gate then refuses.

A distinct SLIP-0010 derivation path (account ``1'``, where the agent identity is
account ``0'``) is used on top of the separate phrase. The separate phrase is
what makes the keys independent; the distinct path is defence in depth, so the
owner ``did`` still differs from the agent ``did`` even if the same phrase were
ever fed to both.

The OIDC nonce IS the binding, and it is not optional here
----------------------------------------------------------
⚠️ HISTORY — fixed upstream in ``sm-authority`` 0.2.0, which this distribution
now floors and pins. Under **0.1.0**, ``OIDCVerifier`` checked ``iss`` and
``oid``/``sub`` against the envelope anchor, then ``if nonce is not None and
...`` — the nonce was OPTIONAL, and nothing else in the envelope bound the ID
token to ``grantor_did`` (``build_authority_evidence`` takes it as a plain
field, and the envelope signature is by the *issuer*, whose authority the
library explicitly disclaims: "authority itself comes from the evidence blocks,
not the issuer").

So without a nonce, anyone holding a valid ID token for a subject — which
includes every relying party that person has ever signed into — could assemble a
VERIFIED envelope naming THEIR OWN did as grantor over that person's anchor. It
verified and proved nothing about which key the owner authorised. Measured
against the published 0.1.0 wheel: that envelope returns ``VERIFIED``/``ok``.

0.2.0 binds the nonce to ``grantor_did`` (the block carries ``nonce_salt`` and
the verifier recomputes ``oidc_binding_nonce``), and ``require_nonce`` defaults
to ``True``, so the same envelope now returns ``INDETERMINATE``/
``malformed_evidence``. ``require_nonce=False`` restores the old behaviour IN
FULL — measured, it accepts the attacker envelope again — so it is never set
here; it exists upstream only to migrate pre-``nonce_salt`` evidence.

The local binding below is retained regardless, as defence in depth: it is what
made this path safe for the ten days between the finding and the upstream fix,
and it keeps the guarantee from depending solely on a transitive pin.

This module therefore makes the nonce a COMMITMENT TO THE OWNER DID —
``base64url(sha256(owner_did || "|" || fresh_random))`` — sent in the
authorization request so the IdP itself echoes the binding into the signed
token. It is required non-empty at construction and at the gate. An OIDC
evidence block with no nonce is refused, in the same spirit as
``DID_CONTROL``-signed-by-the-agent-key being refused.

Three paths, and they are not equally ready
-------------------------------------------
``INDIVIDUAL`` (OIDC) is real: loopback redirect + PKCE, no client secret —
verifying an ID token needs only the client id as audience.

``DOMAIN-OWNING BUSINESS`` (domain control) is real: an ACME-style HTTP-01 or
DNS-01 challenge, bound to the owner key. ⚠️ It serves businesses **that own a
domain**, not businesses generally — HTTP-01 needs the ability to host a file at
a well-known path and DNS-01 needs registrar access, and a three-chair barber on
Instagram and Square has neither. Nothing here should imply otherwise.

``PLATFORM INSTALL`` (Shopify / Wix / Toast) REFUSES: three string constants and
an injected validator, no integration and no partner account, so there is nothing
from which the claim could be built. See :func:`platform_install_refusal`. A
consent step that faked success would be the worst version of the failure this
module exists to prevent.

A business with no domain therefore still gets a refusal that names what is
missing. It is not quietly routed to the OIDC path: a personal sign-in proves a
PERSON, and letting it read as proof of business ownership is the laundering the
refusal exists to stop.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, replace

# This distribution supports Python >=3.10, where datetime.UTC does not exist
# (it landed in 3.11). timezone.utc is the portable spelling, and the gate below
# runs in every announce check — including on 3.10.
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._dat import build_dat, verify_dat_signature

__all__ = [
    "BINDING_FILE",
    "DNS_01",
    "DOMAIN_CHALLENGES",
    "DOMAIN_CHALLENGE_DNS_NAME",
    "DOMAIN_CHALLENGE_HTTP_PATH",
    "GRANT_LIFETIME_DAYS",
    "LIFECYCLE_ACTIVE",
    "LIFECYCLE_NOT_ESTABLISHED",
    "LIFECYCLE_REVOKED",
    "LIFECYCLE_STATES",
    "LIFECYCLE_SUSPENDED",
    "LIFECYCLE_TRANSITIONS",
    "HTTP_01",
    "LISTING_ACTION_CATEGORY",
    "OWNER_DERIVATION_PATH",
    "PROVIDERS",
    "BoundDomainControlVerifier",
    "DomainAssertion",
    "DomainChallenge",
    "GrantVerdict",
    "LifecycleAnswer",
    "LifecycleError",
    "OidcProvider",
    "OwnerAssertion",
    "OwnerConfigError",
    "OwnerIdentity",
    "acquire_owner_assertion",
    "anchor_from_claims",
    "authorization_request",
    "build_domain_challenge",
    "build_domain_evidence",
    "build_listing_grant",
    "build_owner_evidence",
    "claims_from_id_token",
    "delete_binding",
    "discover_endpoints",
    "dns_challenge_name",
    "dnspython_txt_lookup",
    "exchange_code",
    "http_challenge_url",
    "httpx_text_fetcher",
    "jwk_thumbprint",
    "jwk_thumbprint_from_did",
    "key_authorization",
    "lifecycle_statement_bytes",
    "listing_grant_verdict",
    "load_binding",
    "make_bound_challenge_validator",
    "make_bound_domain_control_verifier",
    "mint_owner_identity",
    "new_challenge_token",
    "oidc_client_id",
    "owner_nonce",
    "platform_install_refusal",
    "provider_by_id",
    "recover_owner_identity",
    "resolve_lifecycle",
    "resume_listing",
    "revoke_listing",
    "save_binding",
    "set_lifecycle",
    "sign_lifecycle_transition",
    "suspend_listing",
    "validate_domain",
    "verify_domain_challenge",
    "verify_id_token_fail_fast",
    "verify_lifecycle_signature",
]

# The agent identity is account 0' (recovery.DEFAULT_PATH). The owner binding key
# is account 1'. See the module docstring for why the path is defence in depth
# rather than the separation itself.
OWNER_DERIVATION_PATH = "m/44'/9004'/1'/0'/0'"

# The single scope this grant confers. Narrow on purpose: consenting to be
# discoverable is not consenting to anything else the agent might later do.
LISTING_ACTION_CATEGORY = "index_listing"

BINDING_FILE = "owner_binding.json"

# A consent that never expires is a consent nobody revisits.
GRANT_LIFETIME_DAYS = 365

# Evidence type names, as sm_authority spells them.
_OIDC = "oidc"
_DOMAIN_CONTROL = "domain_control"

# Challenge method names and the wire locations a domain publishes its proof at.
#
# ⚠️ THESE ARE A HAND-MIRROR OF nanda-connect's WIRE VALUES AND NOTHING PINS THEM.
# They must match `nanda_connect.providers.validators.HTTP_CHALLENGE_PATH` /
# `DNS_CHALLENGE_NAME` exactly, because the domain owner publishes at one
# location and every verifier — including a registry running nanda-connect —
# must look at the same one. nanda-connect is not on PyPI and not importable
# here (verified), so this cannot be mechanically pinned to its source the way
# schema/0.4's enums are. Publishing that package is what would close it; until
# then this comment is the only guard, which is stated rather than hidden.
HTTP_01 = "http-01"
DNS_01 = "dns-01"
DOMAIN_CHALLENGES = frozenset({HTTP_01, DNS_01})
DOMAIN_CHALLENGE_HTTP_PATH = "/.well-known/nanda-connect-challenge/"
DOMAIN_CHALLENGE_DNS_NAME = "_nanda-connect-challenge"


class OwnerConfigError(ValueError):
    """Configuration is missing or empty — refuse, never fall through.

    Unset and empty are the SAME error on purpose. A blank client id is a
    deployment that *looks* configured, which is the worse of the two failures.
    """


@dataclass(frozen=True)
class OidcProvider:
    """A consumer identity provider we can acquire an owner ID token from.

    ⚠️ Deliberately NOT ``server/chapter_auth.py``'s ``VALID_PROVIDERS``. That
    registry (Okta / Entra ID / Google Workspace / generic) binds an ORG to its
    enterprise IdP with tenant-specific issuers. This one authenticates an
    INDIVIDUAL against a consumer account — the barber with a Gmail address.
    Copying that list here would have been wrong by semantics before it was
    wrong by drift, so neither happens.
    """

    id: str
    label: str
    issuer: str
    # The durable, immutable subject id. Google's is ``sub``; Microsoft's own
    # guidance is ``oid``, never the mutable email. sm_authority reads
    # ``claims.get("oid") or claims.get("sub")``, which is correct for both.
    anchor_claim: str


PROVIDERS: tuple[OidcProvider, ...] = (
    OidcProvider("google", "Google", "https://accounts.google.com", "sub"),
    OidcProvider("microsoft", "Microsoft", "https://login.microsoftonline.com/common/v2.0", "oid"),
)


def provider_by_id(provider_id: str) -> OidcProvider:
    for p in PROVIDERS:
        if p.id == provider_id:
            return p
    raise OwnerConfigError(f"unknown OIDC provider {provider_id!r}; known: {[p.id for p in PROVIDERS]}")


def oidc_client_id(provider_id: str, env: dict[str, str] | None = None) -> str:
    """The OAuth client id for ``provider_id``, or refuse.

    ⚠️ FAIL CLOSED. Unset and empty (and whitespace-only) are the same error.
    There is no default and no fall-through: without a client id there is no
    audience to pin an ID token to, so there is no owner principal, so nothing
    may be listed.

    NOTE there is no client SECRET here, by design. Verifying an ID token needs
    only the client id as audience, and a desktop app cannot keep a secret. If a
    secret ever appears in this module, that is the bug.
    """
    provider = provider_by_id(provider_id)
    source = os.environ if env is None else env
    var = f"ORRERY_OIDC_CLIENT_ID_{provider.id.upper()}"
    raw = (source.get(var) or "").strip()
    if not raw:
        raise OwnerConfigError(
            f"{var} is not set (or is empty) — cannot establish an owner principal for "
            f"{provider.label}. Refusing: no owner means no consent, and no consent means no listing."
        )
    return raw


# ── the owner binding key ────────────────────────────────────────────────────


@dataclass(frozen=True)
class OwnerIdentity:
    """A freshly derived owner principal.

    ``private_key_b64`` lives in memory for the length of one wizard run and is
    never persisted by this module. ``mnemonic`` is shown to the user exactly
    once. Neither belongs in a log line.
    """

    did: str
    private_key_b64: str
    public_key_b64: str
    mnemonic: str

    def signing_key_bytes(self) -> bytes:
        return base64.b64decode(self.private_key_b64)


def _material_to_owner(material: Any) -> OwnerIdentity:
    return OwnerIdentity(
        did=material.did_key,
        private_key_b64=material.private_key_b64,
        public_key_b64=material.public_key_b64,
        mnemonic=material.mnemonic,
    )


def mint_owner_identity() -> OwnerIdentity:
    """Derive a fresh owner principal from a NEW BIP39 phrase on the owner path.

    A separate phrase (not a second path off the agent's) is what makes the two
    keys independent: whoever holds the agent phrase cannot derive this one.
    """
    from . import recovery

    return _material_to_owner(recovery.generate_recovery(path=OWNER_DERIVATION_PATH))


def recover_owner_identity(phrase: str) -> OwnerIdentity:
    """Re-derive the owner principal from its phrase, for re-consent or renewal.

    The one operation that needs this key back. Withdrawing consent does not —
    see :func:`delete_binding`.
    """
    from . import recovery

    return _material_to_owner(recovery.recover_from_mnemonic(phrase, path=OWNER_DERIVATION_PATH))


# ── the nonce that binds the token to the owner key ──────────────────────────


def owner_nonce(owner_did: str, randomness: str) -> str:
    """``base64url(sha256(owner_did || "|" || randomness))`` — the OIDC nonce.

    This is the whole reason the OIDC path proves anything. We send it in the
    authorization request; the IdP echoes it into the ID token it signs; so the
    token is bound by the IdP to THIS owner key, not merely to this subject.
    Without it an envelope verifies while binding an arbitrary key to a real
    person's anchor (see the module docstring).

    The separator is there so ``(did, rand)`` pairs cannot be re-split into a
    different pair with the same concatenation.
    """
    if not owner_did.strip():
        raise ValueError("owner_did is required to build the nonce commitment")
    if not randomness.strip():
        raise ValueError("randomness is required — a fixed nonce is replayable")
    digest = hashlib.sha256(f"{owner_did}|{randomness}".encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# ── OIDC acquisition (loopback + PKCE) ───────────────────────────────────────


@dataclass(frozen=True)
class AuthorizationRequest:
    """Everything the caller needs to drive one loopback+PKCE authorization.

    ``code_verifier`` and ``state`` never leave the machine; ``nonce`` is the
    owner-DID commitment; ``randomness`` is kept so the nonce can be recomputed
    and re-checked rather than trusted.
    """

    url: str
    state: str
    code_verifier: str
    nonce: str
    randomness: str
    redirect_uri: str


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def authorization_request(
    provider: OidcProvider,
    client_id: str,
    owner_did: str,
    *,
    authorization_endpoint: str,
    redirect_uri: str,
    scope: str = "openid email",
) -> AuthorizationRequest:
    """Build the authorization URL for a desktop loopback + PKCE(S256) flow.

    No client secret is sent — a desktop client cannot hold one, and an ID token
    is audience-verified by client id alone. PKCE is what binds the code
    redemption to this process.
    """
    if not client_id.strip():
        raise OwnerConfigError("client_id is required — refusing to start an OIDC flow without an audience")
    verifier = secrets.token_urlsafe(64)
    randomness = secrets.token_urlsafe(32)
    nonce = owner_nonce(owner_did, randomness)
    state = secrets.token_urlsafe(24)
    query = {
        "client_id": client_id,
        "response_type": "code",
        "scope": scope,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    url = f"{authorization_endpoint}?{urllib.parse.urlencode(query)}"
    return AuthorizationRequest(
        url=url,
        state=state,
        code_verifier=verifier,
        nonce=nonce,
        randomness=randomness,
        redirect_uri=redirect_uri,
    )


def claims_from_id_token(id_token: str) -> dict[str, Any]:
    """Decode an ID token's claims WITHOUT verifying its signature.

    ⚠️ READ THIS BEFORE REUSING IT. This is not a verification function and this
    module is not the authority boundary. The party whose decision depends on
    the token is the registry, and the registry verifies the signature against
    the issuer's JWKS.

    Decoding unverified is sound *here* for one specific reason: the token is
    received over TLS in the direct response to our own PKCE-bound code
    exchange with the discovered ``token_endpoint``. OpenID Connect Core
    §3.1.3.7 says exactly this — when the ID token comes via direct
    Client↔Token-Endpoint communication, TLS server validation MAY be used in
    place of checking the token signature. What we do with these claims is a
    FAIL-FAST check (:func:`verify_id_token_fail_fast`) so a bad token stops at
    the wizard instead of failing confusingly at the registry later.

    Deliberately no PyJWT dependency: we neither verify a signature here nor
    hand-roll one. The hardened JWKS validator already exists in
    ``nanda_connect/providers/validators.py``; it is not importable from this
    package (nanda-connect is not published), and vendoring a copy would create
    an unpinnable hand-mirror of security code — so we do neither.
    """
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("id_token is not a well-formed JWS compact serialization")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + padding))
    except Exception as e:  # noqa: BLE001 — any decode failure is a bad token
        raise ValueError(f"id_token payload is not decodable JSON: {e}") from e
    if not isinstance(claims, dict):
        raise ValueError("id_token payload is not a JSON object")
    return claims


def verify_id_token_fail_fast(
    claims: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    nonce: str,
    now: int | None = None,
    leeway: int = 60,
) -> None:
    """Raise unless the claims match the flow we just drove. Fail-fast, not authority.

    Checks issuer, audience (our client id), the owner-DID nonce commitment, and
    the validity window. The nonce check is the load-bearing one: it is what
    ties the IdP's signature to the owner key.
    """
    ts = int(time.time()) if now is None else now
    if claims.get("iss") != issuer:
        raise ValueError(f"id_token issuer mismatch: expected {issuer!r}, got {claims.get('iss')!r}")
    aud = claims.get("aud")
    aud_set = {aud} if isinstance(aud, str) else {str(a) for a in aud} if isinstance(aud, list) else set()
    if audience not in aud_set:
        raise ValueError("id_token audience does not include our client id")
    token_nonce = claims.get("nonce")
    if not token_nonce:
        raise ValueError(
            "id_token carries NO nonce — refusing. Without it the token is not bound to the owner key, "
            "and the evidence would verify while proving nothing about who authorised the listing."
        )
    if token_nonce != nonce:
        raise ValueError("id_token nonce does not match the owner-DID commitment we sent")
    exp = claims.get("exp")
    if isinstance(exp, int | float) and ts > exp + leeway:
        raise ValueError("id_token has expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, int | float) and ts + leeway < nbf:
        raise ValueError("id_token is not yet valid")


def discover_endpoints(issuer: str, *, fetch: Any = None) -> dict[str, str]:
    """OIDC discovery: ``{issuer}/.well-known/openid-configuration`` → endpoints.

    We never hardcode an authorization or token endpoint — the issuer publishes
    them, and pinning the ISSUER (not the endpoints) is what makes the provider
    list short and stable.
    """
    if not issuer.startswith("https://"):
        raise OwnerConfigError(f"issuer must be https://, got {issuer!r}")
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    if fetch is None:
        import httpx

        def fetch(u: str) -> dict[str, Any]:  # type: ignore[misc]
            return dict(httpx.get(u, timeout=10.0, follow_redirects=True).json())

    doc = fetch(url)
    missing = [k for k in ("authorization_endpoint", "token_endpoint") if not doc.get(k)]
    if missing:
        raise OwnerConfigError(f"{issuer} discovery document is missing {missing}")
    if doc.get("issuer") and doc["issuer"].rstrip("/") != issuer.rstrip("/"):
        # A discovery document that names a different issuer is either
        # misconfigured or hostile; either way the anchor we would build from it
        # would not be the anchor we pinned.
        raise OwnerConfigError(f"discovery issuer {doc['issuer']!r} does not match the pinned issuer {issuer!r}")
    return {
        "authorization_endpoint": str(doc["authorization_endpoint"]),
        "token_endpoint": str(doc["token_endpoint"]),
    }


def exchange_code(
    token_endpoint: str,
    *,
    client_id: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    post: Any = None,
) -> str:
    """Redeem the authorization code for an ID token. PKCE, no client secret."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
    }
    if post is None:
        import httpx

        def post(url: str, data: dict[str, str]) -> dict[str, Any]:  # type: ignore[misc]
            return dict(httpx.post(url, data=data, timeout=15.0).json())

    payload = post(token_endpoint, form)
    id_token = payload.get("id_token")
    if not id_token:
        raise ValueError(f"token endpoint returned no id_token (error={payload.get('error', 'none')})")
    return str(id_token)


@dataclass(frozen=True)
class OwnerAssertion:
    """A verified-enough OIDC result, ready to become evidence."""

    id_token: str
    claims: dict[str, Any]
    anchor: dict[str, str]
    nonce: str
    subject: str


def acquire_owner_assertion(
    provider: OidcProvider,
    client_id: str,
    owner_did: str,
    *,
    fetch: Any = None,
    post: Any = None,
    open_url: Any = None,
    timeout: float = 300.0,
) -> OwnerAssertion:
    """Drive one loopback + PKCE authorization and return the owner's assertion.

    Loopback redirect (``http://127.0.0.1:<ephemeral>/callback``) is the native
    desktop pattern: the port is learned by binding first, so the redirect URI in
    the authorization request is always the one actually listening. Single
    request, then the server closes — it is not a service.

    ``fetch``/``post``/``open_url`` are injected so the whole flow is testable
    without a browser or a network.
    """
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    if not client_id.strip():
        raise OwnerConfigError("client_id is required — refusing to start an OIDC flow without an audience")

    endpoints = discover_endpoints(provider.issuer, fetch=fetch)

    # Bind first so the redirect URI names the port we are really listening on.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    req = authorization_request(
        provider,
        client_id,
        owner_did,
        authorization_endpoint=endpoints["authorization_endpoint"],
        redirect_uri=redirect_uri,
    )

    received: dict[str, str] = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's contract
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            received.update({k: v[0] for k, v in query.items() if v})
            body = b"<html><body><h3>You can close this tab and return to the terminal.</h3></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            """Silence the default stderr access log — it would print the code."""

    server = HTTPServer(("127.0.0.1", port), _Handler)
    server.timeout = timeout
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        if open_url is None:
            import webbrowser

            open_url = webbrowser.open
        open_url(req.url)
        thread.join(timeout)
    finally:
        server.server_close()

    if received.get("error"):
        raise ValueError(f"the identity provider refused the sign-in: {received['error']}")
    code = received.get("code")
    if not code:
        raise ValueError("no authorization code came back — the sign-in was cancelled or timed out")
    # A mismatched state means the response is not the one we asked for.
    if received.get("state") != req.state:
        raise ValueError("OAuth state mismatch — refusing this response")

    id_token = exchange_code(
        endpoints["token_endpoint"],
        client_id=client_id,
        code=code,
        code_verifier=req.code_verifier,
        redirect_uri=redirect_uri,
        post=post,
    )
    claims = claims_from_id_token(id_token)
    verify_id_token_fail_fast(claims, issuer=provider.issuer, audience=client_id, nonce=req.nonce)
    return OwnerAssertion(
        id_token=id_token,
        claims=claims,
        anchor=anchor_from_claims(provider, claims),
        nonce=req.nonce,
        subject=str(claims.get("email") or claims.get("preferred_username") or ""),
    )


def anchor_from_claims(provider: OidcProvider, claims: dict[str, Any]) -> dict[str, str]:
    """The durable ``{method, issuer, id}`` anchor — never the mutable email."""
    subject_id = claims.get(provider.anchor_claim) or claims.get("sub")
    if not subject_id:
        raise ValueError(f"id_token has neither {provider.anchor_claim!r} nor 'sub' — no durable anchor")
    return {"method": _OIDC, "issuer": provider.issuer, "id": str(subject_id)}


# ── domain control, bound to the owner key (ACME-style) ──────────────────────
#
# ⚠️⚠️ WHY THIS IS NOT nanda-connect's make_challenge_validator, AND WHY THAT ONE
# IS TREATED AS UNTRUSTED FOR THIS PURPOSE.
#
# Theirs reads ``key_authorization`` FROM CALLER-SUPPLIED CLAIMS and merely
# checks the domain publishes that same string; ``DomainControlVerifier.verify``
# then checks only ``attested["domain"] == anchor["id"]``. Nothing binds either
# to ``grantor_did``. So it proves "someone controls this domain" and never "the
# controller of this domain authorised THIS key".
#
# It is a worse instance of the confused-deputy shape than the optional OIDC
# nonce, because the value an attacker needs is PUBLISHED ON PURPOSE: an HTTP-01
# response lives at a deliberately world-readable URL and DNS-01 is a public TXT
# record. Any passive observer of a legitimate challenge can copy
# {domain, method, token, key_authorization} into their own envelope, name their
# own DID as grantor, and be VERIFIED as the owner of someone else's domain.
# Filed upstream against the NANDA Connect library; not waited on, and that
# repository is untouched.
#
# THE FIX IS RFC 8555's, applied to the owner key:
#     keyAuthorization = token || "." || base64url(JWK_Thumbprint(ownerKey))
# computed HERE from the owner's did:key and NEVER accepted as an input. A
# copied challenge value carries the wrong thumbprint for whoever copied it, so
# it fails for every key but the one it was issued to. That is the A-vs-B
# property, and it is what makes this path real rather than merely shaped right.
#
# ⚠️ NOTE ON THE SEAM: the brief's suggestion was to inject this validator into
# nanda-connect's ``make_domain_control_verifier``. That is the right seam and it
# is unreachable — nanda-connect is not published and not importable from this
# package (re-verified). So :class:`BoundDomainControlVerifier` implements
# ``sm_authority.verify.EvidenceVerifier``, the Protocol that seam is defined
# against and which IS importable — a conformant implementation of the public
# contract, not a fork or a vendoring of nanda-connect. A test asserts the
# Protocol conformance mechanically rather than claiming it.


def jwk_thumbprint(public_key_b64: str) -> str:
    """RFC 7638 JWK thumbprint of an Ed25519 public key, base64url, unpadded.

    RFC 8037 §2 fixes the member set and their lexicographic order for an OKP
    key — ``crv``, ``kty``, ``x`` — and RFC 7638 requires no whitespace, so the
    canonical form is constructed literally rather than via json.dumps, whose
    separators are a setting somebody can change.
    """
    raw = base64.b64decode(public_key_b64)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    x = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")


def jwk_thumbprint_from_did(did: str) -> str:
    """The thumbprint of the key a ``did:key`` encodes.

    Derivable from PUBLIC data on purpose: it means the gate can recompute the
    expected challenge value from the binding alone, with no secret and no
    trust in whatever the claims happen to say.
    """
    from cryptography.hazmat.primitives import serialization
    from sm_arp import pubkey_from_did

    raw = pubkey_from_did(did).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return jwk_thumbprint(base64.b64encode(raw).decode())


def key_authorization(token: str, owner_did: str) -> str:
    """RFC 8555 §8.1 key authorization, over the OWNER key.

    ``token || "." || base64url(JWK_Thumbprint(ownerKey))``. This is the string
    the domain must publish, and the ONLY way it is ever produced — it is never
    read from claims, at acquisition or at the gate.
    """
    if not token.strip():
        raise ValueError("a challenge token is required")
    if not owner_did.strip():
        raise ValueError("an owner did is required — an unbound challenge proves nothing about who authorised")
    return f"{token}.{jwk_thumbprint_from_did(owner_did)}"


def new_challenge_token() -> str:
    """A fresh, unguessable challenge token. Public once published, so its only
    job is to make the URL unpredictable until the owner chooses to serve it."""
    return secrets.token_urlsafe(32)


def http_challenge_url(domain: str, token: str) -> str:
    return f"https://{domain}{DOMAIN_CHALLENGE_HTTP_PATH}{token}"


def dns_challenge_name(domain: str) -> str:
    return f"{DOMAIN_CHALLENGE_DNS_NAME}.{domain}"


def validate_domain(domain: str) -> str:
    """Normalise and refuse anything that is not a plain hostname.

    No scheme, no path, no port, no wildcard: the anchor is the domain itself,
    and an anchor that can be spelled two ways is two anchors.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        raise OwnerConfigError("a domain is required")
    if "://" in d or "/" in d or ":" in d or "*" in d or " " in d:
        raise OwnerConfigError(f"{domain!r} must be a bare hostname, e.g. moonbakery.com")
    if "." not in d or d.startswith(".") or ".." in d:
        raise OwnerConfigError(f"{domain!r} is not a valid domain name")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", d):
        raise OwnerConfigError(f"{domain!r} is not a valid domain name")
    return d


@dataclass(frozen=True)
class DomainChallenge:
    """What the owner must publish, and where. All public — no secret here."""

    domain: str
    method: str
    token: str
    key_authorization: str

    @property
    def location(self) -> str:
        if self.method == HTTP_01:
            return http_challenge_url(self.domain, self.token)
        return f"TXT {dns_challenge_name(self.domain)}"


def build_domain_challenge(domain: str, method: str, owner_did: str, *, token: str | None = None) -> DomainChallenge:
    """Mint a challenge bound to ``owner_did``. Nothing is published by this —
    the owner publishes it, deliberately, as a separate step."""
    if method not in DOMAIN_CHALLENGES:
        raise OwnerConfigError(f"method must be one of {sorted(DOMAIN_CHALLENGES)}, got {method!r}")
    d = validate_domain(domain)
    tok = token or new_challenge_token()
    return DomainChallenge(domain=d, method=method, token=tok, key_authorization=key_authorization(tok, owner_did))


def make_bound_challenge_validator(
    owner_did: str,
    *,
    http_get_text: Any = None,
    dns_txt: Any = None,
) -> Any:
    """A ``challenge_validator`` that binds the challenge to ``owner_did``.

    ⚠️ ``claims["key_authorization"]`` IS NEVER READ. The expected value is
    recomputed from ``(claims["token"], owner_did)`` and compared against what
    the domain actually serves. That is the entire difference from
    nanda-connect's validator, and it is the difference between "someone
    controls this domain" and "the controller of this domain authorised this
    key" — see the section note above.

    Returns the attested ``{domain, method}`` on success, ``None`` otherwise.
    ``None`` on every failure path, never an exception, so a network blip reads
    as "not proven" rather than "proven".
    """
    expected_thumbprint = jwk_thumbprint_from_did(owner_did)

    def validate(claims: dict[str, Any]) -> dict[str, Any] | None:
        domain = claims.get("domain")
        method = claims.get("method")
        token = claims.get("token")
        if not (isinstance(domain, str) and isinstance(token, str) and domain and token):
            return None
        expected = f"{token}.{expected_thumbprint}"

        if method == HTTP_01:
            if http_get_text is None:
                return None
            body = http_get_text(http_challenge_url(domain, token))
            if not isinstance(body, str) or body.strip() != expected:
                return None
            return {"domain": domain, "method": method}

        if method == DNS_01:
            if dns_txt is None:
                return None
            records = [str(r).strip().strip('"') for r in (dns_txt(dns_challenge_name(domain)) or [])]
            if expected not in records:
                return None
            return {"domain": domain, "method": method}

        return None

    return validate


class BoundDomainControlVerifier:
    """A ``domain_control`` evidence verifier bound to a specific owner key.

    Implements ``sm_authority.verify.EvidenceVerifier``. Checks what
    nanda-connect's verifier checks (attested domain == anchor id) AND the thing
    it does not: that the envelope's ``grantor_did`` is the key the challenge was
    issued to. Without that second check the first one is satisfiable by anyone
    who can read a public URL.
    """

    def __init__(self, owner_did: str, challenge_validator: Any):
        self._owner_did = owner_did
        self._validate = challenge_validator

    def verify(self, block: dict[str, Any], env: dict[str, Any]) -> Any:
        from sm_authority import INDETERMINATE, REFUTED, VERIFIED, EvidenceVerdict

        claims = block.get("claims") or {}
        anchor = env.get("anchor") or {}
        # The binding check comes FIRST, before any network call: if the envelope
        # is not about this owner, performing the challenge would prove something
        # true and irrelevant, and a validator that runs anyway is a lookup
        # oracle for whoever asks.
        if env.get("grantor_did") != self._owner_did:
            return EvidenceVerdict(REFUTED, "grantor_not_bound_to_challenge")
        try:
            attested = self._validate(claims)
        except Exception as e:  # noqa: BLE001 — a broken validator must not pass
            return EvidenceVerdict(INDETERMINATE, "validator_error", str(e))
        if attested is None:
            return EvidenceVerdict(REFUTED, "challenge_failed")
        if attested.get("domain") != anchor.get("id"):
            return EvidenceVerdict(REFUTED, "anchor_mismatch")
        return EvidenceVerdict(VERIFIED, "ok")


def make_bound_domain_control_verifier(owner_did: str, *, http_get_text: Any = None, dns_txt: Any = None) -> Any:
    """The verifier + its bound validator, assembled for ``owner_did``."""
    return BoundDomainControlVerifier(
        owner_did,
        make_bound_challenge_validator(owner_did, http_get_text=http_get_text, dns_txt=dns_txt),
    )


def httpx_text_fetcher(*, timeout: float = 10.0) -> Any:
    """Fetch a challenge URL's body, or ``None``. HTTPS only; no redirects.

    Redirects are refused deliberately: following one would let a domain that
    does not serve the challenge point at one that does.
    """
    import httpx

    def fetch(url: str) -> str | None:
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=False)
            return resp.text if resp.status_code == 200 else None
        except Exception:  # noqa: BLE001 — unreachable is "not proven"
            return None

    return fetch


def dnspython_txt_lookup(*, timeout: float = 10.0) -> Any:
    """TXT lookup for DNS-01. Requires the optional ``domain`` extra (dnspython).

    Absent, this raises rather than returning an empty list — "the resolver is
    missing" and "the record is not there" are different answers, and collapsing
    them would report an unprovable challenge as a failed one.
    """
    try:
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError as e:  # pragma: no cover - depends on the optional extra
        raise OwnerConfigError("DNS-01 needs dnspython — install 'orrery-agent[domain]', or use HTTP-01 instead") from e

    def lookup(name: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(name, "TXT")
        except Exception:  # noqa: BLE001 — NXDOMAIN / timeout is "not proven"
            return []
        return [b"".join(r.strings).decode(errors="replace") for r in answers]

    return lookup


@dataclass(frozen=True)
class DomainAssertion:
    """A domain whose control has been proven FOR A SPECIFIC OWNER KEY."""

    domain: str
    method: str
    token: str
    key_authorization: str
    anchor: dict[str, str]


def verify_domain_challenge(
    challenge: DomainChallenge,
    owner_did: str,
    *,
    http_get_text: Any = None,
    dns_txt: Any = None,
) -> DomainAssertion:
    """Perform the challenge and return the assertion, or raise.

    Raises rather than returning a falsy value so an unproven domain can never be
    mistaken for a proven one by a caller that forgot to check.
    """
    verifier = make_bound_domain_control_verifier(owner_did, http_get_text=http_get_text, dns_txt=dns_txt)
    anchor = {"method": "domain", "issuer": challenge.method, "id": challenge.domain}
    block = {
        "type": _DOMAIN_CONTROL,
        "claims": {
            "domain": challenge.domain,
            "method": challenge.method,
            "token": challenge.token,
            # Recorded so a downstream verifier can recompute it; NOT trusted as
            # an input anywhere in this module.
            "key_authorization": challenge.key_authorization,
        },
    }
    verdict = verifier.verify(block, {"anchor": anchor, "grantor_did": owner_did})
    if verdict.status != "VERIFIED":
        raise ValueError(f"domain control not proven for {challenge.domain}: {verdict.reason}")
    return DomainAssertion(
        domain=challenge.domain,
        method=challenge.method,
        token=challenge.token,
        key_authorization=challenge.key_authorization,
        anchor=anchor,
    )


# ── the authority-evidence envelope ──────────────────────────────────────────


def build_owner_evidence(
    *,
    owner: OwnerIdentity,
    subject: str,
    anchor: dict[str, str],
    id_token: str,
    nonce: str,
    not_after: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble and issuer-sign an ``sm_authority`` Authority Evidence envelope.

    The OIDC block ALWAYS carries the nonce. ``sm_authority`` treats it as
    optional; we do not, for the reason in the module docstring.

    The envelope is signed by the OWNER as issuer, which is honest about what
    that signature means: integrity of assembly, not authority. Authority comes
    from the evidence block.
    """
    if not nonce.strip():
        raise ValueError("refusing to build OIDC evidence without a nonce — see owner.owner_nonce")
    from sm_arp import Identity
    from sm_authority import build_authority_evidence, sign_authority_evidence

    issued = now or datetime.now(timezone.utc)
    expiry = not_after or (issued + timedelta(days=GRANT_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = build_authority_evidence(
        subject=subject,
        anchor=dict(anchor),
        grantor_did=owner.did,
        evidence=[{"type": _OIDC, "claims": {"token": id_token, "nonce": nonce}}],
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=expiry,
    )
    return dict(sign_authority_evidence(Identity.from_seed(owner.signing_key_bytes()), env))


# ── the consent artifact: an owner-signed DAT ────────────────────────────────


def build_domain_evidence(
    *,
    owner: OwnerIdentity,
    assertion: DomainAssertion,
    not_after: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble and issuer-sign a ``domain_control`` Authority Evidence envelope.

    The subject AND the anchor are the domain — unlike the OIDC path, where the
    locator (an email) is mutable and the anchor has to be the IdP's immutable
    subject id. A domain is already durable, which is why this path can anchor
    on the thing the business actually trades under.

    The block always carries the token, so any verifier can RECOMPUTE the
    expected key authorization from the envelope's own ``grantor_did`` instead of
    trusting the recorded string.
    """
    from sm_arp import Identity
    from sm_authority import build_authority_evidence, sign_authority_evidence

    expected = key_authorization(assertion.token, owner.did)
    if expected != assertion.key_authorization:
        raise ValueError("refusing to build domain evidence: the challenge is not bound to this owner key")

    issued = now or datetime.now(timezone.utc)
    expiry = not_after or (issued + timedelta(days=GRANT_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = build_authority_evidence(
        subject=assertion.domain,
        anchor=dict(assertion.anchor),
        grantor_did=owner.did,
        evidence=[
            {
                "type": _DOMAIN_CONTROL,
                "claims": {
                    "domain": assertion.domain,
                    "method": assertion.method,
                    "token": assertion.token,
                    "key_authorization": assertion.key_authorization,
                },
            }
        ],
        issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=expiry,
    )
    return dict(sign_authority_evidence(Identity.from_seed(owner.signing_key_bytes()), env))


def build_listing_grant(
    *,
    owner: OwnerIdentity,
    agent_did: str,
    not_after: str | None = None,
    now: datetime | None = None,
    human_summary: str | None = None,
) -> dict[str, Any]:
    """The consent artifact: a DAT signed by the OWNER granting THE AGENT the listing scope.

    A DAT rather than a nanda-connect grant because Orrery already vendors the
    canonical verifier in ``_dat`` (byte-for-byte lockstep with
    ``conformance/dat``, CI-gated), and it is the format Orrery's counterparties
    already verify — so the individual path needs no nanda-connect dependency.

    Refuses grantor == grantee here as well as at the gate. Belt and braces on
    purpose: ``_dat`` would accept it.
    """
    if owner.did == agent_did:
        raise ValueError(
            "refusing to build a self-granted listing consent: the owner principal and the agent "
            "identity are the same key, which proves nothing about who authorised the listing"
        )
    issued = now or datetime.now(timezone.utc)
    expiry = not_after or (issued + timedelta(days=GRANT_LIFETIME_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return build_dat(
        grantor_sk_bytes=owner.signing_key_bytes(),
        grantor_did=owner.did,
        grantee_did=agent_did,
        action_categories=[LISTING_ACTION_CATEGORY],
        not_after=expiry,
        human_summary=human_summary or f"The owner authorises this agent to be listed publicly until {expiry}.",
    )


# ── lifecycle: a RESOLVABLE state, never presence-or-absence ─────────────────
#
# ⚠️ WHY THIS EXISTS, AND WHY DELETION IS THE WRONG SHORTCUT. Before it, a
# listing was consent-gated, which is presence or ABSENCE — so a caller could not
# tell "this business no longer has an agent" from "resolution failed". That is
# the same defect as the strict-selector rule one layer up: an unrecognised ``?schema=`` selector
# used to return a PLAUSIBLE WRONG ANSWER instead of a 400, and the fix was to
# make the failure explicit. An ambiguous answer is worse than an honest error,
# because a stale endpoint produces a plausible transaction with a party that no
# longer exists.
#
# So withdrawal produces ``revoked``, not a deleted file. Deleting the record
# makes revocation indistinguishable from never-existed, which is precisely the
# ambiguity this removes. ``not_established`` is its own answer for the genuine
# never-existed case, and it is ANSWERED rather than 404'd for the same reason.
#
# REVOCATION IS TERMINAL. ``suspended`` is reversible; ``revoked`` is not. A
# resolver that saw "revoked" and cached it must not be made wrong later, so
# re-listing after revocation requires a NEW binding — i.e. fresh consent, which
# is what actually changed.
#
# ⚠️ ON ATTESTATION, STATED BECAUSE THE DIFFERENCE IS LOAD-BEARING. The owner key
# is never persisted, so a withdrawal cannot require it — locking someone out of
# revoking their own listing because they lost a phrase would be a worse failure
# than an unattested record. Withdrawal therefore always writes the local
# lifecycle record, and attaches an owner SIGNATURE only when the owner supplies
# the phrase. The two are NOT equivalent and the answer says which it is:
#   - unattested  → this runtime will no longer act. Self-enforcing and true,
#                   because the runtime is the party being asked; it proves
#                   nothing to a third party.
#   - attested    → the owner cryptographically revoked. Verifiable by anyone.
# Reporting an unattested record as though the owner had signed it would be the
# same "plausible wrong answer" this whole unit exists to delete.

LIFECYCLE_ACTIVE = "active"
LIFECYCLE_SUSPENDED = "suspended"
LIFECYCLE_REVOKED = "revoked"
# Not one of the three: the answer for a subject that never had a binding here.
# It is a STATE, not an error, so that "never existed" is as explicit as the rest.
LIFECYCLE_NOT_ESTABLISHED = "not_established"
LIFECYCLE_STATES = frozenset({LIFECYCLE_ACTIVE, LIFECYCLE_SUSPENDED, LIFECYCLE_REVOKED})

# Which states may follow which. Revoked is absent as a key: it is terminal.
LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    LIFECYCLE_ACTIVE: frozenset({LIFECYCLE_SUSPENDED, LIFECYCLE_REVOKED}),
    LIFECYCLE_SUSPENDED: frozenset({LIFECYCLE_ACTIVE, LIFECYCLE_REVOKED}),
    LIFECYCLE_REVOKED: frozenset(),
}

_LIFECYCLE_STATEMENT_VERSION = "orrery-lifecycle/0.1"


class LifecycleError(ValueError):
    """An illegal lifecycle transition. Raised, never swallowed into a no-op."""


@dataclass(frozen=True)
class LifecycleAnswer:
    """The resolvable answer about a subject's listing.

    Always has a ``state``. There is no shape of this object that means "I do not
    know" — that is what ``not_established`` is for.
    """

    state: str
    subject: str | None = None
    since: str | None = None
    by: str | None = None
    reason: str | None = None
    attested: bool = False

    @property
    def resolvable(self) -> bool:
        """Whether a caller should transact with this subject."""
        return self.state == LIFECYCLE_ACTIVE

    @property
    def terminal(self) -> bool:
        return self.state == LIFECYCLE_REVOKED

    def to_public_dict(self) -> dict[str, Any]:
        """The document served to a resolver. Every field always present.

        Omitting keys when unknown would make a consumer's ``.get()`` return
        ``None`` for both "not revoked" and "revoked but we lost the details" —
        the ambiguity again, one level down.
        """
        return {
            "version": _LIFECYCLE_STATEMENT_VERSION,
            "state": self.state,
            "subject": self.subject,
            "since": self.since,
            "revoking_authority": self.by,
            "reason": self.reason,
            # ⚠️ False means "this runtime says so", NOT "the owner did not".
            "owner_attested": self.attested,
        }


def lifecycle_statement_bytes(*, subject: str, owner_did: str, state: str, since: str, reason: str | None) -> bytes:
    """The canonical bytes an owner signs to attest a transition.

    Binds the subject, the owner, the state AND the timestamp together, so a
    signature over "revoked" cannot be replayed as a signature over "suspended",
    nor an old revocation re-presented with a fresh time.
    """
    import jcs

    return jcs.canonicalize(
        {
            "version": _LIFECYCLE_STATEMENT_VERSION,
            "subject": subject,
            "owner_did": owner_did,
            "state": state,
            "since": since,
            "reason": reason or "",
        }
    )


def sign_lifecycle_transition(
    owner: OwnerIdentity, *, subject: str, state: str, since: str, reason: str | None = None
) -> str:
    """Owner-attest a transition. Needs the owner phrase, so it is optional."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    message = lifecycle_statement_bytes(subject=subject, owner_did=owner.did, state=state, since=since, reason=reason)
    signature = Ed25519PrivateKey.from_private_bytes(owner.signing_key_bytes()).sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_lifecycle_signature(lifecycle: dict[str, Any], owner_did: str, subject: str) -> bool:
    """True iff the recorded signature verifies under ``owner_did``.

    Any malformed or absent piece is False — an unverifiable attestation claim is
    an UNATTESTED record, never an attested one.
    """
    signature = lifecycle.get("signature")
    if not signature or not owner_did:
        return False
    try:
        from sm_arp import pubkey_from_did

        pubkey_from_did(owner_did).verify(
            base64.b64decode(signature),
            lifecycle_statement_bytes(
                subject=subject,
                owner_did=owner_did,
                state=str(lifecycle.get("state") or ""),
                since=str(lifecycle.get("since") or ""),
                reason=lifecycle.get("reason"),
            ),
        )
        return True
    except Exception:  # noqa: BLE001 — any failure is "not attested"
        return False


def _lifecycle_of(binding: dict[str, Any]) -> dict[str, Any]:
    """The stored lifecycle block. A binding written before this existed has
    none, and reads as ACTIVE — it was consented to and never withdrawn, so
    treating it as anything else would revoke listings nobody withdrew."""
    block = binding.get("lifecycle")
    if isinstance(block, dict) and block.get("state") in LIFECYCLE_STATES:
        return block
    return {"state": LIFECYCLE_ACTIVE, "since": binding.get("established_at"), "by": binding.get("owner_did")}


def resolve_lifecycle(binding: dict[str, Any] | None) -> LifecycleAnswer:
    """Resolve a subject's listing state. ALWAYS answers.

    ``None`` (no binding on disk) is ``not_established`` — a real answer, not a
    failure, and distinguishable from ``revoked``. That distinction is the whole
    point of the unit.
    """
    if not binding:
        return LifecycleAnswer(state=LIFECYCLE_NOT_ESTABLISHED)
    block = _lifecycle_of(binding)
    state = str(block.get("state") or LIFECYCLE_ACTIVE)
    subject = binding.get("subject")
    owner_did = str(binding.get("owner_did") or "")
    attested = (
        verify_lifecycle_signature(block, owner_did, str(subject or ""))
        if state in {LIFECYCLE_SUSPENDED, LIFECYCLE_REVOKED}
        else False
    )
    return LifecycleAnswer(
        state=state,
        subject=subject,
        since=block.get("since"),
        by=block.get("by") or owner_did or None,
        reason=block.get("reason"),
        attested=attested,
    )


def set_lifecycle(
    home: Path,
    state: str,
    *,
    reason: str | None = None,
    owner: OwnerIdentity | None = None,
    authority: str | None = None,
    now: str | None = None,
) -> LifecycleAnswer:
    """Transition the local listing to ``state`` and persist it.

    ``owner`` is optional: supply it (i.e. the user re-entered their phrase) and
    the transition is owner-ATTESTED; omit it and the record is written anyway,
    unattested. Withdrawal must never be blocked on holding a key — see the
    section note.

    ``authority`` records WHO caused the transition when that is not the owner —
    a commerce platform reporting an uninstall, for example. It defaults to the
    owner, which is the only authority the wizard paths ever have.

    ⚠️ An ``authority`` other than the owner can never be attested: the signature
    is over the owner's statement, and a third party has not made one. That is
    the point rather than a limitation — ``owner_attested`` stays false and the
    resolved answer names the platform, so nobody reads a vendor's billing event
    as the owner's withdrawal.

    Raises :class:`LifecycleError` on an illegal transition, notably anything out
    of ``revoked``, which is terminal.
    """
    if state not in LIFECYCLE_STATES:
        raise LifecycleError(f"state must be one of {sorted(LIFECYCLE_STATES)}, got {state!r}")
    binding = load_binding(home)
    if binding is None:
        raise LifecycleError("no owner binding to transition — there is no listing to suspend or revoke")

    current = resolve_lifecycle(binding)
    if current.state == state:
        return current
    allowed = LIFECYCLE_TRANSITIONS.get(current.state, frozenset())
    if state not in allowed:
        raise LifecycleError(
            f"cannot go from {current.state!r} to {state!r}"
            + (" — revocation is terminal; re-listing requires fresh consent" if current.terminal else "")
        )

    stamp = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    owner_did = str(binding.get("owner_did") or "")
    subject = str(binding.get("subject") or "")
    by = authority or owner_did
    if owner is not None:
        # Order matters: the wrong-key case is the more specific answer and must
        # keep its own message rather than being shadowed by the authority check.
        if owner.did != owner_did:
            raise LifecycleError("that owner key did not authorise this listing")
        if authority is not None and authority != owner.did:
            # Signing proves the OWNER acted; recording someone else as the actor
            # would make the signature attest to a claim it does not cover.
            raise LifecycleError("an owner-signed transition cannot name a different authority")
    block: dict[str, Any] = {"state": state, "since": stamp, "by": by, "reason": reason}
    if owner is not None:
        block["signature"] = sign_lifecycle_transition(owner, subject=subject, state=state, since=stamp, reason=reason)

    binding["lifecycle"] = block
    binding_path(home).write_text(json.dumps(binding, indent=2, sort_keys=True))
    return resolve_lifecycle(binding)


def revoke_listing(home: Path, *, reason: str | None = None, owner: OwnerIdentity | None = None) -> LifecycleAnswer:
    """Withdraw consent. Produces ``revoked`` — it does NOT delete the record.

    A retraction has to be observable: deleting the binding would make this
    indistinguishable from a subject that never existed, which is the ambiguity
    the owner-attested rework exists to remove.
    """
    return set_lifecycle(home, LIFECYCLE_REVOKED, reason=reason, owner=owner)


def suspend_listing(
    home: Path,
    *,
    reason: str | None = None,
    owner: OwnerIdentity | None = None,
    authority: str | None = None,
) -> LifecycleAnswer:
    """Pause the listing, reversibly. Distinct from revoked on purpose: a caller
    that sees ``suspended`` learns to come back, where ``revoked`` says do not.

    ``authority`` lets a non-owner actor — a platform reporting an uninstall — be
    recorded as the cause without the record implying the owner said anything."""
    return set_lifecycle(home, LIFECYCLE_SUSPENDED, reason=reason, owner=owner, authority=authority)


def resume_listing(home: Path, *, owner: OwnerIdentity | None = None) -> LifecycleAnswer:
    """Un-suspend. Refuses on a revoked listing — that is what terminal means."""
    return set_lifecycle(home, LIFECYCLE_ACTIVE, owner=owner)


# ── on-disk binding (PUBLIC data + the signed artifacts; never the owner key) ──


def binding_path(home: Path) -> Path:
    return Path(home) / BINDING_FILE


def save_binding(
    home: Path,
    *,
    owner_did: str,
    subject: str,
    anchor: dict[str, str],
    evidence: dict[str, Any],
    grant: dict[str, Any],
) -> Path:
    """Persist the binding. Contains no private key material, by construction.

    ``OwnerIdentity`` is not accepted here on purpose — there is no code path in
    which this function could be handed a private key to write out.
    """
    path = binding_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": "orrery-owner-binding/0.1",
                "owner_did": owner_did,
                "subject": subject,
                "anchor": dict(anchor),
                "evidence": evidence,
                "grant": grant,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return path


def load_binding(home: Path) -> dict[str, Any] | None:
    path = binding_path(home)
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text())
    except Exception:  # noqa: BLE001 — an unreadable binding is an absent one
        return None
    return loaded if isinstance(loaded, dict) else None


def delete_binding(home: Path) -> bool:
    """⚠️ DESTROY the record. This is NOT the withdrawal path — use :func:`revoke_listing`.

    Deleting makes a revocation indistinguishable from a subject that never
    existed, which is exactly the ambiguity the owner-attested rework removed: a caller can no longer
    tell "this business no longer has an agent" from "resolution failed". This
    function is kept for genuine local cleanup (wiping a machine, test
    teardown) and deliberately not called by any withdrawal flow.
    """
    path = binding_path(home)
    if path.exists():
        path.unlink()
        return True
    return False


# ── THE GATE ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GrantVerdict:
    """Whether this agent may be listed publicly, and if not, precisely why.

    ``evidence_type`` and ``evidence_anchor`` describe the evidence that
    satisfied the gate. They are set by ``_evidence_verdict`` from the block it
    accepted and are empty on any refusal. A caller cannot supply them through
    the gate: ``listing_grant_verdict`` builds its own verdict and copies these
    two fields from the evidence verdict, so what they report is the block that
    was actually checked.

    They exist because the gate used to discard the evidence type once it had
    passed. Both an OIDC sign-in and a domain-control challenge produced
    ``GrantVerdict(True, "ok", "listing authorised by <owner did>")``, whose
    detail names the key rather than the evidence, so a caller could not tell a
    listing anchored by a personal sign-in from one anchored by control of a
    domain. Deciding what a published record may assert needs that distinction.
    """

    ok: bool
    reason: str
    detail: str = ""
    # "oidc" or "domain_control" on success; "" otherwise.
    evidence_type: str = ""
    # The durable identifier the accepted evidence anchors: the proven domain for
    # domain control, the provider subject for OIDC. Whose identity the evidence
    # establishes, which is the second input the attestation derivation needs.
    evidence_anchor: str = ""

    def __bool__(self) -> bool:
        return self.ok


def listing_grant_verdict(
    binding: dict[str, Any] | None,
    agent_did: str,
    *,
    now: str | None = None,
) -> GrantVerdict:
    """Fail-closed: a listing is permitted only on a valid owner-signed grant.

    Every refusal is named, because "not ok" with no reason is how a gate ends
    up silently protecting nothing. ``revoked`` and ``suspended`` are their own
    reasons rather than collapsing into "no consent" — the caller has to be able
    to tell a withdrawal from an absence here too, not only at the resolution
    surface.
    """
    if not agent_did:
        return GrantVerdict(False, "no_agent_did", "this agent has no did:key to be the grantee of a consent")
    if not binding:
        return GrantVerdict(False, "no_owner_consent", "no owner binding on disk — nothing has authorised a listing")

    # Lifecycle is checked BEFORE the grant's own validity. A revoked listing
    # whose grant also happens to have expired must still report "revoked": the
    # withdrawal is the operative fact and the more specific answer.
    lifecycle = resolve_lifecycle(binding)
    if lifecycle.state == LIFECYCLE_REVOKED:
        return GrantVerdict(False, "revoked", f"consent was withdrawn at {lifecycle.since or 'an unrecorded time'}")
    if lifecycle.state == LIFECYCLE_SUSPENDED:
        return GrantVerdict(False, "suspended", f"listing suspended at {lifecycle.since or 'an unrecorded time'}")

    grant = binding.get("grant")
    if not isinstance(grant, dict):
        return GrantVerdict(False, "malformed_binding", "binding carries no grant object")

    grantor = grant.get("grantor_did") or ""
    grantee = grant.get("grantee_did") or ""

    # ⚠️ THE CHECK VERIFICATION DOES NOT MAKE. _dat accepts grantor == grantee
    # (measured). If this refusal is ever removed, a self-granted consent passes
    # every remaining check below and the listing looks authorised while being
    # entirely self-asserted. This is the whole point of the module.
    if grantor and grantor == grantee:
        return GrantVerdict(
            False,
            "self_grant",
            "grantor and grantee are the same key — the agent cannot authorise its own listing",
        )
    if grantee != agent_did:
        return GrantVerdict(False, "grantee_mismatch", "the consent was issued to a different agent identity")

    owner_did = binding.get("owner_did") or ""
    if not owner_did or owner_did != grantor:
        return GrantVerdict(False, "owner_mismatch", "binding's owner_did is not the grantor of the grant")
    if owner_did == agent_did:
        return GrantVerdict(False, "self_grant", "the owner principal is the agent's own identity")

    scope = grant.get("scope") or {}
    categories = scope.get("action_categories") or []
    if LISTING_ACTION_CATEGORY not in categories:
        return GrantVerdict(False, "scope", f"grant does not cover {LISTING_ACTION_CATEGORY!r}")

    sig = verify_dat_signature(grant)
    if not sig.ok:
        return GrantVerdict(False, "grant_invalid", f"{sig.stage}: {sig.detail}")

    stamp = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = grant.get("not_after") or ""
    not_before = grant.get("not_before") or ""
    if not not_after or stamp > not_after:
        return GrantVerdict(False, "expired", f"consent expired at {not_after or 'unspecified'}")
    if not_before and stamp < not_before:
        return GrantVerdict(False, "not_yet_valid", f"consent starts at {not_before}")

    evidence_verdict = _evidence_verdict(binding.get("evidence"), owner_did)
    if not evidence_verdict.ok:
        return evidence_verdict

    return GrantVerdict(
        True,
        "ok",
        f"listing authorised by {owner_did[:32]}…",
        evidence_type=evidence_verdict.evidence_type,
        evidence_anchor=evidence_verdict.evidence_anchor,
    )


def _evidence_verdict(evidence: Any, owner_did: str) -> GrantVerdict:
    """The owner principal must be anchored out-of-band, and BOUND TO THIS KEY.

    We do not re-perform the challenge or re-verify the ID token's signature here
    — the registry does, and this module says so plainly rather than implying a
    check it is not making. What we DO enforce is the property both upstream
    verifiers leave optional: that the evidence is about the key that signed the
    grant, and not merely about a subject or a domain.

    For OIDC that is the nonce; for domain control it is the key authorization,
    RECOMPUTED here from ``(token, owner_did)`` rather than read from the claims.
    In both cases the recorded value is treated as untrusted input.
    """
    if not isinstance(evidence, dict):
        return GrantVerdict(False, "no_evidence", "no authority evidence — the owner principal is unanchored")
    if evidence.get("grantor_did") != owner_did:
        return GrantVerdict(False, "evidence_grantor_mismatch", "evidence anchors a different key than the grantor")
    anchor = evidence.get("anchor") or {}
    if not anchor.get("issuer") or not anchor.get("id"):
        return GrantVerdict(False, "evidence_anchor_incomplete", "anchor is missing its issuer or durable id")
    blocks = evidence.get("evidence") or []
    if not isinstance(blocks, list) or not blocks:
        return GrantVerdict(False, "no_evidence", "evidence envelope carries no blocks")
    anchor_id = str(anchor.get("id") or "")
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == _OIDC:
            verdict = _oidc_block_verdict(block)
            # The type travels out only when the block actually satisfied the
            # gate. Recording it on a refusal would let a caller read an
            # evidence type off a verdict that rejected that evidence.
            if not verdict.ok:
                return verdict
            return replace(verdict, evidence_type=_OIDC, evidence_anchor=anchor_id)
        if block.get("type") == _DOMAIN_CONTROL:
            verdict = _domain_block_verdict(block, owner_did, anchor)
            if not verdict.ok:
                return verdict
            # The anchored domain, not the block's claim: _domain_block_verdict
            # has already refused any block whose claimed domain differs from
            # the anchor, so the two agree by the time this line runs.
            return replace(verdict, evidence_type=_DOMAIN_CONTROL, evidence_anchor=anchor_id)
    return GrantVerdict(False, "no_supported_evidence", "no OIDC or domain-control evidence block found")


def _oidc_block_verdict(block: dict[str, Any]) -> GrantVerdict:
    claims = block.get("claims") or {}
    if not claims.get("nonce"):
        return GrantVerdict(
            False,
            "evidence_nonce_missing",
            "OIDC evidence has no nonce, so the token is not bound to the owner key",
        )
    if not claims.get("token"):
        return GrantVerdict(False, "evidence_token_missing", "OIDC evidence carries no token")
    return GrantVerdict(True, "ok")


def _domain_block_verdict(block: dict[str, Any], owner_did: str, anchor: dict[str, Any]) -> GrantVerdict:
    """⚠️ The A-vs-B check, at the gate.

    An HTTP-01 response is served at a deliberately world-readable URL and a
    DNS-01 record is public, so the challenge value is published ON PURPOSE.
    Copying a legitimate one into another envelope is the attack.
    Recomputing the expected value from THIS envelope's owner did means a copied
    challenge carries the wrong thumbprint for whoever copied it, and is refused
    here even if the domain genuinely serves it.
    """
    claims = block.get("claims") or {}
    domain = claims.get("domain")
    token = claims.get("token")
    if not domain or not token:
        return GrantVerdict(False, "evidence_challenge_incomplete", "domain evidence carries no domain or token")
    if domain != anchor.get("id"):
        return GrantVerdict(False, "evidence_anchor_mismatch", "the proven domain is not the anchored one")
    if claims.get("method") not in DOMAIN_CHALLENGES:
        return GrantVerdict(False, "evidence_challenge_method", f"unknown challenge method {claims.get('method')!r}")
    try:
        expected = key_authorization(str(token), owner_did)
    except Exception as e:  # noqa: BLE001 — an unresolvable owner did is a refusal
        return GrantVerdict(False, "evidence_owner_unresolvable", str(e))
    if claims.get("key_authorization") != expected:
        return GrantVerdict(
            False,
            "evidence_challenge_unbound",
            "the challenge is not bound to this owner key — it proves control of a domain by someone else",
        )
    return GrantVerdict(True, "ok")


# ── what a published listing may assert about the owner ──────────────────────

# The four values a record may carry. Three are the evidence types this module
# already distinguishes; the fourth names the case the code previously had no
# word for. They are not a scale and must not be rendered as one: only
# OWNER_DOMAIN_VERIFIED and OWNER_PLATFORM_ATTESTED bear on ownership of a
# business. OWNER_INDIVIDUAL_OIDC is a strong check of a person and no check of
# a business, so ordering it "between" the others would restore the conflation
# these values exist to remove.
OWNER_OPERATOR_VOUCHED = "operator_vouched"
OWNER_INDIVIDUAL_OIDC = "individual_oidc"
OWNER_DOMAIN_VERIFIED = "domain_verified"
# Not reachable: the platform path refuses at platform_install_refusal. Named
# here so the vocabulary is complete and a future implementation has one place
# to attach to.
OWNER_PLATFORM_ATTESTED = "platform_attested"


def owner_attestation(
    verdict: GrantVerdict | None,
    *,
    business_domain: str | None = None,
    business_principal: str | None = None,
) -> str:
    """What was checked about the owner of the listed business.

    Two inputs, not one. Reading ``verdict.evidence_type`` and mapping
    ``domain_control`` to ``domain_verified`` would be wrong in the dangerous
    direction: in the operator-as-owner shape the evidence is genuine domain
    control, but over the operator's domain, not the listed business's. A type
    lookup would publish a verified-business-domain claim that nothing checked.

    So the evidence type decides only which comparison applies, and the
    comparison is against the business being listed:

    * ``domain_verified`` — domain-control evidence whose proven domain is the
      business's own.
    * ``individual_oidc`` — OIDC evidence whose subject is the business's
      principal.
    * ``operator_vouched`` — otherwise.

    ``business_domain`` and ``business_principal`` describe the listed business.
    Nothing in this stack establishes either one today: a tenant is provisioned
    by the operator and its identifier is built from the operator's domain, so
    there is no verified business domain and no recorded business principal to
    compare against. Callers therefore pass neither, and the two stronger values
    are unreachable rather than merely unused. They are parameters instead of
    being omitted so that the condition each value requires is written down
    where it will be read when a business domain becomes real.

    ``operator_vouched`` is not "no evidence". A binding with no valid owner
    evidence is refused by ``listing_grant_verdict`` and nothing is published at
    all. It means evidence exists, is valid, and anchors the operator.
    """
    # The weakest honest value is what a missing or refused verdict produces.
    # A record whose attestation is absent is to be read as unverified, so this
    # never returns "" and never reaches for a stronger value on less evidence.
    if verdict is None or not verdict.ok:
        return OWNER_OPERATOR_VOUCHED

    anchored = (verdict.evidence_anchor or "").strip().lower()
    if verdict.evidence_type == _DOMAIN_CONTROL:
        listed = (business_domain or "").strip().lower()
        if listed and anchored == listed:
            return OWNER_DOMAIN_VERIFIED
        return OWNER_OPERATOR_VOUCHED
    if verdict.evidence_type == _OIDC:
        principal = (business_principal or "").strip().lower()
        if principal and anchored == principal:
            return OWNER_INDIVIDUAL_OIDC
        return OWNER_OPERATOR_VOUCHED
    return OWNER_OPERATOR_VOUCHED


# ── the SMB / platform path: refuse, and say why ─────────────────────────────

# Verified 2026-07-30 against nanda-connect: providers/platform_install.py is a
# 66-line verifier in which SHOPIFY/WIX/TOAST are three string constants and the
# install validator is INJECTED. There is no Shopify, Wix or Toast code anywhere
# in the stack and no partner account to get an install attestation from.
PLATFORM_INSTALL_AVAILABLE = False


def platform_install_refusal(platform: str | None = None) -> str:
    """Why the SMB path cannot establish an owner principal yet.

    This returns a refusal, never a stub success. A faked consent step here
    would be the exact fails-silently-and-looks-green failure this whole module
    exists to prevent, on the surface where it would do the most damage: it
        would publish a business listing that nobody actually authorised.
    """
    named = f" for {platform}" if platform else ""
    return (
        f"Business verification is not available yet{named}.\n"
        "Proving that you own a business needs an install credential from the platform that runs it "
        "(Shopify, Wix, Toast, Square, Booksy). That integration does not exist in this stack — there is "
        "no partner app and no partner account — so there is nothing here that could check the claim.\n"
        "We will not list a business on its own say-so, so this path stops here rather than pretending "
        "it worked."
    )
