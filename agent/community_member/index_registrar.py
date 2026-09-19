"""Register ONE provisioned SMB tenant on a NANDA Index — the write half.

Kept apart from :mod:`community_member.nanda_index` on purpose. Discovery needs
no secret; registration needs an account password and can create rows on a live
third party. Two modules means an agent that imports discovery to find a peer
cannot reach the surface that creates orgs.

WHY NOT ``server/nanda_registry.register_on_index_v2``
-----------------------------------------------------
Measured, not assumed. That function registers ONE HARDCODED ORG — ITSELF::

    org_id       <- AGENT_ID (module global, set by init())
    hosting_path <- "registry"                 # hardcoded
    registry_url <- the SERVER's public URL
    media_type   <- "application/ai-catalog+json"

It takes no arguments, so "register N tenants" is a signature change, not a
config change. Worse, ``hosting_path=registry`` PROMISES hop-2 surfaces —
``GET /agents/<id>`` and ``/.well-known/ai-catalog.json`` — which live in
``server/`` and resolve against the chapter's member map. An ``smb_host`` tenant
is in neither: ``smb_host`` serves five routes and none of them is a registry.
Pointing a ``registry`` record at it would produce a record that resolves to a
404 on hop two.

SIBLING, NOT SHARED CORE — and the boundary is why. Extracting a core both
callers pass a record into would require ``server/`` to import from ``agent/``.
That dependency edge does not exist: ``server/`` has ZERO runtime imports of
``community_member`` (its ``aae_export.py`` says outright that it "mirrors
agent/community_member/aae_export.py"), because the two are separately deployed.
Adding the edge to share ~15 lines of "POST and read the status code" would buy
less than it costs, and bending ``register_on_index_v2`` with flags until it
serves both is the outcome that leaves neither caller legible. So: a sibling
that builds a tenant's record, next to ``host39.py``, which is the same kind of
thing (an upstream publishing client with credentials).

⚠️ THE RECORD SAYS TWO DIFFERENT THINGS, AND THEY MUST NOT BE CONFLATED.
``identifier: urn:ai:domain:<our-domain>:agent:<slug>`` says WHO VOUCHED for the
listing — us, the host operator, because it is our domain that is verified.
``trust_manifest.identity: did:key:…`` says WHO SIGNS THE RECEIPTS — the tenant.
The barber does not own our domain and nothing here may imply they do.

⚠️ NO PRECEDENT FOR THE did:key. Across all 251 live records the string
``did:key`` appears zero times: ``identityType: "did"`` is common but every
instance describes a bulk PUBLISHER's identity, not a per-agent key. Putting a
tenant's ``did:key`` in ``trust_manifest.identity`` is a first, not a convention
being followed.

⚠️ VERIFY BY RESOLVE, NEVER BY THE 201. A live record (``org_id=mahesh``) is
``status: active`` in the bulk listing and "not found or is not active" at
``resolve``. A 201 establishes nothing about discoverability, so
:func:`confirm_by_resolve` is the success condition and the 201 is not.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

BASE_URL_ENV = "INDEX_BASE_URL"
EMAIL_ENV = "INDEX_ACCOUNT_EMAIL"
PASSWORD_ENV = "INDEX_ACCOUNT_PASSWORD"
DOMAIN_ENV = "ORG_DOMAIN"
CONTACT_ENV = "ORG_CONTACT_EMAIL"

MEDIA_A2A_CARD = "application/a2a-agent-card+json"

#: ``hosting_path`` is OMITTED by default, and that is a decision rather than an
#: oversight. The live enum is ``registry | dns-aid | smb | personal``; the field
#: is optional; and it is WRITE-ONLY — absent from every read schema and from all
#: 251 live records — so no amount of reading reveals what a value does.
#:
#: What is documented: ``GET /api/v1/verify-email`` "activates personal orgs;
#: others still need domain verification". We WANT domain verification, because
#: it is verified once per domain instead of once per business. So sending
#: ``personal`` would actively request the activation we do not want, and ``smb``
#: — which looks apt by name — has unknown activation behaviour. Omitting sends
#: no claim at all, which is the only honest option for a field whose effect we
#: cannot observe. Override deliberately via ``hosting_path=`` if a write ever
#: settles it.
HOSTING_PATH: str | None = None

_ORG_ID = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
_TIMEOUT = 20.0


class IndexConfigError(RuntimeError):
    """The registrar is not configured well enough to make a call."""


class IndexAuthError(RuntimeError):
    """The index refused the account credential."""


def _env(name: str) -> str:
    """An unset and an empty variable are the same thing here, deliberately —
    ``REGISTRY_URL=`` once meant "live production" on a neighbouring path."""
    return os.environ.get(name, "").strip()


def slugify(business_name: str) -> str:
    """A business name as an index-legal ``org_id`` / URN slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", business_name.strip().lower()).strip("-")
    return slug


def tenant_description(business_name: str) -> str:
    """The description for an SMB tenant — served on its A2A card and
    AgentFacts (``smb_host.main._build_tenant_card`` / ``agent_facts``), and
    used here as the fallback when a caller of :func:`build_org_record`
    supplies none.

    NOT "sovereign": the tenant does not hold its own key. One operator
    passphrase decrypts every tenant on the host it runs on, and the tenant's
    process is that host's process, not its own. Single source so the card,
    AgentFacts, and (absent an override) the index record describe one
    tenant the same way.
    """
    return f"Agent for {business_name}, hosted on this service"


@dataclass(frozen=True)
class RegistrarConfig:
    """Everything the registrar needs, read from the environment only.

    Never accepts a credential as an argument: argv is world-readable on this box.
    """

    base_url: str
    email: str
    password: str
    domain: str
    contact_email: str

    @classmethod
    def from_env(cls) -> RegistrarConfig:
        base = _env(BASE_URL_ENV)
        email = _env(EMAIL_ENV)
        domain = _env(DOMAIN_ENV)
        return cls(
            base_url=base.rstrip("/"),
            email=email,
            password=_env(PASSWORD_ENV),
            domain=domain,
            contact_email=_env(CONTACT_ENV) or email,
        )


def missing_config(cfg: RegistrarConfig | None = None) -> list[str]:
    """Which variables are unset — named individually, so the message is actionable.

    Note ``PASSWORD_ENV`` is expected to be missing until a human fills it. That
    is the ordinary state of this repo, not an error, which is why the dry-run
    path does not consult this function at all.
    """
    cfg = cfg or RegistrarConfig.from_env()
    missing = []
    if not cfg.base_url:
        missing.append(BASE_URL_ENV)
    if not cfg.email:
        missing.append(EMAIL_ENV)
    if not cfg.password:
        missing.append(PASSWORD_ENV)
    if not cfg.domain:
        missing.append(DOMAIN_ENV)
    return missing


def registration_configured(cfg: RegistrarConfig | None = None) -> bool:
    return not missing_config(cfg)


# ── the record ───────────────────────────────────────────────────────────────


def _owner_attestation(grant_verdict: Any) -> str:
    """The attestation value for a record, derived and never supplied.

    Imported inside the function because ``owner`` pulls in the signing stack,
    and this module is imported by the dry-run path that must work without it.
    """
    from . import owner

    return owner.owner_attestation(grant_verdict)


def build_org_record(
    *,
    tenant_id: str,
    business_name: str,
    did: str,
    card_url: str,
    domain: str,
    contact_email: str,
    service_type: str | None = None,
    description: str | None = None,
    slug: str | None = None,
    version: str | None = None,
    hosting_path: str | None = HOSTING_PATH,
    grant_verdict: Any = None,
) -> dict[str, Any]:
    """The exact ``POST /api/v1/orgs`` body for one tenant. Pure — no network.

    Pure on purpose: the dry run and the real registration build the body with
    THIS function, so what a reviewer approves in a dry run is byte-for-byte
    what is sent. A dry run that rendered an approximation would be worse than
    no dry run.

    ⚠️ ``catalog_metadata`` CARRIES THE ``org.projectnanda.*`` CONVENTION, AND
    THAT MAPPING IS AN INFERENCE. Reads expose ``metadata`` and ``data``; writes
    accept ``catalog_metadata`` and ``entry_data``. Neither write name appears on
    read and neither read name appears on write, so the pairing is near-certain —
    but it is unconfirmed until a real registration is read back. The post-write
    check reports whether the convention keys survived rather than assuming they did.

    ``grant_verdict`` is the ``owner.GrantVerdict`` from the listing gate, when
    the caller has consulted it. It carries evidence, not a conclusion: the
    ``org.projectnanda.ownerAttestation`` value is derived here by
    ``owner.owner_attestation`` and there is no parameter that sets it. Passing
    no verdict yields the weakest honest value rather than omitting the field.
    """
    slug = slug or slugify(business_name) or tenant_id
    tags = ["smb", "agent"]
    if service_type:
        tags.extend(t for t in slugify(service_type).split("-") if t)

    record: dict[str, Any] = {
        "org_id": slug,
        "display_name": business_name,
        "domain": domain,
        "contact_email": contact_email,
        # registry_url IS the card: media_type a2a-agent-card+json means a
        # resolver fetches this URL and is done. No registry to walk, which is
        # exactly why smb_host (which serves no registry surfaces) can be the target.
        "registry_url": card_url,
        "media_type": MEDIA_A2A_CARD,
        "identifier": f"urn:ai:domain:{domain}:agent:{slug}",
        "description": description or tenant_description(business_name),
        "tags": sorted(set(tags))[:20],
        # WHO VOUCHED. The publisher is the host operator, identified by the
        # domain that is actually verified. Saying the business is the publisher
        # would assert a domain claim it cannot back.
        "publisher": {
            "identifier": f"urn:ai:domain:{domain}",
            "displayName": domain,
            "identityType": "dns",
        },
        # WHO SIGNS. The tenant's own key, independent of the vouching above.
        "trust_manifest": {
            "identity": did,
            "identityType": "did",
        },
        "catalog_metadata": {
            "org.projectnanda.agentCardHost": _host_of(card_url),
            "org.projectnanda.resolutionRole": "smb-agent-card",
            "org.projectnanda.preferredDiscovery": "nandaindex",
            "org.projectnanda.nandaIndexRole": "optional-fallback-entry",
            "org.projectnanda.auth.metadata": "public",
            "org.projectnanda.auth.execution": "booking_session_required",
            "org.projectnanda.runtime.provider": domain,
            # What was checked about the owner of this business, derived from the
            # evidence the listing gate accepted. Always present: absent-and-valid
            # is not a state this field has, and a reader who does not find it
            # cannot tell "nobody checked" from "the writer forgot".
            #
            # The business's own domain and principal are deliberately not passed.
            # `domain` here is the operator's verified domain — it is what the
            # publisher block and the identifier are built from — so handing it to
            # the derivation as the business's domain would manufacture exactly
            # the domain_verified claim that nothing checked.
            "org.projectnanda.ownerAttestation": _owner_attestation(grant_verdict),
        },
    }
    if version:
        record["version"] = version
    if hosting_path:
        record["hosting_path"] = hosting_path
    return record


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc or url


def record_problems(record: dict[str, Any]) -> list[str]:
    """Everything the index would reject, checked BEFORE any network call.

    Fail before the write, not after: a rejected POST against a live third party
    is a request that still happened.
    """
    problems: list[str] = []
    org_id = str(record.get("org_id") or "")
    if not _ORG_ID.match(org_id) or not (2 <= len(org_id) <= 64):
        problems.append(f"org_id {org_id!r} does not match ^[a-z0-9][a-z0-9-]*[a-z0-9]$ (2-64 chars)")
    if not str(record.get("display_name") or "").strip():
        problems.append("display_name is empty")
    if not str(record.get("contact_email") or "").strip():
        problems.append("contact_email is empty")
    registry_url = str(record.get("registry_url") or "")
    if len(registry_url) > 512:
        problems.append("registry_url exceeds the index's 512-character limit")
    if not registry_url.startswith(("http://", "https://")):
        problems.append(f"registry_url {registry_url!r} is not an absolute URL")
    if registry_url.startswith("http://") or "127.0.0.1" in registry_url or "localhost" in registry_url:
        # A loopback card URL registered on the PUBLIC index is a record nobody
        # else can resolve. It would still return 201.
        problems.append(
            f"registry_url {registry_url!r} is not publicly reachable — the record would "
            "resolve to an address no other party can fetch"
        )
    did = str((record.get("trust_manifest") or {}).get("identity") or "")
    if not did.startswith("did:key:"):
        problems.append(f"trust_manifest.identity {did!r} is not a did:key")
    return problems


# ── the client ───────────────────────────────────────────────────────────────


@dataclass
class IndexRegistrarClient:
    """Authenticated calls against one NANDA Index. Nothing here auto-fires."""

    cfg: RegistrarConfig
    timeout: float = _TIMEOUT
    _token: str = field(default="", repr=False)

    @classmethod
    def from_env(cls) -> IndexRegistrarClient:
        cfg = RegistrarConfig.from_env()
        missing = missing_config(cfg)
        if missing:
            raise IndexConfigError(
                "refusing to build an index registrar client; unset: "
                + ", ".join(missing)
                + ". There is deliberately no default target and no unauthenticated fallback."
            )
        return cls(cfg=cfg)

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout)

    def authenticate(self, http: httpx.Client) -> str:
        """A JWT via register, falling back to login on 409 (the account exists).

        The account under this address already exists, so 409-then-login is the
        expected path rather than the exceptional one.
        """
        if self._token:
            return self._token
        base = self.cfg.base_url
        response = http.post(
            f"{base}/auth/register",
            json={"email": self.cfg.email, "password": self.cfg.password, "display_name": self.cfg.domain},
        )
        token = ""
        if response.status_code == 201:
            token = str(response.json().get("token") or "")
        elif response.status_code == 409:
            login = http.post(f"{base}/auth/login", json={"email": self.cfg.email, "password": self.cfg.password})
            if login.status_code == 200:
                token = str(login.json().get("token") or "")
            elif login.status_code in (400, 401):
                raise IndexAuthError(
                    f"the index rejected the credential in ${PASSWORD_ENV} for {self.cfg.email} "
                    f"(HTTP {login.status_code}). The account exists, so the password is wrong."
                )
        if not token:
            raise IndexAuthError(
                f"could not obtain a JWT from {base} (register={response.status_code}); "
                "no org can be created without one"
            )
        self._token = token
        return token

    def _auth_headers(self, http: httpx.Client) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.authenticate(http)}"}

    def create_org(self, record: dict[str, Any]) -> dict[str, Any]:
        """``POST /api/v1/orgs``. Returns ``{status, org_id, response}``.

        ``status`` is ``created`` | ``exists``; NEITHER means discoverable. The
        caller must confirm with :func:`confirm_by_resolve`.
        """
        problems = record_problems(record)
        if problems:
            raise IndexConfigError(
                "refusing to send a record the index would reject or that would be "
                "unresolvable:\n  - " + "\n  - ".join(problems)
            )
        with self._client() as http:
            response = http.post(f"{self.cfg.base_url}/api/v1/orgs", json=record, headers=self._auth_headers(http))
            org_id = str(record["org_id"])
            if response.status_code == 201:
                return {"status": "created", "org_id": org_id, "response": _json_or_text(response)}
            if response.status_code == 409:
                return {"status": "exists", "org_id": org_id, "response": _json_or_text(response)}
            raise IndexConfigError(f"POST /api/v1/orgs returned {response.status_code}: {response.text[:300]}")

    def domain_challenge(self, org_id: str) -> dict[str, Any]:
        """``POST /orgs/{org_id}/domain-challenge`` — the TXT record a human publishes.

        Returns the index's own ``{record_name, record_type, record_value,
        expires_at}``. That value is handed to the human verbatim; nothing here
        can publish DNS.
        """
        with self._client() as http:
            response = http.post(
                f"{self.cfg.base_url}/api/v1/orgs/{org_id}/domain-challenge",
                headers=self._auth_headers(http),
            )
            if response.status_code not in (200, 201):
                raise IndexConfigError(
                    f"domain-challenge for {org_id} returned {response.status_code}: {response.text[:300]}"
                )
            return response.json()

    def verify_domain(self, org_id: str) -> dict[str, Any]:
        """``POST /orgs/{org_id}/verify-domain`` — ask the index to read the TXT."""
        with self._client() as http:
            response = http.post(
                f"{self.cfg.base_url}/api/v1/orgs/{org_id}/verify-domain",
                headers=self._auth_headers(http),
            )
            if response.status_code not in (200, 201):
                raise IndexConfigError(
                    f"verify-domain for {org_id} returned {response.status_code}: {response.text[:300]}"
                )
            return response.json()


def _json_or_text(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text[:300]


# ── the success condition ────────────────────────────────────────────────────


def confirm_by_resolve(record: dict[str, Any], *, index: str | None = None) -> Any:
    """THE success condition: does the index resolve our URN to our card?

    Not the 201, and not presence in the bulk listing — a live record is
    ``active`` in the listing and unresolvable at ``resolve`` today. This calls
    the same discovery path an outside caller would use, so a pass means an
    outside caller can do it too.
    """
    from . import nanda_index

    return nanda_index.discover(str(record.get("identifier") or ""), index=index or _env(BASE_URL_ENV) or None)


def confirmation_problems(record: dict[str, Any], found: Any) -> list[str]:
    """What is still wrong AFTER a resolve that returned our record.

    Resolving is necessary and not sufficient: the record can resolve while
    carrying the wrong card, losing the ``org.projectnanda.*`` convention (the
    ``catalog_metadata`` -> ``metadata`` mapping is inferred, not confirmed), or
    dropping the ``did:key`` nobody has published before.
    """
    problems: list[str] = []
    if not found.ok:
        return [f"resolve refused: {found.reason} — {found.detail}"]

    expected_card = str(record.get("registry_url") or "")
    actual_card = str(found.record.get("registry_url") or "")
    if expected_card != actual_card:
        problems.append(f"registry_url came back as {actual_card!r}, not {expected_card!r}")

    expected_did = str((record.get("trust_manifest") or {}).get("identity") or "")
    manifest = found.record.get("trust_manifest")
    actual_did = str(manifest.get("identity") or "") if isinstance(manifest, dict) else ""
    if actual_did != expected_did:
        problems.append(
            f"trust_manifest.identity came back as {actual_did!r}, not the tenant's did — "
            "no live record carries a did:key, so this is the field most likely to be dropped"
        )
    if found.did and expected_did and found.did != expected_did:
        problems.append(f"the card's did ({found.did}) is not the did the index record vouches for ({expected_did})")

    sent_meta = record.get("catalog_metadata") or {}
    got_meta = found.record.get("metadata")
    if sent_meta and not isinstance(got_meta, dict):
        problems.append(
            "catalog_metadata did not come back as metadata — the inferred "
            "catalog_metadata -> metadata mapping is wrong"
        )
    elif sent_meta and isinstance(got_meta, dict):
        lost = sorted(set(sent_meta) - set(got_meta))
        if lost:
            problems.append(f"the org.projectnanda.* convention keys did not survive: {lost}")
    return problems


# ── the opt-in gate ──────────────────────────────────────────────────────────


def listing_refusal(tenant_home: Path) -> str | None:
    """Why this tenant may NOT be listed, or None if it may.

    ⚠️ THIS INVENTS NO VOCABULARY. The stack already had one, and it is stronger
    than a flag: ``registry.should_announce`` requires a valid OWNER-SIGNED
    listing grant naming this agent's ``did:key`` as grantee, plus
    ``COMMUNITY_MEMBER_NO_REGISTRY`` as a hard veto on top. Opt-out and opt-in
    are not two competing concepts there — the grant IS the opt-in and the
    variable is a veto that overrides even a valid grant.

    It already answers per tenant with no change: an ``smb_host`` tenant is an
    ``AgentContext`` pinned to its own home, so the binding it reads is that
    tenant's. The three properties the listing rule needs fall out of the
    existing gate rather than needing new mechanism:

    * DEFAULT FALSE — a freshly provisioned tenant has no binding, and the gate
      refuses it by name (``no_owner_consent``).
    * NO INHERITANCE — a grant names ONE grantee did, so a parent's grant fails
      ``grantee_mismatch`` against a child's key. Inheritance is not forbidden by
      a rule that could be forgotten; it is unrepresentable.
    * EXPLICIT, NEVER A SIDE EFFECT — this is consulted by the registrar, which
      is a separate process from provisioning. ``smb_host`` never calls it.
    """
    from . import owner, registry
    from .config import Config

    config = Config.load(home=Path(tenant_home))
    if registry.is_opted_out():
        return "COMMUNITY_MEMBER_NO_REGISTRY is set — the operator asked to stay off public discovery"
    verdict = owner.listing_grant_verdict(owner.load_binding(Path(tenant_home)), registry.agent_did_key(config))
    if not verdict:
        return f"{verdict.reason}: {verdict.detail}"
    return None


def listing_verdict(tenant_home: Path) -> Any:
    """The listing gate's verdict for this tenant, evidence fields included.

    ``listing_refusal`` answers the yes/no question and discards everything else.
    A record has to state what was checked about the owner, which needs the
    verdict itself. Both call the same gate, so the two cannot disagree about
    whether a tenant may be listed.
    """
    from . import owner, registry
    from .config import Config

    config = Config.load(home=Path(tenant_home))
    return owner.listing_grant_verdict(owner.load_binding(Path(tenant_home)), registry.agent_did_key(config))
