"""Discovery: turn a NANDA Index locator into a live agent you can call.

This is the READ half of the index. Registration is a separate, credentialed,
operator act and deliberately does NOT live here (see
``scripts/register_tenant_on_index.py``) — discovery needs no secret, so nothing
an agent imports to *find* a peer should also be able to *create* an org.

WHY THIS MODULE EXISTS. The stack could already write to the index and could
already call another agent (``a2a_client_v2.GoogleA2AClient`` signs as the
caller). What it could not do in library code was the hop between the two: take
a URN and end up at a runtime. The one place that did it was a demo script, and
it hard-coded a single hop shape::

    index -> registry_url/agents/<id> -> card -> agent          # 4 hops

That shape is correct for ``media_type: application/ai-catalog+json``, where
``registry_url`` names a registry that must then be walked. It is WRONG for
``application/a2a-agent-card+json``, where ``registry_url`` IS the card and the
walk is two hops. Both shapes are live on the production index today, so a
resolver that assumes either one silently fails against half the records.
``fetch_card`` therefore dispatches on ``media_type`` and REFUSES a type it does
not know, by name, rather than guessing a hop and returning a plausible wrong
answer.

FAIL CLOSED, AND SAY WHICH CHECK REFUSED. Every failure returns a
:class:`Discovery` whose ``reason`` names the step, because "could not resolve"
collapses "no such agent", "listed but not active", "card is unfetchable" and
"card names no runtime" into one word — and those want four different responses
from a caller.

⚠️ LISTED IS NOT RESOLVABLE, AND RESOLVABLE IS NOT ACTIVE. A record can appear
in ``GET /api/v1/index`` with ``status: active`` and still be refused by
``GET /api/v1/resolve`` (measured on the live index: ``org_id=mahesh``). The
listing is not evidence about the record; only ``resolve`` is. Nothing here
reads the bulk listing.

USAGE::

    from community_member import nanda_index

    found = nanda_index.discover("urn:ai:domain:example.com:agent:booking")
    if not found:
        print(f"cannot reach it: {found.reason} — {found.detail}")
    else:
        with nanda_index.client_for(found, agent_id=me, private_key=sk, public_key=pk) as peer:
            peer.send_task("book_appointment", {...})   # signed as the caller
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import httpx

from . import attestation_copy

DEFAULT_INDEX = "https://api.nandaindex.org"

#: ``registry_url`` points straight at an A2A agent card — a two-hop resolve.
MEDIA_A2A_CARD = "application/a2a-agent-card+json"
#: ``registry_url`` points at a registry that must be walked — the four-hop resolve.
MEDIA_AI_CATALOG = "application/ai-catalog+json"

_RESOLVE_TIMEOUT = 20.0


def index_url(override: str | None = None) -> str:
    """The index base URL: explicit argument, else ``NANDA_INDEX_URL``, else the
    public index.

    ``NANDA_INDEX_URL`` is comma-separated where it is used for *publication*
    (``registry.index_urls``) because an agent may announce to several. Discovery
    asks one index a question, so only the first is used — silently querying a
    second index on a miss would make the answer depend on configuration order.
    """
    if override:
        return override.rstrip("/")
    configured = os.environ.get("NANDA_INDEX_URL", "").strip()
    if configured:
        first = configured.split(",")[0].strip().rstrip("/")
        if first:
            return first
    return DEFAULT_INDEX


@dataclass(frozen=True)
class Discovery:
    """The outcome of resolving one locator, and if it failed, precisely why.

    Falsy on failure, so ``if not found:`` is the idiom. ``reason`` is a stable
    machine-readable token; ``detail`` is for a human.
    """

    ok: bool
    reason: str
    detail: str = ""
    locator: str = ""
    identifier: str = ""
    record: dict[str, Any] = field(default_factory=dict)
    card: dict[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    did: str = ""

    def __bool__(self) -> bool:
        return self.ok

    @property
    def owner_attestation(self) -> str | None:
        """What the resolved record states was checked about the business's owner.

        The raw wire value, or ``None`` when the record states nothing. Read
        from the record this Discovery already carries — no second hop, no
        network — because the value travels in the record and was simply never
        looked at: a caller that resolved a business got a name, an endpoint and
        a did:key, with nothing about who authorised the association.

        Use :attr:`attestation` to say it in words. Comparing raw values is what
        this vocabulary must not be used for: they name three different subjects
        (a business, a person, the host operator) and do not order.
        """
        return attestation_copy.attestation_of(self.record)

    @property
    def attestation(self) -> attestation_copy.AttestationCopy:
        """The owner statement in words, ALWAYS — never ``None``.

        A record that states nothing renders as
        :data:`~community_member.attestation_copy.ABSENT`, and one naming a check
        this build does not know renders as
        :data:`~community_member.attestation_copy.UNRECOGNISED`. Both are
        distinct from every vocabulary value and from each other, so a caller
        that renders this cannot silently show a stranger's listing as though
        somebody had checked it.
        """
        return attestation_copy.rendering_for(self.owner_attestation)


def _refuse(reason: str, detail: str, **kept: Any) -> Discovery:
    return Discovery(ok=False, reason=reason, detail=detail, **kept)


def resolve(
    locator: str,
    *,
    index: str | None = None,
    client: httpx.Client | None = None,
) -> Discovery:
    """``GET /api/v1/resolve?locator=…`` — the index record, or a named refusal.

    Returns a Discovery carrying only ``record``/``identifier``; it makes no
    second hop. ``discover`` is the whole chain.
    """
    if not locator.strip():
        return _refuse("no_locator", "a locator is required")
    base = index_url(index)
    owned = client is None
    http = client or httpx.Client(timeout=_RESOLVE_TIMEOUT)
    try:
        response = http.get(f"{base}/api/v1/resolve", params={"locator": locator})
    except httpx.HTTPError as exc:
        return _refuse("index_unreachable", f"{base}: {exc}", locator=locator)
    finally:
        if owned:
            http.close()

    if response.status_code == 404:
        # The index answers 404 both for "no such record" and for a record that
        # exists but is not active. It does not distinguish them and neither do
        # we — claiming to know which would be inventing information.
        return _refuse(
            "not_resolvable",
            f"the index does not resolve {locator!r} (no such record, or it is not active)",
            locator=locator,
        )
    if response.status_code != 200:
        return _refuse(
            "index_error",
            f"HTTP {response.status_code} from {base}/api/v1/resolve",
            locator=locator,
        )
    try:
        payload = response.json()
    except ValueError:
        return _refuse("index_not_json", f"{base} returned a non-JSON resolve body", locator=locator)
    if not isinstance(payload, dict):
        return _refuse("index_not_json", "resolve did not return an object", locator=locator)

    record = payload.get("index_record")
    if not isinstance(record, dict):
        return _refuse("no_index_record", "resolve returned no index_record", locator=locator)

    status = str(record.get("status") or "")
    if status != "active":
        # Reachable in principle: resolve normally refuses non-active records
        # itself. Checked anyway — this is the property the caller cares about,
        # and relying on an upstream to enforce it is how it stops being true.
        return _refuse(
            "not_active",
            f"the record resolves but its status is {status!r}, not 'active'",
            locator=locator,
            identifier=str(payload.get("identifier") or ""),
            record=record,
        )

    return Discovery(
        ok=True,
        reason="ok",
        locator=locator,
        identifier=str(payload.get("identifier") or record.get("identifier") or ""),
        record=record,
    )


def fetch_card(
    resolved: Discovery,
    *,
    client: httpx.Client | None = None,
) -> Discovery:
    """Follow a resolved record to the agent card, by the hop shape its
    ``media_type`` declares.

    ⚠️ THE MEDIA TYPE CHOOSES THE HOPS. ``application/a2a-agent-card+json`` means
    ``registry_url`` is already the card (two hops total). ``application/ai-catalog+json``
    means it is a registry to walk (four hops). Any other declared type is
    REFUSED by name — a resolver that fell back to "try it as a card" would
    return a wrong answer for an MCP server card or a skill zip.
    """
    if not resolved.ok:
        return resolved
    record = resolved.record
    registry_url = str(record.get("registry_url") or "").strip()
    if not registry_url:
        return _refuse(
            "no_registry_url",
            "the record carries no registry_url, so it names nothing to fetch",
            locator=resolved.locator,
            identifier=resolved.identifier,
            record=record,
        )

    media_type = str(record.get("media_type") or "").strip()
    owned = client is None
    http = client or httpx.Client(timeout=_RESOLVE_TIMEOUT, follow_redirects=True)
    try:
        if media_type == MEDIA_A2A_CARD:
            card = _get_json(http, registry_url)
        elif media_type == MEDIA_AI_CATALOG:
            card = _walk_registry(http, registry_url, resolved.identifier)
        else:
            return _refuse(
                "unsupported_media_type",
                f"media_type {media_type!r} is not a hop shape this resolver knows "
                f"(known: {MEDIA_A2A_CARD}, {MEDIA_AI_CATALOG})",
                locator=resolved.locator,
                identifier=resolved.identifier,
                record=record,
            )
    except _HopError as exc:
        return _refuse(
            exc.reason,
            exc.detail,
            locator=resolved.locator,
            identifier=resolved.identifier,
            record=record,
        )
    finally:
        if owned:
            http.close()

    endpoint = str(card.get("url") or "").strip()
    if not endpoint:
        # The exact defect the personal record on the live index has today: the
        # chain resolves end to end and lands on a card whose url is null. That
        # is a successful resolve of an agent you cannot call, and calling it a
        # success is what makes it hard to notice.
        return _refuse(
            "card_names_no_runtime",
            "the card resolved but its 'url' is empty — there is no endpoint to call",
            locator=resolved.locator,
            identifier=resolved.identifier,
            record=record,
            card=card,
        )

    return Discovery(
        ok=True,
        reason="ok",
        locator=resolved.locator,
        identifier=resolved.identifier,
        record=record,
        card=card,
        endpoint=endpoint.rstrip("/"),
        did=_card_did(card),
    )


class _HopError(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _get_json(http: httpx.Client, url: str) -> dict[str, Any]:
    try:
        response = http.get(url)
    except httpx.HTTPError as exc:
        raise _HopError("card_unreachable", f"{url}: {exc}") from exc
    if response.status_code != 200:
        raise _HopError("card_unfetchable", f"HTTP {response.status_code} fetching {url}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise _HopError("card_not_json", f"{url} did not return JSON") from exc
    if not isinstance(payload, dict):
        raise _HopError("card_not_json", f"{url} did not return a JSON object")
    return payload


def _walk_registry(http: httpx.Client, registry_url: str, identifier: str) -> dict[str, Any]:
    """The catalog shape: registry -> agent entry -> card."""
    if not identifier:
        raise _HopError("no_identifier", "a catalog record needs an identifier to look up")
    entry = _get_json(http, f"{registry_url.rstrip('/')}/agents/{identifier}")
    card_url = str(entry.get("url") or "").strip()
    if not card_url:
        raise _HopError("registry_entry_incomplete", f"the registry entry for {identifier} names no card url")
    return _get_json(http, card_url)


def _card_did(card: dict[str, Any]) -> str:
    """The agent's ``did:key`` as the card states it.

    Two independent places carry it — ``authentication.credentials`` and the
    ``x-nanda`` extension. Preferring the authentication block is deliberate:
    it is the one a caller would actually authenticate against.
    """
    auth = card.get("authentication")
    if isinstance(auth, dict):
        credentials = str(auth.get("credentials") or "").strip()
        if credentials.startswith("did:"):
            return credentials
    extension = card.get("x-nanda") or card.get("x_nanda")
    if isinstance(extension, dict):
        did = str(extension.get("did") or "").strip()
        if did.startswith("did:"):
            return did
    return ""


def discover(
    locator: str,
    *,
    index: str | None = None,
    client: httpx.Client | None = None,
) -> Discovery:
    """URN in, callable agent out — ``resolve`` then ``fetch_card``.

    The success case carries ``endpoint`` (where to call) and ``did`` (who it
    claims to be). Hand it to :func:`client_for` to actually call it.
    """
    return fetch_card(resolve(locator, index=index, client=client), client=client)


def did_matches_record(found: Discovery) -> bool:
    """Whether the card's did:key is the one the index record vouches for.

    The index record's ``trust_manifest.identity`` and the card's
    ``authentication.credentials`` are two INDEPENDENT statements of the same
    identity, published through different channels. Agreement is worth checking
    precisely because the card is served by whoever runs the runtime, while the
    record is served by the index — a card that quietly changed its key would
    otherwise be indistinguishable from the one that was registered.

    False when either side is silent: absence is not agreement.
    """
    manifest = found.record.get("trust_manifest")
    if not isinstance(manifest, dict):
        return False
    claimed = str(manifest.get("identity") or "").strip()
    return bool(claimed) and bool(found.did) and claimed == found.did


def client_for(
    found: Discovery,
    *,
    agent_id: str | None = None,
    private_key: str | None = None,
    public_key: str | None = None,
    sig_scheme: str | None = None,
    timeout: float = 30.0,
) -> Any:
    """A signed A2A client pointed at a discovered agent.

    This is the JOIN, not a new client: the calling and signing are
    ``a2a_client_v2.GoogleA2AClient`` exactly as they already were. Discovery's
    only contribution is having learned the endpoint from a URN instead of being
    handed a URL by somebody.
    """
    if not found.ok:
        raise ValueError(f"cannot build a client for an unresolved agent: {found.reason} — {found.detail}")
    from .a2a_client_v2 import GoogleA2AClient

    return GoogleA2AClient(
        found.endpoint,
        agent_id=agent_id,
        private_key=private_key,
        public_key=public_key,
        sig_scheme=sig_scheme,
        timeout=timeout,
    )
