#!/usr/bin/env python3
"""Publish a provisioned SMB tenant's A2A agent card to host39 (Leg B).

    provision (smb_host)  ->  POST /cards (host39)  ->  unauthenticated GET proof

This is an **explicit operator trigger**. Nothing in Orrery auto-publishes: it is
not wired into app startup and not wired into ``POST /provision``, because the
credential and the target must both be a deliberate choice.

THE BUSINESS CONSENTS, NOT ONLY THE OPERATOR. A hosted card is a public listing
of the business, so this publishes only with the business's own owner-signed
listing grant on file — the same gate ``register_tenant_on_index.py`` consults
(``index_registrar.listing_refusal``): the grant names the tenant's ``did:key``
as grantee, a fresh tenant has none, and ``COMMUNITY_MEMBER_NO_REGISTRY`` vetoes
even a valid one. The grant lives in the tenant's home, so pass ``--tenant-home``
or run where the host's ``$SMB_HOST_DATA_DIR`` is; publishing from a box that
cannot see the home is refused by name, not quietly allowed. ``--dry-run``
never needs the grant — it prints the body and sends nothing. Leg B stops at
host39 — this script makes NO ``api.nandaindex.org`` call (that is Leg C, which
has an unresolved architecture question).

WHICH ARTIFACT: host39 takes the **A2A agent card**, not canonical NANDA
AgentFacts — its ``POST /cards`` schema is ``additionalProperties: false`` over a
flattened A2A field set. AgentFacts keeps its own home at the runtime's
``GET /agentfacts.json``; the published card points back at it through the
``x-nanda`` bag. See ``community_member/host39.py`` for the full argument.

CREDENTIALS — environment only::

    export HOST39_BASE_URL=https://agentcards.host39.org   # no default, on purpose
    export HOST39_TOKEN=...                                # or:
    export HOST39_EMAIL=... HOST39_PASSWORD=...
    export SMB_HOST_PROVISION_TOKEN=...                    # if the smb_host gates provisioning

An unset var and an empty var are treated identically, and neither falls back to
a default target or to an unauthenticated call. Never pass a credential as a
command-line argument — argv is visible to every process on the box.

USAGE::

    # publish the card of a tenant already served by a live smb_host
    scripts/publish_host39_card.py --tenant-card-url https://smb.example.org/t/bobs/.well-known/agent.json

    # or provision a fresh tenant on a live smb_host first, then publish it
    scripts/publish_host39_card.py --smb-host https://smb.example.org --business-name "Bob's Barbers"

    # dry run: print the exact POST /cards body and exit without calling host39
    scripts/publish_host39_card.py --tenant-card-url ... --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "agent"))

import httpx
from community_member import host39
from community_member import index_registrar as registrar


def _slug_from(value: str) -> str:
    """A host39-legal slug from a tenant id or business name."""
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def fetch_tenant_card(url: str, *, timeout: float = 20.0) -> dict[str, Any]:
    """GET a tenant's A2A card from a live smb_host."""
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    if response.status_code != 200:
        raise SystemExit(
            f"could not fetch the tenant card at {url}: HTTP {response.status_code}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise SystemExit(f"{url} did not return a JSON object")
    return payload


def provision_tenant(
    smb_host: str, business_name: str, service_type: str | None, contact: str
) -> dict[str, Any]:
    """``POST /provision`` on a live smb_host. Returns its response.

    NOTE the recovery phrase in that response is a one-time secret: it is used
    only to be dropped here, never printed and never persisted.
    """
    base = smb_host.rstrip("/")
    # smb_host requires a delivery channel at claim time: a business that cannot
    # be reached cannot receive a booking. This script provisions on an
    # operator's behalf, so the operator supplies it.
    body: dict[str, Any] = {"business_name": business_name, "contact": contact}
    if service_type:
        body["service_type"] = service_type
    # A host bound to a public address gates provisioning on a shared secret
    # (SMB_HOST_PROVISION_TOKEN in smb_host/main.py); one bound to loopback does
    # not. Read from the environment only, never argv — argv is visible to every
    # process on the box — and send it only when the operator set one, so the
    # loopback shape keeps working with nothing configured.
    headers: dict[str, str] = {}
    provision_token = os.environ.get("SMB_HOST_PROVISION_TOKEN", "").strip()
    if provision_token:
        headers["Authorization"] = f"Bearer {provision_token}"
    response = httpx.post(f"{base}/provision", json=body, headers=headers, timeout=60.0)
    if response.status_code == 401:
        raise SystemExit(
            f"POST {base}/provision returned 401: that host gates provisioning on a shared secret. "
            f"Set SMB_HOST_PROVISION_TOKEN to the value the host was started with."
        )
    if response.status_code not in (200, 201):
        raise SystemExit(
            f"POST {base}/provision returned {response.status_code}: {response.text[:300]}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise SystemExit("provision did not return an object")
    payload.pop("recovery_phrase", None)  # a secret we neither need nor want to hold
    return payload


def _tenant_home_for(args, *, tenant_id: str) -> Path | None:
    """The tenant's on-disk home, if this box is the one running the host.

    Same rule as ``register_tenant_on_index.py``: the listing grant lives in the
    tenant's home, so the gate can only be consulted where that home is, and
    publishing from elsewhere is refused rather than allowed to skip it.
    """
    if args.tenant_home:
        return Path(args.tenant_home)
    data_dir = os.environ.get("SMB_HOST_DATA_DIR", "").strip()
    if data_dir and tenant_id:
        candidate = Path(data_dir) / tenant_id
        if candidate.is_dir():
            return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish a provisioned SMB tenant's A2A agent card to host39 (Leg B).",
        epilog="Credentials come from HOST39_* environment variables only — never argv.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--tenant-card-url",
        help="URL of a tenant's A2A card, e.g. https://smb.example.org/t/<tenant>/.well-known/agent.json",
    )
    source.add_argument(
        "--smb-host", help="base URL of a live smb_host to provision a fresh tenant on"
    )
    parser.add_argument("--business-name", help="required with --smb-host")
    parser.add_argument(
        "--contact",
        help=(
            "required with --smb-host: where the business receives its bookings "
            "(an https webhook URL or an email address)"
        ),
    )
    parser.add_argument(
        "--record-on-org",
        metavar="ORG_BASE_URL",
        help=(
            "after a VERIFIED publish, record the publication on the org so its AI "
            "Catalog will advertise this card. Needs ORG_ADMIN_TOKEN. Without "
            "this the card exists but the catalog keeps omitting the member — which is "
            "the safe direction: the catalog never advertises what it cannot back."
        ),
    )
    parser.add_argument(
        "--record-agent-id",
        help="the member's agent_id on the org; required with --record-on-org",
    )
    parser.add_argument(
        "--service-type", help="optional service category, e.g. 'barber'"
    )
    parser.add_argument(
        "--slug", help="host39 slug (default: derived from the card name / tenant id)"
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="publish with is_public=false (host39 will not serve it publicly)",
    )
    parser.add_argument(
        "--no-nanda-extension",
        action="store_true",
        help="omit the x-nanda bag (drops the pointer to canonical AgentFacts)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the POST /cards body and exit — makes no host39 call",
    )
    parser.add_argument(
        "--tenant-home",
        help="the tenant's on-disk home, for the owner's listing-grant check "
        "(default: $SMB_HOST_DATA_DIR/<tenant id>)",
    )
    args = parser.parse_args(argv)

    if args.smb_host and not args.contact:
        print(
            "--smb-host needs --contact: the host requires a delivery channel at claim time, "
            "because a business that cannot be reached cannot receive a booking",
            file=sys.stderr,
        )
        return 2
    if args.smb_host and not args.business_name:
        parser.error("--business-name is required with --smb-host")

    # ── obtain the tenant card ───────────────────────────────────────────────
    if args.smb_host:
        provisioned = provision_tenant(
            args.smb_host, args.business_name, args.service_type, args.contact
        )
        tenant_id = str(provisioned["tenant_id"])
        endpoint = str(provisioned["endpoint"])
        print(f"provisioned tenant {tenant_id} at {endpoint}")
        card = fetch_tenant_card(f"{endpoint}/.well-known/agent.json")
        default_slug = tenant_id
    else:
        card = fetch_tenant_card(args.tenant_card_url)
        default_slug = _slug_from(str(card.get("name") or "")) or "agent"

    slug = args.slug or default_slug

    body = host39.a2a_card_to_host39_body(
        card,
        slug=slug,
        is_public=not args.private,
        include_nanda_extension=not args.no_nanda_extension,
    )

    # The card's x-nanda bag points at canonical AgentFacts on the runtime. host39
    # stores no AgentFacts, so a dead pointer means the published card links
    # nowhere for a NANDA-aware reader. Warn loudly; do not fail (the card is
    # still valid A2A, and the missing route is a runtime-side gap, not a Leg B one).
    facts_warning = host39.check_agentfacts_pointer(body)
    if facts_warning:
        print(f"WARNING: {facts_warning}", file=sys.stderr)

    if args.dry_run:
        print("POST /cards body (dry run — no host39 call made):")
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0

    # ── the business's opt-in, before anything is sent ───────────────────────
    home = _tenant_home_for(args, tenant_id=default_slug)
    if home is None:
        print(
            "refusing to publish: cannot find this tenant's home, so the owner's listing grant "
            "cannot be checked. Pass --tenant-home, or run this where the host's "
            "$SMB_HOST_DATA_DIR is. Publishing a business's card without its grant is the one "
            "thing this path must not do.",
            file=sys.stderr,
        )
        return 3
    refusal = registrar.listing_refusal(home)
    if refusal:
        print(f"refusing to publish {slug}: {refusal}", file=sys.stderr)
        print(
            "\nA hosted card is a public listing, and listing is per business and opt-in. It "
            "needs an owner-signed listing grant naming this tenant's did:key as grantee — "
            "there is no flag here that substitutes for one.",
            file=sys.stderr,
        )
        return 3

    # ── fail closed before any network call ──────────────────────────────────
    if not host39.publishing_configured():
        missing = ", ".join(host39.missing_config())
        print(
            f"refusing to publish: host39 is not configured (missing: {missing}).\n"
            "Unset and empty are treated identically, and there is deliberately no "
            "default target — set the variables explicitly.",
            file=sys.stderr,
        )
        return 2

    client = host39.Host39Client.from_env()
    account = client.me()
    print(
        f"authenticated to {client.base_url} as handle={account.get('handle')!r} identity_type={account.get('identity_type')!r}"
    )

    result = client.publish_a2a_card(
        card,
        slug=slug,
        is_public=not args.private,
        include_nanda_extension=not args.no_nanda_extension,
    )

    print(f"card_id     : {result.card_id}")
    print(f"slug        : {result.slug}")
    print(f"status      : {result.status}")
    print(f"card_url    : {result.card_url}")
    print(f"runtime_url : {result.runtime_url}")
    print(f"did         : {result.did}")
    print(
        f"probe       : HTTP {result.fetched.status_code} content-type={result.fetched.content_type!r}"
    )

    if not result.ok:
        print("\nPUBLISHED CARD FAILED VERIFICATION:", file=sys.stderr)
        for problem in result.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("\nOK — card is fetchable at its published URL with the A2A media type,")
    print(
        "runtime_url points at the live agent endpoint, and credentials carries the did."
    )

    # Recorded only AFTER result.ok — the record must never run ahead of the
    # publication it describes, or the catalog goes back to advertising a URL
    # nothing guarantees exists, which is exactly the resolvable-card rule.
    if args.record_on_org:
        return _record_on_org(args.record_on_org, args.record_agent_id, result.card_url)
    return 0


def _record_on_org(org_base: str, agent_id: str | None, card_url: str) -> int:
    """Tell the org this member's card is published, so the catalog lists it."""
    if not agent_id:
        print("--record-on-org requires --record-agent-id", file=sys.stderr)
        return 2
    token = os.environ.get("ORG_ADMIN_TOKEN", "").strip()
    if not token:
        print(
            "--record-on-org needs ORG_ADMIN_TOKEN in the environment "
            "(never pass a credential as an argument — argv is world-readable)",
            file=sys.stderr,
        )
        return 2
    url = f"{org_base.rstrip('/')}/admin/api/host39/record-publication/{agent_id}"
    resp = httpx.post(
        url,
        headers={"X-Admin-Token": token},
        json={"card_url": card_url},
        timeout=30,
    )
    if resp.status_code >= 300:
        print(f"failed to record publication: HTTP {resp.status_code} {resp.text[:200]}", file=sys.stderr)
        return 1
    print(f"recorded on org: {resp.json()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
