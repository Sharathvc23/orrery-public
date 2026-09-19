#!/usr/bin/env python3
"""List ONE provisioned SMB tenant on a NANDA Index (Leg C) — an explicit act.

    provision (smb_host)  ->  [this script]  ->  POST /api/v1/orgs  ->  RESOLVE proof

⚠️ THIS IS A SEPARATE CALLER, AND THAT IS THE POINT. ``smb_host`` makes NO
outbound calls — a property that is asserted by a test and kept deliberately,
because ``REGISTRY_URL=`` once meant live production on a neighbouring path and
put 31 phantom records into a public registry. So listing is not a route on the
host and not a side effect of ``POST /provision``: it is this script, reading a
tenant the host already provisioned and acting on it. Nothing here is imported
by ``smb_host``.

⚠️ THE SUCCESS CONDITION IS RESOLVE, NOT THE 201. A live record (``org_id=mahesh``)
is ``status: active`` in the bulk listing and "not found or is not active" at
``resolve``. This script treats a 201 as having established nothing and exits
non-zero unless ``GET /api/v1/resolve`` returns our record pointing at our card.

⚠️ LISTING IS PER BUSINESS AND OPT-IN, ENFORCED BY THE EXISTING GATE. A tenant is
listed only with a valid owner-signed listing grant naming that tenant's
``did:key`` (``community_member.registry`` / ``owner.listing_grant_verdict``).
A fresh tenant has none and is refused by name. ``--i-am-the-owner-and-accept``
does not exist: there is no flag here that substitutes for a grant.

CREDENTIALS — environment only, never argv (argv is world-readable)::

    INDEX_BASE_URL=https://api.nandaindex.org
    INDEX_ACCOUNT_EMAIL=...
    INDEX_ACCOUNT_PASSWORD=...          # a human fills this; empty until then
    ORG_DOMAIN=stellarminds.ai
    ORG_CONTACT_EMAIL=...

Load them from a private file rather than exporting by hand::

    set -a; . ~/.config/orrery/index.env; set +a

USAGE::

    # DEFAULT: build and check the record, make no write. Works with no password.
    scripts/register_tenant_on_index.py --tenant-card-url https://smb.example.org/t/bobs/.well-known/agent.json

    # the TXT value to hand a human (needs the account password)
    scripts/register_tenant_on_index.py --tenant-card-url ... --domain-challenge

    # the real thing (needs the password, and refuses without a listing grant)
    scripts/register_tenant_on_index.py --tenant-card-url ... --register

    # prove an existing listing still resolves — read-only, no credential
    scripts/register_tenant_on_index.py --confirm urn:ai:domain:example.com:agent:bobs
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "agent"))

import httpx
from community_member import attestation_copy
from community_member import index_registrar as registrar
from community_member import nanda_index


def _say(key: str, value: object) -> None:
    print(f"{key:<26}: {value}")


def _say_attestation(value: str | None) -> None:
    """Print what was checked about the owner, in words rather than as a token.

    The record has always carried ``org.projectnanda.ownerAttestation``, but the
    only place it appeared was inside the dumped JSON, where it reads as one
    more key. A reviewer approving a dry run is deciding whether this listing
    may assert what it asserts, and that decision is the one thing the raw token
    does not help with.

    ⚠️ THE CAVEAT IS PRINTED TOO, ALWAYS. Every value has one, including the
    ones that sound conclusive, because these four name three different subjects
    and printing only the positive half of some of them is how a reader starts
    ranking them.
    """
    copy = attestation_copy.rendering_for(value)
    _say("owner attestation", value if value else "(none stated)")
    print(f"{'':<26}  {copy.sentence}")
    print(f"{'':<26}  {copy.caveat}")


def fetch_tenant_card(url: str) -> dict:
    """GET a tenant's A2A card from a live smb_host."""
    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise SystemExit(f"could not fetch the tenant card at {url}: {exc}")
    if response.status_code != 200:
        raise SystemExit(f"could not fetch the tenant card at {url}: HTTP {response.status_code}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise SystemExit(f"{url} did not return a JSON object")
    return payload


def public_card_url(card: dict, fetched_from: str) -> str:
    """Where the card lives AS THE HOST ADVERTISES IT — which is what the record
    must carry, not the URL this script happened to fetch it from.

    The two differ routinely and legitimately: an operator fetches over loopback
    or through a tunnel while the host serves a public ``HOST_PUBLIC_URL``. The
    record has to name the address a stranger can reach, so it is derived from
    the card's own ``url`` (the endpoint the host publishes about itself) rather
    than from the operator's vantage point. Falls back to the fetch URL when the
    card names no endpoint — where ``record_problems`` then catches it.
    """
    endpoint = str(card.get("url") or "").strip().rstrip("/")
    if not endpoint:
        return fetched_from
    return f"{endpoint}/.well-known/agent.json"


def record_from_card(card: dict, card_url: str, cfg: registrar.RegistrarConfig, args, grant_verdict=None) -> dict:
    """Build the index record from the card the host actually serves.

    From the SERVED card rather than from provision's response on purpose: the
    card is what a resolver will fetch, so if the two ever disagree the record
    must describe the one the world can see.
    """
    did = str((card.get("authentication") or {}).get("credentials") or "")
    if not did:
        extension = card.get("x-nanda") or {}
        did = str(extension.get("did") or "")
    business_name = str(card.get("name") or "")
    if not business_name:
        raise SystemExit(f"the card at {card_url} carries no name; nothing to list")
    return registrar.build_org_record(
        tenant_id=args.slug or registrar.slugify(business_name),
        business_name=business_name,
        did=did,
        card_url=card_url,
        domain=cfg.domain or (args.domain or ""),
        contact_email=cfg.contact_email or (args.contact_email or ""),
        service_type=args.service_type,
        description=str(card.get("description") or "") or None,
        slug=args.slug,
        version=str(card.get("version") or "") or None,
        hosting_path=args.hosting_path,
        grant_verdict=grant_verdict,
    )


def _tenant_home_for(args) -> Path | None:
    """The tenant's on-disk home, if this box is the one running the host.

    The listing grant lives in the tenant's home, so the gate can only be
    consulted where that home is. Registering from another machine is a
    legitimate shape, and it is NOT silently allowed to skip the gate — it
    refuses with a message naming what is missing.
    """
    if args.tenant_home:
        return Path(args.tenant_home)
    data_dir = os.environ.get("SMB_HOST_DATA_DIR", "").strip()
    if data_dir and args.slug:
        candidate = Path(data_dir) / args.slug
        if candidate.is_dir():
            return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="List one provisioned SMB tenant on a NANDA Index.",
        epilog="Credentials come from the environment only — never argv.",
    )
    parser.add_argument(
        "--tenant-card-url",
        help="URL of the tenant's A2A card on a live smb_host "
        "(https://host/t/<tenant>/.well-known/agent.json)",
    )
    parser.add_argument(
        "--confirm",
        metavar="URN",
        help="read-only: resolve this locator and report whether it reaches a live agent",
    )
    parser.add_argument("--slug", help="org_id / URN slug (default: from the card name)")
    parser.add_argument("--service-type", help="service category, e.g. 'barber shop'")
    parser.add_argument("--domain", help=f"override ${registrar.DOMAIN_ENV}")
    parser.add_argument("--contact-email", help=f"override ${registrar.CONTACT_ENV}")
    parser.add_argument("--tenant-home", help="the tenant's on-disk home, for the listing-grant check")
    parser.add_argument(
        "--hosting-path",
        default=registrar.HOSTING_PATH,
        help="deliberately unset by default: the field is write-only, so its effect is unobservable",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--register", action="store_true", help="actually create the org (needs the account password)"
    )
    action.add_argument(
        "--domain-challenge",
        action="store_true",
        help="fetch the TXT record a human must publish (needs the account password)",
    )
    action.add_argument(
        "--verify-domain", action="store_true", help="ask the index to read the TXT record and activate"
    )
    args = parser.parse_args(argv)

    if args.confirm:
        return _confirm_only(args.confirm)
    if not args.tenant_card_url:
        parser.error("one of --tenant-card-url or --confirm is required")

    cfg = registrar.RegistrarConfig.from_env()
    if args.domain:
        cfg = registrar.RegistrarConfig(cfg.base_url, cfg.email, cfg.password, args.domain, cfg.contact_email)
    if not cfg.domain:
        raise SystemExit(f"no domain: set ${registrar.DOMAIN_ENV} or pass --domain")

    card = fetch_tenant_card(args.tenant_card_url)
    advertised = public_card_url(card, args.tenant_card_url)
    if advertised != args.tenant_card_url:
        print(
            f"note: fetched from {args.tenant_card_url}, but the host advertises itself at "
            f"{advertised} — the record will carry the advertised address.\n"
        )
    # The gate is consulted before the record is built, not after, because the
    # record states what the gate found. Building first and checking second would
    # leave the attestation describing a verdict the record never saw. A tenant
    # home is not always available — registering from another machine is a
    # legitimate shape — and no verdict yields the weakest honest value.
    home = _tenant_home_for(args)
    grant_verdict = registrar.listing_verdict(home) if home is not None else None
    record = record_from_card(card, advertised, cfg, args, grant_verdict=grant_verdict)
    problems = registrar.record_problems(record)

    print("── the record ────────────────────────────────────────────────")
    print(json.dumps(record, indent=2, sort_keys=True))
    print()
    _say("card served by", advertised)
    _say("tenant did", record["trust_manifest"]["identity"] or "(none — the card names no key)")
    _say("URN it would resolve at", record["identifier"])
    _say_attestation(attestation_copy.attestation_of(record))
    print()

    if problems:
        print("THE INDEX WOULD REJECT THIS, or it would be unresolvable:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        # Refused BEFORE any network call: a rejected POST to a live third party
        # is still a request that happened.
        return 2

    # ── the opt-in gate, before anything is sent ─────────────────────────────
    if args.register:
        if home is None:
            print(
                "refusing to list: cannot find this tenant's home, so the owner's listing grant "
                "cannot be checked. Pass --tenant-home, or run this where the host's "
                "$SMB_HOST_DATA_DIR is. Listing without checking the grant is the one thing "
                "this path must not do.",
                file=sys.stderr,
            )
            return 2
        refusal = registrar.listing_refusal(home)
        if refusal:
            print(f"refusing to list {record['org_id']}: {refusal}", file=sys.stderr)
            print(
                "\nListing is per business and opt-in. It needs an owner-signed listing grant "
                "naming this tenant's did:key as grantee — there is no flag here that "
                "substitutes for one.",
                file=sys.stderr,
            )
            return 3

    if not (args.register or args.domain_challenge or args.verify_domain):
        print("DRY RUN — no call was made to the index.")
        print("This is the exact body --register would send; it is built by the same function.")
        missing = registrar.missing_config(cfg)
        if missing:
            print(f"\nNot yet able to register: unset {', '.join(missing)}.")
            if registrar.PASSWORD_ENV in missing:
                print(f"${registrar.PASSWORD_ENV} is filled by a human, by design.")
        return 0

    missing = registrar.missing_config(cfg)
    if missing:
        print(f"refusing to call the index: unset {', '.join(missing)}", file=sys.stderr)
        return 2
    client = registrar.IndexRegistrarClient(cfg=cfg)

    if args.domain_challenge:
        return _domain_challenge(client, record["org_id"])
    if args.verify_domain:
        result = client.verify_domain(record["org_id"])
        _say("domain_verified", result.get("domain_verified"))
        _say("status", result.get("status"))
        return 0 if result.get("domain_verified") else 1

    return _register(client, record)


def _domain_challenge(client: registrar.IndexRegistrarClient, org_id: str) -> int:
    challenge = client.domain_challenge(org_id)
    print("── hand these three lines to whoever controls the DNS ─────────")
    _say("record name", challenge.get("record_name"))
    _say("record type", challenge.get("record_type"))
    _say("record value", challenge.get("record_value"))
    _say("expires at", challenge.get("expires_at"))
    print()
    print("⚠️ REPLACE any existing _nanda-challenge value; do not add a second one.")
    print("⚠️ The value must have NO leading or trailing space inside the quotes —")
    print("   a published record already carries one, and an exact-match check would fail on it.")
    return 0


def _register(client: registrar.IndexRegistrarClient, record: dict) -> int:
    result = client.create_org(record)
    _say("write status", f"{result['status']} (this proves nothing on its own)")
    _say("org_id", result["org_id"])
    print()
    print("── the only thing that counts: does it resolve? ──────────────")
    found = registrar.confirm_by_resolve(record)
    issues = registrar.confirmation_problems(record, found)
    _say("resolve", "OK" if found.ok else f"REFUSED — {found.reason}")
    if found.ok:
        _say("endpoint", found.endpoint)
        _say("did on the card", found.did or "(none)")
        # Read back off what the index returned, not off the record we sent: the
        # question here is what a stranger resolving this business is told, and
        # the catalog_metadata -> metadata mapping is still an inference. If the
        # field did not survive the write, this says so instead of echoing our
        # own intent back at us.
        _say_attestation(found.owner_attestation)
    if issues:
        print("\nNOT LISTED AS INTENDED:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        print(
            "\nThe org row may exist. It is not discoverable as intended, which is "
            "the state this script reports as failure.",
            file=sys.stderr,
        )
        return 1
    print("\nOK — the index resolves our URN to our card, and the card names a live endpoint.")
    return 0


def _confirm_only(locator: str) -> int:
    """Read-only proof for a locator. No credential, no write."""
    found = nanda_index.discover(locator)
    _say("locator", locator)
    _say("resolves", "yes" if found.ok else f"no — {found.reason}")
    if not found.ok:
        _say("detail", found.detail)
        return 1
    _say("org_id", found.record.get("org_id"))
    _say("registry_url", found.record.get("registry_url"))
    _say("endpoint", found.endpoint)
    _say("did on the card", found.did or "(none)")
    _say("did matches record", nanda_index.did_matches_record(found))
    _say_attestation(found.owner_attestation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
