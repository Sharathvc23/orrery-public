#!/usr/bin/env python3
"""Exercise a deployed SMB host end to end, as a business and as a stranger.

The SMB host provisions an identity, serves a card and takes bookings for
businesses that run nothing themselves. Nothing watched it: a dead deploy, a
lost volume or a card that stopped resolving would have been found by a person
clicking. Same reasoning as ``catalog_canary.py`` and ``receipt_verify_canary.py``
— the conditions this catches only exist in the deployed state, so a hermetic CI
stack cannot observe them.

Seven checks, reported separately and in this order:

    1. /health answers 200 and reports the shape it should
    2. POST /provision WITHOUT the credential is refused 401     ← CRITICAL if not
    3. POST /provision WITH the credential returns 201, and the endpoint it
       returns is under the base URL this canary was given
    4. the card at that endpoint resolves and its did equals the provisioned did
    5. AgentFacts resolves
    6. a booking returns a receipt whose issuer_did is that same did
    7. a tenant provisioned by a PREVIOUS run still serves the SAME did

⚠️ CHECK 7 IS THE POINT. Checks 1–6 are all satisfiable by a host that just came
up empty — a redeploy onto a fresh volume passes every one of them, because they
only ever look at a tenant this run created. Check 7 is the only one that asks
whether anything SURVIVED, which is what a lost volume and a keystore that cannot
decrypt its old vaults both look like. It needs state carried between runs, so it
reports NO PRIOR STATE distinctly rather than as success: a run that verified
nothing must not read as a run that verified something.

⚠️ THIS PROVISIONS A REAL TENANT ON A REAL HOST, EVERY RUN. There is no delete
route on this host and this script does not add one, so tenant homes accumulate
on the volume — one per run, each an Ed25519 key and a small directory. That is
the running cost of the check, and it is deliberate: check 7 only means something
because the tenants are still there. Canary tenants are named with
``CANARY_NAME_PREFIX`` so an operator can tell them from real businesses.

Exit status:
    0 — every check passed (or check 7 had no prior state to compare)
    1 — at least one check failed; what failed is printed, not a traceback

The base URL and the state file are flags, because pointing this at the wrong
host or silently reusing another host's state is exactly the mistake worth making
hard. The credential is read from the environment ONLY, never from argv — argv is
readable by every process on the box.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

TIMEOUT = 30.0
TOKEN_ENV = "SMB_HOST_PROVISION_TOKEN"

# Canary tenants are real tenants on a real host. The prefix is what lets an
# operator tell them apart from businesses somebody actually onboarded, and it is
# also what makes the accumulation auditable rather than mysterious.
CANARY_NAME_PREFIX = "orrery-canary"

# The host requires a delivery channel at claim time. The canary is not a
# business and has nowhere to receive a booking, so it provisions with an address
# on a reserved-for-documentation domain: the tenant is reachable-by-shape, the
# delivery attempt fails, and check 6 asserts the receipt rather than the
# delivery. A canary that claimed a real endpoint would post test bookings to it.
CANARY_CONTACT = "https://bookings.invalid/orrery-canary"

# The host refuses a repeated business name (409, exact slug), so the name has to
# differ per run. The timestamp tells an operator reading the volume when the
# tenant was minted; the random suffix is what actually guarantees uniqueness.
#
# The timestamp alone is NOT enough, and this is measured rather than assumed:
# three runs in quick succession, the second failed
#   3. /provision: HTTP 409 a business is already provisioned under the name
#      'orrery-canary 20260818-215616'
# because the stamp has second resolution and two runs landed inside one second.
# A canary that goes red when it is run twice quickly, or retried after a
# transient failure, reports on itself rather than on the host.
_RUN_STAMP_FORMAT = "%Y%m%d-%H%M%S"


class CheckFailed(Exception):
    """A check did not hold. Carries the operator-facing sentence, not a trace."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _under(base: str, url: str) -> bool:
    """True when ``url`` is served by the host at ``base``.

    Compared on the parsed scheme, host and port rather than as a prefix string:
    for a base of "https://smb-host.example", the URL
    "https://smb-host.example.attacker.test/t/x" starts with the base and is a
    different host. Same argument as _is_loopback in smb_host/main.py — a
    substring test on a URL is not a test on its host.
    """
    b, u = urlparse(base), urlparse(url)
    return (b.scheme, b.hostname, b.port) == (u.scheme, u.hostname, u.port)


# ── the checks ───────────────────────────────────────────────────────────────────


def check_health(client: httpx.Client, base: str) -> str:
    resp = client.get(f"{base}/health")
    if resp.status_code != 200:
        raise CheckFailed(f"/health returned HTTP {resp.status_code}, not 200")
    body = resp.json()
    if body.get("service") != "smb-host":
        raise CheckFailed(
            f"/health says service={body.get('service')!r}, not 'smb-host' — wrong service at this URL"
        )
    if body.get("status") != "ok":
        raise CheckFailed(f"/health says status={body.get('status')!r}, not 'ok'")
    for field in ("tenants", "pool_target", "pool_ready"):
        if not isinstance(body.get(field), int):
            raise CheckFailed(
                f"/health omits {field!r} or it is not an integer: {body!r}"
            )
    return f"tenants={body['tenants']} pool={body['pool_ready']}/{body['pool_target']}"


def check_provision_is_gated(
    client: httpx.Client, base: str, business_name: str
) -> str:
    """An UNCREDENTIALED provision must be refused.

    A 201 here is the critical case: provisioning mints an identity and writes a
    tenant home, so an open host lets anyone who finds it mint identities in any
    business name. It is reported as CRITICAL rather than as one failure among
    seven because the others describe a host that is broken, and this one
    describes a host that is working for strangers.

    ⚠️ The probe uses its OWN business name, not the one check 3 will use. On an
    open host this request SUCCEEDS and mints a tenant under whatever name it
    sends; if that were check 3's name, check 3 would then fail 409 on a
    duplicate and report "provisioning is broken" when provisioning is fine and
    the gate is the thing that is missing. One fault must produce one finding.
    """
    resp = client.post(
        f"{base}/provision",
        json={"business_name": f"{business_name} gate-probe", "contact": CANARY_CONTACT},
    )
    if resp.status_code == 201:
        minted = resp.json()
        raise CheckFailed(
            f"CRITICAL: POST /provision with NO credential returned 201 and minted "
            f"tenant {minted.get('tenant_id')!r} ({minted.get('did', '')[:32]}…). "
            f"This host is open — anyone who finds it can mint identities in any "
            f"business name. Set {TOKEN_ENV} on the deployment and redeploy. "
            f"(That tenant is now on the host; this probe cannot avoid minting one "
            f"on a host that does not refuse it, which is the finding.)"
        )
    if resp.status_code == 503:
        raise CheckFailed(
            f"POST /provision with no credential returned 503, not 401: {resp.text[:200]}. "
            f"The host is refusing to provision at all — {TOKEN_ENV} or HOST_PUBLIC_URL "
            f"is unset on the deployment."
        )
    if resp.status_code != 401:
        raise CheckFailed(
            f"POST /provision with no credential returned HTTP {resp.status_code}, expected 401"
        )
    return "401 as it should"


def check_provision(
    client: httpx.Client, base: str, token: str, business_name: str
) -> tuple[str, dict[str, Any]]:
    resp = client.post(
        f"{base}/provision",
        json={"business_name": business_name, "service_type": "canary", "contact": CANARY_CONTACT},
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 401:
        raise CheckFailed(
            f"POST /provision was refused 401 with the credential from ${TOKEN_ENV} — "
            f"the value this canary holds is not the one the host was deployed with"
        )
    if resp.status_code != 201:
        raise CheckFailed(
            f"POST /provision returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    body = resp.json()
    for field in ("tenant_id", "endpoint", "did", "recovery_phrase"):
        if not body.get(field):
            raise CheckFailed(f"the provision response omits {field!r}: {sorted(body)}")

    endpoint = body["endpoint"]
    if not _under(base, endpoint):
        raise CheckFailed(
            f"provision returned endpoint {endpoint!r}, which is not served by {base}. "
            f"HOST_PUBLIC_URL is wrong on the deployment — that field is the address a "
            f"business hands to a card host and to its customers, and a wrong one is "
            f"indistinguishable from a right one at the moment it is issued"
        )
    # The recovery phrase is a one-time secret. It is neither printed nor written
    # to the state file — the canary has no use for it beyond asserting it exists.
    body.pop("recovery_phrase", None)
    return f"{body['tenant_id']} {body['did'][:32]}…", body


def check_card(client: httpx.Client, endpoint: str, expected_did: str) -> str:
    resp = client.get(f"{endpoint}/.well-known/agent.json")
    if resp.status_code != 200:
        raise CheckFailed(
            f"the agent card at {endpoint} returned HTTP {resp.status_code}"
        )
    card = resp.json()
    served = (card.get("authentication") or {}).get("credentials")
    if served != expected_did:
        raise CheckFailed(
            f"the card advertises {served!r} but provision returned {expected_did!r} — "
            f"the tenant is signing under a key its card does not advertise"
        )
    return f"{card.get('name')!r} advertises the provisioned did"


def check_agentfacts(client: httpx.Client, endpoint: str) -> str:
    resp = client.get(f"{endpoint}/agentfacts.json")
    if resp.status_code != 200:
        raise CheckFailed(
            f"AgentFacts at {endpoint}/agentfacts.json returned HTTP {resp.status_code}"
        )
    facts = resp.json()
    if not isinstance(facts, dict) or not facts:
        raise CheckFailed("AgentFacts resolved but is not a JSON object")
    return "resolves"


def check_booking(
    client: httpx.Client, endpoint: str, expected_did: str, stamp: str
) -> str:
    resp = client.post(
        f"{endpoint}/book",
        json={
            "service": "canary check",
            "provider": CANARY_NAME_PREFIX,
            "datetime": stamp,
            "notes": "automated liveness check — not a real appointment",
        },
    )
    if resp.status_code != 200:
        raise CheckFailed(
            f"POST {endpoint}/book returned HTTP {resp.status_code}: {resp.text[:200]}"
        )
    body = resp.json()
    receipt = body.get("receipt")
    if not receipt:
        raise CheckFailed(f"the booking returned no receipt: {sorted(body)}")
    issuer = receipt.get("issuer_did")
    if issuer != expected_did:
        raise CheckFailed(
            f"the receipt is issued by {issuer!r} but the tenant provisioned as {expected_did!r} — "
            f"the booking was signed by a different key than the one this tenant was minted with"
        )
    return f"receipt {body.get('receipt_id', '?')[:8]}… signed by the provisioned did"


def check_previous_tenants(
    client: httpx.Client, base: str, prior: list[dict[str, Any]]
) -> tuple[str, list[str]]:
    """THE CHECK THAT CANNOT BE SATISFIED BY AN EMPTY HOST.

    Every earlier run's tenant must still serve the SAME did. A lost volume, a
    keystore that cannot decrypt vaults written by the previous container, and a
    redeploy onto fresh storage all present here and nowhere else in this script.
    """
    if not prior:
        return "NO PRIOR STATE — nothing from an earlier run to compare", []

    failures: list[str] = []
    survived = 0
    for entry in prior:
        endpoint, tenant_id, did = entry["endpoint"], entry["tenant_id"], entry["did"]
        first_seen = entry.get("first_seen", "?")
        try:
            resp = client.get(f"{endpoint}/.well-known/agent.json")
        except Exception as exc:  # noqa: BLE001 — an unreachable prior tenant IS the failure
            failures.append(
                f"{tenant_id} (first seen {first_seen}): UNREACHABLE ({type(exc).__name__})"
            )
            continue
        if resp.status_code == 404:
            failures.append(
                f"{tenant_id} (first seen {first_seen}): 404 — this tenant was provisioned by an "
                f"earlier run and the host no longer has it. The volume did not survive, or the "
                f"tenant home was removed"
            )
            continue
        if resp.status_code != 200:
            failures.append(
                f"{tenant_id} (first seen {first_seen}): HTTP {resp.status_code}"
            )
            continue
        served = (resp.json().get("authentication") or {}).get("credentials")
        if served != did:
            failures.append(
                f"{tenant_id} (first seen {first_seen}): serves {served!r}, was minted as {did!r} — "
                f"the tenant home survived but its identity did not. A keystore that cannot decrypt "
                f"the vault written by the previous container looks exactly like this"
            )
            continue
        survived += 1

    return (
        f"{survived}/{len(prior)} tenant(s) from earlier runs still serve their original did",
        failures,
    )


# ── state carried between runs ───────────────────────────────────────────────────


def load_state(path: Path, base: str) -> list[dict[str, Any]]:
    """Prior tenants recorded for THIS base URL only.

    Filtered by base rather than trusting the whole file: a state file written
    against a local host would otherwise be asserted against the deployed one,
    and every entry would 404 for a reason that has nothing to do with the
    deployment.
    """
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckFailed(
            f"the state file {path} could not be read ({type(exc).__name__}: {exc})"
        ) from exc
    entries = doc.get("tenants", []) if isinstance(doc, dict) else []
    return [e for e in entries if _under(base, e.get("endpoint", ""))]


def save_state(path: Path, base: str, provisioned: dict[str, Any], stamp: str) -> None:
    doc: dict[str, Any] = {"tenants": []}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            if isinstance(existing, dict) and isinstance(existing.get("tenants"), list):
                doc = existing
        except (OSError, json.JSONDecodeError):
            # A corrupt state file is reported by load_state before we get here;
            # reaching this point means it parsed, so this is belt-and-braces.
            pass
    doc["tenants"].append(
        {
            "first_seen": stamp,
            "base_url": base,
            "tenant_id": provisioned["tenant_id"],
            "endpoint": provisioned["endpoint"],
            "did": provisioned["did"],
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


# ── driver ───────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise a deployed SMB host end to end and report what is broken.",
        epilog=(
            f"The provisioning credential is read from ${TOKEN_ENV} and never from the "
            f"command line. Each run provisions one real tenant, which stays on the host — "
            f"that is what check 7 needs in order to mean anything."
        ),
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="the SMB host to check, e.g. https://smb-host.example",
    )
    parser.add_argument(
        "--state-file",
        required=True,
        type=Path,
        help="where to record this run's tenant, and where to read earlier runs' tenants from",
    )
    args = parser.parse_args(argv)

    base = args.base_url.rstrip("/")
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(
            f"{TOKEN_ENV} is not set. This canary provisions against a gated host and reads "
            f"the credential from the environment only — never pass it as an argument, argv is "
            f"readable by every process on the box.",
            file=sys.stderr,
        )
        return 1

    stamp = _now().strftime(_RUN_STAMP_FORMAT)
    business_name = f"{CANARY_NAME_PREFIX} {stamp} {secrets.token_hex(3)}"
    failures: list[str] = []
    provisioned: dict[str, Any] | None = None

    print(f"smb-host canary → {base}")
    print(f"  canary tenant name: {business_name!r}\n")

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        # Checks 1-6 run in order and each depends on the one before, so a failure
        # stops the chain — but check 7 is independent of all of them and must run
        # regardless. A host that cannot provision today can still tell you whether
        # it kept yesterday's tenants, and that is the more serious question.
        steps: list[tuple[str, Any]] = [
            ("1. /health", lambda: check_health(client, base)),
            (
                "2. /provision is gated",
                lambda: check_provision_is_gated(client, base, business_name),
            ),
        ]
        for label, run in steps:
            try:
                print(f"  {label}: {run()}")
            except CheckFailed as exc:
                print(f"  {label}: FAILED")
                failures.append(f"{label}: {exc}")
            except Exception as exc:  # noqa: BLE001 — the canary reports, it does not traceback
                print(f"  {label}: FAILED")
                failures.append(f"{label}: {type(exc).__name__}: {exc}")

        try:
            line, provisioned = check_provision(client, base, token, business_name)
            print(f"  3. /provision: {line}")
        except CheckFailed as exc:
            print("  3. /provision: FAILED")
            failures.append(f"3. /provision: {exc}")
        except Exception as exc:  # noqa: BLE001
            print("  3. /provision: FAILED")
            failures.append(f"3. /provision: {type(exc).__name__}: {exc}")

        if provisioned is not None:
            endpoint, did = provisioned["endpoint"], provisioned["did"]
            chained: list[tuple[str, Any]] = [
                ("4. agent card", lambda: check_card(client, endpoint, did)),
                ("5. AgentFacts", lambda: check_agentfacts(client, endpoint)),
                (
                    "6. booking receipt",
                    lambda: check_booking(client, endpoint, did, stamp),
                ),
            ]
            for label, run in chained:
                try:
                    print(f"  {label}: {run()}")
                except CheckFailed as exc:
                    print(f"  {label}: FAILED")
                    failures.append(f"{label}: {exc}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  {label}: FAILED")
                    failures.append(f"{label}: {type(exc).__name__}: {exc}")
        else:
            print("  4-6. skipped — nothing was provisioned to check")

        # Check 7 runs whether or not 1-6 did.
        prior: list[dict[str, Any]] = []
        state_readable = True
        try:
            prior = load_state(args.state_file, base)
            line, survivor_failures = check_previous_tenants(client, base, prior)
            print(f"  7. earlier runs' tenants: {line}")
            failures.extend(f"7. earlier runs' tenants: {f}" for f in survivor_failures)
        except CheckFailed as exc:
            state_readable = False
            print("  7. earlier runs' tenants: FAILED")
            failures.append(f"7. earlier runs' tenants: {exc}")

    if provisioned is not None and not state_readable:
        # DO NOT overwrite a state file that could not be read. Writing a fresh
        # one here would replace an unreadable file with a valid empty one: the
        # next run would report NO PRIOR STATE and exit 0, so a persistent
        # failure would present as one red run followed by green forever, with
        # every earlier tenant record gone. An operator has to look at the file.
        print(
            f"\n  NOT recording {provisioned['tenant_id']}: {args.state_file} could not be read, "
            f"and overwriting it would discard whatever earlier runs put there. "
            f"Fix or move the file, then run again."
        )
    elif provisioned is not None:
        try:
            save_state(args.state_file, base, provisioned, stamp)
            print(
                f"\n  recorded {provisioned['tenant_id']} in {args.state_file} for the next run to check"
            )
        except OSError as exc:
            failures.append(
                f"the run succeeded but its tenant could not be recorded in {args.state_file} "
                f"({type(exc).__name__}: {exc}) — check 7 will have nothing to compare next run"
            )

    if failures:
        print(f"\n{len(failures)} check(s) failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    # The summary states what was actually checked. Saying "every tenant from an
    # earlier run survived" on a first run would be the false-green shape
    # receipt_verify_canary.py documents: a run that verified nothing must not
    # read the same as a run that verified something.
    if prior:
        print(
            f"\nOK — the host provisions, serves and signs, and all {len(prior)} tenant(s) "
            f"from earlier runs still serve their original did."
        )
    else:
        print(
            "\nOK — the host provisions, serves and signs. NOTHING WAS CHECKED FOR SURVIVAL: "
            "this state file records no earlier tenant for this host, so check 7 had nothing to "
            "compare. A host that came up empty passes this run. Run it again to get that check."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
