# SMB host

A multi-tenant host that provisions isolated sovereign agents for small
businesses. One call — `POST /provision` — mints an Ed25519 identity for a
business, serves its A2A agent card and its NANDA AgentFacts at a stable
per-tenant URL, and takes bookings that return signed receipts.

The business runs nothing. Somebody has to run **this**, and that is what this
page is for.

This host registers on no index. `POST /provision` returns what a card host
needs to do that separately.

> **Running it for other people?** [`OPERATIONS.md`](./OPERATIONS.md) covers what
> that costs: what is on disk and why a volume alone does not preserve it, the
> four settings and what each does when unset or wrong, the seven post-deploy
> checks including the redeploy one that proves the volume is real, and what this
> host deliberately does not do.
>
> [`scripts/smb_host_canary.py`](../scripts/smb_host_canary.py) runs those seven
> checks against a deployed host. It takes a base URL and a state file, reads the
> provisioning credential from the environment, and **provisions a real tenant on
> every run** — which is what lets it check that an earlier run's tenant survived.

## Requirements

- Python 3.10 or newer, or Docker.
- The `community_member` package from `agent/` in the same repository. This
  service is **not** installable on its own — `pip install ./smb_host` fails, by
  design; see the note at the top of `pyproject.toml`.

## Run it with Docker

The build context is the repository root, because the image needs both
`smb_host/` and `agent/`:

```bash
docker build -f infra/Dockerfile.smb-host -t orrery-smb-host .

export COMMUNITY_MEMBER_PASSPHRASE="$(openssl rand -base64 24)"   # keep this

docker run --rm -p 8080:8080 \
  -e HOST_PUBLIC_URL=http://127.0.0.1:8080 \
  -e SMB_HOST_TENANT_CAP=50 \
  -e COMMUNITY_MEMBER_KEYSTORE=passphrase \
  -e COMMUNITY_MEMBER_PASSPHRASE="$COMMUNITY_MEMBER_PASSPHRASE" \
  -v orrery-smb-tenants:/data \
  orrery-smb-host
```

**The two `COMMUNITY_MEMBER_*` lines are not optional, and the volume does not
substitute for them.** Each tenant's key is encrypted under a passphrase the
keystore backend chooses, and the default backend in a container derives it from
a machine fingerprint that includes the hostname — which changes every time the
container is replaced. Without them the next container cannot open the vaults the
previous one wrote, and because rehydration has no per-tenant error handling the
first unreadable home takes the whole service down. Run without them, this is the
first redeploy:

```
$ docker rm -f <container>          # replacing the container IS a redeploy
$ docker run … -v orrery-smb-tenants:/data orrery-smb-host
$ docker ps -a
smb-host   Exited (1)
$ docker logs smb-host
ValueError: Decryption failed: wrong passphrase or tampered data
```

The volume is intact and every business on it is unreadable. Nothing on this
host can recover one — the recovery phrase is returned to the caller once and
never stored here.

Both halves were driven on this image: without the two variables the redeploy
above exits 1; with them the same remove-and-restart against the same named
volume comes back healthy and the tenant serves the same `did:key`.

Keep `COMMUNITY_MEMBER_PASSPHRASE` wherever production secrets live. It decrypts
every business on the volume, so losing it is the same event as losing the
volume. [`OPERATIONS.md`](OPERATIONS.md) §1 carries the rest, including what a
platform-managed volume does and does not cover.

## Run it directly

From the repository root:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r agent/requirements.lock
pip install -e ./agent --no-deps

cd smb_host
HOST_PUBLIC_URL=http://127.0.0.1:8080 SMB_HOST_TENANT_CAP=50 \
  python -m uvicorn main:app --host 127.0.0.1 --port 8080
```

## Check it is up

```bash
curl -s http://127.0.0.1:8080/health
```

```json
{"status":"ok","service":"smb-host","tenants":3,"pool_target":3,"pool_ready":3,"pool_reclaimable":0,"tenant_cap":50,"headroom":47,"at_capacity":false,"trusted_proxies":0}
```

`tenants` counts **every** tenant this host holds, including the pre-warmed ones
nobody has claimed yet, so a fresh host at the default `SMB_HOST_POOL_SIZE=3`
reports `3` and not `0`. Provisioning a business makes it `4`: the claimed tenant
plus the three the warmer keeps ready.

`tenants: 0` alongside `pool_ready: 3` cannot occur — a ready pool tenant is a
tenant. `tenants: 0` with `pool_ready: 0` does, and means the warmer never
started; the log line says which variable is missing.

`trusted_proxies` is the configured `SMB_HOST_TRUSTED_PROXIES` (see
"Attribution" below). It is reported because it is the switch that decides
whether an `X-Forwarded-For` an upstream service states about a caller is
recorded or ignored, and `0` — the correct default for a host reached directly —
is also the value at which a front door's forwarding does nothing. Both settings
are individually right there and the pair silently records the front door's own
address, so the number has to be readable from outside the container.

## Provision a business

```bash
curl -s -X POST http://127.0.0.1:8080/provision \
  -H 'Content-Type: application/json' \
  -d '{"business_name":"Moon Bakery"}'
```

```json
{
  "tenant_id": "smb-pool-5714830593fe",
  "endpoint": "http://127.0.0.1:8080/t/smb-pool-5714830593fe",
  "recovery_phrase": "…24 words, shown once, never stored…",
  "did": "did:key:z6MkfyjJzbhzyyNEGfGEzKrLyJXMTf3sVVkRSbzHTy7qLo1J"
}
```

The identifier is a pool id because `SMB_HOST_POOL_SIZE` defaults to 3 and the
request was answered from a tenant minted in advance. With `SMB_HOST_POOL_SIZE=0`
it is a slug of the business name instead.

### The tenant URL identifies a tenant, not a business

`/provision` takes no credential and checks no relationship between the caller and
the name it is given. `business_name` is a display label written onto the card; it
is not a claim anyone verified, and the host has no way to verify it.

A repeated name is refused with `409` on **both** provisioning paths — the warm
pool claim and the cold mint — so the behaviour does not depend on
`SMB_HOST_POOL_SIZE`. What that refusal covers, exactly:

- **Same slug collides.** `_slugify` lowercases and collapses every
  non-alphanumeric run to a hyphen, so `CORNER BAKERY`, `Corner-Bakery`,
  `corner  bakery` and `Corner Bakery.` all reduce to `corner-bakery` and are
  refused once `Corner Bakery` holds it.
- **A different slug does not.** `Corner Bakery Ltd` and `Corner Bakery NYC` are
  different slugs, so they still provision on the same host with their own
  `did:key` and their own URL. This refuses a repeated name; it does not
  establish who is entitled to one.
- **A name that slugs to nothing is refused before either of those.** A name with
  no alphanumeric characters at all — `!!!`, `---`, `   ` — cannot produce an id,
  and is a `400`, not a `409`:

  ```json
  {"detail":"business_name must contain at least one alphanumeric character"}
  ```

  The empty string is a different refusal again: `business_name` is declared with
  a minimum length, so `""` is rejected by request validation as a `422` before
  any of this runs.

The refusal names the name the caller sent, never the existing tenant's id —
`/t/<id>` is that tenant's endpoint, card and booking route, and provisioning is
open on the loopback shape, so echoing it would turn a duplicate-name probe into
a directory of every business on the host.

A customer's browser verifying a receipt against this host's card learns that the
host signed consistently, not that the host is the business. What settles that is
where the customer got the URL — the shop's own site or a code on the counter, as
against a directory entry or a link inside the receipt — and nothing here can tell
those apart.

`endpoint` is the address the business hands onward. It is built from
`HOST_PUBLIC_URL`, which is why that variable has no default — see below.

## Take a booking

The tenant id is the one `/provision` just returned. The body needs
`service`, `provider` and `datetime`; `notes` is optional. Any of the three
missing is a `400` naming them — the route validates the body itself rather
than returning FastAPI's default `422`.

```bash
curl -s -X POST http://127.0.0.1:8080/t/smb-pool-5714830593fe/book \
  -H 'Content-Type: application/json' \
  -d '{"service":"birthday cake","provider":"Moon Bakery","datetime":"2026-09-02T10:30:00Z","notes":"vanilla, no nuts"}'
```

```json
{
  "booking": {
    "id": 1,
    "service": "birthday cake",
    "provider": "Moon Bakery",
    "datetime": "2026-09-02T10:30:00Z",
    "notes": "vanilla, no nuts",
    "status": "recorded",
    "tenant_id": "smb-pool-5714830593fe"
  },
  "receipt_id": "58f9ab68-4528-4026-8de2-527f6eb878ee",
  "receipt": {
    "version": "arp/0.1",
    "receipt_id": "58f9ab68-4528-4026-8de2-527f6eb878ee",
    "issuer_did": "did:key:z6MkfyjJzbhzyyNEGfGEzKrLyJXMTf3sVVkRSbzHTy7qLo1J",
    "principal_did": "did:key:z6MkfyjJzbhzyyNEGfGEzKrLyJXMTf3sVVkRSbzHTy7qLo1J",
    "issued_at": "2026-08-18T20:24:25Z",
    "action": {
      "category": "appointment_booked",
      "outcome": "completed",
      "human_summary": "Booked birthday cake with Moon Bakery at 2026-09-02T10:30:00Z",
      "machine_payload": {
        "service": "birthday cake",
        "provider": "Moon Bakery",
        "datetime": "2026-09-02T10:30:00Z",
        "notes": "vanilla, no nuts",
        "booking_id": 1
      }
    },
    "signature": "…base64 Ed25519 over the canonicalized receipt…"
  }
}
```

`receipt` is returned byte-for-byte as it was persisted in that tenant's Agency
Log, so it re-canonicalizes and verifies offline under `issuer_did` with
`arp.verify_receipt` — the caller does not have to trust this host. The booking
row and the receipt live only under that tenant's home and are signed by that
tenant's key; nothing here is shared between tenants.

## What the business does with the result

This host is the agent **runtime**. It serves the tenant's A2A card at

```
http://127.0.0.1:8080/t/smb-pool-5714830593fe/.well-known/agent.json
```

and its NANDA AgentFacts alongside it, but it **registers on no index** — it
makes no call to `api.nandaindex.org` and holds no index credential, by design.

So the card URL and the `did` from `/provision` have to be handed to a card
host, which is the party that registers the business at `api.nandaindex.org`.
Until that happens the agent is reachable by anyone who already has its
`endpoint`, and discoverable by nobody. That handshake — who registers, with
what credential, and how a record becomes active — is specified in
[docs/integrations/SMB_NANDA_HANDSHAKE.md](../docs/integrations/SMB_NANDA_HANDSHAKE.md).

## Configuration

| Variable | Required | Default | What it does |
|---|---|---|---|
| `HOST_PUBLIC_URL` | **yes, to provision** | none | The address this host is reachable at from outside. Written into every provisioned agent's card and returned as `endpoint`. |
| `SMB_HOST_PROVISION_TOKEN` | **yes, unless bound to loopback** | none | Shared secret gating `POST /provision`. Sent as `Authorization: Bearer <token>`. Unset is allowed only when `HOST_PUBLIC_URL` is a loopback address. |
| `SMB_HOST_DATA_DIR` | no | `$XDG_DATA_HOME/orrery-smb-host/tenants`, else `~/.local/share/orrery-smb-host/tenants` | Where tenant homes live. The image sets `/data/smb-tenants`. |
| `SMB_HOST_POOL_SIZE` | no | `3` | Tenants minted ahead of demand so provisioning is instant. `0` mints on the request. |
| `SMB_HOST_CORS_ORIGINS` | no | `*` | Comma-separated browser origin allowlist. The header allowlist always includes `Authorization`, because a gated `POST /provision` from a browser is preceded by a preflight naming it. |
| `SMB_HOST_TENANT_CAP` | **yes, unconditionally** | none | The maximum number of tenants this host will ever hold (claimed or pool-ready). No loopback carve-out — see [Bounding total capacity](#bounding-total-capacity-and-attributing-a-provision) below. |
| `SMB_HOST_TRUSTED_PROXIES` | no | `0` | How many proxy hops in front of this host to trust when attributing a provision to a caller. `0` trusts nothing and records the raw socket peer. |

### Why `HOST_PUBLIC_URL` has no default and refuses instead

It used to default to `http://localhost:8080`, which tracked neither the bind
host nor the port. Running on any other port returned an `endpoint` that refused
connection while the host itself answered normally — and that field is the one a
business gives to a card host, a customer, or an index. A wrong address is
indistinguishable from a right one at the moment it is issued; the business
finds out when someone cannot reach them.

So the host boots without it — health, and the existing tenants' cards and
booking routes, do not need it — and refuses to provision:

```
HTTP 503
HOST_PUBLIC_URL is not set, so this host does not know the address to put in the
agent's card. Set it to the URL this host is reachable at …
```

Set it to whatever a client outside this machine would type. Behind a reverse
proxy or a tunnel, that is the public name, not the local bind address.

## Gating provisioning

`POST /provision` mints an Ed25519 identity and writes a tenant home to disk.
An open one lets anyone who finds the host mint identities in someone else's
business name, so a host reachable off this machine has to be gated:

```bash
export SMB_HOST_PROVISION_TOKEN="$(openssl rand -base64 24)"

HOST_PUBLIC_URL=https://smb.example.com \
  python -m uvicorn main:app --host 127.0.0.1 --port 8080
```

Generate it rather than choosing it, and keep it out of the repository, your
shell history and any command line — argv is readable by every process on the
box. The caller sends it as a bearer:

```bash
curl -s -X POST https://smb.example.com/provision \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $SMB_HOST_PROVISION_TOKEN" \
  -d '{"business_name":"Moon Bakery"}'
```

Without the header, or with the wrong secret:

```
HTTP 401
www-authenticate: Bearer
{"detail":"provisioning on this host requires 'Authorization: Bearer <token>' (SMB_HOST_PROVISION_TOKEN)."}
```

The refusal is identical whether or not the business name would have collided —
the name is not read to produce it. An authorized caller who reuses a name gets a
`409` naming **the name they sent**, never the existing tenant's id:

```json
{"detail":"a business is already provisioned under the name 'Moon Bakery'"}
```

The id is withheld deliberately. `/t/<id>` is that tenant's endpoint, card and
booking route, so a refusal that returned it would let a caller turn
duplicate-name probes into a directory of every business on the host.

Everything else on this host stays open: `/health`, the tenant cards, the
AgentFacts, and `POST /t/<tenant>/book`. Only minting a new identity is gated.

### The three cases, and why there is no "open when unset" default

`SMB_HOST_PROVISION_TOKEN` has no default that is open, for the same reason
`HOST_PUBLIC_URL` has no default at all: a default that is correct in one
deployment shape and wrong in another fires in whichever shape the operator did
not test. The unset case is decided by the address the operator has already
stated.

| `SMB_HOST_PROVISION_TOKEN` | `HOST_PUBLIC_URL` | `POST /provision` |
|---|---|---|
| set | any | `Authorization: Bearer <token>` required; `401` otherwise |
| unset | loopback (`127.0.0.1`, `localhost`, `::1`) | open — the development and CI shape, unchanged |
| unset | anything else | refused, `503` naming `SMB_HOST_PROVISION_TOKEN` |
| either | **unset** | refused, `503` naming `HOST_PUBLIC_URL` — that is the one to fix first |

The last row is easy to miss because "unset" is neither loopback nor anything
else. With no `HOST_PUBLIC_URL` the host cannot classify its own address, so it
refuses for that reason and names that variable, whatever the token is set to:

```
HTTP 503
HOST_PUBLIC_URL is not set, so this host does not know the address to put in the
agent's card. Set it to the URL this host is reachable at …
```

The pre-warm pool is refused on the same condition and logs the same sentence, so
`/health` reports `pool_ready: 0` and `tenants: 0` until it is set.

The third row is the one that is new. An operator who has stated a public
address and configured no token has described a host that mints identities for
strangers:

```
HTTP 503
SMB_HOST_PROVISION_TOKEN is not set and HOST_PUBLIC_URL is 'https://smb.example.com',
which is not a loopback address. Provisioning mints an identity and writes a tenant
home, so an un-gated host reachable off this machine mints identities for anyone who
finds it. Set SMB_HOST_PROVISION_TOKEN to a shared secret and send it as
'Authorization: Bearer <token>', or bind this host to loopback, and restart.
```

Loopback is decided from the parsed host, not a substring: `http://127.0.0.1.example.com/`
contains `127.0.0.1` and resolves wherever its owner points it, so it counts as
public.

The **pre-warm pool is gated on the same condition**. The warmer mints tenants
before any request arrives and writes them to disk, where a later restart picks
them up as fully provisioned — so refusing at the route alone would still leave
an un-gated host producing identities. On the refused configuration it logs the
reason above and stays down, and `/health` reports `pool_ready: 0`.

The token is never logged and never echoed in a refusal. `Authorization` **is**
in this host's CORS header allowlist — a gated `POST /provision` from a browser
is preceded by a preflight naming it, so blocking the header would only turn an
honest 401 into an unreadable CORS error. Allowing it is not advice to put the
secret in a page: whatever a browser sends, the reader can read. Where the token
should live is a question about your deployment, and this page does not answer
it.

## Bounding total capacity and attributing a provision

`SMB_HOST_PROVISION_TOKEN` bounds **who** may call `POST /provision`. It says
nothing about **how much** — measured on the deployed host, `tenants` went from
23 to 68 with nothing on the host able to say who provisioned the other 45.
`SMB_HOST_TENANT_CAP` closes that: it is the maximum number of tenants — claimed
or a not-yet-claimed pool slot — this host will ever hold, and it is required
**unconditionally**, with no loopback exception. Provisioning mints an Ed25519
identity and writes a vault to disk, and this host has no delete route, so an
unbounded cap is unlimited identities accumulating with no way to remove them —
that is true on `127.0.0.1` as much as on a public address, which is why this
bound, unlike the token, does not vary with `HOST_PUBLIC_URL`.

Unset, empty or unparsable is refused the same way `HOST_PUBLIC_URL` is, and for
the pre-warm pool for the same reason: the warmer mints before any request
arrives, so gating the route alone would still leave an ungated host producing
identities.

```
HTTP 503
SMB_HOST_TENANT_CAP is not set to a positive integer. Provisioning mints an
Ed25519 identity and writes a tenant vault to disk, and this host has no delete
route — an unbounded cap means unlimited identities accumulating with no way to
remove them. Set SMB_HOST_TENANT_CAP to the maximum number of tenants this host
should ever hold and restart.
```

Once the cap is reached, `POST /provision` refuses with its own status — `507`,
distinct from the `503` above, because the two need different responses: a
`503` means an operator forgot a variable, a `507` means real demand reached a
real limit and the operator needs to decide whether to raise it.

```
HTTP 507
this host has issued its full allocation of tenants (5 of 5). No further
provisioning until an operator raises SMB_HOST_TENANT_CAP.
```

`GET /health` reports the cap and the remaining headroom next to `tenants` and
`pool_ready`, so exhaustion is visible before a business is turned away:

```json
{"status": "ok", "service": "smb-host", "tenants": 3, "pool_target": 3,
 "pool_ready": 0, "pool_reclaimable": 3, "tenant_cap": 5, "headroom": 2,
 "at_capacity": false, "trusted_proxies": 0}
```

**Every provision is attributed.** Each tenant's record carries `provisioned_at`
(a timestamp) and `provisioned_by` (a caller discriminator — the request's
socket peer, or `X-Forwarded-For` if `SMB_HOST_TRUSTED_PROXIES` says how many
hops to trust). This is attribution, not authorization or identity: behind an
unconfigured proxy it is that proxy's own address, and it is never used to
refuse a request.

**Behind `smb_signup`, set `SMB_HOST_TRUSTED_PROXIES=1`.** The front door
terminates the visitor's connection and states the one caller it resolved in a
single-entry `X-Forwarded-For`, replacing whatever the caller sent. Leaving this
host at `0` is not stricter: it records the front door's own address for every
visitor and for the operator's own direct calls alike, which is what this host
did for every public signup before the front door forwarded anything. `/health`
reports `trusted_proxies` so the mismatch is readable rather than inferred, and
`smb_signup`'s own `/health` reports `caller_attribution` for the same reason. Two absent states are deliberately different and neither is
backfilled with a guess:

* `provisioned_by: null` — no claim has been recorded for this tenant at all.
  This is every tenant provisioned before this field existed (recorded as
  unknown, not migrated), and a pool slot the warmer minted but nobody has
  claimed yet.
* `provisioned_by: "unattributable"` — a claim WAS made and no usable caller
  signal existed for it. This is a recorded outcome, never a fabricated
  default like an IP address nothing sent.

## Tests

```bash
cd smb_host && python -m pytest -q
```
