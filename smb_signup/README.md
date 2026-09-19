# smb_signup — the public front door

Serves the `smb_funnel` bundle and holds the provisioning credential a static
page cannot. **That is the smaller half of what it does.** The larger half is
that it *bounds* signup.

## Why a credential-holding proxy is not the point

`smb_host` gates `POST /provision` on `SMB_HOST_PROVISION_TOKEN`. A static bundle
cannot keep a secret, so the obvious move is a server-side component that keeps
one and forwards the call.

**On its own, that component is exactly as open as publishing the token.** One
extra hop, the same openness: anyone who can reach it can mint identities.

Nothing else bounds provisioning. There is no rate limiting in `smb_host`,
`SMB_HOST_POOL_SIZE` bounds *pre-warming* rather than the total, the cold path
mints on demand with no cap, and there is no expiry or per-source accounting.
Driven at `origin/main` c920702 with a valid token, a loop provisioned **60
tenants in 3.7 s and was never refused** — roughly 20 KB of key material each. The
token was the only bound that had ever existed.

Each provision mints an Ed25519 keypair, writes an encrypted vault to a
persistent volume, and creates a permanent tenant. Unbounded means unlimited
identities issued under this operator's vouching, on a disk filling with key
material nobody can attribute. The cost is **identity issuance and storage**, not
CPU, which is what the bounds are sized against.

## The bounds

| Setting | Required | What it does |
| --- | :---: | --- |
| `SMB_SIGNUP_HOST_URL` | **yes** | The `smb_host` this front door provisions on. |
| `SMB_HOST_PROVISION_TOKEN` | **yes** | The host's shared secret. Held here; never sent to a browser. |
| `SMB_SIGNUP_TENANT_CAP` | **yes** | Total tenants allowed to exist. Counted from the **host's** tenant count. |
| `SMB_SIGNUP_RATE_PER_HOUR` | **yes** | Signups allowed per source per hour. |
| `SMB_SIGNUP_TRUSTED_PROXIES` | no | How many proxies run in front. Unset ⇒ trust none. Decides both the rate-limit bucket and the caller forwarded to the host — one determination, see below. |

**Every one is required, and an unset bound stops provisioning rather than
defaulting to permissive.** Unset, empty, `0`, negative and unparseable are all
the same answer: refuse. The façade cannot exist without its bounds, because a
façade without them is the thing this service was written to avoid.

**The tenant cap is counted from the host, not from this process.** A tally kept
here would reset on redeploy, and a cap that resets is not a cap. Reading the
host's own count also counts tenants created through the operator path, which
occupy the same disk. If the host cannot be reached, signup **refuses** — not
knowing the headroom is not permission to ignore the cap.

**The rate limit is in-process and is deliberately not the load-bearing bound.**
It slows one source down; a restart empties it and a distributed source never
fills it. The tenant cap is what bounds the damage. Saying which is which matters:
a rate limit presented as a cap is a control that looks like a bound and is not
one.

### Source attribution

`X-Forwarded-For` is **client-supplied**. Trusting it by default would let one
caller mint a fresh bucket per request and defeat the per-source limit entirely,
so it is ignored unless `SMB_SIGNUP_TRUSTED_PROXIES` states how many hops you
actually run. Behind a load balancer with that unset, every request shares one
source and the limit becomes global — more restrictive, not less, which is the
direction an unconfigured deployment should err in.

### The caller reaches the host's record

`smb_host` records `provisioned_by` from the caller **it** can see, and every
request it sees from here arrives on this service's socket. So a façade that
relays only the credential and the body destroys the attribution it relays:
measured on a real pair, three distinct visitors through the front door and one
operator calling the host directly were all four recorded as `127.0.0.1`. The cap
still said how many agents had been issued; nothing said by whom.

**This service is authoritative for who the caller is**, because it terminates
the visitor's connection and is the only party that sees the socket the request
arrived on — and because it already has to decide, in order to rate-limit. So
attribution reuses that decision rather than making a second one: the source is
resolved **once** per provision and is both the rate-limit bucket and the address
forwarded to the host. Two determinations could disagree, and a bound that
counted one address while the record named another would be worse than no record.

What goes on the wire is a **single-entry `X-Forwarded-For` carrying that one
address, replacing whatever the caller sent** — never appended to:

| `SMB_SIGNUP_TRUSTED_PROXIES` | What is forwarded |
| --- | --- |
| unset / `0` | this service's socket peer. Any inbound `X-Forwarded-For` is discarded unread, so a caller cannot write its own attribution. |
| `N` | the Nth-from-the-right entry of the real proxy chain — the same entry the rate limit counts. An address a caller prepends sits to the left of what the proxy appended and is never selected. |

Appending is the version that must not be written: it hands the caller a
plausible forged address, which is worse than `127.0.0.1` — one obviously wrong
value is visibly wrong and a plausible one is not — and it makes the chain's
*length* caller-controlled, so what a hop count selects stops being fixed.

**`provisioned_by` identifies the network address this service resolved for the
connection that asked, under the hop count its operator declared — nothing more.**
It is a network-path observation, not a person and not an identity: it does not
say who, it is shared by everyone behind one NAT or one corporate proxy, it
changes when the same person's address changes, and where the declared hop count
is wrong it is whatever that declaration selected. It distinguishes callers, and
only as well as the network distinguishes them. It is never used to authorize or
refuse.

**The host half has to be configured too: set `SMB_HOST_TRUSTED_PROXIES=1` on the
host behind this service.** `smb_host` ignores `X-Forwarded-For` entirely below
that, because a header from a peer it was not told to trust is exactly what it
must not believe. Both halves are individually correct and the pair does nothing
when the host's is unset — provisions succeed, the record fills in, and every row
says this service's own address. `GET /health` reports `caller_attribution` so
that is read off a surface rather than discovered later from a directory of
identical attributions.

### No cross-origin access, on purpose

This service *serves* the funnel, so the public shape is same-origin and needs no
cross-origin permission — and it grants none. `smb_host` allows any origin
because a static bundle hosted elsewhere has to reach it, **and because
provisioning there is gated on a bearer token a stranger's page does not hold.**
This front door has no such gate by design: provisioning through it carries no
caller credential at all, so granting any origin access would let any page on the
internet spend a visitor's rate-limit allowance and this cap from that visitor's
browser — and, now that the caller is forwarded, record that visitor's address as
having provisioned an agent. The permission that is safe on the host is not the
same permission here, because what made it safe there is a gate this service does
not have.

The absence is asserted in the suite so that hosting the bundle elsewhere fails
loudly and forces the choice to be made again, rather than being discovered as a
missing header. `smb_funnel/src/config.js` says the same thing on the page's
side: `API_BASE` may point cross-origin at `smb_host`, and pointing it
cross-origin at this service is not a supported shape.

**And a page in the unsupported shape is now told the truth.** A browser that
stops a request hands page script an error with no status, so the funnel rendered
its catch-all *"Couldn't create your agent. Please try again."* — a verdict on an
exchange that never happened, and advice that could never work. Every status this
service can send was equally invisible. The funnel now has a distinct state for
"nothing was received", which claims nothing about the details entered or about
capacity, and names the one cause a page can check for itself: it is configured
to call another origin. It does not claim the cause was CORS, because page script
cannot tell a refused preflight from a dead host.

## Observability

`GET /health` reports the cap, the count, the headroom, and whether the caller
this service forwards is actually recorded:

```json
{ "status": "ok", "service": "smb-signup", "configured": true,
  "tenant_cap": 250, "rate_per_hour": 5,
  "tenants": 31, "headroom": 219, "at_capacity": false,
  "caller_attribution": "recorded" }
```

**A cap nobody can see coming is learned from the first business turned away.**
If the host is unreachable, `headroom` is `null` and `host_unreachable` says why —
a health surface that invents a number is worse than one that admits ignorance.

`caller_attribution` is read from the host's own `/health`:

| Value | Meaning |
| --- | --- |
| `recorded` | the host trusts at least one hop, so the caller stated here is what `provisioned_by` gets. |
| `discarded-by-host` | `SMB_HOST_TRUSTED_PROXIES` is `0` or unset on the host, so every provision is recorded as **this service's** address. Forwarding is doing nothing. |
| `unknown` | the host could not be reached, or is older than the field. Never guessed, for the same reason `headroom` is not. |

## The contract

A façade of the shape `smb_funnel` already speaks, so the funnel needs no new
configuration switch. This service **serves** the bundle, so the page it hands a
visitor is already talking to its own origin and needs no `API_BASE` at all;
pointing a separately-served page at this origin is the shape above that does not
work.

`POST /provision` carries `{business_name, service_type?, contact}`. The
**contact is required**, because a business that cannot be reached cannot receive
a booking — provisioning without one would ship exactly the outcome the booking
work removed.

**The shape is checked here; the contact's meaning is not re-judged.** What counts
as a usable contact is derived from what the host's delivery path can actually
deliver on, so that rule stays the host's: a second opinion in this façade could
accept something the host would refuse, or refuse something it would take. The
same reasoning as leaving confusable names to the host — a check that does not own
the thing it checks lets two services disagree. A refused contact also does not
spend cap headroom, or anyone could exhaust the front door with requests the host
was never going to accept.

| Method & path | Bounded | Credentialed |
| --- | :---: | :---: |
| `POST /provision` | **yes** — rate limit, then cap | this service's token, added here; caller forwarded |
| `GET /t/{tenant}/.well-known/agent.json` | no | no |
| `POST /t/{tenant}/book` | no | no |
| `GET /health` | no | no |

Reading a card and making a booking mint nothing and write no key material, so
they are relayed untouched. An `Authorization` header supplied by a browser is
**discarded**, never forwarded: the credential on the wire to the host is this
service's, or there is none.

Refusals keep their own statuses so the funnel can give correct advice:

| Status | Meaning | Does waiting help? |
| --- | --- | --- |
| `429` | too many signups from this source | **yes**, it clears on its own |
| `507` | the whole allocation is issued | **no**, an operator must raise the cap |
| `503` | this service is misconfigured, or the host is unreachable | no |
| `502` | the host could not be reached to provision | maybe |
| `400`/`409`/`422` | the host's own refusal, passed through unchanged | depends |

## Running it

```bash
SMB_SIGNUP_HOST_URL=http://127.0.0.1:8080 \
SMB_HOST_PROVISION_TOKEN=… \
SMB_SIGNUP_TENANT_CAP=250 \
SMB_SIGNUP_RATE_PER_HOUR=5 \
python3 -m uvicorn smb_signup.main:app --port 8700
```

Tests — the bounds are proven by **reaching** them, never by reading a constant:

```bash
PYTHONPATH=agent:. python3 -m pytest smb_signup/test_main.py -q
```

## What this does not do

- **It does not stop confusable names.** `Corner Bakery Ltd` still provisions
  beside `Corner Bakery`; the host's `409` catches exact slug collisions only. On
  a public product whose agents take bookings, that is a route to taking another
  business's customers. It is not fixed here on purpose — see below.
- **It does not verify that a business is the business.** `POST /provision`
  checks no relationship between the caller and the name, and this front door
  adds none. A tenant URL identifies a tenant, not a business.
- **It does not make bookings reach anyone.** An agent provisioned today takes
  bookings that notify no human. Public signup must not open before that is true.

### Confusable names belong in the host, not here

A normalized-name check placed in this façade would only see the tenants it
provisioned itself, so an operator-path tenant would be invisible to it — and the
authority on tenant identity is `smb_host`, which already owns slugging and the
`409`. Splitting name policy across two services lets the two disagree, and a
check that cannot see the whole namespace is the same shape as the façade
without a bound: it looks like a control and is not one.

The recommendation is a **confusability key** in `smb_host` alongside the
existing slug: case-folded, punctuation and whitespace stripped, common
suffixes (`ltd`, `inc`, `llc`, `co`) removed, and confusable characters mapped to
a canonical form. Store it per tenant and refuse a collision with a distinct
status so the funnel can say *"a business with a very similar name is already
here"* rather than the generic `409`. That is a `smb_host` change with its own
migration for existing tenants, which is why it is named here rather than
half-built.
