# Running the SMB host for other people

[`README.md`](./README.md) in this directory shows how to start the host and drive it. This page
is the other half: what running it for real businesses costs, what an operator has
to decide, and how to tell — before anyone depends on it — whether the deployment
will survive its own first redeploy.

Provider-agnostic. Nothing here names a hosting product, and nothing here needs
one: the whole contract is a container, five settings and a volume.

**Read the first section before deploying.** It is the one that decides whether a
provisioned business still exists tomorrow.

| Claim on this page | Status |
|---|---|
| What a tenant home contains, and which file holds the key | **Verified** — listed the directory after a provision, and again after a booking; the two differ |
| A tenant's `did:key` survives a restart in place | **Verified** — driven |
| The default keystore backend does **not** survive a host identity change | **Verified** — reproduced; the host fails to boot |
| `COMMUNITY_MEMBER_KEYSTORE=passphrase` does survive one | **Verified** — same drill, identity stable |
| The five settings' unset and wrong behaviour | **Verified** — each case driven |
| The provisioning gate's five cases | **Verified** — each driven, including the pool warmer |
| Which backend the published image picks on first boot | **UNVERIFIED** — inferred from the code; the check that settles it is below |

---

## 1. The state on disk is the business's identity

Tenant homes live under `SMB_HOST_DATA_DIR`. The image sets it to
`/data/smb-tenants` and declares `VOLUME ["/data"]`. One directory per tenant,
named by its `tenant_id`:

A freshly provisioned tenant has **four** files:

```
<data dir>/<tenant_id>/
  keystore.enc          # the Ed25519 private key, encrypted   (mode 0600)
  keystore.meta.json    # which backend encrypted it
  config.json           # agent id, display name, skills, PUBLIC key
  smb_tenant.json       # tenant_id, business_name, service_type, did, endpoint
```

Two more appear at the **first booking**, not before — serving the card and
AgentFacts creates nothing on disk:

```
  bookings.json         # this tenant's bookings
  agency-log.sqlite     # the Agency Log, where signed receipts are persisted
```

So a tenant that has been provisioned but never booked is a four-file directory,
and that is the normal state of every canary tenant and every business that has
not taken its first appointment. An operator inspecting the volume should not read
the absence of the other two as damage.

`keystore.enc` is the whole business. The `did:key` a tenant's agent card
advertises is derived from that key, and every booking receipt is signed with it.
`config.json` carries the public key only — the private half is moved into the
vault and the field is left empty, which is worth knowing before anyone treats
`config.json` as harmless.

**The recovery phrase is not on disk and cannot be.** Provisioning returns a
24-word phrase to the caller once, in the `POST /provision` response body. This
host never writes it anywhere — checked by searching every file in a freshly
provisioned tenant home for it, and it appears in none of them. That is the
correct design and it has a consequence an operator has to plan around: if the
caller did not keep the phrase, nothing can reproduce that key.

**Nothing here re-associates a recovered key with an existing tenant home.**
There is no import route, no restore route, and no parameter on `POST /provision`
that accepts a phrase — the phrase generator is only ever used to mint a new
identity. So "recovery" today means the phrase reconstructs a key in some other
tool that accepts one. It does not mean this host can be handed a phrase and put a
business back. If a tenant home is lost, that business's agent is gone from this
host, and the URL its customers hold resolves to nothing.

### A volume is necessary and it is not sufficient

Two independent things have to be true for a provisioned business to survive a
redeploy. The first is well understood; the second is the one that will bite.

**A container without a persistent volume loses every business on the next
deploy.** The tenant directory goes with the container filesystem, every
`keystore.enc` with it. Nothing is recoverable from this host, and the only thing
that could reconstruct a key is a phrase this host never stored.

**With a volume, the key can still become undecryptable, and the whole service
then fails to start.** `keystore.enc` is encrypted under a passphrase chosen by
the keystore backend, and the default backend in a headless container is
`device` — a fingerprint derived from the machine, deliberately, so that copying
a vault to another machine does not yield a usable key. The fingerprint is built
from the hostname, the home directory and the machine id. **A container gets a new
hostname on redeploy**, so the fingerprint changes, and the vault written by the
previous container cannot be opened by the new one.

The failure is total rather than partial. Rehydration has no per-tenant error
handling, so the first undecryptable home raises out of application startup:

```
ValueError: Decryption failed: wrong passphrase or tampered data
```

The process does not start, so every tenant becomes unreachable — including the
ones that would have loaded. Reproduced directly: provision under one hostname,
restart against the same data directory under a different hostname, and startup
raises before serving anything.

That it fails loudly rather than silently minting a replacement key is the one
piece of good news, and it is worth saying why it matters: a host that quietly
re-minted would keep serving cards under a new `did:key`, and every receipt it
signed afterwards would fail verification against the identity a customer already
has. A crash is recoverable. A silent identity change is not.

**The fix is to choose a backend whose passphrase you control**, which the agent
runtime already supports for exactly this reason:

```
COMMUNITY_MEMBER_KEYSTORE=passphrase
COMMUNITY_MEMBER_PASSPHRASE=<a secret you generate and keep>
```

Verified with the same drill: provision, then restart against the same data
directory under a different hostname. The host boots, the tenant rehydrates, its
card serves the **same** `did:key`, and a booking taken after the restart returns
a receipt signed by the original key.

Treat `COMMUNITY_MEMBER_PASSPHRASE` as the thing that decrypts every business on
the host, because it is. Losing it is equivalent to losing the volume.

**Switching backends after tenants exist is a migration, not a setting change.**
The environment override is consulted before the backend recorded in
`keystore.meta.json`, so pointing an existing `device` vault at `passphrase` does
not convert it — it tries the wrong passphrase and lands in the failure above.
Decide before the first provision.

**Which backend a fresh container actually picks is the one thing here not
driven.** The selection probes the OS keyring by using it, not by importing it,
then falls back to a passphrase prompt only if there is a terminal, and to
`device` otherwise — so a container with no keyring daemon and no terminal lands
on `device`. That is inference from the code, not an executed check. Settle it in
one command against the deployed volume:

```bash
cat <data dir>/<any tenant_id>/keystore.meta.json
# {"agents": {...}, "current_backend": "device"}   <- machine-bound, will not survive
# {"agents": {...}, "current_backend": "passphrase"} <- survives, given the same secret
```

---

## 2. The five settings

Four are this host's own. The fifth belongs to the agent runtime underneath it
and is listed here because leaving it unset is the failure in section 1.

### `HOST_PUBLIC_URL`

The address this host is reachable at from outside. It is written into every
provisioned agent's card and returned as `endpoint` — the value a business hands
to a card host, a customer, or an index.

- **Unset:** the host boots and serves `/health`, and `POST /provision` refuses
  with `503` naming the variable — for an authorized caller. An unauthorized one
  is refused first, with the `401`, so a configuration mistake is never disclosed
  to a caller who has not proved authority. Deliberate: an address nobody stated
  would be a guess that reads as a fact.
- **Wrong:** nothing refuses. Provisioning succeeds and returns an endpoint that
  resolves nowhere or somewhere else, and the business finds out when a customer
  cannot reach them. Behind a proxy or a tunnel this is the public name, not the
  local bind address.
- **Changing it:** captured once when the application is built, so a change needs
  a restart. Confirmed by changing it in a live process and watching provisioning
  keep returning the old base. On restart, existing tenants' endpoints are
  recomputed from the new value, so a moved host serves its existing tenants at
  the new address — but any card already published elsewhere still points at the
  old one.

### `SMB_HOST_PROVISION_TOKEN`

The shared secret gating `POST /provision`, sent as `Authorization: Bearer
<token>`. Provisioning mints an identity and writes a tenant home, so an open one
lets anyone who finds the host mint identities in someone else's business name.
The configuration table and the full rationale are in [`README.md`](./README.md); what an
operator needs here is the behaviour, driven:

| `SMB_HOST_PROVISION_TOKEN` | `HOST_PUBLIC_URL` | `POST /provision` |
|---|---|---|
| set | any | `201` with the right bearer; `401` for a missing header, a wrong scheme or a wrong secret |
| unset | loopback | open — the development shape |
| unset | anything else | `503` naming `SMB_HOST_PROVISION_TOKEN`, and the pre-warm pool does not run either |
| either | **unset** | `503` naming `HOST_PUBLIC_URL`, warmer refused too — fix this one first |

- **Unset on a public address:** refused rather than opened, and the refusal
  covers the background warmer as well as the route — so a misconfigured host
  produces no identities at all rather than quietly minting them ahead of demand.
  `/health` shows `pool_ready: 0`.
- **Wrong:** every caller gets `401`. The refusal carries nothing derived from the
  value supplied and is identical whether or not the business name would have
  collided, so it cannot be used to ask which names are taken.
- **Changing it:** read from the environment on every request, so there is no
  cached copy to worry about and **no overlap window** — the moment the value
  changes, callers using the old one get `401` on the next call. Confirmed in a
  live process. In practice changing a container's environment restarts it
  anyway; the point is that there is no rotation endpoint and no grace period, so
  a rotation is a coordinated change with whatever calls `/provision`.

### `SMB_HOST_TENANT_CAP`

The maximum number of tenants — claimed or a not-yet-claimed pool slot — this
host will ever hold. Unlike the other three, there is **no loopback carve-out**:
provisioning mints an identity and writes a vault with no delete route, so an
unbounded cap is unlimited identities accumulating with no way to remove them,
on `127.0.0.1` as much as on a public address.

- **Unset, empty, `0` or unparsable:** refused the same way an unset
  `HOST_PUBLIC_URL` is — `503` naming `SMB_HOST_TENANT_CAP` for an authorized
  caller, and the pre-warm pool does not start either, for the same reason: the
  warmer mints before any request arrives.
- **Reached:** `POST /provision` refuses `507`, distinct from the `503` above —
  one is an operator omission, the other is real demand meeting a real limit.
  `GET /health` reports `tenant_cap`, `headroom` and `at_capacity` so this is
  visible before a business is turned away.
- **Raising it live:** read on every provision and on every warmer tick, so
  raising it takes effect without a restart — the warmer resumes topping up the
  pool on its next tick once headroom exists again.
- **It does not gate reclaiming.** Re-keying a stranded pool home (below)
  creates no new home and moves the count by nothing, so a host at its cap still
  makes its own stranded slots usable. Gating that too would leave a full host
  permanently unable to serve anyone while holding homes nobody can reach.

#### Sizing it: `tenants` counts homes, not businesses

A host that has served no business at all still holds tenant homes, because the
pre-warm pool mints them before anyone asks. `GET /health`'s `tenants` counts
homes; the businesses among them are the ones whose `smb_tenant.json` records
`"claimed": true`. A cap sized against a signup forecast alone will be reached by
pool slots first.

`SMB_HOST_TRUSTED_PROXIES` is related but not a bound: it decides how many
`X-Forwarded-For` hops this host trusts when recording which caller a provision
is attributed to (`smb_tenant.json`'s `provisioned_by`). Unset trusts nothing and
records the raw socket peer, which behind an unconfigured proxy is that proxy's
own address — a real limit on what the record can say, not a bug. It never
refuses a request; it only decides what gets written down.

**Set it to `1` when `smb_signup` is in front of this host.** The front door
states one resolved caller per provision in a single-entry `X-Forwarded-For`,
replacing anything the caller supplied, so one trusted hop is exactly right and
`0` records the front door's address for every visitor. Check it without reading
the container's environment: `/health` reports `trusted_proxies`, and
`smb_signup`'s `/health` reports `caller_attribution` — `recorded` when this host
is set to honour what the front door states, `discarded-by-host` when it is not.

### `SMB_HOST_DATA_DIR`

Where tenant homes live. The image sets `/data/smb-tenants`, with `/data`
declared as a volume.

- **Unset:** falls back to a user-writable path under the standard data
  directory. Fine on a workstation; on a container it is a path inside the
  container filesystem, which is section 1's first failure.
- **Wrong (pointing at non-persistent storage):** nothing refuses, nothing warns,
  and the first deploy looks perfect. The loss appears on the second one. This is
  the case the redeploy check in section 3 exists to catch.
- **Changing it:** captured at startup. Pointing it at a new location does not
  move anything; the previous tenants simply are not found, and `/health` reports
  `tenants: 0`.

### `COMMUNITY_MEMBER_KEYSTORE` and `COMMUNITY_MEMBER_PASSPHRASE`

Which backend encrypts each tenant's key, and the secret it uses. Not this host's
variables — they belong to the agent runtime it embeds — but on a container they
decide whether section 1's failure happens.

- **Unset:** a headless container lands on the machine-bound `device` backend,
  which does not survive the container's hostname changing.
- **Set to `passphrase` with no `COMMUNITY_MEMBER_PASSPHRASE`:** the backend
  wants a prompt and there is no terminal to prompt on. Set both or neither.
- **Passphrase lost:** every tenant vault on the volume is undecryptable and the
  host will not start. There is no recovery path on this host.
- **Changing it after tenants exist:** a migration, not a setting change — see the
  end of section 1.

---

## 3. After deploying: seven checks

Run them in order against the deployed host. The first six prove it works. The
seventh proves it will still work tomorrow, and it is the one that gets skipped.

**There is a script that runs all seven**
([`scripts/smb_host_canary.py`](../scripts/smb_host_canary.py)), and for check 7
it is not merely the convenient form — it is the only form. Run by hand, check 7
can compare a tenant against a redeploy you just performed; the script records
each run's tenant in a state file and compares against a tenant an **earlier** run
provisioned, which is the comparison that catches a volume quietly replaced
between deploys nobody was watching. Read the rest of this section anyway: it says
what each check establishes and how it fails, which the script's output assumes
you know.

```bash
export SMB_HOST_PROVISION_TOKEN=…     # read from the environment only, never argv
python3 scripts/smb_host_canary.py \
  --base-url https://smb.example.com \
  --state-file ./smb-canary-state.json
```

Both flags are required and neither has a default — pointing it at the wrong host,
or silently reusing another host's state, is the mistake worth making hard. It
exits `0` when every check passed **or** when check 7 had no prior state to
compare, and it reports that case distinctly rather than as a success: a run that
verified nothing must not read as a run that verified something.

⚠️ **Every run provisions a real tenant on the real host, and it stays.** There is
no delete route, so canary tenants accumulate on the volume — one Ed25519 key and
one small directory per run. That is the running cost of the check, and it is the
reason check 7 means anything. They are named with a fixed prefix so an operator
reading the volume can tell them from businesses somebody actually onboarded.

To run the checks by hand instead:

```bash
BASE=https://smb.example.com          # your HOST_PUBLIC_URL
TOKEN=…                                # your SMB_HOST_PROVISION_TOKEN
```

**1 — Health.** `tenants` counts every tenant the host holds, the pre-warmed ones
included, so at the default `SMB_HOST_POOL_SIZE=3` a first deploy reports `3`
rather than `0`.

```bash
curl -fsS "$BASE/health"
# {"status":"ok","service":"smb-host","tenants":3,"pool_target":3,"pool_ready":3,"pool_reclaimable":0,"tenant_cap":50,"headroom":47,"at_capacity":false,"trusted_proxies":0}
```

`tenants: 0` with `pool_ready: 3` cannot occur — a ready pool tenant is a tenant.
`tenants: 0` with `pool_ready: 0` means the warmer never started; the log names
the variable that is missing.

**2 — Provisioning is refused without the credential.** Expect `401`, and
`WWW-Authenticate: Bearer`. A `201` here means the host is open; stop and fix it
before going further.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/provision" \
  -H 'Content-Type: application/json' -d '{"business_name":"Check Co"}'
# 401
```

**3 — Provisioning is accepted with it.** Keep the response; the next checks use
`tenant_id` and `did`.

```bash
curl -s -X POST "$BASE/provision" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"business_name":"Check Co"}'
# {"tenant_id":"…","endpoint":"…","recovery_phrase":"…24 words…","did":"did:key:z6Mk…"}
```

**4 — The returned endpoint serves the card, and the card agrees with the
response.** The card's `url` must equal the `endpoint` returned, and its
`x-nanda.did` must equal the `did` returned. If the `url` is wrong, `HOST_PUBLIC_URL`
is wrong.

```bash
curl -fsS "$BASE/t/<tenant_id>/.well-known/agent.json"
```

**5 — AgentFacts resolves, and names the business.** The card points at it; a
card advertising a pointer that 404s is one defect this check exists for. The
other is what the document says once it resolves — this is the NANDA-facing half,
the one a card host hands onward to register the business, so `label` and
`provider.name` must be the business, not the pre-mint placeholder.

```bash
curl -fsS "$BASE/t/<tenant_id>/agentfacts.json"
# label, provider.name  -> the business_name from check 3
# agent_name            -> the tenant_id, deliberately: it is the agent's stable
#                          identifier, not a display name
```

`label: "(unclaimed)"` on a provisioned tenant means the claim did not reach the
tenant's config — the card would read correctly while the document a registry
consumes would describe no business.

**6 — A booking returns a receipt signed by the provisioned identity.** The
receipt's `issuer_did` must equal the `did` from check 3. Anything else means the
tenant is signing under a key its card does not advertise.

```bash
curl -s -X POST "$BASE/t/<tenant_id>/book" -H 'Content-Type: application/json' \
  -d '{"service":"Check","provider":"Ops","datetime":"2026-01-01T10:00:00Z"}'
```

**7 — Redeploy once, then confirm the tenant from check 3 still resolves.**

```bash
# trigger a redeploy by whatever mechanism your platform uses, then:
curl -fsS "$BASE/t/<tenant_id>/.well-known/agent.json"     # 200, SAME did as check 3
```

**Check the tenant, not the count.** `tenants` is not a usable signal across a
redeploy: rehydration loads the unclaimed pool tenants without returning them to
the pool, so the warmer mints a fresh set and the number grows by the pool size
every time the host restarts, whether or not anything was lost. Measured on one
restart with a surviving volume and nothing lost, `tenants` went from `4` to `7`.
A reader comparing counts would read that as a gain and a real loss as noise.

The tenant from check 3 is the signal. It resolves and serves the same `did:key`,
or it does not.

This is the only check that proves the volume is real and the keystore backend
survives, and it is the only one whose failure is expensive. Three distinct
failures show up here and nowhere else:

- **The host does not come back at all** — the vault cannot be decrypted under
  the new container's fingerprint. Section 1.
- **The card 404s** — the data directory was not backed by persistent storage.
  Every business provisioned before the redeploy is gone. Note the count does not
  show this: a host that lost everything still reports the pool it just minted,
  which is why the card is what you check.
- **The card serves a different `did`** — should not happen, and would mean a key
  was re-minted rather than reloaded. Treat it as an incident: every receipt
  signed before the redeploy now fails to verify against the current card.

A deployment that has skipped this check looks **identical** to one that is about
to lose everything. Both answer every other check correctly. Run it before a real
business provisions, not after.

Once the host is live, this is the check worth running on a schedule rather than
once — a volume can be replaced by a later deploy just as easily as by the first
one. That is what the canary script's state file is for.

---

## 4. Asking the host who provisioned what

Every claim records `provisioned_by` and `provisioned_at` into the tenant's
`smb_tenant.json`. `GET /provisions/summary` reads that record back. It takes the
same credential `POST /provision` does:

```
curl -sS -H "Authorization: Bearer $SMB_HOST_PROVISION_TOKEN" \
     https://<host>/provisions/summary
# {"tenants":6,"claimed":3,"unclaimed_pool_slots":3,"recorded":[{"source":"203.0.113.9","count":2,"first_provisioned_at":"2026-08-30T18:04:11+00:00","last_provisioned_at":"2026-08-30T18:07:52+00:00"}],"unattributable":1,"unrecorded":0}
```

Without the bearer it answers `401`, and the body is identical for a missing
header, a wrong scheme and a wrong secret — the response cannot be used to
measure the host. It is an **aggregate, not a roster**: it names no `tenant_id`
and no business. The distribution is what answers "who provisioned these", and a
per-tenant listing would additionally hand its reader every tenant id on the
host.

Unlike `POST /provision`, it does **not** refuse when `SMB_HOST_TENANT_CAP` is
unset. That configuration is one of the states this endpoint exists to explain,
and a diagnostic that refuses in the configuration it diagnoses is not one.

Four buckets, and the differences between them are the point:

| Field | What it counts |
|---|---|
| `recorded` | Claims whose caller signal resolved, grouped by source, with the first and last timestamp for each. What `source` is worth depends on `SMB_HOST_TRUSTED_PROXIES` — see section 2. |
| `unattributable` | Claims that WERE attributed and whose signal did not resolve. Attribution was attempted and failed. |
| `unrecorded` | Claimed tenants carrying no `provisioned_by` key at all — provisioned before the field existed. Nothing was ever attempted. |
| `unclaimed_pool_slots` | Pre-minted pool tenants nobody has claimed. Not provisions at all. |

`unattributable` and `unrecorded` are never defaulted to one another, and two
identities hold on every response, so you can check that no tenant was dropped or
double-counted:

    tenants == claimed + unclaimed_pool_slots
    claimed == sum(recorded[].count) + unattributable + unrecorded

### `tenants` counts homes, `claimed` counts businesses

These are different numbers and only the second one answers "how many businesses
are on this host". A tenant home exists from the moment the warmer mints it,
which is before anybody has asked for it and whether or not anybody ever does.
Reading `tenants` on `/health` as a signup count is the specific mistake this
endpoint exists to prevent — the deployed host reported 83 tenants and 5
businesses. Section 5 explains where the other 78 came from.

## 5. Stranded pool slots, and why the tenant count used to climb on its own

A pool tenant's one-time recovery phrase exists only in memory between its mint
and its claim — it is never persisted, which is what makes it a real secret. So a
slot that survives a restart no longer has one, and `_load_tenant_from_home`
correctly refuses to put it back in the pool: handing it to a business would
return an empty string in the field that is the sole means of recovering that
business's key.

The consequence, before the warmer learned to reclaim: every boot started with an
empty queue, minted `SMB_HOST_POOL_SIZE` fresh homes, and left the previous
boot's un-claimed ones on disk where nothing would ever look at them again.
**Tenant count rose by the pool size per restart, with no provision involved**,
and the stranded homes could never be handed to anyone.

Measured on the deployed host on 2026-08-30, derived read-only from its complete
deployment history: 58 container boots, 26 of which ran the warmer (the other 32
refused it because `SMB_HOST_TENANT_CAP` was unset), and **5 successful
`POST /provision` in the service's entire lifetime**, all within its first two
days. `26 x 3 + 5 = 83`, which is exactly the tenant count the host reports. Of
83 homes, 5 are businesses and 78 are stranded pool slots.

**What happens now.** The warmer spends a stranded slot before it mints anything
new: the home is re-keyed in place — a fresh recovery phrase generated for it, so
the phrase handed out at claim really does recover that tenant's key — and put
back in the pool. Tenant count is stable across restarts, and an existing backlog
is consumed by real signups instead of accumulating beside them.

`GET /health` reports `pool_reclaimable`, the size of that backlog. Falling while
`tenants` stays flat is the reclaim working.

### What is never re-keyed

Re-keying replaces the Ed25519 seed in a tenant's vault. On a slot nobody
claimed that costs nothing. On a claimed tenant it would destroy a business's
signing identity, recoverable only from a phrase its owner saw once. A home is
re-keyed only when **all** of these hold together, each a positive property the
warmer itself writes at mint time and that a claim overwrites:

- `claimed` is explicitly `false` in `smb_tenant.json`. A home whose meta lacks
  the key at all rehydrates as *claimed* and is excluded — which is what keeps a
  tenant provisioned before that field existed out of reach.
- it is not already sitting in the pool queue.
- its id carries the warmer's own `smb-pool-` prefix; a cold-provisioned tenant's
  id is the slug of its business name.
- its display name is still the `(unclaimed)` placeholder.
- it has no stored contact, and no `provisioned_at`/`provisioned_by`.

Requiring several together means no single missing or corrupted field can make a
business's home look reclaimable. The asymmetry is deliberate: an over-strict
rule leaves a home stranded, which is the behaviour that already existed; an
under-strict one destroys a business.

## 6. What this host does not do

Each checked against the code rather than assumed.

- **It does not register anyone on any index.** The service imports no HTTP
  client — there is no `httpx`, no `requests` and no `urllib.request` anywhere in
  it, so there is nothing for it to call out with. `POST /provision` returns
  `{tenant_id, endpoint, did, recovery_phrase}` and stops; making the agent
  discoverable is a downstream operator's job.
- **It does not back up tenant homes.** Nothing in this service copies, exports or
  snapshots a tenant directory. The volume is the only copy, and the encrypted
  vault on it is only useful together with the secret that opens it — a copy of
  the volume alone does not preserve a business under the `device` backend.
- **It does not store the recovery phrase**, and offers no way to redeem one. See
  section 1.
- **It does not authenticate the booking route.** `POST /t/<tenant>/book` takes no
  credential. Anyone who knows a tenant id can create bookings under that business
  and receive receipts signed with its key. The identifier is in the business's
  own published card, so it is not a secret and cannot be treated as one. Cards
  and AgentFacts are likewise open, which is correct for documents meant to be
  resolved; the booking route is the one where "open" is a decision an operator
  should make knowingly.
- **It does not offer token rotation as an operation.** There is no endpoint and
  no reload signal — only the environment, and no grace period. See section 2.
- **It does not isolate tenants from each other at the process level.** Each
  tenant has its own home, vault, identity and booking store, and that is real
  isolation of state; but one process serves all of them, so it is not a
  boundary that survives a compromise of the process.

## What is deliberately not here

No service-level objective, no scaling guidance, no backup procedure and no
incident runbook. There is nothing in the tree to derive them from: no load has
been driven against this host, no backup mechanism exists to document, and an
availability target this project has never measured would be a number invented to
look complete. Section 1 states what the durability actually depends on, which is
what those sections would need as their input anyway.
