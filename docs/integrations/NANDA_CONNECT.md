# Decision record: NANDA Connect as the authority model for Leg C

### Should Orrery adopt `nanda-connect` (delegated binding provisioning), and where does it attach?

**Status: proposed.** Nothing is wired, and after tracing the code the
recommendation is that nothing should be until an external party answers. This
record exists because
[STELLARMINDS.md](STELLARMINDS.md) says an integration decision is recorded
before code lands.

Grounded in **current code**, traced 2026-08-01:

- **Orrery** — `origin/main` `0921851`. `smb_host/main.py` `/provision` returns
  `{tenant_id, endpoint, did, recovery_phrase}` and makes no index calls on the
  SMB path. `agent/community_member/owner.py` already separates the authorising
  principal from the agent key. `server/nanda_registry.py::register_on_index_v2()`
  registers the *org server* to the index under an explicit operator trigger.
- **nanda-connect** — `Sharathvc23/nanda-connect` `main`, v0.2.0. Field-scoped
  owner-signed grants over `sm-provision`; federated authority evidence over
  `sm-authority`; `GET /nanda-connect/catalog?subject=` groups a merchant's
  bindings into one ordered answer; grantor-bound authority evidence;
  `KVBindingStore` so bindings survive a redeploy.
- **The gap it addresses** — [SMB_NANDA_HANDSHAKE.md](SMB_NANDA_HANDSHAKE.md)'s
  own open risks, quoted below.

---

## Why: the handshake spec's three open risks are one problem

The handshake spec is engineering-ready and its remaining risks are all the same
question — *on whose authority does a registrar write a business's listing?*

| Handshake spec says | What that means |
|---|---|
| "host39 holds one machine account and registers all SMBs under it (host39 becomes org `admin`)" | One credential with admin over **every** business host39 serves. Compromise it and the blast radius is the whole population. |
| "host39 does *not* verify domain ownership today… If host39 ever vouches for `domain` orgs, it must add ownership proof — otherwise it'd be attesting an unproven claim" | The domain path is blocked on an evidence mechanism that does not exist there. |
| "**Host-vouched activation** — a verified registrar activates the subpaths it hosts *without* the per-SMB email click… Net-new." | The thing that makes the flow genuinely 3-click needs a vouching artifact nobody has specified. |

`nanda-connect` is a specification of exactly that artifact: a **per-merchant,
owner-signed, field-scoped, expiring grant** that authorises one delegate to
write one binding and nothing else. It replaces "one machine account with admin
over everyone" with "one grant per business, scoped to that business."

Its `domain_control` evidence (ACME-style challenge, bound to `grantor_did` since
That change) is the ownership proof the domain path is missing.

## What is already decided, in code

Two prior decisions bound this one, and both were made deliberately.

**`the self-registration removal` removed index registration from the SMB stack.** "Orrery must NOT
register agents to any index… that is host39's job." `index_registration.py`,
the CLI verb, the config field and every `smb_host` index call are gone, with an
acceptance grep guarding it. **Nothing proposed here re-introduces them.** A
grant is a consent artifact signed by the *owner*; presenting it to an index is
the delegate's act, and the delegate is host39.

**`build_listing_grant` already chose DAT over nanda-connect**, and says why:

> "A DAT rather than a nanda-connect grant because Orrery already vendors the
> canonical verifier in `_dat` (byte-for-byte lockstep with `conformance/dat`,
> CI-gated), and it is the format Orrery's counterparties already verify — so
> **the individual path needs no nanda-connect dependency**."

That reasoning is correct and this record does not reopen it.

## Decision

**Nothing changes for the individual path. The open question is narrower than it
looks, and it is confined to a leg that does not exist yet.**

The distinction is what `sm-provision` adds *over* `sm-dat`, since it is a
profile of it rather than a competitor:

| | says | enough for |
|---|---|---|
| DAT listing grant (today) | *this owner authorises this agent to be listed* | the individual path — **owner grants their own agent** |
| `sm-provision` binding grant | *this delegate may change **these fields**, on **these hosts**, until **then*** | a **third party** writing the owner's binding |

`build_listing_grant`'s grantee is the agent itself. Leg C's grantee would be
**host39** — a party that is neither the owner nor the agent, writing a registry
record on the owner's behalf. Field scope and target-host pinning are what bound
that, and a DAT's `action_categories` do not express either.

So: **adopt `sm-provision` only if and when Leg C is built with host39 as a
scoped delegate rather than an admin-account holder.** Until then the dependency
buys nothing, and `build_listing_grant` should be left alone.

## Positions on the four questions this raises

**1. Dependency direction — nanda-connect is not an `sm-*` library.**

STELLARMINDS.md's rule is "Orrery depends on `sm-*`; no `sm-*` may depend on
Orrery." nanda-connect is not in that set: it is a *downstream consumer* of
`sm-provision`, `sm-authority`, `sm-dat`, `sm-bridge`, and `sm-arp` — the same
tier as Orrery, not above it.

Position: **Orrery may depend on nanda-connect as a peer protocol
implementation, under the same never-patch rule.** If Orrery needs a change,
it goes upstream to nanda-connect's own repo. The arrow still never inverts:
nanda-connect must not learn about Orrery.

**2. `owner.py` stays as it is. It is not a re-implementation.**

`agent/community_member/owner.py` implements grantor ≠ grantee, citing `sm-dat`
SPEC O1 and `sm_authority`'s docstring by name, and refuses a self-granted
listing at both build and gate because `_dat` would accept one. On a first read
that looks like nanda-connect's authority model rebuilt locally. It is not, and
an earlier draft of this record wrongly implied its grant shape should be
replaced.

Three separate concerns, only one of which nanda-connect covers:

- **Key custody** — the owner key is derived from its own BIP39 phrase, used
  once, and **never persisted**, so the long-running LLM-connected runtime
  cannot hold it. nanda-connect says nothing about custody.
- **Grant shape for owner → own agent** — a DAT, for the reasons
  `build_listing_grant` states. Settled; not reopened here.
- **Grant shape for owner → third-party delegate** — does not exist yet,
  because Leg C does not exist yet. This is the only slot `sm-provision` fills.

Position: **change nothing in `owner.py`.** If Leg C is built, it gains a second
grant builder alongside `build_listing_grant`, for a different grantee. It does
not replace one.

**3. The lean index is out of scope — record it so nobody wires it.**

`index/main.py` states that open writes are deliberate: *"That is not a hole — it
is the threat model this registry exists inside."* nanda-connect's premise is
bounded write authority. These are opposite by design and both are correct for
their purpose.

Position: **nanda-connect targets `api.nandaindex.org` only.** The handshake
spec already fixes "one index" for this path. Do not add a Connect surface to
`index/`; it would contradict that module's stated threat model and buy nothing,
since the lean index exists to be corroborated against, not to be authoritative.

**4. Orrery's suspend-never-revoke is stronger than upstream — push it.**

`the platform-uninstall work` decided an uninstall webhook produces `suspended`, never `revoked`,
because *revoked* means the owner withdrew and an uninstall is the platform
observing its own billing. nanda-connect's lifecycle table currently reads
"Automatic revoke **or** suspend, without owner action," which permits the
attribution error `the platform-uninstall work` rejects.

Position: **raise it upstream as a nanda-connect spec issue.** This is the
STELLARMINDS.md pattern working in the intended direction — a downstream
consumer improving a published primitive rather than patching it locally.

## Cost

Three new upstream packages, two of them genuinely new:

| Package | Status in Orrery today |
|---|---|
| `sm-provision` | **new** |
| `sm-authority` | **new** |
| `sm-dat` | present but **vendored** (`_dat/`, byte-lockstep with `conformance/dat`) — decide whether Leg C's verifier path un-vendors or keeps the mirror |
| `sm-bridge`, `sm-arp`, `sm-conformance` | already live |

## Build order

1. **Raise the suspend/revoke issue upstream.** ✅ Done —
   `Sharathvc23/an upstream issue filed against the NANDA Connect library`. Costs nothing, improves the spec whatever
   Orrery decides, touches no Orrery code.
2. **Nothing else, until host39 answers.** An earlier draft proposed a
   grant-shape spike here. It was dropped on reading `build_listing_grant`: the
   grant already exists for the grantee Orrery actually has, and building a
   second one for a delegate nobody has agreed to be would be inventing a
   counterparty. The spike only becomes meaningful once host39 says whether it
   will hold per-merchant grants instead of one admin account.
3. **If host39 agrees**, the first real step is a `build_delegate_grant`
   alongside `build_listing_grant` — same owner principal, different grantee,
   field-scoped — verified locally with no index call, exactly as Leg B's
   publisher was built before it was wired.
4. **Leg C itself stays host39's to build.** Orrery's contribution is the
   consent artifact, never the index client — `the self-registration removal` settled that.

## Open

- **Who is the grantor for a no-infra SMB?** The personal/email path has no
  domain and no key of the owner's before provisioning. `owner.py` mints an owner
  principal from a BIP39 phrase shown once; whether an SMB who has clicked three
  buttons has meaningfully *held* that key is a product question, not a protocol
  one, and it decides whether the grant means what it claims.
- **nanda-connect is private and pre-1.0** (v0.2.0, "still in works"). Depending
  on it from Orrery means depending on an unpublished package. Either it gets
  published, or Leg C waits.
- **Does host39 want this?** Every position above assumes host39 is willing to
  be a Connect delegate rather than an admin account holder. Nobody has asked.
