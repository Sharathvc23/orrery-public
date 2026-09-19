# Changelog

All notable changes to Orrery are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). The Python packages (`server`, `agent`, `skill`)
and the agent JS surfaces share the `0.3.0` line.

> **`0.3.0` is the first public release. Orrery is not a new project.** It was
> developed privately through `0.1.0` and `0.2.0` — `0.1.0` was the initial
> working system, and `0.2.0` was the agent-native pivot (Orrery became an org of
> accountable agents rather than a SaaS app) together with a full two-phase
> security audit and release-readiness hardening.
>
> Those entries are not reproduced here, and the omission is deliberate rather
> than tidying: every one of them cited pull requests in a private repository,
> and a changelog entry whose evidence a reader cannot open is a claim, not a
> record. What survived that history is not the entries — it is the software, and
> the audit findings and their dispositions, which are written out in full in
> [`docs/audit/RELEASE_SIGNOFF_v0.2.0.md`](docs/audit/RELEASE_SIGNOFF_v0.2.0.md) and
> [`docs/HARDENING.md`](docs/HARDENING.md) as prose a stranger can check against
> the code in this repository.

## [Unreleased]

Unreleased changes are recorded as fragments under `changelog.d/` — one file per change, so pull requests do not conflict here. `python3 scripts/changelog_assemble.py --preview` renders them; `--release <version>` writes the release section.

## [0.3.0] - 2026-08-13

**The first public release.**

Two breaking changes, both closing a surface that was open by default: an
unconfigured org no longer talks to a registry, and the member directory no
longer answers anonymously. Everything else is the security and correctness work
that accumulated on top of `0.2.0` — member keys written down where they can be
checked, streaming surfaces inheriting the gate their non-streaming twin already
had, and jurisdiction retention overrides that can no longer shorten a statutory
minimum on a path that deletes.

### Fixed — a jurisdiction's retention number is a floor or a ceiling, never an assignment

`ORG_JURISDICTION=US-FED` **shortened** `chapter_audit_events` from the 2555-day
default to 1095 and the sweeper deleted the four years in between — in the name of a
NIST 800-171 / DFARS rule that the entry's own comment called a *three-year minimum*.
`US-HIPAA` did the same thing with a six-year minimum against a seven-year default.

The cause is one line: `retention.resolve_retention_policy` applied every jurisdiction
override as `policy[table] = days`. An assignment is neither of the two things a regime
can mean. NIST hands you 1095 saying *at least this*; GDPR hands you 365 saying *at most
this*. One operator cannot serve both, and the direction was recorded only in a comment —
including in a docstring that already promised a jurisdiction is "a floor the regime
imposes, not a ceiling on the operator's own policy".

**Every entry now declares its direction structurally.** `FLOOR` (statutory minimum →
`max` against the module default) or `CEILING` (minimisation regime → `min`), each with
the statute it comes from. There is no default direction and no inferred one: an entry
that declares neither is a `RetentionDirectionError` where the table is loaded, because
this path deletes and a defaulted direction on a delete path is how an unreviewed
deletion policy ships. The check enumerates the table rather than consulting a list of
entries known to need one — an override added in six months is covered by the same rule
as the ones written today, proved by adding a directionless entry in a test and watching
it fail. The operator's own `chapter_policy.retention_days_by_category` is unchanged and
still outranks both directions.

**No org, whatever it declared, now deletes anything it did not delete before.** A **floor**
resolved with `max` can only lengthen, and every **ceiling** entry in the table is already at
or below its default so `min` returns the number it used to assign — enumerated over the
whole table as a test rather than argued here. The only resolved changes are lengthenings:
`US-FED` audit events 1095 → 2555, `US-HIPAA` receipts and audit events 2190 → 2555.
Nothing in the repo sets `ORG_JURISDICTION` outside tests, so live orgs sweep byte-
identically either way; the `chapter_policy` database path became functional and
cannot be read from here, which is why the no-additional-deletion property is asserted
mechanically instead of assumed from the env being unset.

**Directions are exercised through the sweeper that deletes, not the resolver that
reports.** A row 1200 days old — past the US-FED floor, inside the module default —
survives a US-FED sweep and is deleted by an EU one; a resolver-only assertion cannot tell
a wired sweeper from an unwired one. Both directions are proved load-bearing by planting
the wrong one on a real entry and requiring an independent test to go red. That change's
`test_the_sweeper_honours_a_LONGER_statutory_floor` stops routing around the case its own
name promises: it asserted a *shortening* under a different jurisdiction and noted that the
US-FED floor "happens to be longer", which is exactly the case that was broken.

### Added — `POST /admin/api/keys/revoke/{agent_id}` accepts `successor_public_key`

Revoke **and** pre-authorise in one act. A bare revocation leaves the member's identity
unclaimed and the pin lands on the first claim, so from the moment an operator revokes, the
legitimate member is racing anyone else watching. Naming the successor means there is
nothing to race for: the key is on file, so every other claimant meets the guard from
the first moment. The body is optional; a revoke without it behaves exactly as before.

This lets an operator install a key rather than only deny one, and an operator holding
that key can sign **as** the member. That is impersonation rather than denial, and it would
be a new power if operators did not already have it. **They already do, by three paths,
each measured end to end across a restart:** revoke then claim the vacancy with
`X-Agent-DID-Key`; revoke then claim it with an open `POST /api/members`; or
`DELETE /admin/api/members/{id}` and register the id afresh. All three need only the admin
token plus the open registration path — no database credential — and all three end with the
operator's key in the auth store after a reboot. This endpoint adds no capability; it makes
the same act **atomic, labelled and audited** instead of a race an operator wins by going
first.

What the server cannot do, since it was proposed as a safeguard: it cannot
verify that the successor key originated with the member. Any proof-of-possession a member
could supply, an operator can equally produce for a keypair they generated — a signature
proves someone holds the private key, never *which* someone. "The operator only relays the
member's key" is a procedural control, not a mechanical one.

**Provenance gets its own value:** `operator_vouched`, carrying `attested: false` and
`vouched_by`. Stronger than a first-claim pin — a named party is accountable — and **weaker
than a rotation**, the only establishment with a signature from the key it replaces.
Precedence, asserted by tests rather than described: **rotation > operator vouch >
first-claim pin.** A rotation performed *from* the vouched key supersedes the vouch; a vouch
cannot be silently reverted by the chain it replaces; a first claim cannot displace either.

**Both halves are audited**, hash-chained: `admin.key.revoke` and a separate
`admin.key.preauthorize` carrying the operator identity. One act to the operator, two facts
to anyone reading the ledger later.

**Recovery, since a pre-authorisation can be wrong:** a member handed a key they do not hold
can neither claim nor rotate. The way back is a second revocation, which reopens the claim —
operator-mediated, and asserted by a test rather than assumed. A malformed successor is
refused outright so a typo cannot strand anyone.

### Security — a member's key is written down where it can be checked, and a pinned key says so

Three changes with one shape: the server kept accepting keys it never recorded, so the key-change guard — which only fires on a **non-empty** stored key — was a no-op for
everyone it had not recorded, and stayed one after every restart.

- **A key established by `X-Agent-DID-Key` is now persisted.** `store_did_key` filed it in
  an in-memory map that is empty on every boot, so a member whose key was only ever
  established that way had **no durable key anywhere**: the loader hydrated `public_key=""`
  and an unauthenticated `POST /api/members` could set a new one, again, after every
  restart, indefinitely.
- **A key presented for a member who has none is pinned on first claim** rather than
  accepted repeatedly.
- **`POST /admin/api/keys/revoke/{agent_id}` now actually revokes.** It nulled
  `ed25519_pubkey`, `public_key` and `signing_secret` — three columns that **do not exist**
  on `agents`. The `UPDATE` failed, the failure was swallowed, and the response said
  `revoked: true` while the durable key sat untouched in `agent_facts.provider.did`, so the
  next redeploy handed the member back the key an operator had just revoked. The first use
  case in that endpoint's own docstring is *"compromised key suspected"*. The response now
  carries `durable`, reporting whether the clear outlived the process rather than asserting
  it did.

The weakness, stated: pin-on-first-claim means whoever claims first wins. Nothing
proves the claimant is the member. This is the same trust model registration itself uses,
so it is not a new weakness — but it is a real one, and **a pinned key must never be read
as a verified key.** What it changes is the size of the window: from *replaceable at will,
by anyone, on every restart, forever, with no record* to *claimable once, durably, with an
audit row*. The hole becomes a single race instead of a standing invitation.

**It is deliberately not a refusal.** Refusing a key for a member whose key cannot be
established locks them out of their own account with no way back — they can neither
re-register (refused) nor rotate, since `/api/members/rotate` answers `no stored key for
this agent`. The rule adopted here is **never a refusal without a recovery path**.

**Narrowed as far as it goes:** a pin applies only to a member with **no key on file and no
rotation history**, never creates a member, and never displaces a key already recorded. A
member who has rotated has an *attested* key in `member_key_rotations` — the superseded key
signed for its successor — and is recovered from there instead. When the rotation table
cannot be read, the answer is *unknown* and the pin is declined.

**Distinguishable in the data, not only in the log.** `agent_facts.key_provenance` records
`registered` / `pinned_registration` / `pinned_tofu_header` / `revoked`, with
`attested: false` on every one of them — a rotation is the only establishment with a
signature behind it, and its evidence is the chain, not a marker. Each pin also appends
`member_key_pinned` to the hash-chained audit ledger, flagged `after_revocation` when it
follows one, which is the case an operator most needs to see. `agent_facts` now merges on
re-registration so a member's next profile update cannot relabel a pinned key as a
registered one.

### ⚠️ BREAKING — `REGISTRY_URL` has no default; an unconfigured org talks to no registry

An unset `REGISTRY_URL` resolved to `https://nest.projectnanda.org`, so a deployment that
configured nothing contacted a registry run by somebody else. **Not only to publish:** the
boot reconcile and federation discovery both queried it, and **neither consults
`AUTO_REGISTER`** — a self-hoster who had explicitly opted out still reached out. A default
that points a stranger's deployment at a third party is not a default; it is an assumption
about who they federate with.

**What changes for an org relying on the default:** it stops publishing **and stops
discovering peers through the registry**. Federation peers then come only from
`KNOWN_CHAPTER_ENDPOINTS`. **Set `REGISTRY_URL=https://nest.projectnanda.org` explicitly to
keep the old behaviour.**

**The failure would otherwise be silent, so it is announced in four places.** "No peers
found" is indistinguishable from "no peers exist", and a boot line scrolls past once while
discovery runs forever. Every path that would have queried now says so **at the point it
declines** — federation discovery, the registry reconcile, the agent count, and
publication — rate-limited per path (15 min) because a notice per discovery cycle is noise,
and noise is how a real warning stops being read. Each notice names `REGISTRY_URL` and the
value that used to be inherited.

**Three ungated calls were found and fixed while proving this.**
`federation_discovery.discover()` and `nanda_registry.get_agent_count()` had no
`_registry_url` check at the call site: with an empty value they built the *relative* URL
`/api/agents` and attempted it. The acceptance criterion is a driven number — **zero
outbound attempts across a real boot and a discovery cycle** — asserted in
`test_no_registry_by_default.py::test_Z1`, not inferred from reading the guards.

### Added
- **The Listing is discoverable from the node descriptor** (`sm-federation==0.6.0`). The
  §2 descriptor now carries `listing_url`, and the `listing/0.1` capability token is
  **derived by `build_node_descriptor`** from that URL — never hand-set, the same rule as
  `federation/0.1#4` from `feed_url`. A peer that has never met an org can now go
  descriptor → listing → member without being told where to look.

  `listing_url` is gated on the profile being implemented, never on the listing
  having members. Present ⟺ the token is claimed; it does **not** imply the listing is
  non-empty. An org running the surface with nobody opted in advertises it and serves an
  empty document — *"I run this surface; nobody has opted in"* is a different and more
  useful fact than silence. Gating on entry count would make the descriptor flap as
  members opt in and out, and would make an empty-but-consented org indistinguishable from
  one that never implemented the profile.

- **The Listing — consented discovery** (`sm-listing==0.3.0`). `GET
  /.well-known/agent-community-listing.json` (the profile's mandatory path, taken from
  `sm_listing.WELL_KNOWN_PATH`) publishes the members who **actively chose** to be
  discoverable, carrying **only the fields they chose**, built with the published
  `build_listing` rather than a local dict.

  It is not a filter over the member directory. The Directory stays gated and
  unchanged; this is a different resource over a different population, and its **default
  state is empty** — a community that enables it with nobody opted in publishes an empty
  document forever, which is correct rather than a misconfiguration.

  - **Consent reuses what is already here**: row visibility follows `chronicle_public`
    (explicit opt-in in `agents.config`, default private); per-field visibility follows
    `contact_public` (an unconsented field is absent, the row is not hidden for it).
    `profiles.is_public` is the counter-example on both counts. `consent_gate` is **not**
    reused — "I agreed to meet this counterparty" and "I agreed to be world-readable
    forever" are different decisions.
  - **A non-consenting member is absent**, not opaque, and **no count of them exists** —
    not published, not computed. A present-but-opaque row in an enumeration is a census of
    the non-consenting, and a count computed then withheld is one refactor from being
    emitted. (`omittedMembers` in the AI catalog is the resolvable-card rule's no-resolvable-card count and is
    not a consent signal.)
  - **§3 binds both ways.** An empty listing trivially contains no non-consenting member,
    so a consenting member must appear: `build_listing` **raises** rather than skipping an
    entry it cannot publish, and the endpoint answers **500 naming the member** rather than
    serving a listing with someone silently missing.
  - **The contact route is the member's agent endpoint**, never a human contact detail —
    and it is **server-set into the consent record**, not accepted from the member.
  - **A node that does not implement the profile 404s**, it does not serve an empty
    document. `ORRERY_LISTING_ENABLED` defaults **off**: publishing a discovery surface at
    all is a decision somebody makes, not one they inherit. An org that does implement
    it with nobody opted in serves an **empty** listing, and that is conformant and
    correct — it says *"I run this surface; nobody has opted in"*, which is a different and
    more useful fact than silence.
  - The opt-in (`POST /api/me/listing`) is **refused** when it could not be honoured, so
    "consenting implies publishable" holds by construction.


### Security — boot issued DELETEs against a registry, keyed on an endpoint string

`clean_stale_agents` ran **unconditionally in the startup path** and issued
`DELETE {registry}/api/agents/{id}` for every registry record whose `endpoint` string
equalled this org's and whose id was not one of its members. Measured against a real boot
with a registry that answered `200`: **two DELETEs, for records that were not ours**,
logged as *"NEST cleaned 2 stale agents"*. It fired with `AUTO_REGISTER=false`.

Two independent defects, and fixing either alone leaves a live hazard:

- **Destructive at boot.** Nothing triggered it and nobody asked for it. Removal is now an
  explicit operator action — `reconcile_stale_agents(url, delete=True)`. The startup path
  calls the default, which **reports and never deletes**.
- **An endpoint-string match is not identity.** Two orgs behind one hostname — a shared
  host, a reverse proxy, a redeployment that reused a name — both match, and each would
  delete the other's records. Attribution is now one of two things: **this process
  published it** (`registered_on_nest`), or **it carries this org's signed endpoint
  attestation**, whose `did` *is* this org's public key and therefore could only have been
  produced by something holding its private key. The attestation is the check that
  survives a restart, since the in-memory set is empty on a fresh boot.

Anything else — including a record that merely shares the endpoint — is **reported by name
with the reason and never removed**.

The Index half was never defective and is unchanged in behaviour: it only ever removed ids
from `registered_on_index`, this process's own record of what it published, which is
attributable identity rather than a string match.

**If you relied on boot tidying the registry:** it now tells you what it would remove
instead of removing it.


### Fixed
- **AgentFacts `provider` named the wrong organisation on every self-hosted org.**
  `provider.url` was hardcoded to `https://projectnanda.org` and `provider.name` fell back
  to `"NANDA Community"`, so a stranger resolving a self-hoster's member facts — the
  richest anonymous surface this runtime serves — was told the provider was an
  organisation with nothing to do with that deployment. Both are now derived from what the
  deployment already declares (`AGENT_ID`, `PUBLIC_URL`) and **omitted when unset**: a
  field whose honest value is unknown should be absent, not defaulted to somebody else's
  identity.

  It was an outlier rather than a convention — the A2A card already used `PUBLIC_URL`, and
  `sm_bridge_adapter` documents `provider_url = chapter's PUBLIC_URL`. A test now asserts
  the card and the facts agree, because two documents describing one org disagreeing about
  who hosts it is the same class as the two-reads-of-one-identity `did` defect.

  **`provider.did` is unchanged and the block still always exists** — member keys are
  rehydrated from `agent_facts.provider.did` at boot, and `dsar`/`agent_export` read the
  same path. "Omit what is unknown" applied one field further would have broken key
  rehydration on every restart.

  If you consumed `provider.url` expecting a constant, it is now your org's own
  `PUBLIC_URL`, or absent on an org that has not configured one.


### Security — a gated surface's streaming twin was not gated

**Seven pages answered `401` on their page path and `200` on `/stream`, emitting the
complete document to an unauthenticated caller** — `RunStarted`, then
`data: {"snapshot": {...}}`, no credentials. Measured by driving a running instance and
reading the bytes:

`/api/surfaces/settings` · `/intents` · `/messages` · `/conversations` · `/voice` ·
`/channels` · `/chapter-security`

**`/api/surfaces/settings` is a member's private preferences page** (LLM, voice, channels,
trust, privacy). This was not a design decision anyone made — the page's gate and its
stream's gate were two separate decisions with nothing tying them together, so gating a
page never gated its stream.

**Fixed as a rule, not as seven fixes.** `auth_verify.canonical_surface_path` collapses
`/api/surfaces/<page>/stream` onto `/api/surfaces/<page>` before either `is_open_path` or
`requires_auth` decides, so a twin **inherits** its page's gate. A page gated next year
cannot ship with an open stream, and nobody has to remember the pairing. The test is
derived from the gated set rather than listing the seven, so it covers pages that do not
exist yet.

**Behaviour change beyond the fix:** `/api/surfaces/today/stream` was the one gated page
whose stream was closed, by a check inside the handler that answered **403**. It now
answers **401** — refused by the middleware, before the handler, saying the accurate
thing: the caller is unauthenticated, not authenticated-and-forbidden. The handler check
remains as a second layer.

**If your UI streamed these pages:** sign the request, exactly as the page path already
required. The open pages (`dashboard`, `profile`, and the rest) are unaffected and their
streams stay open — asserted in both directions, because a rule that gated every stream
would have satisfied the fix and broken the live dashboard.

**Surveyed while here, and reported rather than assumed:** the route table has **no
websocket routes**, and the other suffixed twins (`/admin/api/audit/export`,
`/api/chapter/audit/{id}/export.jsonl`) already **agree** with their base paths. `/stream`
was the only paired form with a hole. `SURFACE_TWIN_SUFFIXES` exists so adding another
paired form is one edit rather than a second silent decision.


### ⚠️ BREAKING — anonymous member enumeration is closed

**What a stranger could read before and cannot now.** An audit drove every
endpoint of a running org and found `GET /api/members` gated (401) while the same
population was published anonymously by four other surfaces. A member's own free-text
`description` flowed into all of them: the audit put an email address and a phone number
in one and both came back to an unauthenticated GET.

**Now requires a signed request** (401 to a stranger; unchanged for a verified member):

| endpoint | what it disclosed anonymously |
|---|---|
| `GET /api/surfaces/directory` | a `MemberCard` per member — name, agent id, role, skills, description |
| `GET /api/surfaces/members` | the same |
| `GET /api/surfaces/chapter` | the org page including the full member list |
| `GET /api/surfaces/subscriptions` | member ids, names and skills |

**Changed shape rather than gated:**

- `GET /api/portal/layout` — still `200` for everyone, and still renders the org's hero,
  focus, leaders and federation. The **member section** appears only for a verified
  caller. The document was not gated because it is the org's own landing page and a
  stranger loading it is the normal case.
- `GET /.well-known/ai-catalog.json` — still `200`, still `application/ai-catalog+json`,
  and still carries the org's own entry, because it is the **unauthenticated registry
  hop**: an org registers at the Index with `registry_url` pointing at itself, so a
  resolver that has never met the org fetches this document next, and gating it would
  break the resolution the org asked for. **Member entries now require a verified
  caller**, and a new `withheldMembers` count reports how many were withheld.
  `omittedMembers` keeps its meaning exactly — members with no resolvable card URL —
  because folding the two together would make a privacy decision indistinguishable from an
  unpublished card.

**If your UI depended on this:** anonymous links to `/api/surfaces/directory` and
`/api/surfaces/members` now 401, and a crawler reading your catalog sees only your org's
entry. Sign the request as a member — the same Ed25519 scheme `GET /api/members` already
required — and every one of these returns exactly what it did before. Nothing was
deleted; the data moved behind the signature the JSON directory already required.

**Deliberately still open:** `/api/surfaces/reputation`, `profile`, `trust`,
`endorsements` and `chronicle`. Those name one agent, which is what a shareable per-agent
URL is for, and `test_read_surface_lockdown.py` already locks that decision.

**Not fixed by this, and stated because closing a surface does not un-write anything:**
`description` is still published to every signed member, to federation peers, and through
each member's AgentFacts. Registration responses now carry a `publication_notice` naming
the published fields and stating plainly that there is **no per-member opt-out today**.

### Fixed
- **`profiles.is_public` was selected and never read**.
  `/api/surfaces/profile` — one of the deliberately-open shareable per-agent pages —
  composed `full_name`, `bio`, `avatar_url`, `title`, `company` and **`location`** into a
  publicly reachable document regardless of the flag. The column appeared in the query's
  `select` list and nowhere after it. **A control that is queried and ignored is worse
  than one that is missing, because the column in the select list reads like it is being
  honoured** — the same shape as `jurisdiction.py`'s structurally-impossible reads
  and the scheduler that was never started. The flag is now consulted, failing
  closed on an absent value, and asserted both ways.

### Added
- **A general anonymous-disclosure guard**, not a list of the surfaces we happened to
  find. `test_member_enumeration_closed.py` drives **every** registered A2UI page
  anonymously and fails if a member's id, name, email, phone or skill appears in any of
  them. The ruling named two pages; driving all 42 found five, and a test hard-coding
  those five would go green forever while a sixth published the directory again.
- **Identity-aware open paths.** A few open documents now serve more to a caller who
  signed than to a stranger. The middleware short-circuited open paths *before*
  verification, so a handler could not tell the two apart; it now verifies a signature
  when one is present on those paths. This gates nothing — the result only populates
  identity, never rejects — and the paths stay declared in `OPEN_PATHS` rather than being
  quietly removed from it, because removing them would make their openness implicit again
  (the mistake).


Landed on `main` after the `0.2.0` tag; both are headline features in the README
and are live on the mesh.

### Added
- **sm-federation 0.1 §4 — a signed, completeness-verifiable intelligence feed.**
  `GET /api/federation/intelligence/feed?since=<cursor>` serves a hash-chained
  `sm-feed` page, Ed25519-signed by the org's existing key, so a peer that discovered
  this node through its descriptor can now actually **subscribe** to it. Serving the
  descriptor alone never made an org federation-capable, and this closes that.
  - **The durable log is the feature.** `public.federation_feed_entries` (additive;
    `infra/init.sql` + `infra/migrations/0005_federation_feed.sql`) backs
    `sm_feed.FeedLog`, so the chain outlives the process that wrote it. `test_D1`
    rebuilds from the persisted rows and asserts the next append continues at the
    durable tip rather than reseeding. That is a store-level restart. The process-level assertion is the feed-restart conformance work's
    `test_feed_restart.py` and it has not run: its `_boot()` never enters the
    lifespan, so the instance never runs the boot ensure and always skips.
    Pending a fix to that harness — an assertion existing is not an assertion having run.
  - **What a subscriber can detect**, each proven by planting it: a dropped entry, a
    reordered entry (every entry still individually valid — the chain is what fails),
    and a restarted sequence in **both** shapes: a shorter reseed is `head_rewind`
    and invisible to the chain; a reseed that grew past the pinned head is invisible
    to the head check and caught by the chain. Neither check subsumes the other.
  - **Boot ensure with a deliberately different failure policy from
    `pg_store.execute_ddl`'s contract.** There is no migration runner, so an existing
    install would never get the table. The ensure creates it — but a role without
    CREATE **degrades the node to §2-only, loudly, and does not raise**, and an
    unreachable database defers rather than fails (`db_reachable`'s own docstring
    already specified that). Bricking a working install to add an optional federation
    surface is worse than the surface being absent. Any other DDL failure still raises.
  - `feed_url` is gated on the table **actually existing**, so `federation/0.1#4`
    (derived by the builder, never hand-set) cannot be claimed by a node that cannot
    serve it. Such a node answers `501`, not `404`.
  - **A producer, wired at boot and after each reflection cycle**, content-deduped so an
    unchanged snapshot appends nothing. Without it the endpoint serves an empty page
    forever: an empty feed yields no cursor, so a peer cannot even begin to subscribe.
    Caught by the feed-restart conformance work's conformance suite, which landed first and measured this PR.
  - `/api/knowledge/summary` is unchanged and is **not** the feed: an unsigned,
    cursorless full snapshot, the v0.1 model §4 replaced. `test_H1` was **inverted**
    rather than deleted to keep asserting exactly that.
  - Pinned `sm-federation==0.5.0` — a correctness floor, not a bump. Below 0.4.0 a
    served feed emits a descriptor the published schema rejects; through 0.4.2
    `read_intelligence` never passed `expected_head`, so a reseed returned a bare `ok`.
    A new guard asserts the pin is one number repo-wide: `server/` had drifted to
    0.2.0 while `conformance/federation/` validated against 0.4.2.

- **A present-then-exercised layer over `federation_feed.py`.** The §4 tests assert
  behaviour; nothing asserted the guards were still *there*, and a deleted guard is
  indistinguishable from one that never fires to a suite that only checks messages.
  `test_federation_feed_guards.py` enumerates every defensive exit **from the AST**
  (18 today — no hand-maintained list, which is the suppression-list shape this
  replaces), requires each to execute under coverage, and proves each load-bearing by
  disabling it and requiring the *behavioural* suite to go red. It also asserts the
  producer is **wired** — by driving the real boot and observing the appended row,
  not by reading the source — which is the defect class 30 green tests could not see.
  It found four real gaps on its first run: the unreachable-database deferral and the
  non-envelope-tip branch were never executed, and the no-key guard and the SQLSTATE
  discriminator could both be deleted with everything still green.

### Changed
- **`server/constraints.txt`'s refusal of sm-bridge's `[feed]` extra is kept and
  clarified, not reversed.** It is about the **member-delta** store — in-memory,
  wall-clock reseeded, deliberately gapped — which still must not be hash-chained.
  The federation feed is a different payload, store and contract. This org now runs
  **two** logs and the file says which is which, because the note had already been
  overgeneralised twice, once in `conformance/federation/claims.json`,
  into "Orrery cannot have a completeness-verifiable feed", which it never said.

- **sm-federation 0.1 node descriptor — an Orrery org is federation-discoverable by a
  stranger.** `GET /.well-known/agent-community.json`, unauthenticated, serving the §2
  node descriptor of the published [sm-federation](https://github.com/Sharathvc23/sm-federation)
  protocol (`sm-federation==0.2.0` pinned). It is built with the published
  `build_node_descriptor`, not a local literal, so the wire contract has one definition
  instead of a mirror nothing compares. **Every field is read from live org state or
  omitted — nothing is synthesised to fill a slot the schema would accept empty.**
  - Open by design and *declared* open in `auth_verify.OPEN_PATHS` rather than merely
    defaulting there (the public-discovery rule: a discovery document behind auth defeats itself, and
    `did.json`'s openness was implicit, which is why it stayed broken).
  - Pure read — a keyless org gets a descriptor with `did` omitted, never an identity
    minted by an anonymous GET.
  - `did` is byte-identical to `/.well-known/did.json`. Four surfaces published the org
    DID by three different derivations; they now share one `routes.identity.org_did`,
    which also fixes the malformed `did:web:` those two emitted when `PUBLIC_URL` was
    unset.
  - `conformance_url` appears only when a badge has actually been written, and
    `feed_url` **not at all** — see Known gaps.
- **Known gap, stated rather than implied: Orrery serves the sm-federation descriptor
  but does not implement §4's intelligence exchange.** There is no signed `sm-feed`, so
  a peer that discovers this node cannot subscribe to it, and publishing the descriptor
  does not make an org sm-federation-capable. The absence is a decision with a record:
  `server/constraints.txt` already refused sm-bridge's `[feed]` extra because the
  in-memory DeltaStore reseeds from a wall-clock base_seq on every restart, so a
  completeness-verifiable feed over an intentionally gapped log would either false-alarm
  on every restart or claim a guarantee the store cannot honour. Fixing the store is the
  prerequisite; the feed is the smaller half.
- **Skill marketplace — signed `.nandaskill` packages**. A skill can be packed
  into a portable, self-authenticating ZIP bundle (manifest + signed content +
  detached Ed25519 signature) that re-verifies fail-closed on arrival, with keyless
  `GET /api/skills/{id}/package` (download) and `POST /api/skills/publish/package`
  (verify + register) endpoints. Developer-guide packaging & distribution docs.

### Security
- **Secrets are sealed at rest, and sealing is now required** (AUDIT_HARSH C11 +
  C1 + H3) — **breaking for any deployment that does not set `ORRERY_KEY_SECRET`.**
  - `ORRERY_KEY_SECRET` was optional. Unset, the server printed one warning line and
    stored the org's Ed25519 signing key in plaintext in `chapter_keys` and on disk —
    identity-forgery material in any dump, backup or replica, enough to sign ARP
    receipts, VRP attestations and federation broadcasts as the org. It now refuses to
    start (`server/secret_sealing.py`, gated by
    `env_flags.security_flag("ORRERY_REQUIRE_SEALED_SECRETS", default=True)`). Set
    `ORRERY_REQUIRE_SEALED_SECRETS=false` to deliberately accept plaintext at rest.
  - **Existing plaintext is migrated, not just new writes.** Legacy `chapter_keys` rows
    and offline key files are sealed in place on the first boot that has the secret. The
    same key bytes are re-encoded, so `did:key` is unchanged and no peer re-pins; the key
    file is also chmod'd `0600` on rewrite, which `O_CREAT` does not do for an existing file.
  - Members' LLM provider keys (`agent_api_keys.api_key_encrypted`) were plaintext despite
    the column name — both runtimes read the value straight into the provider client. They
    now go through `server/api_key_store.py`, which unseals on read and seals existing rows
    in place. These are bring-your-own-key member credentials: a leak costs the member their
    own provider spend, which is materially less severe than the signing key above.
  - The OpenClaw skill's identity key can be stored as an encrypted PKCS8 PEM by setting
    `ORRERY_SKILL_KEY_PASSPHRASE`; an existing plaintext key is re-encrypted in place,
    unchanged. Opt-in, because the passphrase must be readable by the same uid as the key
    file — it removes the key from disk images and backups, not from a same-uid attacker.
    Scope stated in `skill/SECURITY.md`.

### Changed
- **`GET /api/members` is no longer public** — **breaking for unauthenticated
  readers.** The member directory returned every member's profile and contact links to
  anyone; bulk enumeration worked. It now requires a signed member, an operator
  `X-Admin-Token`, or a signature-verified federation peer, and the
  `GET /api/federation/{peer}/members` proxy is gated with it. Unchanged: `POST /api/members`
  first-contact registration (open, TOFU) and the exact-match `GET /api/agents/{id}/profile`
  — sharing an agent's profile link still works with no account. Cross-org discovery now
  signs its outbound member query (`federation_signing.sign_request`) and reports a failed
  peer query loudly instead of returning an empty list.
- Registry heartbeat refresh records the real index status instead of an assumed one.
- `/health` `git_commit` reports the actually-deployed commit.
- Product-spec README + a full-stack capability run driven against the live mesh.

### Removed
- An internal subsystem and its `/memory/*` routes — kept internal, not shipped in
  the public release. Named only internally, so the removal is recorded here
  without the programme name.
