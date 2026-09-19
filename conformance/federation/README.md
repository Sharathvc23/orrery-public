# sm-federation 0.1 conformance

Does Orrery implement the federation protocol we publish?

`sm-federation` is an open, vendor-neutral protocol for agent-community
federation, published to PyPI. Orrery is the reference stack. A protocol whose
own reference stack does not implement it is a whitepaper, so this suite measures
one against the other — continuously, and in a way that fails when they part
company.

## Where the contract comes from

`sm_federation.wire.load_schema(...)` — **the installed distribution**. There is
no copy of the federation schemas in this repo and there must not be: a suite
that validates against its own copy of a contract proves only that it agrees with
itself. If `sm-federation` is not installed the suite **fails**; it does not
skip, because a skipped conformance suite reports green.

This is why `sm-federation` 0.3.0 exists. The published 0.2.0 wheel contained
four `.py` files and no schemas at all, so there was no way to obtain the
published contract other than transcribing it. The 0.3.0 wheel carries both
schemas and all four vector corpora under `sm_federation/wire/` — checked
against the published artifact, not against the repo or `pyproject.toml`, which
is the reading that missed it for two releases.

## What it asserts

| File | Asserts |
| --- | --- |
| `claims.json` + `test_surface_claims.py` | per published surface, whether Orrery implements it — and checks the claim both ways; the node's own §2.1 `capabilities` declaration cross-checked against those claims; plus the profile's own valid/invalid vector corpora run through the validator this suite uses |
| `envelope_field_map.json` + `test_envelope_field_map.py` | the field-level delta between Orrery's intelligence summary and the published envelope, both directions, every field classified |

### Claims are checked, not trusted

`implemented: true` → the surface must respond **and** validate against the
published schema.

`implemented: false` → the surface must genuinely be absent. **The moment it
starts responding, the suite fails**, the claim has to be flipped to `true`, and
the schema validation above turns on.

That second direction is the load-bearing one. Without it, "not implemented yet"
exempts a surface forever, and the day somebody ships it nothing asserts it
conforms. With it, shipping the surface is what switches the assertion on.

### DRIFT vs DELIBERATE-EXCLUSION

A generic protocol legitimately omits things one implementation has, so the
verdict cannot be "these must be identical".

- **MAPPED** — the profile defines the field, possibly under another name
  (`chapter_id` → `community_id`).
- **DELIBERATE-EXCLUSION** — stays out on purpose, with a `reason_code` from a
  closed set and an argued reason.
- **DRIFT** — the profile fell behind and should carry it. **DRIFT is a hard
  failure.** It is not a bucket to park divergence in; it fails until the
  published profile moves forward or the field is reclassified. The list is
  empty by construction — the one real DRIFT this measurement found
  (`active_member_count`) was resolved by adding it to the profile, not by
  labelling it.

An exclusion is a claim the suite checks, not a label that exempts:

- the field must actually be emitted → no phantom exclusions outliving the field
  they excused;
- every emitted field must appear exactly once → nothing opts out by being
  unlisted;
- the field must be **absent from the published schema** → the day the profile
  adopts it, the exclusion is false and this suite goes red. That is a failure
  triggered by a change made in the *other* repository.

## Where it runs, and what triggers it

**Repo: Orrery. Job: `server` in `.github/workflows/ci.yml`** — not the
`conformance` job. The suite boots the real app through `TestClient`, so it
asserts what Orrery *serves*, not what a route table says; the `server` job is
the one with the runtime installed.

Triggered by the `changes` filter for the `server` group, widened to:

```
^(server/|scripts/|schema/|conformance/federation/|renderer/tests/stubdom\.mjs)
```

Both sides of the pair trigger it deliberately — a `server/` edit that breaks
conformance, and a `conformance/federation/` edit that changes what conformance
means. Listing only one side is the hole this repo has already paid for twice:
a schema-only edit skipped the suite guarding the schema mirror, and a
vectors-only edit skipped the suite guarding the vectors mirror.

### When only the *other* side changes

**This is not a cross-repo guard, deliberately, and there is no scheduled
canary.** An earlier draft had one; it was removed.

The guard runs where the implementation is, against the version it pinned
(`conformance/federation/requirements.txt`). Everything a conformance check needs
— the schemas *and* the rejection vectors — is inside that pinned artifact, so
the check needs no network at test time, no trigger in another repository, and no
credentials for one. That property is the point of publishing a protocol at all:
**a third-party implementer we do not own gets exactly this guard from `pip
install`**, which a cross-repo mechanism could never give them.

A scheduled canary against the profile's HEAD is the only shape available when
the schemas are *not* shipped, and it fails badly: red with no PR to blame, in a
repo whose maintainers cannot fix the other side. That is the failure mode
`gate-canary` was built to survive, not one to reproduce.

So an upstream change reaches Orrery **when someone bumps the pin** — a normal,
reviewable dependency bump, on which every assertion below re-runs. Between
bumps Orrery is conformant to a named version, which is a true and checkable
statement; "conformant to whatever upstream pushed an hour ago" is not.

| Change | Caught by | When |
| --- | --- | --- |
| Orrery emits a new envelope field | `server` job | that PR |
| Orrery ships a surface claimed unimplemented | `server` job | that PR |
| Orrery ships a surface non-conformantly | `server` job | that PR |
| Someone edits claims / field map / the pin | `server` job | that PR |
| The profile adopts an excluded field | `server` job | the pin-bump PR |
| The profile drops or renames a mapped property | `server` job | the pin-bump PR |
| The profile publishes a whole new schema | `server` job | the pin-bump PR |

### Emitted-but-not-expressible needs the emitter to validate itself

Validating a *received* document against a permissive schema cannot catch a
producer emitting a field the profile has no property for. Only
`additionalProperties: false` applied to **the emitter's own output, in the
emitter's own repo**, turns that into a red build — and then the fix is a spec PR
rather than a silent divergence.

That is what this suite does: it runs in the repo that emits, against the schema
that forbids unknown fields, over the documents Orrery actually produces. It is
also why `test_published_invalid_vectors_are_rejected` exists — every assertion
here is only as strong as the validator behind it, so the profile's own rejection
corpus is run through that validator to prove it is not permissive.

## What it does NOT cover

Stated plainly, because a guard whose limits are unstated gets read as covering
everything.

1. **It is not a live-deployment check.** It runs against a `TestClient`-booted
   app with no database, not against a deployed org. A surface that works in
   CI and 500s in production is not caught here.
2. **Upstream changes land at pin-bump time, not before.** Between bumps this
   asserts conformance to a *named version*. A brand-new published schema is
   caught at the bump — `test_the_published_profile_has_no_unclaimed_surface`
   fails until `claims.json` states whether Orrery implements it.

   A **loosened constraint** inside an existing schema is not caught *here*, but
   it is caught **one repo over, at commit time**: sm-federation's own
   conformance suite runs its shipped invalid corpora against its schemas, so
   loosening a constraint a vector exercises turns that repo red before anything
   is published. This suite's
   `test_published_invalid_vectors_are_rejected` then re-checks the same corpus
   against the validator used here.

   Two residuals, both narrow and both real:

   - a change that loosens the schema **and** weakens its own rejection corpus in
     the same commit escapes both — that is a reviewable PR in a repo we own,
     not silent drift;
   - a constraint **no vector exercises** is guarded by nothing anywhere. This
     was the sharper of the two residuals and it is now **closed at the source**:
     sm-federation 0.4.2 asserts full corpus coverage in its own CI
     (`conformance/test_corpus_coverage.py` there), so a constraint no vector
     exercises fails **at the commit that introduces it**, for every consumer at
     once — including consumers nobody here owns, which is the point of
     publishing a protocol. It is not re-asserted downstream: a recorded number
     in a consumer can only be checked by whoever happens to bump the pin.

     History, because the direction of travel is the point and both intermediate
     figures looked like completion at the time: **16 of 68 → 33 of 68 → 66
     guarded, 1 proven-redundant, 0 unguarded.** A hand-picked sample of twenty
     mutations reported 8/20 then 20/20 across the first two of those — true, and
     uninformative, because it was chosen by the person who wrote the vectors.
     Enumerating beats sampling.

     Cross-checked at this pin bump, worth recording because the two harnesses
     evolved separately in two repositories: Orrery's re-derived **66 of 68
     caught**, upstream's **66 guarded / 1 redundant / 0 unguarded**. They agree
     exactly on the substantive number and differ only in classifying the two
     constraints no vector can exercise — upstream excludes `if`-subschemas by
     construction (a condition selects which rule applies rather than
     constraining a document) and computes the remaining one to be redundant.
     Both are the better treatment, so the classification lives there.

3. **`implemented: false` is verified by absence, not by design review.** The
   suite proves Orrery does not serve a surface; it says nothing about whether
   it should, or when.

   A surface marked `may_degrade` in `claims.json` is different again: it may be
   implemented and still absent on a given instance. Orrery's feed boot degrades
   rather than crashing when the app role lacks DDL privilege, because bricking a
   self-hosted install to add an optional feature is worse than the feature being
   absent — so a DB-less or least-privilege node legitimately serves no
   `feed_url` and declares §2 only. **That is valid conformance and this suite
   treats it as such.** What is asserted for those surfaces is not presence but
   **coherence**: `feed_url`, the `federation/0.1#4` token and the endpoint must
   agree. A node that dropped the feed but kept the claim, or serves a feed it
   does not advertise, is non-conformant even though each field looks reasonable
   on its own.
4. **The intelligence feed's path is a proposal.** No feed exists, so
   `/api/federation/intelligence/feed` in `claims.json` is unbound. When the feed
   is built at a different path, that entry must be corrected — the suite asserts
   *a* 404 there, and a feed at some other path would not be noticed by that
   assertion alone.
5. ~~**No signature or hash-chain verification.**~~ **CLOSED 2026-08-09.** All
   three failures a completeness guarantee exists to catch — a dropped entry, a
   reordered entry, and a **restarted sequence** — are asserted against the
   published verifier, and the §4 suite has now run **over the wire** against a
   real feed on a real Postgres: `37 passed, 0 skipped`. That includes the
   restart assertion, which had never executed, and signature verification
   against the DID resolved from `/.well-known/did.json`.

   On a node with no database the same suite reports `34 passed, 3 skipped` —
   honest skips for a degraded install, and the difference between those two
   numbers is now itself asserted (see the harness guards in
   `test_feed_restart.py`).
6. **Semantics beyond shape.** `skill_graph` validating as `{string: integer}`
   does not mean the weights mean the same thing on both sides.
7. **Nothing about runtime behaviour** under load, concurrency, or partial peer
   failure.
8. ~~**`federation_versions` is not checkable.**~~ **Retired at the 0.4.0 pin
   bump.** It read: *"this suite asserts the descriptor is well-formed; it
   cannot assert the advertisement is precise, because the vocabulary has no way
   to be."* sm-federation 0.4.0 (§2.1) gave the vocabulary a way to be precise —
   `capabilities` section tokens, with `federation/<v>#4` bound to `feed_url` in
   both directions — so `test_descriptor_declares_exactly_the_sections_orrery_
   implements` now cross-checks the node's own advertisement against
   `claims.json`. The limit was in the protocol, not the suite, and it was fixed
   in the protocol.

   What remains uncheckable: `federation_versions` itself is still one flat
   list. §2.1 narrows it normatively to "the version this descriptor conforms
   to", but nothing enforces that reading — a node listing a version it does not
   conform to still emits valid bytes.

9. ~~**The two published schemas are not asserted the same way.**~~ **RETIRED
   2026-08-09.** Both published schemas are now asserted
   over the wire.

   The condition set for retirement was that a real emitted envelope be validated
   against `intelligence-envelope.schema.json` — not that the assertion exist,
   which it had for a cycle. It has now **executed**: against the live feed on a real
   Postgres, `test_the_live_feed_serves_a_verifiable_page` verified a served page
   and validated the two envelopes it carried, both clean. Recorded with the
   distinction intact, because the limit stood for a cycle *while the assertion
   was already written* — an assertion existing is not an assertion having run,
   and the gap between those two is where this suite has hidden things twice.

   `envelope_field_map.json` still classifies `get_our_summary`'s fields against
   the envelope schema, and that remains a classification rather than a
   validation — but it is no longer the *only* route to that schema.

## Known gap, reported and deliberately not built

The envelope's vocabulary is **skills only** — `skill_graph`, `skill_gaps`,
`top_skills`. It has no geography and no service taxonomy, so it cannot express
"in Napa" or "ships to Japan". For supplier discovery — an agent in Japan
finding a Napa winery — that vocabulary is not expressive enough at any level of
conformance. This is a real gap in the published profile and a protocol decision
that has not been made. It is recorded here, not built.
