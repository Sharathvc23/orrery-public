# Response to the SMB resolution draft: two mechanisms already running

**Date:** 2026-08-01

## What this is

A response to two open points in the SMB resolution draft, from a system that
already runs a primitive for each. These are offered as contributions to the
model, not as gaps we are asking the draft to close:

1. **§7.3 / §9 — accreditation of index writers.** The draft leaves the
   mechanism open and ranks it highest priority. We run a mechanical
   alternative to the contractual DNS analogue: signed conformance badges.
2. **§3.2 / §9 — detecting an accredited writer that lies.** The draft
   restricts *who may write* but has no mechanism for *when a writer
   equivocates*. We run cross-registry divergence detection, and separately
   publish a proof form that fires only when a conflict can be
   cryptographically attributed.

Two further points — outcome-linked bindings and a recoverable key-rooted
subject — are noted at the end and deliberately not developed here.

## How the claims in this document were checked

Everything below is stated against what is deployed on 2026-08-01, not against
design notes. The check is named inline with each claim. Three of the checks
came back weaker than we expected; those results are reported in place rather
than dropped, in the sections **Known limitation: version coverage**, **What
the deployed findings actually are**, and **§2b**.

---

## 1. Accreditation as a checkable artifact rather than a relationship

**Answers:** §7.3, which states the accreditation mechanism for index writers
as an open governance decision, and §9, which ranks it highest priority on the
grounds that every other mechanism depends on it.

### The shape of the draft's analogue

The DNS analogue the draft reaches for is contractual: entry requirements,
conduct obligations, audit, revocation by litigation. That makes a writer's
right to assert a **relationship**. To evaluate it, a relying party has to know
who the accreditor is, trust that the audit happened, and be able to reach
someone. The accreditation is real but it is not in the relying party's hands.

### The mechanism we run

A **signed conformance badge** is a JSON envelope, emitted by a runtime that has
run a conformance suite against itself and signed the result with an Ed25519
key identified by a `did:key`.

The payload names:

- the runtime it attests,
- the protocol versions attested,
- a `suite_digest` — a SHA-256 over the vector corpus the suite exercised,
  scoped to the subtree that suite actually reads rather than the whole tree,
- pass / fail / skip counts, exit status, and completion time.

Verification is a pure function of the envelope: RFC 8785 canonical JSON plus
an Ed25519 signature check. There is no registry to query, no certificate
authority, no accreditor to reach, and no network call. The `suite_digest` pins
what was tested, so a badge naming a corpus a reader does not recognise does not
verify as attesting anything that reader cares about.

The envelope also admits an optional **countersignature**: a second key — an
independent lab acting as notary — signs the same payload, so a third party's
attestation rides on the same artifact without disturbing the issuer's
signature.

### Why this is a different answer in kind

- A writer's right to assert becomes an **artifact the relying party evaluates
  itself**, rather than a relationship it has to take on report.
- The claim's **scope is explicit and machine-readable** — which protocol
  versions, which corpus — instead of being implied by membership in a scheme.
- Withdrawal is by **digest drift** rather than by legal process. Verification
  recomputes the scoped `suite_digest` at the corpus's current state and fails
  if the badge no longer pins it, so a badge stops verifying when the thing it
  attested moved. Nobody has to revoke it.

### What we verified, 2026-08-01

- **Ran the verifier against all three badges** in our conformance repository.
  All three exit 0 and report runtime, attested versions, pass/fail counts,
  suite scope, and suite digest.
- **The verifier is not signature-only.** It recomputes the scoped digest at
  the corpus's current state and fails on mismatch. One of the three badges was
  signed seven weeks before the other two and still verifies — because the
  subtree its scope covers has not changed since it was signed. The scoping is
  doing real work rather than being ignored.
- **A third party can verify without our source.** The verifier and the badge
  format are a published package (`sm-conformance` on PyPI), so re-verification
  does not depend on access to us. (One caveat, in **Limits**: signature and
  payload verification need only the badge; the digest-freshness check needs a
  copy of the corpus.)

### Known limitation: version coverage

This is an open issue in our own conformance repository as of today, and it
would be dishonest to propose badges as the answer to accreditation without
stating it.

All three badges attest:

```json
"protocol_versions": ["0.3"]
```

The runtime they attest advertises **three**. Checked live on 2026-08-01, its
version endpoint returns `["0.2", "0.3", "0.4"]`, and a 0.5 specification has
since shipped.

The badges do not lie — each says `["0.3"]` plainly. The problem is that
**nothing mechanically compares a badge's version list against what the target
advertises**, so a green badge gets read as certifying *the runtime* when it
certifies *one of the protocol versions the runtime exposes*. The uncovered
surface is precisely where the newest and least-exercised code is.

That is the badge mechanism's own failure mode reappearing one level up: an
artifact being read as a stronger claim than it makes. A fix is in progress —
asserting in CI that a badge's `protocol_versions` covers the versions its
target advertises, so under-coverage fails instead of passing quietly, together
with extending suite runs to the newer versions. Until that lands, a badge
should be read as attesting the versions it names and nothing more.

### Not yet exercised: countersignature

None of our three badges currently carries a countersignature. The countersign
mechanism ships in the published package and its tests pass (verified
2026-08-01, 16 tests), but as deployed our badges are **self-signed by the
runtime's own key**. A self-signature plus a pinned `suite_digest` is a weaker
claim than an independent lab's countersignature, and we should not be read as
offering the latter today.

---

## 2. Attributable divergence proofs

**Answers:** §3.2, whose unverifiable-assertion problem is mitigated only by
restricting who may write, and §9's open item — two accredited writers
publishing valid, competing bindings for the same subject.

Restricting who may write is a control on **entry**, not on **conduct**. It
does not detect an accredited writer that lies after admission. The draft's own
constraint on any mitigation is that it *cannot be a dispute process; it must be
structural.*

We have two pieces here at different maturity. They are usually described
together and they are not the same thing, so they are stated separately.

### 2a. Cross-registry divergence detection — deployed

Each org host periodically asks every registry it is configured against the same
by-id question about the same watch set, and compares the answers. Records are
fetched by id rather than from list endpoints, because list projections
paginate and can strip the attestations that make the comparison meaningful.

Disagreement is classified:

| Kind | Fires when |
| --- | --- |
| `omission` | One registry serves a record another **positively** reports absent (404 or a not-found body). |
| `endpoint` | Registries claim different endpoints for the same id. |
| `did` | Registries serve different **valid** attestations whose subject DIDs disagree. |
| `unconfirmed` | A registry errored or timed out on an id a sibling serves. |

Two design properties matter for §3.2:

**Silence is never converted into an accusation.** A registry that is
unreachable is excluded from the comparison entirely — a timeout is not a claim
of absence. `unconfirmed` exists so that a registry cannot hide an omission
behind a 500 while still not being accused of one; it is explicitly weaker than
`omission` and louder than nothing.

**`did` is the attributable kind.** It fires only when both registries serve an
attestation that cryptographically verifies for that subject and the DIDs inside
those attestations differ. Two valid signatures making incompatible statements
about the same subject is the writer's own contradiction, established without an
observer's judgement entering into it. `endpoint` and `omission` do **not** have
this property — they compare unsigned registry claims, and so are signals to
investigate rather than proofs.

That distinction is the contribution. The draft needs a mechanism that produces
a verdict without a dispute process; the way to get one is to emit a finding
only where the evidence is the accused party's own signature, and to emit a
weaker, clearly-labelled signal everywhere else.

The comparison itself is not bespoke to us. The classification kernel is
published (`sm-divergence` and `sm-resolver` on PyPI), and its corroboration
diff is the reference implementation of
`draft-chandra-agent-registry-corroboration-00`, so the semantics above are
specified independently of our deployment.

### What the deployed findings actually are

**Verified 2026-08-01:** queried the divergence read endpoint
(`GET /api/federation/divergence`) on all three deployed org hosts. All three
returned findings — 1, 4, and 1 respectively — with observation timestamps
between 2026-07-16 and 2026-07-29. The endpoint is live and the detector is
emitting.

**But every finding on all three hosts is kind `unconfirmed`.** No `omission`,
`endpoint`, or `did` finding has been observed in production. The accurate claim
is therefore:

- The detector runs in production against two independently operated
  registries and reports real findings.
- What it has caught so far is **registries failing to answer**, not a registry
  lying.
- We have **not** observed an actual equivocation in production.

Read the deployed evidence as evidence that the mechanism runs and reports, not
as evidence that equivocation is common or that we have caught one.

### 2b. Non-repudiable equivocation proofs — a published library, not wired in

Separately from the detector above, we publish a feed primitive (`sm-feed` on
PyPI) with a `detect_equivocation` function over signed feed heads. It returns a
proof object
**only** when both heads carry valid Ed25519 signatures by the same feed
identifier, at the same sequence position, with conflicting entry hashes. Every
other combination — heads whose signatures do not verify, heads from different
feeds, heads at different positions, heads that agree — returns `None`.

**The `None` is the part worth proposing.** A conflict that cannot be
cryptographically attributed to the issuer does not produce a proof at all. When
a proof is produced, its content is the issuer's own two contradictory
signatures, so any third party can re-verify it without trusting whoever
reported it and without any adjudication step. That is a direct answer to the
draft's constraint that the mitigation be structural rather than procedural.

**Verified 2026-08-01:** read the implementation against its stated contract and
ran its equivocation tests (7 passing); the package is published. We also
checked whether the deployed org host uses it — **it does not**. There is no
reference to the feed package anywhere in the org host.

So the two halves of this section are not connected today: **2a is deployed and
does not emit non-repudiable proofs; 2b emits non-repudiable proofs and is not
deployed.** The feed package's own documentation states that the gossip
transport — who to ask for heads, and how often — is left to the consumer and is
not shipped.

We are proposing the shape, and we hold the primitive. We are not claiming to
run end-to-end attributable equivocation detection.

---

## 3. Limits

What each mechanism does **not** cover.

### Badges

- **Conformance is not honesty.** A badge attests that a runtime's protocol
  behaviour conforms to a pinned corpus. It says nothing about whether that
  writer's assertions *about the world* — that this business runs that agent —
  are true. It accredits protocol competence, not truthfulness.
- **It only reaches parties who run a conformance suite.** A writer that will
  not or cannot run the suite is outside the mechanism entirely, and the badge
  form has no answer for that population.
- **It attests the versions it names**, which today under-covers the deployed
  surface (see above).
- **Self-signed as deployed.** Countersignature is available and unexercised.
- **Offline is exact for the signature, approximate for freshness.** Verifying
  the signature and payload needs only the badge. Verifying that the
  `suite_digest` still pins the current corpus needs a copy of the corpus.
- **It is a claim about one run at one time.** It does not attest that a runtime
  continued to conform after signing.
- **It does not answer who may issue badges.** That is a governance question the
  artifact form does not resolve; it changes what accreditation *is*, not who
  decides.

### Divergence detection

- **Attribution only where both sides are signed.** `did` findings are
  attributable. `endpoint` and `omission` compare unsigned registry claims and
  are investigative signals, not proofs. "Detects lying" is narrower than it
  sounds: it is "detects contradictory *signed* statements".
- **Requires at least two registries.** With one configured registry it is a
  no-op by design — corroboration has nothing to corroborate against.
- **It compares registries against each other, not a registry against itself
  over time.** A single registry serving different answers to different clients
  is a transparency-log problem. This is not a transparency log.
- **It cannot say which side is right.** A `did` finding proves a contradiction
  exists, not which of the two bindings is correct. What follows from that is
  policy, and deliberately outside the mechanism.
- **Scope is the configured watch set** — org-level records — not every subject
  in either registry.
- **The sweep is bounded.** Per-request timeouts and a total budget keep a
  hanging registry from wedging the host. A registry too slow to answer within
  the budget produces `unconfirmed` rather than silence, but it is also not
  compared that round.
- **The non-repudiable proof form is not deployed**, and its transport layer is
  not shipped (§2b).

---

## 4. Noted but not developed here

- **Outcome-linked bindings.** §4.5 and §6.1 keep the binding layer descriptive
  and write-only, so nothing ever checks whether a binding was honest; we hold
  hash-chained, offline-verifiable receipts that could close that loop without
  putting the resolution layer in the request path or turning it into a ranker.
  More speculative than the two items above and not argued here.
- **Recoverable key-rooted subject.** §6.2 lists "existing binding key" as an
  authority blocked by key loss with no recovery path; our owner principal is a
  separate key on its own derivation path with a recovery phrase that is never
  persisted and never loaded by the runtime, which addresses that stated
  objection directly. Also more speculative, with real custody burden, and not
  argued here.
