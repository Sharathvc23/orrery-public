### A listed business says what was actually checked about its owner

`org.projectnanda.ownerAttestation` has been written into every index record
since the owner-attestation decision landed, and until now nothing read it back.
The value travelled to the index and stopped there: a consumer resolving a
business got a name, an endpoint and a did:key, and nothing about who had
authorised the association between them. The decision's own sentence names both
halves — a published listing carries a statement of what was checked **and the
consumer surface renders that statement instead of a generic "verified"** — and
only the first half was built.

`community_member.attestation_copy` is the one place a value becomes words.
Every value gets its own sentence naming WHO was verified and HOW, plus a caveat
naming what that check does not establish.

⚠️ **The four values are not a scale and are not rendered as one.**
`domain_verified` and `platform_attested` bear on ownership of a BUSINESS;
`individual_oidc` is a strong check of a PERSON and no check of a business;
`operator_vouched` is a check of the HOST OPERATOR. Three different subjects,
not three positions on one axis, so there are no stars, no percentage, no badge
that gets greener, and no arrangement that reads top-to-bottom as
strongest-to-weakest. Every value carries both a positive clause and a caveat —
the symmetry is the mechanism, because two values with caveats and two without
read as two tiers. `operator_vouched` reads as neither a failure nor
"unverified": a listing with no valid owner evidence is refused by
`listing_grant_verdict` and never published, so rendering it as an absence would
describe a state the publishing path cannot produce.

**A line that was wrong, not merely generic.** The wizard's agent-card panel read
`Listing: authorised by <subject>`, taking the subject off the owner binding —
for an OIDC binding, the person's email address. So it told the reader that
`barber@example.com` had authorised the listing, while the derivation on that
same binding says `operator_vouched`: the OPERATOR authorised it, and the sign-in
proved a person rather than a business. The panel now leads with what was
checked and shows the subject labelled as the binding it is. The rendered output
was never malformed, so nothing that inspected the panel for shape could have
caught it — only asking where the string came from does.

**Three states, not two.** A record that states nothing, a record naming a check
this build does not know, and a known value are different facts arriving through
one field. An unknown value is named back to the reader rather than defaulted;
nothing falls through to `operator_vouched`, which would answer a question nobody
asked in the direction of reassurance. A missing value reads as unverified,
which is the one place that word appears.

**The guard is the deliverable.** The vocabulary is parsed out of `owner.py`'s
source and compared for SET EQUALITY with what can be rendered, so a fifth value
added there fails at merge instead of rendering as blank space on every consumer
surface — and a rendering left behind for a removed value fails too. The
enumeration is checked for vacuity first, because a parser that matches nothing
would make that equality hold over no input. Proven by planting: a fifth value, a
deleted rendering, a strongest-to-weakest arrangement, a `rank` field in the
payload, `operator_vouched` reworded as a failure, the old wizard line restored,
and an import that would drag the signing stack onto the read path — each reddens
its named test, and the tree is clean after each revert.

Rendered on the discovery read path (`Discovery.attestation`), the registration
script's dry run and read-back, the CLI's `Discoverable:` block and the wizard's
agent-card panel. `owner.py`, `index_registrar.py` and the decision document are
untouched: this adds no way to obtain evidence and no new value.

**Not done here, and it needs a decision first.** The tenant agent card and
`smb_host` are the surfaces a stranger actually reaches, and the attestation is
absent from both. The decision document lists "whether the attestation value
should also appear on the tenant's agent card" under *Not decided here*, and
`smb_host` deliberately imports no identity or signing module — a constraint its
own derived isolation guard enforces. Both are reasons to take that step as its
own unit rather than as a side effect of this one.
