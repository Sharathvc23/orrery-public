### A signature is not membership, and a silent member is not disclosed

Two findings on the GET side of an org whose member directory is "closed",
both measured over the wire before the fix.

**Trust-on-first-use verified anyone.** A caller who had never registered could
mint a keypair, choose any `agent_id`, sign a GET and be `tofu_accepted` — which
set the request's verified identity and passed every signed-only gate:
`GET /api/members` returned the directory, descriptions included, and so did the
directory surfaces, the catalog's member list and another member's endorsements.
TOFU is the spec's bootstrap for a *registered* member whose key is not yet on
file; reading possession of some key as membership made it a registration path
with no registration. The verifier now consults an installed eligibility
predicate and fails closed without one; a refused caller files no key. The org
installs "is a registered member", and — outside the A2A interop surfaces, where
a signature is accountability rather than membership — treats a verified
signature as authenticated only for a registered id, on the gated paths and on
the identity-aware open ones alike, so a key already on file is not membership
either. A stranger is told `unknown_agent`; a stored key without a row is
`not_a_member`.

**Four per-member routes disclosed members who never opted in, and two of them
republished the member's free-text description.** The profile route was
consent-gated for exactly this, and the design note that accompanied it said the
profile was the one open path still reshaping the member row. It was not.
`GET /agents/{id}` (the registry hop) and the AgentFacts document both carried
`description` — the field an audit found holding an email address and a phone
number, and the one the consented Listing forbids outright — and
`/sm-bridge/index` enumerated every member with it: measured on a deployed org,
twenty-three members, names and descriptions, to an anonymous GET.
`/api/agents/{id}/trust` answered 200 for a member and 404 for anyone else with
no credential at all, and `/api/agents/{id}/aae-events` answered a stranger with
a 403 naming the chronicle as internal while an unknown id got an empty 200 —
the membership oracle the profile gate closed, reopened by status code.

Now: the registry hop and the AgentFacts document carry no member prose. The
trust route is open for a member who opted in, readable by any signed member,
and otherwise answers a stranger exactly as it answers an unknown id — the
earlier ruling that it "was always meant to be open" predates the consent model
and is superseded by it; its one external consumer, the agent's own trust
refresh, signs. A third party on a private chronicle gets the unknown-id answer.
The sm-bridge index enumerates only members who opted in, reading the same
consent record the Listing does, and describes them by display name. So does the
sm-bridge **delta feed**, which is the index in another shape — a consumer that
replays it from sequence zero rebuilds the index — and which re-seeded every
member at boot and upserted on every registration: one `discoverable` rule now
admits a member to the index, the feed and the boot-time re-seed, and the
member's own opt-in and opt-out are the upsert and delete the feed carries.

Guarded, each planted and observed reddening by name, the tree clean after each
revert: TOFU eligibility ignored (the shipped defect — ten tests, the seven
gated reads among them); the membership bind removed from the gated branch, and
separately from the identity-aware branch (one test each — the stored-key
stranger, and the stranger reading the catalog's member list); the trust gate
removed; the chronicle's 403 restored; the sm-bridge consent filter removed; the
description restored on the registry hop, and on AgentFacts. The regression
file drives every per-member route for a silent member and for an unknown id and
requires the answers to be byte-identical, so a gate cannot close a disclosure by
opening an oracle.
