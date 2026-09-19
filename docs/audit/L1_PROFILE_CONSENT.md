# L1 — consent-gated agent profiles

**Design note. No implementation.** L1 stays `residual` in
[`findings.json`](./findings.json) until a change lands; this document records
what the surface does today, why the accepted-residual reasoning is narrower
than it looked, and what gating would cost.

Facts below are from `server/chapter_agent.py`, `server/member_listing.py`,
`server/auth_verify.py` and `agent/community_member/` as of 2026-09-14.

## The finding as accepted, and what it missed

L1 was recorded as a membership oracle: `GET /api/agents/{id}/profile` answers
200 for a member and 404 for a non-member, so ids can be probed. It was accepted
because "public profiles are the point" and the handler "returns only fields
already public by design (skills, trust score, did:key)".

The second half of that is wrong. The handler builds its card from the member
row:

```python
skills = list(m.get("skills") or [])[:12]
description = m.get("description") or ""
...
a2ui_helpers.member_card(..., subtitle=description, avatar_url=m.get("avatar_url") or "", ...)
```

`description` is member-authored free text. It is the exact field C7 was about —
`member_listing.entry_for`'s own docstring records the incident:

> An audit put an email address and a phone number in a member's free-text
> description and both came back to an unauthenticated GET.

The listing was built so that could not recur: §4.1 of `sm-listing 0.1` forbids
`email`/`phone`/`address` and §4.2 forbids member-authored prose, and `entry_for`
enforces both structurally — it copies named fields from a consent record rather
than reshaping the member row. `agent_profile_surface` does reshape the member
row, and at the time this was written it was believed to be the one open path
that still did. It was not: `GET /agents/{id}` (the registry hop) and the
AgentFacts document at `/.well-known/agentfacts/{id}.json` both republished
`description` to an unauthenticated GET, and `/sm-bridge/index` enumerated
every member with it — found by the release-readiness inspection after this
gate landed, and closed the same way (see `test_anonymous_member_disclosure.py`).

So the oracle is the smaller half of L1. The larger half is that one unauthenticated
route republishes member-authored prose that a different unauthenticated route
was deliberately built to exclude.

## Two surfaces, opposite postures

| | `/.well-known/agent-community-listing.json` | `/api/agents/{id}/profile` |
|---|---|---|
| Org-level switch | `ORRERY_LISTING_ENABLED`, **default off** | none |
| Member opt-in | required — only `listed is True` counts | none |
| Fields | `did`, `geo`, `offering`, `trade`, each consented separately | whatever the member row holds |
| Free-text prose | forbidden | published as `subtitle` |
| Contact route | `agent_url`, **server-set** from the registered endpoint | n/a |

`server/auth_verify.py` states the listing's rationale and, in doing so, states
the gap:

> It is NOT a filter over the directory: that stays gated.

The directory is gated. Per-agent profiles are not. Anyone who can guess an id
gets the row the directory would have refused, plus prose the listing would have
stripped.

## The mechanism already exists

Nothing new has to be invented. Orrery already has a two-level consent model and
it is already the one the org-level concern asks for:

1. **Org level** — `member_listing.is_enabled()`, `env_flags.security_flag(..., default=False)`.
   An org that publishes nothing publishes nothing.
2. **Member level** — `member_listing.consent_of(member)`, reading
   `agents.config.listing`, deliberately strict: a truthy string or a `1` is not
   consent, only `listed is True` is. Written through the member's own
   signature-authenticated `POST`, with the module's rule that "there is no state
   in which silence means yes".

Lifecycle is there too: `build_listing_grant`, `listing_grant_verdict`,
`revoke_listing`, `suspend_listing`, `resume_listing` in
`agent/community_member/owner.py`.

And the indistinguishable 404 the oracle needs is already implemented and already
tested. `agent_profile_surface` opens with:

```python
if _hidden_from_public_listing(safe) or safe not in members:
    raise HTTPException(status_code=404, detail="agent_not_found")
```

`test_public_listing_gate.py` asserts that a hidden agent 404s exactly like a
nonexistent one, with no branch that distinguishes them. Adding non-consent to
that predicate reuses a proven gate rather than adding a second one.

## Proposed design

**One consent record, not two.** Gate the profile on the same
`agents.config.listing` consent the listing reads. Two consent mechanisms for one
decision drift, and the member has already answered the question the profile is
asking.

**Narrow the field set to what the listing's own rule permits.** Consent to be
listed is not consent to publish arbitrary prose, so the profile should serve
`name`, `skills`, `trust_score`, `did:key` and `avatar_url`, and **drop
`description`**. That makes the profile the rendered form of the listing entry
instead of a second, looser publication of the member row — and it closes C7's
vector on the last route that still carries it.

**The oracle closes as a side effect.** A non-consenting member 404s identically
to a nonexistent id, through the existing predicate. It is a consequence of the
consent gate, not the goal of it.

Result: agents are private by default, per-member opt-in, under an org-level
switch that is already off by default.

## What it costs

Stated rather than left for a reader to discover.

**Shared links stop working for non-consenting members.** `auth_verify` records
the intent that "a link to @alice's profile renders for everyone (Twitter /
LinkedIn crawlers included)". After the gate, that holds only for members who
opted in. This is the trade being made deliberately, and it is the whole of the
user-visible change.

**Three in-repo consumers break for non-consenting members:**

| Consumer | Effect |
|---|---|
| `agent/examples/quickstart.py:186` | prints the public profile URL as onboarding's payoff; a new member gets a 404 until they opt in |
| `agent/community_member/a2a_client.py:324` | `get_agent_profile` → `_get_open`; returns 404 for non-consenting members |
| `scripts/restart_durability_probe.py:216` | uses the profile as a cross-restart liveness canary; needs a consenting canary or a different probe |

**The federation case is the open question, and it is where the research is.**
`a2a_client` has a signed path (`_get_signed`), but switching `get_agent_profile`
to it does not preserve cross-org fetch: a federated peer is not a member of the
org it is querying, so it has no signature that org will accept for a
member-scoped read. Either federated peers lose profile fetch, or profiles need a
peer-signed path — an org-to-org credential rather than a member one.
That decision is not settled here.

## What landed, 2026-09-14

The gate, in `agent_profile_surface`, reading the same consent record
`member_listing.consent_of` reads:

```python
if member_listing.consent_of(m) is None:
    raise HTTPException(status_code=404, detail="agent_not_found")
```

Byte-identical to the two 404s above it, so closing the disclosure does not open
an oracle in its place. `description` is gone from the card; the remaining
fields are the ones the Listing's own rule permits.

**One correction to the design above.** The note said the profile would sit
"under an org-level switch that is already off by default" — meaning
`ORRERY_LISTING_ENABLED`. Reading the routes more carefully, that flag gates only
the listing DOCUMENT at `/.well-known/agent-community-listing.json`; the consent
endpoint accepts a member's opt-in regardless of it. So the gate reads member
consent **only**. Gating profiles on the document flag too would conflate "does
this org publish a directory document" with "may this member's profile be
shown", and would let an org's choice about its own surface silently overrule a
member's answer about theirs. Default-private already gives an org what it
needs: no member is visible until that member says so.

**The federated-peer question is answered by default, not by a bypass.** A
non-consenting member's profile 404s for everyone, peers included. No org-to-org
credential was added — a peer seeing what a stranger cannot would be a hole in
the consent model, and the member's answer should not depend on who is asking.

**The existing tests could not have caught any of this.**
`test_agent_profile_surface.py` asserts against `_build_profile_surface`, a
helper hand-copied from the route into the test file, and its
`test_route_and_helper_in_lockstep` fingerprints that copy while describing
itself as a canary for route drift. It never calls the route. The copy still
carried `subtitle=description` and would have gone on reporting a shape the route
no longer produces. The copy is corrected and the canary claim withdrawn;
`test_profile_consent_gate.py` asserts the real handler over HTTP.

**Plant-proved.** Three defects, each reddening the assertion meant to catch it:

| planted defect | caught by |
|---|---|
| the consent gate removed (the old ungated behaviour) | 9 assertions, incl. the indistinguishability test |
| `description` restored as the card subtitle | `test_ADVERSARIAL_consenting_profile_carries_no_member_authored_prose` |
| the gate given its own 404 detail, `profile_not_public` | `test_ADVERSARIAL_silent_member_is_indistinguishable_from_a_stranger` |

The third is the one worth naming: it is a gate that closes the disclosure and
opens an oracle, and it is the failure this change would most plausibly ship
with.

## Status

L1 moves to `fixed`.

**The live consequence, stated.** `ORRERY_LISTING_ENABLED` is false on all three
deployed orgs and no member has opted in, so on the next deploy **every profile
on the mesh returns 404** — 34 members across astrocity, rocketbrain and
regentix. That is the intended end state, not a regression: profiles are now
something a member turns on, and nobody has. Restoring any individual profile is
one signed `POST /api/me/listing` by that member.
