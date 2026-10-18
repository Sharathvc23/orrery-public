### An org registered at the NANDA Index answers the agent search it is asked

Measured against the live index 2026-10-17: the Index's `/api/v1/agentic-search`
ranks orgs locally and then fans out LIVE to `GET {registry_url}/agents/search?q=...`
for every org registered as `application/ai-catalog+json`. Orrery served no such
route, so `/agents/{identifier}` matched and read `search` as an agent id —
`404 {"detail":"agent not found in this registry"}` — and the index recorded
every one of our live orgs as `orgsUnreachable`. `q="space science education
outreach"` returned count 0 with `orgsUnreachable: ["astrocity"]`;
`q="intelligent automation for business"` returned count 2 with
`orgsUnreachable: ["rocketbrain"]`. Nothing was unreachable: the same orgs'
catalogs answered 200 in 0.13 s on a direct probe at the same moment and the
fan-out leg returned in 468 ms, so it failed on SHAPE, fast. We were registered
and we did not appear.

`GET /agents/search?q=<query>` now answers at that exact path, declared ABOVE the
`/agents/{identifier}` catch-all because declaration order was the whole defect.
Its entries are **derived from the catalog's own builders** — `_org_catalog_entry`
and `_member_catalog_entry`, through one shared `_gated_catalog_entries` helper
that `/.well-known/ai-catalog.json` now also calls — so the two surfaces
describing one agent cannot drift apart. Identifiers stay BARE: the Index's
`qualifyIdentifier` anchors a bare id to the domain whose ownership it verified,
and a urn we minted ourselves would anchor to a value nobody checked. An empty
result is `200` with `entries: []`, never a 404 and never a 400, because any
non-2xx, timeout or malformed body makes the Index record the org unreachable —
being dropped from discovery for having nothing to say is the same failure as
not answering at all. A blank or missing `q` applies no filter. Entries are
capped at 10, the Index's own `perOrgLimit`, inside a fan-out budget of 2500 ms
that belongs to the Index; the handler does no network I/O.

The member gate is the catalog's, not a second one. The fan-out is
UNAUTHENTICATED, and member entries were closed to anonymous callers after an
audit found an email address and a phone number in a member's free-text
description reachable by an unauthenticated GET; a search route with its own gate
is exactly where that reopens. `/agents/search` is added to
`auth_verify.IDENTITY_AWARE_OPEN_PATHS` so a signed member is distinguishable
from the anonymous index — it populates identity and gates nothing, so an absent
or invalid signature leaves the path exactly as open as it was.
`omittedMembers` (no resolvable card URL) and `withheldMembers` (the caller is
not entitled) stay two separate counts.

**The product limit, stated rather than engineered around: an org that does not
publish its members publicly is discoverable on the Index as ONE agent, not as
its roster.** That is the privacy default working, and there is deliberately no
bypass.

Guarded by `server/tests/test_agent_search.py`: the exact path answers 200 with
no `Location` header (the Index fetches with `redirect: 'error'`); the measured
catch-all 404 body cannot come back; every returned entry is compared for
equality against the entry the CATALOG ROUTE produces for that agent rather than
against a literal; a non-matching query, a blank `q` and a missing `q` are each
asserted; the cap is asserted at 25 members; and the registry hop still resolves
`root`, the agent_id, the org_id and the org domain as well as a member id.
Two plants, each observed reddening and then reverted with the tree clean:
removing `/agents/search` from `IDENTITY_AWARE_OPEN_PATHS` reddened
`test_a_verified_member_sees_members_with_the_flag_off` and nothing else;
treating every caller as entitled at the search handler's own call site reddened
the five member-gate tests in this suite and no test outside it.

Not verified here, and it is the acceptance test: that one of our orgs appears in
a live `api.nandaindex.org` agentic-search result and leaves `orgsUnreachable`.
That needs a redeploy of the orgs.
