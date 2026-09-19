### Both documents about one tenant name the same operator

`smb_host` serves two documents for every tenant: the A2A card at
`/t/{id}/.well-known/agent.json` and the canonical NANDA AgentFacts at
`/t/{id}/agentfacts.json`. They disagreed about who runs the endpoint. The
card's `provider.organization` was the hosting domain — set deliberately,
because the tenant does not hold its own key or run its own process. The
AgentFacts for the same tenant had no provider override at all and fell back to
`config.name`, which is the tenant. So a consumer that resolved both was told
two different things about **who it is dealing with**, and AgentFacts is the
half a card host hands onward to a directory, i.e. the copy a stranger reads.

`build_self_agentfacts` now takes `provider_organization` / `provider_url`, the
same per-surface override `build_agent_card` already took, and `smb_host`
passes both from `_operator_identity(public_url)` — **the same function the
card is built from**, so the two documents share one source of truth for the
provider rather than being two values that happen to agree. The member
runtime's default is unchanged and asserted: there, the agent genuinely is its
own provider.

**The host is the right answer, and the reasoning is in the code** so a later
hardening pass does not reverse it silently. sm-bridge documents `SmProvider`
as "the organization running the agent"; one operator passphrase decrypts every
tenant and every tenant route is served from one process. Declining to name the
tenant here loses nothing — `label`, `agent_name` and `handle` already carry it,
so putting the business in `provider` too would replace the only field saying
who is accountable for the endpoint with a second copy of who is being hosted.
And `business_name` is a display label nobody verified, so promoting it into the
field a directory reads as the operator is the worse half of the same mistake.

**A fourth divergence surfaced while fixing the third and is fixed with it.**
`provider.did` carried the *agent's* did:key in a block whose `name` is somebody
else — asserting that the operator's key is the tenant's key. Under an override
the field is now absent rather than false; with no override the agent is its own
provider and the did:key is emitted as before.

**The guard is against a third source, not against the other document.** Each
document is asserted against `HOST_PUBLIC_URL` — the value the host was
configured with, which neither document is derived from in the test — so a
parity check cannot pass by reading its expectation off one of the two things it
compares. Proven by planting: drift on the card side reddened only the card's
named test, drift on the AgentFacts side reddened only its own, and a drift
planted on the shared `_operator_identity` left the two documents agreeing with
each other and still reddened all three tests. `docs/CLAIMS.md` was rewritten
only after reading the values off a running host rather than off the call.
