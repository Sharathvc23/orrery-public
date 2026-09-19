### An SMB agent's card says what it can do, and its AgentFacts pointer resolves

A tenant provisioned on the SMB host served `"skills": []` on its A2A agent card
while `POST /t/<tenant>/book` answered with a signed receipt. A client that
resolved the agent could not tell it takes bookings — on the one document it has
to go on.

The card is now built from the table of tenant-scoped action routes the host
actually serves, so it cannot advertise a capability that is not there. Booking
had no entry in the tool-to-skill mapping, so deriving the card from the tool
alone would have advertised a "General assistant"; it maps to `skill.booking`
now, which corrects the card of any agent exposing that tool.

The same card advertised `x-nanda.agentfacts_url` — set whenever the agent has a
`did:key`, which for a provisioned tenant is always — and the host mounted no
such route, so the one link from a published card to the agent's AgentFacts
returned 404. `GET /t/<tenant_id>/agentfacts.json` is now served, built by the
same function the agent runtime uses for its own `/agentfacts.json`, so the two
surfaces cannot describe one agent differently. The publisher's existing pointer
check probed exactly this URL, so it was already reporting a dead link.

AgentFacts carried the same problem less visibly. It requires at least one skill,
so a tenant with none configured fell back to a "general-purpose agent"
placeholder — a populated field that says nothing, which is harder to notice than
an empty one. Both documents are now derived from the same source, and a
`service_type` given at provisioning appears alongside the booking capability
rather than instead of it.

A test walks the host's own route table and fails if a tenant-scoped route is
neither a declared capability nor declared metadata, so a route cannot be added
without the card describing it.
