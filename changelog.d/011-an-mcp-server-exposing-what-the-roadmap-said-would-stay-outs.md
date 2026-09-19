### An MCP server, exposing what the roadmap said would stay outside

`docs/ROADMAP.md` used to list "built-in MCP integration" under deliberately
out of scope: Orrery would *compose* MCP-speaking tools as a complement, never
embed a client or server of its own. That line is now wrong, on measured
grounds rather than a change of mind: `langchain-mcp-adapters` exists on PyPI
(0.3.2); an equivalent `langchain-a2a` does not. MCP is what the LangChain /
CrewAI / Claude / Cursor ecosystem actually consumes, so it is the one wire
that makes "point your existing agent at Orrery" true with zero
framework-specific code — and A2A, the protocol this repository already
speaks, cannot make that claim.

`mcp_server/` exposes six accountability primitives as MCP tools —
`register_agent`, `request_grant`, `check_grant`, `issue_receipt`,
`verify_receipt`, `resolve_peer` — over **stdio only**. Each is a thin wrapper
over an existing `community_member` function; no new identity, consent, or
signing mechanism was introduced to build it. Stdio, not HTTP: it is
local-trust, which matches the sovereign-agent model exactly (the agent
already runs on its owner's machine), so the signing key never has to answer
"who is on the other end of this connection" — the answer is always "this
machine's owner." An HTTP transport would reopen that question and needs its
own ruling; it is not built here.

**The risk an MCP tool call carries that an HTTP request doesn't: it is
invoked by a model, not a person.** Two things follow, enforced by consent
gate code this change did not write, not by anything new:

- `request_grant` can never return an approval. It calls the same
  `consent.gate.check_and_record` every gated action already calls, whose
  only two possible outcomes are `"reject"` and `"prompt"` — there is no code
  path that constructs `"approved"`. A real approval is a separate, human-only
  action, deliberately not exposed as a tool.
- `issue_receipt` refuses `"untrusted"` provenance before touching a signing
  key, reusing the consent gate's own anti-injection rule rather than a
  second, divergent copy of it.

Explicitly not built: a bridge from a receipt's ARP `action.category` to a
specific approved consent-gate `capability`. No such bridge exists anywhere
else in this codebase — the two vocabularies are disjoint, and even the
built-in booking skill signs its receipt unconditionally with no consent
check at all. Inventing one for this single call path would be a new
mechanism, not a wrapper around an existing one.

**The oracle is not us.** Every interop test this repository owned before
drove its own code against its own code — which is exactly how an A2A spec
drift went unnoticed for months. This server is driven by two libraries
nobody here wrote: the stock `mcp` SDK client, spawning the real server as a
subprocess and talking stdio; and `langchain-mcp-adapters`, the library that
makes the "a LangChain agent can drive this" claim true rather than assumed.
29 tests total, both oracles green.

**A real, measured version conflict, left in the open rather than picked
around silently.** `mcp` 2.1.1 is the latest release on PyPI.
`langchain-mcp-adapters` 0.3.2 depends on `mcp<2.0.0,>=1.24.0`, so
`mcp_server/pyproject.toml` pins to that older range — pinning to the newest
`mcp` would make it impossible to install alongside the client library that
proves the interop claim.
