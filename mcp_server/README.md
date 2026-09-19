# Orrery MCP server

Six accountability primitives — identity, consent, receipts, peer resolution —
exposed as [MCP](https://modelcontextprotocol.io) tools over **stdio**. Build
your agent's reasoning with LangChain, CrewAI, Claude, or your own loop; point
it at this server for an owned Ed25519 identity, a consent gate, and signed,
offline-verifiable receipts for what it does.

This server does not reason, plan, or generate. If a tool here looks like
"think for me," that is a bug — file it, don't build around it.

## Why MCP, measured rather than assumed

`langchain-mcp-adapters` exists on PyPI (0.3.2); an equivalent `langchain-a2a`
does not. MCP is what the LangChain / CrewAI / Claude / Cursor ecosystem
actually consumes — so MCP is the wire that makes "point your existing agent
at Orrery" true, with zero framework-specific code in this repository.

## Why stdio only, not HTTP

MCP over stdio is **local-trust**: the client that spawns this process and the
process itself run as the same OS user, on the same machine. That fits the
sovereign-agent model exactly — the agent already runs on its owner's own
machine — so the question "who is on the other end of this connection, and
should this identity sign on their behalf" never has to be answered. It is
always "this machine's owner," because nothing else can spawn this process
with access to its identity's keystore.

An HTTP transport would reopen that question from scratch (bearer token?
mTLS? which caller may invoke which tool?) and needs its own ruling — it is
not built here, and this server refuses to speak anything but stdio.

## The tools

| Tool | Wraps | What it does |
|---|---|---|
| `register_agent` | `community_member.wizard.express_setup` (read-only here) | Reports this machine's `agent_id`, `did:key`, and name. **Never mints an identity** — see Security model. |
| `request_grant` | `consent.gate.check_and_record` | Proposes an action for consent; returns `"reject"` or `"prompt"` — never `"approved"`. |
| `check_grant` | `consent.gate.find_valid_approval` | Reads whether a human already approved this exact action. Never mutates anything. |
| `issue_receipt` | `arp.emit` (same pattern as the booking skill's `_emit_receipt`) | Signs and persists an ARP receipt for something that already happened. Refuses `"untrusted"` provenance before signing — see Security model. |
| `verify_receipt` | `arp.verify_receipt` | Verifies any receipt fully offline — schema, Ed25519 signature, hash chain. Works on a stranger's receipt too. |
| `resolve_peer` | `nanda_index.discover` | Resolves a URN locator to a callable peer through the NANDA Index. Read-only. |

Every tool is a thin wrapper — see `tools.py`'s module docstring and each
function's own docstring for the exact canonical source it calls. No new
identity, consent, or signing mechanism is introduced here.

## Run it

```bash
pip install -r agent/requirements.lock
pip install -e ./agent --no-deps
pip install "mcp>=1.24.0,<2.0.0"
```

`mcp_server/` is not itself an installable package (its `pyproject.toml` says
so and setuptools refuses to build it — two flat modules, no build backend);
it runs as a module from the repository root. Then point an MCP client at
`python -m mcp_server`, run from the repository root. A LangChain config (via `langchain-mcp-adapters`):

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "orrery": {
        "transport": "stdio",
        "command": "python3",
        "args": ["-m", "mcp_server"],
        "cwd": "/path/to/orrery",
    }
})
tools = await client.get_tools()
```

A Claude Desktop / Cursor-style config:

```json
{
  "mcpServers": {
    "orrery": {
      "command": "python3",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/orrery"
    }
  }
}
```

`COMMUNITY_MEMBER_HOME` scopes which identity the server operates on, exactly
as it does for the CLI and the dashboard — unset, it defaults to
`~/.community-member`.

### ⚠️ A real, measured version conflict

`mcp` 2.1.1 is the latest release on PyPI. `langchain-mcp-adapters` 0.3.2 (the
library this package's own tests are required to be driven by) depends on
`mcp<2.0.0,>=1.24.0`. `mcp_server/pyproject.toml` pins to that older range —
pinning to the newest `mcp` would make it impossible to install this package
alongside the client library that proves the "a LangChain agent can drive
this" claim. Revisit when `langchain-mcp-adapters` raises its own ceiling.

## Security model

**An MCP tool is invoked by a model, not a person.** A model's input can
carry content it never asked for — a scraped web page, an email, a document
it did not author — and an agent that signs whatever a tool call tells it to
sign is exactly the failure this whole stack exists to prevent. Two rules
follow from that, and both are enforced by code this server did not write
(the consent gate's own), not by anything new here.

**`register_agent` never mints an identity over this transport.**
`wizard.express_setup` mints a fresh identity from a one-time BIP39 recovery
phrase that is returned exactly once and never persisted anywhere. Handing
that phrase to whatever process is driving a model is exactly the exposure
this rule prevents — so if no identity exists yet, `register_agent` refuses
and names the local command (`community-member wizard --express --name <name>`) to
run instead. This is a real, deliberate limit: the server cannot bootstrap
itself, on purpose.

**`request_grant` structurally cannot return an approval.** It calls
`consent.gate.check_and_record`, which calls `evaluate()` — and `evaluate()`
has exactly two possible outcomes, `"reject"` and `"prompt"`; there is no
code path in it that constructs `"approved"`. A real approval
(`consent.gate.approve`) is a separate, human-only action, deliberately **not
exposed as a tool here**: a model can ask for consent and can be told a human
already granted it (`check_grant`), but it can never grant itself one.

**`issue_receipt` refuses `"untrusted"` provenance before anything is
signed.** Every acting tool requires the caller to declare `provenance`
(`"trusted"` / `"semi_trusted"` / `"untrusted"`), and `issue_receipt` runs the
same `consent.gate.evaluate` check `request_grant` does before touching a
signing key. A request whose only basis is untrusted content is refused —
proven in `test_tools.py::test_issue_receipt_refuses_untrusted_provenance` by
checking the Agency Log stayed empty, not only that the call raised.

**What this deliberately does NOT do.** It does not bridge a receipt's ARP
`action.category` (`purchase`, `appointment_booked`, ...) to a specific
approved consent-gate `capability` (`browser.navigate`, `shell.exec`, ...).
Measured before building: no such bridge exists anywhere else in this
codebase — the two vocabularies are disjoint, and nothing translates between
them (not `arp.py`, not the ARP schema, not any action module). Even the
built-in booking skill signs its own receipt unconditionally once an identity
exists, with no consent check at all. Building that bridge here — requiring a
specific pre-approved grant before any receipt of any category could be
signed — would be a **new** mechanism invented for this one call path, not a
wrapper around an existing one, and would make `issue_receipt` behave
differently from every other receipt this codebase already signs. So a
`"prompt"`-state screening result (trusted or semi-trusted content, no rule
against it) does not block signing — only the untrusted-provenance rule does.
If tighter binding between grants and receipts is wanted, that is a follow-up
unit, not a silent expansion of this one.

## Guards

`test_tools.py` — direct unit tests of the tool logic, no MCP transport.
`test_stdio_oracle.py` — drives the real server, spawned as a subprocess,
with the **stock `mcp` SDK client** — never a client this repository wrote.
`test_langchain_oracle.py` — drives it again with `langchain-mcp-adapters`,
the library that makes the "a LangChain agent can point at this" claim true.
Both oracle files exist because every interop test this repository owned
before drove its own code against its own code, which is exactly how an A2A
spec drift went unnoticed for months (see the top-level README's "What Orrery
does NOT do").

```bash
cd mcp_server && python -m pytest -q
```
