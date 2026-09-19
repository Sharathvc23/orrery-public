# Spec — AG-UI / A2UI generative surfaces

**Status:** built (surface generation + endpoints + the bundled
[reference renderer](../../renderer/README.md); streaming client rules below are
normative as of that change). Remaining roadmap: the generation trust/safety guard suite
(server-side, see [roadmap](../ROADMAP.md)).

Orrery's org is **headless by default** — a signed HTTP API plus the NANDA discovery
surfaces. This spec describes the **opt-in** UI layer: an agent (or the org) emits its UI
**as data** — an *A2UI v0.10 surface envelope* — which any renderer can paint. The engine
ships the surface data, not a renderer. Two ideas:

- **A2UI v0.10** — the *envelope*: a declarative component tree (the "what to show").
- **AG-UI** — the *transport*: how a surface is delivered and kept live (snapshot + deltas over SSE).

## A2UI v0.10 surface envelope

A surface is a flat list of components plus a `root`, addressed by `surfaceId`. Built by
`agent/community_member/arp_surfaces.py` (`_surface(...)`):

```json
{
  "createSurface": { "surfaceId": "today" },
  "updateComponents": {
    "surfaceId": "today",
    "root": "col-root",
    "components": [
      { "id": "col-root", "component": "Column", "children": ["card-1"] },
      { "id": "card-1",   "component": "Card",   "child": "txt-1" },
      { "id": "txt-1",    "component": "Text",   "text": "3 receipts today", "usageHint": "body" }
    ]
  },
  "version": "0.9"
}
```

> **Normative key name:** the envelope's component payload lives under
> **`updateComponents`** — that is what every builder in this repo emits
> (`server/a2ui_helpers.py::surface`, `agent/.../arp_surfaces.py::_surface`).
> An earlier revision of this page showed `updateSurface` in the example;
> that key never shipped. Renderers MAY accept `updateSurface` as a
> read-side alias for envelopes authored against the old example, but
> producers MUST emit `updateComponents`. The envelope shape is FROZEN.

- **Flat component list** — every component has a stable `id`; containers (`Column`, `Card`) reference children by id, so deltas can patch a single node without re-sending the tree.
- **Component model (v0.10):** `Text` (`text`, `usageHint`), `Card` (`child`), `Column` (`children`), extended over time. Renderers MUST tolerate unknown component types (skip + warn), never crash.
- **`version`** pins the A2UI schema; consumers branch on it (`?schema=v0.8` is accepted by the legacy renderer path).

## Endpoints

Served by the agent (and the org for its own pages); see `agent/community_member/server.py`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/surfaces/{page_id}` | Fetch a surface (e.g. `today`, `chronicle`) as an A2UI envelope. |
| `GET` | `/api/surfaces/{page_id}/stream` | **AG-UI stream** — SSE: an initial snapshot, then deltas as state changes. |
| `POST` | `/api/surfaces/compose` | **Generate** a surface from a free-text intent (BYOK LLM). Returns an A2UI envelope. |
| `POST` | `/api/surfaces/action` | Submit a form/action from a rendered surface; returns a fresh surface. |

The org additionally serves profile/layout *data* at `/api/portal/chapter` and
`/api/portal/layout` (org page content for a renderer to compose).

## AG-UI streaming

`/api/surfaces/{id}/stream` is a Server-Sent Events channel. Each event is one JSON
object on a single SSE `data:` line, terminated by a blank line. The event vocabulary
(`server/agui_streaming.py`; names are AG-UI-stable and MUST NOT change):

| event | payload | meaning |
|---|---|---|
| `RunStarted` | `runId`, `threadId` | a fresh surface run begins |
| `StateSnapshot` | `snapshot` = full A2UI envelope | the complete surface |
| `StateDelta` | `delta` = RFC 6902 JSON Patch ops | incremental update to the last snapshot |
| `RunError` | `message`, `code?` | the run failed server-side |
| `RunFinished` | `runId` | the run ended (e.g. `max_iterations` reached) |

A renderer applies the snapshot, then each delta — no full-page reloads. This is the
"live page" path; `GET /api/surfaces/{id}` is the static one-shot.

### Normative client behavior (hardened in that change)

The rules below are what make a stream consumer safe against a hostile or broken
upstream. The bundled [reference renderer](../../renderer/README.md) implements them
(`renderer/src/stream.js`) and is the conformance yardstick.

**Reconnect & backfill — snapshot replay.**
The stream is stateless per connection: every (re)connect starts a fresh run, and the
server's first state event is always a full `StateSnapshot`. That snapshot **is** the
backfill mechanism — there is no `Last-Event-ID` resume and no delta replay across
connections. Therefore a client:

- MUST discard all held surface state at `RunStarted` and rebuild from the next
  `StateSnapshot`; deltas from a previous run MUST NOT be applied to a new run.
- MUST treat `RunFinished` (or transport loss) as "reconnect when you still want the
  page", and SHOULD reconnect with exponential backoff plus jitter (reference: 1 s
  base, 30 s cap, reset after a healthy snapshot).
- MUST NOT assume events arrive whole: SSE frames split across arbitrary transport
  chunks, and `data:` lines may span CRLF or LF framing.

**Malformed-delta rejection — atomic or nothing.**
A `StateDelta` payload MUST be an array of RFC 6902 operations limited to
`add` / `replace` / `remove` (this is all the server emits). A client:

- MUST validate the whole delta before applying any of it, and MUST reject the whole
  delta if any op is malformed (unknown op, invalid RFC 6901 path, missing `value`,
  target that does not resolve). A delta is never partially applied.
- MUST re-validate the patched document as a complete A2UI envelope; a delta that
  mutates the surface into an invalid envelope is malformed.
- MUST reject ops whose paths traverse `__proto__` / `constructor` / `prototype`
  (prototype-pollution guard).
- MUST treat a delta arriving before any snapshot in the current run as a protocol
  violation.
- On any rejection, MUST resynchronize by dropping held state and reconnecting for a
  fresh snapshot (or falling back to the one-shot `GET`) — never keep painting from a
  document a bad delta may have described.
- MUST ignore unknown event `type`s (forward compatibility with the wider AG-UI
  vocabulary: `TextMessage*`, `ToolCall*`, future additions) and unparseable event
  lines, but SHOULD resync if garbage is sustained.

**Versioned envelope negotiation.**
The envelope's `version` field pins the A2UI schema. Wire versions in flight today:
`"0.9"` and `"0.10"` (native flat shape — v0.10 is a superset component vocabulary on
the v0.9 envelope), and `"0.8"` (legacy OpenClaw Canvas shape, requested explicitly
with `?schema=v0.8`; also downgradable per-response). A client:

- MUST check `version` on every snapshot (and on every patched document) and render
  only versions it supports.
- MUST treat an unsupported `version` as a rejected envelope — show a clear
  "unsupported version" state or deterministic fallback, never guess at the schema
  and never crash.
- The negotiation channel is the `?schema=` query parameter (client asks); the
  server answers with the `version` it actually produced. There is no header-based
  negotiation, and the envelope shape itself stays frozen.

## Generation, trust & degradation

- **Source of truth is data, not the LLM.** Deterministic surfaces (`today`, `chronicle`) are built directly from the local **Agency Log / receipt ledger** — no model in the path. `compose` is the only LLM-generated path and is **opt-in** (requires a BYOK key).
- **BYOK degradation.** No key, a failed generation, or a guard rejection MUST fall back to a deterministic view — never a broken or empty page.
- **A generated surface is an attack surface.** Generated output passes the trust/safety guards before it's served; renderers treat surface data as untrusted (no script execution, declarative components only).
- **No fabricated content.** Surfaces render real receipts/state; the agent never invents trust signals to display.

## Renderer contract

A renderer is anything that consumes the envelope. To be conformant it MUST:

1. Resolve `root`, then walk the flat `components` list by `id`.
2. Render only declarative components; **skip unknown component types** without failing.
3. For live pages, apply `snapshot` then `delta` events per the normative client
   behavior above (atomic deltas, snapshot-replay resync).
4. Submit user actions to `POST /api/surfaces/action` and render the returned surface.
5. Execute no code from surface data — it is untrusted, declarative UI only.
   Concretely: surface text MUST only reach the page as text nodes (no HTML parsing
   of surface data anywhere), URL-bearing fields (`Link.url`, `Image.url`,
   `Avatar.imageUrl`, markdown link targets) MUST pass a scheme allowlist
   (`javascript:`/`vbscript:`/`data:text/*` are hostile), enum-ish fields
   (`variant`, `usageHint`, `inputType`, …) MUST map through fixed token sets
   rather than concatenating into markup or class names, and reference walks MUST
   be bounded by all three of: a cycle guard, a depth cap, and a **budget on the
   total number of component instances one surface may paint**.

   > This rule previously required only the first two. A cycle guard that tracks
   > the current path — the usual implementation — refuses a component only when
   > it appears on its own ancestor chain, and a directed acyclic graph contains
   > no such repeat. A chain of components, each referencing the next one twice,
   > is acyclic, stays under any depth cap, declares two children per node, and
   > doubles the painted node count at every level. Measured on the reference
   > renderer: twenty components and 1.2 KB on the wire painted 1,048,575 nodes,
   > and twenty-one exhausted a 2 GB heap, with every other cap satisfied
   > throughout. A client bounding only cycles and depth does not terminate on
   > such a surface.
6. Survive hostile structure: dangling `child`/`children` references, duplicate
   ids (first declaration wins), and component floods (cap and reject) — degrade to
   visible placeholders, never crash.

The bundled reference renderer (`renderer/`) implements this contract; its test
suite (`renderer/tests/`, including the hostile-payload fixture
`renderer/tests/fixtures/hostile-surface.json`) is the executable form of rules
5–6 and runs in CI.

## Built vs. roadmap

| | Status |
|---|---|
| A2UI v0.10 envelope + builders (`arp_surfaces.py`) | ✅ built |
| `GET /surfaces/{id}`, `compose`, `action`, `stream` | ✅ built |
| Deterministic surfaces from the Agency Log | ✅ built |
| A **reference renderer** (paint the envelope) | ✅ built (`renderer/`) |
| Hardened AG-UI delta protocol + reconnection | ✅ built (normative rules above + `renderer/src/stream.js`) |
| Generation trust/safety guard suite | 🛠 roadmap (server-side; renderer-side guards shipped in that change) |

See the [Roadmap](../ROADMAP.md) for sequencing.
