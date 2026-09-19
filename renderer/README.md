# A2UI reference renderer

The suite's bundled way to *see* a surface. Orrery agents and orgs emit their UI as
data — [A2UI](../docs/specs/agui.md) envelopes over AG-UI SSE — and this package
paints it: connect to any org/agent `/api/surfaces/*`, render the snapshot, apply
live deltas.

It is deliberately **not** a portal: no accounts, no state, no backend. A static
page plus five ES modules, zero dependencies, no build step. Its other job is to be
the **executable form of the renderer contract** in
[`docs/specs/agui.md`](../docs/specs/agui.md) — the untrusted-content rules,
the hardened streaming behavior, and the keyless degradation ladder all live here
with tests.

## Run it

**It is already running after `./orrery-up`.** The installer brings this
directory up as a Compose service on `http://localhost:8600` (the `ui` profile),
so a fresh install has something to open, and `./orrery-up down` stops it with
the rest of the stack — the reason it is a service rather than a process the
installer spawns and then cannot account for.

Serving it yourself works exactly as well, and is the right thing when you are
pointing it at an org somewhere else. Any static file server works; nothing is
compiled, and the container runs this same command:

```bash
cd renderer
python3 -m http.server 8600
# open http://localhost:8600, point "Server" at your org (e.g. http://localhost:7000)
```

Pick a page (`dashboard`, `digest`, `members`, …) and either **Connect (live)**
(AG-UI SSE: snapshot + deltas, auto-reconnect) or **Fetch once** (deterministic
one-shot). Against a bare `docker compose up` with **no LLM key configured**, the
deterministic surfaces render fully — that is the BYOK-degradation guarantee: no
key never means a broken page.

Cross-origin note: the renderer only needs `GET /api/surfaces/*` (and
`POST /api/surfaces/action` for interactive components). It is always a
*different origin* from the org — a different port is a different origin — so
CORS applies even on one machine, and the answer depends entirely on the org's
deployment profile:

| org `ORRERY_PROFILE` | what the renderer needs |
|---|---|
| `dev` (what `./orrery-up` writes) | nothing. Measured against a live keyless stack: `GET /api/surfaces/dashboard` with `Origin: http://127.0.0.1:8600` returns `access-control-allow-origin: *`, and the preflight for `POST /api/surfaces/action` allows `POST` and `content-type`. |
| `prod` (the Compose default, deny-by-default) | the renderer's origin listed in `ALLOWED_ORIGINS`. Without it the page loads and every read is blocked by the browser: no `access-control-allow-origin` header is sent, and the renderer reports *server unreachable*. With `ALLOWED_ORIGINS=http://127.0.0.1:8600` the org echoes that exact origin and the surface paints. |

**Shipping the renderer changes neither default.** A production deployment names
the renderer's origin in `ALLOWED_ORIGINS` deliberately, the same as any other
browser client; nothing here relaxes the prod policy to make the local demo
work. See `docs/HARDENING.md`. There is no other server-side coupling.

## Layout

| file | role |
|---|---|
| `index.html` + `styles.css` | the page (strict CSP, theme-aware) |
| `src/envelope.js` | envelope validation + version negotiation (0.8 / 0.9 / 0.10) |
| `src/patch.js` | RFC 6902 subset — validate-then-apply, atomic rejection |
| `src/stream.js` | AG-UI SSE session + reconnect/backoff transport |
| `src/render.js` | sanitizing DOM painter (text-nodes-only, URL/enum allowlists) |
| `src/sanitize.js` | URL scheme allowlists, token maps, id hygiene |
| `src/app.js` | browser wiring + the degradation ladder |

Degradation ladder: live stream → deterministic one-shot `GET` → explicit
offline/error state with retry. Never a spinner that lies, never a blank page.

## Security model

Surface data is **untrusted** (it may be LLM-composed from attacker-influenced
intent, or relayed from a remote org). The renderer holds four structural
guarantees, enforced by tests:

1. surface text only ever becomes DOM **text nodes** — no HTML parsing sink exists
   in the codebase (`tests/source-guard.test.mjs` bans them statically);
2. URLs pass scheme allowlists (`javascript:` / `vbscript:` / `data:text/*` are
   defanged to a visible inert placeholder);
3. enum-ish fields map through fixed token sets — surface data never reaches an
   attribute name, event handler, or class-name concatenation;
4. hostile structure (cycles, dangling refs, duplicate ids, component floods,
   prototype-pollution ids/paths) degrades to placeholders, never a crash.

`tests/fixtures/hostile-surface.json` is the injection fixture from issue —
a surface full of script tags, handler attributes, hostile URLs and graph attacks
that must render inert. `node --test tests/*.test.mjs` runs it (CI job `renderer`).

## Tests

```bash
cd renderer
node --test tests/*.test.mjs   # unit + injection suites (no network, no deps)
node tests/e2e_live_probe.mjs http://localhost:7000 digest   # quick probe vs a live stack

# Full portal UI e2e (real Chromium via Playwright — the one dev dependency,
# exact-pinned + locked, used only for this suite):
npm ci && npx playwright install chromium
python3 -m http.server 8600 &          # serve the renderer on its own origin
ORG_URL=http://localhost:7000 node --test tests/e2e/*.e2e.mjs
```

The quick probe and the full portal suite both run in the compose e2e CI job
against a fresh keyless stack. The portal suite derives the page list and the
auth-gating split from server source at run time (`tests/e2e/gen_contract.py` —
nothing hardcoded), drives every wired surface page cross-origin in real
Chromium, and asserts painted surfaces, readable 401 states, a live AG-UI
stream, browser-consumable divergence/badge/health reads, the pill-width
fix, and zero CORS errors.
