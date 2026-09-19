# smb_funnel — the 3-click SMB onboarding funnel

> "A barber clicks three times and has a sovereign, verifiable agent."

A lightweight, self-contained web funnel that takes a small business from *"what
do you do?"* to a **provisioned agent with a verifiable did:key identity** — the
on-stage demo experience for Milestone B3.

The funnel (and `smb_host`) register on **no index**. There is one NANDA Index
(`api.nandaindex.org`) and putting the agent there is host39's job, downstream of
what `POST /provision` returns (`{tenant_id, endpoint, did, recovery_phrase}`).
The funnel's role is: provision the agent, show its identity + live card, and
prove a booking receipt verifies **offline** in the browser.

Framework-free: static HTML + CSS + vanilla JS (same shape as `renderer/`). No
build step, no runtime dependencies. Runs end-to-end standalone against an
in-page mock, and flips to the real multi-tenant host (`smb_host/`) with a
one-line config change. The funnel speaks the **real host contract** either way,
and the booking receipt it renders is a **genuine, offline-verifiable** ARP
receipt — the same accept/reject the member-SDK's `arp.verify_receipt` makes,
recomputed in the browser with real Ed25519.

## The three screens (≤ 3 primary clicks)

1. **Get your business its own AI agent** — one screen: business name +
   a one-line "what do you do?". One CTA: **Create my agent**. *(click 1)*
2. **Creating your agent…** — provisioning state; calls `POST /provision`.
3. **Agent provisioned** — shows a copyable **agent card link**
   (`endpoint + /.well-known/agent.json`), the **endpoint**, the **did:key**, the
   **recovery phrase** (with a *"write this down, shown once"* warning), and an
   honest note that registering on NANDA is host39's next step — plus a **Try it**
   action *(click 2)* that calls `POST /t/{tenant}/book` and renders the returned
   **raw signed ARP receipt**, verified **offline in the browser**.

Click path from cold start to live: **1 click** (the CTA). The Try-it booking is
one more optional primary click. Everything else (copy buttons, start-over) is
secondary.

## The verification badge is real, and it says which check it ran

`POST /t/{tenant}/book` returns the **raw signed ARP receipt** exactly as the
host persists it:

```json
{
  "version": "arp/0.1",
  "receipt_id": "…uuid…",
  "issuer_did": "did:key:z6Mk…",
  "principal_did": "did:key:z6Mk…",
  "issued_at": "2026-08-01T14:30:00Z",
  "action": {
    "category": "appointment_booked",
    "outcome": "completed",
    "human_summary": "Booked Haircut with …",
    "machine_payload": { "service": "…", "provider": "…", "datetime": "…", "notes": "…", "booking_id": 1 }
  },
  "signature": "…base64 ed25519…"
}
```

`src/arp.js` verifies it the same way the server does, with **no trust in the
server**:

1. Parse `issuer_did` (`did:key:z…` → base58btc → multicodec `0xed01` ‖ 32-byte
   Ed25519 public key).
2. Reconstruct the JCS / RFC 8785 canonical bytes of the receipt **without** its
   `signature` field — byte-for-byte identical to `arp.py`'s
   `canonical_bytes_for_signing`.
3. Ed25519-verify the base64 `signature` over those bytes (WebCrypto
   `crypto.subtle`).
4. Check that `issuer_did` is the key published on the tenant's agent card —
   fetched from the host in this session (`app.js` passes `liveTenant.cardDid` as
   `expectedIssuer`).

**There is no stored pin, and the badge no longer claims one.** `src/pin.js` kept
a `did:key` per host in `localStorage` and reported `new` / `trusted` / `warning`
/ `unknown`; nothing on the verification path read it, and the success tooltip
told the customer the issuer matched "this business's pinned did:key". It was
removed rather than wired, because trust-on-first-use needs a **second
encounter** and this funnel mints a **new tenant on every run** — a pin would be
written and read inside a single session, making its verdict a function of its
own write. If a repeat-visit customer surface is ever built, that is where a pin
belongs, keyed by host **and** tenant. `tests/wiring.test.mjs` now drives the real
app against a host that serves one key on the card and signs with another, so the
anchor is asserted where it is used rather than where it is defined.

Steps 1–3 match `arp.verify_receipt` on accept and reject. **Step 4 has no
server-side counterpart, and it is the one that makes the badge mean what a
customer reads into it.** A signature check alone proves a receipt is
self-consistent: whoever signed it holds the key named inside it. It cannot prove
the receipt came from the business you booked with, because the key and the claim
about whose key it is both come from the same document — so anyone can mint a
key, sign "paid in full" with it, and satisfy steps 1–3.

The badge therefore has three outcomes rather than two:

| Badge | What it means |
| --- | --- |
| **Verified offline — matches this agent's card ✓** | Signature good, and the issuer is the key on the agent card this host served for this tenant |
| **Signature valid — issuer not confirmed** | Signature good, but no card DID was available to check the issuer against |
| **Signed by a different key than the agent card ✗** | Signature good, issuer is not the key on the card — a rotation, or someone else |
| **Verification failed ✗** | The receipt was altered, or the signature does not match |

Each label names the comparison that ran. That is a deliberate constraint rather
than a stylistic one: the previous success label read "signed by this business"
and its tooltip cited a pin, and between them they described a check on the
business's identity when what had actually run was a check on one host's internal
consistency.

### What none of this proves: the issuer is the business

The card and the receipt are served by the **same origin**. Checking one against
the other establishes that the host is internally consistent — the key it put on
the card is the key it signed with. It does not establish that the host is the
business the customer believes they are dealing with, and no check performed in
the browser can, because both documents come from the party under question.

The anchor is outside the software: **how the customer got the URL.**

| How they arrived | What a verifying receipt is worth |
| --- | --- |
| Typed from the shop's own site, or scanned from a code on the counter | The origin was vouched for by the business itself, so the identity chain holds |
| Followed a directory entry, a search result, or a link inside the receipt | Nothing about the business — it establishes only that whoever runs that host signed consistently |

**Nothing in the product can tell those two cases apart.** The badge reads the
same in both. Provisioning bears this out: `POST /provision` takes no credential
and checks no relationship between the caller and the name, so the name on a card
is a display label rather than a claim anyone verified. A repeated name is now
refused on both provisioning paths, but that refusal is exact-slug: `Corner
Bakery Ltd` and `Corner Bakery NYC` are different slugs and each provision with
their own `did:key` alongside `Corner Bakery`. Refusing a repeat is not deciding
who is entitled to a name. A tenant URL identifies a tenant. It does not identify
a business.

`verify.mjs` takes the same anchor on the command line:

```bash
node verify.mjs --issuer did:key:z6Mk… receipt.json
```

It reports four outcomes, and **refused never shares one with unchecked** —
telling those apart is the tool's whole job:

| Outcome | Exit | Means |
| --- | :---: | --- |
| `VERIFIED ✓` | 0 | Signature good, and made by `--issuer` |
| `FAILED ✗` | 1 | The document is not what it says — a tampered receipt lands here |
| *(unreadable)* | 2 | Not JSON, or no such file |
| `UNCONFIRMED ?` | 3 | Signature good, but no `--issuer` was supplied, so nobody checked **who** signed |
| `MISMATCH ✗` | 4 | Signature good, and made by a key that is **not** `--issuer` — a rotation, or someone else |

The outcome is decided on the verifier's `stage`, never on its `provenance`.
`verifyReceipt` returns `provenance: "unknown"` for two unrelated cases — a
signature that failed, and a signature that passed with nothing to check the
issuer against — so a wrapper that branches on provenance first reports a
**tampered receipt as validly signed**. This one did, printing the `UNCONFIRMED`
line above for a receipt whose signature had just failed. `tests/verify-cli.test.mjs`
runs the binary over all five cases and asserts the printed line and the exit
code, including that no two outcomes share either.

Crypto backend: **WebCrypto Ed25519** (`crypto.subtle`), native in Node ≥ 20 and
in current Chrome (137+), Safari (17+) and Firefox (129+). No npm runtime
dependency, no vendored library. On an older browser without WebCrypto Ed25519
the badge reports verification as unavailable rather than claiming a false pass.

## Run it against the mock (zero external deps)

The funnel defaults to an **in-page mock** — no server, no network. The mock
mints a **real** Ed25519 key per tenant and signs each receipt with it, so the
exact browser verify path is exercised standalone. Just serve the static files:

```bash
cd smb_funnel
python3 -m http.server 8700     # or: npm run serve
# open http://localhost:8700
```

Enter a business name → **Create my agent** → watch it provision → land on the
"live on NANDA" screen → **Try it** to see a receipt verify offline.

### Headless smoke

Exercises the *same* `src/mock_core.js` + `src/arp.js` the browser runs —
provision → resolve card → book → **verify receipt true → tamper → false**, plus
error paths and `/health`:

```bash
node smoke.mjs        # npm run smoke   (exit 0 = all good)
```

### Verify any receipt from the CLI

```bash
# a bare receipt, a {receipt:{…}} book response, or piped from curl:
node verify.mjs receipt.json
curl -s http://localhost:8080/t/<tenant>/book -H 'content-type: application/json' \
     -d '{"service":"Haircut","provider":"…","datetime":"2026-08-01T14:30:00Z"}' | node verify.mjs
```

### Optional: run the mock as a real HTTP server

A real `fetch()` hop without the real host. Zero-dependency Node stub, backed by
the same core:

```bash
node mock_server.mjs            # npm run mock   → http://localhost:8788
# then point the funnel at it, in the browser console on http://localhost:8700:
#   localStorage.setItem("smb_funnel.api_base", "http://localhost:8788")
```

## Point it at a local smb_host

The funnel targets the real `smb_host` contract unchanged. To run the whole
loop locally (the host mints an identity and serves the card + booking receipts;
it registers on no index):

1. **Boot the smb_host** (needs the `community_member` package importable — use
   the repo `.venv`):

   ```bash
   cd smb_host
   HOST_PUBLIC_URL=http://localhost:8080 \
   SMB_HOST_DATA_DIR=/tmp/smb-tenants \
   COMMUNITY_MEMBER_KEYSTORE=device \
   python3 -m uvicorn main:app --port 8080
   ```

   A **loopback** `HOST_PUBLIC_URL` needs no provisioning token, so this is
   unchanged. A host on any other address requires one — see below.

   The host serves permissive CORS by default (a public provisioning API), so the
   browser funnel on another origin can reach it. Lock it down with
   `SMB_HOST_CORS_ORIGINS=http://localhost:8700` if you want an allowlist. The
   `Authorization` header is on the host's CORS allowlist because the gated
   `POST /provision` is preceded by a preflight naming it; without that the
   browser blocks the request before it is sent and the page sees a network
   failure rather than the host's answer.

2. **Point the funnel at it** — no file edit needed. In the browser console on
   `http://localhost:8700`:

   ```js
   localStorage.setItem("smb_funnel.api_base", "http://localhost:8080")
   ```

   Or set `API_BASE` in `src/config.js`. Precedence:
   **localStorage → `API_BASE` constant**. The top-right ribbon shows which
   backend is active (mock vs live).

   A `?api=` query parameter is not read. The provisioning screen displays the
   `/provision` response, including the recovery phrase, so the host that
   produces it is selected in the browser or in the build rather than by a link.

   ⚠️ **This works because `smb_host` mounts CORS. It does not work against
   `smb_signup`.** The public front door grants no cross-origin access on
   purpose — it serves this bundle from its own origin, and provisioning through
   it carries no caller credential, so any origin being allowed would let any
   page on the internet spend a visitor's allowance and the operator's cap from
   that visitor's browser. To drive the front door, open **its** address rather
   than pointing a separately-served copy of this page at it. A page in the
   unsupported shape now says so instead of showing a generic failure; see
   `src/config.js`.

## Provisioning a gated host

`smb_host` gates `POST /provision` on a shared secret whenever it is reachable
off its own machine (`SMB_HOST_PROVISION_TOKEN`; see `smb_host/README.md`).
Reading a card and making a booking are not gated, and the funnel sends a
credential to neither.

**The funnel is a static page, so it holds no secret of its own.** Anything
compiled into it is public, which is why the token is not a build value and why
this page is not itself deployed publicly in this shape: it runs locally, against
whichever host the operator points it at. The token is handed to a running page by
whoever is driving the demo:

```
http://localhost:8700/index.html?provision_token=<the secret the host was started with>
```

Read once at boot, moved into `sessionStorage`, and **stripped from the address
bar before anything renders** — so it does not survive a copied URL, a bookmark,
the back button, or a screen share, and it dies with the tab. It is sent only as
`Authorization: Bearer …` on `POST /provision`, and it is never rendered:
`tests/provision-token.test.mjs` asserts its absence over the whole node tree,
not over the elements a leak was expected in. `src/render.js` is not given the
value at all — only a boolean — so the module that writes to the document cannot
leak what it was never handed.

A browser with no token sends **no `Authorization` header at all** rather than an
empty one, so the un-gated loopback path is byte-identical to what it was before
the gate existed.

### What the page says when provisioning is refused

Four causes, four states, because they need different advice — and three of them
are not "please try again":

| Host answers | The page says | Because |
| --- | --- | --- |
| `401`, this browser has no token | This host needs a provisioning credential, and how to supply it | A gated host answers 401 forever; retrying is the one thing that cannot work |
| `401`, this browser has one | The host rejected this browser's credential | The host refuses identically either way on purpose, but the page knows which it sent |
| `503` | This host is not set up to provide agents, with the host's own diagnosis | Reachable only when the host has **no** token configured, so pasting a secret would change nothing |
| `400` or `422` | That business name can't be used — change it, with the host's own reason | Submitting the same name again gets the same answer, forever |
| `409` | That name is already taken on this host — choose another | A tenant id is claimed once; resubmitting this name cannot succeed |
| anything else (network, `5xx`) | Couldn't create your agent — please try again | The only genuinely retryable case |

**Only one row says "try again", and that is the point.** An earlier version
routed everything that was not `401`/`503` to it, justified on a name collision
being worth retrying. It is not: a `409` means the id is claimed, and a `400`
means the name has no alphanumerics to build an id from. Both repeat forever.

The host's own message is shown in each case. It used to be discarded: the client
read `data.error`, which is the mock's shape, while `smb_host` is FastAPI and
sends `detail` — so against the real host every refusal rendered as a bare `HTTP
409`/`HTTP 400`, with the explanation the host had already written thrown away.
A `422` is read too: FastAPI refuses an absent, empty or wrongly-typed name
*before* the handler runs, so its `detail` is a **list** of `{loc, msg}` objects
rather than a string, and it renders as `business_name: Field required`.

## Contract this funnel targets (smb_host)

| Method & path | Request | Response |
| --- | --- | --- |
| `POST /provision` | `{business_name, service_type?}`, `Authorization: Bearer <token>` when the host is gated | `201` `{tenant_id, endpoint, recovery_phrase, did}` · refusals all carry `{detail}`: `400` string (name has no alphanumerics), `401` string (no/!bad token), `409` string (name taken), `422` **array** (absent, empty or non-string name), `503` string (host unconfigured) |
| `GET /t/{tenant_id}/.well-known/agent.json` | — | A2A agent card (carries the did:key) · `404` `{detail}` |
| `POST /t/{tenant_id}/book` | `{service, provider, datetime, notes?}` | `{booking:{…,status:"recorded",tenant_id}, receipt_id, receipt}` — `receipt` is the raw signed ARP receipt · `400`/`404` `{detail}` |
| `GET /health` | — | health JSON |

**Every refusal is `{detail}`, and the in-page mock produces the same ones.** It
did not: the mock answered `{error: …}` with different statuses, and it
*provisioned* a punctuation-only name and a non-string name that the host refuses
outright — so a demo on the mock showed a success path the product does not have.
`tests/host_contract.json` now states the refusals once, and two suites hold both
sides to it: `smb_host/test_main.py` drives the real host, and
`tests/contract-parity.test.mjs` drives the mock. Neither can drift without the
other going red.

## Files

| File | Role |
| --- | --- |
| `index.html` | The 3 screens (one lives at a time). CSP-locked. |
| `styles.css` | Product-grade, theme-aware, responsive styling. |
| `src/config.js` | The single `API_BASE` switch (+ runtime overrides), and the provisioning token's capture out of the URL. |
| `src/api.js` | Thin client; dispatches to mock or real `fetch()`. |
| `src/app.js` | Funnel state machine + rendering + receipt verification. |
| `src/arp.js` | ARP crypto: JCS canonicalization, did:key, Ed25519 sign + verify. |
| `src/mock_core.js` | Shared contract implementation (browser **and** server), signs real receipts. |
| `mock_server.mjs` | Zero-dep HTTP stub host for real-network demos. |
| `smoke.mjs` | Headless end-to-end test incl. verify-true / tamper-false. |
| `verify.mjs` | CLI: verify a receipt from a file / stdin (works on real-host receipts). |
| `package.json` | Scripts only — **no runtime dependencies**. `npm test`, `npm run smoke`, `npm run serve`, `npm run mock`, `npm run verify`. |
| `tests/` | `node --test` suites (see below). `host_contract.json` is the refusal contract `smb_host` is held to as well. |

## Run the tests

No dependencies to install — `node --test`, built in, Node ≥ 20:

```bash
cd smb_funnel
npm test          # every suite below
node smoke.mjs    # the headless contract loop (npm run smoke)
```

| Suite | What it holds down |
| --- | --- |
| `tests/render.test.mjs` | The real render path under a stub DOM that throws on `innerHTML` — a `<script>` tag in a recovery phrase stays a text node. |
| `tests/source-guard.test.mjs` | Static audit: no HTML/eval sink, no navigable-URL assignment, and no UI string claiming a pin. |
| `tests/provenance.test.mjs` | A receipt signed by a stranger is refused; the anchor cannot come from the receipt. |
| `tests/wiring.test.mjs` | Boots the real `app.js` against an HTTP host and reads the badge it painted — including a host that serves one key on the card and signs with another. |
| `tests/provision-token.test.mjs` | The bearer is sent when held and absent when not (asserted from what the **server received**), the token never reaches the document, and each refusal state is distinct. |
| `tests/contract-parity.test.mjs` | The in-page mock refuses exactly what the real host refuses. |
| `tests/verify-cli.test.mjs` | Runs `verify.mjs` as a subprocess: the printed line **and** the exit code for all five outcomes. |
| `../scripts/browser_smb_funnel.py` | The three clicks in a real browser against the real host, cross-origin — the only thing here that performs a preflight. |

The CI job for this directory runs `node --check` on every module, then these
suites, then `smoke.mjs`.

### And one that opens a browser

None of the suites above can see a preflight, a CSP refusal, or what the address
bar holds — a constructed document performs no CORS, and `smoke.mjs` never
touches the network. That blind spot shipped a real defect: `Authorization` was
missing from `smb_host`'s CORS allowlist, so a **gated host was unreachable from a
browser with a valid token exactly as much as without one**, and five green suites
saw nothing. It took a person opening a browser.

```bash
pip install playwright && playwright install chromium-headless-shell
PYTHONPATH=agent python3 scripts/browser_smb_funnel.py    # add --headed to watch
```

It boots the real `smb_host` gated on a token, serves this directory on a
**different origin** (same-origin would remove the preflight, which is the point),
and drives the actual page: fill both fields, click through, read what was
rendered, click *Try it*, and assert the badge. Three cases — a credentialed
happy path, a browser with no credential, and a host serving one key on its card
while signing with another. It runs in CI as `smb_browser`.

## Security

- **No secret is built into this page.** The one credential it can hold — the
  provisioning token — is supplied at runtime, kept in `sessionStorage` for the
  life of the tab, stripped from the URL on read, sent only as a bearer on
  `POST /provision`, and never rendered. No external calls except to `API_BASE`.
- CSP in `index.html` restricts scripts/styles to `'self'`. **`connect-src` is
  `'self' http: https:` — any http or https host, not only the configured one.**
  It stops a page from reaching a `ws:` or `data:` destination and nothing
  narrower; what actually constrains where the funnel talks is `API_BASE`, which
  is not a browser-enforced control. Narrowing the header would mean baking the
  deployment's host into it, which is why it is written this way — but the
  previous wording claimed a restriction the header does not impose. All rendered contract values are HTML-escaped.
- The recovery phrase is returned **only** by `POST /provision` and shown once;
  the mock never re-serves it from any GET.
- Receipt verification is **client-side**: the signature is recomputed in the
  browser against the issuer's own `did:key`, so a receipt altered after signing
  is rejected without asking the host anything.
  ⚠️ **It is not trustless, and a lying server is the case it does NOT catch.**
  This bullet used to claim it did, three hundred lines below the section that
  says the opposite. The host serves the card AND signs the receipt, so a host
  that wants to lie signs with the key it published and every check on this page
  passes. What is detected is a receipt changed by someone who is not the signer.
  See [What none of this proves](#what-none-of-this-proves-the-issuer-is-the-business).
