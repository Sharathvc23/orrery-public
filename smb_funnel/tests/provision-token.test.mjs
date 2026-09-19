/**
 * The provisioning credential: sent when held, absent when not, never rendered.
 *
 * `smb_host` gates `POST /provision` on a shared secret and answers 401 without
 * it (`SMB_HOST_PROVISION_TOKEN`). Three things have to be true of the funnel and
 * none of them can be seen by testing a module on its own:
 *
 *   1. the header is on the wire when this browser holds a token, and the request
 *      is byte-identical to the old one when it does not;
 *   2. a 401 reads as "this host wants a credential you have not given it", not
 *      as "something went wrong, please try again" — a gated host answers 401
 *      forever, so retrying is the one advice that cannot work;
 *   3. the token reaches the network and nothing else. Not the document, not an
 *      attribute, not an error string, and not the address bar after load.
 *
 * So these drive the REAL app against a real HTTP host and assert (1) FROM WHAT
 * THE SERVER RECEIVED rather than from what the client believes it sent, and (3)
 * over the WHOLE node tree rather than over the elements a leak was expected in.
 *
 * Classification: ADVERSARIAL (credential handling) + WIRING.
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { after } from "node:test";

import { fire, installDocument } from "./funneldom.mjs";

const TOKEN = "s3cret-demo-token-do-not-render";

/** "ok" | "401" | "503" | "409" — the host's answer to POST /provision. */
let mode = "ok";

/** Every request the host actually received, headers included. */
let received = [];

const TENANT = "fadeaway-barbershop";

const server = createServer((req, res) => {
  const base = `http://127.0.0.1:${server.address().port}`;
  received.push({ method: req.method, url: req.url, headers: req.headers });
  const send = (status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };

  if (req.method === "POST" && req.url === "/provision") {
    // The host's real wording and real body shape: FastAPI sends `detail`.
    if (mode === "401") {
      res.setHeader("WWW-Authenticate", "Bearer");
      return send(401, {
        detail: "provisioning on this host requires 'Authorization: Bearer <token>' (SMB_HOST_PROVISION_TOKEN).",
      });
    }
    if (mode === "503") {
      return send(503, {
        detail:
          "SMB_HOST_PROVISION_TOKEN is not set and HOST_PUBLIC_URL is 'https://smb.example.com', which is not a loopback address.",
      });
    }
    if (mode === "409") {
      return send(409, { detail: "a business is already provisioned under the name 'Fadeaway Barbershop'" });
    }
    if (mode === "400") {
      return send(400, { detail: "business_name must contain at least one alphanumeric character" });
    }
    if (mode === "400-contact") {
      return send(400, {
        detail: "a plain http webhook is refused: a booking carries a customer's name and time",
      });
    }
    if (mode === "422") {
      // FastAPI's validation body: detail is an ARRAY, not a string.
      return send(422, {
        detail: [{ type: "missing", loc: ["body", "business_name"], msg: "Field required", input: {} }],
      });
    }
    if (mode === "500") {
      return send(500, { detail: "internal error" });
    }
    if (mode === "429") {
      res.setHeader("Retry-After", "1800");
      return send(429, { detail: "too many signups from this connection in the last hour. Try again in about 30 minute(s)." });
    }
    if (mode === "507") {
      return send(507, {
        detail: "this service has issued its full allocation of agents (250 of 250). No further signups until an operator raises the cap.",
      });
    }
    return send(201, {
      tenant_id: TENANT,
      endpoint: `${base}/t/${TENANT}`,
      did: "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
      recovery_phrase: Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(" "),
    });
  }
  if (req.method === "GET" && req.url === `/t/${TENANT}/.well-known/agent.json`) {
    return send(200, { name: "Fadeaway Barbershop", "x-nanda": { did: "did:key:z6Mkw" } });
  }
  return send(404, { detail: "not found" });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const apiBase = `http://127.0.0.1:${server.address().port}`;

// The API host is operator configuration and keeps its existing home. Set before
// the first import of any funnel module, because api.js resolves it once.
globalThis.localStorage = { getItem: (k) => (k === "smb_funnel.api_base" ? apiBase : null), setItem() {}, removeItem() {} };

after(() => server.close());

/** A tab: its own session storage, its own address bar, its own history. */
function newTab(search) {
  const store = new Map();
  globalThis.sessionStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  const replaced = [];
  globalThis.location = { search, pathname: "/index.html", hash: "" };
  globalThis.history = {
    replaceState(_state, _title, url) {
      replaced.push(url);
      globalThis.location.search = String(url).includes("?") ? `?${String(url).split("?")[1]}` : "";
    },
  };
  return { store, replaced };
}

/**
 * Boot a fresh app in a fresh tab and submit the form.
 *
 * Each case gets its own module instance (the query string busts the cache) so
 * boot-time work — taking the token out of the URL — runs per case, while
 * `./api.js` stays shared and every case talks to the one host.
 */
async function provisionOnce(caseName, search) {
  received = [];
  const tab = newTab(search);
  const doc = installDocument();
  await import(`../src/app.js?token-case=${caseName}`);
  doc.querySelector("#business-name").value = "Fadeaway Barbershop";
  // Required by the host and by the form, so the submit reaches the network at
  // all — this suite is about the credential, not about the contact.
  doc.querySelector("#contact").value = "https://bookings.example/hook";
  doc.querySelector("#service-type").value = "Haircuts";
  await fire(doc, "#funnel-form", "submit");
  const provision = received.find((r) => r.method === "POST" && r.url === "/provision");
  const box = doc.querySelector("#form-error");
  return { doc, tab, provision, box, state: box.dataset.state, text: box.textContent };
}

/**
 * Every string this page could show a human: the text of every node, every
 * attribute set on it, and every dataset value.
 *
 * Deliberately not "the element I expect the leak in" — a credential guard that
 * looks where the secret was supposed to go finds it only where it was already
 * known to be.
 */
function documentSurface(doc) {
  // ⚠️ THE SEPARATOR IS AN ESCAPE, NOT A RAW NUL. It was a literal NUL byte in
  // the source, which made git classify this file as BINARY — no diffs in review,
  // and a rebase that cannot three-way merge it at all. Same separator, same
  // behaviour, and the file is text again.
  const parts = [];
  for (const el of [...doc.elements.values(), ...doc.created]) {
    parts.push(el.textContent ?? "");
    parts.push(JSON.stringify(el.attributes ?? {}));
    parts.push(JSON.stringify(el.dataset ?? {}));
    parts.push(String(el.title ?? ""), String(el.value ?? ""));
  }
  for (const node of doc.textNodes) parts.push(node.data);
  return parts.join("\u0000");
}

test("a token in the URL is sent as a bearer, then taken out of the address bar", async () => {
  mode = "ok";
  const { doc, tab, provision } = await provisionOnce("sent", `?provision_token=${TOKEN}`);

  // (1) asserted from what the SERVER received.
  assert.equal(provision.headers.authorization, `Bearer ${TOKEN}`, "the host did not receive the bearer token");

  // It survives the tab and only the tab.
  assert.equal(tab.store.get("smb_funnel.provision_token"), TOKEN);

  // And it is out of the address bar before anything rendered.
  assert.equal(tab.replaced.length, 1, "the token parameter was never stripped");
  assert.doesNotMatch(tab.replaced[0], /provision_token/);
  assert.doesNotMatch(globalThis.location.search, /provision_token/);

  // (3) and it is nowhere a person can see.
  assert.ok(!documentSurface(doc).includes(TOKEN), "the token reached the rendered document");
});

test("a browser with no token sends no Authorization header at all", async () => {
  /** ⚠️ ABSENT, NOT EMPTY. `Authorization: Bearer ` with nothing after it is a
   * third state neither side has a rule for, and this is the shape CI, the demo
   * scripts and every loopback host use — it must be the request that was sent
   * before the gate existed. */
  mode = "401";
  const { provision } = await provisionOnce("unsent", "");

  assert.ok(!("authorization" in provision.headers), `an Authorization header was sent: ${provision.headers.authorization}`);
});

test("a 401 with no token says the host wants a credential, not 'try again'", async () => {
  mode = "401";
  const { state, text } = await provisionOnce("missing", "");

  assert.equal(state, "credential-missing");
  assert.match(text, /needs a provisioning credential/i);
  assert.match(text, /provision_token/, "the page must say how the credential is supplied");
  assert.doesNotMatch(text, /Please try again/i, "a gated host answers 401 forever; retrying cannot work");
  // The host's own words are shown rather than discarded.
  assert.match(text, /SMB_HOST_PROVISION_TOKEN/);
});

test("a 401 while holding a token says the token was rejected", async () => {
  /** The two 401s are different facts for the operator: paste the token, versus
   * the token you pasted is the wrong one. The response cannot tell them apart —
   * the host refuses identically on purpose — but the page knows which it sent. */
  mode = "401";
  const { doc, state, text } = await provisionOnce("rejected", `?provision_token=${TOKEN}`);

  assert.equal(state, "credential-rejected");
  assert.match(text, /rejected/i);
  assert.doesNotMatch(text, /Please try again/i);
  assert.ok(!documentSurface(doc).includes(TOKEN), "the rejected token was rendered back");
});

test("a 503 is the host's own misconfiguration, and says so", async () => {
  /** Reachable only when the host has NO token configured, so it is never the
   * browser's credential at fault — collapsing it into the 401 state would send
   * the operator to paste a secret that would change nothing. */
  mode = "503";
  const { state, text } = await provisionOnce("unconfigured", "");

  assert.equal(state, "host-unconfigured");
  assert.match(text, /not set up to provide agents/i);
  assert.match(text, /HOST_PUBLIC_URL/, "the host's diagnosis must reach the operator");
});

test("a name the host refuses says to change it, not to try again", async () => {
  /** ⚠️ THE ADVICE HAS TO BE ACTIONABLE. A punctuation-only or whitespace-only
   * name is a 400 that repeats forever; "please try again" is the single
   * instruction that cannot work, and it was what the page said. */
  mode = "400";
  const { state, text } = await provisionOnce("badname", "");

  assert.equal(state, "input-rejected");
  assert.match(text, /can't be used/i);
  assert.match(text, /[Cc]hange what it names/);
  assert.doesNotMatch(text, /Please try again/i);
  assert.match(text, /at least one alphanumeric character/, "the host's own reason must reach the person");
  // ⚠️ THE HEADLINE MUST NOT NAME ONE FIELD. Provisioning now also requires a
  // contact, so this panel is reached by refusals that have nothing to do with
  // the name; it used to open "That business name can't be used".
  assert.doesNotMatch(text, /That business name/, "the panel blames a field it cannot know is at fault");
});

test("a refused contact reaches the same panel, with the host's own reason", async () => {
  /** ⚠️ THE DECISION, ASSERTED. A refused contact is the same ACTION as a refused
   * name — change what you entered and submit again — so it is the same state,
   * and the specificity comes from the host's message rather than from a second
   * panel that would give identical advice under a different heading. */
  mode = "400-contact";
  const { state, text } = await provisionOnce("contactrejected", "");

  assert.equal(state, "input-rejected");
  assert.match(text, /plain http webhook is refused/, "the host's reason about the CONTACT must reach the person");
  assert.doesNotMatch(text, /Please try again/i);
});

test("a 422 renders the host's field and reason, not a status code or [object Object]", async () => {
  /** FastAPI refuses an absent or empty name BEFORE the handler, so `detail` is a
   * validation ARRAY. The client read only string details, so the commonest
   * refusal a person can provoke rendered as the bare `HTTP 422`. */
  mode = "422";
  const { state, text } = await provisionOnce("validation", "");

  assert.equal(state, "input-rejected");
  assert.match(text, /business_name: Field required/);
  assert.doesNotMatch(text, /\[object Object\]/);
  assert.doesNotMatch(text, /HTTP 422/, "a status code is not what the host said");
});

test("a taken name says it is taken, and that resubmitting cannot work", async () => {
  /** ⚠️ MY OWN EARLIER REASONING, CORRECTED. The generic state was justified on
   * "a name collision IS worth retrying". It is not: a 409 means the tenant id is
   * claimed, so the identical name collides forever. */
  mode = "409";
  const { state, text } = await provisionOnce("taken", "");

  assert.equal(state, "name-taken");
  assert.match(text, /already taken/i);
  assert.match(text, /different name/i);
  assert.doesNotMatch(text, /Please try again/i);
});

test("a rate limit says the wait clears it, and does not blame the name", async () => {
  /** The public front door bounds signup, so a browser now meets refusals the
   * host alone never sent. Waiting genuinely fixes this one. */
  mode = "429";
  const { state, text } = await provisionOnce("ratelimited", "");

  assert.equal(state, "rate-limited");
  assert.match(text, /too many signups/i);
  assert.match(text, /clears on its own/i);
  assert.doesNotMatch(text, /change the name/i, "a rate limit is not the name's fault");
});

test("at capacity says waiting will NOT clear it", async () => {
  /** ⚠️ THE DISTINCTION THAT MATTERS. A full allocation stays full until an
   * operator raises it, so advising a wait would send a business away to a door
   * that will still be shut — the 401 "try again" defect one floor up. */
  mode = "507";
  const { state, text } = await provisionOnce("atcapacity", "");

  assert.equal(state, "at-capacity");
  assert.match(text, /all the agents it is allowed to/i);
  assert.match(text, /Waiting will not clear it/i);
  assert.doesNotMatch(text, /Please try again/i);
});

test("the eight refusal states are eight distinct panels", async () => {
  /** The assertion that catches this class without knowing the cause: two
   * outcomes a reader cannot tell apart are one outcome. */
  const runs = [
    ["401-none", "401", ""],
    ["401-held", "401", `?provision_token=${TOKEN}`],
    ["503-x", "503", ""],
    ["400-x", "400", ""],
    ["409-x", "409", ""],
    ["429-x", "429", ""],
    ["507-x", "507", ""],
    ["500-x", "500", ""],
  ];
  const seen = [];
  for (const [name, m, search] of runs) {
    mode = m;
    const { state, text } = await provisionOnce(`distinct-${name}`, search);
    seen.push({ state, headline: text.split(".")[0] });
  }
  assert.equal(new Set(seen.map((s) => s.state)).size, runs.length, `states collide: ${seen.map((s) => s.state)}`);
  assert.equal(
    new Set(seen.map((s) => s.headline)).size,
    runs.length,
    `headlines collide: ${seen.map((s) => s.headline).join(" | ")}`,
  );
  // Exactly one of them may tell a person to try again.
  const retryable = seen.filter((s) => /try again/i.test(s.headline)).length;
  assert.ok(retryable <= 1, "more than one state advises retrying");
});

test("an ordinary failure still reads as a failure, and shows what the host said", async () => {
  /** ⚠️ THE REGRESSION THAT WAS ALREADY SHIPPING. The funnel read `data.error`,
   * which is `mock_core.js`'s shape; the real host is FastAPI and sends `detail`.
   * So against the deployed host EVERY refusal rendered as the bare status — the
   * duplicate-name 409 included. A control that refuses everything and a page
   * that explains nothing both pass a test that only checks failure happened. */
  mode = "500";
  const { state, text } = await provisionOnce("server-error", "");

  assert.equal(state, "failed");
  assert.match(text, /internal error/, "the host's detail was discarded");
  assert.match(text, /Please try again/i, "a server-side fault IS worth retrying, unlike a 400 or a 401");
});
