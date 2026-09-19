/**
 * THE SIX STATES A REAL HOST PUTS A VISITOR IN — driven against a REAL host.
 *
 * ⚠️ WHY THIS SUITE EXISTS. The funnel words eight refusal states carefully, and
 * every one of them was tested against a hand-written node server whose bodies
 * were copied from a reading of `smb_host`'s source. That proves the app's own
 * wiring and it cannot prove that the copy is right. The gap it left was not
 * hypothetical: the fake's 503 is the `SMB_HOST_PROVISION_TOKEN`-not-set variant,
 * while the state the DEPLOYED host has been in is the `SMB_HOST_TENANT_CAP` one
 * — a different refusal, a different sentence, and no test had ever rendered it.
 * Every visitor to a funnel pointed at that host lands in that branch.
 *
 * So each case here starts a REAL `smb_host` (or a real `smb_signup`), configured
 * only through its environment, drives the REAL app against it, and asserts WHAT
 * THE PAGE RENDERED — the state on the box and the words in the node tree —
 * rather than the status code the fetch received. A status code is what the
 * transport saw; what the visitor is told is a different fact, and this file
 * asserts the second one.
 *
 * ⚠️ 429 IS NOT AN `smb_host` STATE, AND SAYING SO IS PART OF THE RESULT.
 * `smb_host` contains no rate limiter — the string "429" does not appear
 * anywhere in it. The per-source limit lives in `smb_signup`, the front door
 * that holds the credential on a static page's behalf. So the rate-limited case
 * boots a real `smb_signup` in front of a real `smb_host`, and is the one state
 * of the six a visitor cannot reach by talking to the host directly. That is a
 * property of the deployment, reproduced by configuration, not worked around
 * with a fake.
 *
 * Classification: WIRING (the app against the real contract) + REGRESSION.
 */

import assert from "node:assert/strict";
import test, { after, before } from "node:test";

import { fire, installDocument } from "./funneldom.mjs";
import { bootHost, bootSignup, HOST_PORT, requireHost, UPSTREAM_PORT } from "./hostboot.mjs";

const TOKEN = "real-host-suite-token";
const WRONG_TOKEN = "not-the-token-the-host-was-started-with";
const CONTACT = "https://bookings.example/hook";
const BASE = `http://127.0.0.1:${HOST_PORT}`;

// The API host is operator configuration. Set before the first import of any
// funnel module, because api.js resolves it once and shares it.
globalThis.localStorage = {
  getItem: (k) => (k === "smb_funnel.api_base" ? BASE : null),
  setItem() {},
  removeItem() {},
};

before(requireHost);

/** A tab: its own session storage, its own address bar, its own history. */
function newTab(search) {
  const store = new Map();
  globalThis.sessionStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.location = { search, pathname: "/index.html", hash: "" };
  globalThis.history = {
    replaceState(_s, _t, url) {
      globalThis.location.search = String(url).includes("?") ? `?${String(url).split("?")[1]}` : "";
    },
  };
}

/**
 * Boot the app in a fresh tab, fill the form, submit, and report WHAT IS ON THE
 * SCREEN.
 *
 * `headline` and `body` are read out of the nodes the renderer actually created,
 * not out of the copy table — a test that asserted against `COPY` would pass
 * while the renderer rendered nothing at all.
 */
async function visit(caseName, { search = "", name = "Fadeaway Barbershop" } = {}) {
  newTab(search);
  const doc = installDocument();
  await import(`../src/app.js?host-state=${caseName}`);
  doc.querySelector("#business-name").value = name;
  doc.querySelector("#contact").value = CONTACT;
  doc.querySelector("#service-type").value = "Haircuts";
  await fire(doc, "#funnel-form", "submit");

  const box = doc.querySelector("#form-error");
  const pick = (cls) => doc.created.filter((el) => el.className === cls).pop();
  const fieldValue = (sel) => {
    const el = doc.querySelector(sel);
    return el ? el.value || el.textContent || "" : "";
  };
  return {
    doc,
    state: box.dataset.state,
    hidden: box.hidden,
    headline: pick("err-headline")?.textContent ?? "",
    body: pick("err-body")?.textContent ?? "",
    detail: pick("err-detail")?.textContent ?? "",
    liveName: doc.querySelector("#live-name")?.textContent ?? "",
    endpoint: fieldValue("#endpoint"),
    did: fieldValue("#did"),
  };
}

/**
 * Does this copy tell the visitor that WAITING OR RETRYING will help?
 *
 * ⚠️ SENTENCES THAT DENY IT ARE DROPPED FIRST, and getting this wrong is how the
 * check first read. "Waiting will not clear it" contains the word "waiting" and
 * says the exact opposite of advice to wait; a plain word search classified the
 * at-capacity panel — whose whole purpose is to deny that waiting helps — as
 * advising it. Splitting on sentences and discarding the negated ones is what
 * makes this a question about the advice rather than about the vocabulary.
 */
function advisesWaiting(copy) {
  const sentences = String(copy).split(/(?<=[.!?])\s+/);
  const affirmative = sentences.filter((s) => !/\b(will not|won't|cannot|can't|never)\b/i.test(s));
  return affirmative.some((s) => /\b(try again|retry|retrying|wait|waiting|later|come back)\b/i.test(s));
}

/** What every case saw, so the distinctness assertion reads real renders. */
const seen = new Map();

async function record(key, fn) {
  const result = await fn();
  seen.set(key, result);
  return result;
}

// ── 1. 503 — the state the deployed host has actually been in ───────────────

test("503, cap unconfigured: the visitor is told the host is not set up, and NOT to retry", async () => {
  // The live configuration exactly: a token IS set and the caller HAS it, so
  // authorization passes and the refusal is purely about configuration. Reached
  // with a correct credential, which is what makes "try again" so wrong here.
  const host = await bootHost({
    HOST_PUBLIC_URL: BASE,
    SMB_HOST_PROVISION_TOKEN: TOKEN,
    SMB_HOST_POOL_SIZE: "0",
    // SMB_HOST_TENANT_CAP deliberately absent — this IS the state under test.
  });
  try {
    const r = await record("503", () => visit("cap-unset", { search: `?provision_token=${TOKEN}` }));
    assert.equal(r.state, "host-unconfigured");
    assert.equal(r.hidden, false, "the page rendered nothing at all");
    assert.equal(r.headline, "This host is not set up to provide agents.");

    // ⚠️ THE POINT OF THE WHOLE CASE. Nothing the visitor can do fixes this and
    // nothing they can wait for fixes it either — an operator has not finished
    // configuring the service. Advice to retry would be false in exactly the way
    // the at-capacity/rate-limited conflation was false one floor up.
    const shown = `${r.headline} ${r.body}`;
    assert.equal(advisesWaiting(shown), false, `the 503 panel tells the visitor to wait or retry: ${shown}`);

    // And it forwards the host's own words, which name the missing variable —
    // the one thing on the screen that is actionable, by the operator.
    assert.match(r.detail, /SMB_HOST_TENANT_CAP/, `the host's own explanation did not reach the page: ${r.detail}`);
  } finally {
    await host.stop();
  }
});

// ── 2 & 3. the two 401s — same status, different truth ──────────────────────

test("401 with no token: the visitor is told the host wants a credential this browser lacks", async () => {
  const host = await bootHost({
    HOST_PUBLIC_URL: BASE,
    SMB_HOST_PROVISION_TOKEN: TOKEN,
    SMB_HOST_TENANT_CAP: "10",
    SMB_HOST_POOL_SIZE: "0",
  });
  try {
    const r = await record("401-missing", () => visit("no-token"));
    assert.equal(r.state, "credential-missing");
    assert.equal(r.headline, "This host needs a provisioning credential.");
    assert.match(r.body, /does not have one/);
  } finally {
    await host.stop();
  }
});

test("401 with the wrong token: the visitor is told THIS token was rejected, not that one is missing", async () => {
  const host = await bootHost({
    HOST_PUBLIC_URL: BASE,
    SMB_HOST_PROVISION_TOKEN: TOKEN,
    SMB_HOST_TENANT_CAP: "10",
    SMB_HOST_POOL_SIZE: "0",
  });
  try {
    const r = await record("401-rejected", () => visit("wrong-token", { search: `?provision_token=${WRONG_TOKEN}` }));
    assert.equal(r.state, "credential-rejected");
    assert.match(r.headline, /rejected this browser's provisioning credential/);
    assert.match(r.body, /retrying will not change the answer/);

    // The rejected secret is not echoed back onto the screen.
    assert.doesNotMatch(`${r.headline} ${r.body} ${r.detail}`, new RegExp(WRONG_TOKEN));
  } finally {
    await host.stop();
  }
});

// ── 4. 507 — the allocation is spent ────────────────────────────────────────

test("507 at capacity: the visitor is told waiting will NOT clear it", async () => {
  const host = await bootHost({
    HOST_PUBLIC_URL: BASE,
    SMB_HOST_PROVISION_TOKEN: TOKEN,
    SMB_HOST_TENANT_CAP: "1",
    SMB_HOST_POOL_SIZE: "0",
  });
  try {
    // Fill the one slot through the host's own operator path, so the state under
    // test is a real exhausted allocation rather than a stubbed status.
    const fill = await fetch(`${BASE}/provision`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ business_name: "First Through The Door", contact: CONTACT }),
    });
    assert.equal(fill.status, 201, await fill.text());

    const r = await record("507", () =>
      visit("at-capacity", { search: `?provision_token=${TOKEN}`, name: "Second In Line" }),
    );
    assert.equal(r.state, "at-capacity");
    assert.match(r.headline, /issued all the agents it is allowed to/);
    assert.match(r.body, /Waiting will not clear it/);
    assert.match(r.detail, /full allocation of tenants \(1 of 1\)/);
  } finally {
    await host.stop();
  }
});

// ── 5. 429 — and it does not come from the host ─────────────────────────────

test("429 rate-limited: the visitor is told the wait clears it, and the name is not blamed", async () => {
  // ⚠️ TWO SERVICES, BECAUSE THE STATE GENUINELY NEEDS TWO. `smb_host` has no
  // rate limiter. The per-source limit is `smb_signup`'s, and `smb_signup` is
  // what a public visitor would actually be talking to, so this is the real
  // deployment shape rather than a convenience.
  //
  // ⚠️ AND THE LIMIT OF WHAT THIS CASE PROVES, STATED RATHER THAN LEFT IMPLIED.
  // `smb_signup` mounts NO CORS middleware — unlike `smb_host`, which mounts one
  // naming `Authorization` deliberately. So this assertion holds for the shape
  // `smb_signup` documents, where it serves the funnel bundle from its own
  // origin and no preflight is involved. Driven in a real Chromium against a
  // real pair, both measured: same-origin renders `rate-limited` with the host's
  // own "Try again in about 60 minute(s)"; a CROSS-ORIGIN page — the shape
  // `config.js` documents, `API_BASE` pointed at another origin — is refused at
  // the preflight and renders the generic "Couldn't create your agent. Please
  // try again." for a 429 it never saw. Node performs no preflight, so this test
  // passes either way; that gap is a real finding about `smb_signup` and is
  // reported rather than pinned here, because a test asserting today's behaviour
  // would make the defect permanent.
  const upstreamBase = `http://127.0.0.1:${UPSTREAM_PORT}`;
  const host = await bootHost(
    {
      HOST_PUBLIC_URL: upstreamBase,
      SMB_HOST_PROVISION_TOKEN: TOKEN,
      SMB_HOST_TENANT_CAP: "10",
      SMB_HOST_POOL_SIZE: "0",
    },
    UPSTREAM_PORT,
  );
  const signup = await bootSignup(
    {
      SMB_SIGNUP_HOST_URL: upstreamBase,
      SMB_HOST_PROVISION_TOKEN: TOKEN,
      SMB_SIGNUP_TENANT_CAP: "10",
      SMB_SIGNUP_RATE_PER_HOUR: "1",
    },
    HOST_PORT,
  );
  try {
    // Spend this source's single allowance for the hour.
    const first = await fetch(`${BASE}/provision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ business_name: "Early Bird Co", contact: CONTACT }),
    });
    assert.equal(first.status, 201, await first.text());

    const r = await record("429", () => visit("rate-limited", { name: "Second Signup Co" }));
    assert.equal(r.state, "rate-limited");
    assert.match(r.headline, /Too many signups from this connection/);
    assert.match(r.body, /clears on its own/);
    assert.match(r.body, /Nothing is wrong with the name you entered/);
  } finally {
    await signup.stop();
    await host.stop();
  }
});

// ── 6. 201 — and the credential does not survive onto the screen ────────────

test("201 success: the visitor gets the agent, and the token is nowhere on the page", async () => {
  const host = await bootHost({
    HOST_PUBLIC_URL: BASE,
    SMB_HOST_PROVISION_TOKEN: TOKEN,
    SMB_HOST_TENANT_CAP: "10",
    SMB_HOST_POOL_SIZE: "0",
  });
  try {
    const r = await record("201", () =>
      visit("success", { search: `?provision_token=${TOKEN}`, name: "Fadeaway Barbershop" }),
    );
    assert.equal(r.state, undefined, `a successful provision still rendered a refusal panel: ${r.state}`);
    assert.equal(r.liveName, "Fadeaway Barbershop");
    assert.match(r.endpoint, /\/t\/fadeaway-barbershop$/);
    assert.match(r.did, /^did:key:z/);

    // The whole node tree, not the fields a leak was expected in.
    const surface = [...r.doc.elements.values(), ...r.doc.created]
      .map((el) => `${el.textContent ?? ""} ${JSON.stringify(el.attributes ?? {})} ${el.value ?? ""}`)
      .join(" ");
    assert.ok(!surface.includes(TOKEN), "the provisioning token reached the document");
  } finally {
    await host.stop();
  }
});

// ── G1: the six are six, at the page ────────────────────────────────────────

test("the six real host states render six distinguishable pages", () => {
  assert.equal(seen.size, 6, `only ${seen.size} of the six states were driven — a missing case is not a pass`);

  // Distinguishable at what the page RENDERS. The state attribute alone would be
  // a weaker claim than it looks: 201 sets none, so the headline is included and
  // the pair is what has to be unique.
  const fingerprints = [...seen.entries()].map(([k, r]) => [k, `${r.state ?? "<none>"}|${r.headline}`]);
  const unique = new Set(fingerprints.map(([, f]) => f));
  assert.equal(unique.size, 6, `two states render the same page: ${JSON.stringify(fingerprints)}`);

  // ⚠️ AND THE ADVICE HAS TO DIFFER WHERE THE ACTION DIFFERS. Exactly one of the
  // six — the rate limit — is fixed by waiting. If a second one starts telling a
  // visitor to wait, that is the conflation this wording exists to prevent,
  // arriving from a direction no single-state test would see.
  const waitable = [...seen.entries()].filter(([, r]) => advisesWaiting(`${r.headline} ${r.body}`));
  assert.deepEqual(
    waitable.map(([k]) => k),
    ["429"],
    `these states tell the visitor to wait: ${JSON.stringify(waitable.map(([k, r]) => [k, r.body]))}`,
  );
});

after(() => {
  // Printed so the report of "what a visitor sees" is read off the run rather
  // than off the source.
  for (const [k, r] of seen) {
    console.log(`[${k}] state=${r.state ?? "<success>"} headline=${JSON.stringify(r.headline || r.liveName)}`);
  }
});
