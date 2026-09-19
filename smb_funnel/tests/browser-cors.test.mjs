/**
 * THE BROWSER PATH, ASSERTED RATHER THAN INFERRED.
 *
 * ⚠️ THE FAILURE THIS EXISTS FOR. The gated host was unreachable from a browser
 * for a whole release: `CORSMiddleware`'s `allow_headers` omitted
 * `Authorization`, so the preflight for `POST /provision` was refused, the real
 * request never left the browser, and the page saw an opaque network failure
 * with a valid token exactly as it did without one. Every test in this tree
 * passed throughout, because node's `fetch` performs no preflight and enforces
 * no cross-origin rule — and the one preflight test that existed asked only for
 * `content-type`, the header that was never in question.
 *
 * So these drive the REAL app against a REAL host through `corsFetch`, which
 * applies the browser's rule at the moment the browser applies it: before the
 * request is sent. The positive case asserts the funnel reaches a real 201
 * FROM A CROSS-ORIGIN PAGE while carrying a bearer token. The negative case
 * makes a real, configuration-reachable CORS refusal happen and asserts what the
 * visitor is then told — which is the second half of the defect, and the half a
 * header-only assertion cannot reach.
 *
 * Classification: REGRESSION (the release-long browser outage) + WIRING.
 */

import assert from "node:assert/strict";
import test, { before } from "node:test";

import { corsFetch } from "./corsfetch.mjs";
import { fire, installDocument } from "./funneldom.mjs";
import { bootHost, CORS_HOST_PORT, requireHost } from "./hostboot.mjs";

const TOKEN = "browser-cors-suite-token";
const CONTACT = "https://bookings.example/hook";
const BASE = `http://127.0.0.1:${CORS_HOST_PORT}`;
// Where the funnel is actually served from in the documented local setup
// (`npm run serve`). A DIFFERENT origin from the host — which is the only
// reason any of this applies.
const PAGE_ORIGIN = "http://localhost:8700";

globalThis.localStorage = {
  getItem: (k) => (k === "smb_funnel.api_base" ? BASE : null),
  setItem() {},
  removeItem() {},
};

before(requireHost);

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

/** Drive the real app from a cross-origin page, under the browser's CORS rule. */
async function visitFromBrowser(caseName, { search = "", name = "Crossorigin Cuts" } = {}) {
  const blocked = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = corsFetch(PAGE_ORIGIN, { blocked });
  try {
    newTab(search);
    const doc = installDocument();
    await import(`../src/app.js?browser-cors=${caseName}`);
    doc.querySelector("#business-name").value = name;
    doc.querySelector("#contact").value = CONTACT;
    doc.querySelector("#service-type").value = "Haircuts";
    await fire(doc, "#funnel-form", "submit");

    const box = doc.querySelector("#form-error");
    const pick = (cls) => doc.created.filter((el) => el.className === cls).pop();
    return {
      doc,
      blocked,
      state: box.dataset.state,
      headline: pick("err-headline")?.textContent ?? "",
      body: pick("err-body")?.textContent ?? "",
      liveName: doc.querySelector("#live-name")?.textContent ?? "",
      did: (() => {
        const el = doc.querySelector("#did");
        return el ? el.value || el.textContent || "" : "";
      })(),
    };
  } finally {
    globalThis.fetch = realFetch;
  }
}

// ── the positive: a bearer token survives the preflight ─────────────────────

test("a cross-origin page provisions with a bearer token, so the preflight allows Authorization", async () => {
  const host = await bootHost(
    {
      HOST_PUBLIC_URL: BASE,
      SMB_HOST_PROVISION_TOKEN: TOKEN,
      SMB_HOST_TENANT_CAP: "10",
      SMB_HOST_POOL_SIZE: "0",
    },
    CORS_HOST_PORT,
  );
  try {
    const r = await visitFromBrowser("allowed", { search: `?provision_token=${TOKEN}` });

    // ⚠️ ASSERTED AT THE PAGE, NOT AT A HEADER. Reading
    // `access-control-allow-headers` off a preflight and calling it proof is the
    // shape of the assertion that passed through the outage. This one is the
    // funnel completing a real provision from a real cross-origin page: the
    // preflight was sent, allowed, and the credentialed POST followed it.
    assert.deepEqual(r.blocked, [], `the browser rule stopped a request: ${JSON.stringify(r.blocked)}`);
    assert.equal(r.state, undefined, `provisioning failed from a browser: ${r.state} — ${r.headline}`);
    assert.equal(r.liveName, "Crossorigin Cuts");
    assert.match(r.did, /^did:key:z/);
  } finally {
    await host.stop();
  }
});

// ── the negative: a real refusal, and what the visitor is then told ──────────

test("when the preflight refuses the page's origin, the visitor sees a network failure and NOT a credential verdict", async () => {
  // A real, configuration-reachable CORS refusal: the host is pinned to an
  // allowlist this page is not on. No code is changed to produce it.
  const host = await bootHost(
    {
      HOST_PUBLIC_URL: BASE,
      SMB_HOST_PROVISION_TOKEN: TOKEN,
      SMB_HOST_TENANT_CAP: "10",
      SMB_HOST_POOL_SIZE: "0",
      SMB_HOST_CORS_ORIGINS: "https://somewhere-else.example",
    },
    CORS_HOST_PORT,
  );
  try {
    const r = await visitFromBrowser("origin-refused", { search: `?provision_token=${TOKEN}` });

    assert.equal(r.blocked.length, 1, "the browser rule did not stop the request it should have");
    // Starlette answers a disallowed origin's preflight 400 rather than 200
    // without the header, so THAT is what a browser sees here — recorded as
    // measured rather than as predicted, because the two differ and only the
    // measured one is what stops the request.
    assert.match(r.blocked[0].why, /the preflight was refused with 400/);

    // ⚠️ AND THIS IS THE DEFECT IN ONE ASSERTION. The host holds a token and
    // this browser has the RIGHT one, so a page that could reach it would be
    // provisioned. It cannot, so it must not render any verdict about the
    // credential — the request carrying it was never sent, and "your token was
    // rejected" would be a claim about an exchange that did not happen.
    //
    // The state asserted here is `not-delivered` and NOT the generic `failed`.
    // When this test was written the page had no way to say "the request never
    // left the browser", so a stopped request fell through the status table
    // into `failed` — which reads as "the server answered and we could not
    // classify it", itself a claim about an exchange that did not happen. The
    // undelivered states now say only what is knowable. What this test pins is
    // unchanged and is the property, not the label: whatever the page renders
    // for a request the browser stopped, it must not be a verdict about the
    // credential, and it must not be a live agent.
    assert.equal(
      r.state,
      "not-delivered",
      `a blocked request rendered ${r.state}, a verdict nothing established`,
    );
    assert.notEqual(r.state, "credential-rejected");
    assert.notEqual(r.state, "credential-missing");
    assert.notEqual(r.state, "failed");
    assert.equal(r.liveName, "", "a blocked request still rendered a live agent");
  } finally {
    await host.stop();
  }
});

// ── the shim is enforcing, not decorative ───────────────────────────────────

test("the browser rule this suite applies actually blocks a disallowed header", async () => {
  // ⚠️ A HARNESS THAT ENFORCES NOTHING WOULD MAKE BOTH TESTS ABOVE PASS FOREVER.
  // Driven against a server that allows the origin and the method and refuses
  // exactly the one header the outage was about, so the check being relied on is
  // shown to fire rather than assumed to.
  const { createServer } = await import("node:http");
  const server = createServer((req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        // Authorization deliberately absent — the omission that caused the outage.
        "Access-Control-Allow-Headers": "Content-Type, Accept",
      });
      return res.end();
    }
    res.writeHead(201, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({ tenant_id: "should-never-be-read" }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/provision`;
  try {
    const blocked = [];
    const f = corsFetch(PAGE_ORIGIN, { blocked });
    await assert.rejects(
      () =>
        f(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
          body: "{}",
        }),
      TypeError,
    );
    assert.equal(blocked.length, 1);
    assert.match(blocked[0].why, /did not allow the header\(s\).*authorization/i);
  } finally {
    server.close();
  }
});
