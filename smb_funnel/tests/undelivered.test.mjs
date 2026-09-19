/**
 * A REQUEST THAT NEVER REACHED A SERVER MUST NOT RENDER AS A SERVER'S ANSWER.
 *
 * ⚠️ THE FAILURE THIS EXISTS FOR. `fetch` rejects with a `TypeError` carrying no
 * status when the browser stops a request, so `err.status` was `undefined` — and
 * `buildProvisionError`'s table, which asks only what the server said, fell
 * through every branch into "Couldn't create your agent. Please try again."
 * Measured in a real Chromium against a real `smb_funnel`/`smb_signup` pair with
 * the rate limit already spent: a cross-origin page was shown that sentence for
 * a 429 whose request never left the browser, and 507, 401 and 201 were equally
 * invisible to it. The page reported a verdict on an exchange that did not
 * happen, and told the visitor to retry something that could never succeed.
 *
 * So this drives the REAL app against an address nothing is listening on — a
 * genuine transport failure, not a stubbed rejection — and asserts what the page
 * says. The page origin differs from the configured API base, which is the shape
 * a public visitor's browser is in when `API_BASE` points at a front door that
 * grants no cross-origin access.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED: that the cause was CORS. Page script cannot
 * tell a refused preflight from a dead host from a dropped connection — they are
 * the same object — so a page claiming any one of them would be guessing. It
 * asserts what is knowable: nothing was received, and this page is configured to
 * call another origin.
 *
 * Classification: REGRESSION (the invisible-status defect) + WIRING.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { fire, installDocument } from "./funneldom.mjs";

// Nothing listens here, so the real `fetch` fails at the transport — the same
// place a browser's own rule stops a request, and the same empty-handed error
// page script is given for either.
const DEAD_BASE = "http://127.0.0.1:1";
// A DIFFERENT origin from DEAD_BASE, so the page's own configuration check sees
// what a separately-served funnel sees.
const PAGE_ORIGIN = "http://localhost:8700";

globalThis.localStorage = {
  getItem: (k) => (k === "smb_funnel.api_base" ? DEAD_BASE : null),
  setItem() {},
  removeItem() {},
};
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.location = { search: "", pathname: "/index.html", hash: "", origin: PAGE_ORIGIN };
globalThis.history = { replaceState() {} };

test("a request that never reached the service is not rendered as the service's answer", async () => {
  const doc = installDocument();
  await import("../src/app.js?undelivered=cross-origin");
  doc.querySelector("#business-name").value = "Unreachable Cuts";
  doc.querySelector("#contact").value = "https://bookings.example/hook";
  doc.querySelector("#service-type").value = "Haircuts";
  await fire(doc, "#funnel-form", "submit");

  const box = doc.querySelector("#form-error");
  const pick = (cls) => doc.created.filter((el) => el.className === cls).pop();
  const headline = pick("err-headline")?.textContent ?? "";
  const body = pick("err-body")?.textContent ?? "";

  assert.equal(box.dataset.state, "not-delivered-config", `rendered ${box.dataset.state}`);
  // ⚠️ THE DEFECT IN ONE ASSERTION. `failed` is the catch-all for a status the
  // table has no row for; using it for NO status is what made every refusal the
  // front door can send look identical to a visitor.
  assert.notEqual(box.dataset.state, "failed");
  assert.match(headline, /cannot reach the service/i);
  assert.match(body, /never asked|nothing came back/i);
  assert.match(body, /cross-origin/i);
  // Advice that cannot work is the second half of the defect: a page origin the
  // service will never allow does not become allowed by resubmitting.
  assert.match(body, /Retrying will not change the answer/i);
});

test("the same failure on a same-origin page reads as transient, because there it is", async () => {
  // ⚠️ ONE MODULE INSTANCE PER PROCESS. `api.js` resolves the base URL and the
  // cross-origin fact ONCE at load and every re-import of `app.js` shares it, so
  // the second shape cannot be reached by driving the app again in this process.
  // It is asserted on the renderer directly, and the browser drive
  // (`scripts/browser_smb_funnel.py`, case E) is what asserts the cross-origin
  // path at the page against a real service.
  const { buildProvisionError } = await import("../src/render.js");
  const doc = installDocument();

  const near = buildProvisionError(doc, { unreachable: true, crossOrigin: false });
  assert.equal(near.state, "not-delivered");
  const nearBody = near.nodes.find((n) => n.className === "err-body").textContent;
  assert.match(nearBody, /no verdict here/i);
  assert.match(nearBody, /Try again in a moment/i);

  // And a status that DID arrive still routes by status, so adding the new
  // states did not swallow the table they sit in front of.
  assert.equal(buildProvisionError(doc, { status: 429 }).state, "rate-limited");
  assert.equal(buildProvisionError(doc, { status: 507 }).state, "at-capacity");
  assert.equal(buildProvisionError(doc, { status: 500 }).state, "failed");
  assert.equal(buildProvisionError(doc, { status: 401, hasToken: false }).state, "credential-missing");
});
