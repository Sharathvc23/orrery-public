/**
 * Portal UI e2e — real Chromium over the reference renderer against a REAL
 * running org (no mocks, no fixtures): every wired surface page must reach a
 * correct terminal UI state, the AG-UI stream must go live, gated surfaces
 * must show a readable auth state cross-origin, and the newer keyless reads
 * (federation divergence, conformance badge) must be browser-consumable.
 *
 * Inputs (all environment, nothing hardcoded):
 *   ORG_URL           the org under test           (default http://localhost:7000)
 *   RENDERER_URL      where index.html is served   (default http://localhost:8600)
 *   SURFACE_CONTRACT  path to gen_contract.py output; defaults to invoking
 *                     the generator against this repo checkout at run time,
 *                     so the tested page list always matches the server code
 *                     the stack was built from.
 *
 * Run: node --test renderer/tests/e2e/*.e2e.mjs   (CI: e2e job, after compose is healthy)
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";

import { chromium } from "playwright";

const ORG_URL = (process.env.ORG_URL || "http://localhost:7000").replace(/\/+$/, "");
const RENDERER_URL = (process.env.RENDERER_URL || "http://localhost:8600").replace(/\/+$/, "");

function loadContract() {
  if (process.env.SURFACE_CONTRACT) {
    return JSON.parse(readFileSync(process.env.SURFACE_CONTRACT, "utf8"));
  }
  const script = new URL("./gen_contract.py", import.meta.url).pathname;
  return JSON.parse(execFileSync("python3", [script], { encoding: "utf8" }));
}

const contract = loadContract();
const GATED = new Set(contract.gated);
assert.ok(contract.pages.length > 0, "surface contract is empty");

let browser;
let page;
const corsErrors = [];

before(async () => {
  browser = await chromium.launch();
  page = await browser.newPage();
  page.on("console", (m) => {
    if (m.type() === "error" && /CORS|Cross-Origin/.test(m.text())) corsErrors.push(m.text());
  });
});

after(async () => {
  await browser?.close();
});

/** Load the renderer fresh, point it at the org, fetch one page, and return
 * the terminal state: either a painted surface or an explicit note. */
async function fetchSurface(pageId) {
  await page.goto(`${RENDERER_URL}/`, { waitUntil: "networkidle" });
  await page.fill("#base-url", ORG_URL);
  await page.fill("#page-id", pageId);
  // Clear the initial "Not connected" note so the wait below can't match it.
  await page.evaluate(() => document.getElementById("surface-root").replaceChildren());
  await page.click("#fetch-once");
  await page.waitForSelector("#surface-root [data-a2ui-id], #surface-root .render-note", { timeout: 30000 });
  return page.evaluate(() => {
    const components = document.querySelectorAll("#surface-root [data-a2ui-id]").length;
    const note = document.querySelector("#surface-root .render-note");
    return {
      components,
      text: document.getElementById("surface-root").textContent.trim(),
      noteTitle: note?.querySelector(".a2ui-alert-title")?.textContent ?? null,
      noteBody: note?.querySelector(".a2ui-alert-message")?.textContent ?? null,
      status: document.getElementById("status").textContent,
    };
  });
}

// ── every wired page reaches a correct terminal state ──────────────

for (const pageId of contract.pages) {
  test(`surface "${pageId}" ${GATED.has(pageId) ? "shows a readable auth-required state" : "paints"}`, async () => {
    const r = await fetchSurface(pageId);
    if (GATED.has(pageId)) {
      assert.equal(r.noteTitle, "Surface not available", `expected the gated note, got: ${JSON.stringify(r)}`);
      assert.match(r.noteBody ?? "", /Authentication required/, "the 401 body must be readable cross-origin");
    } else {
      assert.ok(r.components >= 1, `no components painted: ${JSON.stringify(r)}`);
      assert.ok(r.text.length > 0, "painted surface has no text");
      assert.equal(r.noteTitle, null, `open page degraded to a note: ${r.noteTitle} — ${r.noteBody}`);
      assert.match(r.status, new RegExp(`"${pageId}"`), "status line should name the rendered page");
    }
  });
}

// ── live path: the AG-UI stream goes live and paints ────────────────

test("dashboard streams live over AG-UI SSE", async () => {
  await page.goto(`${RENDERER_URL}/`, { waitUntil: "networkidle" });
  await page.fill("#base-url", ORG_URL);
  await page.fill("#page-id", "dashboard");
  await page.click("#connect");
  await page.waitForSelector("#surface-root [data-a2ui-id]", { timeout: 30000 });
  await page.waitForFunction(() => document.getElementById("status").getAttribute("data-state") === "live", null, {
    timeout: 30000,
  });
  const components = await page.locator("#surface-root [data-a2ui-id]").count();
  assert.ok(components >= 1, "live stream painted nothing");
  await page.click("#disconnect");
});

// ── That change regression: pills in column-flex contexts stay content-width ──

test("badges inside Columns are content-width, not stretched", async () => {
  await fetchSurface("dashboard");
  const report = await page.evaluate(() => {
    const out = [];
    for (const el of document.querySelectorAll(
      ".a2ui-column > .a2ui-badge, .a2ui-column > .a2ui-chip, .a2ui-column > .a2ui-trustbadge",
    )) {
      out.push({ own: el.getBoundingClientRect().width, parent: el.parentElement.getBoundingClientRect().width });
    }
    return out;
  });
  // A fresh org may render no column-pills; only assert when they exist.
  for (const r of report) {
    assert.ok(r.own < r.parent - 2, `pill stretched to parent width (${r.own} vs ${r.parent})`);
  }
});

// ── the one control the banner tells a stranger to use ─────────────
//
// `./orrery-up` ends by sending the reader to the dashboard, whose only
// interactive element is the "What Do You Need?" form. Every other assertion
// in this file is a READ; this one is the write a first-time user actually
// performs. It drove a real defect out: the renderer submits a Form's values
// keyed by each Input's component id (A2UI gives an Input no name of its own)
// while the handler read a second spelling, so a filled-in field answered
// "Missing Intent" and no row was written. The assertion is on what lands —
// the dashboard's active-intent count, read back through the same surface —
// not on the response envelope alone, because the envelope is what lied.

async function activeIntentCount() {
  await fetchSurface("dashboard");
  return page.evaluate(() => {
    const label = document.querySelector('#surface-root [data-a2ui-id="dash-intents-label"]');
    const m = label?.textContent.match(/^(\d+) Active Intents?/);
    return m ? Number(m[1]) : 0;
  });
}

test("the dashboard intent form submits through the shipped renderer and the intent lands", async () => {
  const before = await activeIntentCount();
  const need = `e2e: someone who can review a Python package (${Date.now()})`;

  await fetchSurface("dashboard");
  const form = page.locator('#surface-root [data-a2ui-id="dash-intent-form"]');
  await form.locator("input").first().fill(need);
  const [request, response] = await Promise.all([
    page.waitForRequest((r) => r.url().endsWith("/api/surfaces/action") && r.method() === "POST"),
    page.waitForResponse((r) => r.url().endsWith("/api/surfaces/action")),
    form.locator('button[type="submit"]').click(),
  ]);
  // What the renderer put on the wire: the Form's children by component id.
  const posted = request.postDataJSON();
  assert.equal(posted.action, "submit_intent");
  assert.equal(posted.values["dash-intent-input"], need, "the typed need was not submitted under the input's id");
  assert.equal(response.status(), 200);

  // What the org painted back — and it must not be the refusal.
  await page.waitForSelector(".action-result [data-a2ui-id]", { timeout: 30000 });
  const painted = await page.evaluate(() => document.querySelector(".action-result").textContent.replace(/\s+/g, " "));
  assert.doesNotMatch(painted, /Missing Intent/, `the org refused a filled-in field: ${painted}`);
  assert.match(painted, /Intent Matched/, `unexpected action result: ${painted}`);

  // What the DB holds after, read back through the dashboard itself. The
  // dashboard surface is memoised for surface_cache.DEFAULT_TTL_SECONDS (10s),
  // so the new row shows up on the next rebuild, not the next request.
  let after = before;
  for (const deadline = Date.now() + 30000; after === before && Date.now() < deadline; ) {
    await page.waitForTimeout(1000);
    after = await activeIntentCount();
  }
  assert.equal(after, before + 1, `active intents went ${before} → ${after}; the submission did not land`);
  const listed = await page.evaluate(() => document.getElementById("surface-root").textContent);
  assert.ok(listed.includes(need.slice(0, 100)), "the new intent is not listed on the dashboard");
});

// ── newer keyless reads are browser-consumable cross-origin ────────

test("GET /api/federation/divergence is 200, JSON, and readable cross-origin", async () => {
  await page.goto(`${RENDERER_URL}/`, { waitUntil: "networkidle" });
  const r = await page.evaluate(async (org) => {
    const resp = await fetch(`${org}/api/federation/divergence`);
    return { status: resp.status, body: await resp.json() };
  }, ORG_URL);
  assert.equal(r.status, 200);
  assert.ok(Array.isArray(r.body.findings), "divergence body missing findings[]");
});

test("conformance badge serves and has a verifiable envelope shape", async () => {
  await page.goto(`${RENDERER_URL}/`, { waitUntil: "networkidle" });
  const badge = await page.evaluate(async (org) => (await fetch(`${org}/.well-known/conformance.json`)).json(), ORG_URL);
  assert.equal(typeof badge.signature, "string");
  assert.match(badge.signed_by ?? "", /^did:key:z/, "badge must be signed by a did:key");
  assert.equal(badge.payload.failed, 0, "org booted with failing conformance vectors");
  assert.ok(badge.payload.passed >= 1);
});

test("/health provenance is a real commit, not 'unknown'", async () => {
  await page.goto(`${RENDERER_URL}/`, { waitUntil: "networkidle" });
  const health = await page.evaluate(async (org) => (await fetch(`${org}/health`)).json(), ORG_URL);
  assert.match(health.git_commit ?? "", /^[0-9a-f]{7,40}$/, `git_commit is "${health.git_commit}"`);
});

// ── the whole run stayed CORS-clean ────────────────────────────────

test("zero CORS console errors across the entire run", () => {
  assert.deepEqual(corsErrors, []);
});
