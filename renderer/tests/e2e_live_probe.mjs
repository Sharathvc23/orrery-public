/**
 * Live end-to-end probe (issue acceptance): against a REAL running
 * stack — `docker compose up` with zero LLM key — prove that
 *
 *   1. the deterministic one-shot surface fetch renders (BYOK degradation),
 *   2. the AG-UI stream delivers a snapshot that this renderer paints to a
 *      non-trivial DOM tree,
 *
 * using the exact same modules the browser page loads (envelope → session →
 * renderer), with the recording stub standing in for the browser DOM.
 *
 * Usage: node renderer/tests/e2e_live_probe.mjs [base-url] [page]
 *        defaults: http://localhost:7000 digest
 */

import process from "node:process";

import { normalizeEnvelope } from "../src/envelope.js";
import { SurfaceRenderer } from "../src/render.js";
import { AgUiSession } from "../src/stream.js";
import { allText, StubDocument } from "./stubdom.mjs";

const base = (process.argv[2] || "http://localhost:7000").replace(/\/+$/, "");
const page = process.argv[3] || "digest";

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

function paint(normalized) {
  const doc = new StubDocument();
  const renderer = new SurfaceRenderer({ document: doc, onWarn: () => {} });
  const root = renderer.render(normalized);
  return { elements: doc.created.length, text: allText(root).trim() };
}

// ── 1. deterministic one-shot ──────────────────────────────────────
const resp = await fetch(`${base}/api/surfaces/${page}`, { headers: { accept: "application/json" } });
if (!resp.ok) fail(`GET /api/surfaces/${page} → HTTP ${resp.status}`);
const oneShot = normalizeEnvelope(await resp.json());
if (!oneShot.ok) fail(`one-shot envelope rejected: ${oneShot.reason} ${oneShot.detail}`);
const staticRender = paint(oneShot);
if (staticRender.elements < 4 || !staticRender.text) fail("one-shot render is empty");
console.log(`one-shot OK: "${page}" A2UI ${oneShot.version}, ${oneShot.components.size} components, ${staticRender.elements} elements`);

// ── 2. AG-UI stream snapshot ───────────────────────────────────────
const painted = [];
const statuses = [];
const session = new AgUiSession({
  onSurface: (n) => painted.push(n),
  onStatus: (state, detail) => statuses.push(`${state}:${detail}`),
});

const ac = new AbortController();
const timer = setTimeout(() => ac.abort(), 30000);
let streamResp;
try {
  streamResp = await fetch(`${base}/api/surfaces/${page}/stream?max_iterations=2&interval_seconds=1`, {
    headers: { accept: "text/event-stream" },
    signal: ac.signal,
  });
  if (!streamResp.ok) fail(`stream → HTTP ${streamResp.status}`);
  const reader = streamResp.body.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!session.feed(decoder.decode(value, { stream: true }))) fail(`session demanded resync: ${statuses.join(" | ")}`);
    if (statuses.some((s) => s.startsWith("finished"))) break;
  }
} catch (e) {
  if (!statuses.some((s) => s.startsWith("finished"))) fail(`stream transport error: ${e.message} (statuses: ${statuses.join(" | ")})`);
} finally {
  clearTimeout(timer);
  ac.abort();
}

if (painted.length < 1) fail(`no snapshot painted (statuses: ${statuses.join(" | ")})`);
const live = paint(painted[painted.length - 1]);
if (live.elements < 4 || !live.text) fail("live render is empty");
console.log(`stream OK: ${painted.length} paint(s), last render ${live.elements} elements, statuses: ${statuses.join(" | ")}`);
console.log(`PASS: end-to-end surface render with zero LLM key (${base}, page "${page}")`);
