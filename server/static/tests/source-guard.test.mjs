/**
 * Static source audit for the org console UI.
 *
 * ⚠️ THE HALF THAT LASTS. `console.test.mjs` proves today's render path is safe;
 * this proves no FUTURE one is unsafe, including paths no behavioural test
 * reaches. Mirrors `renderer/tests/source-guard.test.mjs` and
 * `smb_funnel/tests/source-guard.test.mjs` deliberately.
 *
 * ⚠️ SCOPED TO `ui/` ON PURPOSE. The org's THREE OLDER static pages —
 * `admin/`, `receipts/`, `leaderboard/` — all build HTML from data and would
 * fail this. They are pre-existing and out of this PR's scope; the audit of
 * what they actually do is in the PR body. Widening this guard to cover them
 * without fixing them would just mean disabling it, and a disabled guard is
 * worse than a scoped one.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const UI = new URL("../ui/", import.meta.url).pathname;

const FORBIDDEN = [
  /\binnerHTML\b/,
  /\bouterHTML\b/,
  /insertAdjacentHTML/,
  /\bdocument\.write\b/,
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /setTimeout\s*\(\s*["'`]/,
  /setInterval\s*\(\s*["'`]/,
  /createContextualFragment/,
  /DOMParser/,
  /dangerouslySetInnerHTML/,
  /srcdoc/,
];

/** Strip comments, leaving string and template literals intact, so the modules
 *  can name the banned sinks in prose without tripping the ban. */
function stripComments(source) {
  let out = "";
  let i = 0;
  let state = "code";
  let quote = "";
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (state === "code") {
      if (c === "/" && next === "/") { state = "line"; i += 2; continue; }
      if (c === "/" && next === "*") { state = "block"; i += 2; continue; }
      if (c === '"' || c === "'" || c === "`") { state = "string"; quote = c; out += c; i += 1; continue; }
      out += c;
      i += 1;
    } else if (state === "string") {
      if (c === "\\") { out += c + (next ?? ""); i += 2; continue; }
      if (c === quote) state = "code";
      out += c;
      i += 1;
    } else if (state === "line") {
      if (c === "\n") { state = "code"; out += c; }
      i += 1;
    } else {
      if (c === "*" && next === "/") { state = "code"; i += 2; continue; }
      i += 1;
    }
  }
  return out;
}

test("stripComments keeps code and strings, drops only comments", () => {
  // Pinned, so the guard below cannot pass vacuously by eating everything.
  assert.equal(stripComments("const a = 1; // innerHTML\n").trim(), "const a = 1;");
  assert.equal(stripComments("/* innerHTML */ const b = 2;").trim(), "const b = 2;");
  assert.ok(stripComments('const u = "https://x/y";').includes("https://x/y"));
  assert.ok(/\binnerHTML\b/.test(stripComments('el.innerHTML = "x"; // fine')));
});

test("no HTML or eval sink appears anywhere in the console UI source", () => {
  const files = readdirSync(UI).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 4, `expected the ui modules, found ${files.length}`);
  for (const file of files) {
    const source = stripComments(readFileSync(join(UI, file), "utf8"));
    for (const re of FORBIDDEN) {
      assert.ok(!re.test(source), `${file} contains forbidden sink ${re}`);
    }
  }
});

test("no escapeHtml — a live escaper invites the string-building style back", () => {
  for (const file of readdirSync(UI).filter((f) => f.endsWith(".js"))) {
    const source = stripComments(readFileSync(join(UI, file), "utf8"));
    assert.ok(!/function\s+escapeHtml/.test(source), `${file} defines escapeHtml`);
  }
});

test("the pure render modules touch no globals, so node can drive them", () => {
  /** console.js and join.js must stay importable under a stub DOM. A `document`
   * or `fetch` reference at module scope is what made smb_funnel's app.js
   * untestable until the boot-module split split it — the boot modules own that. */
  for (const file of ["console.js", "join.js", "dom.js"]) {
    const source = stripComments(readFileSync(join(UI, file), "utf8"));
    assert.ok(!/\bdocument\./.test(source), `${file} reaches for the global document`);
    assert.ok(!/\bfetch\s*\(/.test(source), `${file} performs I/O`);
    assert.ok(!/\blocation\./.test(source), `${file} reads location`);
  }
});

test("the console asks the model for nothing — it must work with no LLM key", () => {
  /** ⚠️ A keyless install currently busy-loops against xAI, measured.
   * An operator's window into the org must not be the thing that goes dark when
   * inference is unavailable, so nothing here may reach an inference path. */
  for (const file of readdirSync(UI).filter((f) => f.endsWith(".js"))) {
    const source = stripComments(readFileSync(join(UI, file), "utf8"));
    for (const re of [/\bllm\b/i, /openai/i, /anthropic/i, /\bxai\b/i, /\/api\/(compose|intent)\b/]) {
      assert.ok(!re.test(source), `${file} reaches an inference path (${re})`);
    }
  }
});
