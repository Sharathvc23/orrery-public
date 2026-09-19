/**
 * Static source audit: the renderer must have NO code path that can parse
 * surface data as HTML or evaluate it as code. This is the belt to the
 * stub-DOM braces — if a future change introduces one of these sinks, this
 * fails even for code paths the behavioral tests didn't reach.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const SRC = new URL("../src/", import.meta.url).pathname;

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

test("no HTML/eval sink appears anywhere in renderer source", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the renderer modules under src/, found ${files.length}`);
  for (const file of files) {
    const source = readFileSync(join(SRC, file), "utf8");
    for (const re of FORBIDDEN) {
      assert.ok(!re.test(source), `${file} contains forbidden sink ${re}`);
    }
  }
});

test("only the painting modules touch the DOM at all", () => {
  // render.js and app.js paint; everything else is pure
  // protocol/sanitization logic and must stay DOM-free.
  for (const file of ["envelope.js", "patch.js", "sanitize.js", "stream.js"]) {
    const source = readFileSync(join(SRC, file), "utf8");
    assert.ok(!/createElement|appendChild|textContent/.test(source), `${file} should be DOM-free`);
  }
});
