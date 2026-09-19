/**
 * Injection acceptance test (issue): the hostile fixture — script tags,
 * handler attributes, javascript:/data: URLs, class-token breakouts, cycles,
 * prototype pollution — must render INERT: text stays text, no executable
 * sink is ever produced, and the renderer neither crashes nor hangs.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { normalizeEnvelope } from "../src/envelope.js";
import { SurfaceRenderer } from "../src/render.js";
import { allText, StubDocument, walk } from "./stubdom.mjs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/hostile-surface.json", import.meta.url), "utf8"));

function renderFixture() {
  const doc = new StubDocument();
  const warnings = [];
  const normalized = normalizeEnvelope(fixture);
  assert.equal(normalized.ok, true, "hostile-but-well-formed envelope must still normalize");
  const renderer = new SurfaceRenderer({ document: doc, onWarn: (w) => warnings.push(w) });
  const root = renderer.render(normalized);
  return { doc, root, warnings, normalized };
}

test("hostile fixture renders without crashing, with warnings, not exceptions", () => {
  const { warnings } = renderFixture();
  assert.ok(warnings.length >= 4, `expected warnings for cycle/dangling/unknown/dup, got: ${warnings.join(" | ")}`);
});

test("no script/iframe/object element is ever created", () => {
  const { doc } = renderFixture();
  const tags = new Set(doc.created.map((el) => el.tagName));
  for (const banned of ["script", "iframe", "object", "embed", "frame", "svg"]) {
    assert.ok(!tags.has(banned), `renderer created a <${banned}> element`);
  }
});

test("markup in surface text lands ONLY in text nodes, never parsed", () => {
  const { doc, root } = renderFixture();
  // The payload strings must be reachable as literal text…
  const text = allText(root);
  assert.ok(text.includes("<script>window.__pwned=1</script>"), "script markup should paint as literal text");
  assert.ok(text.includes('<img src=x onerror="window.__pwned=2">'), "img markup should paint as literal text");
  // …and the stub throws on innerHTML/insertAdjacentHTML, so reaching here
  // proves no HTML parser was invoked. Belt: every attribute the renderer
  // sets has a name from this fixed list (setAttribute never parses values,
  // so markup is inert there — but a surface-controlled attribute NAME
  // would be a real sink), and markup only ever lands in the free-text
  // attributes where it stays data.
  const ALLOWED_ATTRS = new Set([
    "href", "src", "rel", "target", "type", "name", "rows", "width", "height",
    "loading", "selected", "checked", "open", "data-a2ui-id", "data-a2ui-surface",
    "data-language", "role", "aria-valuenow", "placeholder", "value", "alt",
  ]);
  const FREE_TEXT_ATTRS = new Set(["placeholder", "value", "alt"]);
  for (const { name, value } of doc.attributesSet) {
    assert.ok(ALLOWED_ATTRS.has(name), `unexpected attribute name set: ${name}`);
    if (!FREE_TEXT_ATTRS.has(name)) {
      assert.ok(!/[<>]/.test(value), `attribute ${name} carries markup: ${value}`);
    }
  }
});

test("no event-handler attribute is ever set (stub throws, plus audit)", () => {
  const { doc } = renderFixture();
  for (const { name } of doc.attributesSet) {
    assert.ok(!/^on/i.test(name), `handler attribute set: ${name}`);
  }
});

test("javascript:/data:text/html/vbscript URLs are all defanged", () => {
  const { doc } = renderFixture();
  for (const el of doc.created) {
    const href = el.attributes.href;
    const src = el.attributes.src;
    for (const url of [href, src]) {
      if (url === undefined) continue;
      const flat = url.toLowerCase().replace(/[\s\u0000-\u0020]/g, "");
      assert.ok(!flat.startsWith("javascript:"), `live javascript: URL survived: ${url}`);
      assert.ok(!flat.startsWith("vbscript:"), `live vbscript: URL survived: ${url}`);
      assert.ok(!flat.startsWith("data:text"), `data:text URL survived: ${url}`);
    }
  }
  // The hostile links must still exist — visibly blocked, not silently gone.
  const anchors = doc.created.filter((el) => el.tagName === "a");
  assert.ok(anchors.some((a) => a.attributes.href === "about:blank#blocked"), "blocked links should point at the inert placeholder");
  // And every anchor is opener-safe.
  for (const a of anchors) {
    assert.match(a.attributes.rel ?? "", /noopener/, "anchor missing rel=noopener");
  }
});

test("class tokens cannot be broken out of via variant/usageHint/tier", () => {
  const { doc } = renderFixture();
  for (const el of doc.created) {
    assert.ok(!/[<>"']/.test(el.className), `raw surface data reached className: ${el.className}`);
  }
});

test("hostile ids: __proto__ dropped, Object.prototype not polluted", () => {
  const { normalized } = renderFixture();
  assert.equal(normalized.components.has("__proto__"), false, "__proto__ id must be dropped at normalize time");
  assert.equal({}.polluted, undefined, "Object.prototype was polluted");
  assert.equal(Object.prototype.polluted, undefined, "Object.prototype was polluted");
});

test("cycles terminate with a placeholder; dangling refs and unknown components are inert", () => {
  const { root, warnings } = renderFixture();
  const text = allText(root);
  assert.ok(text.includes("[cycle detected]"), "cycle placeholder missing");
  assert.ok(text.includes("[missing component]"), "dangling-ref placeholder missing");
  assert.ok(text.includes("[unsupported component: WebView]"), "unknown-component placeholder missing");
  assert.ok(warnings.some((w) => w.includes("duplicate component id")), "duplicate id should warn");
  // The unknown component's payload (a WebView pointing at evil.example)
  // must not produce any element with that URL.
  for (const el of walk(root)) {
    assert.notEqual(el.attributes?.src, "https://evil.example");
  }
});

test("markdown: raw HTML is literal text, hostile link defanged, benign formatting still works", () => {
  const { doc, root } = renderFixture();
  const text = allText(root);
  assert.ok(text.includes('<iframe src="https://evil.example"></iframe>'), "markdown HTML must stay literal");
  const anchors = doc.created.filter((el) => el.tagName === "a");
  const mdBlocked = anchors.filter((a) => a.textContent === "click me");
  assert.equal(mdBlocked.length, 1);
  assert.equal(mdBlocked[0].attributes.href, "about:blank#blocked");
  const mdOk = anchors.filter((a) => a.textContent === "ok");
  assert.equal(mdOk[0].attributes.href, "https://example.com/x");
  assert.ok(doc.created.some((el) => el.tagName === "strong" && el.textContent === "bold"), "benign markdown bold should render");
});

test("input type/attribute smuggling is neutralized", () => {
  const { doc } = renderFixture();
  const inputs = doc.created.filter((el) => el.tagName === "input");
  for (const input of inputs) {
    assert.match(input.attributes.type, /^(text|checkbox)$/, `hostile inputType survived: ${input.attributes.type}`);
  }
});
