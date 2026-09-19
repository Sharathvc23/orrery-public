import assert from "node:assert/strict";
import test from "node:test";

import { normalizeEnvelope, SUPPORTED_VERSIONS } from "../src/envelope.js";

const V09 = {
  createSurface: { surfaceId: "today" },
  updateComponents: {
    surfaceId: "today",
    root: "root",
    components: [
      { id: "root", component: "Column", children: ["t"] },
      { id: "t", component: "Text", text: "hello", usageHint: "body" },
    ],
  },
  version: "0.9",
};

test("native v0.9 envelope normalizes", () => {
  const n = normalizeEnvelope(V09);
  assert.equal(n.ok, true);
  assert.equal(n.version, "0.9");
  assert.equal(n.surfaceId, "today");
  assert.equal(n.root, "root");
  assert.equal(n.components.size, 2);
});

test("v0.10 is accepted; supported set is exactly 0.8/0.9/0.10", () => {
  assert.deepEqual([...SUPPORTED_VERSIONS], ["0.8", "0.9", "0.10"]);
  const n = normalizeEnvelope({ ...V09, version: "0.10" });
  assert.equal(n.ok, true);
});

test("unknown version is rejected as unsupported_version — never guessed at", () => {
  for (const version of ["9.9", "1.0", "", undefined, 0.9]) {
    const n = normalizeEnvelope({ ...V09, version });
    assert.equal(n.ok, false);
    assert.equal(n.reason, "unsupported_version");
  }
});

test("updateSurface read-alias is accepted (older spec-doc example shape)", () => {
  const { updateComponents, ...rest } = V09;
  const n = normalizeEnvelope({ ...rest, updateSurface: updateComponents });
  assert.equal(n.ok, true);
  assert.equal(n.components.size, 2);
});

test("legacy v0.8 wire shape normalizes to the flat component model", () => {
  const n = normalizeEnvelope({
    beginRendering: { root: "r" },
    surfaceUpdate: {
      surfaceId: "s8",
      components: [
        { id: "r", Column: { children: ["x"] } },
        { id: "x", Text: { text: "legacy", usageHint: "body" } },
      ],
    },
    version: "0.8",
  });
  assert.equal(n.ok, true);
  assert.equal(n.version, "0.8");
  assert.equal(n.components.get("x").component, "Text");
  assert.equal(n.components.get("x").text, "legacy");
});

test("upstream {'error': ...} payload becomes a typed rejection (degradation path)", () => {
  const n = normalizeEnvelope({ error: "Chapter unreachable: boom" });
  assert.equal(n.ok, false);
  assert.equal(n.reason, "upstream_error");
  assert.match(n.detail, /unreachable/);
});

test("structurally broken payloads are rejected, not thrown on", () => {
  for (const payload of [null, [], "str", 7, { version: "0.9" }, { version: "0.9", updateComponents: { root: "r", components: "nope" } }]) {
    const n = normalizeEnvelope(payload);
    assert.equal(n.ok, false);
  }
});

test("missing root, unsafe root, and root-not-in-list are all malformed", () => {
  const base = (root, components) => ({ version: "0.9", updateComponents: { surfaceId: "s", root, components } });
  assert.equal(normalizeEnvelope(base(undefined, [{ id: "a", component: "Text", text: "x" }])).ok, false);
  assert.equal(normalizeEnvelope(base("__proto__", [{ id: "a", component: "Text", text: "x" }])).ok, false);
  assert.equal(normalizeEnvelope(base("ghost", [{ id: "a", component: "Text", text: "x" }])).ok, false);
});

test("duplicate ids: first declaration wins, warning emitted", () => {
  const n = normalizeEnvelope({
    version: "0.9",
    updateComponents: {
      surfaceId: "s",
      root: "a",
      components: [
        { id: "a", component: "Text", text: "first" },
        { id: "a", component: "Text", text: "second" },
      ],
    },
  });
  assert.equal(n.ok, true);
  assert.equal(n.components.get("a").text, "first");
  assert.ok(n.warnings.some((w) => w.includes("duplicate")));
});

test("component-count cap rejects a flooding envelope outright", () => {
  const components = [{ id: "root", component: "Column", children: [] }];
  for (let i = 0; i < 5001; i++) components.push({ id: `c${i}`, component: "Text", text: "x" });
  const n = normalizeEnvelope({ version: "0.9", updateComponents: { surfaceId: "s", root: "root", components } });
  assert.equal(n.ok, false);
  assert.equal(n.reason, "malformed");
});
