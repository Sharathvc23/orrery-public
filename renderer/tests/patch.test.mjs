import assert from "node:assert/strict";
import test from "node:test";

import { applyDelta, parsePointer, validateDelta } from "../src/patch.js";

const doc = () => ({
  version: "0.9",
  updateComponents: {
    surfaceId: "s",
    root: "root",
    components: [
      { id: "root", component: "Column", children: ["t"] },
      { id: "t", component: "Text", text: "old" },
    ],
  },
});

test("RFC 6901 pointer parsing incl. ~0/~1 escapes", () => {
  assert.deepEqual(parsePointer(""), []);
  assert.deepEqual(parsePointer("/a/0/b"), ["a", "0", "b"]);
  assert.deepEqual(parsePointer("/a~1b/c~0d"), ["a/b", "c~d"]);
  assert.equal(parsePointer("a/b"), null);
  assert.equal(parsePointer(42), null);
});

test("whole-document replace (the shape agui_streaming.diff_surfaces emits)", () => {
  const next = doc();
  next.updateComponents.components[1].text = "new";
  const r = applyDelta(doc(), [{ op: "replace", path: "", value: next }]);
  assert.equal(r.ok, true);
  assert.equal(r.doc.updateComponents.components[1].text, "new");
});

test("targeted add/replace/remove ops apply; '-' appends", () => {
  const r = applyDelta(doc(), [
    { op: "replace", path: "/updateComponents/components/1/text", value: "patched" },
    { op: "add", path: "/updateComponents/components/-", value: { id: "n", component: "Text", text: "appended" } },
    { op: "add", path: "/updateComponents/components/0/children/-", value: "n" },
  ]);
  assert.equal(r.ok, true);
  assert.equal(r.doc.updateComponents.components[1].text, "patched");
  assert.equal(r.doc.updateComponents.components[2].id, "n");
  assert.deepEqual(r.doc.updateComponents.components[0].children, ["t", "n"]);
});

test("malformed deltas are rejected by shape validation alone", () => {
  for (const delta of [
    "nope",
    { op: "replace", path: "", value: 1 }, // not an array
    [{ op: "move", from: "/a", path: "/b" }], // unsupported op
    [{ op: "replace", path: "no-slash", value: 1 }],
    [{ op: "add", path: "/a" }], // missing value
    [{ op: "remove", path: "" }], // cannot remove whole doc
    [{ op: "replace", path: 3, value: 1 }],
    [null],
  ]) {
    const v = validateDelta(delta);
    assert.equal(v.ok, false, `expected rejection: ${JSON.stringify(delta)}`);
  }
});

test("prototype-plumbing paths are rejected", () => {
  for (const path of ["/__proto__/x", "/updateComponents/constructor/y", "/prototype"]) {
    assert.equal(validateDelta([{ op: "add", path, value: 1 }]).ok, false, path);
  }
  assert.equal(Object.prototype.x, undefined);
});

test("rejection is ATOMIC: a failing later op leaves the input untouched and applies nothing", () => {
  const original = doc();
  const snapshotBefore = JSON.stringify(original);
  const r = applyDelta(original, [
    { op: "replace", path: "/updateComponents/components/1/text", value: "half-applied" },
    { op: "replace", path: "/updateComponents/components/99/text", value: "boom" },
  ]);
  assert.equal(r.ok, false);
  assert.equal(JSON.stringify(original), snapshotBefore, "input document was mutated by a rejected delta");
});

test("apply is pure: a successful delta never mutates the input document", () => {
  const original = doc();
  const before = JSON.stringify(original);
  const r = applyDelta(original, [{ op: "replace", path: "/updateComponents/components/1/text", value: "new" }]);
  assert.equal(r.ok, true);
  assert.equal(JSON.stringify(original), before);
});

test("out-of-bounds and missing-key targets fail cleanly", () => {
  assert.equal(applyDelta(doc(), [{ op: "replace", path: "/nope/x", value: 1 }]).ok, false);
  assert.equal(applyDelta(doc(), [{ op: "remove", path: "/updateComponents/components/9" }]).ok, false);
  assert.equal(applyDelta(doc(), [{ op: "add", path: "/updateComponents/components/99", value: {} }]).ok, false);
  assert.equal(applyDelta(doc(), [{ op: "replace", path: "/updateComponents/ghost", value: 1 }]).ok, false);
});
