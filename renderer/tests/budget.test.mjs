/**
 * The render budget: the third bound on the reference walk.
 *
 * The graph these tests use is neither cyclic nor deep. `renderRef` copies
 * `pathIds` at each level, so the cycle guard refuses a component only when it
 * appears on its own ancestor chain, and a component that references the next
 * one twice is acyclic. Depth stays under MAX_DEPTH, children under
 * MAX_CHILDREN, and the component count under MAX_COMPONENTS, while the painted
 * node count doubles at every level.
 *
 * Measured against render.js before the budget was added:
 *
 *     components  envelope_bytes   wall_ms   nodes_painted
 *              9            619          3             511
 *             13            852         64           8,191
 *             17           1088        504         131,071
 *             19           1206       2147         524,287
 *             20           1265       4767       1,048,575
 *             21           1324       ——        heap exhausted at 2 GB after 31 s
 *
 * The surface may come from any A2UI endpoint the renderer is pointed at,
 * including a remote org's.
 *
 * The last test disables the budget on one renderer instance, asserts the same
 * envelope expands without it, and restores it.
 *
 * Classification: ADVERSARIAL (security control).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { normalizeEnvelope } from "../src/envelope.js";
import { MAX_RENDERED_COMPONENTS, SurfaceRenderer } from "../src/render.js";
import { StubDocument, allText } from "./stubdom.mjs";

/**
 * `depth` components in a chain, each naming the next one `fanout` times.
 * Acyclic. Without a budget this paints fanout^depth nodes.
 */
function fanoutEnvelope(depth, fanout = 2) {
  const components = [];
  for (let i = 0; i < depth; i++) {
    components.push({ id: `n${i}`, component: "Column", children: Array(fanout).fill(`n${i + 1}`) });
  }
  components.push({ id: `n${depth}`, component: "Text", text: "leaf" });
  return {
    createSurface: { surfaceId: "fanout" },
    updateComponents: { surfaceId: "fanout", root: "n0", components },
    version: "0.10",
  };
}

function paint(envelope, renderer) {
  const doc = new StubDocument();
  const warnings = [];
  const normalized = normalizeEnvelope(envelope);
  assert.equal(normalized.ok, true, "the envelope must normalize — the caps it exercises are downstream of that");
  const r = renderer || new SurfaceRenderer({ document: doc, onWarn: (w) => warnings.push(w) });
  if (renderer) renderer.doc = doc;
  const root = r.render(normalized);
  return { doc, root, warnings, renderer: r };
}

test("the expanding envelope is small, valid, and within every other cap", () => {
  /** The other caps bound envelope size, children per node and chain depth. None
   * of them bound total expansion, which is what the budget covers. */
  const env = fanoutEnvelope(20);
  assert.ok(JSON.stringify(env).length < 2000, "under 2 KB on the wire");
  assert.ok(env.updateComponents.components.length < 30, "well under MAX_COMPONENTS (5000)");
  for (const c of env.updateComponents.components) {
    assert.ok((c.children || []).length < 1000, "well under MAX_CHILDREN (1000)");
  }
  assert.equal(normalizeEnvelope(env).ok, true, "and envelope.js accepts it");
});

test("a fan-out graph terminates within budget", () => {
  const { doc, warnings } = paint(fanoutEnvelope(20));
  assert.ok(
    doc.created.length <= MAX_RENDERED_COMPONENTS * 4,
    `painted ${doc.created.length} elements — the walk was not bounded`,
  );
  assert.ok(
    warnings.some((w) => w.includes("render budget")),
    `truncation must be announced, got: ${warnings.join(" | ")}`,
  );
});

test("truncation is visible in the page rather than a silently shorter surface", () => {
  /** Matches the depth cap. A reader of a truncated surface can otherwise not
   * tell it from a complete one. */
  const { root } = paint(fanoutEnvelope(20));
  assert.ok(allText(root).includes("[truncated: surface too large]"));
});

test("an honest surface is nowhere near the budget and renders whole", () => {
  /** 600 siblings under one root is well past what this org's builders emit.
   * Wide rather than deep, because a deep chain would exercise MAX_DEPTH instead
   * of the budget. */
  const children = [];
  const components = [{ id: "root", component: "Column", children }];
  for (let i = 0; i < 600; i++) {
    children.push(`t${i}`);
    components.push({ id: `t${i}`, component: "Text", text: i === 599 ? "end of an honest surface" : `row ${i}` });
  }
  const { root, warnings } = paint({
    createSurface: { surfaceId: "honest" },
    updateComponents: { surfaceId: "honest", root: "root", components },
    version: "0.10",
  });
  assert.ok(allText(root).includes("end of an honest surface"), "an honest surface was truncated");
  assert.deepEqual(warnings.filter((w) => w.includes("render budget")), []);
});

test("the budget resets per render, so a big surface cannot starve the next one", () => {
  /** app.js reuses one renderer for action results, so a budget carried across
   * paints would let one large surface truncate every later render. */
  const renderer = new SurfaceRenderer({ document: new StubDocument(), onWarn: () => {} });
  paint(fanoutEnvelope(20), renderer);
  const { root } = paint(fanoutEnvelope(3), renderer);
  assert.ok(!allText(root).includes("[truncated"), "the second, tiny surface was starved by the first");
});

test("removing the budget makes the same envelope expand again", () => {
  /** Shows the budget is what bounds the walk, rather than some other cap. Depth
   * 16 (131,071 nodes, ~0.5 s) rather than 20 (1,048,575 nodes, ~4.8 s): the
   * ratio is the assertion, and the suite need not spend five seconds on it. */
  const doc = new StubDocument();
  const renderer = new SurfaceRenderer({ document: doc, onWarn: () => {} });
  const normalized = normalizeEnvelope(fanoutEnvelope(16));

  renderer.render(normalized);
  const guarded = doc.created.length;

  // Make the budget unreachable, as deleting the check would.
  const doc2 = new StubDocument();
  const unguarded = new SurfaceRenderer({ document: doc2, onWarn: () => {} });
  const realRenderRef = Object.getPrototypeOf(unguarded).renderRef;
  Object.getPrototypeOf(unguarded).renderRef = function patched(id, pathIds, depth) {
    this.budget = Number.POSITIVE_INFINITY; // the check can never fire
    return realRenderRef.call(this, id, pathIds, depth);
  };
  try {
    unguarded.render(normalized);
  } finally {
    Object.getPrototypeOf(unguarded).renderRef = realRenderRef;
  }

  assert.ok(
    doc2.created.length > guarded * 4,
    `without the budget the same envelope must expand: guarded=${guarded}, unguarded=${doc2.created.length}`,
  );
  assert.ok(doc2.created.length > 100000, "the unbudgeted walk should exceed 100,000 nodes at depth 16");

  // A fresh renderer is bounded again, so the patch above did not persist.
  const doc3 = new StubDocument();
  new SurfaceRenderer({ document: doc3, onWarn: () => {} }).render(normalized);
  assert.ok(doc3.created.length <= guarded, "the patched renderRef outlived this test");
});
