/**
 * Adversarial render tests for the receipts page.
 *
 * Every field of a receipt is server-supplied. The document is the reference
 * renderer's recording stub, which throws on `innerHTML`/`outerHTML` and on any
 * attribute beginning with `on`, so reaching the end of a test shows the render
 * path did not go through an HTML parser.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { StubDocument, allText, walk } from "../../../renderer/tests/stubdom.mjs";
import { buildReceiptCard, buildReceipts, paintVerdict, preview } from "../ui/receipts.js";

const SCRIPT = "<script>alert('xss')</script>";
const ATTR_BREAKER = `"><img src=x onerror=alert(1)>`;

function tags(doc) {
  return doc.created.map((el) => el.tagName);
}

function assertNoInjection(doc, node, payload) {
  assert.ok(allText(node).includes(payload), "payload should be present as text");
  for (const bad of ["script", "img"]) {
    assert.ok(!tags(doc).includes(bad), `a <${bad}> element was created from data`);
  }
  assert.deepEqual(
    doc.attributesSet.filter((a) => /^on/i.test(a.name)),
    [],
  );
}

test("hostile receipt fields land as text", () => {
  const doc = new StubDocument();
  const node = buildReceiptCard(doc, {
    action: { category: ATTR_BREAKER, outcome: SCRIPT, human_summary: SCRIPT, counterparty_label: SCRIPT },
    issuer_did: SCRIPT,
    signature: SCRIPT,
    issued_at: "",
  });
  assertNoInjection(doc, node, SCRIPT);
});

test("truncation happens on the raw value, never on an escaped one", () => {
  /** ⚠️ The old page did `esc(r.signature).slice(0, 28)` — truncating an
   * ALREADY-ESCAPED string, so a signature containing `&` could be cut
   * mid-entity (`&amp;` → `&am`). Harmless (a severed entity cannot open a tag)
   * but it rendered corrupted text. */
  assert.equal(preview("&&&&&&", 3), "&&&…");
  assert.equal(preview("short", 40), "short");
  assert.equal(preview(null, 4), "");
});

test("the verdict label is a constant, never assembled from the result", () => {
  const doc = new StubDocument();
  const badge = doc.createElement("span");
  paintVerdict(doc, badge, "invalid");
  assert.equal(badge.textContent, "✗ INVALID signature");
  assert.ok(!badge.textContent.includes("<"));
  paintVerdict(doc, badge, "verified");
  assert.equal(badge.className, "ok verified");
  // An unknown verdict paints nothing rather than guessing.
  const before = badge.textContent;
  paintVerdict(doc, badge, "not-a-verdict");
  assert.equal(badge.textContent, before);
});

test("an empty receipt list says so", () => {
  const doc = new StubDocument();
  assert.ok(allText(buildReceipts(doc, [])).includes("No receipts yet"));
});

test("each receipt card gets the id its verification badge will be found by", () => {
  const doc = new StubDocument();
  const node = buildReceipts(doc, [{}, {}], { idFor: (_r, i) => `verify-${i}` });
  const ids = [...walk(node)].map((el) => el.getAttribute("id")).filter(Boolean);
  assert.deepEqual(ids, ["verify-0", "verify-1"]);
});
