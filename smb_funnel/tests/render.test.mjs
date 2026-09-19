/**
 * Adversarial render tests for the SMB funnel (G3 / AUDIT_HARSH C7 + H13).
 *
 * ⚠️ WHAT THIS ASSERTS, AND WHY IT IS NOT "escapeHtml WAS CALLED". A test that
 * checks an escaper ran proves nothing about the node that ends up in the DOM —
 * it passes just as happily if the escaped string is then handed to an HTML
 * parser. These push a `<script>` tag, quotes and an event-handler attribute
 * through the REAL render path and assert what the document actually contains:
 * a text node holding the payload verbatim, and no element created from it.
 *
 * The document is the reference renderer's recording stub, which THROWS on any
 * read or write of `innerHTML`/`outerHTML` and on `insertAdjacentHTML`. So these
 * tests do not merely check the output — reaching the end of one is itself proof
 * that the render path never went through an HTML parser. Reused rather than
 * copied: a second stub would be a hand-mirror of a security fixture, and the
 * CI `changes` filter is widened so editing it re-runs this suite too.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { StubDocument, allText, walk } from "../../renderer/tests/stubdom.mjs";
import { buildBookingError, buildPhraseChips, buildReceipt, paintVerifyBadge } from "../src/render.js";

// A single "word" with no spaces, so the phrase splitter keeps it in one chip.
const SCRIPT_WORD = "<script>alert('xss')</script>";
const ATTR_BREAKER = `"><img src=x onerror=alert(1)>`;
const QUOTE_WORD = `'"\`&`;

function tags(doc) {
  return doc.created.map((el) => el.tagName);
}

// ── input classification for the fields the funnel renders ───────────────────

test("a URL query parameter does not select the API host", async () => {
  // The provisioning screen renders the /provision response verbatim: the
  // agent's endpoint, its did:key, and the recovery phrase the page instructs
  // the user to write down. While `?api=` was honoured, the author of a link
  // selected the host that produced those values, and they were displayed on
  // this origin. No script execution is involved, so the page's
  // Content-Security-Policy does not affect it.
  const realLocation = globalThis.location;
  const realStorage = globalThis.localStorage;
  globalThis.location = { search: "?api=https://attacker.example" };
  globalThis.localStorage = { getItem: () => null };
  try {
    // Awaited, not returned: a `finally` around a returned promise restores the
    // globals BEFORE the assertion runs, so the test would read the restored
    // value and fail for the wrong reason. (It did, first time.)
    const config = await import("../src/config.js");
    assert.equal(
      config.resolveApiBase(),
      config.API_BASE,
      "a query parameter selects the API host again",
    );
  } finally {
    globalThis.location = realLocation;
    globalThis.localStorage = realStorage;
  }
});

test("the recovery phrase is remote input, whichever host is configured", async () => {
  // The phrase is not generated in the page. It arrives in the /provision
  // response, so the configured host writes it. localStorage still selects that
  // host, and a deployment points the constant at one. Everything downstream
  // must therefore treat the phrase, the endpoint and the did:key as untrusted
  // remote strings, which is what the rest of this file asserts.
  const realLocation = globalThis.location;
  const realStorage = globalThis.localStorage;
  globalThis.location = { search: "" };
  globalThis.localStorage = { getItem: (k) => (k === "smb_funnel.api_base" ? "https://operator-chose-this.example" : null) };
  try {
    const config = await import("../src/config.js");
    assert.equal(
      config.resolveApiBase(),
      "https://operator-chose-this.example",
      "the response — recovery phrase included — still comes from a host this page did not author",
    );
  } finally {
    globalThis.location = realLocation;
    globalThis.localStorage = realStorage;
  }
});

// ── the recovery phrase: the bug, and the payload that matters most ──────────

test("a phrase word containing a script tag lands as TEXT, not as an element", () => {
  const doc = new StubDocument();
  const phrase = `abandon ${SCRIPT_WORD} ability`;

  const chips = buildPhraseChips(doc, phrase);

  // The payload is in the document as data...
  const text = chips.map((c) => allText(c)).join("|");
  assert.ok(text.includes(SCRIPT_WORD), `payload missing from rendered text: ${text}`);
  // ...and NOT as an element. This is the assertion escapeHtml-was-called cannot make.
  assert.ok(!tags(doc).includes("script"), `a <script> element was created: ${tags(doc)}`);
  assert.deepEqual(new Set(tags(doc)), new Set(["span"]), "only spans should exist in a phrase chip tree");
});

test("a phrase word cannot break out of an attribute", () => {
  const doc = new StubDocument();
  buildPhraseChips(doc, `alpha ${ATTR_BREAKER} bravo`);
  assert.ok(!tags(doc).includes("img"), "an <img> element was created from a phrase word");
  // The stub throws on any attribute starting with "on"; reaching here proves
  // no event-handler attribute was set either.
  assert.deepEqual(
    doc.attributesSet.filter((a) => /^on/i.test(a.name)),
    [],
  );
});

test("quotes, ampersands and backticks survive verbatim as text", () => {
  const doc = new StubDocument();
  const chips = buildPhraseChips(doc, `alpha ${QUOTE_WORD} bravo`);
  assert.ok(allText(chips[1]).includes(QUOTE_WORD), "a quote-heavy word was mangled or dropped");
});

test("the chip keeps its number and its word, in that order", () => {
  const doc = new StubDocument();
  const chips = buildPhraseChips(doc, "alpha bravo charlie");
  assert.equal(chips.length, 3);
  assert.equal(chips[1].className, "word");

  // Asserted against childNodes rather than allText: the shared stub's allText
  // is element-major (it collects each element's own text children as it walks),
  // so it cannot express document order for mixed content. Using it here would
  // have been a test of the helper, not of the chip.
  const [indexNode, wordNode] = chips[1].childNodes;
  assert.equal(indexNode.className, "word-n");
  assert.equal(indexNode.textContent, "2");
  assert.equal(wordNode.nodeType, 3, "the word must be a text node, never an element");
  assert.equal(wordNode.data, "bravo");
  assert.equal(chips[1].childNodes.filter((n) => n.tagName).length, 1, "only the index span may be an element");
});

test("an empty or absent phrase renders nothing rather than a blank chip", () => {
  const doc = new StubDocument();
  assert.deepEqual(buildPhraseChips(doc, ""), []);
  assert.deepEqual(buildPhraseChips(doc, null), []);
  assert.deepEqual(buildPhraseChips(doc, "  "), []);
});

// ── the receipt (H13): every field is server-supplied ────────────────────────

test("hostile receipt fields land as text, not as elements", () => {
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, {
    receiptId: SCRIPT_WORD,
    booking: { service: ATTR_BREAKER, provider: SCRIPT_WORD, status: QUOTE_WORD },
    receipt: {
      version: SCRIPT_WORD,
      issuer_did: ATTR_BREAKER,
      issued_at: SCRIPT_WORD,
      signature: SCRIPT_WORD,
      action: { category: SCRIPT_WORD, outcome: ATTR_BREAKER },
    },
    whenStr: SCRIPT_WORD,
  });

  const rendered = allText(node);
  assert.ok(rendered.includes(SCRIPT_WORD), "the payload should be present as text");
  for (const forbidden of ["script", "img"]) {
    assert.ok(!tags(doc).includes(forbidden), `a <${forbidden}> element was created from receipt data`);
  }
  assert.deepEqual(
    doc.attributesSet.filter((a) => /^on/i.test(a.name)),
    [],
  );
});

test("the receipt renders the same structure the stylesheet expects", () => {
  const doc = new StubDocument();
  const { node, badge } = buildReceipt(doc, {
    receiptId: "rcpt-1",
    booking: { service: "Haircut", provider: "Moon Bakery", status: "recorded" },
    receipt: { version: "arp/0.2", issuer_did: "did:key:z6Mk", issued_at: "now", signature: "sig", action: {} },
    whenStr: "Tomorrow",
  });
  const classes = [...walk(node)].map((el) => el.className).filter(Boolean);
  for (const cls of ["receipt-head", "receipt-title", "receipt-id", "receipt-grid", "sig", "sig-val"]) {
    assert.ok(
      classes.some((c) => c.split(" ").includes(cls)),
      `missing .${cls} — the receipt markup changed shape`,
    );
  }
  assert.equal(badge.getAttribute("id"), "verify-badge");
  assert.ok(allText(node).includes("Haircut"));
});

test("a receipt with no signature says so instead of claiming verification", () => {
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, { receiptId: "r", booking: {}, receipt: null, whenStr: "—" });
  assert.ok(allText(node).includes("No signed receipt returned"));
  assert.ok(!allText(node).includes("Signature evidence"));
});

// ── the booking error and the verification badge ─────────────────────────────

test("a hostile error message lands as text", () => {
  const doc = new StubDocument();
  const node = buildBookingError(doc, SCRIPT_WORD);
  assert.ok(allText(node).includes(SCRIPT_WORD));
  assert.ok(!tags(doc).includes("script"));
  assert.equal(node.className, "err");
});

test("the verify badge label is a constant, never assembled from the result", () => {
  const doc = new StubDocument();
  const badge = doc.createElement("span");
  paintVerifyBadge(doc, badge, "fail");
  const label = allText(badge);
  assert.ok(label.includes("Verification failed"));
  // The attacker-influenced stage/detail must not reach the visible label; they
  // go to `title`, which is a property assignment and cannot become markup.
  assert.ok(!label.includes("<"), "the badge label should contain no markup characters");
});

test("the badge repaints cleanly between states rather than accumulating", () => {
  const doc = new StubDocument();
  const badge = doc.createElement("span");
  paintVerifyBadge(doc, badge, "ok");
  paintVerifyBadge(doc, badge, "fail");
  assert.ok(!allText(badge).includes("Verified offline"), "a stale label survived a repaint");
  assert.equal(badge.className, "verify-badge verify-fail");
});

test("an unknown badge state paints nothing rather than guessing", () => {
  const doc = new StubDocument();
  const badge = doc.createElement("span");
  badge.className = "verify-badge verify-pending";
  paintVerifyBadge(doc, badge, "not-a-state");
  assert.equal(badge.className, "verify-badge verify-pending");
});

// ── the delivery outcome: three states, and silence is not a failure ─────────
//
// ⚠️ WHAT THIS EXISTS TO STOP. The panel rendered "Booking confirmed" and a
// Status row and nothing else, while `smb_host` had been sending `delivered`,
// `delivery_channel` and `delivery_note` on every `/book` response for exactly
// this reader — its own source says "a caller that is told nothing cannot tell a
// delivered booking from one the business will never see." The funnel read none
// of them, so a booking that reached nobody rendered identically to one that
// arrived, on a page whose form promises the contact address is where bookings
// go. Nothing could catch it from the outside: the markup was well-formed, the
// receipt verified, and the missing fact was one the panel never mentioned.

function receiptText(extra) {
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, {
    receiptId: "rcpt-1",
    booking: { service: "Haircut", provider: "Stellar Barbers", status: "recorded" },
    receipt: null,
    whenStr: "Tomorrow",
    ...extra,
  });
  return allText(node);
}

test("a delivered booking names the channel it reached", () => {
  const text = receiptText({ delivered: true, deliveryChannel: "email" });
  assert.ok(text.includes("Delivered"), text);
  assert.ok(text.includes("email"), text);
  assert.ok(!text.includes("Not delivered"), text);
});

test("an undelivered booking says so, and repeats the host's reason", () => {
  const text = receiptText({ delivered: false, deliveryNote: "the contact names no channel" });
  assert.ok(text.includes("Not delivered"), text);
  assert.ok(text.includes("the contact names no channel"), text);
});

test("a backend that says nothing about delivery is reported as silent, not as a failure", () => {
  /** ⚠️ ABSENT IS NOT FALSE. The in-page demo backend used to omit these fields
   *  entirely, and a reader shown "Not delivered" for silence would be told a
   *  judgement nobody made. The three states must be three, and this one must
   *  not borrow the failure wording. */
  const text = receiptText({});
  assert.ok(text.includes("Not stated"), text);
  assert.ok(!text.includes("Not delivered"), text);
  assert.ok(!text.includes("Delivered ·"), text);
});

test("the three delivery states share no wording", () => {
  /** Distinctness is the property: two states that read alike are one state with
   *  extra steps, which is the defect this row was added to remove. */
  const seen = [
    receiptText({ delivered: true, deliveryChannel: "email" }),
    receiptText({ delivered: false, deliveryNote: "nowhere to send it" }),
    receiptText({}),
  ];
  assert.equal(new Set(seen).size, 3, "two delivery states render the same text");
});

test("the panel never invents a status the backend did not send", () => {
  /** The Status cell fell back to the literal "confirmed" whenever `status` was
   *  absent — the renderer asserting the one word the reader is there for. */
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, {
    receiptId: "r",
    booking: { service: "Haircut" },
    receipt: null,
    whenStr: "—",
  });
  // Asserts what the STATUS CELL renders, rather than that some word is absent
  // from the panel. Two reasons the narrower form is the right one: a
  // word-absence check goes green for a renderer that invents any word nobody
  // listed, and the panel legitimately contains the status word in its own
  // label ("Status (as the host recorded it)"), so scanning the whole panel
  // cannot tell the label from the value.
  const cell = [...walk(node)].find((el) => (el.className || "").split(" ").includes("status-recorded"));
  assert.ok(cell, "no status cell was rendered at all");
  assert.equal(allText(cell), "—", "the renderer supplied a status the response did not carry");
});

test("a hostile delivery note lands as text, like every other host-supplied field", () => {
  const text = receiptText({ delivered: false, deliveryNote: SCRIPT_WORD });
  assert.ok(text.includes(SCRIPT_WORD), text);
});

// ── the host's word, attributed to the host ─────────────────────────────────
//
// ⚠️ MEASURED, NOT READ. Driving a real smb_host: a booking comes back with
// a booking status and `delivered: false` in the SAME response, because
// `booking["status"]` is set unconditionally before delivery is
// consulted. There is no acceptance step anywhere in the path — nobody at the
// business confirms anything. Unattributed and painted in the success green,
// that word tells the reader the business agreed. Attributed to the host's own
// record, it is exactly true.

test("the status is labelled as the host's record rather than presented as an outcome", () => {
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, {
    receiptId: "r",
    booking: { service: "Haircut", status: "recorded" },
    receipt: null,
    whenStr: "—",
    delivered: false,
    deliveryNote: "no sender is configured for the email channel",
  });
  const text = allText(node);
  assert.ok(text.includes("as the host recorded it"), `the status row names no speaker: ${text}`);
  assert.ok(text.includes("recorded"), text);
});

test("the status value carries no success styling it has not earned", () => {
  /** Neutral is NOT negative, and this test exists so nobody reads it as one: no
   *  "unconfirmed" label is added and nothing is hidden. The word the host sent
   *  is shown verbatim. What it must not carry is the green that says a good
   *  outcome was observed, because the same response can report the booking
   *  reached nobody. The colour belongs to the Delivery row. */
  const doc = new StubDocument();
  const { node } = buildReceipt(doc, {
    receiptId: "r",
    booking: { status: "recorded" },
    receipt: null,
    whenStr: "—",
    delivered: false,
  });
  const classes = [...walk(node)].map((el) => el.className).filter(Boolean);
  const statusish = classes.filter((c) => c.split(" ").some((x) => x.startsWith("status-")));
  assert.ok(statusish.length >= 2, `expected a status class and a delivery class, got ${statusish}`);
  assert.ok(!statusish.includes("status-ok"), `an undelivered booking still paints a success status: ${statusish}`);
  assert.ok(statusish.includes("status-recorded"), statusish);
});
