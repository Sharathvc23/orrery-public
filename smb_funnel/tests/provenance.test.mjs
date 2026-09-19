/**
 * Provenance: whose key signed this receipt?
 *
 * The signature check proves a receipt is internally consistent — whoever signed
 * it holds the key named inside it. It cannot prove the receipt came from the
 * business the customer dealt with, because the key and the claim about whose
 * key it is both come from the same document. A stranger can mint a key, write
 * "PAID IN FULL" into the summary, sign it honestly, and satisfy every check
 * that reads only the receipt.
 *
 * The first test below is that receipt. It must not pass.
 *
 * Classification: ADVERSARIAL (security control).
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  base64Encode,
  canonicalBytesForSigning,
  didFromAgentCard,
  generateIdentity,
  publicKeyToDidKey,
  signReceipt,
  verifyReceipt,
} from "../src/arp.js";
import { paintVerifyBadge } from "../src/render.js";
import { StubDocument, allText } from "../../renderer/tests/stubdom.mjs";

/** A receipt the given identity signs honestly. */
async function receiptFrom(identity, summary = "Appointment booked") {
  const receipt = {
    version: "arp/0.1",
    receipt_id: "11111111-2222-3333-4444-555555555555",
    issuer_did: identity.did,
    principal_did: identity.did,
    issued_at: "2026-08-16T12:00:00Z",
    action: { category: "appointment_booked", human_summary: summary, outcome: "completed" },
  };
  return signReceipt(receipt, identity.privateKey);
}

test("a receipt a stranger signed with their own key is refused", async () => {
  /** ⚠️ THE ORIGINAL REPRODUCTION. Nothing here is tampered — it is a genuine
   * Ed25519 signature, valid under the did:key the receipt names. What makes it
   * worthless is that the customer never dealt with that key. Before the
   * provenance stage existed this returned ok:true and painted a green tick. */
  const business = await generateIdentity();
  const stranger = await generateIdentity();
  const forged = await receiptFrom(stranger, "Booking confirmed and PAID IN FULL - $5000");

  const result = await verifyReceipt(forged, { expectedIssuer: business.did });

  assert.equal(result.ok, false, "a receipt signed by a stranger must not verify");
  assert.equal(result.stage, "provenance");
  assert.equal(result.provenance, "warning");
});

test("the same stranger's receipt is not verified when there is no pin either", async () => {
  /** The no-pin case must not be the loophole that reinstates the defect: with
   * nothing to compare against, the answer is "unknown", never "verified". */
  const stranger = await generateIdentity();
  const forged = await receiptFrom(stranger, "Booking confirmed and PAID IN FULL - $5000");

  const result = await verifyReceipt(forged);

  assert.equal(result.ok, false);
  assert.equal(result.provenance, "unknown");
});

test("a genuine receipt from the pinned business still passes", async () => {
  /** The honest case. A check that refuses everything passes every tamper test
   * and is worth nothing, so this is the assertion that keeps the fix useful. */
  const business = await generateIdentity();
  const genuine = await receiptFrom(business);

  const result = await verifyReceipt(genuine, { expectedIssuer: business.did });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "accepted");
  assert.equal(result.provenance, "trusted");
});

test("tampering is still caught before provenance is considered", async () => {
  const business = await generateIdentity();
  const receipt = await receiptFrom(business);
  receipt.action.human_summary = "Refund issued";

  const result = await verifyReceipt(receipt, { expectedIssuer: business.did });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "signature", "a broken signature must fail at the signature stage");
});

test("a signature that is valid but 64 bytes of the wrong value fails on cryptography", async () => {
  /** Guards the guard: an earlier attempt mutated the signature's LENGTH and was
   * caught by a length check, which proves nothing about Ed25519. */
  const business = await generateIdentity();
  const receipt = await receiptFrom(business);
  const bytes = new Uint8Array(64);
  bytes[0] = 0xff;
  receipt.signature = base64Encode(bytes);

  const result = await verifyReceipt(receipt, { expectedIssuer: business.did });
  assert.equal(result.ok, false);
  assert.equal(result.stage, "signature");
  assert.match(result.detail, /Ed25519 verification failed/);
});

test("the expected issuer is read from the agent card, not from the receipt", async () => {
  /** The anchor has to come from somewhere else, so the card is where it comes
   * from — both the shapes smb_host publishes are accepted. */
  const id = await generateIdentity();
  assert.equal(didFromAgentCard({ "x-nanda": { did: id.did } }), id.did);
  assert.equal(didFromAgentCard({ authentication: { credentials: id.did } }), id.did);
  assert.equal(didFromAgentCard({ authentication: { credentials: "not-a-did" } }), "");
  assert.equal(didFromAgentCard(null), "");
});

test("the badge never says verified for a receipt whose issuer was not checked", async () => {
  /** The wording is part of the control. "Verified" on an unconfirmed issuer is
   * how a stranger's receipt was read as genuine by the person looking at it. */
  const labels = {};
  for (const state of ["ok", "unknown", "mismatch", "fail", "unsigned"]) {
    const doc = new StubDocument();
    labels[state] = allText(paintVerifyBadge(doc, doc.createElement("span"), state));
  }
  assert.match(labels.ok, /Verified/);
  assert.doesNotMatch(labels.unknown, /Verified/, "an unconfirmed issuer must not read as verified");
  assert.doesNotMatch(labels.mismatch, /Verified/);
  assert.match(labels.unknown, /not confirmed/i);
  assert.match(labels.mismatch, /different key/i);

  const seen = new Set(Object.values(labels));
  assert.equal(seen.size, Object.keys(labels).length, "each state needs its own words");
});

test("a did:key built from a raw public key round-trips", async () => {
  const id = await generateIdentity();
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])).publicKey));
  assert.match(publicKeyToDidKey(raw), /^did:key:z/);
  assert.match(id.did, /^did:key:z/);
  assert.ok(canonicalBytesForSigning({ a: 1, signature: "x" }).length > 0);
});

// ── the anchor, and where it does NOT come from ─────────────────────────────
//
// ⚠️ WHAT USED TO BE HERE. Three tests drove `src/pin.js`, a localStorage
// trust-on-first-use store, through new / trusted / warning / unknown. They
// passed, and they proved nothing about this product: no code on the verdict
// path ever read the stored value — `app.js` passed the card DID it had fetched
// in the same session — so the suite asserted a module the funnel did not use
// while the UI cited it as a control. The store was removed rather than wired,
// because trust-on-first-use needs a second encounter and this funnel mints a
// new tenant on every run. See the CHANGELOG entry and tests/wiring.test.mjs,
// which drives the anchor through the real app instead of asserting a module.

test("the anchor cannot be taken from the receipt, which is why it is a parameter", async () => {
  /** The whole defect in one assertion: a receipt that names itself as its own
   * expected issuer passes every check, so `expectedIssuer` must never be
   * derivable from the document being checked. */
  const stranger = await generateIdentity();
  const forged = await receiptFrom(stranger, "PAID IN FULL - $5000");

  const selfAnchored = await verifyReceipt(forged, { expectedIssuer: forged.issuer_did });
  assert.equal(selfAnchored.ok, true, "self-anchoring accepts a stranger — this is the failure, stated");

  const cardAnchored = await verifyReceipt(forged, {
    expectedIssuer: didFromAgentCard({ "x-nanda": { did: (await generateIdentity()).did } }),
  });
  assert.equal(cardAnchored.ok, false, "an anchor read from the card refuses it");
  assert.equal(cardAnchored.provenance, "warning");
});

test("no funnel module keeps a browser-side identity store", () => {
  /** A grep-shaped guard, and deliberately so: the failure being prevented is a
   * module that exists, is covered, and is cited by the UI while no code path
   * calls it. Behavioural tests cannot see that — only absence can. */
  const src = new URL("../src/", import.meta.url).pathname;
  const files = readdirSync(src).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the funnel modules under src/, found ${files.length}`);
  assert.ok(!files.includes("pin.js"), "pin.js is back without a caller on the verdict path");
  for (const file of files) {
    const source = readFileSync(join(src, file), "utf8");
    assert.ok(!/localStorage\s*\.\s*setItem/.test(source), `${file} writes a browser store`);
  }
  // config.js READS localStorage (the operator's API base) and that is not this.
  assert.ok(
    /localStorage/.test(readFileSync(join(src, "config.js"), "utf8")),
    "the guard must not be passing because it stopped looking",
  );
});
