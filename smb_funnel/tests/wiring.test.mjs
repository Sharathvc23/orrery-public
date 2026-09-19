/**
 * The verdict path consults the anchor — asserted by driving the app, not the
 * module.
 *
 * ⚠️ THE DEFECT THIS SUITE EXISTS FOR. `src/pin.js` stored a `did:key` in
 * `localStorage` and reported new / trusted / warning / unknown. Its own tests
 * were green, 31 of them, and every one of them was true. None of them could see
 * that no code on the verification path ever read the stored value: `app.js`
 * computed a pin state, assigned it to `liveTenant`, and then verified the
 * receipt against the card DID it had fetched in the same session — while the
 * success tooltip told the customer the issuer matched "this business's pinned
 * did:key". A control the UI cited, the tests covered, and the code did not call.
 *
 * The store is gone (see the CHANGELOG entry: trust-on-first-use needs a second
 * encounter, and this funnel mints a new tenant on every run, so a pin would be
 * written and read inside one session — a check whose verdict is a function of
 * its own write). What remains is the anchor that was doing the work all along:
 * the `did:key` the host publishes on the tenant's agent card, read this session.
 *
 * So these tests run the REAL `app.js` — its submit handler, its booking click,
 * its badge — against a real HTTP host, and read the badge it painted. The
 * load-bearing case is `divergent`: a host that serves ONE key on the card and
 * signs the receipt with ANOTHER. If the app stops passing the card DID it paints
 * "issuer not confirmed"; if it ever anchors the receipt to itself it paints
 * "Verified". Only consulting the card produces the mismatch this asserts.
 *
 * Classification: ADVERSARIAL (security control) + WIRING.
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { after } from "node:test";

import { allText } from "../../renderer/tests/stubdom.mjs";
import { generateIdentity, signReceipt } from "../src/arp.js";
import { fire, installDocument, verifyBadge } from "./funneldom.mjs";

// ── a host under this test's control ────────────────────────────────────────
//
// Two identities, kept apart on purpose: the key the host SIGNS receipts with,
// and the key it PUBLISHES on the agent card. An honest host uses one key for
// both. Nothing but the card can tell the customer's browser which case it is in.
const signer = await generateIdentity();
const other = await generateIdentity();

/** "aligned" | "divergent" | "cardless" — set per test, read per request. */
let mode = "aligned";

const TENANT = "fadeaway-barbershop";

function cardDid() {
  return mode === "divergent" ? other.did : signer.did;
}

async function bookingResponse(base) {
  const receipt = await signReceipt(
    {
      version: "arp/0.1",
      receipt_id: "11111111-2222-3333-4444-555555555555",
      issuer_did: signer.did,
      principal_did: signer.did,
      issued_at: "2026-08-18T12:00:00Z",
      action: {
        category: "appointment_booked",
        human_summary: "Booked Haircut with Fadeaway Barbershop",
        outcome: "completed",
        machine_payload: { booking_id: 1, provider: "Fadeaway Barbershop" },
      },
    },
    signer.privateKey,
  );
  return {
    receipt_id: receipt.receipt_id,
    booking: {
      tenant_id: TENANT,
      service: "Haircut",
      provider: "Fadeaway Barbershop",
      datetime: "2026-08-20T10:00:00.000Z",
      status: "recorded",
    },
    receipt,
    base,
  };
}

const server = createServer(async (req, res) => {
  const base = `http://127.0.0.1:${server.address().port}`;
  const send = (status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const url = req.url.split("?")[0];

  if (req.method === "POST" && url === "/provision") {
    return send(201, {
      tenant_id: TENANT,
      endpoint: `${base}/t/${TENANT}`,
      did: signer.did,
      recovery_phrase: Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(" "),
    });
  }
  if (req.method === "GET" && url === `/t/${TENANT}/.well-known/agent.json`) {
    // "cardless" is a host that answers everything EXCEPT the card. app.js
    // swallows that failure by design (the live screen is still useful), which
    // is precisely why the badge must not then claim a check it could not run.
    if (mode === "cardless") return send(404, { error: "no card" });
    return send(200, {
      name: "Fadeaway Barbershop",
      "x-nanda": { did: cardDid() },
      authentication: { credentials: cardDid() },
    });
  }
  if (req.method === "POST" && url === `/t/${TENANT}/book`) {
    return send(200, await bookingResponse(base));
  }
  return send(404, { error: "not found" });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const apiBase = `http://127.0.0.1:${server.address().port}`;

// api.js resolves the host once, at import, from this store. It must be in place
// before the first import of any funnel module below.
globalThis.localStorage = {
  getItem: (k) => (k === "smb_funnel.api_base" ? apiBase : null),
  setItem() {},
  removeItem() {},
};

after(() => server.close());

/**
 * Boot a fresh copy of the app against a fresh document and drive it all the way
 * to a painted badge: fill the form, submit it, click "Try it".
 *
 * The query string gives each case its own module instance — `app.js` registers
 * its handlers against whatever `document` exists at import — while `./api.js`
 * and `./arp.js` resolve without one and stay shared, so every case speaks to the
 * same host on the same resolved base.
 */
async function runFunnel(caseName) {
  const doc = installDocument();
  await import(`../src/app.js?case=${caseName}`);
  doc.querySelector("#business-name").value = "Fadeaway Barbershop";
  doc.querySelector("#service-type").value = "Haircuts & hot-towel shaves";
  // Required by the host and by the form: an agent with nowhere to send a
  // booking would accept appointments the business never sees.
  doc.querySelector("#contact").value = "https://bookings.example/hook";
  await fire(doc, "#funnel-form", "submit");
  await fire(doc, "#try-btn", "click");
  const badge = verifyBadge(doc);
  assert.ok(badge, "the app painted no verification badge at all");
  return { doc, badge, label: allText(badge), title: badge.title };
}

test("an honest host verifies, and the badge says what was compared", async () => {
  /** The useful case. A control that refuses everything passes every adversarial
   * test and is worth nothing, so this is what keeps the rest meaningful. */
  mode = "aligned";
  const { doc, label, title } = await runFunnel("aligned");

  assert.match(label, /Verified/, "a receipt signed by the card's key must verify");
  assert.match(label, /card/i, "the label must name what it compared against");
  assert.doesNotMatch(label, /pin/i);
  assert.match(title, /agent card/i, "the tooltip must name the check that ran");
  assert.doesNotMatch(title, /pin/i, "the tooltip claims a pin the code does not consult");
  assert.match(title, /same origin/i, "the tooltip must not imply more than same-origin agreement");
  assert.equal(doc.querySelector("#did").textContent, signer.did);
});

test("a host that signs with a key it did not put on the card is caught", async () => {
  /** ⚠️ THE GUARD. Every byte of this receipt is honestly signed and internally
   * consistent — it fails only against the card. Drop `expectedIssuer` from the
   * verify call and this paints "issuer not confirmed"; anchor the receipt to
   * itself and it paints "Verified". Neither is what this asserts. */
  mode = "divergent";
  const { label, title } = await runFunnel("divergent");

  assert.doesNotMatch(label, /Verified/, "a key the card never published must not read as verified");
  assert.match(label, /different key/i);
  assert.match(label, /agent card/i, "the label must say what the key differed from");
  assert.match(title, /different key/i);
  assert.doesNotMatch(title, /pin/i);
});

test("a host that serves no card leaves the issuer unconfirmed, not verified", async () => {
  /** The anchor is fetched, so it can be missing. The badge then has to say so:
   * "no anchor" degrading to "verified" is how a stranger's receipt earned a
   * green tick in the first place. */
  mode = "cardless";
  const { label, title } = await runFunnel("cardless");

  assert.doesNotMatch(label, /Verified/, "a receipt with nothing to check the issuer against is not verified");
  assert.match(label, /not confirmed/i);
  assert.match(title, /no did:key was available/i);
  assert.doesNotMatch(title, /pin/i);
});
