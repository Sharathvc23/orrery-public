#!/usr/bin/env node
// smb_funnel — headless end-to-end smoke test.
//
// Exercises the exact mock_core.js the browser funnel runs against, driving the
// full 3-screen flow's network path: provision → resolve agent card → book →
// verify the signed receipt OFFLINE (real Ed25519, the same src/arp.js path the
// browser uses) → tamper it and confirm verification fails. Plus /health and
// the error paths the UI depends on.
//
//   node smoke.mjs        (exit 0 = all good, non-zero = failure)

import { readFileSync } from "node:fs";

import { verifyReceipt } from "./src/arp.js";
import { route } from "./src/mock_core.js";

// The booking status comes from the contract file both sides are held to, not
// from a literal here. A smoke test that restates one side's expectation is the
// shape that let the mock and the host disagree on the refusal path.
const CONTRACT = JSON.parse(readFileSync(new URL("./tests/host_contract.json", import.meta.url).pathname, "utf8"));
const BOOKING_STATUS = CONTRACT.book_success.booking_status;

let failed = 0;
function check(name, cond) {
  const ok = !!cond;
  process.stdout.write(`${ok ? "PASS" : "FAIL"}  ${name}\n`);
  if (!ok) failed++;
}

// ── screen 2: provision ──────────────────────────────────────────────
const CONTACT = "https://bookings.example/hook";
const prov = await route("POST", "/provision", {
  business_name: "Fadeaway Barbershop",
  service_type: "Haircuts & hot-towel shaves",
  contact: CONTACT,
});
check("provision returns 201", prov.status === 201);
const p = prov.json;
check("provision tenant_id is the slug", p.tenant_id === "fadeaway-barbershop");
check("provision endpoint (/t/<slug>)", /^https?:\/\/.+\/t\/fadeaway-barbershop$/.test(p.endpoint));
check("provision recovery_phrase (24 words)", (p.recovery_phrase || "").split(" ").length === 24);
check("provision did:key (Ed25519 z6Mk…)", /^did:key:z6Mk/.test(p.did));
check("provision response has no urn (index concept)", !("urn" in p));

// duplicate provision → 409 (same slug already taken)
const dup = await route("POST", "/provision", { business_name: "Fadeaway Barbershop", contact: CONTACT });
check("duplicate business → 409", dup.status === 409);

// ── screen 2: resolve the published agent card ───────────────────────
const card = await route("GET", `/t/${p.tenant_id}/.well-known/agent.json`);
check("agent card returns 200", card.status === 200);
check("agent card name = business name", card.json.name === "Fadeaway Barbershop");
check("agent card carries did (x-nanda)", card.json["x-nanda"]?.did === p.did);
check("agent card auth credentials = did", card.json.authentication?.credentials === p.did);
check("agent card has a booking skill", card.json.skills?.some((s) => s.id === "book-appointment"));

// ── screen 3: try-it booking → RAW signed ARP receipt ────────────────
const bk = await route("POST", `/t/${p.tenant_id}/book`, {
  service: "Haircut",
  provider: "Fadeaway Barbershop",
  datetime: new Date(Date.now() + 864e5).toISOString(),
  notes: "smoke test",
});
check("book returns 200", bk.status === 200);
const body = bk.json;
check(`book returns booking with status '${BOOKING_STATUS}' (contract)`, body.booking && body.booking.status === BOOKING_STATUS);
check("book booking carries tenant_id", body.booking?.tenant_id === p.tenant_id);
check("book returns receipt_id == receipt.receipt_id", body.receipt_id === body.receipt?.receipt_id);

const rcpt = body.receipt;
check("receipt is raw ARP (version arp/0.1)", rcpt?.version === "arp/0.1");
check("receipt issuer_did = tenant did", rcpt?.issuer_did === p.did);
check("receipt principal_did = tenant did", rcpt?.principal_did === p.did);
check("receipt action.category = appointment_booked", rcpt?.action?.category === "appointment_booked");
check("receipt has base64 signature", typeof rcpt?.signature === "string" && rcpt.signature.length > 0);

// ── the whole point: the receipt verifies OFFLINE, and tampering breaks it ──
// The expected issuer comes from the provision response, which is the host
// speaking about itself over a different call than the one that returned the
// receipt — the same anchor the browser reads off the agent card. A different
// call from the same host: it rules out a receipt that vouches for itself, not a
// host that is not the business.
const good = await verifyReceipt(rcpt, { expectedIssuer: p.did });
check("receipt VERIFIES offline (real Ed25519)", good.ok === true && good.stage === "accepted");

const unanchored = await verifyReceipt(rcpt);
check(
  "same receipt is UNCONFIRMED with no expected issuer",
  unanchored.ok === false && unanchored.stage === "provenance" && unanchored.provenance === "unknown",
);

const strangerDid = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
const wrongIssuer = await verifyReceipt(rcpt, { expectedIssuer: strangerDid });
check(
  "receipt REFUSED against a different expected issuer",
  wrongIssuer.ok === false && wrongIssuer.provenance === "warning",
);

const tamperedSummary = structuredClone(rcpt);
tamperedSummary.action.human_summary = tamperedSummary.action.human_summary.slice(0, -1) + "X";
const badSummary = await verifyReceipt(tamperedSummary, { expectedIssuer: p.did });
check("tampered human_summary FAILS verify", badSummary.ok === false && badSummary.stage === "signature");

const tamperedSig = structuredClone(rcpt);
const s = tamperedSig.signature;
tamperedSig.signature = (s[0] === "A" ? "B" : "A") + s.slice(1);
const badSig = await verifyReceipt(tamperedSig, { expectedIssuer: p.did });
check("tampered signature FAILS verify", badSig.ok === false);

// ── error paths + health ──────────────────────────────────────────────
check("unknown tenant book → 404", (await route("POST", "/t/nope/book", { service: "a", provider: "b", datetime: "c" })).status === 404);
check("book missing fields → 400", (await route("POST", `/t/${p.tenant_id}/book`, { service: "x" })).status === 400);
// ⚠️ THIS ASSERTED 400, WHICH WAS THE MOCK'S ANSWER. The real host is FastAPI:
// an absent business_name is refused before the handler is entered, so it is a
// 422 whose `detail` is a validation ARRAY. In the suite whose stated job is
// proving this funnel speaks the real host contract, that line pinned the wrong
// side of the very difference it should have caught. The refusal contract now
// lives in tests/host_contract.json and is asserted from both sides.
const noName = await route("POST", "/provision", {});
check("missing business_name → 422 (the host's answer, not the mock's)", noName.status === 422);
check("…and its detail is a validation ARRAY", Array.isArray(noName.json.detail));
// With a valid contact, so the refusal is the name's and not the contact's.
const badName = await route("POST", "/provision", { business_name: "!!!", contact: CONTACT });
check("a name with no alphanumerics → 400, not a provisioned agent", badName.status === 400 && !badName.json.did);
check("health returns ok", (await route("GET", "/health")).json.status === "ok");

process.stdout.write(`\n${failed === 0 ? "ALL PASS" : failed + " FAILED"}\n`);
process.exit(failed === 0 ? 0 : 1);
