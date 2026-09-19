/**
 * The mock answers what the real host answers — refusals included.
 *
 * ⚠️ THE CLAIM THIS EXISTS TO MAKE TRUE. `README.md` says the funnel "speaks the
 * real host contract either way", and that claim is what makes a demo on the mock
 * evidence of anything. It was false on every refusal:
 *
 *   POST /provision {}      host: 422, detail an ARRAY   mock: 400, {error: "…"}
 *   business_name ""        host: 422, detail an ARRAY   mock: 400, {error: "…"}
 *   business_name "!!!"     host: 400                    mock: 201 — IT PROVISIONED
 *   business_name 5         host: 422                    mock: 201 — IT PROVISIONED
 *
 * The last two are the ones that matter: the mock was not differently-worded, it
 * was more PERMISSIVE. A barber typing `!!!` into the demo got a did:key and a
 * recovery phrase to write down, for input the product refuses. A mock that is
 * softer than the thing it stands in for produces confidence, not evidence.
 *
 * ⚠️ AND `smoke.mjs` PINNED THE WRONG SIDE. It asserted `missing business_name →
 * 400`, which is the MOCK's answer, in the suite whose stated job is proving the
 * funnel speaks the real contract. A parity suite that reads its expectations off
 * one of the two things it is comparing cannot fail.
 *
 * So the expectations live in `host_contract.json`, measured from the host, and
 * are asserted from BOTH sides — `smb_host/test_main.py` drives the real host
 * against the same file. Neither can drift without the other going red.
 *
 * Classification: CONTRACT (parity).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { provision, route } from "../src/mock_core.js";

const contract = JSON.parse(readFileSync(new URL("./host_contract.json", import.meta.url).pathname, "utf8"));

/** Assert one response against one contract entry — the same checks both sides make. */
function assertMatches(res, expected, label) {
  assert.equal(res.status, expected.status, `${label}: status`);
  const detail = res.json && res.json.detail;

  if (expected.detail === "string") {
    assert.equal(typeof detail, "string", `${label}: detail must be a string, got ${typeof detail}`);
    assert.equal(detail, expected.message, `${label}: message`);
    return;
  }

  assert.ok(Array.isArray(detail), `${label}: detail must be an array, got ${typeof detail}`);
  assert.ok(detail.length >= 1, `${label}: empty validation array`);
  assert.deepEqual(detail[0].loc, expected.loc, `${label}: loc`);
  assert.equal(detail[0].type, expected.type, `${label}: type`);
  // `msg` is the framework's wording and is deliberately NOT pinned — pinning it
  // would make a FastAPI upgrade look like a contract break.
  assert.equal(typeof detail[0].msg, "string", `${label}: msg`);
}

test("no refusal in this mock answers with the {error: …} shape", () => {
  /** The whole family in one assertion: `smb_host` is FastAPI and every refusal
   * it makes is `{detail: …}`. A client reading `error` reads nothing from the
   * real host — which is exactly what the funnel did until it was fixed. */
  const source = readFileSync(new URL("../src/mock_core.js", import.meta.url).pathname, "utf8");
  const bodies = source.match(/json:\s*\{[^}]*\}/g) || [];
  assert.ok(bodies.length > 3, `expected several response bodies, found ${bodies.length}`);
  for (const body of bodies) {
    assert.ok(!/\berror\s*:/.test(body), `a mock response still answers with {error: …}: ${body}`);
  }
});

test("POST /provision refuses exactly what the host refuses", async () => {
  for (const c of contract.provision) {
    if (c.provision_first) {
      const first = await provision(c.body);
      assert.equal(first.status, 201, `${c.case}: the setup provision should succeed`);
    }
    const res = await provision(c.body);
    assertMatches(res, c, `provision / ${c.case}`);
  }
});

test("⚠️ the mock does not provision names the host refuses", async () => {
  /** THE DEFECT, STATED ON ITS OWN because it is not a formatting difference.
   * These returned 201 with a tenant_id, an endpoint, a did:key and a 24-word
   * recovery phrase for input the product rejects outright. */
  // ⚠️ THE EXPECTED STATUS, NOT MERELY "not 201". A first draft asserted
  // notEqual(201) and passed for the wrong reason: an earlier case in the same
  // file had already taken the tenant id, so the mock answered 409 and the
  // assertion was satisfied by a collision rather than by a refusal.
  const expected = [
    [{ contact: "https://bookings.example/hook", business_name: "!!!" }, 400],
    [{ contact: "https://bookings.example/hook", business_name: "..." }, 400],
    [{ contact: "https://bookings.example/hook", business_name: "   " }, 400],
    [{ contact: "https://bookings.example/hook", business_name: 5 }, 422],
  ];
  for (const [body, status] of expected) {
    const res = await provision(body);
    assert.equal(res.status, status, `the mock answered ${res.status} for ${JSON.stringify(body)}`);
    assert.ok(!res.json.did, "a refusal must not carry an identity");
    assert.ok(!res.json.recovery_phrase, "a refusal must not hand out a recovery phrase");
    assert.ok(!res.json.tenant_id, "a refusal must not name a tenant");
  }
});

test("the card and booking refusals match the host too", async () => {
  const live = await provision({ contact: "https://bookings.example/hook", business_name: "Parity Test Co" });
  assert.equal(live.status, 201);
  const tenant = live.json.tenant_id;

  for (const c of contract.card) {
    const res = await route("GET", `/t/${c.tenant_id}/.well-known/agent.json`);
    assertMatches(res, c, `card / ${c.case}`);
  }
  for (const c of contract.book) {
    const res = await route("POST", `/t/${c.tenant_id || tenant}/book`, c.body);
    assertMatches(res, c, `book / ${c.case}`);
  }
  const unknown = await route("GET", contract.unknown_route.path);
  assertMatches(unknown, contract.unknown_route, "unknown route");
});

test("the honest path is untouched — a real name still provisions", async () => {
  /** A mock that refuses everything matches no host and demos nothing. This is
   * what keeps the assertions above from being satisfied by breaking it. */
  const res = await provision({ contact: "https://bookings.example/hook", business_name: "Fadeaway Barbershop II" });

  assert.equal(res.status, 201);
  assert.match(res.json.did, /^did:key:z6Mk/);
  assert.equal(res.json.recovery_phrase.split(" ").length, 24);
  assert.equal(res.json.tenant_id, "fadeaway-barbershop-ii");
});

test("the contract file is read, not assumed", () => {
  /** Guards the guard: an unreadable or emptied fixture would make every loop
   * above iterate zero times and pass. */
  assert.ok(contract.provision.length >= 6, `only ${contract.provision.length} provision cases`);
  assert.ok(contract.book.length >= 3);
  assert.ok(contract.card.length >= 1);
  assert.ok(
    contract.provision.some((c) => c.detail === "array") && contract.provision.some((c) => c.detail === "string"),
    "the contract must cover both detail shapes, or the shape check is vacuous",
  );
});

test("the mock reports a delivery outcome, because the host always does", async () => {
  /**
   * ⚠️ PARITY ON THE SUCCESS PATH, NOT ONLY ON REFUSALS. `smb_host` puts
   * `delivered`, `delivery_channel` and — when it did not land — `delivery_note`
   * on every `/book` response, so a caller can tell a delivered booking from one
   * the business will never see. This mock omitted all three, which made it the
   * permissive side again: the funnel could not have reported delivery on the
   * demo backend even once it started reading the fields, and `API_BASE = "mock"`
   * is the default at the public front door.
   *
   * The mock delivers nothing, so the honest answer is `false` with a note
   * saying why — NOT silence, and not `true`. A mock that claimed delivery would
   * be the success-screen version of provisioning a name the host refuses.
   */
  const live = await provision({ contact: "https://bookings.example/hook", business_name: "Delivery Parity Co" });
  assert.equal(live.status, 201);

  const res = await route("POST", `/t/${live.json.tenant_id}/book`, {
    service: "Haircut",
    provider: "Stellar Barbers",
    datetime: "2026-09-01T10:00:00Z",
  });
  assert.equal(res.status, 200);
  assert.equal(typeof res.json.delivered, "boolean", "the mock states no delivery outcome");
  assert.equal(res.json.delivered, false, "the in-page mock delivers nothing and must not claim otherwise");
  assert.equal(res.json.delivery_channel, "none");
  assert.match(res.json.delivery_note, /\S/, "an undelivered booking must carry the reason");
});

// ── the success path's one shared value ──────────────────────────────────────
//
// ⚠️ WHY THIS IS THE DELIVERABLE AND THE RENAME IS NOT. `booking.status` was a
// literal held twice: `smb_host` assigned it, this mock constructed it, and each
// side's suite asserted its own copy. Two copies of a wire value with no shared
// statement is precisely how the mock became MORE PERMISSIVE than the host on
// the refusal path — and there, the parity suite read its expectation off one of
// the two things it was comparing, so it could not fail. Renaming the value
// without fixing that leaves the next divergence just as invisible.
//
// So the value is stated ONCE, in host_contract.json, and both sides are held to
// it: this file drives the mock, and `smb_host/test_main.py` drives the real
// host. Editing the file wakes both suites — the CI filter runs the smb_host job
// when this contract changes — so neither side can move alone.

test("the mock produces the booking status the contract states", async () => {
  const live = await provision({ contact: "https://bookings.example/hook", business_name: "Status Parity Co" });
  assert.equal(live.status, 201);

  const res = await route("POST", `/t/${live.json.tenant_id}/book`, {
    service: "Haircut",
    provider: "Stellar Barbers",
    datetime: "2026-09-01T10:00:00Z",
  });
  assert.equal(res.status, 200);
  assert.equal(
    res.json.booking.status,
    contract.book_success.booking_status,
    "the mock's booking status has drifted from the contract",
  );
});

test("the host assigns the booking status the contract states", () => {
  /**
   * ⚠️ THE OTHER SIDE, READ FROM ITS SOURCE — and this test exists because of a
   * gap in the interlock rather than out of distrust. Editing the contract wakes
   * both suites, and a mock change wakes this one, but a change to
   * `smb_host/main.py` ALONE does not re-run the funnel job: the CI filter for
   * this suite matches `smb_funnel/`. So one direction of the pair has no
   * cross-check at the moment the drift is introduced.
   *
   * Reading the host's assigned literal closes it. This is read-only — the
   * funnel does not import, execute or modify `smb_host`, which stays out of
   * bounds for this subtree; it reads one line of its source the way the
   * attestation guard reads `owner.py`'s.
   *
   * If this fails after a legitimate refactor of that line, the fix is to make
   * the host read `book_success.booking_status` from the contract too, not to
   * loosen the pattern here.
   */
  const hostSrc = readFileSync(new URL("../../smb_host/main.py", import.meta.url).pathname, "utf8");
  const assigned = [...hostSrc.matchAll(/booking\["status"\]\s*=\s*"([^"]+)"/g)].map((m) => m[1]);

  assert.ok(
    assigned.length >= 1,
    "no `booking[\"status\"] = \"...\"` assignment found in smb_host/main.py — this guard is reading nothing",
  );
  for (const value of assigned) {
    assert.equal(
      value,
      contract.book_success.booking_status,
      `smb_host assigns booking.status = "${value}" but the contract states ` +
        `"${contract.book_success.booking_status}" — the host and the mock would disagree`,
    );
  }
});

test("the rename did not eat the receipt badge's vocabulary", () => {
  /**
   * ⚠️ THE HAZARD IN THIS PARTICULAR RENAME. The funnel uses the word
   * "confirmed" in a second, unrelated sense: the verification badge's
   * "Signature valid — issuer not confirmed", which is about a RECEIPT'S ISSUER
   * and has nothing to do with a booking's status. A sweep over the word would
   * have rewritten a load-bearing label that `provenance.test.mjs` and
   * `wiring.test.mjs` both pin, and the booking rename would have looked clean
   * while quietly changing what the badge claims.
   *
   * Pinned here so the two vocabularies stay separable by name.
   */
  const render = readFileSync(new URL("../src/render.js", import.meta.url).pathname, "utf8");
  assert.match(render, /issuer not confirmed/, "the badge's unknown-provenance label lost its wording");
  assert.ok(
    !/status:\s*"confirmed"/.test(render),
    "a booking status literal came back into the render path",
  );
});
