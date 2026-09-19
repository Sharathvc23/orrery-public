/**
 * The CLI verifier's REPORTING — what a person is told, and what a script reads.
 *
 * ⚠️ THE DEFECT THIS SUITE EXISTS FOR. `verify.mjs` branched on
 * `result.provenance === "unknown"` before it looked at `result.stage`.
 * `verifyReceipt` returns provenance "unknown" for TWO unrelated outcomes — a
 * signature that FAILED, and a signature that passed with no expected issuer to
 * check it against — because in neither case is there anything to say about
 * whose key it is. Branching on provenance first collapsed them, so a TAMPERED
 * receipt printed:
 *
 *     UNCONFIRMED ?  the signature is valid, but no --issuer was given …
 *
 * byte-identical to an honest receipt nobody had checked, and exited 3 alongside
 * it. The library was right the whole time; the wrapper reported the opposite of
 * what happened, in the one tool whose entire job is to tell a person whether to
 * trust a document.
 *
 * ⚠️ WHY NOTHING CAUGHT IT. `provenance.test.mjs` covers `verifyReceipt` and is
 * green — it tests the library, and the library was never wrong. The e2e script
 * runs the CLI over a tampered receipt, but as `>/dev/null 2>&1 && die || ok`:
 * it asserts the exit was NON-ZERO and discards every byte of what the operator
 * was told. Two suites, both green, neither looking at the output. So this one
 * runs the real binary as a subprocess and asserts THE PRINTED LINE and THE EXIT
 * CODE for every outcome the tool can reach.
 *
 * Classification: ADVERSARIAL (a trust decision reported to a human).
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";
import { promisify } from "node:util";

import { generateIdentity, signReceipt } from "../src/arp.js";

const CLI = new URL("../verify.mjs", import.meta.url).pathname;
const run = promisify(execFile);

let dir;
let business;
let stranger;

/** Run the CLI and report what a caller actually sees: output and exit code. */
async function verify(...args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args]);
    return { code: 0, out: stdout + stderr };
  } catch (e) {
    return { code: e.code, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "verify-cli-"));
  business = await generateIdentity();
  stranger = await generateIdentity();

  const honest = await signReceipt(
    {
      version: "arp/0.1",
      receipt_id: "11111111-2222-3333-4444-555555555555",
      issuer_did: business.did,
      principal_did: business.did,
      issued_at: "2026-08-18T12:00:00Z",
      action: {
        category: "appointment_booked",
        human_summary: "Booked Haircut with Fadeaway Barbershop",
        outcome: "completed",
      },
    },
    business.privateKey,
  );
  writeFileSync(join(dir, "honest.json"), JSON.stringify(honest));

  // One word changed after signing — the shape a real tamper takes.
  const tampered = JSON.parse(JSON.stringify(honest));
  tampered.action.human_summary = "Booked Haircut with Fadeaway Barbershop and PAID IN FULL";
  writeFileSync(join(dir, "tampered.json"), JSON.stringify(tampered));

  // A book response, since the CLI accepts {booking, receipt} as well.
  writeFileSync(join(dir, "response.json"), JSON.stringify({ booking: { status: "recorded" }, receipt: honest }));

  writeFileSync(join(dir, "garbage.json"), "not json at all");
});

after(() => {
  // Left in the OS temp dir; nothing here is a secret and the OS reaps it.
});

test("(a) an honest receipt with the right --issuer verifies, and exits 0", async () => {
  /** A verifier that refuses everything passes every adversarial test below and
   * is worth nothing. This is the assertion that keeps the rest meaningful. */
  const { code, out } = await verify(join(dir, "honest.json"), "--issuer", business.did);

  assert.equal(code, 0);
  assert.match(out, /^VERIFIED/m);
  assert.match(out, new RegExp(business.did));
});

test("(b) an honest receipt with the WRONG --issuer is a mismatch, not a failure", async () => {
  /** The signature really is valid here; only the identity is wrong. Saying
   * "verification failed" would send someone looking for a corrupted file. */
  const { code, out } = await verify(join(dir, "honest.json"), "--issuer", stranger.did);

  assert.equal(code, 4, "a mismatched issuer must not share an exit code with a bad document");
  assert.match(out, /^MISMATCH/m);
  assert.match(out, /DIFFERENT key/);
  assert.doesNotMatch(out, /^UNCONFIRMED/m);
  assert.doesNotMatch(out, /no --issuer was given/);
});

test("(c) an honest receipt with no --issuer is unconfirmed, and exits 3", async () => {
  const { code, out } = await verify(join(dir, "honest.json"));

  assert.equal(code, 3);
  assert.match(out, /^UNCONFIRMED/m);
  assert.match(out, /the signature is valid/);
  assert.match(out, /no --issuer was given/);
});

test("(d) ⚠️ A TAMPERED RECEIPT WITH --issuer SAYS FAILED, NOT 'the signature is valid'", async () => {
  /** THE REPORTED DEFECT. This printed the (c) message verbatim and exited 3. */
  const { code, out } = await verify(join(dir, "tampered.json"), "--issuer", business.did);

  assert.equal(code, 1, "a tampered receipt must not exit 3 — that code means nobody checked");
  assert.match(out, /^FAILED/m);
  assert.match(out, /stage=signature/);
  assert.doesNotMatch(out, /the signature is valid/, "a tampered receipt was reported as validly signed");
  assert.doesNotMatch(out, /^UNCONFIRMED/m);
});

test("(e) a tampered receipt with no --issuer says the same thing", async () => {
  /** The anchor is irrelevant to a broken signature: the document is not what it
   * says, whoever it claims to be from. */
  const { code, out } = await verify(join(dir, "tampered.json"));

  assert.equal(code, 1);
  assert.match(out, /^FAILED/m);
  assert.doesNotMatch(out, /the signature is valid/);
});

test("the five outcomes are five distinct messages and codes", async () => {
  /** ⚠️ THE ASSERTION THAT WOULD HAVE CAUGHT IT WITH NO KNOWLEDGE OF THE CAUSE.
   * (c) and (d) printed the SAME BYTES and the SAME EXIT CODE. Any two outcomes
   * a reader cannot tell apart are one outcome, however the code is written. */
  const seen = [
    await verify(join(dir, "honest.json"), "--issuer", business.did),
    await verify(join(dir, "honest.json"), "--issuer", stranger.did),
    await verify(join(dir, "honest.json")),
    await verify(join(dir, "tampered.json"), "--issuer", business.did),
    await verify(join(dir, "garbage.json")),
  ];

  const codes = seen.map((r) => r.code);
  assert.equal(new Set(codes).size, seen.length, `outcomes share an exit code: ${codes.join(",")}`);

  const headlines = seen.map((r) => r.out.split(/\s/)[0]);
  assert.equal(new Set(headlines).size, seen.length, `outcomes share a headline: ${headlines.join(",")}`);
});

test("an empty --issuer is not reported as no --issuer", async () => {
  /** The instruction has to fit what the operator did, or they will follow it and
   * see the identical message again. */
  const { code, out } = await verify(join(dir, "honest.json"), "--issuer", "");

  assert.equal(code, 3);
  assert.match(out, /--issuer was empty/);
  assert.doesNotMatch(out, /no --issuer was given/);
});

test("a book response verifies the receipt inside it", async () => {
  /** The documented curl-into-stdin shape. Kept here because the outcome table
   * above is only meaningful if the tool reads what the README says it reads. */
  const { code, out } = await verify(join(dir, "response.json"), "--issuer", business.did);

  assert.equal(code, 0);
  assert.match(out, /^VERIFIED/m);
});

test("an unreadable file exits 2 and claims nothing about a signature", async () => {
  const { code, out } = await verify(join(dir, "garbage.json"));

  assert.equal(code, 2);
  assert.match(out, /could not read\/parse/);
  assert.doesNotMatch(out, /VERIFIED|UNCONFIRMED|the signature is valid/);
});
