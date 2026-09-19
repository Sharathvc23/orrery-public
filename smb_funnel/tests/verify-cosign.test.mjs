/**
 * `verify_cosign.mjs` — the counterparty co-signature, checked by a second
 * implementation, and what its CLI tells a person.
 *
 * The receipts here are built and co-signed IN JAVASCRIPT over WebCrypto, so
 * the suite proves the verifier against the spec's payload rule
 * (spec/arp/0.2/cosign-companion.md §1: JCS of the receipt minus `signature`
 * and minus `evidence.witness_signatures`, an emptied `evidence` dropped) and
 * not against its own producer. Agreement with the Python producer
 * (`sm_arp.vrp.cosign_receipt`) is asserted where a real receipt exists —
 * scripts/demo_two_agents.sh runs this CLI over one — and pinned by the
 * checked-in fixture below, which was co-signed by that producer.
 *
 * Every outcome the tool can reach is asserted by PRINTED LINE and EXIT CODE,
 * for the reason verify-cli.test.mjs gives: a wrapper that reports the wrong
 * verdict with the right library underneath is the failure mode to guard.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { before } from "node:test";
import { promisify } from "node:util";

import { base64Encode, generateIdentity, signReceipt } from "../src/arp.js";
import { corroborationBytes, verifyCosign } from "../verify_cosign.mjs";

const CLI = new URL("../verify_cosign.mjs", import.meta.url).pathname;
const run = promisify(execFile);

async function cli(...args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args]);
    return { code: 0, out: stdout + stderr };
  } catch (e) {
    return { code: e.code, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

let dir;
let issuer;
let witness;
let stranger;
let corroborated;

/** B's half of the handshake, done here in JS: sign the corroboration payload. */
async function cosign(receipt, identity) {
  const sig = await globalThis.crypto.subtle.sign("Ed25519", identity.privateKey, corroborationBytes(receipt));
  return { witness_did: identity.did, signature: base64Encode(new Uint8Array(sig)) };
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "verify-cosign-"));
  issuer = await generateIdentity();
  witness = await generateIdentity();
  stranger = await generateIdentity();

  const unsigned = {
    version: "arp/0.1",
    receipt_id: "11111111-2222-3333-4444-555555555555",
    issuer_did: issuer.did,
    principal_did: issuer.did,
    issued_at: "2026-09-19T00:00:00Z",
    action: {
      category: "message_sent",
      human_summary: "Called Agent B (save_note).",
      outcome: "completed",
      counterparty_did: witness.did,
      counterparty_label: "Agent B",
    },
  };
  // Order as the issuer does it: the witness signs first, then the issuer
  // signs the whole receipt including the witness entry.
  const entry = await cosign(unsigned, witness);
  unsigned.evidence = { witness_signatures: [entry] };
  corroborated = await signReceipt(unsigned, issuer.privateKey);
  writeFileSync(join(dir, "corroborated.json"), JSON.stringify(corroborated));

  const flipped = JSON.parse(JSON.stringify(corroborated));
  flipped.action.human_summary = "Called Agent B (install_skill).";
  writeFileSync(join(dir, "flipped.json"), JSON.stringify(flipped));

  const unwitnessed = JSON.parse(JSON.stringify(corroborated));
  delete unwitnessed.evidence;
  writeFileSync(join(dir, "unwitnessed.json"), JSON.stringify(unwitnessed));
});

// ── the payload rule ───────────────────────────────────────────────────────

test("the corroboration payload excludes the issuer signature and the witness entries, and drops an emptied evidence", () => {
  const withEvidence = JSON.parse(JSON.stringify(corroborated));
  const bytes = new TextDecoder().decode(corroborationBytes(withEvidence));
  assert.ok(!bytes.includes('"signature"'), "issuer signature must not be signed over");
  assert.ok(!bytes.includes("witness_signatures"), "witness entries must not be signed over");
  assert.ok(!bytes.includes('"evidence"'), "an evidence object emptied by the removal is dropped");
  // The receipt object itself is not mutated.
  assert.ok(withEvidence.signature && withEvidence.evidence.witness_signatures.length === 1);
});

test("verifyCosign accepts the counterparty's co-signature and rejects everyone else's", async () => {
  assert.equal((await verifyCosign(corroborated, witness.did)).ok, true);
  const r = await verifyCosign(corroborated, stranger.did);
  assert.equal(r.ok, false);
  assert.equal(r.stage, "witness");
  const self = JSON.parse(JSON.stringify(corroborated));
  self.action.counterparty_did = issuer.did;
  assert.equal((await verifyCosign(self, issuer.did)).stage, "witness", "the issuer cannot witness its own receipt");
});

// ── the CLI, by printed line and exit code ─────────────────────────────────

test("VERIFIED, exit 0, with --witness from the counterparty's card", async () => {
  const r = await cli("--witness", witness.did, join(dir, "corroborated.json"));
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /^VERIFIED ✓/);
  assert.ok(r.out.includes(witness.did));
});

test("a flipped byte: FAILED stage=signature, exit 1", async () => {
  const r = await cli("--witness", witness.did, join(dir, "flipped.json"));
  assert.equal(r.code, 1);
  assert.match(r.out, /^FAILED ✗\s+stage=signature/);
});

test("no witness entry: FAILED stage=witness, exit 1", async () => {
  const r = await cli("--witness", witness.did, join(dir, "unwitnessed.json"));
  assert.equal(r.code, 1);
  assert.match(r.out, /^FAILED ✗\s+stage=witness/);
});

test("no --witness: UNCONFIRMED, exit 3 — never mistaken for VERIFIED", async () => {
  const r = await cli(join(dir, "corroborated.json"));
  assert.equal(r.code, 3);
  assert.match(r.out, /^UNCONFIRMED \?/);
  assert.ok(r.out.includes("no --witness was given"));
});

test("--witness that is not the receipt's counterparty: MISMATCH, exit 4", async () => {
  const r = await cli("--witness", stranger.did, join(dir, "corroborated.json"));
  assert.equal(r.code, 4);
  assert.match(r.out, /^MISMATCH ✗/);
});

test("unreadable input: exit 2", async () => {
  const r = await cli("--witness", witness.did, join(dir, "no-such-file.json"));
  assert.equal(r.code, 2);
});

// ── agreement with the Python producer, pinned by fixture ──────────────────

test("a receipt co-signed by the Python producer (sm_arp.vrp.cosign_receipt) verifies here", async () => {
  const fixture = JSON.parse(
    new TextDecoder().decode(
      await import("node:fs/promises").then((fs) => fs.readFile(new URL("./fixtures/cosigned-by-python.json", import.meta.url))),
    ),
  );
  const r = await cli("--witness", fixture.action.counterparty_did, new URL("./fixtures/cosigned-by-python.json", import.meta.url).pathname);
  assert.equal(r.code, 0, r.out);
});
