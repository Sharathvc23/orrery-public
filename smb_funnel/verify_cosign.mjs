#!/usr/bin/env node
// smb_funnel — offline verifier for a receipt's COUNTERPARTY CO-SIGNATURE.
//
// `verify.mjs` checks the issuer's signature: that A signed this receipt. This
// checks the other half of a corroborated receipt: that the counterparty B
// signed the same interaction (spec/arp/0.2/cosign-companion.md, VRP 0.3 §A).
// Written from the spec in JavaScript over WebCrypto, so it shares no code with
// the Python producer (`sm_arp.vrp.cosign_receipt` / `is_corroborated`).
//
// What B signed: the JCS canonical bytes of the receipt with the two mutable
// signature carriers removed — the top-level `signature` and
// `evidence.witness_signatures` — and an `evidence` object left empty by that
// removal dropped. So B attests the action, the parties and the chain links,
// independent of A's signature and of any other witness.
//
// Usage:
//   node verify_cosign.mjs --witness did:key:z6Mk... path/to/receipt.json
//
// `--witness` is the counterparty's did:key from somewhere that is NOT the
// receipt — its agent card at {endpoint}/.well-known/agent.json. It must equal
// the receipt's `action.counterparty_did`: a witness who is not the named
// counterparty corroborates nothing (§A.1), and so does the issuer witnessing
// its own receipt.
//
// EXIT CODES, same scheme as verify.mjs:
//   0  VERIFIED     a witness entry by --witness verifies over the payload
//   1  FAILED       no entry by the named counterparty, or its signature does
//                   not verify (a tampered receipt lands here)
//   2  unreadable   not JSON, or no such file
//   3  UNCONFIRMED  an entry by action.counterparty_did verifies, but no
//                   --witness was supplied, so nobody checked WHO that is
//   4  MISMATCH     --witness is not the receipt's counterparty_did
//
// What this does NOT check: the issuer's signature (verify.mjs), the DAT or
// any authority, the receipt's chain position, or revocation.

import { readFileSync } from "node:fs";
import { base64Decode, canonicalizeString, publicKeyFromDidKey } from "./src/arp.js";

const argv = process.argv.slice(2);
let expectedWitness = "";
const at = argv.indexOf("--witness");
const witnessFlagGiven = at !== -1;
if (witnessFlagGiven) {
  expectedWitness = argv[at + 1] || "";
  argv.splice(at, 2);
}

function readInput() {
  const arg = argv[0];
  if (arg && arg !== "-") return readFileSync(arg, "utf8");
  return readFileSync(0, "utf8");
}

/** The bytes a counterparty signs (cosign-companion.md §1). */
export function corroborationBytes(receipt) {
  const r = structuredClone(receipt);
  delete r.signature;
  if (r.evidence && typeof r.evidence === "object" && !Array.isArray(r.evidence)) {
    delete r.evidence.witness_signatures;
    if (Object.keys(r.evidence).length === 0) delete r.evidence;
  }
  return new TextEncoder().encode(canonicalizeString(r));
}

/** Verify the witness entries signed by `witnessDid`. Returns {ok, stage, detail}. */
export async function verifyCosign(receipt, witnessDid) {
  if (!receipt || typeof receipt !== "object") return { ok: false, stage: "schema", detail: "receipt is not an object" };
  const counterparty = receipt.action?.counterparty_did;
  if (typeof counterparty !== "string" || !counterparty) {
    return { ok: false, stage: "schema", detail: "receipt names no action.counterparty_did" };
  }
  if (witnessDid !== counterparty) {
    return { ok: false, stage: "witness", detail: `witness ${witnessDid} is not the receipt's counterparty ${counterparty}` };
  }
  if (witnessDid === receipt.issuer_did) {
    return { ok: false, stage: "witness", detail: "the issuer cannot witness its own receipt" };
  }
  const entries = (receipt.evidence?.witness_signatures ?? []).filter((e) => e && e.witness_did === witnessDid);
  if (entries.length === 0) return { ok: false, stage: "witness", detail: `no witness entry by ${witnessDid}` };
  let pubkey;
  try {
    pubkey = publicKeyFromDidKey(witnessDid);
  } catch (e) {
    return { ok: false, stage: "signature", detail: `invalid witness did: ${e.message}` };
  }
  const key = await globalThis.crypto.subtle.importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
  const payload = corroborationBytes(receipt);
  for (const entry of entries) {
    let sig;
    try {
      sig = base64Decode(entry.signature);
    } catch {
      continue;
    }
    if (sig.length !== 64) continue;
    if (await globalThis.crypto.subtle.verify("Ed25519", key, sig, payload)) {
      return { ok: true, stage: "accepted", detail: "co-signature verifies" };
    }
  }
  return { ok: false, stage: "signature", detail: "Ed25519 verification of the co-signature failed" };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let parsed;
  try {
    parsed = JSON.parse(readInput());
  } catch (e) {
    process.stderr.write(`could not read/parse receipt JSON: ${e.message}\n`);
    process.exit(2);
  }
  const receipt = parsed && parsed.receipt ? parsed.receipt : parsed;
  const claimed = receipt?.action?.counterparty_did;

  if (witnessFlagGiven && expectedWitness && claimed && expectedWitness !== claimed) {
    process.stdout.write(
      `MISMATCH ✗     --witness is not this receipt's counterparty.\n` +
        `               expected --witness=${expectedWitness}\n` +
        `               receipt names counterparty_did=${claimed}\n`,
    );
    process.exit(4);
  }
  const result = await verifyCosign(receipt, expectedWitness || claimed);
  if (!result.ok) {
    process.stdout.write(`FAILED ✗       stage=${result.stage} detail=${result.detail}\n`);
    process.exit(1);
  }
  if (!expectedWitness) {
    const missing = witnessFlagGiven ? "--witness was empty" : "no --witness was given";
    process.stdout.write(
      `UNCONFIRMED ?  a co-signature by the named counterparty verifies, but ${missing} so nobody checked who that is.\n` +
        `               receipt names counterparty_did=${claimed}\n` +
        `               re-run with --witness <the counterparty's did:key from its agent card> to confirm it.\n`,
    );
    process.exit(3);
  }
  process.stdout.write(`VERIFIED ✓  co-signed by witness_did=${expectedWitness} over action=${receipt.action?.category}\n`);
  process.exit(0);
}
