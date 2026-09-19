#!/usr/bin/env node
// smb_funnel — offline receipt verifier CLI.
//
// Verifies a raw ARP receipt with the SAME code path the browser funnel uses
// (src/arp.js): JCS-canonicalize the receipt sans signature, then Ed25519-verify
// the base64 signature under `issuer_did`. Produces the same accept/reject as the
// member-SDK's `arp.verify_receipt`.
//
// Usage:
//   node verify.mjs --issuer did:key:z6Mk... path/to/receipt.json
//   node verify.mjs --issuer did:key:z6Mk... path/to/book_response.json
//   curl -s .../book | node verify.mjs --issuer did:key:z6Mk...
//
// `--issuer` is the business's did:key, obtained from somewhere that is NOT the
// receipt — its agent card at {endpoint}/.well-known/agent.json, or however you
// were given it. Without it the signature can still be checked, but nothing can
// confirm WHO signed, and the exit code says so: a receipt anyone minted with
// their own key satisfies every other check.
//
// EXIT CODES. Four outcomes, not two, and REFUSED never shares one with
// UNCHECKED — the whole job of this tool is to tell a person which it is:
//
//   0  VERIFIED     signature good, and it was made by --issuer
//   1  FAILED       the document is not what it says (schema, or the signature
//                   does not verify — a tampered receipt lands here)
//   2  unreadable   not JSON, or no such file
//   3  UNCONFIRMED  signature good, but no --issuer was supplied to check it
//                   against, so nobody checked WHO signed
//   4  MISMATCH     signature good, and made by a key that is not --issuer
//
// A caller that only distinguishes zero from non-zero is still correct.

import { readFileSync } from "node:fs";
import { verifyReceipt } from "./src/arp.js";

const argv = process.argv.slice(2);
let expectedIssuer = "";
const issuerAt = argv.indexOf("--issuer");
// Whether the FLAG was present, kept apart from whether it carried a value: the
// unconfirmed message tells the operator what to do next, and "no --issuer was
// given" is the wrong instruction for someone who gave `--issuer ""`.
const issuerFlagGiven = issuerAt !== -1;
if (issuerFlagGiven) {
  expectedIssuer = argv[issuerAt + 1] || "";
  argv.splice(issuerAt, 2);
}

function readInput() {
  const arg = argv[0];
  if (arg && arg !== "-") return readFileSync(arg, "utf8");
  return readFileSync(0, "utf8"); // stdin
}

let parsed;
try {
  parsed = JSON.parse(readInput());
} catch (e) {
  process.stderr.write(`could not read/parse receipt JSON: ${e.message}\n`);
  process.exit(2);
}

// Accept either a bare receipt or a smb_host book response {booking, receipt}.
const receipt = parsed && parsed.receipt ? parsed.receipt : parsed;

const result = await verifyReceipt(receipt, { expectedIssuer });
if (result.ok) {
  process.stdout.write(`VERIFIED ✓  issuer_did=${receipt.issuer_did} action=${receipt.action?.category}\n`);
  process.exit(0);
}
// ⚠️ THE OUTCOME IS DECIDED ON `stage`, NEVER ON `provenance`, AND THIS LINE IS
// THE WHOLE BUG THIS FILE ONCE HAD. `verifyReceipt` returns provenance:"unknown"
// for TWO unrelated outcomes — a signature that FAILED, and a signature that
// passed with no expected issuer supplied — because in neither case is there
// anything to say about whose key it is. Branching on provenance first collapsed
// them, so a TAMPERED receipt printed "the signature is valid, but no --issuer
// was given" and exited 3, byte-identical to an honest unchecked one. An
// operator was told the opposite of what happened, by the one tool whose entire
// job is to tell them whether to trust the document.
//
// `stage` says WHERE the verdict was reached and does not have that ambiguity:
// only stage "provenance" means the signature itself was good.
if (result.stage === "provenance") {
  if (result.provenance === "warning") {
    process.stdout.write(
      `MISMATCH ✗     the signature is valid, but it was made with a DIFFERENT key than --issuer.\n` +
        `               expected --issuer=${expectedIssuer}\n` +
        `               receipt claims issuer_did=${receipt.issuer_did}\n` +
        `               a key rotation, or someone else's receipt. This tool cannot tell which.\n`,
    );
    process.exit(4);
  }
  // Both halves of the condition are checked rather than one inferred from the
  // other: "the flag was present" does not by itself mean "and it was empty",
  // and an instruction that does not fit what the operator actually typed sends
  // them round the same loop again.
  const missing = issuerFlagGiven && !expectedIssuer ? "--issuer was empty" : "no --issuer was given";
  process.stdout.write(
    `UNCONFIRMED ?  the signature is valid, but ${missing} so nobody checked who signed it.\n` +
      `               receipt claims issuer_did=${receipt.issuer_did}\n` +
      `               re-run with --issuer <the business's did:key> to confirm it.\n`,
  );
  process.exit(3);
}
// Everything else: the document is not what it says. A tampered receipt is here.
process.stdout.write(`FAILED ✗       stage=${result.stage} detail=${result.detail}\n`);
process.exit(1);
