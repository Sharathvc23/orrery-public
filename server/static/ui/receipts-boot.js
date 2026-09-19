// Receipts wiring: client-side Ed25519 re-verification + fetch.
//
// The crypto below is carried over UNCHANGED from the page's inline script — it
// re-checks every receipt's signature in YOUR browser (base58 did:key → pubkey,
// JCS canonical bytes, Web Crypto verify) rather than on the server's word. Only
// the RENDERING moved out, into receipts.js, so node can drive it under a stub
// DOM. Rewriting verified crypto while fixing a markup bug would be two changes
// wearing one commit.

import { replace } from "./dom.js";
import { buildNotice, buildReceipts, paintVerdict } from "./receipts.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58decode(s) {
  let bytes = [0];
  for (const ch of s) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error("bad base58");
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (let k = 0; k < s.length && s[k] === "1"; k++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
// JCS (RFC 8785) for the receipt value space (ASCII strings, ints, bools, null,
// nested) — recursively sort object keys; JSON.stringify matches.
function jcs(v) {
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  return JSON.stringify(v);
}
async function verifyReceipt(r) {
  try {
    if (!(crypto.subtle && crypto.subtle.importKey)) return null; // unsupported
    const body = {};
    for (const k of Object.keys(r)) if (k !== "signature") body[k] = r[k];
    const msg = new TextEncoder().encode(jcs(body));
    const pub = base58decode(r.issuer_did.slice("did:key:z".length)).slice(2); // strip 0xed01
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64ToBytes(r.signature), msg);
  } catch {
    return null;
  }
}

const list = document.getElementById("list");
const count = document.getElementById("count");

async function load() {
  try {
    const resp = await fetch("/api/receipts/recent?limit=200");
    if (resp.status === 404) {
      count.textContent = "";
      replace(list, [
        buildNotice(
          document,
          "This chapter is not in offline mode — receipts are served only via the authenticated /api/receipts.",
        ),
      ]);
      return;
    }
    const data = await resp.json();
    const rs = data.receipts || [];
    count.textContent = `${rs.length} receipt${rs.length === 1 ? "" : "s"} in the chapter Issuer Log`;
    replace(list, [buildReceipts(document, rs, { idFor: (_r, i) => `verify-${i}` })]);

    // Re-verify each signature client-side and repaint its badge. The label is
    // chosen from a closed set inside paintVerdict — never assembled from the
    // result, whose detail is issuer-controlled.
    for (let i = 0; i < rs.length; i++) {
      const badge = document.getElementById(`verify-${i}`);
      if (!badge) continue;
      const ok = await verifyReceipt(rs[i]);
      paintVerdict(document, badge, ok === true ? "verified" : ok === false ? "invalid" : "unchecked");
    }
  } catch {
    count.textContent = "";
    replace(list, [buildNotice(document, "Could not reach the chapter. Is it running?")]);
  }
}

document.getElementById("refresh")?.addEventListener("click", load);
load();
