// smb_funnel — ARP receipt crypto: canonicalization, did:key, sign + verify.
//
// A dependency-free, browser-AND-Node ES module that replicates the member-SDK's
// signing/verification path (agent/community_member/arp.py +
// agent/community_member/_arp_verify/__init__.py) byte-for-byte, so a booking
// receipt returned by the real smb_host can be verified OFFLINE in the client:
//
//   canonical bytes = RFC 8785 (JCS) canonicalization of the receipt WITHOUT
//   its `signature` field, UTF-8 encoded; the base64 `signature` is an Ed25519
//   signature over those bytes under the key named by `issuer_did` (a did:key).
//
// The verifier here MUST produce the SAME accept/reject decision as Python's
// `arp.verify_receipt` for the receipts this funnel handles (arp/0.1, no
// authority chain, no previous_receipt_hash). It is exercised standalone against
// the mock (which signs with a real, in-process-generated Ed25519 key) and,
// end-to-end, against a receipt minted by the actual smb_host.
//
// Crypto backend: WebCrypto (`crypto.subtle` Ed25519) — native in Node ≥ 20 and
// in current Chrome/Safari/Firefox. No npm runtime dependency, no vendored lib.

const ARP_VERSION = "arp/0.1";
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ── WebCrypto handle (browser: globalThis.crypto; Node ≥ 20: same global) ─────

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("WebCrypto (crypto.subtle) is unavailable in this environment");
  }
  return c.subtle;
}

/** True iff this environment can do Ed25519 via WebCrypto (feature probe). */
export async function ed25519Available() {
  try {
    const kp = await subtle().generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    return !!kp;
  } catch {
    return false;
  }
}

// ── base58btc (Bitcoin alphabet) ─────────────────────────────────────────────

export function base58btcDecode(str) {
  const map = new Int16Array(128).fill(-1);
  for (let i = 0; i < BASE58_ALPHABET.length; i++) map[BASE58_ALPHABET.charCodeAt(i)] = i;

  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const value = code < 128 ? map[code] : -1;
    if (value < 0) throw new Error(`invalid base58 character ${JSON.stringify(str[i])}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's in base58 map to leading zero bytes.
  for (let i = 0; i < str.length && str[i] === "1"; i++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

export function base58btcEncode(bytes) {
  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out += "1"; // leading zeros
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}

// ── base64 (standard, with padding) ──────────────────────────────────────────

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function base64Decode(str) {
  const clean = str.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error("invalid base64");
  const lut = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) lut[B64.charCodeAt(i)] = i;
  const noPad = clean.replace(/=+$/, "");
  const out = new Uint8Array((noPad.length * 6) >> 3);
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < noPad.length; i++) {
    acc = (acc << 6) | lut[noPad.charCodeAt(i)];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

export function base64Encode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < bytes.length ? B64[b2 & 63] : "=";
  }
  return out;
}

// ── JCS canonicalization (RFC 8785) ──────────────────────────────────────────
//
// Replicates jcs.canonicalize(...) as used by arp.py. Object keys are sorted by
// UTF-16 code unit (JS default string sort == RFC 8785 for BMP keys, which is
// every key in an ARP receipt). Strings use JSON.stringify escaping (identical
// to RFC 8785 §3.2.2.2). The receipts here carry only strings and integers, for
// which JSON number serialization matches RFC 8785 exactly.

export function canonicalizeString(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("cannot canonicalize non-finite number");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalizeString).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      if (value[k] === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalizeString(value[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

/** JCS-canonical UTF-8 bytes of `receipt` with its `signature` field removed. */
export function canonicalBytesForSigning(receipt) {
  const body = {};
  for (const k of Object.keys(receipt)) {
    if (k !== "signature") body[k] = receipt[k];
  }
  return new TextEncoder().encode(canonicalizeString(body));
}

// ── did:key <-> Ed25519 public key (multicodec 0xed01 ‖ pubkey32) ────────────

export function publicKeyToDidKey(pubkey32) {
  if (pubkey32.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pubkey32, 2);
  return "did:key:z" + base58btcEncode(prefixed);
}

export function publicKeyFromDidKey(didKey) {
  if (typeof didKey !== "string" || !didKey.startsWith("did:key:z")) {
    throw new Error(`unsupported DID method: ${JSON.stringify(didKey)}`);
  }
  const decoded = base58btcDecode(didKey.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("not a did:key Ed25519 record");
  }
  return decoded.slice(2);
}

// ── verification ─────────────────────────────────────────────────────────────

/**
 * Verify one ARP receipt in three stages.
 *
 *   schema      — envelope malformations Python's JSON Schema would reject
 *   signature   — Ed25519 over JCS-canonical bytes under `issuer_did`, matching
 *                 Python `arp.verify_receipt` for the receipts this funnel
 *                 handles (arp/0.1, no authority chain, no previous hash)
 *   provenance  — is `issuer_did` the business the customer dealt with?
 *
 * The first two stages mirror the Python verifier and `stage` keeps its names for
 * parity in tests. The third has no Python counterpart because it cannot be
 * answered from the receipt: it needs `expectedIssuer`, a `did:key` the caller
 * obtained elsewhere.
 *
 * Returns { ok, stage, detail, provenance } where provenance is one of
 * "trusted" | "warning" | "unknown", the same vocabulary the member agent's
 * chapter TOFU uses (agent/community_member/trust.py) so the two describe the
 * same states in the same words.
 *
 * `ok` is true only when all three stages pass. A receipt that is internally
 * consistent but whose issuer cannot be checked is NOT verified.
 */
export async function verifyReceipt(receipt, { expectedIssuer } = {}) {
  // ── schema stage: reject malformations Python's JSON Schema would reject ──
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    return { ok: false, stage: "schema", detail: "receipt is not an object" };
  }
  if (receipt.version !== ARP_VERSION) {
    return { ok: false, stage: "schema", detail: `unsupported ARP version ${JSON.stringify(receipt.version)}` };
  }
  for (const f of ["receipt_id", "issuer_did", "principal_did", "issued_at", "signature"]) {
    if (typeof receipt[f] !== "string" || receipt[f].length === 0) {
      return { ok: false, stage: "schema", detail: `missing or invalid ${f}` };
    }
  }
  const action = receipt.action;
  if (action === null || typeof action !== "object" || Array.isArray(action)) {
    return { ok: false, stage: "schema", detail: "missing action object" };
  }
  for (const f of ["category", "human_summary", "outcome"]) {
    if (typeof action[f] !== "string" || action[f].length === 0) {
      return { ok: false, stage: "schema", detail: `missing or invalid action.${f}` };
    }
  }

  // ── signature stage: Ed25519 over canonical bytes under issuer_did ──
  let pubkey;
  try {
    pubkey = publicKeyFromDidKey(receipt.issuer_did);
  } catch (e) {
    return { ok: false, stage: "signature", detail: `invalid issuer_did: ${e.message}` };
  }
  let sig;
  try {
    sig = base64Decode(receipt.signature);
  } catch (e) {
    return { ok: false, stage: "signature", detail: `signature base64 decode failed: ${e.message}` };
  }
  if (sig.length !== 64) {
    return { ok: false, stage: "signature", detail: `signature length ${sig.length} != 64` };
  }

  let key;
  try {
    key = await subtle().importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
  } catch (e) {
    return { ok: false, stage: "signature", detail: `could not import issuer key: ${e.message}` };
  }
  const canonical = canonicalBytesForSigning(receipt);
  const ok = await subtle().verify("Ed25519", key, sig, canonical);
  if (!ok) return { ok: false, stage: "signature", detail: "Ed25519 verification failed", provenance: "unknown" };

  // ── provenance stage: whose key is it? ──
  //
  // The signature check above proves the receipt is INTERNALLY CONSISTENT —
  // whoever signed it holds the key named in `issuer_did`. It cannot prove the
  // receipt came from the business the customer dealt with, because the key and
  // the claim about whose key it is both come from the same document. Anyone can
  // mint a key, sign "paid in full" with it, and satisfy every check above.
  //
  // So the caller supplies the issuer it expects, obtained from somewhere that is
  // NOT the receipt — the tenant's A2A agent card, served by the host under the
  // tenant's own endpoint. Without one there is nothing to compare against, and
  // that is reported rather than passed: UNKNOWN PROVENANCE IS NOT VERIFIED.
  // Returning ok:true here for a self-consistent document is how a receipt signed
  // by a stranger earned a green tick.
  //
  // ⚠️ WHAT THIS STAGE DOES NOT ESTABLISH. The card and the receipt come from the
  // SAME ORIGIN, so agreeing proves the host put the key it signs with on the card
  // it serves — internal consistency, not that the host is the business. No check
  // run in the browser can close that gap, because both documents come from the
  // party under question; what closes it is how the customer reached the URL. The
  // funnel used to hold a browser-side pin (`pin.js`) that might have narrowed it
  // across sessions, but nothing on this path ever read it and the funnel mints a
  // new tenant per run, so it was removed rather than wired. See smb_funnel/README.
  if (!expectedIssuer) {
    return {
      ok: false,
      stage: "provenance",
      provenance: "unknown",
      detail: "signature is valid, but no expected issuer was supplied to check the issuer against",
    };
  }
  if (expectedIssuer !== receipt.issuer_did) {
    return {
      ok: false,
      stage: "provenance",
      provenance: "warning",
      detail: "signed by a different key than the one on this tenant's agent card",
    };
  }
  return { ok: true, stage: "accepted", provenance: "trusted", detail: "receipt verifies" };
}

/**
 * The tenant's `did:key` as published on its A2A agent card.
 *
 * This is the anchor: the card is a source independent of any RECEIPT, which is
 * what the provenance stage needs — `smb_host` builds the card with the same
 * `did:key` it returned at provisioning, and asserts that in its own tests. It is
 * not a source independent of the HOST: the same origin serves both. See the
 * provenance stage above for what that does and does not establish.
 */
export function didFromAgentCard(card) {
  if (card === null || typeof card !== "object") return "";
  const fromExt = card["x-nanda"] && card["x-nanda"].did;
  const fromAuth = card.authentication && card.authentication.credentials;
  const did = typeof fromExt === "string" && fromExt ? fromExt : fromAuth;
  return typeof did === "string" && did.startsWith("did:key:") ? did : "";
}

// ── signing (used by the mock so the same verify path is exercised) ──────────

/** Generate a fresh Ed25519 identity: { privateKey (CryptoKey), did (did:key) }. */
export async function generateIdentity() {
  const kp = await subtle().generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, did: publicKeyToDidKey(raw) };
}

/** Sign `receipt` in place with a WebCrypto Ed25519 private key; returns it. */
export async function signReceipt(receipt, privateKey) {
  const canonical = canonicalBytesForSigning(receipt);
  const sig = new Uint8Array(await subtle().sign("Ed25519", privateKey, canonical));
  receipt.signature = base64Encode(sig);
  return receipt;
}

export { ARP_VERSION };
