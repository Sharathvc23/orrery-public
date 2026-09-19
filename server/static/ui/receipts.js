// Receipt-card rendering — nodes, not an escaper (sweep).
//
// ⚠️ WHY THIS CHANGED EVEN THOUGH IT WAS NOT BROKEN. Every interpolation in the
// old `card()` WAS escaped — seven of them, correctly, in text positions. It was
// not a live vector. It was correct by discipline across seven sites in a file
// whose sibling (leaderboard) got the same discipline wrong on three, and the boot-module split's
// disposition was explicit: a live escaper invites the string-building style
// straight back. The property worth having is "no code in a rendered surface can
// turn data into markup", and that property cannot be enforced while the
// escaper-plus-template pattern remains as the local example to copy.
//
// One thing the old version did that was subtly wrong and is now impossible:
// `esc(r.signature).slice(0, 28)` truncated an ALREADY-ESCAPED string, so a
// signature containing `&` could be cut mid-entity (`&amp;` → `&am`). Harmless —
// a severed entity cannot open a tag — but it rendered corrupted text. Truncation
// now happens on the raw value before it becomes a text node.

import { el, text } from "./dom.js";

const SIGNATURE_PREVIEW = 28;
const ISSUER_PREVIEW = 14;

/** Truncate for display. Operates on the RAW value — see the module note. */
export function preview(value, limit) {
  const s = String(value ?? "");
  return s.length > limit ? `${s.slice(0, limit)}…` : s;
}

export function buildReceiptCard(doc, receipt, { verifyId } = {}) {
  const r = receipt || {};
  const action = r.action || {};
  const when = r.issued_at ? new Date(r.issued_at).toLocaleString() : "";
  const issuer = String(r.issuer_did ?? "").replace("did:key:", "");

  const children = [
    el(doc, "div", { className: "row1" }, [
      el(doc, "span", { className: "cat", text: action.category || "other" }),
      el(doc, "span", { className: "outcome", text: action.outcome || "" }),
      el(doc, "span", { className: "when", text: when }),
    ]),
    el(doc, "div", { className: "summary", text: action.human_summary || "(no summary)" }),
  ];

  if (action.counterparty_label) {
    children.push(el(doc, "div", { className: "cp", text: `↔ ${action.counterparty_label}` }));
  }

  children.push(
    el(doc, "div", { className: "sig" }, [
      el(doc, "span", {
        className: "ok",
        id: verifyId,
        text: "… verifying",
        attrs: { title: "re-verifying in your browser…" },
      }),
      el(doc, "code", { text: r.signature ? preview(r.signature, SIGNATURE_PREVIEW) : "(no signature)" }),
      el(doc, "code", { className: "issuer", text: preview(issuer, ISSUER_PREVIEW) }),
    ]),
  );

  return el(doc, "div", { className: "card" }, children);
}

export function buildReceipts(doc, receipts, { idFor } = {}) {
  const list = Array.isArray(receipts) ? receipts : [];
  if (!list.length) {
    return el(doc, "div", {
      className: "empty",
      text: "No receipts yet. POST signed receipts to /api/receipts.",
    });
  }
  return el(
    doc,
    "div",
    { className: "cards" },
    list.map((r, i) => buildReceiptCard(doc, r, { verifyId: idFor ? idFor(r, i) : undefined })),
  );
}

export function buildNotice(doc, message) {
  return el(doc, "div", { className: "empty", text: message });
}

/** The verification badge, repainted in place.
 *
 *  ⚠️ The label is chosen from a closed set — never assembled from the
 *  verification result, whose detail is issuer-controlled. Same rule as the
 *  funnel's badge in the boot-module split. */
export function paintVerdict(doc, node, verdict) {
  if (!node) return node;
  const LABELS = {
    verified: { text: "✓ verified in your browser", className: "ok verified" },
    invalid: { text: "✗ INVALID signature", className: "ok invalid" },
    unchecked: { text: "✓ signed", className: "ok unchecked" },
  };
  const spec = LABELS[verdict];
  if (!spec) return node;
  node.className = spec.className;
  node.textContent = spec.text;
  if (verdict === "unchecked") {
    node.setAttribute("title", "browser Ed25519 unavailable — server-attested");
  }
  return node;
}

export { text };
