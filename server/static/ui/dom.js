// Org console — DOM builders. No HTML strings, by construction.
//
// ⚠️ WHY THIS EXISTS RATHER THAN TEMPLATE LITERALS. This console renders
// agent-supplied names, task descriptions, approval payloads and receipt fields
// — every one of them written by something other than the operator reading the
// page. The boot-module split removed every path in `smb_funnel` that could turn data into
// markup, after a recovery-phrase word reached `innerHTML` unescaped four lines
// from a correctly-escaped neighbour. The same surface is here, with more
// fields and more writers, so it gets the same treatment: element and text
// nodes, and no code that can produce markup from data.
//
// The escaper approach is deliberately NOT repeated. It puts correctness on
// every future call site remembering, and the org's existing static pages show
// how that ages — `receipts/index.html` gets it right on seven interpolations
// and `leaderboard/index.html` leaves three numeric ones raw.
//
// The document is INJECTED so the real render path can be driven under a stub
// DOM that detonates on `innerHTML`, which is what makes the adversarial tests
// assertions about the node tree rather than about which helper was called.
//
// Note on duplication: `el`/`text`/`clear` are ~20 lines of generic DOM
// construction and also exist in `smb_funnel/src/render.js`. That is a
// deliberate copy, not an oversight — they carry no wire contract, so drift
// between them cannot desynchronise anything. (Contrast the domain-challenge
// path constants in `owner.py`, which MUST match nanda-connect byte for byte
// and are flagged as an unpinnable mirror precisely because they do.)

/** Create an element. `text` becomes a single text node; `children` are appended. */
export function el(doc, tag, { className, id, text, attrs, dataset } = {}, children = []) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (id) node.setAttribute("id", id);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      // Event-handler attributes are markup-adjacent code. Nothing in this
      // console needs one — listeners are attached with addEventListener, where
      // the handler is a function rather than a string the browser compiles.
      if (/^on/i.test(k)) throw new Error(`refusing to set event-handler attribute "${k}"`);
      node.setAttribute(k, String(v));
    }
  }
  if (dataset) for (const [k, v] of Object.entries(dataset)) node.setAttribute(`data-${k}`, String(v));
  if (text !== undefined && text !== null) node.appendChild(doc.createTextNode(String(text)));
  for (const child of children) if (child) node.appendChild(child);
  return node;
}

/** A bare text node — the only way data enters the tree. */
export function text(doc, value) {
  return doc.createTextNode(String(value ?? ""));
}

/** Empty an element. `textContent = ""` clears children with no HTML parsing. */
export function clear(node) {
  node.textContent = "";
}

/** Replace an element's children in one step. */
export function replace(node, children) {
  clear(node);
  for (const child of children) if (child) node.appendChild(child);
  return node;
}
