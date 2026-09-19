/**
 * Just enough Document to boot `src/app.js` outside a browser.
 *
 * ⚠️ WHY THIS EXISTS RATHER THAN A THIRD SET OF UNIT TESTS. The defect this
 * harness was built for (the funnel computed a localStorage pin, never read it,
 * and the UI cited it as a control) was invisible to a suite that imported the
 * module and drove it directly: the module worked. What was wrong was the
 * WIRING. So the assertion has to run the app's own submit and click handlers
 * and read the badge the app painted, which needs a document.
 *
 * It extends the reference renderer's recording stub rather than replacing it,
 * so every element the funnel builds still detonates on `innerHTML`,
 * `outerHTML`, `insertAdjacentHTML` and `on*` attributes. Adding a DOM for the
 * app to run in must not quietly remove the trap the render tests rely on.
 *
 * The element registry is built FROM `index.html`, not from a hand-written list:
 * a selector the app queries that the shipped document does not define resolves
 * to null here exactly as it would in a browser, instead of being invented by
 * the fixture.
 */

import { readFileSync } from "node:fs";

import { StubDocument, StubElement } from "../../renderer/tests/stubdom.mjs";

class FunnelElement extends StubElement {
  constructor(doc, tagName) {
    super(doc, tagName);
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.title = "";
  }

  /** No child lookup is modelled: `[data-autofocus]` legitimately finds nothing. */
  querySelector() {
    return null;
  }

  focus() {}
  reset() {}
  remove() {}
}

class FunnelDocument extends StubDocument {
  constructor(ids) {
    super();
    this.listeners = {};
    this.elements = new Map();
    this.body = new FunnelElement(this, "body");
    for (const id of ids) this.elements.set(`#${id}`, new FunnelElement(this, "div"));
  }

  createElement(tagName) {
    const el = new FunnelElement(this, tagName);
    this.created.push(el);
    return el;
  }

  querySelector(selector) {
    return this.elements.get(selector) ?? null;
  }

  /** `#creating-steps li` — the progress list, which no assertion here reads. */
  querySelectorAll() {
    return [];
  }

  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }
}

/** Every `id="…"` the shipped funnel document defines. */
export function idsFromIndexHtml() {
  const html = readFileSync(new URL("../index.html", import.meta.url).pathname, "utf8");
  return [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
}

/** A document carrying the shipped page's ids, installed as `globalThis.document`. */
export function installDocument() {
  const doc = new FunnelDocument(idsFromIndexHtml());
  globalThis.document = doc;
  return doc;
}

/**
 * Fire one listener the app registered on `selector`, and await it.
 *
 * The app's handlers are async, so returning the promise is what makes the test
 * deterministic — polling for a rendered badge would pass on a slow machine and
 * on a broken one alike.
 */
export function fire(doc, selector, type, event = {}) {
  const el = doc.querySelector(selector);
  if (!el) throw new Error(`no element for ${selector} — index.html does not define it`);
  const handlers = el.listeners[type] || [];
  if (handlers.length === 0) throw new Error(`app.js registered no ${type} handler on ${selector}`);
  return Promise.all(handlers.map((fn) => fn({ preventDefault() {}, ...event })));
}

/** The verification badge the app painted, found the way a user's eye would. */
export function verifyBadge(doc) {
  return doc.created.filter((el) => el.getAttribute("id") === "verify-badge").pop() ?? null;
}
