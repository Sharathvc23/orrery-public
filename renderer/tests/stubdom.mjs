/**
 * Minimal recording DOM stub for node --test.
 *
 * Implements exactly the Document subset render.js is allowed to use, and
 * BOOBY-TRAPS the dangerous surface: any read/write of innerHTML/outerHTML,
 * any insertAdjacentHTML call, and any attribute whose name starts with
 * "on" throws — so if the renderer ever grows an HTML-parsing or handler-
 * attribute code path, the whole suite detonates, not just one assertion.
 */

export class StubElement {
  constructor(doc, tagName) {
    this.ownerDocument = doc;
    this.tagName = tagName.toLowerCase();
    this.childNodes = [];
    this.attributes = {};
    this.className = "";
    this.style = {};
    this.listeners = {};
    this._text = null;

    Object.defineProperty(this, "innerHTML", {
      get() {
        throw new Error(`forbidden: innerHTML read on <${tagName}>`);
      },
      set() {
        throw new Error(`forbidden: innerHTML write on <${tagName}>`);
      },
    });
    Object.defineProperty(this, "outerHTML", {
      get() {
        throw new Error(`forbidden: outerHTML read on <${tagName}>`);
      },
      set() {
        throw new Error(`forbidden: outerHTML write on <${tagName}>`);
      },
    });
  }

  insertAdjacentHTML() {
    throw new Error(`forbidden: insertAdjacentHTML on <${this.tagName}>`);
  }

  appendChild(node) {
    this.childNodes.push(node);
    this.ownerDocument.appended.push(node);
    return node;
  }

  setAttribute(name, value) {
    if (/^on/i.test(name)) throw new Error(`forbidden: event-handler attribute "${name}"`);
    this.attributes[name] = String(value);
    this.ownerDocument.attributesSet.push({ tag: this.tagName, name, value: String(value) });
  }

  getAttribute(name) {
    return name in this.attributes ? this.attributes[name] : null;
  }

  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }

  set textContent(value) {
    this._text = String(value);
    this.childNodes = [{ nodeType: 3, data: this._text }];
  }

  get textContent() {
    if (this._text !== null && this.childNodes.length === 1 && this.childNodes[0].nodeType === 3) return this._text;
    return this.childNodes.map((n) => (n.nodeType === 3 ? n.data : n.textContent ?? "")).join("");
  }
}

export class StubDocument {
  constructor() {
    this.created = [];
    this.appended = [];
    this.attributesSet = [];
    this.textNodes = [];
  }

  createElement(tagName) {
    const el = new StubElement(this, tagName);
    this.created.push(el);
    return el;
  }

  createTextNode(data) {
    const node = { nodeType: 3, data: String(data) };
    this.textNodes.push(node);
    return node;
  }

  write() {
    throw new Error("forbidden: document.write");
  }
}

/** Depth-first walk of a stub tree, elements only. */
export function* walk(el) {
  yield el;
  for (const child of el.childNodes || []) {
    if (child instanceof StubElement) yield* walk(child);
  }
}

/** All text content in a tree, concatenated (text nodes only — never parsed). */
export function allText(el) {
  let out = "";
  for (const node of walk(el)) {
    for (const child of node.childNodes || []) {
      if (child.nodeType === 3) out += child.data;
    }
  }
  return out;
}
