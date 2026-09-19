/**
 * RFC 6902 JSON Patch — the subset AG-UI StateDelta events carry
 * (server/agui_streaming.py emits add / replace / remove ops).
 *
 * Hardening rules (docs/specs/agui.md §Malformed deltas):
 *   - A delta is validated BEFORE anything is applied. If any op is
 *     malformed, or any op fails to apply, the WHOLE delta is rejected and
 *     the input document is returned untouched — a delta never half-applies.
 *   - Application is pure: the input document is never mutated; a rejected
 *     delta therefore cannot corrupt renderer state.
 *   - Paths that would write through object prototype plumbing
 *     (__proto__ / constructor / prototype) are rejected outright.
 */

const OPS = new Set(["add", "replace", "remove"]);
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** RFC 6901 pointer → array of unescaped reference tokens; null if invalid. */
export function parsePointer(path) {
  if (typeof path !== "string") return null;
  if (path === "") return [];
  if (!path.startsWith("/")) return null;
  return path
    .slice(1)
    .split("/")
    .map((tok) => tok.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * Validate the delta payload shape. Returns { ok: true } or
 * { ok: false, detail } without touching any document.
 */
export function validateDelta(delta) {
  if (!Array.isArray(delta)) return { ok: false, detail: "delta is not an array" };
  if (delta.length > 1000) return { ok: false, detail: "delta over op cap" };
  for (let i = 0; i < delta.length; i++) {
    const op = delta[i];
    if (op === null || typeof op !== "object" || Array.isArray(op)) {
      return { ok: false, detail: `op[${i}] is not an object` };
    }
    if (!OPS.has(op.op)) return { ok: false, detail: `op[${i}] has unsupported op "${op.op}"` };
    const tokens = parsePointer(op.path);
    if (tokens === null) return { ok: false, detail: `op[${i}] has an invalid path` };
    if (tokens.some((t) => FORBIDDEN_KEYS.has(t))) {
      return { ok: false, detail: `op[${i}] path touches prototype plumbing` };
    }
    if ((op.op === "add" || op.op === "replace") && !("value" in op)) {
      return { ok: false, detail: `op[${i}] ${op.op} is missing "value"` };
    }
    if (op.op === "remove" && tokens.length === 0) {
      return { ok: false, detail: `op[${i}] cannot remove the whole document` };
    }
  }
  return { ok: true };
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

/** Walk to the parent container of the pointer target. Returns null on any miss. */
function resolveParent(doc, tokens) {
  let node = doc;
  for (let i = 0; i < tokens.length - 1; i++) {
    const tok = tokens[i];
    if (Array.isArray(node)) {
      const idx = /^(0|[1-9]\d*)$/.test(tok) ? Number(tok) : NaN;
      if (!Number.isInteger(idx) || idx >= node.length) return null;
      node = node[idx];
    } else if (node !== null && typeof node === "object") {
      if (!Object.prototype.hasOwnProperty.call(node, tok)) return null;
      node = node[tok];
    } else {
      return null;
    }
  }
  return node;
}

function applyOne(doc, op, tokens) {
  if (tokens.length === 0) {
    // Whole-document replace/add — the shape agui_streaming.diff_surfaces
    // actually emits ({op: "replace", path: "", value: <new surface>}).
    return { ok: true, doc: clone(op.value) };
  }
  const parent = resolveParent(doc, tokens);
  if (parent === null || parent === undefined) return { ok: false };
  const last = tokens[tokens.length - 1];

  if (Array.isArray(parent)) {
    if (op.op === "add" && last === "-") {
      parent.push(clone(op.value));
      return { ok: true, doc };
    }
    if (!/^(0|[1-9]\d*)$/.test(last)) return { ok: false };
    const idx = Number(last);
    if (op.op === "add") {
      if (idx > parent.length) return { ok: false };
      parent.splice(idx, 0, clone(op.value));
    } else if (op.op === "replace") {
      if (idx >= parent.length) return { ok: false };
      parent[idx] = clone(op.value);
    } else {
      if (idx >= parent.length) return { ok: false };
      parent.splice(idx, 1);
    }
    return { ok: true, doc };
  }

  if (parent !== null && typeof parent === "object") {
    const exists = Object.prototype.hasOwnProperty.call(parent, last);
    if (op.op === "replace" && !exists) return { ok: false };
    if (op.op === "remove") {
      if (!exists) return { ok: false };
      delete parent[last];
    } else {
      parent[last] = clone(op.value);
    }
    return { ok: true, doc };
  }
  return { ok: false };
}

/**
 * Apply a StateDelta to a document. Returns
 *   { ok: true, doc: <new document> }        — all ops applied, input untouched
 *   { ok: false, detail }                    — rejected atomically
 */
export function applyDelta(doc, delta) {
  const valid = validateDelta(delta);
  if (!valid.ok) return valid;
  let work = clone(doc);
  for (let i = 0; i < delta.length; i++) {
    const op = delta[i];
    const tokens = parsePointer(op.path);
    const res = applyOne(work, op, tokens);
    if (!res.ok) return { ok: false, detail: `op[${i}] (${op.op} ${op.path}) failed to apply` };
    work = res.doc;
  }
  return { ok: true, doc: work };
}
