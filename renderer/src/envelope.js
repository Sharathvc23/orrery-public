/**
 * A2UI envelope validation + version negotiation.
 *
 * The wire shape is FROZEN (docs/specs/agui.md): this module only reads it.
 * Normalization turns an untrusted payload into either
 *
 *   { ok: true, version, surfaceId, root, components: Map<id, component>,
 *     warnings: string[] }
 *
 * or a typed rejection `{ ok: false, reason, detail }` the caller can turn
 * into a deterministic fallback view. It never throws on hostile input.
 *
 * Supported wire versions:
 *   - "0.9" / "0.10" — native: { createSurface, updateComponents: { surfaceId,
 *     root, components: [{ id, component, ...fields }] }, version }
 *   - "0.8" — legacy (`?schema=v0.8`): { beginRendering: { root },
 *     surfaceUpdate: { surfaceId, components: [{ id, <Type>: {fields} }] },
 *     version }
 *
 * Envelopes whose `version` is outside SUPPORTED_VERSIONS are rejected with
 * reason "unsupported_version" — the renderer must show its fallback state,
 * never guess at an unknown schema (spec §Versioning).
 */

import { isSafeComponentId } from "./sanitize.js";

export const SUPPORTED_VERSIONS = Object.freeze(["0.8", "0.9", "0.10"]);

// Abuse caps on untrusted payloads. Generous — real surfaces are two orders
// of magnitude below these — but bounded, so a hostile envelope cannot wedge
// the tab. Overflow is a rejection, not a truncation (a partially rendered
// surface could silently hide content a full render would show).
export const MAX_COMPONENTS = 5000;
export const MAX_CHILDREN = 1000;

function reject(reason, detail) {
  return { ok: false, reason, detail: detail || "" };
}

function normalizeComponentList(rawList, warnings) {
  if (!Array.isArray(rawList)) return null;
  if (rawList.length > MAX_COMPONENTS) return null;
  const components = new Map();
  for (const entry of rawList) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      warnings.push("dropped a non-object component entry");
      continue;
    }
    const id = entry.id;
    if (!isSafeComponentId(id)) {
      warnings.push(`dropped a component with a missing/unsafe id`);
      continue;
    }
    if (components.has(id)) {
      // First occurrence wins — deterministic, and a hostile duplicate can
      // never override a component that was already declared.
      warnings.push(`duplicate component id "${id}" ignored`);
      continue;
    }
    components.set(id, entry);
  }
  return components;
}

/** Lift a v0.8 type-keyed component ({id, Text: {...}}) into the flat v0.9 shape. */
function liftV08Component(entry, warnings) {
  const keys = Object.keys(entry).filter((k) => k !== "id");
  if (keys.length !== 1) {
    warnings.push("dropped a v0.8 component without exactly one type key");
    return null;
  }
  const type = keys[0];
  const payload = entry[type];
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    warnings.push(`dropped v0.8 component "${entry.id}" with a non-object payload`);
    return null;
  }
  return { id: entry.id, component: type, ...payload };
}

/**
 * Validate + normalize one envelope. Accepts the payload as parsed JSON.
 */
export function normalizeEnvelope(payload) {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return reject("not_an_object");
  }
  // Upstream error passthrough: the agent proxy answers {"error": "..."} when
  // the org is unreachable. Surface it as a typed rejection so the UI can say
  // so instead of painting a broken page (BYOK/offline degradation rule).
  if (typeof payload.error === "string" && payload.error) {
    return reject("upstream_error", payload.error);
  }

  const version = typeof payload.version === "string" ? payload.version : "";
  if (!SUPPORTED_VERSIONS.includes(version)) {
    return reject("unsupported_version", version || "(missing)");
  }

  const warnings = [];

  if (version === "0.8") {
    const upd = payload.surfaceUpdate;
    if (upd === null || typeof upd !== "object" || Array.isArray(upd)) return reject("malformed", "surfaceUpdate missing");
    const rawList = Array.isArray(upd.components) ? upd.components : null;
    if (rawList === null) return reject("malformed", "surfaceUpdate.components missing");
    const lifted = [];
    for (const entry of rawList) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) continue;
      const flat = liftV08Component(entry, warnings);
      if (flat) lifted.push(flat);
    }
    const components = normalizeComponentList(lifted, warnings);
    if (components === null) return reject("malformed", "component list invalid or over cap");
    const root = payload.beginRendering && typeof payload.beginRendering === "object" ? payload.beginRendering.root : undefined;
    if (!isSafeComponentId(root)) return reject("malformed", "beginRendering.root missing/unsafe");
    if (!components.has(root)) return reject("malformed", `root "${root}" not in component list`);
    const surfaceId = typeof upd.surfaceId === "string" ? upd.surfaceId : "";
    return { ok: true, version, surfaceId, root, components, warnings };
  }

  // v0.9 / v0.10 native shape. The spec's normative key is `updateComponents`
  // (what every builder in this repo emits); `updateSurface` is accepted as a
  // read-side alias for envelopes produced from the older spec-doc example.
  const upd = payload.updateComponents ?? payload.updateSurface;
  if (upd === null || upd === undefined || typeof upd !== "object" || Array.isArray(upd)) {
    return reject("malformed", "updateComponents missing");
  }
  const components = normalizeComponentList(upd.components, warnings);
  if (components === null) return reject("malformed", "component list invalid or over cap");
  const root = upd.root;
  if (!isSafeComponentId(root)) return reject("malformed", "root missing/unsafe");
  if (!components.has(root)) return reject("malformed", `root "${root}" not in component list`);
  const surfaceId =
    typeof upd.surfaceId === "string"
      ? upd.surfaceId
      : payload.createSurface && typeof payload.createSurface === "object" && typeof payload.createSurface.surfaceId === "string"
        ? payload.createSurface.surfaceId
        : "";
  return { ok: true, version, surfaceId, root, components, warnings };
}
