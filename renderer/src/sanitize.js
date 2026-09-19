/**
 * Sanitizers for untrusted surface data.
 *
 * Everything in an A2UI envelope is untrusted input (docs/specs/agui.md,
 * "Renderer contract" rule 5): a surface may have been composed by an LLM
 * from attacker-influenced intent text, or relayed from a remote org. The
 * renderer's only defense is structural — text is only ever painted via
 * text nodes (see render.js), and the few attribute values we do emit
 * (URLs, class tokens) pass through the allowlists below.
 */

// Schemes a Link may navigate to. Everything else — javascript:, vbscript:,
// data:, blob:, file:, custom app schemes — is blocked.
const LINK_SCHEMES = new Set(["http:", "https:", "mailto:"]);

// Image sources: network fetches plus inline raster data URIs. data: is safe
// here (an <img> never executes its source document), but only for image
// MIME types — data:text/html or data:image/svg+xml must not survive to a
// context where they could be opened as a document.
const IMAGE_SCHEMES = new Set(["http:", "https:"]);
const IMAGE_DATA_RE = /^data:image\/(png|jpe?g|gif|webp|avif);base64,[a-z0-9+/=]+$/i;

const BLOCKED = "about:blank#blocked";

/**
 * Strip ASCII control characters and whitespace that browsers ignore when
 * parsing a URL scheme (`java\tscript:` parses as javascript:).
 */
function preclean(raw) {
  return String(raw).replace(/[\u0000-\u0020\u007f]/g, "");
}

function schemeOf(cleaned) {
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(cleaned);
  return m ? `${m[1].toLowerCase()}:` : null;
}

/**
 * Return a URL safe to place in an <a href>. Relative URLs (no scheme) are
 * allowed — they resolve against the page serving the renderer, which the
 * surface author does not control. Anything with a scheme outside the
 * allowlist becomes an inert placeholder, never silently dropped, so a
 * hostile link is visibly defanged rather than invisibly rewritten.
 */
export function safeLinkUrl(raw) {
  if (typeof raw !== "string" || raw === "") return BLOCKED;
  const cleaned = preclean(raw);
  // A protocol-relative URL (//host) keeps the page scheme — acceptable.
  const scheme = schemeOf(cleaned);
  if (scheme === null) return cleaned;
  return LINK_SCHEMES.has(scheme) ? cleaned : BLOCKED;
}

/**
 * Return a URL safe to place in an <img src>, or null to render the
 * component's textual fallback (alt / initials) instead.
 */
export function safeImageUrl(raw) {
  if (typeof raw !== "string" || raw === "") return null;
  const cleaned = preclean(raw);
  const scheme = schemeOf(cleaned);
  if (scheme === null) return cleaned;
  if (IMAGE_SCHEMES.has(scheme)) return cleaned;
  if (scheme === "data:" && IMAGE_DATA_RE.test(cleaned)) return cleaned;
  return null;
}

/**
 * Map an untrusted enum-ish field (usageHint, variant, trend, tier...) onto
 * a class-name token. Only values in `allowed` pass; anything else gets the
 * fallback. Class names are never concatenated from raw surface data — a
 * hostile `variant: "x\" onmouseover=..."` can therefore never reach markup.
 */
export function safeToken(raw, allowed, fallback) {
  return typeof raw === "string" && allowed.has(raw) ? raw : fallback;
}

/**
 * Component ids come from the wire and are used as Map keys and data-
 * attribute values. Reject ids that could collide with Object prototype
 * plumbing or blow up selectors/logs. (We use Map, not plain objects, for
 * the component index — this is defense in depth, not the primary guard.)
 */
const ID_RE = /^[\w][\w.:-]{0,199}$/;
export function isSafeComponentId(raw) {
  return typeof raw === "string" && ID_RE.test(raw) && raw !== "__proto__" && raw !== "constructor" && raw !== "prototype";
}

/** Clamp untrusted text to a sane length so a hostile envelope can't wedge the tab. */
export function clampText(raw, max = 20000) {
  const s = typeof raw === "string" ? raw : raw == null ? "" : String(raw);
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
