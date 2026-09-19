/**
 * A2UI → DOM painter.
 *
 * Safety model (docs/specs/agui.md, renderer contract): surface data is
 * UNTRUSTED. Structural guarantees this module maintains:
 *
 *   1. All surface-supplied text reaches the page exclusively through
 *      `textContent` / text nodes — never through any HTML-parsing sink
 *      (tests/source-guard.test.mjs enforces the full banned list).
 *      Markup in surface data paints as literal characters.
 *   2. The only surface-derived attribute values emitted are URLs passed
 *      through sanitize.js allowlists, and enum tokens mapped through
 *      fixed sets. No attribute NAME ever comes from surface data.
 *   3. No code path evaluates surface data (no eval/Function/timers-with-
 *      strings), and no event-handler attributes are ever set.
 *   4. Unknown component types render an inert placeholder and are skipped
 *      (spec rule 2) — never a crash, never a guess.
 *   5. Reference walks are bounded three ways, and all three are required: a
 *      cycle guard, a depth cap, and a budget on total component instances.
 *
 * Rule 5 previously read "reference walks are cycle-guarded and depth-capped, so
 * a hostile component graph terminates". Those two bounds do not terminate every
 * graph. The cycle guard is per path — `renderRef` copies `pathIds` at each
 * level, so a component is refused only when it appears on its own ancestor
 * chain — and a directed acyclic graph contains no such repeat. A chain of
 * components, each referencing the next one twice, is acyclic, at most 64 levels
 * deep, declares two children per node, and doubles the painted node count at
 * every level. Measured against this file before the budget was added:
 *
 *     components  envelope_bytes   wall_ms   nodes_painted
 *              9            619          3             511
 *             13            852         64           8,191
 *             17           1088        504         131,071
 *             19           1206       2147         524,287
 *             20           1265       4767       1,048,575
 *             21           1324       ——        heap exhausted at 2 GB after 31 s
 *
 * The budget caps how many component instances a walk may paint. It does not cap
 * how large a single component may be: a `Table` is bounded by its own 1000-row
 * by 50-cell limit, a `List` by 500 items, and so on. Those per-component caps
 * remain the only bound on one component's own size.
 *
 * The painter takes an explicit `document` so tests can drive it with a
 * recording stub (tests/stubdom.mjs) and assert the guarantees above.
 */

import { clampText, safeImageUrl, safeLinkUrl, safeToken } from "./sanitize.js";

const MAX_DEPTH = 64;

/**
 * Total component instances one surface may paint, across the whole walk.
 *
 * Set well above real use: surfaces from this org's builders run 30–100
 * components, and an envelope may declare at most MAX_COMPONENTS (5000) distinct
 * ones. The value only has to be finite to bound an exponentially expanding
 * graph, so it is chosen not to truncate honest surfaces.
 */
export const MAX_RENDERED_COMPONENTS = 20000;

const USAGE_HINTS = new Set(["h1", "h2", "h3", "h4", "body", "caption", "label"]);
const VARIANTS = new Set(["default", "primary", "secondary", "info", "success", "warning", "danger", "error"]);
const TRENDS = new Set(["up", "down", "neutral"]);
const TIERS = new Set(["newcomer", "member", "established", "trusted", "leader", "power", "core"]);
const INPUT_TYPES = new Set(["text", "email", "number", "password", "date", "url", "search", "tel"]);
const HINT_TAG = { h1: "h2", h2: "h3", h3: "h4", h4: "h5", body: "p", caption: "p", label: "p" };

function num(value, lo, hi, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, n));
}

function strList(value, max = 200) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, max).map((v) => clampText(v, 2000));
}

export class SurfaceRenderer {
  /**
   * @param {object} opts
   * @param {Document} opts.document
   * @param {(action: {surfaceId: string, componentId: string, action: string, values: object}) => void} [opts.onAction]
   * @param {(msg: string) => void} [opts.onWarn]
   */
  constructor({ document, onAction, onWarn } = {}) {
    if (!document) throw new Error("SurfaceRenderer requires a document");
    this.doc = document;
    this.onAction = typeof onAction === "function" ? onAction : null;
    this.warn = typeof onWarn === "function" ? onWarn : () => {};
    // Also set here, not only in render(), so the budget is never `undefined`:
    // a caller reaching renderRef without going through render() stays bounded.
    this.budget = MAX_RENDERED_COMPONENTS;
    this.budgetWarned = false;
  }

  /**
   * Paint a normalized envelope (envelope.js normalizeEnvelope result with
   * ok: true). Returns a detached root element for the caller to mount.
   */
  render(normalized) {
    this.surface = normalized;
    // Reset per render: the budget belongs to one paint, not to the renderer
    // instance. app.js reuses a renderer for action results.
    this.budget = MAX_RENDERED_COMPONENTS;
    this.budgetWarned = false;
    const rootEl = this.el("div", "a2ui-surface");
    rootEl.setAttribute("data-a2ui-surface", normalized.surfaceId || "");
    for (const w of normalized.warnings || []) this.warn(w);
    rootEl.appendChild(this.renderRef(normalized.root, new Set(), 0));
    return rootEl;
  }

  el(tag, className) {
    const e = this.doc.createElement(tag);
    if (className) e.className = className;
    return e;
  }

  textEl(tag, className, text) {
    const e = this.el(tag, className);
    e.textContent = clampText(text);
    return e;
  }

  placeholder(message) {
    return this.textEl("div", "a2ui-placeholder", message);
  }

  /** Render a component by id reference, with cycle + depth + budget guards. */
  renderRef(id, pathIds, depth) {
    // Every reference expansion in the painter — children(), c_Card,
    // c_Accordion, c_Tabs — reaches its child through this method, so a single
    // decrement here bounds the whole walk. A check in children() alone would
    // miss c_Card, a single-child container that expands the same way.
    //
    // Overflow truncates with a placeholder and a warning, as the depth cap
    // below does, so the cut is visible in the page. envelope.js instead rejects
    // an over-cap envelope outright: there the whole payload is still in hand,
    // and a partial render would hide content the caller could have shown.
    if (this.budget-- <= 0) {
      if (!this.budgetWarned) {
        this.budgetWarned = true;
        this.warn(`render budget of ${MAX_RENDERED_COMPONENTS} components hit — surface truncated`);
      }
      return this.placeholder("[truncated: surface too large]");
    }
    if (depth > MAX_DEPTH) {
      this.warn("depth cap hit — subtree truncated");
      return this.placeholder("[truncated: too deep]");
    }
    const comp = this.surface.components.get(id);
    if (!comp) {
      this.warn(`dangling reference "${id}"`);
      return this.placeholder("[missing component]");
    }
    if (pathIds.has(id)) {
      this.warn(`cycle at "${id}" — reference skipped`);
      return this.placeholder("[cycle detected]");
    }
    const nextPath = new Set(pathIds);
    nextPath.add(id);
    const element = this.renderComponent(comp, nextPath, depth + 1);
    element.setAttribute("data-a2ui-id", id);
    return element;
  }

  children(comp, pathIds, depth, parent, max = 1000) {
    const refs = Array.isArray(comp.children) ? comp.children.slice(0, max) : [];
    for (const ref of refs) {
      if (typeof ref !== "string") continue;
      parent.appendChild(this.renderRef(ref, pathIds, depth));
    }
    return parent;
  }

  renderComponent(comp, pathIds, depth) {
    const type = typeof comp.component === "string" ? comp.component : "";
    const fn = this[`c_${type}`];
    if (typeof fn !== "function") {
      this.warn(`unknown component type "${clampText(type, 60)}" skipped`);
      return this.textEl("div", "a2ui-unknown", `[unsupported component: ${clampText(type, 60) || "?"}]`);
    }
    return fn.call(this, comp, pathIds, depth);
  }

  // ── Layout ──────────────────────────────────────────────────────

  c_Card(c, p, d) {
    const e = this.el("div", "a2ui-card");
    if (typeof c.child === "string") e.appendChild(this.renderRef(c.child, p, d));
    return e;
  }

  c_Column(c, p, d) {
    return this.children(c, p, d, this.el("div", "a2ui-column"));
  }

  c_Row(c, p, d) {
    return this.children(c, p, d, this.el("div", "a2ui-row"));
  }

  c_Grid(c, p, d) {
    const e = this.children(c, p, d, this.el("div", "a2ui-grid"));
    const cols = num(c.cols, 1, 8, 3);
    if (e.style) e.style.gridTemplateColumns = `repeat(${cols}, minmax(0, 1fr))`;
    return e;
  }

  c_Divider() {
    return this.el("hr", "a2ui-divider");
  }

  // ── Display ─────────────────────────────────────────────────────

  c_Text(c) {
    const hint = safeToken(c.usageHint, USAGE_HINTS, "body");
    return this.textEl(HINT_TAG[hint], `a2ui-text a2ui-hint-${hint}`, c.text);
  }

  c_Heading(c) {
    const lvl = num(c.level, 1, 6, 2);
    // Shift down one: the page's own <h1> is the renderer chrome.
    return this.textEl(`h${Math.min(6, lvl + 1)}`, `a2ui-heading a2ui-heading-${lvl}`, c.text);
  }

  c_Markdown(c) {
    return renderMarkdown(this, typeof c.text === "string" ? c.text : typeof c.content === "string" ? c.content : "");
  }

  c_Badge(c) {
    const variant = safeToken(c.variant, VARIANTS, "default");
    return this.textEl("span", `a2ui-badge a2ui-variant-${variant}`, c.text);
  }

  c_Progress(c) {
    const value = num(c.value, 0, 100, 0);
    const e = this.el("div", "a2ui-progress");
    if (typeof c.label === "string" && c.label) e.appendChild(this.textEl("span", "a2ui-progress-label", c.label));
    const track = this.el("div", "a2ui-progress-track");
    const bar = this.el("div", "a2ui-progress-bar");
    if (bar.style) bar.style.width = `${value}%`;
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-valuenow", String(value));
    track.appendChild(bar);
    e.appendChild(track);
    return e;
  }

  c_Metric(c) {
    const e = this.el("div", "a2ui-metric");
    const trend = safeToken(c.trend, TRENDS, "neutral");
    e.appendChild(this.textEl("div", `a2ui-metric-value a2ui-trend-${trend}`, `${clampText(c.value, 200)}${clampText(c.suffix, 40)}`));
    e.appendChild(this.textEl("div", "a2ui-metric-label", c.label));
    return e;
  }

  c_Stat(c) {
    const e = this.el("div", "a2ui-stat");
    e.appendChild(this.textEl("div", "a2ui-stat-value", c.value));
    e.appendChild(this.textEl("div", "a2ui-stat-label", c.label));
    return e;
  }

  c_StatGroup(c) {
    const e = this.el("div", "a2ui-statgroup");
    for (const item of Array.isArray(c.items) ? c.items.slice(0, 50) : []) {
      if (item === null || typeof item !== "object") continue;
      e.appendChild(this.c_Metric({ value: item.value, label: item.label, suffix: item.suffix, trend: item.trend }));
    }
    return e;
  }

  c_List(c) {
    const e = this.el(c.ordered === true ? "ol" : "ul", "a2ui-list");
    for (const item of strList(c.items, 500)) e.appendChild(this.textEl("li", "", item));
    return e;
  }

  c_Avatar(c) {
    const e = this.el("div", "a2ui-avatar");
    const src = safeImageUrl(c.imageUrl);
    if (src) {
      const img = this.el("img", "a2ui-avatar-img");
      img.setAttribute("src", src);
      img.setAttribute("alt", clampText(c.name, 200));
      e.appendChild(img);
    } else {
      const initials = clampText(c.name, 80)
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((w) => w[0].toUpperCase())
        .join("");
      e.appendChild(this.textEl("span", "a2ui-avatar-initials", initials || "?"));
    }
    const meta = this.el("div", "a2ui-avatar-meta");
    meta.appendChild(this.textEl("div", "a2ui-avatar-name", c.name));
    if (typeof c.subtitle === "string" && c.subtitle) meta.appendChild(this.textEl("div", "a2ui-avatar-subtitle", c.subtitle));
    e.appendChild(meta);
    return e;
  }

  c_Alert(c) {
    const variant = safeToken(c.variant, VARIANTS, "default");
    const e = this.el("div", `a2ui-alert a2ui-variant-${variant}`);
    if (typeof c.title === "string" && c.title) e.appendChild(this.textEl("div", "a2ui-alert-title", c.title));
    e.appendChild(this.textEl("div", "a2ui-alert-message", c.message));
    return e;
  }

  c_Callout(c) {
    const variant = safeToken(c.variant, VARIANTS, "info");
    const e = this.el("div", `a2ui-callout a2ui-variant-${variant}`);
    if (typeof c.title === "string" && c.title) e.appendChild(this.textEl("div", "a2ui-callout-title", c.title));
    e.appendChild(this.textEl("div", "a2ui-callout-text", c.text));
    return e;
  }

  c_Toast(c) {
    return this.c_Alert({ title: c.title, message: c.message, variant: c.variant });
  }

  c_Link(c) {
    const a = this.textEl("a", "a2ui-link", c.text || c.url || "link");
    a.setAttribute("href", safeLinkUrl(c.url));
    // Never hand a surface-authored destination the opener, and keep
    // link-juice neutral for generated content.
    a.setAttribute("rel", "noopener noreferrer nofollow");
    a.setAttribute("target", "_blank");
    return a;
  }

  c_Image(c) {
    const src = safeImageUrl(c.url);
    if (!src) return this.textEl("div", "a2ui-image-blocked", `[image blocked${c.alt ? `: ${clampText(c.alt, 200)}` : ""}]`);
    const img = this.el("img", "a2ui-image");
    img.setAttribute("src", src);
    img.setAttribute("alt", clampText(c.alt, 500));
    img.setAttribute("loading", "lazy");
    const w = num(c.width, 1, 4000, 0);
    const h = num(c.height, 1, 4000, 0);
    if (w) img.setAttribute("width", String(w));
    if (h) img.setAttribute("height", String(h));
    return img;
  }

  c_CodeBlock(c) {
    const pre = this.el("pre", "a2ui-codeblock");
    const code = this.textEl("code", "", c.code);
    if (typeof c.language === "string" && /^[\w+-]{1,30}$/.test(c.language)) {
      code.setAttribute("data-language", c.language);
    }
    pre.appendChild(code);
    return pre;
  }

  c_Accordion(c, p, d) {
    const e = this.el("div", "a2ui-accordion");
    for (const section of Array.isArray(c.sections) ? c.sections.slice(0, 100) : []) {
      if (section === null || typeof section !== "object") continue;
      const details = this.el("details", "a2ui-accordion-section");
      if (section.defaultOpen === true) details.setAttribute("open", "");
      details.appendChild(this.textEl("summary", "", section.title));
      if (typeof section.childId === "string") details.appendChild(this.renderRef(section.childId, p, d));
      e.appendChild(details);
    }
    return e;
  }

  c_Tabs(c, p, d) {
    // Reference rendering: tabs paint as stacked titled sections. An id-
    // referenced child (childId) and inline text content are both accepted.
    const e = this.el("div", "a2ui-tabs");
    for (const tab of Array.isArray(c.tabs) ? c.tabs.slice(0, 50) : []) {
      if (tab === null || typeof tab !== "object") continue;
      const section = this.el("section", "a2ui-tab");
      section.appendChild(this.textEl("div", "a2ui-tab-label", tab.label ?? tab.title ?? ""));
      if (typeof tab.childId === "string") section.appendChild(this.renderRef(tab.childId, p, d));
      else if (typeof tab.content === "string") section.appendChild(this.textEl("div", "", tab.content));
      e.appendChild(section);
    }
    return e;
  }

  c_Table(c) {
    const wrap = this.el("div", "a2ui-table-wrap");
    const table = this.el("table", "a2ui-table");
    if (typeof c.caption === "string" && c.caption) table.appendChild(this.textEl("caption", "", c.caption));
    const headers = strList(c.headers, 50);
    if (headers.length) {
      const thead = this.el("thead", "");
      const tr = this.el("tr", "");
      for (const h of headers) tr.appendChild(this.textEl("th", "", h));
      thead.appendChild(tr);
      table.appendChild(thead);
    }
    const tbody = this.el("tbody", "");
    for (const row of Array.isArray(c.rows) ? c.rows.slice(0, 1000) : []) {
      const tr = this.el("tr", "");
      for (const cell of strList(row, 50)) tr.appendChild(this.textEl("td", "", cell));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  c_TrustBadge(c) {
    const tier = safeToken(c.tier, TIERS, "newcomer");
    const score = num(c.score, 0, 100, 0);
    return this.textEl("span", `a2ui-trustbadge a2ui-tier-${tier}`, `${tier} · ${score}`);
  }

  c_Timeline(c) {
    const e = this.el("ol", "a2ui-timeline");
    for (const entry of Array.isArray(c.entries) ? c.entries.slice(0, 500) : []) {
      if (entry === null || typeof entry !== "object") continue;
      const li = this.el("li", "a2ui-timeline-entry");
      li.appendChild(this.textEl("span", "a2ui-timeline-ts", entry.timestamp));
      li.appendChild(this.textEl("span", "a2ui-timeline-title", entry.title));
      if (typeof entry.body === "string" && entry.body) li.appendChild(this.textEl("div", "a2ui-timeline-body", entry.body));
      e.appendChild(li);
    }
    return e;
  }

  c_MemberCard(c) {
    const e = this.el("div", "a2ui-membercard");
    e.appendChild(this.c_Avatar({ name: c.name, subtitle: c.subtitle, imageUrl: c.avatarUrl }));
    const meta = this.el("div", "a2ui-membercard-meta");
    if (typeof c.agentId === "string" && c.agentId) meta.appendChild(this.textEl("div", "a2ui-membercard-agentid", `@${clampText(c.agentId, 200)}`));
    if (typeof c.role === "string" && c.role) meta.appendChild(this.textEl("div", "a2ui-membercard-role", c.role));
    if (typeof c.trustScore === "number" && Number.isFinite(c.trustScore)) {
      meta.appendChild(this.c_TrustBadge({ score: c.trustScore, tier: undefined }));
    }
    const skills = strList(c.skills, 12);
    if (skills.length) {
      const row = this.el("div", "a2ui-membercard-skills");
      for (const s of skills) row.appendChild(this.textEl("span", "a2ui-badge a2ui-variant-secondary", s));
      meta.appendChild(row);
    }
    e.appendChild(meta);
    return e;
  }

  // ── Interactive ─────────────────────────────────────────────────

  labeled(c, control) {
    const wrap = this.el("label", "a2ui-field");
    if (typeof c.label === "string" && c.label) wrap.appendChild(this.textEl("span", "a2ui-field-label", c.label));
    wrap.appendChild(control);
    return wrap;
  }

  c_Input(c) {
    const input = this.el("input", "a2ui-input");
    input.setAttribute("type", safeToken(c.inputType, INPUT_TYPES, "text"));
    input.setAttribute("name", typeof c.id === "string" ? c.id : "");
    if (typeof c.placeholder === "string") input.setAttribute("placeholder", clampText(c.placeholder, 500));
    if (typeof c.value === "string") input.setAttribute("value", clampText(c.value, 2000));
    return this.labeled(c, input);
  }

  c_TextArea(c) {
    const ta = this.el("textarea", "a2ui-textarea");
    ta.setAttribute("name", typeof c.id === "string" ? c.id : "");
    ta.setAttribute("rows", String(num(c.rows, 1, 40, 3)));
    if (typeof c.placeholder === "string") ta.setAttribute("placeholder", clampText(c.placeholder, 500));
    ta.textContent = clampText(c.value, 20000);
    return this.labeled(c, ta);
  }

  c_Select(c) {
    const select = this.el("select", "a2ui-select");
    select.setAttribute("name", typeof c.id === "string" ? c.id : "");
    for (const opt of Array.isArray(c.options) ? c.options.slice(0, 200) : []) {
      if (opt === null || typeof opt !== "object") continue;
      const o = this.textEl("option", "", opt.label ?? opt.value ?? "");
      o.setAttribute("value", clampText(opt.value ?? opt.label ?? "", 500));
      if (c.value !== undefined && c.value === opt.value) o.setAttribute("selected", "");
      select.appendChild(o);
    }
    return this.labeled(c, select);
  }

  c_Toggle(c) {
    const input = this.el("input", "a2ui-toggle");
    input.setAttribute("type", "checkbox");
    input.setAttribute("name", typeof c.id === "string" ? c.id : "");
    if (c.checked === true) input.setAttribute("checked", "");
    return this.labeled(c, input);
  }

  c_Chip(c) {
    const e = this.textEl("span", `a2ui-chip${c.selected === true ? " a2ui-chip-selected" : ""}`, c.label);
    return e;
  }

  c_ChipGroup(c, p, d) {
    return this.children(c, p, d, this.el("div", "a2ui-chipgroup"));
  }

  c_ActionButton(c) {
    const btn = this.textEl("button", `a2ui-button a2ui-variant-${safeToken(c.variant, VARIANTS, "default")}`, c.label || "Submit");
    btn.setAttribute("type", "button");
    this.bindAction(btn, c, () => ({ ...(c.data !== null && typeof c.data === "object" && !Array.isArray(c.data) ? c.data : {}) }));
    return btn;
  }

  c_Form(c, p, d) {
    const form = this.children(c, p, d, this.el("form", "a2ui-form"));
    const submit = this.textEl("button", "a2ui-button a2ui-variant-primary", clampText(c.submitLabel, 200) || "Submit");
    submit.setAttribute("type", "submit");
    form.appendChild(submit);
    if (typeof form.addEventListener === "function") {
      form.addEventListener("submit", (ev) => {
        if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
        this.emitAction(c, collectFormValues(form));
      });
    }
    return form;
  }

  bindAction(el, comp, valueFn) {
    if (typeof el.addEventListener !== "function") return;
    el.addEventListener("click", () => this.emitAction(comp, valueFn()));
  }

  emitAction(comp, values) {
    if (!this.onAction) return;
    const action = typeof comp.action === "string" ? comp.action.slice(0, 200) : "";
    this.onAction({
      surfaceId: this.surface.surfaceId || "",
      componentId: typeof comp.id === "string" ? comp.id : "",
      action,
      values: values || {},
    });
  }
}

/** Gather named control values from a rendered form (browser path only). */
function collectFormValues(form) {
  const values = {};
  if (typeof form.querySelectorAll !== "function") return values;
  for (const el of form.querySelectorAll("input[name], textarea[name], select[name]")) {
    const name = el.getAttribute("name");
    if (!name) continue;
    values[name] = el.type === "checkbox" ? el.checked : el.value;
  }
  return values;
}

// ── Safe mini-markdown ────────────────────────────────────────────
//
// Renders the small markdown subset org surfaces actually use — headings,
// bullets, fenced code, bold/italic/inline code, links — by constructing
// DOM nodes directly. Raw HTML in the source is NOT parsed; it paints as
// literal text. Link destinations pass through safeLinkUrl.

function renderMarkdown(r, source) {
  const container = r.el("div", "a2ui-markdown");
  const lines = clampText(source, 100000).split("\n").slice(0, 2000);
  let paragraph = [];
  let listEl = null;
  let codeLines = null;

  const flushParagraph = () => {
    if (paragraph.length) {
      const p = r.el("p", "");
      renderInline(r, p, paragraph.join(" "));
      container.appendChild(p);
      paragraph = [];
    }
  };
  const flushList = () => {
    if (listEl) {
      container.appendChild(listEl);
      listEl = null;
    }
  };

  for (const line of lines) {
    if (codeLines !== null) {
      if (/^\s*```/.test(line)) {
        const pre = r.el("pre", "a2ui-codeblock");
        pre.appendChild(r.textEl("code", "", codeLines.join("\n")));
        container.appendChild(pre);
        codeLines = null;
      } else {
        codeLines.push(line);
      }
      continue;
    }
    if (/^\s*```/.test(line)) {
      flushParagraph();
      flushList();
      codeLines = [];
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      const level = Math.min(6, heading[1].length + 1);
      const h = r.el(`h${level}`, "a2ui-md-heading");
      renderInline(r, h, heading[2]);
      container.appendChild(h);
      continue;
    }
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      flushParagraph();
      if (!listEl) listEl = r.el("ul", "a2ui-list");
      const li = r.el("li", "");
      renderInline(r, li, bullet[1]);
      listEl.appendChild(li);
      continue;
    }
    if (/^\s*$/.test(line)) {
      flushParagraph();
      flushList();
      continue;
    }
    flushList();
    paragraph.push(line);
  }
  if (codeLines !== null) {
    const pre = r.el("pre", "a2ui-codeblock");
    pre.appendChild(r.textEl("code", "", codeLines.join("\n")));
    container.appendChild(pre);
  }
  flushParagraph();
  flushList();
  return container;
}

const INLINE_RE = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]{1,500}\]\([^)\s]{1,2000}\))/;

function renderInline(r, parent, text) {
  let rest = text;
  let guard = 0;
  while (rest && guard++ < 500) {
    const m = INLINE_RE.exec(rest);
    if (!m) break;
    if (m.index > 0) parent.appendChild(r.doc.createTextNode(rest.slice(0, m.index)));
    const tok = m[0];
    if (tok.startsWith("**")) {
      parent.appendChild(r.textEl("strong", "", tok.slice(2, -2)));
    } else if (tok.startsWith("`")) {
      parent.appendChild(r.textEl("code", "", tok.slice(1, -1)));
    } else if (tok.startsWith("*")) {
      parent.appendChild(r.textEl("em", "", tok.slice(1, -1)));
    } else {
      const link = /^\[([^\]]*)\]\(([^)]*)\)$/.exec(tok);
      const a = r.textEl("a", "a2ui-link", link[1]);
      a.setAttribute("href", safeLinkUrl(link[2]));
      a.setAttribute("rel", "noopener noreferrer nofollow");
      a.setAttribute("target", "_blank");
      parent.appendChild(a);
    }
    rest = rest.slice(m.index + tok.length);
  }
  if (rest) parent.appendChild(r.doc.createTextNode(rest));
}
