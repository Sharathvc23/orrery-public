/**
 * Browser wiring for the reference renderer page.
 *
 * Degradation ladder (docs/specs/agui.md §Generation, trust & degradation —
 * "never a broken or empty page"):
 *   1. live AG-UI stream (snapshot + deltas)
 *   2. stream unavailable → deterministic one-shot GET /api/surfaces/{page}
 *   3. that too unavailable / upstream {"error": ...} → an explicit offline
 *      state with a retry affordance
 * None of these paths require an LLM key: the deterministic surfaces are
 * built server-side from real org/agent state.
 */

import { normalizeEnvelope } from "./envelope.js";
import { SurfaceRenderer } from "./render.js";
import { SurfaceStream } from "./stream.js";

const $ = (id) => document.getElementById(id);
const baseInput = $("base-url");
const pageInput = $("page-id");
const statusEl = $("status");
const rootEl = $("surface-root");
const connectBtn = $("connect");
const fetchBtn = $("fetch-once");
const disconnectBtn = $("disconnect");

let stream = null;

baseInput.value = window.location.protocol.startsWith("http") ? window.location.origin : "http://localhost:7000";

function setStatus(state, text) {
  statusEl.setAttribute("data-state", state);
  statusEl.textContent = text;
}

function baseUrl() {
  const raw = baseInput.value.trim().replace(/\/+$/, "");
  return /^https?:\/\//.test(raw) ? raw : "";
}

function pageId() {
  const raw = pageInput.value.trim();
  return /^[\w-]{1,80}$/.test(raw) ? raw : "";
}

function makeRenderer() {
  return new SurfaceRenderer({
    document,
    onAction: submitAction,
    onWarn: (msg) => console.warn(`[a2ui] ${msg}`),
  });
}

function mount(el) {
  rootEl.replaceChildren(el);
}

function note(kind, title, body, retry) {
  const wrap = document.createElement("div");
  wrap.className = `a2ui-alert a2ui-variant-${kind} render-note`;
  const t = document.createElement("div");
  t.className = "a2ui-alert-title";
  t.textContent = title;
  const b = document.createElement("div");
  b.className = "a2ui-alert-message";
  b.textContent = body;
  wrap.append(t, b);
  if (retry) {
    const btn = document.createElement("button");
    btn.className = "a2ui-button";
    btn.type = "button";
    btn.textContent = retry.label;
    btn.addEventListener("click", retry.fn);
    wrap.appendChild(btn);
  }
  return wrap;
}

function paint(normalized) {
  mount(makeRenderer().render(normalized));
}

function stopStream() {
  if (stream) {
    stream.stop();
    stream = null;
  }
  disconnectBtn.hidden = true;
}

/** 2nd rung: deterministic one-shot fetch. Returns true if it painted. */
async function fetchOnce() {
  const base = baseUrl();
  const page = pageId();
  if (!base || !page) {
    setStatus("error", "enter a valid http(s) server URL and page id");
    return false;
  }
  setStatus("degraded", `fetching ${page} once…`);
  try {
    const resp = await fetch(`${base}/api/surfaces/${encodeURIComponent(page)}`, { headers: { accept: "application/json" } });
    const payload = await resp.json();
    const normalized = normalizeEnvelope(payload);
    if (!normalized.ok) {
      if (normalized.reason === "upstream_error") {
        // Covers both "org unreachable" proxies and auth-gated surfaces
        // ({"error": "Authentication required"}) — the endpoint said no,
        // and we say so instead of painting a broken page.
        mount(note("warning", "Surface not available", `The endpoint answered: ${normalized.detail}`, { label: "Retry", fn: fetchOnce }));
        setStatus("degraded", "upstream error");
      } else if (normalized.reason === "unsupported_version") {
        mount(note("warning", "Unsupported envelope version", `This renderer speaks A2UI 0.8/0.9/0.10; the server sent "${normalized.detail}". Update the renderer.`));
        setStatus("degraded", "version mismatch");
      } else {
        mount(note("danger", "Invalid surface", `The payload is not a valid A2UI envelope (${normalized.reason}: ${normalized.detail}).`, { label: "Retry", fn: fetchOnce }));
        setStatus("error", "invalid envelope");
      }
      return false;
    }
    paint(normalized);
    setStatus("degraded", `static render of "${page}" (A2UI ${normalized.version}) — not live`);
    return true;
  } catch (e) {
    mount(
      note("danger", "Server unreachable", `Could not fetch ${base}/api/surfaces/${page}: ${e instanceof Error ? e.message : e}`, {
        label: "Retry",
        fn: fetchOnce,
      }),
    );
    setStatus("offline", "server unreachable");
    return false;
  }
}

function connect() {
  stopStream();
  const base = baseUrl();
  const page = pageId();
  if (!base || !page) {
    setStatus("error", "enter a valid http(s) server URL and page id");
    return;
  }
  let painted = false;
  setStatus("degraded", `connecting to ${page} stream…`);
  disconnectBtn.hidden = false;
  stream = new SurfaceStream(`${base}/api/surfaces/${encodeURIComponent(page)}/stream`, {
    onSurface: (normalized) => {
      painted = true;
      paint(normalized);
      setStatus("live", `live "${page}" (A2UI ${normalized.version}) — ${new Date().toLocaleTimeString()}`);
    },
    onStatus: (state, detail) => {
      if (state === "error" && !painted) {
        // Streaming never delivered anything usable — drop to the
        // deterministic one-shot rung rather than showing a spinner.
        stopStream();
        fetchOnce();
        return;
      }
      if (state === "resync") setStatus("degraded", `resyncing (${detail})`);
      else if (state === "reconnecting") setStatus("degraded", `reconnecting (${detail})`);
      else if (state === "finished") setStatus("degraded", "stream finished — reconnecting");
      else if (state === "error") setStatus("degraded", `stream error (${detail}) — retrying`);
    },
  });
  stream.run();
}

/** POST a component action; render the returned surface inline. */
async function submitAction({ surfaceId, componentId, action, values }) {
  const base = baseUrl();
  if (!base || !action) return;
  setStatus("degraded", `submitting action "${action}"…`);
  try {
    const resp = await fetch(`${base}/api/surfaces/action`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ surface_id: surfaceId, component_id: componentId, action, values }),
    });
    const payload = await resp.json();
    const normalized = normalizeEnvelope(payload);
    const box = document.createElement("div");
    box.className = "action-result";
    const bar = document.createElement("div");
    bar.className = "action-result-bar";
    const label = document.createElement("strong");
    label.textContent = `Action result — ${action}`;
    const close = document.createElement("button");
    close.className = "a2ui-button";
    close.type = "button";
    close.textContent = "Dismiss";
    close.addEventListener("click", () => box.remove());
    bar.append(label, close);
    box.appendChild(bar);
    box.appendChild(
      normalized.ok
        ? makeRenderer().render(normalized)
        : note("warning", "Action response was not a surface", `${normalized.reason}: ${normalized.detail}`),
    );
    rootEl.prepend(box);
    setStatus("live", `action "${action}" answered`);
  } catch (e) {
    rootEl.prepend(note("danger", "Action failed", e instanceof Error ? e.message : String(e)));
    setStatus("error", `action "${action}" failed`);
  }
}

connectBtn.addEventListener("click", connect);
fetchBtn.addEventListener("click", () => {
  stopStream();
  fetchOnce();
});
disconnectBtn.addEventListener("click", () => {
  stopStream();
  setStatus("idle", "disconnected");
});

mount(note("info", "Not connected", "Point the renderer at an Orrery org or agent and press Connect. With no LLM key configured anywhere, the deterministic surfaces (dashboard, digest, members, …) still render — that is the point."));
