// smb_funnel — API client.
//
// One thin layer over the frozen contract. When API_BASE is "mock" it dispatches
// to the in-page mock (no network); otherwise it does real fetch() to the host.
// The rest of the app calls these four functions and never touches transport.

import { provisionToken, resolveApiBase } from "./config.js";
import { route as mockRoute } from "./mock_core.js";

const base = resolveApiBase();
export const usingMock = base === "mock";
export const apiBase = base;

/**
 * Whether the configured API base is a DIFFERENT ORIGIN from the page.
 *
 * ⚠️ THIS IS A CONFIGURATION FACT, NOT A DIAGNOSIS. When a request never reaches
 * a server, page script is handed a `TypeError` with no status and no reason —
 * a refused preflight, a DNS failure and a dropped connection are the same
 * object. So the page cannot say WHY nothing came back, and must not pretend to.
 * What it can say is what it was configured to do, which is checkable and is the
 * commonest cause: `smb_signup` grants no cross-origin access at all (see
 * config.js), so a page it does not serve cannot call it however correct the
 * rest of the setup is.
 *
 * Unknown resolves to `false` — outside a browser, or with an unparseable base —
 * so the page falls back to the transient reading rather than blaming a
 * configuration it could not read.
 */
export const apiIsCrossOrigin = (() => {
  if (usingMock) return false;
  try {
    const here = globalThis.location && globalThis.location.origin;
    if (!here) return false;
    return new URL(base, here).origin !== here;
  } catch {
    return false;
  }
})();

async function call(method, path, body, { auth = false } = {}) {
  if (usingMock) {
    // Simulate a little latency so the "Creating your agent…" state is visible.
    await new Promise((r) => setTimeout(r, 550));
    const res = await mockRoute(method, path, body);
    if (res.status >= 400) {
      const err = new Error(res.json.error || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json;
  }

  const opts = { method, headers: { Accept: "application/json" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  // ⚠️ THE HEADER IS ADDED OR IT IS ABSENT — there is no empty-token form. A
  // browser with no token must send a request byte-identical to the one it sent
  // before this gate existed, because that is the shape CI, the demo scripts and
  // a loopback host all use. `Authorization: Bearer ` with nothing after it is a
  // third state neither side has a rule for.
  if (auth) {
    const token = provisionToken();
    if (token) opts.headers["Authorization"] = `Bearer ${token}`;
  }
  // ⚠️ A REQUEST THAT NEVER LEFT IS NOT A REFUSAL, AND MUST NOT BECOME ONE. A
  // `fetch` that rejects carries no status, so every `err.status` read
  // downstream is `undefined` — the same value a 5xx-less failure has — and the
  // page rendered its catch-all "Couldn't create your agent. Please try again."
  // Measured in a real Chromium against a real pair with the rate limit spent:
  // the visitor was shown that sentence for a 429 the browser never sent the
  // request for. `unreachable` marks the difference so the page can say what is
  // true — nothing was received — instead of a verdict on an exchange that did
  // not happen.
  let resp;
  try {
    resp = await fetch(base.replace(/\/$/, "") + path, opts);
  } catch (cause) {
    const err = new Error(`the request to ${base} was not delivered`);
    err.unreachable = true;
    err.cause = cause;
    throw err;
  }
  const text = await resp.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!resp.ok) {
    const err = new Error(errorMessage(data, resp.status));
    err.status = resp.status;
    err.body = data;
    throw err;
  }
  return data;
}

/**
 * The message the host actually sent, or the status if it sent none.
 *
 * ⚠️ `detail` IS FIRST BECAUSE IT IS WHAT THE REAL HOST SENDS. This read used to
 * be `data.error` alone — the shape `mock_core.js` returns. `smb_host` is FastAPI
 * and raises `HTTPException(detail=…)` at every refusal, so against the deployed
 * host EVERY message was discarded and rendered as the bare `HTTP <status>`
 * fallback: the duplicate-name 409 and the malformed-name 400 as much as the 401
 * this unit is about. The host said exactly what was wrong and the page threw it
 * away. Both shapes are read now, because both are shapes this funnel talks to.
 *
 * Nothing this returns is derived from the request, so a token cannot reach it.
 */
function errorMessage(data, status) {
  if (data && typeof data.detail === "string" && data.detail) return data.detail;
  if (data && Array.isArray(data.detail) && data.detail.length) return validationMessage(data.detail);
  if (data && typeof data.error === "string" && data.error) return data.error;
  return `HTTP ${status}`;
}

/**
 * FastAPI's 422 body is a LIST of error objects, not a string. Read it.
 *
 * ⚠️ THIS IS THE COMMONEST REFUSAL A PERSON CAN PROVOKE — submitting the form
 * with no name, or a name the model rejects — and it was the least legible thing
 * the funnel could say. The `typeof detail === "string"` guard above meant an
 * array fell through to the bare `HTTP 422`, so the page named a status code
 * where the host had sent a field and a reason. (It did at least not print
 * `[object Object]`; a bare status is not much better.)
 *
 * `loc` is a path like ["body", "business_name"], so its last STRING element is
 * the field. Everything here is server-supplied and reaches the document as a
 * text node, like every other value the funnel renders.
 */
function validationMessage(detail) {
  const parts = [];
  for (const item of detail) {
    if (!item || typeof item !== "object") continue;
    const loc = Array.isArray(item.loc) ? item.loc.filter((p) => typeof p === "string") : [];
    const field = loc.length ? loc[loc.length - 1] : "";
    const msg = typeof item.msg === "string" && item.msg ? item.msg : "is not valid";
    parts.push(field ? `${field}: ${msg}` : msg);
  }
  return parts.length ? parts.join("; ") : `HTTP 422`;
}

// POST /provision {business_name, service_type?}
//
// The only gated call in the contract: `smb_host` mints an identity and writes a
// tenant home here, so a host reachable off its own machine requires a bearer
// token (`SMB_HOST_PROVISION_TOKEN`). Reading a card and making a booking are
// not gated, and this does not send a credential to them.
export function provision(businessName, serviceType, contact) {
  return call(
    "POST",
    "/provision",
    { business_name: businessName, service_type: serviceType || undefined, contact },
    { auth: true },
  );
}

// GET /t/{tenant_id}/.well-known/agent.json
export function agentCard(tenantId) {
  return call("GET", `/t/${encodeURIComponent(tenantId)}/.well-known/agent.json`);
}

// POST /t/{tenant_id}/book {service, provider, datetime, notes}
export function book(tenantId, payload) {
  return call("POST", `/t/${encodeURIComponent(tenantId)}/book`, payload);
}

// GET /health
export function health() {
  return call("GET", "/health");
}
