// smb_funnel — the 3-click SMB onboarding funnel.
//
// Screen 1 (form)     → enter business name + what you do → CTA
// Screen 2 (creating) → POST /provision
// Screen 3 (live)     → agent card / endpoint / did / recovery phrase / Try-it booking
//
// Primary clicks from start to "live on NANDA": exactly 1 (the CTA). The
// Try-it booking is a 2nd optional primary click; copy buttons are secondary.

import * as api from "./api.js";
import { usingMock, apiBase, apiIsCrossOrigin } from "./api.js";
import { captureProvisionToken, hasProvisionToken } from "./config.js";
import { didFromAgentCard, verifyReceipt } from "./arp.js";
import {
  buildBookingError,
  buildPhraseChips,
  buildProvisionError,
  buildReceipt,
  clear,
  paintVerifyBadge,
} from "./render.js";

const $ = (sel, root = document) => root.querySelector(sel);

const screens = {
  form: $("#screen-form"),
  creating: $("#screen-creating"),
  live: $("#screen-live"),
};

function show(name) {
  for (const [k, el] of Object.entries(screens)) {
    el.hidden = k !== name;
  }
  const focusEl = screens[name].querySelector("[data-autofocus]");
  if (focusEl) focusEl.focus();
}

// Environment ribbon so the demo audience (and you) can see mock vs live.
function paintEnvBadge() {
  const el = $("#env-badge");
  if (usingMock) {
    el.textContent = "demo backend (mock)";
    el.dataset.mode = "mock";
  } else {
    el.textContent = `live · ${apiBase}`;
    el.dataset.mode = "live";
  }
}

// ── copy-to-clipboard helper (with graceful fallback) ───────────────────────
async function copyText(text, btn) {
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch {
    // Fallback for insecure contexts / older browsers.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    ta.remove();
  }
  if (btn) {
    const prev = btn.textContent;
    btn.textContent = ok ? "Copied" : "Copy failed";
    btn.dataset.state = ok ? "ok" : "err";
    setTimeout(() => {
      btn.textContent = prev;
      delete btn.dataset.state;
    }, 1400);
  }
}

// Delegate all copy buttons: <button data-copy="#selector-or-value">.
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const src = btn.getAttribute("data-copy");
  const target = src.startsWith("#") ? $(src) : null;
  const value = target ? target.dataset.value || target.textContent : src;
  copyText(value, btn);
});

// ── screen 1 → provision ────────────────────────────────────────────────────
let liveTenant = null;

$("#funnel-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const businessName = $("#business-name").value.trim();
  const serviceType = $("#service-type").value.trim();
  const contact = $("#contact").value.trim();
  if (!businessName) {
    $("#business-name").focus();
    return;
  }
  // Required by the host, and required here so the refusal arrives before the
  // staged progress rather than after it. An agent provisioned with nowhere to
  // send a booking would accept appointments the business never sees.
  if (!contact) {
    $("#contact").focus();
    return;
  }
  $("#creating-name").textContent = businessName;
  show("creating");
  setStep(0);
  try {
    // Staged progress purely for demo feel; the provision call is one request.
    await tick(650, 1);
    const result = await api.provision(businessName, serviceType, contact);
    await tick(400, 2);
    // Confirm the agent is resolvable by fetching its card (also proves the
    // well-known endpoint works end-to-end).
    let card = null;
    try {
      card = await api.agentCard(result.tenant_id);
    } catch {
      card = null; // non-fatal for the live screen
    }
    await tick(350, 3);
    // The anchor a receipt is checked against: the did:key this host published on
    // the tenant's agent card, read in THIS session. It is not a receipt, so a
    // receipt cannot supply it — but it is served by the same origin as the
    // receipt, so agreement between the two shows the host is internally
    // consistent, not that the host is the business. See README, "What none of
    // this proves".
    //
    // ⚠️ THERE IS DELIBERATELY NO STORED PIN HERE. `src/pin.js` kept one in
    // localStorage and nothing read it; the value the receipt was checked against
    // was always this session's card DID. Trust-on-first-use needs a SECOND
    // encounter, and this funnel mints a new tenant on every run, so a pin would
    // be written and read inside one session — a check whose verdict is a
    // function of its own write. It was removed rather than wired. See the
    // CHANGELOG entry and tests/wiring.test.mjs.
    const cardDid = didFromAgentCard(card);
    liveTenant = { ...result, card, cardDid, business_name: businessName, service_type: serviceType };
    renderLive(liveTenant);
    show("live");
  } catch (err) {
    renderError(err);
  }
});

function setStep(i) {
  document.querySelectorAll("#creating-steps li").forEach((li, idx) => {
    li.dataset.state = idx < i ? "done" : idx === i ? "active" : "";
  });
}
async function tick(ms, step) {
  setStep(step);
  await new Promise((r) => setTimeout(r, ms));
}

function renderError(err) {
  show("form");
  const box = $("#form-error");
  box.hidden = false;
  // The state is carried on the element as well as in the words, so a stylesheet
  // and a test can both address "the host wants a credential" without matching
  // on prose. Only the state name is written here — never the token, whose value
  // this module is not given (see config.js `hasProvisionToken`).
  const { state, nodes } = buildProvisionError(document, {
    status: err.status,
    message: err.message,
    hasToken: hasProvisionToken(),
    // Whether the request reached a server at all, and — only if it did not —
    // the one cause this page can check for itself. `apiIsCrossOrigin` is a
    // configuration fact read at module load, never a diagnosis of the failure.
    unreachable: err.unreachable === true,
    crossOrigin: apiIsCrossOrigin,
  });
  box.dataset.state = state;
  clear(box);
  for (const node of nodes) box.appendChild(node);
}

// ── screen 3 → live ─────────────────────────────────────────────────────────
function renderLive(t) {
  $("#live-name").textContent = t.business_name;

  setField("#endpoint", t.endpoint);
  setField("#did", t.did);

  // Agent card URL: the canonical A2A card the host serves for this tenant.
  // Displayed and copyable, never navigated, in the same shape as the Endpoint
  // and Identity fields below it.
  //
  // This was previously an <a> whose href was assigned from `t.endpoint`:
  //   const a = $("#card-link"); a.href = `${t.endpoint}/.well-known/agent.json`;
  // `t.endpoint` is a field of the /provision response, so a host answering with
  // {"endpoint": "javascript:..."} produced a javascript: URL that ran on click
  // in any context permitting inline script. No module here now assigns a URL to
  // href or src; tests/source-guard.test.mjs rejects such an assignment rather
  // than relying on a sanitiser at each call site.
  setField("#card-link", `${t.endpoint}/.well-known/agent.json`);

  // Recovery phrase — shown once. Built as nodes: a phrase word re-derives the
  // agent's did:key, so it is the last string in this product that should ever
  // reach an HTML parser. See render.js.
  const phrase = $("#recovery-phrase");
  phrase.dataset.value = t.recovery_phrase;
  clear(phrase);
  for (const chip of buildPhraseChips(document, t.recovery_phrase)) phrase.appendChild(chip);

  // Reset Try-it panel for a clean demo each run.
  $("#try-result").hidden = true;
  $("#try-btn").disabled = false;
  $("#try-btn").textContent = "Try it — book an appointment";
}

function setField(sel, value) {
  const el = $(sel);
  el.textContent = value;
  el.dataset.value = value;
}

// ── Try-it booking ──────────────────────────────────────────────────────────
$("#try-btn").addEventListener("click", async () => {
  if (!liveTenant) return;
  const btn = $("#try-btn");
  btn.disabled = true;
  btn.textContent = "Booking…";
  try {
    const when = new Date(Date.now() + 2 * 864e5);
    when.setHours(10, 0, 0, 0);
    const payload = {
      service: liveTenant.service_type || "Appointment",
      provider: liveTenant.business_name,
      datetime: when.toISOString(),
      // ⚠️ THIS STRING IS SIGNED OVER. It said "Booked by an agent via the NANDA
      // Index", and no code on this path calls any index — the funnel registers
      // nobody. A hedge that only reads as a hedge inside this page does not
      // survive the receipt being exported or verified from the command line,
      // where it reads as a record of an Index hop that never happened.
      notes: "Booked from the demo page on this host. No index was involved.",
    };
    const res = await api.book(liveTenant.tenant_id, payload);
    await renderReceipt(res);
    btn.textContent = "Book another";
    btn.disabled = false;
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "Try again";
    const r = $("#try-result");
    r.hidden = false;
    clear(r);
    r.appendChild(buildBookingError(document, err.message));
  }
});

async function renderReceipt(res) {
  const b = res.booking || {};
  const rcpt = res.receipt || null;
  const box = $("#try-result");
  box.hidden = false;

  const when = b.datetime ? new Date(b.datetime) : null;
  const whenStr = when
    ? when.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : b.datetime || "—";

  // The receipt is the RAW signed ARP receipt returned by the host — every field
  // below is server-supplied. Built as nodes (render.js), so none of it can
  // become markup; the badge starts as "Verifying…" and is only replaced with
  // the "verified offline" claim if the in-browser Ed25519 check actually passes.
  const { node, badge } = buildReceipt(document, {
    receiptId: res.receipt_id,
    booking: b,
    receipt: rcpt,
    whenStr,
    // Read rather than assumed. `delivered` is deliberately passed through
    // undefined when the backend omits it, because "it did not arrive" and "this
    // backend does not say" are different facts and the panel renders them
    // differently. Coercing with `!!` here would collapse them at the door.
    delivered: res.delivered,
    deliveryChannel: res.delivery_channel,
    deliveryNote: res.delivery_note,
  });
  clear(box);
  box.appendChild(node);

  if (!rcpt) {
    paintVerifyBadge(document, badge, "unsigned");
    return;
  }

  // REAL offline verification: JCS-canonicalize the receipt (sans signature) and
  // Ed25519-verify the signature under issuer_did — the same accept/reject the
  // host-side arp.verify_receipt makes.
  //
  // ⚠️ NOT "no trust in the server", which is what this comment used to say. The
  // host serves the card and signs the receipt, so a host that lies signs with
  // the key it published and every check below passes. What runs here needs no
  // trust in the TRANSPORT — the signature is recomputed locally — and that is a
  // different and much smaller claim. The comment mattered because the badge copy
  // gets written from it.
  let result;
  try {
    // The issuer this receipt must match comes from the tenant's agent card,
    // fetched from the host in this session. Passing nothing here would make every
    // self-consistent receipt pass, which is the defect this check exists for —
    // tests/wiring.test.mjs drives this line against a host that serves one key on
    // the card and signs with another, so dropping the anchor turns that suite red.
    result = await verifyReceipt(rcpt, { expectedIssuer: liveTenant && liveTenant.cardDid });
  } catch (e) {
    result = { ok: false, stage: "error", detail: e.message };
  }
  if (result.ok) {
    badge.title =
      "Ed25519 signature checked in this browser, and the issuer is the did:key on the agent card this host served for this tenant. Card and receipt come from the same origin, so this shows the host is internally consistent — not that the host is the business.";
    paintVerifyBadge(document, badge, "ok");
  } else if (result.stage === "provenance" && result.provenance === "unknown") {
    badge.title =
      "The signature is valid, but no did:key was available from this tenant's agent card to check the issuer against.";
    paintVerifyBadge(document, badge, "unknown");
  } else if (result.stage === "provenance" && result.provenance === "warning") {
    badge.title =
      "The signature is valid, but it was made with a different key than the one on this tenant's agent card.";
    paintVerifyBadge(document, badge, "mismatch");
  } else {
    // stage/detail are attacker-influenced; `title` is a property assignment and
    // cannot become markup, and the visible label is a constant.
    badge.title = `Verification failed at the ${result.stage} stage: ${result.detail}`;
    paintVerifyBadge(document, badge, "fail");
  }
}

// "Start over" (secondary) — back to a clean funnel for the next demo run.
$("#restart").addEventListener("click", () => {
  liveTenant = null;
  $("#funnel-form").reset();
  $("#form-error").hidden = true;
  show("form");
});

// ── boot ────────────────────────────────────────────────────────────────────
//
// The token is taken out of the URL FIRST — before the environment badge, before
// a screen is shown, before anything can render — so no paint ever happens with
// a credential still in the address bar.
captureProvisionToken();
paintEnvBadge();
show("form");
