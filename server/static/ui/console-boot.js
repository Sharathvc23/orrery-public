// Console wiring: fetch, then hand the data to the pure render module.
//
// Kept separate from console.js on purpose. The render module touches no
// globals and no network, so node can import it and drive the REAL render path
// under a stub DOM. smb_funnel's app.js did DOM lookups at module scope and was
// therefore untestable until the boot-module split split it; this starts split.
//
// ⚠️ KEYLESS. Every endpoint read here is deterministic org state — approvals,
// agents, tasks, receipts. Nothing on this page asks the model for anything, so
// the console is fully functional on an install with no LLM key. That is a
// requirement, not a happy accident: a keyless install currently busy-loops
// against xAI, measured, and an operator's window into the org must
// not be the thing that goes dark when inference is unavailable.
//
// ⚠️ A REQUEST THAT DID NOT RETURN DATA IS NOT AN EMPTY COLLECTION. This module
// used to fold every failure into a fallback value — `getJson(url, {members: []})`
// returned that fallback on any non-ok response — so a 401 from `/api/members`
// painted "No agents have registered with this org yet." on an org with members.
// Anonymous member enumeration is closed deliberately and stays closed; the
// console's job is to report the refusal, not to translate it into an absence.
// Every read now returns a tagged outcome and each panel renders its own reason.

import { buildAnonymousNotice, renderDashboard, renderLoadError } from "./console.js";

const ROOT = document.getElementById("root");

// The admin page stores its token here, on this same origin. Reading it adds no
// exposure — any script that can run on this origin can already read it — and it
// means an operator who has signed in once gets a working console without a
// second token prompt and without a second place that stores the token.
const ADMIN_TOKEN_KEY = "org_admin_token";

function adminToken() {
  try {
    return (localStorage.getItem(ADMIN_TOKEN_KEY) || "").trim();
  } catch {
    return ""; // storage unavailable (private mode, disabled) — read anonymously.
  }
}

/**
 * Read JSON, reporting WHY on failure.
 *
 * Returns `{ok: true, data}` or `{ok: false, reason, status}` where reason is
 * one of unauthorised / forbidden / missing / unreachable / malformed / error.
 * The distinction is the point: each one implies a different next action for the
 * operator, and collapsing them is what made an authorisation failure look like
 * an empty org.
 */
async function fetchJson(url, token) {
  const headers = { accept: "application/json" };
  if (token) headers["X-Admin-Token"] = token;
  let resp;
  try {
    resp = await fetch(url, { headers });
  } catch {
    return { ok: false, reason: "unreachable" };
  }
  if (!resp.ok) {
    const reason =
      resp.status === 401 ? "unauthorised" : resp.status === 403 ? "forbidden" : resp.status === 404 ? "missing" : "error";
    return { ok: false, reason, status: resp.status };
  }
  try {
    return { ok: true, data: await resp.json() };
  } catch {
    return { ok: false, reason: "malformed", status: resp.status };
  }
}

/** Pull a collection out of a successful payload, keeping the outcome shape. */
function collection(outcome, ...keys) {
  if (!outcome.ok) return outcome;
  const payload = outcome.data || {};
  for (const k of keys) if (Array.isArray(payload[k])) return { ok: true, data: payload[k] };
  return { ok: true, data: [] };
}

async function decide(item, decision, token) {
  const id = item.id || item.approval_id;
  if (!id) return;
  let resp;
  try {
    resp = await fetch(`/api/approvals/${encodeURIComponent(id)}/${decision}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { "X-Admin-Token": token } : {}) },
      body: JSON.stringify({}),
    });
  } catch {
    // A decision that silently fails is worse than one that fails loudly: the
    // queue reloads unchanged and the operator reads it as "already handled".
    renderLoadError(document, ROOT, `The org did not answer when ${decision} was sent. Nothing was recorded.`);
    return;
  }
  if (!resp.ok) {
    renderLoadError(
      document,
      ROOT,
      resp.status === 401 || resp.status === 403
        ? `You are not authorised to ${decision} approvals. Nothing was recorded.`
        : `The org refused the ${decision} (HTTP ${resp.status}). Nothing was recorded.`,
    );
    return;
  }
  await load();
}

async function load() {
  const token = adminToken();

  // The kinds call is the one that must succeed loudly: without it the console
  // cannot tell "nothing pending" from "nothing gated", and silently guessing
  // would restore exactly the reassuring-empty-queue problem.
  const kinds = await fetchJson("/api/approvals/kinds", token);
  if (!kinds.ok) {
    renderLoadError(
      document,
      ROOT,
      kinds.reason === "unauthorised" || kinds.reason === "forbidden"
        ? "This org does not publish its approval vocabulary to you, so the console cannot tell an empty queue from an ungated one."
        : "The approval vocabulary could not be read from this org.",
    );
    return;
  }

  const [approvals, agents, tasks, receipts] = await Promise.all([
    fetchJson("/api/approvals", token),
    fetchJson("/api/members", token),
    // ⚠️ No route has ever served this path. `git log -S '"/api/tasks"'` finds
    // only the commit that added this console, so the panel has answered 404
    // since it shipped and rendered that as "No tasks recorded.". It now says
    // the endpoint is absent; whether the panel should exist at all is a
    // question for whoever owns the console's scope.
    fetchJson("/api/tasks", token),
    fetchJson("/api/receipts/recent?limit=25", token),
  ]);

  const panels = [
    renderDashboard(
      document,
      ROOT,
      {
        signedIn: !!token,
        kinds,
        pending: collection(approvals, "pending"),
        agents: collection(agents, "members", "agents"),
        tasks: collection(tasks, "tasks"),
        receipts: collection(receipts, "receipts", "items"),
      },
      {
        onApprove: (item) => decide(item, "approve", token),
        onReject: (item) => decide(item, "reject", token),
      },
    ),
  ];

  // One banner above the panels when reading anonymously, so the operator knows
  // the state of the whole page rather than inferring it from each panel.
  if (!token) ROOT.prepend(buildAnonymousNotice(document));
  return panels;
}

load();
