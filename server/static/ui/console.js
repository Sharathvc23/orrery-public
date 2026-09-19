// Org console — render functions for agents · tasks · approvals · receipts.
//
// An OPERATOR dashboard, not a product surface: it answers "which agents are
// alive, what did they last do, what is waiting on me, and what did the org
// actually sign".
//
// ⚠️⚠️ THE APPROVAL QUEUE IS THE CENTRE OF GRAVITY, AND IT IS CURRENTLY A NO-OP.
// An unattended-agent spike ran four service agents for a full cycle and
// `pending_approvals` stayed at 0 throughout — not because the queue was fast,
// but because all eight `APPROVAL_KINDS` are SOCIAL (introduction,
// event_proposal, role_promotion…) and an unattended service agent never
// performs a social act. There is no vocabulary for an operational one. PR1
// (be) adds `send_external` / `record_write` / `external_fetch`.
//
// ⚠️ SO THIS UI MUST NOT ENUMERATE THE KINDS. It DISCOVERS them from
// `/api/approvals/kinds`, which the server derives from `governance.APPROVAL_KINDS`.
// Hard-coding a list here would be the `INDIVIDUAL_PROFILE_TYPES` bug again: an
// inclusion allowlist that silently drops everything nobody thought to add. That
// one shipped, excluded six of seven legal values, and was caught in deploy
// verification rather than by a test. When PR1 lands its three kinds, this
// console shows them without being edited — and a test pins that no kind name
// appears in this file at all.
//
// ⚠️ AND IT MUST NOT IMPLY GOVERNANCE THAT IS NOT HAPPENING. An empty queue over
// a busy org means "nothing here is gated", not "everything is approved". The
// empty state says which, because "0 pending" rendered next to four working
// agents reads as reassurance and is currently the opposite.

import { clear, el, replace, text } from "./dom.js";

// ── a panel that has no data, and why ────────────────────────────────────────
//
// A panel reaches this when its request did not return data. Rendering the empty
// state instead would report an absence the console has not established: an
// operator on an org with two members read "No agents have registered with this
// org yet." because `/api/members` answers 401 to anonymous callers and the
// console painted the 401 as emptiness.
//
// The states are kept apart because the operator's next action differs for each.
// `signedIn` decides only the wording of the unauthorised case: the console
// attaches the admin token this origin already holds, so a 401 while signed in
// means the stored token is not accepted rather than that none was sent.

const PANEL_STATE = {
  unauthorised: ({ what, signedIn }) =>
    signedIn
      ? {
          head: `Not authorised to see ${what}.`,
          body:
            "This browser sent the admin token stored on this origin and the org refused it. " +
            "The token may have been rotated since it was saved.",
          fix: "Sign in again on the admin page",
        }
      : {
          head: `Sign in to see ${what}.`,
          body:
            `This org does not publish ${what} to anonymous callers, so the console cannot ` +
            "tell you whether there are any. This is not an empty org.",
          fix: "Sign in on the admin page",
        },
  forbidden: ({ what }) => ({
    head: `Your account cannot see ${what}.`,
    body: "The org accepted the credential and refused the request. A different role is needed.",
  }),
  missing: ({ what, endpoint }) => ({
    head: `This org's build does not serve ${what}.`,
    body: `${endpoint} answered 404, so there is nothing behind this panel. A missing endpoint is not an absence of ${what}.`,
  }),
  unreachable: ({ what }) => ({
    head: `${what} could not be loaded.`,
    body: "The org did not answer. Nothing in this panel is current.",
  }),
  malformed: ({ what, endpoint }) => ({
    head: `${what} could not be read.`,
    body: `${endpoint} answered with something that is not JSON.`,
  }),
  error: ({ what, endpoint, status }) => ({
    head: `${what} could not be loaded.`,
    body: `${endpoint} answered ${status}.`,
  }),
};

/**
 * Render why a panel has no data. `what` names the panel's subject in the
 * operator's terms ("agents", "the approval queue"), not the endpoint's.
 */
export function buildUnavailable(doc, { reason, status, endpoint, what, signedIn } = {}) {
  const make = PANEL_STATE[reason] || PANEL_STATE.error;
  const copy = make({ what: what || "this", endpoint: endpoint || "the endpoint", status: status ?? "an error", signedIn });
  const children = [el(doc, "strong", { text: copy.head }), el(doc, "p", { text: copy.body })];
  if (copy.fix) {
    children.push(el(doc, "p", { className: "muted" }, [el(doc, "a", { attrs: { href: "/admin/" }, text: copy.fix })]));
  }
  return el(doc, "div", { className: "empty warn", dataset: { unavailable: reason || "error" } }, children);
}

/** True when the outcome carried data; false when it carried a reason. */
function ok(outcome) {
  return !!outcome && outcome.ok === true;
}

// ── agents ───────────────────────────────────────────────────────────────────

/**
 * ``liveness`` is reported, never inferred. A dashboard that decides an agent is
 * "down" from a heartbeat gap it invented is asserting a fact it cannot observe;
 * unknown is a state, and it is shown as unknown.
 */
export function buildAgentRow(doc, agent) {
  const state = agent.status || "unknown";
  return el(doc, "tr", { className: "agent", dataset: { state } }, [
    el(doc, "td", {}, [
      el(doc, "span", { className: `dot dot-${state}` }),
      text(doc, agent.name || agent.agent_id || "(unnamed)"),
    ]),
    el(doc, "td", { className: "muted", text: agent.agent_id || "" }),
    el(doc, "td", { text: state }),
    el(doc, "td", { className: "muted", text: agent.last_action || "—" }),
    el(doc, "td", { className: "muted", text: agent.last_seen || "—" }),
  ]);
}

export function buildAgents(doc, agents) {
  const list = Array.isArray(agents) ? agents : [];
  if (!list.length) {
    return el(doc, "p", { className: "empty", text: "No agents have registered with this org yet." });
  }
  const head = el(doc, "tr", {}, [
    el(doc, "th", { text: "Agent" }),
    el(doc, "th", { text: "ID" }),
    el(doc, "th", { text: "State" }),
    el(doc, "th", { text: "Last action" }),
    el(doc, "th", { text: "Last seen" }),
  ]);
  return el(doc, "table", { className: "grid" }, [
    el(doc, "thead", {}, [head]),
    el(doc, "tbody", {}, list.map((a) => buildAgentRow(doc, a))),
  ]);
}

// ── tasks ────────────────────────────────────────────────────────────────────

export function buildTasks(doc, tasks) {
  const list = Array.isArray(tasks) ? tasks : [];
  if (!list.length) return el(doc, "p", { className: "empty", text: "No tasks recorded." });
  return el(
    doc,
    "ul",
    { className: "tasks" },
    list.map((t) =>
      el(doc, "li", {}, [
        el(doc, "span", { className: "task-state", text: t.status || "pending" }),
        text(doc, t.title || t.description || "(untitled task)"),
        el(doc, "span", { className: "muted", text: t.agent_id ? ` · ${t.agent_id}` : "" }),
      ]),
    ),
  );
}

// ── ⚠️ approvals — the screen that matters ───────────────────────────────────

/**
 * The empty state, which is the honest half of this screen.
 *
 * ``gated`` is whether ANY operational kind exists yet. With only social kinds
 * configured, an empty queue does not mean the org is behaving — it means
 * nothing an unattended agent does is gated at all. Saying "0 pending" and
 * stopping there would be a reassuring lie.
 */
export function buildApprovalsEmpty(doc, { operationalKinds }) {
  if (operationalKinds && operationalKinds.length) {
    return el(doc, "p", { className: "empty", text: "Nothing is waiting on you." });
  }
  return el(doc, "div", { className: "empty warn" }, [
    el(doc, "strong", { text: "Nothing here is gated yet." }),
    el(doc, "p", {
      text:
        "This org has no operational approval kinds configured, so actions taken by " +
        "unattended agents — sends, record writes, external fetches — do not reach this " +
        "queue at all. An empty queue is not the same as an approved one.",
    }),
  ]);
}

/**
 * One pending item. The payload is rendered as labelled fields, NOT as a
 * pretty-printed blob: an operator approving `send_external` needs to see the
 * recipient and the body, and a JSON dump buries them.
 *
 * The kind is displayed verbatim, whatever it is. Nothing here switches on a
 * known set — see the module note.
 */
export function buildApprovalCard(doc, item, { onApprove, onReject } = {}) {
  const payload = item.payload && typeof item.payload === "object" ? item.payload : {};
  const fields = Object.entries(payload).map(([k, v]) =>
    el(doc, "div", { className: "field" }, [
      el(doc, "span", { className: "field-k", text: k }),
      el(doc, "span", { className: "field-v", text: typeof v === "object" ? JSON.stringify(v) : String(v) }),
    ]),
  );

  const approve = el(doc, "button", { className: "approve", text: "Approve" });
  const reject = el(doc, "button", { className: "reject", text: "Reject" });
  // Listeners, never `onclick=` strings — the handler is a function, so nothing
  // the payload contains can become code.
  if (onApprove) approve.addEventListener("click", () => onApprove(item));
  if (onReject) reject.addEventListener("click", () => onReject(item));

  return el(doc, "article", { className: "approval", dataset: { kind: item.kind || "unknown" } }, [
    el(doc, "header", {}, [
      el(doc, "span", { className: "kind", text: item.kind || "unknown" }),
      el(doc, "span", { className: "muted", text: item.requested_by || item.requester_agent_id || "" }),
      el(doc, "span", { className: "muted", text: item.expires_at ? `expires ${item.expires_at}` : "" }),
    ]),
    el(doc, "p", { className: "summary", text: item.human_summary || item.summary || "(no summary provided)" }),
    el(doc, "div", { className: "fields" }, fields),
    el(doc, "footer", {}, [approve, reject]),
  ]);
}

export function buildApprovals(doc, { pending, kinds, operationalKinds, onApprove, onReject } = {}) {
  const items = Array.isArray(pending) ? pending : [];
  const children = [];
  if (Array.isArray(kinds) && kinds.length) {
    children.push(
      el(doc, "p", { className: "muted kinds" }, [
        text(doc, `${kinds.length} approval kind${kinds.length === 1 ? "" : "s"} configured: `),
        text(doc, kinds.join(", ")),
      ]),
    );
  }
  children.push(
    items.length
      ? el(
          doc,
          "div",
          { className: "approval-list" },
          items.map((i) => buildApprovalCard(doc, i, { onApprove, onReject })),
        )
      : buildApprovalsEmpty(doc, { operationalKinds }),
  );
  return el(doc, "section", { className: "approvals" }, children);
}

// ── receipts ─────────────────────────────────────────────────────────────────

export function buildReceipts(doc, receipts) {
  const list = Array.isArray(receipts) ? receipts : [];
  if (!list.length) return el(doc, "p", { className: "empty", text: "No receipts yet." });
  return el(
    doc,
    "ul",
    { className: "receipts" },
    list.map((r) => {
      const action = r.action || {};
      return el(doc, "li", {}, [
        el(doc, "span", { className: "cat", text: action.category || "other" }),
        text(doc, action.human_summary || "(no summary)"),
        el(doc, "code", { className: "muted", text: (r.issuer_did || "").replace("did:key:", "").slice(0, 14) }),
        el(doc, "span", { className: "muted", text: r.issued_at || "" }),
      ]);
    }),
  );
}

// ── page assembly ────────────────────────────────────────────────────────────

/**
 * Which of the configured kinds are operational rather than social.
 *
 * ⚠️ Derived by ASKING THE SERVER, not by matching names here. The server marks
 * them because `governance` owns the vocabulary; a name-prefix guess in the
 * browser would be this file quietly re-acquiring the enumeration the module
 * note forbids.
 */
export function operationalKindsOf(kindsPayload) {
  if (!kindsPayload || typeof kindsPayload !== "object") return [];
  const ops = kindsPayload.operational;
  return Array.isArray(ops) ? ops.slice() : [];
}

/**
 * Accept either a fetch outcome (`{ok, ...}` from console-boot) or the plain
 * value a caller already holds, so a panel's data and the reason it is absent
 * travel through the same field.
 */
function outcomeOf(value) {
  if (value && typeof value === "object" && !Array.isArray(value) && "ok" in value) return value;
  return { ok: true, data: value };
}

export function renderDashboard(doc, root, data, handlers = {}) {
  const signedIn = data.signedIn === true;
  const panel = (outcome, what, endpoint, build) =>
    ok(outcome) ? build(outcome.data) : buildUnavailable(doc, { ...outcome, what, endpoint, signedIn });

  const kindsOutcome = outcomeOf(data.kinds);
  const kindsPayload = ok(kindsOutcome) ? kindsOutcome.data || {} : {};
  const kinds = Array.isArray(kindsPayload.kinds) ? kindsPayload.kinds : [];

  return replace(root, [
    el(doc, "section", { className: "panel", id: "panel-approvals" }, [
      el(doc, "h2", { text: "Waiting on you" }),
      panel(outcomeOf(data.pending), "the approval queue", "/api/approvals", (pending) =>
        buildApprovals(doc, {
          pending,
          kinds,
          operationalKinds: operationalKindsOf(kindsPayload),
          onApprove: handlers.onApprove,
          onReject: handlers.onReject,
        }),
      ),
    ]),
    el(doc, "section", { className: "panel", id: "panel-agents" }, [
      el(doc, "h2", { text: "Agents" }),
      panel(outcomeOf(data.agents), "agents", "/api/members", (agents) => buildAgents(doc, agents)),
    ]),
    el(doc, "section", { className: "panel", id: "panel-tasks" }, [
      el(doc, "h2", { text: "Tasks" }),
      panel(outcomeOf(data.tasks), "tasks", "/api/tasks", (tasks) => buildTasks(doc, tasks)),
    ]),
    el(doc, "section", { className: "panel", id: "panel-receipts" }, [
      el(doc, "h2", { text: "Receipts" }),
      panel(outcomeOf(data.receipts), "receipts", "/api/receipts/recent", (receipts) => buildReceipts(doc, receipts)),
    ]),
  ]);
}

/** A banner above the panels when the console is reading the org anonymously. */
export function buildAnonymousNotice(doc) {
  return el(doc, "div", { className: "empty warn", dataset: { notice: "anonymous" } }, [
    el(doc, "strong", { text: "You are not signed in." }),
    el(doc, "p", {
      text:
        "Panels below that this org does not publish anonymously will say so rather than " +
        "appear empty. Sign in with your admin token to see them.",
    }),
    el(doc, "p", { className: "muted" }, [el(doc, "a", { attrs: { href: "/admin/" }, text: "Sign in on the admin page" })]),
  ]);
}

/** A load failure is stated, never rendered as an empty dashboard. */
export function renderLoadError(doc, root, message) {
  return replace(root, [
    el(doc, "div", { className: "empty warn" }, [
      el(doc, "strong", { text: "Could not load the console." }),
      el(doc, "p", { text: String(message ?? "") }),
      el(doc, "p", {
        className: "muted",
        text: "Nothing below is current — this is an error, not an empty org.",
      }),
    ]),
  ]);
}

export { clear };
