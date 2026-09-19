// QR join landing — one invite token, a RUNTIME PICKER.
//
// ⚠️ NOT OPENCLAW-ONLY, AND THE SHAPE IS THE POINT. Two member runtimes exist
// today — `member-sdk` (Python) and `openclaw-skill` — and Claude users are not
// excluded by design; there is simply no MCP member server yet. This repo's own
// mcp_server/ does not change that: it is a stdio accountability layer for an
// agent that ALREADY HAS an identity (register_agent reports one, never mints
// one), and it implements no membership join — no keypair-for-a-new-member, no
// POST /api/members. So the landing offers three paths from one token.
// Hard-coding OpenClaw into the flow would bake in a limitation we already know
// is wrong, and the migration cost lands on whoever adds MCP.
//
// ⚠️ THE MCP PATH IS A STUB AND SAYS SO IN THE UI. A "coming soon" that looks
// like a working option is the plausible-wrong-answer failure on a join flow: a
// Claude user follows it, nothing works, and they cannot tell whether they
// misconfigured something or the path does not exist. It is rendered as
// unavailable, with what is missing named.
//
// ONE TOKEN, NOT THREE. The invite and its TOFU registration already exist
// (`/api/invites`); this is a presentation layer over them, not a second join
// mechanism. Every path carries the same token, so revoking the invite revokes
// all three.

import { el, replace, text } from "./dom.js";

/**
 * The runtimes, and their honest availability.
 *
 * `available: false` is a first-class state rather than an omission — a path
 * that is missing from the list teaches a Claude user that Orrery does not
 * support them, which is not true; it teaches nothing about what is actually
 * absent. Same argument as `not_established` in the lifecycle work: the absence
 * needs a name.
 */
export const RUNTIMES = [
  {
    id: "openclaw",
    label: "OpenClaw skill",
    blurb: "Drop-in skill for an existing OpenClaw agent. Fastest if you already run one.",
    available: true,
  },
  {
    id: "python",
    label: "Python agent",
    blurb: "The member-sdk runtime. Runs on your own machine; you hold the signing key.",
    available: true,
  },
  {
    id: "mcp",
    label: "Claude (MCP)",
    blurb: "Join from Claude via MCP.",
    unavailableReason:
      "Not available yet: there is still no MCP member server — this repo's own MCP " +
      "server doesn't support joining an org. The invite below will work unchanged with " +
      "a future MCP member runtime — nothing about this token is runtime-specific.",
    available: false,
  },
];

function joinCommand(runtime, { orgUrl, token }) {
  // Displayed as TEXT for the user to copy. Rendering a command is not running
  // one, and nothing here executes.
  if (runtime.id === "openclaw") return `openclaw join --org ${orgUrl} --invite ${token}`;
  if (runtime.id === "python") return `pip install orrery-agent && community-member join --org ${orgUrl} --invite ${token}`;
  return "";
}

export function buildRuntimeCard(doc, runtime, { orgUrl, token, onChoose } = {}) {
  const children = [
    el(doc, "h3", { text: runtime.label }),
    el(doc, "p", { className: "blurb", text: runtime.blurb }),
  ];

  if (runtime.available) {
    const command = joinCommand(runtime, { orgUrl, token });
    children.push(el(doc, "code", { className: "cmd", text: command }));
    const button = el(doc, "button", { className: "choose", text: `Join with ${runtime.label}` });
    if (onChoose) button.addEventListener("click", () => onChoose(runtime));
    children.push(button);
  } else {
    children.push(el(doc, "p", { className: "unavailable", text: runtime.unavailableReason }));
    // Rendered, disabled, and labelled — not hidden. See the module note.
    const button = el(doc, "button", { className: "choose", text: "Not available yet", attrs: { disabled: "disabled" } });
    children.push(button);
  }

  return el(doc, "article", {
    className: `runtime${runtime.available ? "" : " runtime-unavailable"}`,
    dataset: { runtime: runtime.id, available: String(!!runtime.available) },
  }, children);
}

/**
 * What this page states about the invite.
 *
 * The page does not check the token. `if (!token)` tests presence, not validity,
 * and an unauthenticated endpoint answering whether a given invite is usable
 * would let anyone test invite codes against the org. The QR route
 * (`invite_qr`) declines to validate for the same reason.
 *
 * What the page can establish without a per-token request is the org's join
 * policy, which is org-wide, already public at `GET /api/org/join-policy`, and
 * says nothing about any particular token. It also determines whether the invite
 * is what admits the user at all: under `open` and `approval` it is not.
 *
 * A revoked, expired, exhausted or never-issued token therefore all render the
 * same. Under the `invite` policy the page quotes the refusal the server returns
 * so that a user who hits it can tell it apart from a local misconfiguration —
 * see `inviteNotice`.
 */

const POLICY_NOTICE = {
  invite: {
    lead: "This org admits new agents by invite.",
    detail:
      "This page has not checked your code — it cannot, because an invite checker open to " +
      "anyone would let anyone test codes against this org. Running the command below is the check.",
    failure:
      "If the code was already used, has expired, or was mistyped, the command fails with " +
      "\"This org requires a valid invite to join.\" That is the org refusing the code, not a " +
      "problem with your setup — ask whoever shared it for a fresh one.",
  },
  open: {
    lead: "This org is open — no invite is needed to join.",
    detail:
      "Your code is carried below and does no harm, but it is not what admits you. Any agent " +
      "that runs the command joins.",
    failure: "",
  },
  approval: {
    lead: "This org admits new agents by leader approval.",
    detail:
      "The command below registers a request. A leader has to approve it before your agent is a " +
      "member, so nothing happens the moment you run it. Your code is not what admits you here.",
    failure: "",
  },
};

const POLICY_UNKNOWN = {
  lead: "This page could not reach the org.",
  detail:
    "It could not read how this org admits new agents, and it never checks the code itself. " +
    "The command below is still correct — run it and the org will answer.",
  failure:
    "If the org refuses, it says so in the command output. Ask whoever shared the code for a " +
    "fresh one before assuming your setup is wrong.",
};

/** States the join policy, that the code is unchecked, and what a refusal looks like. */
function inviteNotice(doc, joinPolicy) {
  const copy = POLICY_NOTICE[joinPolicy] || POLICY_UNKNOWN;
  const known = Object.prototype.hasOwnProperty.call(POLICY_NOTICE, joinPolicy);
  const children = [
    el(doc, "strong", { text: copy.lead }),
    el(doc, "p", { text: copy.detail }),
  ];
  if (copy.failure) children.push(el(doc, "p", { className: "muted", text: copy.failure }));
  return el(
    doc,
    "div",
    {
      className: `invite-notice${known ? "" : " invite-notice-degraded"}`,
      dataset: { policy: known ? joinPolicy : "unknown" },
    },
    children,
  );
}

/**
 * The landing page.
 *
 * Renders no picker without a token: the three commands would otherwise all fail
 * identically, which reads as a broken runtime rather than a missing invite.
 *
 * `orgName` comes from the server, not from the query string. It was previously
 * `params.get("org")`, so the page headline was set by whoever wrote the link.
 * See join-boot.js.
 */
export function renderJoin(doc, root, { orgUrl, orgName, token, joinPolicy, runtimes, onChoose } = {}) {
  if (!token) {
    return replace(root, [
      el(doc, "div", { className: "empty warn" }, [
        el(doc, "strong", { text: "This invite link is incomplete." }),
        el(doc, "p", { text: "No invite token was supplied, so there is nothing to join with." }),
        el(doc, "p", { className: "muted", text: "Ask whoever shared the code for a fresh one." }),
      ]),
    ]);
  }

  const list = Array.isArray(runtimes) ? runtimes : RUNTIMES;
  return replace(root, [
    el(doc, "header", { className: "join-head" }, [
      el(doc, "h1", { text: `Join ${orgName || "this org"}` }),
      el(doc, "p", {
        className: "muted",
        text: "Pick how you want to run your agent. The same invite works for all of them.",
      }),
    ]),
    inviteNotice(doc, joinPolicy),
    el(doc, "div", { className: "runtimes" }, list.map((r) => buildRuntimeCard(doc, r, { orgUrl, token, onChoose }))),
    el(doc, "footer", { className: "join-foot" }, [
      el(doc, "p", { className: "muted" }, [
        text(doc, "Invite: "),
        el(doc, "code", { text: token }),
        text(doc, " — not checked by this page"),
      ]),
      el(doc, "p", {
        className: "muted",
        text: "Your agent generates its own key on your machine. This org never sees it.",
      }),
    ]),
  ]);
}
