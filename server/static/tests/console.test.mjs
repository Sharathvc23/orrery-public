/**
 * Adversarial render tests for the org console and join landing (PR9).
 *
 * ⚠️ This dashboard renders agent-supplied names, task titles, approval payloads
 * and receipt fields — every one written by something other than the operator
 * reading the page, and an approval payload is attacker-adjacent by definition
 * (it is what an agent is ASKING to do). The boot-module split removed every such path from
 * `smb_funnel`; this holds the same line here from the start.
 *
 * The document is the reference renderer's recording stub, which THROWS on any
 * `innerHTML`/`outerHTML` access and on any attribute beginning with `on`. So
 * reaching the end of a test is itself proof the render path never went through
 * an HTML parser, and the assertions are about the node tree.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { StubDocument, allText, walk } from "../../../renderer/tests/stubdom.mjs";
import {
  buildAgents,
  buildApprovalCard,
  buildApprovals,
  buildApprovalsEmpty,
  buildReceipts,
  buildTasks,
  operationalKindsOf,
  renderDashboard,
  renderLoadError,
} from "../ui/console.js";
import { RUNTIMES, buildRuntimeCard, renderJoin } from "../ui/join.js";

const SCRIPT = "<script>alert('xss')</script>";
const ATTR_BREAKER = `"><img src=x onerror=alert(1)>`;

function tags(doc) {
  return doc.created.map((el) => el.tagName);
}

function assertNoInjection(doc, node, payload) {
  assert.ok(allText(node).includes(payload), "payload should be present as text");
  for (const bad of ["script", "img"]) {
    assert.ok(!tags(doc).includes(bad), `a <${bad}> element was created from data`);
  }
  assert.deepEqual(
    doc.attributesSet.filter((a) => /^on/i.test(a.name)),
    [],
  );
}

// ── injection, through the real render path ──────────────────────────────────

test("a hostile agent name lands as text, not as an element", () => {
  const doc = new StubDocument();
  const node = buildAgents(doc, [{ agent_id: ATTR_BREAKER, name: SCRIPT, status: "running", last_action: SCRIPT }]);
  assertNoInjection(doc, node, SCRIPT);
});

test("a hostile task title lands as text", () => {
  const doc = new StubDocument();
  assertNoInjection(doc, buildTasks(doc, [{ title: SCRIPT, status: ATTR_BREAKER }]), SCRIPT);
});

test("a hostile receipt field lands as text", () => {
  const doc = new StubDocument();
  const node = buildReceipts(doc, [
    { action: { category: ATTR_BREAKER, human_summary: SCRIPT }, issuer_did: SCRIPT, issued_at: SCRIPT },
  ]);
  assertNoInjection(doc, node, SCRIPT);
});

test("a hostile approval payload lands as text — the highest-risk field here", () => {
  /** An approval payload is what an agent is ASKING to do. It is the one field
   * on this page whose whole purpose is to carry agent-authored content in
   * front of a human who is about to click Approve. */
  const doc = new StubDocument();
  const node = buildApprovalCard(doc, {
    kind: ATTR_BREAKER,
    human_summary: SCRIPT,
    requested_by: SCRIPT,
    payload: { to: SCRIPT, body: ATTR_BREAKER, nested: { deep: SCRIPT } },
  });
  assertNoInjection(doc, node, SCRIPT);
});

test("approval buttons carry function listeners, never handler attributes", () => {
  const doc = new StubDocument();
  const seen = [];
  const item = { id: "a1", kind: "send_external", payload: {} };
  const node = buildApprovalCard(doc, item, { onApprove: (i) => seen.push(["approve", i.id]) });
  const button = [...walk(node)].find((el) => el.className === "approve");
  button.listeners.click[0]();
  assert.deepEqual(seen, [["approve", "a1"]]);
});

test("the dom helper refuses an event-handler attribute outright", async () => {
  const { el } = await import("../ui/dom.js");
  const doc = new StubDocument();
  assert.throws(() => el(doc, "div", { attrs: { onclick: "alert(1)" } }), /event-handler attribute/);
});

// ── ⚠️ the kinds are DISCOVERED, never enumerated here ───────────────────────

test("an unknown approval kind renders without the UI knowing it", () => {
  /** ⚠️ THE REGRESSION GUARD FOR THE PROFILE_TYPE BUG, one layer up.
   *
   * PR1 adds send_external / record_write / external_fetch. A UI that enumerated
   * kinds would drop or mis-render them until someone edited this file — which
   * is exactly how an inclusion allowlist excluded six of seven legal
   * profile_types and reached production. */
  const doc = new StubDocument();
  const node = buildApprovalCard(doc, { kind: "a_kind_invented_after_this_test_was_written", payload: {} });
  assert.ok(allText(node).includes("a_kind_invented_after_this_test_was_written"));
});

test("no approval kind name is hard-coded in the console module", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../ui/console.js", import.meta.url).pathname, "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const kind of [
    "introduction",
    "event_proposal",
    "role_promotion",
    "member_admission",
    "send_external",
    "record_write",
    "external_fetch",
  ]) {
    assert.ok(!code.includes(`"${kind}"`), `console.js hard-codes the kind ${kind}`);
    assert.ok(!code.includes(`'${kind}'`), `console.js hard-codes the kind ${kind}`);
  }
});

test("operational kinds come from the server payload, not from name matching", () => {
  assert.deepEqual(operationalKindsOf({ operational: ["send_external"] }), ["send_external"]);
  // No payload ⇒ none known. It must not guess from the names in `kinds`.
  assert.deepEqual(operationalKindsOf({ kinds: ["send_external", "introduction"] }), []);
  assert.deepEqual(operationalKindsOf(null), []);
});

// ── ⚠️ the empty queue must not read as reassurance ──────────────────────────

test("with no operational kinds, an empty queue says nothing is GATED", () => {
  /** An unattended-agent spike measured pending_approvals at 0 across a full four-agent
   * run. "0 pending" next to four working agents reads as "all approved" and is
   * currently the opposite. */
  const doc = new StubDocument();
  const text = allText(buildApprovalsEmpty(doc, { operationalKinds: [] })).toLowerCase();
  assert.ok(text.includes("not"), "the empty state should say what is NOT happening");
  assert.ok(text.includes("gated"), "the empty state should name gating, not just pendency");
  assert.ok(!text.includes("nothing is waiting on you"), "that phrasing implies the queue is working");
});

test("with operational kinds present, an empty queue is simply empty", () => {
  const doc = new StubDocument();
  const text = allText(buildApprovalsEmpty(doc, { operationalKinds: ["send_external"] }));
  assert.ok(text.includes("Nothing is waiting on you"));
});

test("a load failure is stated, never rendered as an empty org", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  const text = allText(renderLoadError(doc, root, SCRIPT));
  assert.ok(text.includes("Could not load"));
  assert.ok(
    text.includes("Nothing below is current"),
    "an error must not be mistakable for an empty dashboard",
  );
  assert.ok(!tags(doc).includes("script"));
});

test("the dashboard puts approvals first", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  renderDashboard(doc, root, { kinds: { kinds: [], operational: [] }, pending: [], agents: [], tasks: [] });
  // Element children only: `clear()` sets textContent = "", which empties a real
  // DOM but leaves one empty text node in the stub. Asserting on childNodes[0]
  // would be testing the stub's clearing behaviour, not the panel order.
  const panels = root.childNodes.filter((n) => n.tagName);
  assert.equal(panels[0].getAttribute("id"), "panel-approvals");
});

// ── join landing: three paths, one token ─────────────────────────────────────

test("the runtime picker is not OpenClaw-only", () => {
  const ids = RUNTIMES.map((r) => r.id);
  assert.ok(ids.includes("openclaw"));
  assert.ok(ids.includes("python"));
  assert.ok(ids.includes("mcp"), "Claude users must not be excluded by the shape");
});

test("the MCP path is rendered as unavailable, with what is missing named", () => {
  /** ⚠️ A "coming soon" that looks like a working option is the
   * plausible-wrong-answer failure on a join flow: a Claude user follows it,
   * nothing works, and they cannot tell whether they misconfigured something or
   * the path does not exist. */
  const doc = new StubDocument();
  const mcp = RUNTIMES.find((r) => r.id === "mcp");
  const node = buildRuntimeCard(doc, mcp, { orgUrl: "https://org", token: "t" });
  assert.equal(node.getAttribute("data-available"), "false");
  const text = allText(node);
  assert.ok(text.includes("Not available yet"));
  assert.ok(text.toLowerCase().includes("no mcp member server"), "it must name what is absent");
  const button = [...walk(node)].find((el) => el.className === "choose");
  assert.equal(button.getAttribute("disabled"), "disabled");
});

test("every available runtime carries the SAME single token", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  renderJoin(doc, root, { orgUrl: "https://org.example", orgName: "Acme", token: "TOKEN-123" });
  const cards = [...walk(root)].filter((el) => el.getAttribute("data-runtime"));
  assert.equal(cards.length, RUNTIMES.length);
  const available = cards.filter((c) => c.getAttribute("data-available") === "true");
  assert.ok(available.length >= 2);
  for (const card of available) {
    assert.ok(allText(card).includes("TOKEN-123"), "a runtime path used a different token");
  }
});

test("a hostile token or org name lands as text", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  renderJoin(doc, root, { orgUrl: "https://org", orgName: SCRIPT, token: ATTR_BREAKER });
  assert.ok(!tags(doc).includes("script"));
  assert.ok(!tags(doc).includes("img"));
  assert.deepEqual(
    doc.attributesSet.filter((a) => /^on/i.test(a.name)),
    [],
  );
});

test("a join link with no token refuses instead of offering three broken paths", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  const text = allText(renderJoin(doc, root, { orgUrl: "https://org", token: "" }));
  assert.ok(text.includes("incomplete"));
  assert.equal([...walk(root)].filter((el) => el.getAttribute("data-runtime")).length, 0);
});

// ── The join landing: org identity and invite state ─────────────────────────
//
// The page rendered a `?org=` value as its own headline, and rendered a token it
// had not checked without saying so. It still does not check the token; see the
// note at the top of join.js for why that is not closed with a validity
// endpoint.

test("the org name is not taken from the query string", () => {
  /** `orgName: params.get("org")` set the page headline from the URL. The value
   * reaches the page through a text node, so the rendered output is the same
   * either way and a render assertion cannot distinguish them; the assertion is
   * therefore on where the string comes from. */
  const source = readFileSync(new URL("../ui/join-boot.js", import.meta.url), "utf8");
  const stripped = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const forbidden of [/params\.get\(\s*["']org["']\s*\)/, /searchParams\.get\(\s*["']org["']\s*\)/]) {
    assert.ok(!forbidden.test(stripped), `join-boot.js reads the org name from the URL again: ${forbidden}`);
  }
  // The token is the ONE thing that legitimately comes from the URL.
  assert.ok(/params\.get\(\s*["']invite["']\s*\)/.test(stripped), "the invite token should still come from the URL");
});

test("no join policy branch claims the invite is valid", () => {
  /** The page does not check the token, so no branch may imply that it did. */
  for (const policy of ["invite", "open", "approval", undefined, "nonsense"]) {
    const doc = new StubDocument();
    const root = doc.createElement("main");
    const text = allText(renderJoin(doc, root, { orgUrl: "https://org", orgName: "Acme", token: "T-1", joinPolicy: policy }));
    const lowered = text.toLowerCase();
    for (const claim of ["invite is valid", "valid invite code", "invite confirmed", "verified invite"]) {
      assert.ok(!lowered.includes(claim), `join policy ${policy}: the page claimed validity ("${claim}")`);
    }
    assert.ok(lowered.includes("not checked"), `join policy ${policy}: the page must say the code is unchecked`);
  }
});

test("each join policy is named on the page", () => {
  /** Under `open` and `approval` the code is not what admits the user, and the
   * page previously rendered the same invite-centric picker in all three cases.
   * The policy is org-wide and public at GET /api/org/join-policy, so reading it
   * discloses nothing about any particular token. */
  const expected = {
    invite: "by invite",
    open: "open — no invite is needed",
    approval: "by leader approval",
  };
  for (const [policy, phrase] of Object.entries(expected)) {
    const doc = new StubDocument();
    const root = doc.createElement("main");
    const node = renderJoin(doc, root, { orgUrl: "https://org", orgName: "Acme", token: "T-1", joinPolicy: policy });
    assert.ok(allText(node).includes(phrase), `join policy ${policy} was not named on the page`);
    const notice = [...walk(node)].find((el) => el.getAttribute("data-policy"));
    assert.equal(notice.getAttribute("data-policy"), policy);
  }
});

test("an unreachable org renders as unknown rather than as an invite org", () => {
  const doc = new StubDocument();
  const root = doc.createElement("main");
  const node = renderJoin(doc, root, { orgUrl: "https://org", orgName: "org.example", token: "T-1", joinPolicy: null });
  const notice = [...walk(node)].find((el) => el.getAttribute("data-policy"));
  assert.equal(notice.getAttribute("data-policy"), "unknown");
  assert.ok(allText(node).includes("could not reach the org"));
});

test("the invite-required refusal text is quoted verbatim", () => {
  /** The page quotes the string the server returns for `invite_required`, so a
   * user who hits it can tell it apart from a local misconfiguration. */
  const doc = new StubDocument();
  const root = doc.createElement("main");
  const text = allText(renderJoin(doc, root, { orgUrl: "https://org", orgName: "Acme", token: "T-1", joinPolicy: "invite" }));
  assert.ok(text.includes("This org requires a valid invite to join."), "the real refusal text must be quoted");
  assert.ok(text.includes("not a problem with your setup"));
});

// ── a request that did not return data is not an empty collection ────────────
//
// `/api/members` answers 401 to anonymous callers, deliberately. The console
// folded that into its fallback and painted "No agents have registered with this
// org yet." on an org with two members.

import { buildAnonymousNotice, buildUnavailable } from "../ui/console.js";

const PANEL_IDS = ["panel-approvals", "panel-agents", "panel-tasks", "panel-receipts"];
const EMPTY_CLAIMS = [
  "No agents have registered",
  "No tasks recorded.",
  "No receipts yet.",
  "Nothing is waiting on you.",
  "Nothing here is gated yet.",
];

function dashboard(doc, data, handlers) {
  const root = doc.createElement("main");
  renderDashboard(doc, root, data, handlers);
  return root;
}

const FAILED_ALL = {
  signedIn: false,
  kinds: { ok: true, data: { kinds: ["introduction"], operational: ["send_external"] } },
  pending: { ok: false, reason: "unauthorised", status: 401 },
  agents: { ok: false, reason: "unauthorised", status: 401 },
  tasks: { ok: false, reason: "missing", status: 404 },
  receipts: { ok: false, reason: "unreachable" },
};

test("no panel claims emptiness when nothing loaded", () => {
  /** The enumeration guard. Every panel is driven with a failed outcome at once,
   * so a panel wired to render data but not to render a reason shows up here
   * rather than in the next person's bug report. */
  const doc = new StubDocument();
  const root = dashboard(doc, FAILED_ALL);
  const text = allText(root);
  for (const claim of EMPTY_CLAIMS) {
    assert.ok(!text.includes(claim), `a panel claimed emptiness while its request had failed: "${claim}"`);
  }
  const explained = [...walk(root)].filter((e) => e.getAttribute("data-unavailable"));
  assert.equal(
    explained.length,
    PANEL_IDS.length,
    `${PANEL_IDS.length} panels but ${explained.length} explained their absence — one renders no reason`,
  );
});

test("each panel names its own subject and endpoint rather than a generic error", () => {
  const doc = new StubDocument();
  const text = allText(dashboard(doc, FAILED_ALL));
  assert.ok(text.includes("Sign in to see agents."), "the agents panel must name agents");
  assert.ok(text.includes("Sign in to see the approval queue."), "the approvals panel must name the queue");
  assert.ok(text.includes("/api/tasks answered 404"), "a missing endpoint must be named");
});

test("a 401 is rendered as unauthorised, never as an empty org", () => {
  const doc = new StubDocument();
  const root = dashboard(doc, { ...FAILED_ALL, agents: { ok: false, reason: "unauthorised", status: 401 } });
  const text = allText(root);
  assert.ok(text.includes("Sign in to see agents."));
  assert.ok(text.includes("This is not an empty org."));
  assert.ok(!text.includes("No agents have registered"));
});

test("a genuinely empty collection still reads as empty", () => {
  /** The true-today case has to survive the fix: an authorised read that returns
   * nothing means nothing is there, and must not be dressed up as a failure. */
  const doc = new StubDocument();
  const root = dashboard(doc, {
    signedIn: true,
    kinds: { ok: true, data: { kinds: [], operational: ["send_external"] } },
    pending: { ok: true, data: [] },
    agents: { ok: true, data: [] },
    tasks: { ok: true, data: [] },
    receipts: { ok: true, data: [] },
  });
  const text = allText(root);
  assert.ok(text.includes("No agents have registered with this org yet."));
  assert.ok(text.includes("No tasks recorded."));
  assert.ok(text.includes("No receipts yet."));
  assert.ok(text.includes("Nothing is waiting on you."));
  assert.deepEqual(
    [...walk(root)].filter((e) => e.getAttribute("data-unavailable")).map((e) => e.getAttribute("data-unavailable")),
    [],
    "an authorised read that returned nothing must not be dressed up as a failure",
  );
});

test("the unauthorised wording distinguishes no-token from a rejected token", () => {
  /** Two different operator actions: sign in, versus sign in AGAIN because the
   * token this browser already holds was refused. */
  const anon = allText(buildUnavailable(new StubDocument(), { reason: "unauthorised", what: "agents", signedIn: false }));
  const stale = allText(buildUnavailable(new StubDocument(), { reason: "unauthorised", what: "agents", signedIn: true }));
  assert.ok(anon.includes("Sign in to see agents."));
  assert.ok(stale.includes("Not authorised to see agents."));
  assert.ok(stale.includes("rotated"), "a refused stored token should say why it might be refused");
  assert.notEqual(anon, stale);
});

test("every failure reason renders a distinct, non-empty explanation", () => {
  const seen = new Map();
  for (const reason of ["unauthorised", "forbidden", "missing", "unreachable", "malformed", "error"]) {
    const doc = new StubDocument();
    const node = buildUnavailable(doc, { reason, status: 500, endpoint: "/api/x", what: "agents" });
    assert.equal(node.getAttribute("data-unavailable"), reason);
    const t = allText(node);
    assert.ok(t.length > 20, `${reason} rendered nothing useful`);
    for (const [other, text] of seen) assert.notEqual(t, text, `${reason} reads identically to ${other}`);
    seen.set(reason, t);
  }
});

test("the unauthorised state links to where the token is", () => {
  const doc = new StubDocument();
  buildUnavailable(doc, { reason: "unauthorised", what: "agents", signedIn: false });
  assert.ok(
    doc.attributesSet.some((a) => a.name === "href" && a.value === "/admin/"),
    "an operator told to sign in needs to be told where",
  );
});

test("the anonymous notice states the page-wide condition once", () => {
  const doc = new StubDocument();
  const t = allText(buildAnonymousNotice(doc));
  assert.ok(t.includes("You are not signed in."));
  assert.ok(t.includes("will say so rather than"), "the notice must explain what the panels will do");
});
