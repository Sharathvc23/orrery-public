// smb_funnel — DOM builders. No HTML strings, anywhere, by construction.
//
// ⚠️ WHY THIS MODULE EXISTS. app.js used to build these nodes by interpolating
// data into HTML template strings and assigning `innerHTML`. Most of those
// interpolations were routed through `escapeHtml` — but one was not: the
// RECOVERY PHRASE chip at app.js:158 interpolated a phrase word raw. A recovery
// phrase re-derives the agent's did:key, so that string is full identity
// takeover; it was the single highest-value string this product ever renders and
// the only one the file forgot to escape.
//
// Wrapping it in escapeHtml would have been the patch, not the fix. Correctness
// would still have rested on eleven separate call sites each remembering, and
// the next interpolation would still be one keystroke from the same bug. So the
// unsafe path is removed instead: these functions build element and text nodes,
// and there is no code here that can turn data into markup. `escapeHtml` is gone
// from the funnel with them — a live escaper invites the string-building style
// back.
//
// The document is INJECTED rather than taken from the global so the real render
// path can be driven under a stub DOM that detonates on `innerHTML`. That stub
// is what makes the adversarial test an assertion about the node tree rather
// than about which helper was called.
//
// Guard: tests/source-guard.test.mjs bans the sinks statically, so a future edit
// that reintroduces one fails even on a code path no behavioural test reaches.
// Same two-layer discipline the reference renderer already uses.

/** Create an element. `text` becomes a single text node; `children` are appended. */
export function el(doc, tag, { className, id, text, attrs } = {}, children = []) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (id) node.setAttribute("id", id);
  if (attrs) for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  if (text !== undefined && text !== null) node.appendChild(doc.createTextNode(String(text)));
  for (const child of children) if (child) node.appendChild(child);
  return node;
}

/** A bare text node. The only way data enters the tree. */
export function text(doc, value) {
  return doc.createTextNode(String(value ?? ""));
}

/** Empty an element. `textContent = ""` clears children in a real DOM and needs
 *  no HTML parsing, unlike the `innerHTML = ""` idiom it replaces. */
export function clear(node) {
  node.textContent = "";
}

/**
 * The recovery-phrase chips — the node that carried the bug.
 *
 * A chip is a number and a word. It never needed markup: the index is a span,
 * the word is a text node, and a word containing `<script>` is therefore a
 * string in the document rather than an element in it.
 */
export function buildPhraseChips(doc, phrase) {
  return String(phrase ?? "")
    .split(" ")
    .filter((w) => w.length > 0)
    .map((word, i) =>
      el(doc, "span", { className: "word" }, [
        el(doc, "span", { className: "word-n", text: String(i + 1) }),
        text(doc, word),
      ]),
    );
}

/** The booking-failure line. `message` is server-influenced — see the report. */
export function buildBookingError(doc, message) {
  return el(doc, "p", { className: "err", text: `Booking failed: ${message}` });
}

function sigRow(doc, label, value, { valueClass } = {}) {
  return el(doc, "div", { className: "sig-row" }, [
    el(doc, "span", { text: label }),
    el(doc, "code", { className: valueClass, text: value ?? "" }),
  ]);
}

function definition(doc, term, value, valueNode) {
  return [el(doc, "dt", { text: term }), el(doc, "dd", valueNode ? {} : { text: value }, valueNode ? [valueNode] : [])];
}

/**
 * What happened to the booking after it was recorded — as a state, never as an
 * assumption.
 *
 * ⚠️ THE PANEL USED TO SAY "Booking confirmed" AND STOP. `smb_host` puts
 * `delivered`, `delivery_channel` and `delivery_note` on every `/book` response
 * for one reason, written in its own source: "a caller that is told nothing
 * cannot tell a delivered booking from one the business will never see." This
 * module read none of them. A booking that reached nobody rendered identically
 * to one that arrived, under a heading saying it was confirmed — on the page
 * whose form promises the contact address is where bookings go.
 *
 * THREE STATES, because three things can be true and two of them are not the
 * same fact:
 *
 *   delivered === true    it reached the channel the host names
 *   delivered === false   it did not, and the host says why
 *   absent                this backend said nothing about delivery
 *
 * ⚠️ ABSENT IS NOT A FAILURE AND MUST NOT BE PAINTED AS ONE. The in-page demo
 * backend delivers nothing and used to report nothing; a reader shown a warning
 * for silence would be told a judgement nobody made. It gets neutral styling and
 * words that name the silence.
 *
 * `channel` and `note` are host-supplied text and arrive as TEXT NODES like
 * every other field in this panel — there is no markup path for them to take.
 */
function deliveryState(delivered, channel, note) {
  if (delivered === true) {
    return { className: "status-ok", text: channel ? `Delivered · ${channel}` : "Delivered" };
  }
  if (delivered === false) {
    return { className: "status-warn", text: note ? `Not delivered — ${note}` : "Not delivered" };
  }
  return { className: "status-unknown", text: "Not stated — this backend did not say whether it reached the business" };
}

/**
 * The signed-receipt panel (audit H13 — "innerHTML with user data in the SMB
 * funnel receipt display").
 *
 * ⚠️ EVERY field here is server-supplied: receipt id, booking fields, issuer
 * did, signature. They were all escaped before, so this was not exploitable —
 * but it was the largest attacker-influenced interpolation surface in the
 * product, correct only because eleven call sites each remembered. Built as
 * nodes, it is correct because there is nothing to remember.
 *
 * Returns `{ node, badge }` so the caller can update the verification badge
 * without re-querying the document for an id it just wrote.
 */
export function buildReceipt(doc, { receiptId, booking, receipt, whenStr, delivered, deliveryChannel, deliveryNote }) {
  const b = booking || {};
  const rcpt = receipt || null;
  const action = (rcpt && rcpt.action) || {};

  const badge = el(doc, "span", { className: "verify-badge verify-pending", id: "verify-badge" }, [
    el(doc, "span", { className: "verify-dot" }),
    text(doc, " Verifying…"),
  ]);

  const head = el(doc, "div", { className: "receipt-head" }, [
    el(doc, "div", {}, [
      // ⚠️ "Booking confirmed" WAS THE PANEL'S OWN WORD, NOT THE HOST'S. It
      // rendered whether or not the response carried a status, above a Status
      // cell that then fell back to the same word — the most prominent string
      // here asserting the one thing the reader came to find out. The title now
      // names what the panel IS; what happened to the booking is in the two rows
      // below, each read from the response.
      el(doc, "div", { className: "receipt-title", text: "Booking receipt" }),
      el(doc, "div", { className: "receipt-id", text: receiptId || "" }),
    ]),
    badge,
  ]);

  const grid = el(doc, "dl", { className: "receipt-grid" }, [
    ...definition(doc, "Service", b.service || "—"),
    ...definition(doc, "Provider", b.provider || "—"),
    ...definition(doc, "When", whenStr),
    // ⚠️ NO INVENTED FALLBACK. This cell used to fall back to the literal
    // "confirmed" whenever the host sent no status — the renderer asserting an
    // outcome rather than reporting one, which is the same defect the delivery
    // row below exists to fix, one line up. An absent status renders as an em
    // dash and nothing else.
    //
    // ⚠️ AND THE VALUE IS ATTRIBUTED, BECAUSE OF WHAT IT MEANS AT THE SOURCE.
    // `smb_host` sets `booking["status"]` unconditionally, BEFORE delivery is
    // consulted — measured: a booking comes back with a status alongside
    // `delivered: false` in the same response. Nobody at the business agrees to
    // anything; there is no acceptance step anywhere in the path. The value is
    // now `recorded` rather than `confirmed` for exactly that reason, and both
    // sides are held to it by tests/host_contract.json. Read unattributed and
    // painted green, a status word says the business agreed. Read as the host's
    // own record of what it wrote down, it is exactly true.
    //
    // The label names the speaker and the act. The styling is neutral rather
    // than the success green it used to carry, because green is a verdict on an
    // outcome this panel does not know — NOT because the outcome is bad. The
    // colour belongs to the Delivery row below, which is the one backed by
    // something the host actually observed.
    ...definition(
      doc,
      "Status (as the host recorded it)",
      null,
      el(doc, "span", { className: "status-recorded", text: b.status || "—" }),
    ),
    ...definition(doc, "Delivery", null, el(doc, "span", deliveryState(delivered, deliveryChannel, deliveryNote))),
  ]);

  const evidence = rcpt
    ? el(doc, "details", { className: "sig" }, [
        el(doc, "summary", { text: "Signature evidence" }),
        sigRow(doc, "ARP version", rcpt.version),
        sigRow(doc, "Issuer (did:key)", rcpt.issuer_did),
        sigRow(doc, "Action", `${action.category || ""} · ${action.outcome || ""}`),
        sigRow(doc, "Issued at", rcpt.issued_at),
        // Every other row here is a field OF the receipt. This one is not: an ARP
        // receipt carries no algorithm field, and Ed25519 is fixed by the
        // multicodec prefix of `issuer_did` and by the only verify call this
        // module makes. Presented as a document field, inside a panel headed
        // "Signature evidence", it read as something the receipt stated.
        sigRow(doc, "Algorithm (from the did:key, not a receipt field)", "Ed25519"),
        sigRow(doc, "Signature", rcpt.signature, { valueClass: "sig-val" }),
      ])
    : el(doc, "p", { className: "err", text: "No signed receipt returned — nothing to verify." });

  return { node: el(doc, "div", { className: "receipt" }, [head, grid, evidence]), badge };
}

/**
 * Repaint the verification badge.
 *
 * The label is a constant chosen from a closed set — never assembled from the
 * verification result, whose `stage`/`detail` are attacker-influenced. Those go
 * to `title`, which is a property assignment and cannot become markup.
 */
export function paintVerifyBadge(doc, badge, state) {
  // ⚠️ THE LABEL HAS TO SAY WHAT WAS CHECKED, NOT JUST THAT SOMETHING WAS.
  // "Verified offline in your browser ✓" reads as "this really is from them",
  // and for a receipt whose issuer nobody checked it meant only "this document
  // is self-consistent" — which a stranger's honestly-signed receipt satisfies
  // just as well. Unknown provenance gets its own state and its own words.
  //
  // ⚠️ AND IT MUST NOT NAME A CHECK THAT DID NOT RUN. "signed by this business"
  // was the second version of the same defect: the comparison is against the
  // did:key on the agent card THIS HOST served in this session, which makes the
  // host internally consistent rather than proving it is the business — and the
  // funnel briefly said "pinned", naming a localStorage store that no code on
  // the verdict path ever read. The label now names the card, because the card
  // is what was compared.
  const LABELS = {
    ok: { className: "verify-badge verify-ok", label: " Verified offline — matches this agent's card ✓", dot: true },
    unknown: {
      className: "verify-badge verify-unknown",
      label: " Signature valid — issuer not confirmed",
      dot: true,
    },
    mismatch: {
      className: "verify-badge verify-fail",
      label: " Signed by a different key than the agent card ✗",
      dot: true,
    },
    fail: { className: "verify-badge verify-fail", label: " Verification failed ✗", dot: true },
    unsigned: { className: "verify-badge verify-none", label: "unsigned", dot: false },
  };
  const spec = LABELS[state];
  if (!badge || !spec) return badge;
  badge.className = spec.className;
  clear(badge);
  if (spec.dot) badge.appendChild(el(doc, "span", { className: "verify-dot" }));
  badge.appendChild(text(doc, spec.label));
  return badge;
}

/**
 * The provisioning-failure panel, as a state plus the nodes that say it.
 *
 * ⚠️ WHY A MISSING CREDENTIAL GETS ITS OWN STATE. This was one line —
 * "Couldn't create your agent: <message>. Please try again." — for every way
 * provisioning can fail, and "please try again" is wrong advice for three of
 * them. A host that gates provisioning answers 401 forever; retrying is the one
 * thing that cannot work. The page already knows the difference, so sending the
 * operator to the host's logs for a configuration fact this page holds is a
 * choice, not a limitation.
 *
 * The four states are distinguishable from the response alone plus one bit the
 * page owns — whether this tab is holding a token:
 *
 *   credential-missing   401, and this browser has no token
 *   credential-rejected  401, and it has one the host does not accept
 *   host-unconfigured    503, the host itself is not set up to provision
 *   input-rejected       400/422, the host refused what was entered
 *
 * ⚠️ input-rejected COVERS THE CONTACT AS WELL AS THE NAME, AND ITS HEADLINE HAD
 * TO STOP NAMING ONE FIELD. Provisioning now requires a contact channel, so a
 * 400/422 can be about the name, the contact, or both — and this panel used to
 * open "That business name can't be used", which is simply false when the
 * contact is what was refused. It is one STATE because it is one ACTION: change
 * what you entered and submit again. A separate contact-rejected state would give
 * identical advice under a different heading, which is the same defect as
 * collapsing two actions into one, pointing the other way. The specificity a
 * person needs is already in the host's own message, which is rendered below the
 * copy — "contact: Field required", or the host naming plain http as refused.
 *   name-taken           409, the name is claimed by another business
 *   rate-limited         429, too many signups from this connection just now
 *   at-capacity          507, the service has issued its whole allocation
 *   not-delivered        the request never reached a server — no status at all
 *   not-delivered-config the same, and this page is configured to call another
 *                        origin, which is a cause it can actually check
 *   failed               a status arrived and none of the above matched (5xx)
 *
 * ⚠️ not-delivered EXISTS BECAUSE "failed" WAS A VERDICT ON AN EXCHANGE THAT DID
 * NOT HAPPEN. A `fetch` the browser stops carries no status, so an undelivered
 * request fell through every branch above into "Couldn't create your agent.
 * Please try again." — a sentence that implies a server answered and that
 * answering again might go differently. Measured in a real Chromium: a page on
 * one origin, pointed at `smb_signup` on another with the rate limit already
 * spent, was shown exactly that for a 429 whose request never left the browser,
 * and every other status was equally invisible.
 *
 * The page cannot say WHY — a refused preflight, a dead host and a dropped
 * connection reach page script as the same `TypeError`. It can say that nothing
 * was received, which is true and is the part that matters, and it can name the
 * one cause it is able to check: `smb_signup` grants no cross-origin access, so
 * a page it does not serve cannot call it. That is the second state, and it is a
 * second state rather than a longer paragraph because the ACTION differs —
 * waiting can fix a dead host and cannot fix an origin that will never be
 * allowed.
 *
 * ⚠️ rate-limited AND at-capacity ARE TWO STATES, NOT ONE "we are busy". Waiting
 * fixes the first and never fixes the second: a rate limit clears on its own,
 * while a full allocation stays full until an operator raises it. Collapsing them
 * would tell a business to come back in an hour to a door that will still be
 * shut — the same defect as telling a 401 to try again, one floor up.
 *
 * ⚠️ THE TOKEN IS NOT A PARAMETER HERE, AND THAT IS DELIBERATE. This module
 * writes to the document; if it never receives the secret it cannot render it,
 * whatever a later edit does. `hasToken` is a boolean for exactly that reason.
 * `message` is the host's own words (`detail`), server-influenced, so it goes in
 * as a text node like every other value in this file.
 */
export function buildProvisionError(doc, { status, message, hasToken, unreachable, crossOrigin }) {
  // ⚠️ "PLEASE TRY AGAIN" IS ONLY ADVICE WHEN TRYING AGAIN COULD WORK. The first
  // version of this table routed everything that was not 401 or 503 to it, on the
  // reasoning that a name collision is worth retrying. That reasoning was wrong
  // twice over. A punctuation-only or whitespace-only name is a 400 that repeats
  // forever, and a 409 means the name is ALREADY TAKEN — resubmitting the same
  // name is the one thing that cannot succeed in either case. Both need a changed
  // name, not another attempt, so both say so.
  // ⚠️ CHECKED BEFORE THE STATUS TABLE, NOT INSIDE IT. Every branch below asks
  // what the server said; this one is the case where it said nothing, and a
  // status of `undefined` is indistinguishable from a status the table has no
  // row for. Ordering it first is what stops "no answer" being read as "an
  // answer I do not recognise".
  const state = unreachable
    ? crossOrigin
      ? "not-delivered-config"
      : "not-delivered"
    : status === 401
      ? hasToken
        ? "credential-rejected"
        : "credential-missing"
      : status === 503
        ? "host-unconfigured"
        : status === 429
          ? "rate-limited"
          : status === 507
            ? "at-capacity"
            : status === 409
              ? "name-taken"
              : status === 400 || status === 422
                ? "input-rejected"
                : "failed";

  const COPY = {
    "credential-missing": {
      headline: "This host needs a provisioning credential.",
      body:
        "Provisioning is gated on a shared secret, and this browser does not have one. " +
        "Re-open this page with ?provision_token=<the secret the host was started with> — " +
        "it is kept for this tab only, and removed from the address bar as soon as it is read.",
    },
    "credential-rejected": {
      headline: "The host rejected this browser's provisioning credential.",
      body:
        "This tab is holding a token, and it is not the one the host was started with. " +
        "Re-open this page with the current ?provision_token=… — retrying will not change the answer.",
    },
    "host-unconfigured": {
      headline: "This host is not set up to provide agents.",
      body:
        "The refusal is a setting on the host, not something this page can supply. " +
        "The host's own words are below.",
    },
    "input-rejected": {
      headline: "Those details can't be used as entered.",
      body:
        "The host refused what was entered rather than failing — submitting it again unchanged " +
        "will get the same answer. Change what it names below and try once more.",
    },
    "name-taken": {
      headline: "That business name is already taken on this host.",
      body:
        "Another business has provisioned under it, and a tenant id is claimed once. " +
        "Choose a different name — resubmitting this one cannot succeed.",
    },
    "rate-limited": {
      headline: "Too many signups from this connection just now.",
      body:
        "This is a temporary limit and it clears on its own — wait a little and try again. " +
        "Nothing is wrong with the name you entered.",
    },
    "at-capacity": {
      headline: "This service has issued all the agents it is allowed to.",
      body:
        "Every agent here mints a key and takes storage, so the number is capped on purpose. " +
        "Waiting will not clear it — the cap has to be raised by whoever runs this service.",
    },
    "not-delivered": {
      headline: "The request never reached the service.",
      body:
        "Nothing came back — not a refusal, not an error, no answer at all — so there is no " +
        "verdict here about your details or about this service's capacity. Something between " +
        "this page and the service stopped the request. Try again in a moment; if it keeps " +
        "happening the service is not reachable from here.",
    },
    "not-delivered-config": {
      headline: "This page cannot reach the service it is configured to call.",
      body:
        "Nothing came back, so nothing here is an answer from the service — it was never asked. " +
        "This page is being served from one origin and is configured to call another, and the " +
        "signup service deliberately grants no cross-origin access: it serves this page itself, " +
        "and a page it did not serve cannot call it. Open this page from the signup service's " +
        "own address, or point it at a host that permits this origin. Retrying will not change " +
        "the answer.",
    },
    failed: {
      headline: "Couldn't create your agent.",
      body: "Please try again.",
    },
  };
  const copy = COPY[state];

  const nodes = [
    el(doc, "strong", { className: "err-headline", text: copy.headline }),
    el(doc, "p", { className: "err-body", text: copy.body }),
  ];
  if (message) nodes.push(el(doc, "p", { className: "err-detail" }, [el(doc, "code", { text: message })]));
  return { state, nodes };
}
