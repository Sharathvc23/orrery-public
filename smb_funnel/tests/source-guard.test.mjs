/**
 * Static source audit for the SMB funnel: no code path may turn data into
 * markup or into code.
 *
 * ⚠️ THIS IS THE HALF THAT LASTS. The adversarial tests in render.test.mjs prove
 * the current render path is safe; this proves no FUTURE one is unsafe, including
 * paths no behavioural test reaches. The bug it exists to prevent (a recovery
 * phrase word interpolated raw into `innerHTML`) was one keystroke's worth of
 * difference from its correctly-escaped neighbour four lines away — discipline
 * had already failed once on the highest-value string in the product.
 *
 * Comments are stripped before scanning, so the modules can explain WHY these
 * sinks are banned by name without tripping the ban. Same two-layer discipline
 * as renderer/tests/source-guard.test.mjs, which this mirrors deliberately.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const SRC = new URL("../src/", import.meta.url).pathname;

const FORBIDDEN = [
  /\binnerHTML\b/,
  /\bouterHTML\b/,
  /insertAdjacentHTML/,
  /\bdocument\.write\b/,
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /setTimeout\s*\(\s*["'`]/,
  /setInterval\s*\(\s*["'`]/,
  /createContextualFragment/,
  /DOMParser/,
  /dangerouslySetInnerHTML/,
  /srcdoc/,
];

/**
 * Remove comments while leaving string and template literals intact.
 *
 * A blunt regex would either mangle `"https://…"` (treating `//` as a comment)
 * or miss block comments, and a guard that scans the wrong text is worse than
 * no guard — it reads as protection while checking something else.
 */
function stripComments(source) {
  let out = "";
  let i = 0;
  let state = "code";
  let quote = "";
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (state === "code") {
      if (c === "/" && next === "/") {
        state = "line";
        i += 2;
        continue;
      }
      if (c === "/" && next === "*") {
        state = "block";
        i += 2;
        continue;
      }
      if (c === '"' || c === "'" || c === "`") {
        state = "string";
        quote = c;
        out += c;
        i += 1;
        continue;
      }
      out += c;
      i += 1;
    } else if (state === "string") {
      if (c === "\\") {
        out += c + (next ?? "");
        i += 2;
        continue;
      }
      if (c === quote) state = "code";
      out += c;
      i += 1;
    } else if (state === "line") {
      if (c === "\n") {
        state = "code";
        out += c;
      }
      i += 1;
    } else {
      if (c === "*" && next === "/") {
        state = "code";
        i += 2;
        continue;
      }
      i += 1;
    }
  }
  return out;
}

test("stripComments keeps code and string literals, drops only comments", () => {
  // The guard is only as trustworthy as its stripper, so the stripper is pinned:
  // if it silently ate everything, every assertion below would pass vacuously.
  assert.equal(stripComments('const a = 1; // innerHTML\n').trim(), "const a = 1;");
  assert.equal(stripComments("/* innerHTML */ const b = 2;").trim(), "const b = 2;");
  assert.ok(stripComments('const u = "https://x/y";').includes("https://x/y"));
  assert.ok(stripComments("const s = '// not a comment';").includes("// not a comment"));
  assert.ok(stripComments("const t = `a // b`;").includes("a // b"));
  // And it must NOT be able to hide a real sink.
  assert.ok(/\binnerHTML\b/.test(stripComments('el.innerHTML = "x"; // fine')));
});

test("no HTML or eval sink appears anywhere in smb_funnel source", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the funnel modules under src/, found ${files.length}`);
  for (const file of files) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    for (const re of FORBIDDEN) {
      assert.ok(!re.test(source), `${file} contains forbidden sink ${re}`);
    }
  }
});

test("escapeHtml is gone — a live escaper invites the string-building style back", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  for (const file of files) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    assert.ok(!/function\s+escapeHtml/.test(source), `${file} still defines escapeHtml`);
  }
});

test("only the painting modules touch the DOM at all", () => {
  // api/arp/config/mock_core are protocol and crypto logic; a DOM call appearing
  // in one of them means rendering leaked into a layer this guard does not cover.
  for (const file of ["api.js", "arp.js", "config.js", "mock_core.js"]) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    assert.ok(!/createElement|appendChild|textContent/.test(source), `${file} should be DOM-free`);
  }
});

// ── URL sinks ────────────────────────────────────────────────────────────────
//
// Every pattern in FORBIDDEN above turns data into markup or into code. An
// assignment like `a.href = value` does neither: it parses no HTML and calls no
// evaluator, so those patterns do not match it. It is still a sink, because a
// `javascript:` value runs on click wherever inline script is permitted, and a
// http(s) value navigates the user to a host the page did not author.
//
// The funnel's own Content-Security-Policy (`script-src 'self'` in the index
// meta tag) blocks execution of a javascript: URL, but it is a second layer:
// adding `'unsafe-inline'` removes it, and a copy of the pattern in a document
// served without that meta has no such policy at all.
//
// These assignments are therefore rejected outright rather than routed through a
// sanitiser, which would put correctness on each future call site. Values that
// need to be shown are rendered as text and copied, as the card URL, endpoint
// and did:key fields all are.

const FORBIDDEN_URL_SINKS = [
  /\.\s*href\s*=[^=]/,
  /\.\s*src\s*=[^=]/,
  /\.\s*action\s*=[^=]/,
  /\.\s*formAction\s*=[^=]/,
  /setAttribute\s*\(\s*["'`](href|src|srcset|action|formaction|xlink:href)["'`]/i,
  /location\s*\.\s*(href|assign|replace)\s*[=(]/,
];

test("no module assigns a URL the browser will follow", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the funnel modules under src/, found ${files.length}`);
  for (const file of files) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    for (const re of FORBIDDEN_URL_SINKS) {
      assert.ok(!re.test(source), `${file} assigns a navigable URL from data — ${re}`);
    }
  }
});

test("the URL-sink patterns match assignments and not reads or comparisons", () => {
  /** `.href` also appears when reading a location, and `===` must not be taken
   * for an assignment, so the patterns are pinned against both the forms they
   * must catch and the forms they must leave alone. */
  const catches = [
    'a.href = cardLink;',
    'a.href=`${t.endpoint}/x`;',
    'img.src = data.avatar;',
    'el.setAttribute("href", u);',
    "el.setAttribute('src', u);",
    'location.href = next;',
    'window.location.replace(u);',
  ];
  for (const line of catches) {
    assert.ok(
      FORBIDDEN_URL_SINKS.some((re) => re.test(line)),
      `no pattern catches: ${line}`,
    );
  }
  const allowed = [
    'if (a.href === expected) return;',
    'const here = location.href;',
    'el.setAttribute("data-copy", sel);',
    'el.setAttribute("class", "mono");',
  ];
  for (const line of allowed) {
    assert.ok(
      !FORBIDDEN_URL_SINKS.some((re) => re.test(line)),
      `a pattern wrongly rejects: ${line}`,
    );
  }
});

// ── claims ───────────────────────────────────────────────────────────────────
//
// A sink turns data into markup. A CLAIM turns nothing into anything — it is a
// sentence on screen, and it is a control's whole value to the person reading it.
//
// ⚠️ THE BUG THIS PREVENTS. The funnel's success tooltip read "the issuer matches
// this business's pinned did:key". Nothing was pinned in that comparison:
// `src/pin.js` wrote a `did:key` to localStorage, `pinnedDid()` had no caller
// outside the tests, and the value the receipt was actually checked against was
// the card DID fetched in the same session. Every behavioural test passed —
// including the badge-wording test, which asserted the states differed from each
// other and not that they were true. A rendered badge cannot reveal that its
// label names a check that never ran, so what is checkable is the word.
//
// Comments are exempt: the history of the removed store is worth keeping in the
// source, and a comment is not a claim made to a customer.

const CLAIMS_A_PIN = /\bpin(s|ned|ning)?\b/i;

test("no string the funnel can paint claims a pin", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the funnel modules under src/, found ${files.length}`);
  let scanned = 0;
  for (const file of files) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    for (const literal of source.match(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g) || []) {
      scanned++;
      assert.doesNotMatch(literal, CLAIMS_A_PIN, `${file} paints a string claiming a pin: ${literal}`);
    }
  }
  assert.ok(scanned > 50, `the literal scan found only ${scanned} strings — it is not reading the modules`);
});

test("the shipped document claims no pin either", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url).pathname, "utf8");
  assert.doesNotMatch(html, CLAIMS_A_PIN, "index.html claims a pin");
  assert.match(html, /verify-badge|try-result/, "the scan must be reading the funnel page");
});

test("the pin guard would catch the wording it exists to catch", () => {
  /** Guards the guard. A claim regex that matched nothing would pass every
   * assertion above for the wrong reason, so it is pinned against the exact
   * sentence that shipped and against words it must NOT flag. */
  for (const claim of [
    `"the issuer matches this business's pinned did:key"`,
    `"no pinned identity was supplied"`,
    `"Pin this key"`,
    `"we pin the card DID"`,
  ]) {
    assert.match(claim, CLAIMS_A_PIN, `the guard misses: ${claim}`);
  }
  for (const innocent of ['"spinning up your agent"', '"input"', '"pinnacle"', '"Copy phrase"']) {
    assert.doesNotMatch(innocent, CLAIMS_A_PIN, `the guard wrongly flags: ${innocent}`);
  }
});

test("pin.js is gone, and its absence is what makes the wording true", () => {
  /** The wording guard alone would pass on a funnel that kept the store and
   * merely stopped naming it — which is the same dead security-shaped module
   * with quieter copy. */
  assert.ok(!readdirSync(SRC).includes("pin.js"), "pin.js is back; the verdict path still does not read it");
});

// ── claims, second family: what a check on this page cannot establish ─────────
//
// The pin guard above catches a label naming a check that never ran. This family
// catches the opposite shape — a label naming a check that DID run, and claiming
// more from it than its inputs can carry.
//
// ⚠️ THE LIMIT, ONCE, SO EVERY ASSERTION BELOW IS READ AGAINST IT. The host
// serves the tenant's agent card AND signs the tenant's receipts. Checking one
// against the other establishes that the host put the key it signs with on the
// card it serves — internal consistency. It does not establish that the host is
// the business, and no check performed in this browser can, because both
// documents come from the party under question.
//
// So a customer-facing string on this page may not say the verification defeats
// a dishonest host, may not describe key custody as exclusive when the host
// holds the signing key it minted, and may not name a verified BUSINESS when
// what was compared was a key against a card.
//
// This is not hypothetical drift. The funnel's own README carried
// "client-side and trustless: … a tampered receipt — or a lying server — is
// detected in the browser" three hundred lines below the section stating that a
// lying server is exactly the case nothing here catches. Both sentences were
// written in good faith; nothing compared them.

/** Affirmative trustlessness. The negative lookbehind is load-bearing: prose
 *  SAYING the funnel is not trustless is the correction, not the claim. */
const CLAIMS_TRUSTLESSNESS = /(?<!\bnot )\btrustless\b|\bno trust in (?:the )?(?:server|host)\b|\bzero[- ]trust\b/i;

/** Key custody described as exclusive. The host mints the tenant's Ed25519 key,
 *  persists it in the tenant's vault and signs bookings with it, so the customer
 *  is a holder of that key and not the only one. */
const CLAIMS_EXCLUSIVE_CUSTODY = /\byou (?:keep|hold|own|control) the (?:only )?keys?\b|\bonly you\b[^.]{0,40}\bkeys?\b/i;

/** A verified BUSINESS. What the badge compares is a signature against a card;
 *  the noun it may attach to is a key, a signature or a card — never a merchant. */
const CLAIMS_A_VERIFIED_BUSINESS =
  /\b(?:verified|confirmed|trusted|authenticated|certified)\s+(?:business|merchant|shop|seller|company|owner)\b|\b(?:business|merchant|shop|seller)\b\s+(?:is\s+)?(?:verified|confirmed|authenticated|certified)\b/i;

const OVERCLAIMS = [
  ["trustlessness", CLAIMS_TRUSTLESSNESS],
  ["exclusive key custody", CLAIMS_EXCLUSIVE_CUSTODY],
  ["a verified business", CLAIMS_A_VERIFIED_BUSINESS],
];

/** Every string literal the funnel's modules could paint. */
function paintableLiterals() {
  const out = [];
  const files = readdirSync(SRC).filter((f) => f.endsWith(".js"));
  assert.ok(files.length >= 5, `expected the funnel modules under src/, found ${files.length}`);
  for (const file of files) {
    const source = stripComments(readFileSync(join(SRC, file), "utf8"));
    for (const literal of source.match(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g) || []) {
      out.push([file, literal]);
    }
  }
  return out;
}

test("no string the funnel can paint claims more than the same-origin check establishes", () => {
  const literals = paintableLiterals();
  assert.ok(literals.length > 50, `the literal scan found only ${literals.length} strings — it is not reading the modules`);
  for (const [file, literal] of literals) {
    for (const [name, re] of OVERCLAIMS) {
      assert.doesNotMatch(literal, re, `${file} paints a string claiming ${name}: ${literal}`);
    }
  }
});

test("the shipped document claims no more than that either", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url).pathname, "utf8");
  assert.match(html, /verify-badge|try-result/, "the scan must be reading the funnel page");
  for (const [name, re] of OVERCLAIMS) {
    assert.doesNotMatch(html, re, `index.html claims ${name}`);
  }
});

test("the funnel's own README does not contradict the section it ships", () => {
  /** The README is where the contradiction actually shipped, and it is what the
   *  next person writing badge copy reads. Scanned for the same overclaims — and
   *  the section stating the limit must still be there, so the guard cannot be
   *  satisfied by deleting the honest half. */
  const readme = readFileSync(new URL("../README.md", import.meta.url).pathname, "utf8");
  assert.match(readme, /### What none of this proves: the issuer is the business/, "the limit section is gone");
  assert.match(readme, /same origin/i, "the README no longer states the same-origin limit");
  for (const [name, re] of OVERCLAIMS) {
    assert.doesNotMatch(readme, re, `smb_funnel/README.md claims ${name}`);
  }
});

test("the overclaim guards would catch the wording they exist to catch", () => {
  /** Guards the guards. Each regex is pinned against sentences that shipped or
   *  that a reasonable contributor would write, AND against correct prose it
   *  must not block — a guard that blocks correct prose gets deleted rather than
   *  followed, which is the failure mode this repository names by name. */
  const mustMatch = [
    [CLAIMS_TRUSTLESSNESS, '"Receipt verification is client-side and trustless"'],
    [CLAIMS_TRUSTLESSNESS, '"verified in your browser — no trust in the server"'],
    [CLAIMS_TRUSTLESSNESS, '"zero-trust receipt checking"'],
    [CLAIMS_EXCLUSIVE_CUSTODY, '"Free to start · No credit card · You keep the keys."'],
    [CLAIMS_EXCLUSIVE_CUSTODY, '"you own the keys"'],
    [CLAIMS_EXCLUSIVE_CUSTODY, '"only you can ever use this key"'],
    [CLAIMS_A_VERIFIED_BUSINESS, '"Verified business"'],
    [CLAIMS_A_VERIFIED_BUSINESS, '"this business is verified"'],
    [CLAIMS_A_VERIFIED_BUSINESS, '"trusted merchant"'],
  ];
  for (const [re, claim] of mustMatch) assert.match(claim, re, `the guard misses: ${claim}`);

  const mustNotMatch = [
    // the badge vocabulary that ships today, and must keep shipping
    '" Verified offline — matches this agent\'s card ✓"',
    '" Signature valid — issuer not confirmed"',
    '" Signed by a different key than the agent card ✗"',
    '" Verification failed ✗"',
    // the corrections themselves — prose about the limit is not a claim of it
    '"It is not trustless, and a lying server is the case it does NOT catch."',
    '"You leave with a recovery phrase."',
    '"Copy phrase"',
    '"Your recovery phrase is the only way to restore control of your agent."',
  ];
  for (const innocent of mustNotMatch) {
    for (const [name, re] of OVERCLAIMS) {
      assert.doesNotMatch(innocent, re, `the ${name} guard wrongly flags: ${innocent}`);
    }
  }
});

test("the badge that says 'verified' still says what it did not check", () => {
  /** The positive half. Banning the overclaim leaves a page that could simply
   *  say less — a green tick and no limit anywhere is the same defect quieter.
   *  The success tooltip is the one place the limit reaches a customer, so its
   *  two load-bearing clauses are pinned: the origins are the same, and that is
   *  not the same as knowing who the host is. */
  const app = readFileSync(join(SRC, "app.js"), "utf8");
  const titles = stripComments(app).match(/badge\.title\s*=\s*[\s\S]{0,400}?;/g) || [];
  assert.ok(titles.length >= 4, `expected a tooltip per badge state, found ${titles.length}`);
  const success = titles.find((t) => /Ed25519 signature checked in this browser/.test(t));
  assert.ok(success, "the success tooltip is gone or no longer names the check it runs");
  assert.match(success, /same origin/i, "the success tooltip stopped naming the same-origin limit");
  assert.match(success, /not that the host is the business/i, "the success tooltip stopped naming what it does not prove");
});
