// smb_funnel — single configuration point.
//
// API_BASE selects where the funnel sends its requests:
//   * "mock"          → use the in-page mock backend (src/mock_core.js). Zero
//                       external calls; fully demoable standalone. (default)
//   * "http://…"      → point at a real base URL. Which service is on the other
//     "https://…"       end decides whether this page may be served from
//                       somewhere else; see the next paragraph, which is not
//                       optional reading.
//
// ⚠️ WHERE THIS PAGE IS SERVED FROM IS PART OF THE CONFIGURATION, AND THE TWO
// TARGETS DO NOT AGREE ABOUT IT. This block used to say "point API_BASE at a
// host and nothing else needs to change", which is true of one of them and
// documented a shape the other cannot serve. Measured in a real Chromium against
// a real pair: a cross-origin page pointed at `smb_signup` had its preflight
// refused, the request never left the browser, and every status the service
// would have sent — a 429 with the rate limit spent, a 507 at capacity, a 201 —
// was equally invisible to it.
//
//   * `smb_host` (the multi-tenant host): CROSS-ORIGIN IS SUPPORTED. It mounts
//     CORS naming `Authorization`, because provisioning there is gated on a
//     bearer token and a static bundle hosted elsewhere has to reach it. Serve
//     this page from anywhere and point API_BASE at the host.
//   * `smb_signup` (the public front door): CROSS-ORIGIN IS NOT SUPPORTED, and
//     that is a decision, not an omission. Provisioning through the front door
//     carries no caller credential at all — the bounds are a per-source rate
//     limit and a total tenant cap — so granting any origin access would let any
//     page on the internet spend a visitor's allowance and the operator's cap
//     from that visitor's browser, and (since the front door now forwards caller
//     attribution) record that visitor's address as having provisioned an agent.
//     The shape it supports is the one it is built for: it SERVES this bundle
//     from its own origin, so a public visitor is same-origin by construction.
//     Open the front door's own address; do not point a separately-served page
//     at it. `smb_signup/test_main.py` holds that refusal in place.
//
// To go live against the multi-tenant host:
//   export const API_BASE = "https://smb.nanda.host";
//
// To go live for the public: deploy `smb_signup` and open ITS address. The page
// it serves needs no API_BASE at all — it is already talking to its own origin.
//
// You can also override at runtime without editing this file:
//   * localStorage:      smb_funnel.api_base
// localStorage wins over this constant. It cannot make a cross-origin front door
// work: the refusal is the service's, not this file's.
//
// A `?api=` query parameter was previously honoured here, above localStorage and
// above the constant. It is no longer read.
//
// This value selects the host that answers /provision, and the provisioning
// screen displays that response verbatim: the agent's endpoint, its did:key, and
// the recovery phrase the page instructs the user to write down. A URL parameter
// let the author of a link choose that host, so a link of the form
// `index.html?api=https://other.example` rendered an arbitrary third party's
// values on this origin, including the recovery phrase. No script execution is
// involved, so the page's Content-Security-Policy does not affect it.
//
// localStorage requires the operator to set the value in their own browser. A
// same-origin script could also write it, but a same-origin script on this page
// can already read and alter everything on it, so that is not the boundary this
// setting defends.
//
// The deployment path is unchanged: set the constant below, or replace it in a
// build.

export const API_BASE = "mock";

export function resolveApiBase() {
  try {
    const ls = localStorage.getItem("smb_funnel.api_base");
    if (ls) return ls;
  } catch {
    // localStorage unavailable (e.g. non-browser) — fall through.
  }
  return API_BASE;
}

// ── the provisioning token ───────────────────────────────────────────────────
//
// `smb_host` gates `POST /provision` on a shared secret and answers 401 without
// it (`SMB_HOST_PROVISION_TOKEN`; see smb_host/README.md, "Gating provisioning").
// This funnel is a STATIC PAGE, so anything compiled into it is public — the
// token is therefore never a build-time value. It is handed to a running page by
// whoever is driving the demo, and it dies with the tab.
//
// ⚠️ A QUERY PARAMETER IS READ AGAIN HERE, AND THE `?api=` REMOVAL ABOVE IS NOT
// BEING REVERSED. The two are different risks and the distinction is the whole
// reason one is allowed and the other is not:
//
//   ?api=      — the link's author CHOOSES A HOST for the reader. The reader's
//                recovery phrase, endpoint and did:key are then minted by a
//                stranger's server and displayed on this origin as if they were
//                theirs. The victim is whoever opens the link.
//   ?provision_token= — the link's author GIVES AWAY THEIR OWN SECRET. There is
//                nothing here for an attacker to gain by planting the parameter:
//                a token they already know, sent to the host it already opens.
//                The victim of a leaked link is its author, and the operator
//                pasting it is the person who holds the secret already.
//
// The parameter is therefore accepted, and then made as short-lived as a browser
// permits: read ONCE, moved into `sessionStorage` (which dies with the tab —
// `localStorage` would outlive it and put a credential in a store the funnel
// never clears), and stripped from the address bar before anything renders, so it
// does not survive a copied URL, a bookmark, a screen share, or the history.
//
// It is never rendered. `tests/provision-token.test.mjs` asserts that over the
// whole node tree rather than over the elements a reader expects it in.

const TOKEN_KEY = "smb_funnel.provision_token";
const TOKEN_PARAM = "provision_token";

/**
 * Take the token out of the URL and into session storage, once, at boot.
 *
 * Returns true when a token was captured this call — for the page's own use, not
 * as a value to display. Degrades silently: a browser with session storage off
 * still runs the funnel, it just cannot provision against a gated host.
 */
export function captureProvisionToken() {
  let search = "";
  try {
    search = (globalThis.location && globalThis.location.search) || "";
  } catch {
    return false;
  }
  if (!search) return false;

  let token = "";
  try {
    token = new URLSearchParams(search).get(TOKEN_PARAM) || "";
  } catch {
    return false;
  }
  if (!token) return false;

  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Storage unavailable. The parameter is still stripped below: a credential
    // left in the address bar is worse than one the page cannot remember.
  }
  stripTokenFromUrl(search);
  return true;
}

/** Rewrite the address bar without the token parameter, preserving the rest. */
function stripTokenFromUrl(search) {
  try {
    const params = new URLSearchParams(search);
    params.delete(TOKEN_PARAM);
    const rest = params.toString();
    const { pathname = "", hash = "" } = globalThis.location || {};
    // replaceState, not pushState: the URL carrying the token must not remain a
    // "back" away. No navigation, so nothing is re-fetched.
    globalThis.history.replaceState(null, "", `${pathname}${rest ? `?${rest}` : ""}${hash}`);
  } catch {
    // No history API (or a non-browser). Nothing else to do — the token is
    // already out of the parameter as far as this page's own reads go.
  }
}

/** The token to send with `POST /provision`, or "" when this browser has none. */
export function provisionToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

/**
 * Whether this browser holds a token — WITHOUT handing over its value.
 *
 * The rendering layer needs to tell "the host wants a credential I do not have"
 * apart from "the host refused the credential I do have", and that is the whole
 * of what it needs. Exporting a boolean rather than the string means the module
 * that writes to the document cannot leak a secret it was never given: the
 * no-token-in-the-DOM guard holds by construction there, not by discipline.
 */
export function hasProvisionToken() {
  return provisionToken() !== "";
}
