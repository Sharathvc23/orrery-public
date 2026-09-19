// Join landing wiring. Same split as console-boot: no globals in join.js, so
// the runtime picker can be driven under a stub DOM in node.
//
// The token is the only value this page takes from the URL. It also read `?org=`
// for the headline, so a link of the form
//   /join?invite=x&org=Example%20Payments%20(verified)
// set the page's own heading to text chosen by whoever wrote the link, served
// from the org's origin under its certificate. The name reaches the page through
// a text node, so this was not script injection; the value was simply not the
// org's to state. It now comes from the server.

import { renderJoin } from "./join.js";

const ROOT = document.getElementById("root");
const params = new URLSearchParams(location.search);

// One token, read from the QR's URL. Every runtime path below carries this same
// token — revoking the invite revokes all three, because there is one invite,
// not one per runtime.
const token = (params.get("invite") || params.get("token") || "").trim();

/** Read one field from a same-origin JSON endpoint; null on any failure. */
async function readField(path, field) {
  try {
    const resp = await fetch(path, { headers: { accept: "application/json" } });
    if (!resp.ok) return null;
    const body = await resp.json();
    const value = body && body[field];
    return typeof value === "string" && value ? value : null;
  } catch {
    return null; // offline, blocked, or not this build — the caller degrades.
  }
}

function paint({ orgName, joinPolicy }) {
  renderJoin(document, ROOT, {
    orgUrl: location.origin,
    // location.host is the fallback rather than a query parameter: the visitor
    // can check it against their address bar.
    orgName: orgName || location.host,
    token,
    joinPolicy,
    onChoose: (runtime) => {
      // Selection is local: it reveals the command for that runtime. Nothing is
      // registered here — registration happens when the member's own agent calls
      // the org with the invite, holding a key this page never sees.
      const card = ROOT.querySelector(`[data-runtime="${CSS.escape(runtime.id)}"]`);
      if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
    },
  });
}

// Paint from what is known locally, then again once the org answers, so the page
// is usable before the two requests land.
paint({ orgName: null, joinPolicy: null });

// Neither request carries the token. Both read org-wide values that are already
// public and say nothing about any particular invite; asking the server whether a
// given token is usable would let anyone test codes. See the note in join.js.
Promise.all([
  readField("/api/portal/chapter", "name"),
  readField("/api/org/join-policy", "join_policy"),
]).then(([orgName, joinPolicy]) => paint({ orgName, joinPolicy }));
