// smb_funnel — shared mock backend core.
//
// Implements the REAL multi-tenant host API contract (smb_host) in pure,
// dependency-free JavaScript. Imported by BOTH:
//   * the in-page mock (via src/api.js) — so the funnel runs standalone in a
//     browser with zero external calls, and
//   * the standalone stub server (mock_server.mjs) — a real HTTP backend for
//     headless smoke tests and "point the funnel at a real URL" demos.
//
// The response SHAPES here mirror smb_host byte-for-byte where it matters: in
// particular POST /t/{tenant}/book returns the RAW signed ARP receipt
// (`{version, receipt_id, issuer_did, principal_did, issued_at, action, signature}`),
// signed with a REAL, in-process-generated Ed25519 key — so the SAME offline
// verify path (src/arp.js) that checks a real smb_host receipt is exercised here
// too: a genuine receipt verifies TRUE, a tampered one verifies FALSE.
//
// Because signing/verification are async (WebCrypto), the endpoints and the
// router are async; callers await route(...).

import {
  ARP_VERSION,
  generateIdentity,
  signReceipt,
  publicKeyToDidKey,
  publicKeyFromDidKey,
} from "./arp.js";

// ── deterministic-ish helpers (no crypto dependency needed for these) ───────

const BIP39_SAMPLE = [
  "anchor", "beacon", "cedar", "delta", "ember", "falcon", "granite", "harbor",
  "ivory", "juniper", "kestrel", "lantern", "meadow", "nectar", "opal", "pilot",
  "quartz", "ripple", "summit", "timber", "umber", "violet", "willow", "xenon",
  "yarrow", "zephyr", "amber", "basalt", "copper", "dawn", "echo", "frost",
];

function rand(n) {
  const g = globalThis.crypto;
  if (g && g.getRandomValues) {
    const buf = new Uint32Array(1);
    g.getRandomValues(buf);
    return buf[0] % n;
  }
  return Math.floor(Math.random() * n);
}

// ⚠️ NO `|| "agent"` FALLBACK, AND THAT ABSENCE IS THE FIX. This ended with
// `|| "agent"`, so a name with no alphanumerics — `!!!`, `...` — did not slug to
// nothing, it silently became the tenant id "agent" and PROVISIONED: 201, a
// did:key, a 24-word recovery phrase, for a name the real host refuses with a
// 400. A default that fires where the input was unusable does not rescue the
// request, it invents a different one and answers that. The host's `_slugify`
// returns the empty string here and lets the caller refuse; so does this.
function slugify(name) {
  return (name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

// smb_host hands back a 24-word recovery phrase (recovery.generate_recovery()).
function recoveryPhrase(words = 24) {
  const out = [];
  for (let i = 0; i < words; i++) out.push(BIP39_SAMPLE[rand(BIP39_SAMPLE.length)]);
  return out.join(" ");
}

// RFC 3339 UTC, seconds precision — matches arp.py's _utc_now_rfc3339().
function rfc3339Now() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ── in-memory tenant store ──────────────────────────────────────────────────

const tenants = new Map();

// The host origin the mock pretends to be. The real smb_host returns its own
// absolute endpoint; the funnel treats `endpoint` as opaque.
const MOCK_HOST = "https://smb.nanda.host";

// ── contract endpoints (mirror smb_host/main.py) ────────────────────────────

/** FastAPI's 422 body: a LIST of error objects, not a string. */
function validationError(type, msg, input, field = "business_name") {
  return {
    status: 422,
    json: { detail: [{ type, loc: ["body", field], msg, input: input === undefined ? {} : input }] },
  };
}

// The host classifies a contact by its shape rather than by a caller-supplied
// type, and refuses plain http outright: a booking carries a customer's name and
// time. These two messages are pinned by tests/host_contract.json.
const EMAIL = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

function contactProblem(raw) {
  const value = String(raw).trim();
  const lowered = value.toLowerCase();
  if (lowered.startsWith("https://")) return "";
  if (lowered.startsWith("http://")) {
    return (
      "a plain http webhook is refused: a booking carries a customer's name and time, " +
      "so the delivery URL must be https"
    );
  }
  if (EMAIL.test(value)) return "";
  return (
    `'${value}' is neither an https webhook URL nor an email address, ` +
    "so it names no channel a booking can be delivered on"
  );
}

// POST /provision {business_name, service_type?}
//   → {tenant_id, endpoint, recovery_phrase, did}
// tenant_id is the slug (as smb_host does); did is a REAL Ed25519 did:key whose
// private key stays in-process so this tenant can sign verifiable receipts. This
// host registers on NO index — the response is exactly what a downstream operator
// (host39) needs to register the agent on the NANDA Index itself. No `urn` (that
// was an index concept).
export async function provision(body) {
  // ⚠️ THE REFUSALS BELOW ARE THE HOST'S, NOT THIS FILE'S OPINION OF THEM.
  // This mock answered {error: "business_name is required"} with a 400 where the
  // host answers 422 with FastAPI's validation ARRAY — and, worse, it PROVISIONED
  // a punctuation-only name and a non-string name that the host refuses outright,
  // so a demo on the mock showed a barber getting an agent for input the product
  // rejects. The README's claim that this funnel speaks the real host contract
  // either way is only true if the refusals match too.
  // tests/host_contract.json states them once; smb_host/test_main.py holds the
  // host to it and tests/contract-parity.test.mjs holds this file to it.
  const raw = body ? body.business_name : undefined;

  // 422, the shape FastAPI produces before a handler is entered: absent, wrong
  // type, or empty (min_length=1). `loc` and `type` are pinned by the contract.
  if (raw === undefined || raw === null) return validationError("missing", "Field required", raw);
  if (typeof raw !== "string") {
    return validationError("string_type", "Input should be a valid string", raw);
  }
  if (raw.length === 0) {
    return validationError("string_too_short", "String should have at least 1 character", raw);
  }

  // The contact channel, refused on the same grounds and in the same order the
  // host uses. A business that cannot be reached cannot receive a booking, so
  // this is required rather than optional — a mock that provisioned without one
  // would demo a barber getting an agent that accepts bookings and delivers
  // none, which is the product failure this field exists to prevent.
  const contact = body ? body.contact : undefined;
  if (contact === undefined || contact === null) {
    return validationError("missing", "Field required", contact, "contact");
  }
  if (typeof contact !== "string") {
    return validationError("string_type", "Input should be a valid string", contact, "contact");
  }
  if (contact.length === 0) {
    return validationError("string_too_short", "String should have at least 1 character", contact, "contact");
  }
  const contactRefusal = contactProblem(contact);
  if (contactRefusal) return { status: 400, json: { detail: contactRefusal } };

  const businessName = raw.trim();
  const tenantId = slugify(businessName);
  // 400, the host's own check: a name that slugs to nothing has no tenant id.
  // Whitespace-only reaches here as a non-empty string, exactly as it does there.
  if (!tenantId) {
    return {
      status: 400,
      json: { detail: "business_name must contain at least one alphanumeric character" },
    };
  }

  const serviceType = body.service_type ? String(body.service_type).trim() : "";
  if (tenants.has(tenantId)) {
    return {
      status: 409,
      json: { detail: `a business is already provisioned under the name '${businessName}'` },
    };
  }

  const { privateKey, did } = await generateIdentity();
  const record = {
    tenant_id: tenantId,
    endpoint: `${MOCK_HOST}/t/${tenantId}`,
    recovery_phrase: recoveryPhrase(24),
    did,
    privateKey, // WebCrypto CryptoKey — NEVER serialized out of the mock.
    business_name: businessName,
    service_type: serviceType,
    contact: contact.trim(),
    bookings: 0,
    created_at: rfc3339Now(),
  };
  tenants.set(tenantId, record);
  // recovery_phrase is returned ONCE, on provision only — never from GETs.
  return {
    status: 201,
    json: {
      tenant_id: record.tenant_id,
      endpoint: record.endpoint,
      recovery_phrase: record.recovery_phrase,
      did: record.did,
    },
  };
}

// GET /t/{tenant_id}/.well-known/agent.json → A2A agent card (did:key attached).
export function agentCard(tenantId) {
  const t = tenants.get(tenantId);
  if (!t) return { status: 404, json: { detail: `no tenant '${tenantId}'` } };
  return {
    status: 200,
    json: {
      protocolVersion: "0.3.0",
      name: t.business_name,
      description: t.service_type
        ? `${t.business_name} — ${t.service_type}. Books appointments over A2A.`
        : `${t.business_name} agent on NANDA.`,
      url: t.endpoint,
      preferredTransport: "JSONRPC",
      provider: { organization: t.business_name, url: t.endpoint },
      version: "1.0.0",
      capabilities: { streaming: false },
      defaultInputModes: ["text"],
      defaultOutputModes: ["text"],
      // NANDA sovereign identity attached to the card (mirrors smb_host's
      // build_agent_card: Ed25519 auth carrying the did:key as credential).
      authentication: { schemes: ["ed25519", "did-auth"], credentials: t.did },
      "x-nanda": { did: t.did },
      skills: [
        {
          id: "book-appointment",
          name: "Book an appointment",
          description: t.service_type
            ? `Schedule ${t.service_type} with ${t.business_name}.`
            : `Schedule an appointment with ${t.business_name}.`,
          tags: ["booking", "scheduling"],
          inputModes: ["text"],
          outputModes: ["text"],
        },
      ],
    },
  };
}

// POST /t/{tenant_id}/book {service, provider, datetime, notes}
//   → {booking, receipt_id, receipt}   (receipt is the RAW signed ARP receipt)
export async function book(tenantId, body) {
  const t = tenants.get(tenantId);
  if (!t) return { status: 404, json: { detail: `no tenant '${tenantId}'` } };

  const b = body || {};
  const service = (b.service ? String(b.service) : "").trim();
  const provider = (b.provider ? String(b.provider) : "").trim();
  const datetime = (b.datetime ? String(b.datetime) : "").trim();
  const notes = (b.notes ? String(b.notes) : "").trim();
  const missing = [["service", service], ["provider", provider], ["datetime", datetime]]
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length) {
    return { status: 400, json: { detail: `missing required field(s): ${missing.join(", ")}` } };
  }

  const bookingId = ++t.bookings;
  // Build the raw ARP receipt with the SAME action shape as the member-SDK
  // booking skill (community_member/builtin_skills/booking/skill.py), then sign
  // it with THIS tenant's real Ed25519 key so it verifies offline under its did.
  const receipt = {
    version: ARP_VERSION,
    receipt_id: globalThis.crypto.randomUUID(),
    issuer_did: t.did,
    principal_did: t.did,
    issued_at: rfc3339Now(),
    action: {
      category: "appointment_booked",
      outcome: "completed",
      human_summary: `Booked ${service} with ${provider} at ${datetime}`,
      machine_payload: {
        service,
        provider,
        datetime,
        notes,
        booking_id: bookingId,
      },
    },
  };
  await signReceipt(receipt, t.privateKey);

  // `recorded`, matching the host. The word is not cosmetic: a booking row is
  // written and the slot is checked free, and nobody at the business agrees to
  // anything — there is no acceptance step in the path. The value both sides
  // must produce is stated once in tests/host_contract.json and asserted from
  // both, so this literal cannot drift from the host's without a red test.
  const booking = { service, provider, datetime, notes, status: "recorded", tenant_id: tenantId };
  return {
    status: 200,
    json: {
      booking,
      receipt_id: receipt.receipt_id,
      receipt,
      // ⚠️ THE MOCK DELIVERS NOTHING, AND NOW SAYS SO. It omitted these fields
      // entirely, so the demo backend — which is what API_BASE = "mock" makes
      // the default at the public front door — was the one path where the page
      // could not even have reported delivery had it tried. The mock being the
      // permissive side is the exact divergence host_contract.json exists to
      // stop, and it is worse here than on a refusal: this is a success screen.
      delivered: false,
      delivery_channel: "none",
      delivery_note: "the in-page demo backend records the booking and sends it nowhere",
    },
  };
}

// GET /health
export function health() {
  return {
    status: 200,
    json: { status: "ok", service: "smb-host", tenants: tenants.size },
  };
}

// Router shared by the in-page mock and the Node stub. `method` + `path`
// (pathname only) + parsed `body` object → Promise<{status, json}>.
export async function route(method, path, body) {
  if (method === "GET" && path === "/health") return health();
  if (method === "POST" && path === "/provision") return provision(body);

  const wk = path.match(/^\/t\/([^/]+)\/\.well-known\/agent\.json$/);
  if (method === "GET" && wk) return agentCard(decodeURIComponent(wk[1]));

  const bk = path.match(/^\/t\/([^/]+)\/book$/);
  if (method === "POST" && bk) return book(decodeURIComponent(bk[1]), body);

  return { status: 404, json: { detail: "Not Found" } };
}

// Re-exported so mock_server.mjs / tooling can share the exact primitives.
export { publicKeyToDidKey, publicKeyFromDidKey };
