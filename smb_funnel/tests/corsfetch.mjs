/**
 * `fetch` WITH THE BROWSER'S CORS RULE APPLIED — because node's has none.
 *
 * ⚠️ THIS IS THE WHOLE POINT OF THE FILE. Node's `fetch` performs no preflight
 * and enforces no cross-origin rule, so every existing suite that drives the
 * funnel "against a real host" is really driving it against a host with CORS
 * switched off. A status code node sees is not a status code a page receives:
 * for one release the gated host was unreachable from a browser entirely,
 * because the middleware's `allow_headers` omitted `Authorization` and the
 * preflight was refused — so the page saw an opaque network failure with a valid
 * token as readily as without one, and the preflight test that existed asked
 * only for `content-type` and passed the whole time.
 *
 * A wrapper cannot make node a browser. What it can do is apply the specific
 * rule that failure turned on, at the moment a browser applies it: BEFORE the
 * real request is sent. When a preflight refuses the header, this throws the
 * `TypeError` a browser throws and the real request never goes out — which is
 * exactly why the page could not tell 401 from 201.
 *
 * Deliberately NOT a general CORS implementation. It models the four checks that
 * decide whether the request leaves the browser at all, and nothing else; a
 * fuller mock would be a second specification to keep correct.
 */

/** Headers a browser sends without a preflight (CORS-safelisted). */
const SIMPLE_HEADERS = new Set(["accept", "accept-language", "content-language", "content-type"]);
const SIMPLE_CONTENT_TYPES = new Set([
  "application/x-www-form-urlencoded",
  "multipart/form-data",
  "text/plain",
]);

function needsPreflight(method, headers) {
  if (!["GET", "HEAD", "POST"].includes(method.toUpperCase())) return true;
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (!SIMPLE_HEADERS.has(lower)) return true;
    if (lower === "content-type") {
      const type = String(value).split(";")[0].trim().toLowerCase();
      if (!SIMPLE_CONTENT_TYPES.has(type)) return true;
    }
  }
  return false;
}

function originAllowed(allowOrigin, origin) {
  return allowOrigin === "*" || allowOrigin === origin;
}

function listed(headerValue, wanted) {
  if (headerValue == null) return false;
  if (headerValue.trim() === "*") return true;
  const allowed = new Set(headerValue.split(",").map((h) => h.trim().toLowerCase()));
  return wanted.every((w) => allowed.has(w.toLowerCase()));
}

/**
 * A `fetch` bound to a page origin, enforcing the browser's cross-origin rule.
 *
 * `blocked` receives every request the rule stopped, so a test can assert WHY a
 * page saw nothing rather than only that it did.
 */
export function corsFetch(pageOrigin, { blocked = [] } = {}) {
  const real = globalThis.fetch;

  async function browserFetch(url, init = {}) {
    const target = new URL(String(url));
    const sameOrigin = target.origin === pageOrigin;
    const method = (init.method || "GET").toUpperCase();
    const headers = init.headers || {};

    if (sameOrigin) return real(url, init);

    const fail = (why) => {
      blocked.push({ url: String(url), why });
      // The error a browser surfaces to page script. It carries no status,
      // which is the defect in one sentence: the page cannot tell what the
      // server would have said, because the server was never asked.
      return Promise.reject(new TypeError(`Failed to fetch — ${why}`));
    };

    if (needsPreflight(method, headers)) {
      const requested = Object.keys(headers)
        .map((h) => h.toLowerCase())
        .sort();
      let pre;
      try {
        pre = await real(String(url), {
          method: "OPTIONS",
          headers: {
            Origin: pageOrigin,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": requested.join(", "),
          },
        });
      } catch (e) {
        return fail(`the preflight could not be sent: ${e.message}`);
      }
      if (pre.status < 200 || pre.status >= 300) {
        return fail(`the preflight was refused with ${pre.status}`);
      }
      if (!originAllowed(pre.headers.get("access-control-allow-origin"), pageOrigin)) {
        return fail(`the preflight did not allow the origin ${pageOrigin}`);
      }
      if (!listed(pre.headers.get("access-control-allow-methods"), [method])) {
        return fail(`the preflight did not allow the method ${method}`);
      }
      if (!listed(pre.headers.get("access-control-allow-headers"), requested)) {
        return fail(
          `the preflight did not allow the header(s) ${requested.join(", ")} ` +
            `(it allows: ${pre.headers.get("access-control-allow-headers")})`,
        );
      }
    }

    const resp = await real(url, { ...init, headers: { ...headers, Origin: pageOrigin } });
    // The response check a browser also applies: without the header the body is
    // withheld from page script even though the server ran the request.
    if (!originAllowed(resp.headers.get("access-control-allow-origin"), pageOrigin)) {
      return fail(`the response did not allow the origin ${pageOrigin}`);
    }
    return resp;
  }

  return browserFetch;
}
