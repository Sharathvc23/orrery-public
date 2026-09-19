#!/usr/bin/env python3
"""The three clicks, in a real browser, against the real smb_host.

⚠️ WHY A BROWSER, WHEN THE SUITE IS ALREADY GREEN. The CORS defect this repository
shipped — ``Authorization`` missing from the host's allowlist, which made a gated
host unusable from a browser with a valid token exactly as much as without one —
was invisible to every test here:

  * ``smb_funnel/tests/wiring.test.mjs`` boots the real ``app.js`` and drives its
    own handlers, but a constructed document performs no preflight.
  * ``smb_funnel/smoke.mjs`` speaks to the mock in-process. No network at all.
  * ``scripts/demo_smb_stack.sh`` drives the real host with curl and node, where
    there is no ``Origin`` and therefore no preflight to fail.
  * ``smb_host``'s own preflight test asked only for ``content-type``.

Five green suites, and the front door was shut. It took a person opening a
browser. That is a whole class of defect — preflight, CSP, the address bar,
``sessionStorage``, the fetch the page actually makes — where nothing else here
can see, and where the failure lands on a customer rather than in a log.

WHAT THIS DRIVES. Two separate origins, deliberately: the host on one port and
the funnel on another, because same-origin would remove the preflight, which is
the thing being tested.

  A. the happy path with a credential — three clicks, the live screen, the token
     gone from the address bar, and a receipt the page verifies in-browser
  B. a fresh browser with no credential — the credential-required panel, not a
     generic failure
  C. a host serving ONE key on its card and signing with ANOTHER — the mismatch
     badge, reached through a real fetch rather than a stubbed one
  D. THE PUBLIC PATH — the same three clicks through `smb_signup`, with no
     credential anywhere in the browser, and the at-capacity refusal rendered
  E. A CROSS-ORIGIN PAGE POINTED AT `smb_signup` — the shape the front door
     deliberately does not serve. The browser stops the request, and what the
     visitor is then told must not be a verdict on an exchange that never
     happened

Run it directly; it boots and tears down everything it needs:

    PYTHONPATH=agent python3 scripts/browser_smb_funnel.py [--headed]

Exit 0 iff every case passed.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FUNNEL = ROOT / "smb_funnel"
TOKEN = "browser-e2e-provisioning-secret"
IMPOSTOR_DID = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"

failures: list[str] = []
blocked: list[str] = []
console: list[str] = []


def ok(msg: str) -> None:
    print(f"   \033[32m✓\033[0m {msg}")


def bad(msg: str) -> None:
    failures.append(msg)
    print(f"   \033[31m✗ {msg}\033[0m")


def check(cond: bool, msg: str) -> bool:
    (ok if cond else bad)(msg)
    return bool(cond)


def hr(title: str) -> None:
    print(f"\n\033[1m── {title} ──\033[0m")


def run_case(name: str, fn) -> None:
    """Run one case. A timeout or an exception is a FAILURE, not a crash.

    ⚠️ THE HARNESS HAS TO SURVIVE THE DEFECT IT EXISTS FOR. Under the planted CORS
    regression the first version of this script aborted mid-run with a Playwright
    traceback — a true signal rendered unreadably, and it meant the later cases
    never ran, so one defect hid the others.
    """
    del blocked[:]
    try:
        fn()
    except Exception as e:
        first = (str(e).strip().splitlines() or [type(e).__name__])[0]
        bad(f"case {name}: {first}")
    finally:
        if blocked:
            # The browser knows WHY a request never happened; the page only knows
            # that nothing came back. Without this, a refused preflight reads as an
            # unexplained timeout and sends the next reader to the wrong layer.
            print("      the browser refused these requests:")
            for entry in blocked[-4:]:
                print(f"        · {entry}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for(url: str, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.25)
    return False


# ── the funnel, served as static files on its own origin ─────────────────────


class FunnelHandler(http.server.SimpleHTTPRequestHandler):
    """Serves smb_funnel/. ES modules need a JavaScript MIME type or the browser
    refuses to execute them, which would fail every case for the wrong reason."""

    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".json": "application/json",
    }

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(FUNNEL), **kw)

    def log_message(self, *a):
        pass


# ── a host that lies about its own key, for case C ───────────────────────────


def make_divergent_proxy(upstream: str, fake_did: str):
    """Forward everything to the real host, but rewrite the card's ``did:key``.

    This is the impostor shape a browser cannot otherwise be shown: the receipt
    stays genuinely signed by the tenant's real key, and only the CARD disagrees.
    Everything else — including the host's own CORS headers — is passed through,
    so the preflight this case performs is still the host's answer, not ours.
    """

    class Proxy(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _relay(self, body: bytes | None) -> None:
            req = urllib.request.Request(
                upstream + self.path,
                data=body,
                method=self.command,
                headers={
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in ("host", "content-length", "connection")
                },
            )
            try:
                with urllib.request.urlopen(req) as resp:
                    status = resp.status
                    headers = list(resp.headers.items())
                    payload = resp.read()
            except urllib.error.HTTPError as e:
                status, headers, payload = e.code, list(e.headers.items()), e.read()
            except Exception as e:
                status = 502
                headers = [("Content-Type", "application/json")]
                payload = json.dumps({"detail": f"proxy could not reach the host: {e}"}).encode()

            if self.path.endswith("/.well-known/agent.json") and status == 200:
                card = json.loads(payload)
                card.setdefault("x-nanda", {})["did"] = fake_did
                if isinstance(card.get("authentication"), dict):
                    card["authentication"]["credentials"] = fake_did
                payload = json.dumps(card).encode()

            self.send_response(status)
            for key, value in headers:
                if key.lower() in ("content-length", "transfer-encoding", "connection"):
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._relay(None)

        def do_OPTIONS(self):
            self._relay(None)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self._relay(self.rfile.read(n) if n else b"")

    return Proxy


def serve(handler, port: int) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ── the drive ────────────────────────────────────────────────────────────────


def main() -> int:
    headed = "--headed" in sys.argv
    from playwright.sync_api import sync_playwright

    host_port, funnel_port, proxy_port = free_port(), free_port(), free_port()
    signup_port = free_port()
    host_origin = f"http://127.0.0.1:{host_port}"
    funnel_origin = f"http://127.0.0.1:{funnel_port}"
    proxy_origin = f"http://127.0.0.1:{proxy_port}"
    signup_origin = f"http://127.0.0.1:{signup_port}"
    data_dir = tempfile.mkdtemp(prefix="browser-e2e-")

    hr("0. boot the real smb_host (gated on a provisioning token) and serve the funnel")
    env = {
        **os.environ,
        "HOST_PUBLIC_URL": host_origin,
        "SMB_HOST_DATA_DIR": data_dir,
        "COMMUNITY_MEMBER_KEYSTORE": "device",
        "SMB_HOST_POOL_SIZE": "0",
        "SMB_HOST_PROVISION_TOKEN": TOKEN,
        "SMB_HOST_TENANT_CAP": "1000",
        "PYTHONPATH": f"{ROOT / 'agent'}:{os.environ.get('PYTHONPATH', '')}",
    }
    host = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "main:app",
            "--host", "127.0.0.1", "--port", str(host_port), "--log-level", "warning",
        ],
        cwd=str(ROOT / "smb_host"),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    funnel_srv = serve(FunnelHandler, funnel_port)
    proxy_srv = None
    signup_proc: subprocess.Popen | None = None

    def start_signup(upstream: str, port: int, cap: int) -> subprocess.Popen:
        """The public front door, bounded, holding the token this browser never sees."""
        nonlocal signup_proc
        signup_env = {
            **env,
            "SMB_SIGNUP_HOST_URL": upstream,
            "SMB_SIGNUP_TENANT_CAP": str(cap),
            "SMB_SIGNUP_RATE_PER_HOUR": "50",
        }
        signup_proc = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn", "smb_signup.main:app",
                "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
            ],
            cwd=str(ROOT),
            env=signup_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        return signup_proc

    try:
        if not wait_for(f"{host_origin}/health"):
            bad("smb_host did not come up")
            return 1
        if not wait_for(f"{funnel_origin}/index.html"):
            bad("the funnel is not being served")
            return 1
        ok(f"smb_host @ {host_origin} (gated) · funnel @ {funnel_origin}")
        check(
            host_origin != funnel_origin,
            "the page and the host are on DIFFERENT origins, so a preflight is required",
        )

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not headed)

            def open_funnel(api_base: str, query: str = "", page_origin: str | None = None):
                """A fresh context pointed at `api_base`, as an operator's would be.

                `API_BASE` is read from localStorage by src/config.js — the
                documented way to point the funnel at a host without editing the
                file — injected before any page script runs.
                """
                context = browser.new_context()
                context.add_init_script(
                    "try { localStorage.setItem('smb_funnel.api_base', "
                    + json.dumps(api_base)
                    + "); } catch (e) {}"
                )
                page = context.new_page()
                page.on("console", lambda m: console.append(f"[{m.type}] {m.text}"))
                page.on("pageerror", lambda e: console.append(f"[pageerror] {e}"))
                page.on(
                    "requestfailed",
                    lambda r: blocked.append(f"{r.method} {r.url} — {r.failure or 'failed'}"),
                )
                # The page's own origin. The operator shape serves the bundle
                # from somewhere other than the host, so those cases are
                # cross-origin and exercise a preflight. The PUBLIC shape is
                # served BY the façade, so it is same-origin by construction —
                # which is why smb_signup carries no CORS headers and should not.
                page.goto(f"{page_origin or funnel_origin}/index.html{query}", wait_until="domcontentloaded")
                return context, page

            def three_clicks(page, name: str, service: str) -> None:
                page.fill("#business-name", name)
                page.fill("#service-type", service)
                # Required by the host and by the form: a business that cannot be
                # reached cannot receive a booking, so the submit does not leave
                # the page without one. The address is on a reserved-for-
                # documentation domain, so this drive delivers to nobody.
                page.fill("#contact", "https://bookings.invalid/browser-drive")
                page.click("#funnel-form button[type=submit], #funnel-form .btn-primary")

            def settled_badge(page) -> str:
                page.wait_for_selector("#verify-badge", timeout=30000)
                page.wait_for_function(
                    "() => !/Verifying/.test(document.querySelector('#verify-badge').textContent)",
                    timeout=30000,
                )
                return (page.text_content("#verify-badge") or "").strip()

            def case_a() -> None:
                context, page = open_funnel(host_origin, f"?provision_token={TOKEN}")
                try:
                    three_clicks(page, "Fadeaway Barbershop", "Haircuts & hot-towel shaves")
                    page.wait_for_selector("#screen-live:not([hidden])", timeout=30000)
                    ok("the live screen rendered — the gated POST /provision succeeded from a browser")

                    endpoint = (page.text_content("#endpoint") or "").strip()
                    did = (page.text_content("#did") or "").strip()
                    check(endpoint.startswith(host_origin), f"the page rendered the host's endpoint: {endpoint}")
                    check(did.startswith("did:key:z6Mk"), f"the page rendered a did:key: {did[:34]}…")
                    # Counted as ELEMENTS: render.js builds each word as a <span>
                    # with no whitespace between chips, so splitting the text gives
                    # one run-on token. A first draft asserted on that and failed
                    # for a reason that had nothing to do with the page.
                    words = page.locator("#recovery-phrase .word").count()
                    check(words == 24, f"a 24-word recovery phrase was shown ({words} chips)")

                    check("provision_token" not in page.url, f"the token is gone from the address bar: {page.url}")
                    stored = page.evaluate("() => sessionStorage.getItem('smb_funnel.provision_token')")
                    check(stored == TOKEN, "the token is in sessionStorage, where it dies with the tab")
                    check(TOKEN not in (page.content() or ""), "the token appears nowhere in the rendered document")

                    page.click("#try-btn")
                    badge = settled_badge(page)
                    check("Verified" in badge, f"the receipt verified IN THE BROWSER: {badge}")
                finally:
                    shown = (page.text_content("#form-error") or "").strip()
                    if shown:
                        print(f"      the page said: {shown[:300]}")
                    context.close()

            def case_b() -> None:
                context, page = open_funnel(host_origin)
                try:
                    three_clicks(page, "No Token Co", "Nothing")
                    page.wait_for_selector("#form-error:not([hidden])", timeout=30000)
                    state = page.get_attribute("#form-error", "data-state")
                    text = (page.text_content("#form-error") or "").strip()
                    check(state == "credential-missing", f"the credential panel rendered (data-state={state})")
                    check(
                        "try again" not in text.lower(),
                        "it does not tell the operator to retry a 401 that repeats forever",
                    )
                    check("provision_token" in text, "it says how the credential is supplied")
                finally:
                    context.close()

            def case_c() -> None:
                context, page = open_funnel(proxy_origin, f"?provision_token={TOKEN}")
                try:
                    three_clicks(page, "Divergent Key Co", "Haircuts")
                    page.wait_for_selector("#screen-live:not([hidden])", timeout=30000)
                    page.click("#try-btn")
                    badge = settled_badge(page)
                    check("different key" in badge.lower(), f"the mismatch badge painted: {badge}")
                    check("Verified" not in badge, "a key the card never published is not reported as verified")
                finally:
                    context.close()

            hr("A. three clicks with a provisioning credential, in the browser")
            run_case("A", case_a)

            hr("B. a fresh browser with no credential")
            run_case("B", case_b)

            # ── D ─────────────────────────────────────────────────────────
            def case_d() -> None:
                """The public front door, driven the way a stranger would meet it.

                ⚠️ NO CREDENTIAL IS SUPPLIED ANYWHERE HERE — no query parameter, no
                header, nothing in storage. If the three clicks work, the token is
                being held server-side; if the token were reaching the browser this
                would still pass, so the assertion below greps the whole document
                and every module the page loaded for the secret itself.
                """
                context, page = open_funnel(signup_origin, page_origin=signup_origin)
                try:
                    three_clicks(page, "Public Signup Co", "Haircuts")
                    page.wait_for_selector("#screen-live:not([hidden])", timeout=30000)
                    ok("the live screen rendered with NO credential in the browser")
                    did = (page.text_content("#did") or "").strip()
                    check(did.startswith("did:key:z6Mk"), f"a real identity was minted: {did[:34]}…")

                    served = page.content() or ""
                    for module in ("src/app.js", "src/api.js", "src/config.js"):
                        served += page.evaluate(
                            "async (u) => (await fetch(u)).text()", f"{signup_origin}/{module}"
                        )
                    check(TOKEN not in served, "the provisioning secret is nowhere in what the browser holds")

                    page.click("#try-btn")
                    badge = settled_badge(page)
                    check("Verified" in badge, f"the receipt verified through the front door: {badge}")
                finally:
                    context.close()

            def case_d_full() -> None:
                """The cap, reached through the browser, rendering its own panel."""
                context, page = open_funnel(signup_origin, page_origin=signup_origin)
                try:
                    three_clicks(page, "One Too Many Co", "Haircuts")
                    page.wait_for_selector("#form-error:not([hidden])", timeout=30000)
                    state = page.get_attribute("#form-error", "data-state")
                    text = (page.text_content("#form-error") or "").strip()
                    check(state == "at-capacity", f"the at-capacity panel rendered (data-state={state})")
                    check(
                        "not clear it" in text.lower(),
                        "it says waiting will not help, unlike a rate limit",
                    )
                    check("try again" not in text.lower(), "a full allocation must not advise retrying")
                finally:
                    context.close()

            hr("C. a host serving one key on the card and signing with another")
            proxy_srv = serve(make_divergent_proxy(host_origin, IMPOSTOR_DID), proxy_port)
            check(wait_for(f"{proxy_origin}/health"), "the divergent-key host is up")
            run_case("C", case_c)

            def case_e() -> None:
                """⚠️ THE HALF A STATUS-CODE ASSERTION CANNOT REACH.

                `smb_signup` mounts no CORS middleware, on purpose: it SERVES the
                funnel, so a public visitor is same-origin by construction, and
                provisioning through it carries no caller credential — granting
                any origin access would let any page on the internet spend a
                visitor's rate-limit allowance and the operator's tenant cap from
                that visitor's browser, and record that visitor's address as
                having provisioned an agent.

                What was NOT decided was what a page in the unsupported shape is
                told. Measured before this case existed: the request never left
                the browser, `err.status` was `undefined`, and the page rendered
                its catch-all "Couldn't create your agent. Please try again." —
                a claim that a service answered, and advice that cannot work.
                Every status the front door can send was equally invisible.

                This is the assertion node cannot make. Node's `fetch` performs
                no preflight and enforces no cross-origin rule, so a suite
                driving the same pair with it is driving a service whose CORS is
                effectively off and would pass either way.
                """
                context, page = open_funnel(signup_origin, page_origin=funnel_origin)
                try:
                    check(
                        funnel_origin != signup_origin,
                        "the page and the front door are on DIFFERENT origins, which is the whole case",
                    )
                    three_clicks(page, "Cross Origin Signup Co", "Haircuts")
                    page.wait_for_selector("#form-error:not([hidden])", timeout=30000)
                    state = page.get_attribute("#form-error", "data-state")
                    text = (page.text_content("#form-error") or "").strip()

                    check(
                        state == "not-delivered-config",
                        f"the undelivered-request panel rendered (data-state={state})",
                    )
                    # The defect, named: a status the page never received must not
                    # be answered with the catch-all that implies one arrived.
                    check(state != "failed", "a request that never left the browser did not render as a server failure")
                    check(
                        "please try again." not in text.lower(),
                        "it does not advise retrying an origin that will never be allowed",
                    )
                    check(
                        "cross-origin" in text.lower(),
                        "it names the configuration the page can actually check",
                    )
                    # It must not claim a verdict about the visitor, the details
                    # entered, or the service's capacity — none were established.
                    for word in ("capacity", "credential", "already taken"):
                        check(word not in text.lower(), f"it claims nothing about {word}")
                    check(
                        bool(blocked),
                        "the browser really did stop a request (otherwise this case proves nothing)",
                    )
                finally:
                    context.close()

            hr("D. the public front door — no credential in the browser at all")
            # ⚠️ THE CAP IS SIZED FROM WHAT THE HOST ALREADY HOLDS, not from a
            # constant. Cases A and C each provisioned a tenant, and the cap counts
            # the host's total — so a fixed cap of 1 would put the front door at
            # capacity before the first public signup, and case D would fail for a
            # reason that says nothing about the front door. Room for exactly one
            # more: D fills it, D-full meets it.
            existing = 0
            try:
                with urllib.request.urlopen(f"{host_origin}/health", timeout=5) as resp:
                    existing = int(json.loads(resp.read()).get("tenants", 0))
            except Exception:
                pass
            signup = start_signup(host_origin, signup_port, cap=existing + 1)
            ok(f"front door cap set to {existing + 1} — room for exactly one signup")
            if check(wait_for(f"{signup_origin}/health"), "smb_signup is up"):
                run_case("D", case_d)
                # The cap is 1, so the next signup meets it. Reached, not simulated.
                run_case("D-full", case_d_full)

                hr("E. a cross-origin page pointed at the front door — the shape it does not serve")
                run_case("E", case_e)

            browser.close()
    finally:
        if signup_proc:
            signup_proc.terminate()
            try:
                signup_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                signup_proc.kill()
        if proxy_srv:
            proxy_srv.shutdown()
        funnel_srv.shutdown()
        host.terminate()
        try:
            host.wait(timeout=10)
        except subprocess.TimeoutExpired:
            host.kill()

    hr("RESULT")
    if failures:
        print(f"   \033[31m{len(failures)} FAILED\033[0m")
        for entry in failures:
            print(f"     · {entry}")
        if console:
            print("   last console lines:")
            for line in console[-5:]:
                print(f"     {line}")
        return 1
    print("   \033[32mthe three clicks work in a real browser, against the real host\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
