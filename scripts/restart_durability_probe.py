#!/usr/bin/env python3
"""Assert that a member's record actually survives a RESTART — over the wire,
against a real server and a real Postgres, with a real process replacement.

WHY THIS EXISTS AND WHY THE PYTEST SUITE IS NOT ENOUGH
------------------------------------------------------
`members[]` is rebuilt from Postgres on every boot. Three fields the loader did
not carry — `endpoint`, `public_key`, `origin` — were therefore empty for every
member on every boot, and five readers degraded SILENTLY rather than failing:

  * the key-change guard became a no-op, so an UNAUTHENTICATED POST to the
    open `/api/members` replaced a victim's auth key. Full account takeover;
    the legitimate key then got `key_mismatch`.
  * the origin-immutability guard became a no-op, so the sovereign/openclaw
    trust origin was re-writable by the same open POST.
  * `cosign_broker.resolve_member_endpoint` returned None, so every brokered
    co-sign degraded to a valid-but-UNCORROBORATED receipt — indistinguishable
    from "the counterparty declined".
  * the `@handle` A2A forward fell through to the virtual sub-agent, so a
    message addressed to a real member agent was answered by the ORG's LLM
    impersonating it.
  * the AI catalog omitted the member (visible — The resolvable-card rule counts it — but wrong).

`server/tests/` had 25 passing tests over this path throughout. It could not
have caught any of it: a test whose setup and its assertion live in ONE process
cannot detect a property that only fails across TWO.

THE TWO GUARDS THAT MAKE THIS PROBE HONEST
------------------------------------------
A restart probe has two ways to report a false pass, and they produce output
identical to a real one:

  1. **The row was never written.** Then there is nothing to lose, and every
     "it survived" assertion passes vacuously. Guarded by reading the endpoint
     back out of Postgres directly, BEFORE the restart, and failing if it is
     absent.
  2. **The restart never happened.** Then the original process is still holding
     the in-memory map and everything "survives". Guarded by a CANARY member:
     registered, then DELETED from Postgres while the server is up, so it lives
     ONLY in memory. If the canary is still resolvable after the restart, the
     process was never replaced and this probe refuses to report anything.

Both guards fired for real during development — a DSN missing `sslmode=disable`
meant nothing was persisted at all, and a kill aimed at a wrapper pid left the
original process running. The surface looked healthy in both cases.

USAGE
-----
Against a docker-compose stack:

    scripts/restart_durability_probe.py \\
        --server http://localhost:7000 \\
        --restart-cmd 'docker compose restart server' \\
        --sql-cmd 'docker compose exec -T db psql -U postgres -d orrery -tAq'

`--sql-cmd` must read SQL on stdin and print bare rows (`psql -tAq`).
Exit 0 = every assertion held. Any other exit = a real failure; the output
names which reader regressed.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skill" / "helpers"))
import sign_request as sr  # noqa: E402  — skill/helpers, the shipped signer

# A routable-looking host that does not resolve. Deliberate: the A2A forward
# must be observed TAKING the forward branch, and an unreachable endpoint makes
# that branch return a distinctive "Could not reach @…" instead of an LLM
# answer. A loopback endpoint would be refused by the cosign SSRF guard and a
# reachable one would need a second service.
ENDPOINT = "https://restart-durability-probe.invalid"

PASS, FAIL = "\033[32m✓\033[0m", "\033[31m✗\033[0m"
_failures: list[str] = []


def say(msg: str) -> None:
    print(f"[restart-probe] {msg}", flush=True)


def check(ok: bool, what: str, detail: str = "") -> bool:
    print(
        f"[restart-probe] {PASS if ok else FAIL} {what}"
        + (f" — {detail}" if detail else ""),
        flush=True,
    )
    if not ok:
        _failures.append(what)
    return ok


def die(msg: str) -> None:
    print(f"[restart-probe] {FAIL} ABORT: {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


class Identity:
    """A fresh Ed25519 identity that signs exactly like the shipped skill."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.priv = Ed25519PrivateKey.generate()
        raw = self.priv.public_key().public_bytes_raw()
        self.public_key_b64 = base64.b64encode(raw).decode()
        self.did = sr._build_did_key(raw)

    def headers(
        self, method: str, path: str, body: str = "", agent_id: str | None = None
    ) -> dict[str, str]:
        """Sign as ``agent_id`` (default: our own). Signing as SOMEONE ELSE is
        how the takeover consequence is proven — the attacker's private key
        claiming the victim's id."""
        aid = agent_id or self.agent_id
        ts, nonce = str(int(time.time())), uuid.uuid4().hex
        canonical = sr.canonical_string_v03(method, path, body, aid, ts, nonce)
        return {
            "X-Agent-ID": aid,
            "X-Agent-Signature": sr.ed25519_sign(self.priv, canonical),
            "X-Agent-Timestamp": ts,
            "X-Agent-Nonce": nonce,
            "X-Agent-Sig-Scheme": "ed25519+nonce",
            "X-Agent-DID-Key": self.did,
            "content-type": "application/json",
        }


def sql(cmd: str, statement: str) -> str:
    out = subprocess.run(
        cmd, shell=True, input=statement, capture_output=True, text=True
    )
    if out.returncode != 0:
        die(f"--sql-cmd failed ({out.returncode}): {out.stderr.strip()[:400]}")
    return out.stdout.strip()


def wait_healthy(server: str, timeout_s: int = 180) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if httpx.get(f"{server}/health", timeout=3).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    die(f"{server}/health never became healthy within {timeout_s}s")


def register(
    server: str, ident: Identity, headers: dict[str, str] | None = None, **over
) -> httpx.Response:
    body = {
        "agent_id": ident.agent_id,
        "name": over.pop("name", "Restart Durability Probe"),
        "origin": over.pop("origin", "sovereign"),
        "skills": ["probing"],
        "endpoint": over.pop("endpoint", ENDPOINT),
        "public_key": over.pop("public_key", ident.public_key_b64),
    }
    body.update(over)
    # /api/members is open-pathed — it does its own TOFU, so no signature here.
    return httpx.post(
        f"{server}/api/members", json=body, headers=headers or {}, timeout=30
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--server", required=True, help="base URL of the running org")
    ap.add_argument(
        "--restart-cmd",
        required=True,
        help="shell command that restarts the server process",
    )
    ap.add_argument(
        "--sql-cmd",
        required=True,
        help="shell command reading SQL on stdin, printing bare rows",
    )
    args = ap.parse_args()
    server = args.server.rstrip("/")

    suffix = uuid.uuid4().hex[:8]
    probe = Identity(f"restart-probe-{suffix}")
    canary = Identity(f"restart-canary-{suffix}")
    attacker = Identity(
        f"restart-attacker-{suffix}"
    )  # never registered — only its key is offered

    wait_healthy(server)

    # ── 1. register the probe and the canary ────────────────────────────────
    r = register(server, probe)
    if r.status_code != 200:
        die(f"probe registration failed: {r.status_code} {r.text[:300]}")
    r = register(server, canary, name="Restart Canary")
    if r.status_code != 200:
        die(f"canary registration failed: {r.status_code} {r.text[:300]}")
    say(f"registered {probe.agent_id} (endpoint {ENDPOINT}) and {canary.agent_id}")

    # ── 2. GUARD ONE: the row was actually written, WITH the endpoint ───────
    # The persist is fire-and-forget, so poll rather than assume.
    stored = ""
    for _ in range(30):
        stored = sql(
            args.sql_cmd,
            f"select config->>'endpoint' from public.agents where agent_id='{probe.agent_id}';",
        )
        if stored:
            break
        time.sleep(2)
    if stored != ENDPOINT:
        die(
            f"the probe's endpoint was never persisted (config->>'endpoint' = {stored!r}). "
            "Nothing could be lost by a restart, so every assertion after this would pass "
            "vacuously. This is the failure mode this guard exists for."
        )
    check(True, "GUARD 1: endpoint reached Postgres before the restart", stored)

    # ── 3. arm the canary: delete its row so it lives ONLY in memory ────────
    for _ in range(30):
        if sql(
            args.sql_cmd,
            f"select 1 from public.agents where agent_id='{canary.agent_id}';",
        ):
            break
        time.sleep(2)
    sql(args.sql_cmd, f"delete from public.agents where agent_id='{canary.agent_id}';")
    still = sql(
        args.sql_cmd, f"select 1 from public.agents where agent_id='{canary.agent_id}';"
    )
    if still:
        die("canary row could not be deleted — the restart guard cannot be armed")
    # The canary is observed through its PROFILE, which is consent-gated: it
    # serves a member who opted in and 404s for one who has not. So the canary
    # opts itself in — a signed call it can make because it holds its own key.
    # Without this the pre-restart check would 404 and the probe would abort on
    # a perfectly healthy server; with it, the guard below means what it says,
    # because a 404 after the restart can then only be absence, not silence.
    lp = "/api/me/listing"
    lbody = json.dumps({"listed": True})
    consent = httpx.post(
        f"{server}{lp}",
        content=lbody,
        headers={
            **canary.headers("POST", lp, lbody),
            "content-type": "application/json",
        },
        timeout=20,
    )
    if consent.status_code != 200:
        die(
            f"canary could not opt into publication ({consent.status_code} "
            f"{consent.text[:200]}) — its profile is consent-gated, so without this "
            f"the restart guard cannot be armed"
        )
    pre = httpx.get(f"{server}/api/agents/{canary.agent_id}/profile", timeout=20)
    if pre.status_code != 200:
        die(
            f"canary is not resolvable BEFORE the restart ({pre.status_code}) — it cannot prove anything after"
        )
    say("canary armed: in memory, absent from Postgres, opted into publication")

    # ── 4. the restart ──────────────────────────────────────────────────────
    say(f"restarting: {args.restart_cmd}")
    out = subprocess.run(args.restart_cmd, shell=True, capture_output=True, text=True)
    if out.returncode != 0:
        die(f"--restart-cmd failed ({out.returncode}): {out.stderr.strip()[:400]}")
    wait_healthy(server)

    # ── 5. GUARD TWO: the restart actually happened ─────────────────────────
    post = httpx.get(f"{server}/api/agents/{canary.agent_id}/profile", timeout=20)
    if post.status_code == 200:
        die(
            "the CANARY SURVIVED. It exists only in memory, so the process was never replaced — "
            "'--restart-cmd' did not restart anything, and everything below would have reported "
            "state surviving a restart that did not occur."
        )
    check(
        post.status_code == 404,
        "GUARD 2: canary gone → the process really was replaced",
        f"HTTP {post.status_code}",
    )

    # ── 6. the readers, over the wire, on the restarted process ─────────────
    # The probe member is read through a surface that does not require its
    # consent: its profile is gated like the canary's, and this check is about
    # REHYDRATION, not publication. A signed self-read is the honest equivalent
    # — it proves the org came back holding this member and its key.
    mp = "/api/members"
    prof = httpx.get(f"{server}{mp}", headers=probe.headers("GET", mp), timeout=20)
    if prof.status_code != 200:
        die(
            f"the probe member did not come back at all ({prof.status_code}) — nothing below would be meaningful"
        )
    check(True, "the probe member was rehydrated from Postgres")

    # 6a. AI catalog: endpoint-derived card URL, and the member is not omitted.
    path = "/.well-known/ai-catalog.json"
    cat = httpx.get(f"{server}{path}", headers=probe.headers("GET", path), timeout=20)
    entries = cat.json().get("entries", []) if cat.status_code == 200 else []
    mine = [e for e in entries if e.get("identifier") == probe.agent_id]
    check(
        bool(mine) and mine[0].get("url") == f"{ENDPOINT}/.well-known/agent.json",
        "AI catalog serves the member's endpoint-derived card URL",
        f"omittedMembers={cat.json().get('omittedMembers') if cat.status_code == 200 else 'n/a'}",
    )

    # 6b. The key-change guard key-change guard — the account-takeover vector.
    r = register(server, probe, public_key=attacker.public_key_b64)
    check(
        r.status_code == 403
        and r.json().get("error") == "key_change_requires_rotation",
        "key-change guard refuses an unauthenticated key swap",
        f"HTTP {r.status_code}",
    )
    if r.status_code == 200:
        # Prove the CONSEQUENCE, not just the status code: sign as the victim
        # with the ATTACKER's private key and see whether the org accepts it.
        p = "/api/members"
        atk = httpx.get(
            f"{server}{p}",
            headers=attacker.headers("GET", p, agent_id=probe.agent_id),
            timeout=20,
        )
        check(
            False,
            "ACCOUNT TAKEOVER: the swapped key now authenticates as the victim",
            f"HTTP {atk.status_code}",
        )
        own = httpx.get(f"{server}{p}", headers=probe.headers("GET", p), timeout=20)
        check(
            False,
            "…and the legitimate owner is locked out",
            f"HTTP {own.status_code} {own.text[:120]}",
        )
        die(
            "the member's identity has been replaced — every assertion after this would be "
            "measuring the attacker's member, not the victim's. Stopping here."
        )

    # 6c. origin-immutability guard. A flip TO openclaw is gated first by the
    #     skill-version check (auth_verify.check_openclaw_version), which would
    #     mask the origin guard entirely. Read the required minimum out of that
    #     refusal and retry with it, rather than pinning a version here that
    #     rots the moment the advisory floor moves.
    r = register(server, probe, origin="openclaw")
    body = (
        r.json()
        if r.headers.get("content-type", "").startswith("application/json")
        else {}
    )
    if body.get("error") == "openclaw_skill_outdated":
        r = register(
            server,
            probe,
            origin="openclaw",
            headers={"X-Openclaw-Skill-Version": body.get("minimum_version", "")},
        )
        body = (
            r.json()
            if r.headers.get("content-type", "").startswith("application/json")
            else {}
        )
    check(
        str(body.get("error", "")).startswith("origin mismatch"),
        "origin-immutability guard refuses a trust-origin flip",
        json.dumps(body)[:160],
    )

    # 6d. the @handle A2A forward takes the FORWARD branch, not the LLM
    #     impersonation fallback. The endpoint is unresolvable on purpose, so
    #     "Could not reach @…" is the branch's own signature; any other reply
    #     means the org's LLM answered AS the member.
    #
    #     /a2a is signature-gated, and the signature covers the exact request
    #     body — so send our own serialized bytes rather than letting httpx
    #     re-encode them, or the canonical string will not match what arrives.
    a2a_body = json.dumps(
        {
            "role": "user",
            "content": {"type": "text", "text": f"@{probe.agent_id} ping"},
            "conversation_id": f"restart-probe-{suffix}",
        }
    )
    a2a = httpx.post(
        f"{server}/a2a",
        content=a2a_body,
        headers=probe.headers("POST", "/a2a", a2a_body),
        timeout=60,
    )
    if a2a.status_code == 401:
        die(
            f"/a2a rejected the probe's signature ({a2a.text[:200]}) — the A2A reader cannot be measured"
        )
    reply = (
        (a2a.json().get("content", {}) or {}).get("text", "")
        if a2a.status_code == 200
        else ""
    )
    check(
        reply.startswith(f"Could not reach @{probe.agent_id}"),
        "@handle A2A takes the forward branch (no LLM impersonation of the member)",
        reply[:120] or f"HTTP {a2a.status_code}",
    )

    # 6e. no false lockout: the LEGITIMATE key still re-registers.
    r = register(server, probe, name="Restart Durability Probe II")
    check(
        r.status_code == 200,
        "the real owner can still re-register with their own key",
        f"HTTP {r.status_code}",
    )

    # ── 7. cleanup ──────────────────────────────────────────────────────────
    for aid in (probe.agent_id, canary.agent_id):
        sql(args.sql_cmd, f"delete from public.agents where agent_id='{aid}';")

    if _failures:
        print(
            f"\n[restart-probe] {FAIL} {len(_failures)} assertion(s) failed:",
            file=sys.stderr,
        )
        for f in _failures:
            print(f"    - {f}", file=sys.stderr)
        return 1
    say("all assertions held across a verified real restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
