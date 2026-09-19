/**
 * Boot a REAL `smb_host` (and a real `smb_signup`) for the funnel to talk to.
 *
 * ⚠️ WHY A REAL SERVER AND NOT THE HAND-WRITTEN ONE NEXT DOOR.
 * `tests/provision-token.test.mjs` drives the app against a node `createServer`
 * whose refusal bodies are hand-copied approximations of the host's wording. It
 * proved the app's own wiring, and it could not prove the thing this suite is
 * for: that a state the DEPLOYED host is actually in renders as something true.
 * Its 503 body, for instance, is the `SMB_HOST_PROVISION_TOKEN`-not-set variant —
 * while the deployed host's 503 is the `SMB_HOST_TENANT_CAP` one, a different
 * sentence that no test had ever rendered. A fake whose bodies are written from
 * the same reading of the source that produced the renderer cannot catch a
 * misreading in either.
 *
 * ⚠️ ONE PORT, REUSED, ONE HOST AT A TIME. `src/api.js` resolves its base URL
 * ONCE at module load and the module is shared across every re-import of
 * `app.js`, so a suite that booted six hosts on six ports could not point the app
 * at more than the first. Each state therefore starts a real host on the SAME
 * port, runs its case, and is stopped before the next starts. That keeps one
 * fixed base URL without a proxy standing between the page and the host — a
 * forwarding hop is exactly the kind of thing that would mask a header the real
 * host would have refused.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO = resolve(new URL("../..", import.meta.url).pathname);
// ⚠️ A PORT PER SUITE, NOT PER CASE. `node --test` runs test FILES in parallel
// processes, so two suites sharing a port bind over each other and each sees the
// other's host — which reads as a wrong refusal state rather than as a clash.
// Cases WITHIN a file are sequential, so one port per file is enough, and that
// is what lets each case boot a real host on a fixed address without a proxy.
export const HOST_PORT = 8791;
export const SIGNUP_PORT = 8792;
export const UPSTREAM_PORT = 8793;
export const CORS_HOST_PORT = 8794;

/** The interpreter that has `community_member` and `fastapi` importable. */
export function python() {
  return process.env.SMB_FUNNEL_PYTHON || "python3";
}

/** Whether a real host can be booted here at all — see `requireHost` below. */
export async function hostAvailable() {
  if (!existsSync(join(REPO, "smb_host", "main.py"))) return false;
  const probe = spawn(python(), ["-c", "import fastapi, uvicorn, community_member"], { stdio: "ignore" });
  return new Promise((r) => probe.on("exit", (code) => r(code === 0)));
}

/**
 * ⚠️ NEVER SKIP. A suite whose whole point is "this has never been driven
 * against the real thing" must not report green when the real thing was not
 * there. If the host cannot boot, that is a red — the alternative is a job that
 * passes on a runner missing python and tells nobody.
 */
export async function requireHost() {
  if (!(await hostAvailable())) {
    throw new Error(
      `cannot import fastapi/uvicorn/community_member with ${python()}. ` +
        `These tests drive a REAL smb_host and must not be skipped; install the host's ` +
        `dependencies or set SMB_FUNNEL_PYTHON to an interpreter that has them.`,
    );
  }
}

async function waitForHealth(port, proc, what) {
  const deadline = Date.now() + 40_000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`${what} exited with ${proc.exitCode} before answering /health`);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`${what} never answered /health on port ${port}`);
}

async function stop(proc) {
  if (!proc || proc.exitCode !== null) return;
  proc.kill("SIGKILL");
  await new Promise((r) => proc.on("exit", r));
}

/**
 * Start one service and return `{ base, stop }`.
 *
 * `env` is the WHOLE of the service's configuration for this case: passing a
 * partial environment and inheriting the rest would let a variable set for an
 * earlier state leak into a later one, which is the failure this suite exists to
 * find rather than to commit.
 */
async function boot({ dir, module_, port, env, what }) {
  const data = await mkdtemp(join(tmpdir(), "smb-funnel-states-"));
  const proc = spawn(python(), ["-m", "uvicorn", `${module_}:app`, "--host", "127.0.0.1", "--port", String(port), "--log-level", "warning"], {
    cwd: join(REPO, dir),
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      PYTHONPATH: join(REPO, "agent"),
      COMMUNITY_MEMBER_KEYSTORE: "device",
      SMB_HOST_DATA_DIR: data,
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const log = [];
  proc.stdout.on("data", (b) => log.push(String(b)));
  proc.stderr.on("data", (b) => log.push(String(b)));
  try {
    await waitForHealth(port, proc, what);
  } catch (e) {
    await stop(proc);
    await rm(data, { recursive: true, force: true });
    throw new Error(`${e.message}\n--- ${what} output ---\n${log.join("")}`);
  }
  return {
    base: `http://127.0.0.1:${port}`,
    log,
    async stop() {
      await stop(proc);
      await rm(data, { recursive: true, force: true });
    },
  };
}

/** A real `smb_host`, configured entirely by `env` — never by a code change. */
export function bootHost(env, port = HOST_PORT) {
  return boot({ dir: "smb_host", module_: "main", port, env, what: "smb_host" });
}

/** A real `smb_signup` — the front door that owns the per-source rate limit. */
export function bootSignup(env, port = SIGNUP_PORT) {
  return boot({ dir: "smb_signup", module_: "main", port, env, what: "smb_signup" });
}
