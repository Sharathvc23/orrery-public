"""Fixtures for the live-process end-to-end drives.

These tests boot REAL processes — the org server (``server/chapter_agent.py``
in its in-memory, no-Postgres mode) and sovereign members (``agent/serve.py``)
— and drive the advertised agent capabilities over the wire with real Ed25519
signing. Nothing here is mocked except the LLM, which is replaced by a
deterministic OpenAI-compatible stub so the planner→consent-gate path runs
for real without a model in the loop.

Gating: every module in this package carries

    pytestmark = [pytest.mark.e2e, pytest.mark.skipif(...ORRERY_E2E...)]

so the suite is invisible to CI's unit run. To run:

    ORRERY_E2E=1 ORRERY_SERVER_PYTHON=/path/to/server-venv/python \
        python -m pytest tests/e2e -q -rA

``ORRERY_SERVER_PYTHON`` must point at a python that satisfies
``server/requirements.lock`` (the agent venv does not). server/ is
READ+RUN only from this suite — it is another role's surface.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[3]
SERVER_DIR = REPO / "server"
AGENT_DIR = REPO / "agent"

E2E_ENABLED = os.environ.get("ORRERY_E2E") == "1"

# Members are spawned with this as their local API token, so the Member
# helpers below can reach the routes that require it.
E2E_LOCAL_TOKEN = "e2e-local-token"

# serve.py requires >= 10 chars.
PASSPHRASE = "e2e-pass-0123456789"

# The agent's LLM base URL is provider-keyed and fixed: provider
# ``llama_cpp`` → http://localhost:8080/v1 (community_member/agent.py).
# The stub binds there; if the port is taken the session errors out
# with a clear message rather than silently talking to a real model.
LLM_STUB_PORT = 8080
LLM_STUB_PROVIDER = "llama_cpp"

# Marker applied by every module in this package (import from here so the
# gate condition can't drift between files).
e2e_gate = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not E2E_ENABLED,
        reason="e2e drives: set ORRERY_E2E=1 (+ ORRERY_SERVER_PYTHON=<server-venv python>)",
    ),
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_healthy(base: str, path: str, proc: subprocess.Popen, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"process exited rc={proc.returncode}:\n{out[-3000:]}")
        try:
            if httpx.get(base + path, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.4)
    raise TimeoutError(f"never healthy: {base}{path}")


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ---------------------------------------------------------------- org server


@pytest.fixture(scope="session")
def org_server(tmp_path_factory):
    """The REAL chapter_agent.py, in-memory mode (no DATABASE_URL).

    Runs with its CWD in a tmp dir (invoking the script by absolute path) so
    the server's runtime artifacts — ``.org-admin-token``, ``.nanda/``,
    ``.org/`` — never litter the read-only ``server/`` tree.
    """
    py = os.environ.get("ORRERY_SERVER_PYTHON")
    if not py:
        pytest.skip("ORRERY_SERVER_PYTHON not set (python satisfying server/requirements.lock)")
    port = free_port()
    run_dir = tmp_path_factory.mktemp("org-server-cwd")
    env = {**os.environ}
    env.pop("DATABASE_URL", None)  # force in-memory mode
    env.update(
        AGENT_ID="local-e2e-chapter",
        AGENT_NAME="E2E Local Chapter",
        PORT=str(port),
        XAI_API_KEY="stub",
        PYTHONPATH=str(SERVER_DIR) + os.pathsep + os.environ.get("PYTHONPATH", ""),
        # ORG_HOME pins where the server writes .org-admin-token / .nanda / .org
        # (else server/admin.py falls back to the module dir and litters the
        # read-only server/ tree — see server/admin.py:_token_dir).
        ORG_HOME=str(run_dir),
    )
    proc = subprocess.Popen(
        [py, str(SERVER_DIR / "chapter_agent.py")],
        cwd=run_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        wait_healthy(base, "/health", proc)
        yield base
    finally:
        _terminate(proc)


# ------------------------------------------------------------------ LLM stub


def _extract_balanced_json(text: str) -> str | None:
    """Return the balanced {...} JSON object following ``PLAN::``, if any."""
    idx = text.find("PLAN::")
    if idx < 0:
        return None
    start = text.find("{", idx)
    if start < 0:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


class _PlanEcho(BaseHTTPRequestHandler):
    """OpenAI-compatible /v1/chat/completions that echoes a controlled plan.

    Two control channels, both deterministic:

    1. ``PLAN::{json}`` embedded in the user message (the
       ``/api/local/intent/dispatch`` path — the typed intent flows into
       the planner prompt verbatim, so the test controls the plan).
    2. A queued plan set via ``POST /_control/plan`` (the autonomous
       think-loop path, whose prompt the test cannot influence). The next
       completion request consumes it; subsequent ones fall back to a
       free-text reply, which the planner treats as an empty plan.

    Either way the member process runs its REAL planner parsing, gate
    validation, and executor wiring on a plan of the test's choosing.
    """

    queued_plans: list[str] = []  # class-level; guarded by _lock
    _lock = threading.Lock()

    def do_POST(self):  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) or b"{}"

        if self.path == "/_control/plan":
            with _PlanEcho._lock:
                _PlanEcho.queued_plans.append(raw.decode())
            self.send_response(204)
            self.end_headers()
            return

        body = json.loads(raw)
        user_text = " ".join(str(m.get("content", "")) for m in body.get("messages", []) if m.get("role") == "user")
        arguments = _extract_balanced_json(user_text)
        if arguments is None:
            with _PlanEcho._lock:
                if _PlanEcho.queued_plans:
                    arguments = _PlanEcho.queued_plans.pop(0)
        if arguments is not None:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_e2e",
                        "type": "function",
                        "function": {"name": "propose_actions", "arguments": arguments},
                    }
                ],
            }
        else:
            # Free-text reply → planner treats as empty plan; also serves
            # the chat/skill paths that just want text back.
            message = {"role": "assistant", "content": "ok"}
        resp = {
            "id": "cmpl-e2e",
            "object": "chat.completion",
            "model": body.get("model", "stub"),
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        }
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence
        pass


class _ReuseHTTPServer(ThreadingHTTPServer):
    # SO_REUSEADDR so a TIME_WAIT socket from a prior test session (the
    # llama_cpp provider URL is a FIXED port, so we can't pick a free one)
    # doesn't lose the bind and force a skip.
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture(scope="session")
def llm_stub():
    """Deterministic planner LLM on the fixed llama_cpp port (8080)."""
    server = None
    for attempt in range(10):
        try:
            server = _ReuseHTTPServer(("127.0.0.1", LLM_STUB_PORT), _PlanEcho)
            break
        except OSError:
            time.sleep(0.5)  # a prior session's socket is still releasing
    if server is None:
        pytest.skip(
            f"port {LLM_STUB_PORT} stayed busy after retries — the llama_cpp "
            "provider URL is fixed; free the port to run these drives"
        )
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{LLM_STUB_PORT}/v1"
    server.shutdown()


def plan_intent(proposals: list[dict], summary: str = "e2e plan") -> str:
    """Intent text that makes the stub propose exactly ``proposals``."""
    return "run e2e actions PLAN::" + json.dumps({"summary": summary, "proposals": proposals})


def queue_think_plan(proposals: list[dict], summary: str = "e2e think plan") -> None:
    """Queue a plan for the member's next autonomous think cycle."""
    httpx.post(
        f"http://127.0.0.1:{LLM_STUB_PORT}/_control/plan",
        content=json.dumps({"summary": summary, "proposals": proposals}),
        timeout=5,
    )


def clear_queued_plans() -> None:
    with _PlanEcho._lock:
        _PlanEcho.queued_plans.clear()


# -------------------------------------------------------------------- members


@dataclass
class Member:
    base: str
    home: Path
    port: int
    agent_id: str
    proc: subprocess.Popen
    env: dict = field(repr=False, default_factory=dict)

    def _headers(self, kw: dict) -> dict:
        """Attach the local API token the member was spawned with."""
        headers = dict(kw.pop("headers", None) or {})
        headers.setdefault("Authorization", f"Bearer {E2E_LOCAL_TOKEN}")
        return headers

    def get(self, path: str, **kw) -> httpx.Response:
        return httpx.get(self.base + path, timeout=10, headers=self._headers(kw), **kw)

    def post(self, path: str, **kw) -> httpx.Response:
        return httpx.post(self.base + path, timeout=30, headers=self._headers(kw), **kw)

    def did(self) -> str:
        return self.get("/agentfacts.json").json()["id"]

    def stop(self) -> None:
        _terminate(self.proc)


@pytest.fixture()
def member_factory(org_server, tmp_path):
    """Spawn serve.py members. Respawning with the same ``home`` is the
    restart-persistence drive."""
    live: list[Member] = []

    def spawn(
        agent_id: str,
        home: Path | None = None,
        with_llm_stub: bool = False,
        **env_extra: str,
    ) -> Member:
        home = home or (tmp_path / agent_id)
        home.mkdir(parents=True, exist_ok=True)
        port = free_port()
        env = {**os.environ}
        env.pop("DATABASE_URL", None)
        env.update(
            AGENT_ID=agent_id,
            AGENT_NAME=f"E2E {agent_id}",
            PORT=str(port),
            CHAPTER_URL=org_server,
            COMMUNITY_MEMBER_HOME=str(home),
            COMMUNITY_MEMBER_KEYSTORE="passphrase",
            COMMUNITY_MEMBER_PASSPHRASE=PASSPHRASE,
            COMMUNITY_MEMBER_NO_REGISTRY="1",
            COMMUNITY_MEMBER_LOCAL_TOKEN=E2E_LOCAL_TOKEN,
        )
        if with_llm_stub:
            env.update(AGENT_PROVIDER=LLM_STUB_PROVIDER, AGENT_MODEL="e2e-stub")
        env.update(env_extra)
        proc = subprocess.Popen(
            [sys.executable, "serve.py"],
            cwd=AGENT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base = f"http://127.0.0.1:{port}"
        member = Member(base=base, home=home, port=port, agent_id=agent_id, proc=proc, env=env)
        try:
            wait_healthy(base, "/api/health", proc)
        except Exception:
            _terminate(proc)
            raise
        live.append(member)
        return member

    yield spawn
    for m in live:
        m.stop()
