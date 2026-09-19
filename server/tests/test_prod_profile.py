"""R7 + safe-by-default: deployment profile — CORS + API docs.

prod (DEFAULT): explicit CORS allowlist only (no wildcard default) and the
/docs + /redoc + /openapi.json surfaces are not served at all — the safe-for-public
posture the stock install yields.
dev (opt-in): CORS `*`, /docs + /openapi.json served (local ergonomics).

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import os
import subprocess
import sys

os.environ.setdefault("AGENT_ID", "test-profile-chapter")
os.environ.setdefault("AGENT_NAME", "Test Profile Chapter")

from fastapi.testclient import TestClient

import chapter_agent

SERVER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── resolve_cors_origins ────────────────────────────────────


def test_dev_default_is_wildcard():
    """HAPPY: dev with no config keeps the open-by-default local ergonomics."""
    assert chapter_agent.resolve_cors_origins("dev", None) == ["*"]
    assert chapter_agent.resolve_cors_origins("dev", "") == ["*"]


def test_prod_default_is_no_cross_origin(capsys):
    """HAPPY (R7): prod with no config allows NO cross-origin browser access."""
    assert chapter_agent.resolve_cors_origins("prod", None) == []
    assert "cross-origin browser access" in capsys.readouterr().out


def test_explicit_allowlist_parsed_and_stripped():
    """HAPPY: comma-separated origins are split, trimmed, and empties dropped."""
    raw = " https://portal.example.org , https://ops.example.org ,"
    expected = ["https://portal.example.org", "https://ops.example.org"]
    assert chapter_agent.resolve_cors_origins("prod", raw) == expected
    assert chapter_agent.resolve_cors_origins("dev", raw) == expected


def test_prod_wildcard_respected_but_warned(capsys):
    """EDGE (R7): an operator may still configure `*` in prod — it works, but
    the risk is logged loudly instead of silently accepted."""
    assert chapter_agent.resolve_cors_origins("prod", "*") == ["*"]
    out = capsys.readouterr().out
    assert "[config][WARN]" in out
    assert "ALLOWED_ORIGINS=*" in out


def test_dev_wildcard_does_not_warn(capsys):
    """EDGE: the wildcard is the intended dev default — no warning noise."""
    assert chapter_agent.resolve_cors_origins("dev", "*") == ["*"]
    assert "[config][WARN]" not in capsys.readouterr().out


# ── docs_urls ───────────────────────────────────────────────


def test_docs_urls_prod_disables_all_surfaces():
    """HAPPY (R7): prod serves none of /docs, /redoc, /openapi.json."""
    assert chapter_agent.docs_urls("prod") == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_docs_urls_dev_keeps_fastapi_defaults():
    """HAPPY: dev passes no overrides — FastAPI's default docs stay on."""
    assert chapter_agent.docs_urls("dev") == {}


# ── runtime: the wired app, per profile ─────────────────────


def test_default_import_is_prod_hardened():
    """the DEFAULT profile (no ORRERY_PROFILE set — the stock install) is
    prod-hardened: the imported app serves no /docs or /openapi.json and the CORS
    allowlist is empty. This is what `cp .env.example .env` yields."""
    assert chapter_agent.ORRERY_PROFILE == "prod"
    assert chapter_agent.app.docs_url is None
    assert chapter_agent.app.openapi_url is None
    assert chapter_agent.ALLOWED_ORIGINS == []
    client = TestClient(chapter_agent.app)
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404


def test_default_import_no_wildcard_cors_for_credentialed_origin():
    """a stock (default=prod) server does NOT hand ACAO:* to a foreign origin
    on a gated (credentialed) surface — the empty allowlist means no cross-origin
    echo. (The keyless public-read surfaces intentionally stay ACAO:* — see that change.)"""
    client = TestClient(chapter_agent.app)
    r = client.get("/api/surfaces/intents", headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") != "*", (
        "a gated surface must not be wildcard-CORS-readable under the default prod profile"
    )


def test_prod_profile_app_serves_neither(tmp_path):
    """ADVERSARIAL (R7): a fresh import under ORRERY_PROFILE=prod must not
    expose the route map — /docs and /openapi.json are 404, CORS allowlist is
    empty. Run in a subprocess because the profile is resolved at import."""
    code = "\n".join(
        [
            "import os",
            "os.environ['ORRERY_PROFILE'] = 'prod'",
            "os.environ.pop('ALLOWED_ORIGINS', None)",
            "os.environ.setdefault('AGENT_ID', 'prod-profile-test')",
            "os.environ.setdefault('AGENT_NAME', 'Prod Profile Test')",
            "import chapter_agent",
            "assert chapter_agent.app.docs_url is None",
            "assert chapter_agent.app.redoc_url is None",
            "assert chapter_agent.app.openapi_url is None",
            "assert chapter_agent.ALLOWED_ORIGINS == []",
            "from fastapi.testclient import TestClient",
            "client = TestClient(chapter_agent.app)",
            "assert client.get('/docs').status_code == 404",
            "assert client.get('/openapi.json').status_code == 404",
            "assert client.get('/redoc').status_code == 404",
            "print('PROD-PROFILE-OK')",
        ]
    )
    env = {**os.environ, "PYTHONPATH": f"{SERVER_ROOT}{os.pathsep}{os.path.dirname(SERVER_ROOT)}"}
    env["COMMUNITY_MEMBER_HOME"] = str(tmp_path)  # keep any key writes out of the repo
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=SERVER_ROOT,
        env=env,
        timeout=180,
    )
    assert "PROD-PROFILE-OK" in proc.stdout, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"


def test_dev_profile_opt_in_serves_docs(tmp_path):
    """an operator can still opt into dev — ORRERY_PROFILE=dev serves the
    interactive docs + wildcard CORS. Subprocess because the profile is import-time."""
    code = "\n".join(
        [
            "import os",
            "os.environ['ORRERY_PROFILE'] = 'dev'",
            "os.environ.pop('ALLOWED_ORIGINS', None)",
            "os.environ.setdefault('AGENT_ID', 'dev-profile-test')",
            "os.environ.setdefault('AGENT_NAME', 'Dev Profile Test')",
            "import chapter_agent",
            "assert chapter_agent.app.docs_url == '/docs'",
            "assert chapter_agent.app.openapi_url == '/openapi.json'",
            "assert chapter_agent.ALLOWED_ORIGINS == ['*']",
            "from fastapi.testclient import TestClient",
            "client = TestClient(chapter_agent.app)",
            "assert client.get('/openapi.json').status_code == 200",
            "print('DEV-PROFILE-OK')",
        ]
    )
    env = {**os.environ, "PYTHONPATH": f"{SERVER_ROOT}{os.pathsep}{os.path.dirname(SERVER_ROOT)}"}
    env["COMMUNITY_MEMBER_HOME"] = str(tmp_path)
    env.pop("ORRERY_PROFILE", None)  # let the subprocess set it
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=SERVER_ROOT, env=env, timeout=180
    )
    assert "DEV-PROFILE-OK" in proc.stdout, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
