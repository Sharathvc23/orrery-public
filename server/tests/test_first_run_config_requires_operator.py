"""First-run org setup is the operator's to perform, not whoever reaches the port first.

``POST /api/org/config`` names the org and sets its join policy, once. It was
open until the org was configured, on the reasoning that nothing exists to sign
with before provisioning. That is true of a member signature and beside the
point: the admin token is minted and printed at first boot, before the port is
reachable, so it is exactly the credential a first-run POST can carry. On a
public deploy the window between the process listening and the operator's
first visit was one in which a stranger could name the org and open its join
policy.

The route now takes the boot-printed ``ORG_ADMIN_TOKEN`` bearer (or a signed
admin member). ``GET /api/org/config`` stays open: the join page reads it before
a visitor has any credential, and it discloses only ``{configured, profile}``.
The installer never calls the POST (the profile comes from the ``ORG_*``
variables), so an unattended first run is unchanged.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

TOKEN = "a" * 64


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_ID", "TEST-first-run-org")
    monkeypatch.setenv("AGENT_NAME", "First Run Org")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    monkeypatch.setenv("ORG_ADMIN_TOKEN", TOKEN)
    for mod in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(mod, None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "_ORG_CONFIG_PATH", tmp_path / "org-config.json")
    with TestClient(mod.app) as c:  # lifespan runs admin.init, which reads the token
        yield c


BODY = {"name": "Napa Wine Collective", "join_policy": "open"}


def test_a_stranger_cannot_perform_first_run_setup(client):
    resp = client.post("/api/org/config", json=BODY)
    assert resp.status_code == 401, resp.text
    assert client.get("/api/org/config").json()["configured"] is False, "the stranger's POST must not have landed"


def test_a_wrong_token_cannot_perform_first_run_setup(client):
    resp = client.post("/api/org/config", json=BODY, headers={"X-Admin-Token": "b" * 64})
    assert resp.status_code in (401, 403), resp.text
    assert client.get("/api/org/config").json()["configured"] is False


def test_the_operator_performs_first_run_setup_with_the_boot_token(client):
    resp = client.post("/api/org/config", json=BODY, headers={"X-Admin-Token": TOKEN})
    assert resp.status_code == 200, resp.text
    state = client.get("/api/org/config").json()
    assert state["configured"] is True
    assert state["profile"]["name"] == "Napa Wine Collective"


def test_setup_stays_one_time_even_for_the_operator(client):
    assert client.post("/api/org/config", json=BODY, headers={"X-Admin-Token": TOKEN}).status_code == 200
    again = client.post("/api/org/config", json={"name": "Other"}, headers={"X-Admin-Token": TOKEN})
    assert again.status_code == 403
    assert client.get("/api/org/config").json()["profile"]["name"] == "Napa Wine Collective"


def test_the_first_run_state_stays_readable_without_a_credential(client):
    """The join page reads this before a visitor has any credential."""
    resp = client.get("/api/org/config")
    assert resp.status_code == 200
    assert set(resp.json()) >= {"configured", "profile"}


def test_the_route_is_no_longer_declared_self_signed():
    """A declaration that the handler verifies the body itself would let the
    middleware wave the request through with no credential at all."""
    import auth_verify

    assert "/api/org/config" not in auth_verify.SELF_SIGNED_POST_PATHS
    assert auth_verify.is_admin_bearer_path("POST", "/api/org/config")
    assert auth_verify.requires_auth("POST", "/api/org/config")
    assert not auth_verify.requires_auth("GET", "/api/org/config")


async def test_the_handler_refuses_on_its_own_when_the_middleware_is_not_there(client, monkeypatch, tmp_path):
    """Two layers, each load-bearing: the middleware gate is asserted above
    over the wire; this calls the handler directly, as a request that reached
    it with no credential would, and requires the handler's own refusal. A
    handler that trusted the middleware alone would configure the org here."""
    from unittest.mock import MagicMock

    mod = sys.modules["chapter_agent"]

    req = MagicMock()
    req.state.agent_id = ""
    req.headers = {}

    async def _json():
        return dict(BODY)

    req.json = _json
    resp = await mod.org_config_set(req)
    assert getattr(resp, "status_code", 200) in (401, 403), resp
    assert not mod._load_org_config().get("configured"), "the handler configured the org for an unauthenticated caller"
