"""Every ``/admin/api/*`` route denies an unauthenticated caller — all of them, derived.

WHY THIS FILE EXISTS

``auth_verify.is_open_path`` returns True for the whole ``/admin/api/`` prefix::

    if is_admin_api_path(path):
        return True

so the middleware does not gate the admin API at all; each handler is expected
to call an admin gate itself. That expectation was held by convention and
checked by nothing:

* ``test_route_auth_classification`` walks ``app.routes``, but selects on the
  THIRD STATE — ``is_open_path`` False AND ``requires_auth`` False. The admin
  API is ``is_open_path`` True, so all of it falls outside that scan.
* ``test_admin_api_authz`` runs real adversarial assertions, against a
  hand-listed ``ENDPOINTS`` table of two entries, both under the different
  ``/api/admin/trust/*`` prefix.

Every admin route was in fact gated when this guard was written. The gap was
that a new one that forgot would fail no test.

WHAT THIS GUARD ENFORCES, AND WHY IT IS BEHAVIORAL

The route set is DERIVED from ``chapter_agent.app.routes``, so a route cannot
hide from it by being added without touching this file. What is asserted is not
that a handler CONTAINS a gate call — grepping for a marker string would accept
a gate whose deny path is broken, and there are already two different helpers in
use (``_authorize_admin``, ``_require_admin``) which is how a third gets added
and a call gets missed. Instead each route is CALLED over HTTP with no
credentials and must answer 401/403.

THE FALSE PASS THIS FILE REFUSES TO TAKE

FastAPI validates a request body BEFORE invoking the handler, so a POST with no
body answers 422 without the gate ever running. A 422 therefore proves nothing
about authorization, and counting it as a pass is exactly how a guard becomes
decorative. ``REQUEST_BODIES`` supplies a minimal VALID body for each route that
needs one, and a 422 is a FAILURE telling the author to add an entry — not a
route that got away with it.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402

ADMIN_API_PREFIX = "/admin/api"

#: Minimal VALID bodies for admin routes whose handler sits behind body
#: validation. Keyed by (method, path template). A route missing an entry here
#: shows up as a 422 and fails — see the module docstring.
REQUEST_BODIES: dict[tuple[str, str], dict] = {
    ("POST", "/admin/api/members/{agent_id}/role"): {"role": "member"},
}

#: Placeholders for path parameters. The values only have to route; the gate
#: must refuse before the handler looks at them, which is itself part of what
#: this guard asserts.
PATH_PARAM_VALUES = {"{agent_id}": "probe-agent", "{grant_id}": "probe-grant"}

_GOOD_TOKEN = "a" * 64
_WRONG_TOKEN = "b" * 64

#: The one route used as the POSITIVE CONTROL: it must PASS the gate when the
#: correct token is presented. Without this, a server that denied every request
#: for an unrelated reason (an import error, a wedged dependency) would satisfy
#: every assertion below while proving nothing. Chosen because it reads no
#: database — a control that needs a stub is a control that can break for
#: reasons unrelated to authorization.
POSITIVE_CONTROL = ("GET", "/admin/api/status")


def _admin_routes() -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    for route in chapter_agent.app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods or not path.startswith(ADMIN_API_PREFIX):
            continue
        for method in methods:
            if method in ("HEAD", "OPTIONS"):
                continue
            seen.add((method, path))
    return sorted(seen)


def _concrete(path: str) -> str:
    for placeholder, value in PATH_PARAM_VALUES.items():
        path = path.replace(placeholder, value)
    return path


@pytest.fixture(scope="module")
def routes() -> list[tuple[str, str]]:
    found = _admin_routes()
    assert found, "the admin route scan found nothing; it is broken, not clean"
    return found


@pytest.fixture
def client(monkeypatch):
    """A client whose server HAS an admin token configured.

    Deliberate: ``verify_admin_token`` refuses everything when the token is
    unset, so a suite that left it empty would see 401s everywhere and could not
    tell a real gate from an unconfigured server. Setting it is what makes the
    positive control meaningful.
    """
    import admin as admin_mod

    monkeypatch.setattr(admin_mod, "_admin_token", _GOOD_TOKEN)
    return TestClient(chapter_agent.app)


def _call(client: TestClient, method: str, path: str, headers: dict[str, str] | None = None):
    body = REQUEST_BODIES.get((method, path))
    kwargs: dict = {"headers": headers or {}}
    if method in ("POST", "PUT", "PATCH"):
        kwargs["json"] = body if body is not None else {}
    return client.request(method, _concrete(path), **kwargs)


def test_the_scan_finds_every_admin_route(routes):
    """A scan that silently stopped walking app.routes would report a tiny tree."""
    assert len(routes) >= 10, f"only {len(routes)} admin routes found; the scan is broken"


def test_POSITIVE_CONTROL_the_gate_admits_a_correct_token(client):
    """The 401s below are the gate deciding, not the app being broken."""
    method, path = POSITIVE_CONTROL
    r = _call(client, method, path, headers={"X-Admin-Token": _GOOD_TOKEN})
    assert r.status_code == 200, (
        f"the positive control {method} {path} did not pass the gate with a correct token "
        f"(got {r.status_code}); every denial assertion in this module is therefore unproven"
    )


@pytest.mark.parametrize("method,path", _admin_routes(), ids=lambda v: v if isinstance(v, str) else str(v))
def test_ADVERSARIAL_every_admin_route_denies_an_unauthenticated_caller(client, method, path):
    r = _call(client, method, path)
    assert r.status_code != 422, (
        f"{method} {path} answered 422: body validation rejected the probe BEFORE the handler "
        f"ran, so this route's authorization was never exercised. Add a minimal valid body to "
        f"REQUEST_BODIES[({method!r}, {path!r})] — do not leave it, a 422 is not a denial."
    )
    assert r.status_code in (401, 403), (
        f"{method} {path} is under /admin/api/ — which auth_verify.is_open_path classifies OPEN, "
        f"so the middleware does not gate it — and it answered {r.status_code} to a caller with no "
        f"credentials. Its handler must call an admin gate (_authorize_admin or _require_admin) "
        f"and return the denial before doing any work."
    )


@pytest.mark.parametrize("method,path", _admin_routes(), ids=lambda v: v if isinstance(v, str) else str(v))
def test_ADVERSARIAL_every_admin_route_denies_a_wrong_token(client, method, path):
    """A gate that checks for the HEADER rather than its VALUE passes the test above."""
    r = _call(client, method, path, headers={"X-Admin-Token": _WRONG_TOKEN})
    assert r.status_code != 422, f"{method} {path} answered 422 — see REQUEST_BODIES."
    assert r.status_code in (401, 403), (
        f"{method} {path} answered {r.status_code} to a WRONG admin token; the gate is checking "
        f"for the header's presence, not verifying its value."
    )
