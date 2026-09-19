"""Shared test setup for the agent suite.

The local API requires a token on every route not declared open in
``community_member.local_auth.OPEN_ROUTES``. Tests drive the app through
``TestClient``, so the token is supplied in one place here rather than in each
of the ~75 tests that call a protected route.

A test that needs to exercise the refusal marks itself
``@pytest.mark.no_local_token`` and gets a client with no header attached.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from community_member import local_auth

TEST_LOCAL_TOKEN = "test-local-token-not-a-real-secret"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_local_token: build TestClients without the local API token, to test refusal",
    )


@pytest.fixture(autouse=True)
def local_api_token(request, monkeypatch):
    """Point the middleware at a fixed token and have TestClient send it.

    Setting the env override also stops ``create_app`` writing a token file
    into whatever home a test happens to configure.
    """
    monkeypatch.setenv(local_auth.TOKEN_ENV_VAR, TEST_LOCAL_TOKEN)

    if "no_local_token" in request.keywords:
        yield None
        return

    original_init = TestClient.__init__

    def _init_with_token(self, *args, **kwargs):
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("Authorization", f"Bearer {TEST_LOCAL_TOKEN}")
        original_init(self, *args, headers=headers, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", _init_with_token)
    yield TEST_LOCAL_TOKEN
