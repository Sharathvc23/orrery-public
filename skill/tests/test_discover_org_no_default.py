"""Slug discovery contacts only a registry the user named.

The helper used to default to a public NANDA registry, so `join <slug>` on a
fresh install queried a third party the user never configured. These pin the
replacement rule: no registry configured means no registry contacted, said by
name, and join-by-URL is the path.
"""

import json
import sys

import discover_org
import pytest


@pytest.fixture(autouse=True)
def _no_registry_env(monkeypatch):
    monkeypatch.delenv("REGISTRY_URL", raising=False)
    monkeypatch.delenv("ORRERY_REGISTRY_URL", raising=False)


def test_unset_means_no_registry():
    assert discover_org._registry_url() == ""


def test_the_former_default_is_named_nowhere_in_the_helper():
    """The one host this helper used to reach on its own must not survive as a
    fallback under a different spelling."""
    source = open(discover_org.__file__, encoding="utf-8").read()
    assert "nest.projectnanda.org" not in source
    assert "DEFAULT_REGISTRY" not in source


def test_explicit_empty_registry_url_is_off(monkeypatch):
    monkeypatch.setenv("REGISTRY_URL", "")
    monkeypatch.setenv("ORRERY_REGISTRY_URL", "https://registry.example")
    assert discover_org._registry_url() == "", "an explicit empty REGISTRY_URL must win over the fallback name"


def test_either_variable_names_the_registry(monkeypatch):
    monkeypatch.setenv("ORRERY_REGISTRY_URL", "https://registry.example/")
    assert discover_org._registry_url() == "https://registry.example"
    monkeypatch.setenv("REGISTRY_URL", "https://other.example")
    assert discover_org._registry_url() == "https://other.example"


def test_main_refuses_by_name_and_opens_no_connection(monkeypatch, capsys):
    """With nothing configured, main() must exit 2 with `no_registry_configured`
    before any HTTP client is built."""

    def _explode(*a, **k):
        raise AssertionError("no registry is configured, so no client may be constructed")

    monkeypatch.setattr(discover_org.httpx, "Client", _explode)
    monkeypatch.setattr(sys, "argv", ["discover_org.py", "someorg"])
    rc = discover_org.main()
    err = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert rc == 2
    assert err["error"] == "no_registry_configured"
    assert "REGISTRY_URL" in err["hint"]
