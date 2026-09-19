"""The published-by-default scoring method is env-driven (the nanda-rep/0.2 flip).

A chapter publishes nanda-rep/0.1 by default; setting DEFAULT_SCORING_METHOD=
nanda-rep/0.2 flips it to the corroborated score (a deliberate, reversible,
per-chapter ops decision). An unsupported value falls back to 0.1 rather than
failing the chapter at boot.

Classification: HAPPY / EDGE / FAILURE.
"""

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-key")

import vrp as vrp_mod  # noqa: E402


def test_default_is_v01_when_unset(monkeypatch):  # HAPPY — flip-safe default
    monkeypatch.delenv("DEFAULT_SCORING_METHOD", raising=False)
    assert vrp_mod._resolve_default_scoring_method() == "nanda-rep/0.1"


def test_flip_to_v02_via_env(monkeypatch):  # HAPPY — the flip
    monkeypatch.setenv("DEFAULT_SCORING_METHOD", "nanda-rep/0.2")
    assert vrp_mod._resolve_default_scoring_method() == "nanda-rep/0.2"


def test_whitespace_tolerated(monkeypatch):  # EDGE
    monkeypatch.setenv("DEFAULT_SCORING_METHOD", " nanda-rep/0.2 ")
    assert vrp_mod._resolve_default_scoring_method() == "nanda-rep/0.2"


def test_unsupported_value_falls_back_to_v01(monkeypatch):  # FAILURE — never boot-fail
    monkeypatch.setenv("DEFAULT_SCORING_METHOD", "nanda-rep/9.9")
    assert vrp_mod._resolve_default_scoring_method() == "nanda-rep/0.1"
