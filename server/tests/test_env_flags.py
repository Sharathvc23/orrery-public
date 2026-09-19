"""Security-gating env flags must fail in the direction the caller declared.

C9 (AUDIT_HARSH.md): ``FEDERATION_ENFORCE_SIGNED_BROADCASTS`` was parsed inline
as ``os.environ.get(NAME, "") in {...truthy...}``, so an absent variable landed
in the permissive branch and enforcement was silently OFF — while
``.env.example`` advertised ``true``. These tests pin the flags BY NAME so the
default cannot drift back without a failing test.

The class of bug is "unset means permissive", so the assertions that matter most
are the ones about *absence*: unset, empty, and whitespace must be
indistinguishable from each other, and must land on the declared default.
"""

from __future__ import annotations

import pytest

import env_flags
import federation_discovery
import federation_signing
import secret_sealing

# The two flags C9 named, plus C11's, with the direction each must fail when
# nobody decides. ORRERY_REQUIRE_SEALED_SECRETS is the same shape one subsystem
# over: unset used to mean "write the org's signing key in plaintext".
SECURITY_FLAGS = [
    ("FEDERATION_ENFORCE_SIGNED_BROADCASTS", federation_signing.enforcement_enabled),
    ("FEDERATION_REQUIRE_SIGNED_RECORDS", federation_discovery.require_signed_records),
    ("ORRERY_REQUIRE_SEALED_SECRETS", secret_sealing.sealing_required),
]

# Values that mean "the operator did not decide" — all must yield the default.
UNDECIDED = ["", "   ", "\t", "ture", "enabled", "maybe", "TRUE-ish"]


# ── the parser ───────────────────────────────────────────────────────────────


def test_unset_returns_the_declared_default(monkeypatch):
    monkeypatch.delenv("SOME_SECURITY_FLAG", raising=False)
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=True) is True
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=False) is False


@pytest.mark.parametrize("raw", UNDECIDED)
def test_undecided_values_return_the_declared_default(monkeypatch, raw):
    """Empty, whitespace and unrecognised are all "nobody decided"."""
    monkeypatch.setenv("SOME_SECURITY_FLAG", raw)
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=True) is True
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=False) is False


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "Yes", "on", "  on  "])
def test_recognised_truthy_overrides_a_false_default(monkeypatch, raw):
    monkeypatch.setenv("SOME_SECURITY_FLAG", raw)
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=False) is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "No", "off", "  off  "])
def test_recognised_falsey_overrides_a_true_default(monkeypatch, raw):
    """The operator's escape hatch: re-opening warn-only mode must still work."""
    monkeypatch.setenv("SOME_SECURITY_FLAG", raw)
    assert env_flags.security_flag("SOME_SECURITY_FLAG", default=True) is False


def test_default_is_keyword_only_and_required():
    """The direction of failure must be written at the call site, not inferred."""
    with pytest.raises(TypeError):
        env_flags.security_flag("SOME_SECURITY_FLAG", True)  # type: ignore[misc]
    with pytest.raises(TypeError):
        env_flags.security_flag("SOME_SECURITY_FLAG")  # type: ignore[call-arg]


# ── the two C9 flags, by name ────────────────────────────────────────────────


@pytest.mark.parametrize("name,fn", SECURITY_FLAGS, ids=lambda v: v if isinstance(v, str) else "")
def test_c9_flag_enforces_when_unset(monkeypatch, name, fn):
    """The regression under test: absent must mean ENFORCING, not permissive."""
    monkeypatch.delenv(name, raising=False)
    assert fn() is True, f"{name} unset must enforce (C9: it used to fail open)"


@pytest.mark.parametrize("name,fn", SECURITY_FLAGS, ids=lambda v: v if isinstance(v, str) else "")
@pytest.mark.parametrize("raw", UNDECIDED)
def test_c9_flag_unset_and_empty_are_identical(monkeypatch, name, fn, raw):
    """done-when: "unset AND empty behave identically"."""
    monkeypatch.delenv(name, raising=False)
    unset_result = fn()
    monkeypatch.setenv(name, raw)
    assert fn() is unset_result is True


@pytest.mark.parametrize("name,fn", SECURITY_FLAGS, ids=lambda v: v if isinstance(v, str) else "")
def test_c9_flag_can_still_be_disabled_explicitly(monkeypatch, name, fn):
    """Flipping the default must not remove the operator's warn-only lever."""
    monkeypatch.setenv(name, "false")
    assert fn() is False
    monkeypatch.setenv(name, "0")
    assert fn() is False


@pytest.mark.parametrize("name,fn", SECURITY_FLAGS, ids=lambda v: v if isinstance(v, str) else "")
def test_c9_flag_typo_does_not_silently_disable(monkeypatch, name, fn):
    """A misspelled value is a typo, not a decision to stop enforcing.

    The old inline parse read `ture` as falsey — one keystroke silently
    disabled signature enforcement on a federated mesh.
    """
    monkeypatch.setenv(name, "ture")
    assert fn() is True


def test_env_example_agrees_with_the_code_defaults():
    """C9 was a *disagreement* between code and .env.example, so pin both.

    If someone flips a default back, this fails unless they also edit the
    documented value — which is the conversation the audit wanted forced.
    """
    from pathlib import Path

    env_example = Path(__file__).resolve().parents[2] / ".env.example"
    text = env_example.read_text()
    for name, _fn in SECURITY_FLAGS:
        assert f"{name}=true" in text, f"{name} must be documented as true in .env.example"
