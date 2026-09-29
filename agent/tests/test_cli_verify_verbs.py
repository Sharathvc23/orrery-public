"""CLI verbs that expose the member-side verification libraries:
``community-member dat verify`` and ``community-member checkpoint verify``.

These test the CLI plumbing (read input → call the verifier → exit code +
output). The verification logic itself is covered by test_dat / test_checkpoint.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from community_member import checkpoint as cp_mod
from community_member import cli
from community_member import dat as dat_mod
from community_member._dat import DatResult
from community_member.checkpoint import MembershipResult
from community_member.config import Config


def _write(p: Path, obj) -> Path:
    p.write_text(json.dumps(obj))
    return p


# ── dat verify ──


def test_dat_verify_happy_exit0(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dat_mod, "verify_counterparty_dat", lambda *a, **k: DatResult(True, "accepted", "ok"))
    f = _write(tmp_path / "dat.json", {"grant_id": "g1"})
    assert cli._cmd_dat_verify(f, None, None) == 0
    assert "DAT verified" in capsys.readouterr().out


def test_dat_verify_failure_exit2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dat_mod, "verify_counterparty_dat", lambda *a, **k: DatResult(False, "signature", "bad sig"))
    f = _write(tmp_path / "dat.json", {"grant_id": "g1"})
    assert cli._cmd_dat_verify(f, None, None) == 2
    out = capsys.readouterr().out
    assert "FAILED" in out and "signature" in out


def test_dat_verify_unreadable_exit1(tmp_path):
    assert cli._cmd_dat_verify(tmp_path / "nope.json", None, None) == 1


def test_dat_verify_malformed_exit1(tmp_path):
    # Real verifier path: a DAT with no grant_id can't be resolved.
    f = _write(tmp_path / "dat.json", {"no": "grant_id"})
    assert cli._cmd_dat_verify(f, None, None) == 1


def test_dat_verify_chain_list_is_loaded(tmp_path, monkeypatch):
    seen = {}

    def _capture(dat, *, category=None, dats_by_id=None, revocations=None):
        seen["dats_by_id"] = dats_by_id
        return DatResult(True, "accepted", "ok")

    monkeypatch.setattr(dat_mod, "verify_counterparty_dat", _capture)
    dat_f = _write(tmp_path / "dat.json", {"grant_id": "leaf"})
    chain_f = _write(tmp_path / "chain.json", [{"grant_id": "root"}, {"grant_id": "mid"}])
    assert cli._cmd_dat_verify(dat_f, chain_f, None, config=Config(home=tmp_path / "home")) == 0
    assert set(seen["dats_by_id"]) >= {"root", "mid"}


def test_dat_verify_hands_the_verifier_what_this_member_revoked(tmp_path, monkeypatch):
    """The verb's docstring says it checks revocation; this is what makes that
    true rather than merely claimed.

    ``dat verify`` used to call the verifier with no revocation set, which meant
    the argument defaulted to None, None meant allow, and a grant the operator
    had withdrawn verified clean. The stub asserts the set arrives, so the
    argument cannot be dropped again without this going red.
    """
    seen = {}

    def _capture(dat, *, category=None, dats_by_id=None, revocations=None):
        seen["revocations"] = revocations
        return DatResult(True, "accepted", "ok")

    monkeypatch.setattr(dat_mod, "verify_counterparty_dat", _capture)
    config = Config(home=tmp_path / "home")
    assert cli._cmd_dat_revoke("withdrawn-1", "key rotated", config=config) == 0

    f = _write(tmp_path / "dat.json", {"grant_id": "g1"})
    assert cli._cmd_dat_verify(f, None, None, config=config) == 0

    assert seen["revocations"] == {"withdrawn-1"}, "the verb verified against an empty revocation set"


def test_dat_revocations_lists_what_was_revoked(tmp_path, capsys):
    config = Config(home=tmp_path / "home")
    assert cli._cmd_dat_revocations(config=config) == 0
    assert "no revocations on record" in capsys.readouterr().out

    cli._cmd_dat_revoke("g-1", "", config=config)
    cli._cmd_dat_revoke("g-2", "", config=config)
    capsys.readouterr()

    assert cli._cmd_dat_revocations(config=config) == 0
    out = capsys.readouterr().out
    assert "g-1" in out and "g-2" in out


def test_main_wires_dat_verb(tmp_path, monkeypatch):
    monkeypatch.setattr(dat_mod, "verify_counterparty_dat", lambda *a, **k: DatResult(True, "accepted", "ok"))
    f = _write(tmp_path / "dat.json", {"grant_id": "g1"})
    with pytest.raises(SystemExit) as e:
        cli.main(["dat", "verify", str(f)])
    assert e.value.code == 0


# ── checkpoint verify ──


def test_checkpoint_verify_happy_exit0(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cp_mod, "verify_membership", lambda *a, **k: MembershipResult.accepted())
    r = _write(tmp_path / "r.json", {"id": "r1"})
    c = _write(tmp_path / "c.json", {"payload": {}})
    p = _write(tmp_path / "p.json", {"leaf_index": 0})
    assert cli._cmd_checkpoint_verify(r, c, p) == 0
    assert "Membership verified" in capsys.readouterr().out


def test_checkpoint_verify_failure_exit2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cp_mod, "verify_membership", lambda *a, **k: MembershipResult(False, "not_included", "omitted"))
    r = _write(tmp_path / "r.json", {"id": "r1"})
    c = _write(tmp_path / "c.json", {"payload": {}})
    p = _write(tmp_path / "p.json", {"leaf_index": 0})
    assert cli._cmd_checkpoint_verify(r, c, p) == 2
    out = capsys.readouterr().out
    assert "FAILED" in out and "not_included" in out


def test_checkpoint_verify_unreadable_exit1(tmp_path):
    r = _write(tmp_path / "r.json", {"id": "r1"})
    c = _write(tmp_path / "c.json", {"payload": {}})
    assert cli._cmd_checkpoint_verify(r, c, tmp_path / "missing.json") == 1
