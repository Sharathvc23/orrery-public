"""That change — server .nanda/ → .org/ read-old-migrate back-compat."""

from __future__ import annotations

import json

from org_home import resolve_org_dir


def test_legacy_present_migrates_into_org(tmp_path):
    """An existing .nanda/ is migrated into .org/ on first resolve, so data
    from an upgraded deployment is NOT lost."""
    (tmp_path / ".nanda").mkdir()
    (tmp_path / ".nanda" / "org-config.json").write_text(json.dumps({"slug": "demo"}))

    org = resolve_org_dir(tmp_path)

    assert org == tmp_path / ".org"
    assert json.loads((org / "org-config.json").read_text())["slug"] == "demo"
    # Non-destructive: the legacy dir is left as a backup.
    assert (tmp_path / ".nanda" / "org-config.json").exists()


def test_both_present_new_wins(tmp_path):
    """If .org/ already exists, it's authoritative — the legacy .nanda/ is not
    copied over the top of it."""
    (tmp_path / ".nanda").mkdir()
    (tmp_path / ".nanda" / "org-config.json").write_text(json.dumps({"slug": "OLD"}))
    (tmp_path / ".org").mkdir()
    (tmp_path / ".org" / "org-config.json").write_text(json.dumps({"slug": "NEW"}))

    org = resolve_org_dir(tmp_path)

    assert json.loads((org / "org-config.json").read_text())["slug"] == "NEW"


def test_neither_present_creates_fresh(tmp_path):
    """A fresh install with no legacy dir gets a clean empty .org/."""
    org = resolve_org_dir(tmp_path)

    assert org == tmp_path / ".org"
    assert org.is_dir()
    assert not any(org.iterdir())
