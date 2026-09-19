"""
Security tests for trust.py — SC-8: Chapter Trust (TOFU).

SEC-22: First connect stores key
SEC-23: Changed key triggers warning
"""

import pytest

from community_member.trust import (
    load_trusted,
    reset_trust,
    verify_chapter,
)


@pytest.fixture(autouse=True)
def clean_trust(tmp_path, monkeypatch):
    """Use a temp dir for trust file."""
    import community_member.trust as trust_mod

    trust_file = tmp_path / "trusted_chapters.json"
    monkeypatch.setattr(trust_mod, "TRUST_FILE", trust_file)
    monkeypatch.setattr(trust_mod, "CONFIG_DIR", tmp_path)
    yield trust_file


# ═══════════════════════════════════════════════
# SEC-22: First connect stores key
# ═══════════════════════════════════════════════


def test_first_connect_stores_key():
    """HAPPY: first connection stores chapter identity."""
    status, msg = verify_chapter(
        "https://chapter.example.com",
        "test-chapter",
        "Test Chapter",
        "pubkey123",
    )
    assert status == "new"
    assert "stored" in msg.lower()

    # Verify it's persisted
    trusted = load_trusted()
    assert "https://chapter.example.com" in trusted
    assert trusted["https://chapter.example.com"]["public_key"] == "pubkey123"


def test_second_connect_trusted():
    """HAPPY: second connection with same key passes."""
    verify_chapter("https://ch.com", "ch1", "Chapter", "key1")
    status, msg = verify_chapter("https://ch.com", "ch1", "Chapter", "key1")
    assert status == "trusted"


# ═══════════════════════════════════════════════
# SEC-23: Changed key triggers warning
# ═══════════════════════════════════════════════


def test_changed_key_warns():
    """ADVERSARIAL: different key triggers warning."""
    verify_chapter("https://ch.com", "ch1", "Chapter", "original-key")
    status, msg = verify_chapter("https://ch.com", "ch1", "Chapter", "DIFFERENT-KEY")
    assert status == "warning"
    assert "CHANGED" in msg or "changed" in msg


def test_changed_chapter_id_warns():
    """ADVERSARIAL: different chapter_id triggers warning."""
    verify_chapter("https://ch.com", "original-id", "Chapter", "")
    status, msg = verify_chapter("https://ch.com", "DIFFERENT-id", "Chapter", "")
    assert status == "warning"


def test_no_key_provided():
    """EDGE: chapter provides no key — trusted by ID only."""
    verify_chapter("https://ch.com", "ch1", "Chapter", "")
    status, msg = verify_chapter("https://ch.com", "ch1", "Chapter", "")
    assert status == "trusted"


def test_reset_trust():
    """HAPPY: reset_trust removes stored key."""
    verify_chapter("https://ch.com", "ch1", "Chapter", "key1")
    reset_trust("https://ch.com")
    trusted = load_trusted()
    assert "https://ch.com" not in trusted

    # Next connect is "new" again
    status, _ = verify_chapter("https://ch.com", "ch1", "Chapter", "key2")
    assert status == "new"
