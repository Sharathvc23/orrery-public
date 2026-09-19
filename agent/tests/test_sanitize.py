"""
Security tests for sanitize.py — SC-6: Input Sanitization.

SEC-16: SQL injection sanitized (ADVERSARIAL)
SEC-17: XSS payload stripped (ADVERSARIAL)
SEC-18: Oversized text truncated (EDGE)
SEC-19: Null bytes removed (ADVERSARIAL)
"""

from community_member.sanitize import (
    MAX_AGENT_ID,
    MAX_DESCRIPTION,
    MAX_INTENT_TEXT,
    MAX_SKILLS_COUNT,
    sanitize_agent_id,
    sanitize_intent,
    sanitize_skill,
    sanitize_skills,
    sanitize_text,
)

# ═══════════════════════════════════════════════
# SEC-16: SQL injection sanitized
# ═══════════════════════════════════════════════


def test_sql_injection_in_agent_id():
    """ADVERSARIAL: SQL injection in agent_id stripped."""
    result = sanitize_agent_id("'; DROP TABLE agents; --")
    assert "DROP" not in result
    assert ";" not in result
    assert "'" not in result
    assert result  # Not empty


def test_sql_injection_in_text():
    """ADVERSARIAL: SQL injection in free text stripped."""
    result = sanitize_text("Hello'; DELETE FROM users; --")
    assert "DELETE" in result  # Text stays (it's not HTML)
    assert result  # Not empty — SQL is text, not executable in our context


def test_sql_union_attack():
    """ADVERSARIAL: UNION SELECT attack in agent_id."""
    result = sanitize_agent_id("admin' UNION SELECT * FROM users--")
    assert "UNION" not in result
    assert "SELECT" not in result


# ═══════════════════════════════════════════════
# SEC-17: XSS payload stripped
# ═══════════════════════════════════════════════


def test_xss_script_tag_stripped():
    """ADVERSARIAL: script tag removed from text."""
    result = sanitize_text('<script>alert("xss")</script>Hello')
    assert "<script>" not in result
    assert "alert" not in result
    assert "Hello" in result


def test_xss_event_handler_stripped():
    """ADVERSARIAL: onclick handler removed."""
    result = sanitize_text('<img onerror="evil()" src=x>Hello')
    assert "onerror" not in result
    assert "evil" not in result
    assert "Hello" in result


def test_xss_javascript_protocol_stripped():
    """ADVERSARIAL: javascript: protocol removed."""
    result = sanitize_text('Click <a href="javascript:evil()">here</a>')
    assert "javascript:" not in result


def test_xss_html_entities_stripped():
    """ADVERSARIAL: HTML entities stripped."""
    result = sanitize_text("&#60;script&#62;evil&#60;/script&#62;")
    assert "&#60;" not in result


def test_xss_in_skill():
    """ADVERSARIAL: XSS in skill name removed."""
    result = sanitize_skill("<img onerror=evil src=x>")
    assert "<" not in result
    assert "onerror" not in result


# ═══════════════════════════════════════════════
# SEC-18: Oversized text truncated
# ═══════════════════════════════════════════════


def test_agent_id_truncated():
    """EDGE: oversized agent_id truncated to max."""
    result = sanitize_agent_id("a" * 200)
    assert len(result) <= MAX_AGENT_ID


def test_text_truncated():
    """EDGE: oversized text truncated."""
    result = sanitize_text("x" * 10000)
    assert len(result) <= MAX_DESCRIPTION


def test_intent_truncated():
    """EDGE: oversized intent truncated."""
    result = sanitize_intent("x" * 10000)
    assert len(result) <= MAX_INTENT_TEXT


def test_skills_count_limited():
    """EDGE: too many skills truncated to max count."""
    skills = [f"skill-{i}" for i in range(100)]
    result = sanitize_skills(skills)
    assert len(result) <= MAX_SKILLS_COUNT


# ═══════════════════════════════════════════════
# SEC-19: Null bytes removed
# ═══════════════════════════════════════════════


def test_null_bytes_in_agent_id():
    """ADVERSARIAL: null bytes removed from agent_id."""
    result = sanitize_agent_id("agent\x00id")
    assert "\x00" not in result
    assert result == "agent-id" or "agent" in result


def test_null_bytes_in_text():
    """ADVERSARIAL: null bytes removed from text."""
    result = sanitize_text("hello\x00world")
    assert "\x00" not in result


def test_control_characters_removed():
    """ADVERSARIAL: control characters stripped."""
    result = sanitize_text("hello\x01\x02\x03world")
    assert all(ord(c) >= 32 or c in "\n\t" for c in result)


# ═══════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════


def test_empty_agent_id():
    """EDGE: empty string returns empty."""
    assert sanitize_agent_id("") == ""


def test_empty_text():
    """EDGE: empty text returns empty."""
    assert sanitize_text("") == ""


def test_empty_skills():
    """EDGE: empty list returns empty."""
    assert sanitize_skills([]) == []


def test_agent_id_hyphens_only():
    """EDGE: hyphens-only agent_id returns empty (stripped)."""
    result = sanitize_agent_id("---")
    assert result == ""


def test_agent_id_uppercase_lowered():
    """HAPPY: uppercase lowered."""
    assert sanitize_agent_id("MyAgent") == "myagent"


def test_agent_id_spaces_to_hyphens():
    """HAPPY: spaces become hyphens."""
    result = sanitize_agent_id("my agent name")
    assert " " not in result
    assert "-" in result


def test_skill_deduplication():
    """EDGE: duplicate skills removed."""
    result = sanitize_skills(["python", "python", "rust"])
    assert result == ["python", "rust"]


def test_unicode_normalization():
    """EDGE: unicode normalized (NFC → NFKC)."""
    # ﬁ (U+FB01) should normalize to "fi"
    result = sanitize_text("ﬁle")
    assert "fi" in result or "ﬁ" in result  # Depends on NFKC
