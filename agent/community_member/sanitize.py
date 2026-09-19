"""
Input Sanitization — clean all inputs before sending to chapter.

Every field that leaves this machine passes through sanitization first.
Defense against SQL injection, XSS, command injection, and overflow.
"""

import re
import unicodedata

# Maximum lengths per field type
MAX_AGENT_ID = 50
MAX_SKILL = 50
MAX_SKILLS_COUNT = 20
MAX_INTENT_TEXT = 500
MAX_NAME = 100
MAX_DESCRIPTION = 500
MAX_NOTE = 10_000

# Allowed characters
AGENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$")
SKILL_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 -]*$")

# Dangerous patterns to strip
STRIP_PATTERNS = [
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]+>"),  # All HTML tags
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),  # Event handlers
    re.compile(r"&#\d+;"),  # HTML entities (numeric)
    re.compile(r"&#x[0-9a-f]+;", re.IGNORECASE),  # HTML entities (hex)
]


def sanitize_agent_id(agent_id: str) -> str:
    """Sanitize an agent ID.

    Rules:
    - Lowercase alphanumeric + hyphens only
    - Max 50 characters
    - No leading/trailing hyphens
    - No consecutive hyphens
    """
    if not agent_id:
        return ""

    # Normalize unicode
    agent_id = unicodedata.normalize("NFKC", agent_id)

    # Remove null bytes and control characters
    agent_id = "".join(c for c in agent_id if c.isprintable() and ord(c) >= 32)

    # Lowercase
    agent_id = agent_id.lower().strip()

    # Keep only allowed characters
    agent_id = re.sub(r"[^a-z0-9-]", "-", agent_id)

    # Collapse consecutive hyphens
    agent_id = re.sub(r"-+", "-", agent_id)

    # Strip leading/trailing hyphens
    agent_id = agent_id.strip("-")

    # Truncate
    agent_id = agent_id[:MAX_AGENT_ID]

    return agent_id


def sanitize_text(text: str, max_length: int = MAX_DESCRIPTION) -> str:
    """Sanitize free-form text.

    Removes:
    - HTML/script tags
    - Control characters and null bytes
    - JavaScript event handlers
    Preserves: normal text, punctuation, spaces
    """
    if not text:
        return ""

    # Normalize unicode
    text = unicodedata.normalize("NFKC", text)

    # Remove null bytes and control characters (keep newlines, tabs)
    text = "".join(c for c in text if c in "\n\t" or (c.isprintable() and ord(c) >= 32))

    # Strip dangerous patterns
    for pattern in STRIP_PATTERNS:
        text = pattern.sub("", text)

    # Truncate
    text = text[:max_length].strip()

    return text


def sanitize_skill(skill: str) -> str:
    """Sanitize a single skill tag."""
    skill = sanitize_text(skill, MAX_SKILL)
    # Keep only valid skill characters
    skill = re.sub(r"[^a-zA-Z0-9 -]", "", skill)
    return skill.strip()


def sanitize_skills(skills: list[str]) -> list[str]:
    """Sanitize and limit a list of skills."""
    sanitized = []
    for s in skills[:MAX_SKILLS_COUNT]:
        clean = sanitize_skill(s)
        if clean and clean not in sanitized:
            sanitized.append(clean)
    return sanitized


def sanitize_intent(text: str) -> str:
    """Sanitize intent text."""
    return sanitize_text(text, MAX_INTENT_TEXT)


def sanitize_name(name: str) -> str:
    """Sanitize a display name."""
    return sanitize_text(name, MAX_NAME)


def sanitize_note(text: str) -> str:
    """Sanitize a private note."""
    return sanitize_text(text, MAX_NOTE)
