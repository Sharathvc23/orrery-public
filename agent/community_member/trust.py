"""
Chapter Trust — Trust On First Use (TOFU) verification.

On first connection to a chapter, stores the chapter's identity.
On subsequent connections, verifies the identity hasn't changed.
If it has → warning (potential MITM or chapter key rotation).
"""

import json

from .config import CONFIG_DIR

TRUST_FILE = CONFIG_DIR / "trusted_chapters.json"


def load_trusted() -> dict:
    """Load trusted chapter keys."""
    if TRUST_FILE.exists():
        try:
            return json.loads(TRUST_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_trusted(trusted: dict):
    """Save trusted chapter keys."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    TRUST_FILE.write_text(json.dumps(trusted, indent=2))


def verify_chapter(chapter_url: str, chapter_id: str, chapter_name: str, public_key: str = "") -> tuple[str, str]:
    """Verify chapter identity using TOFU.

    Returns:
        (status, message) where status is:
        - "new": first time seeing this chapter, key stored
        - "trusted": chapter key matches stored key
        - "warning": chapter key changed (possible MITM)
        - "unknown": no key provided by chapter
    """
    trusted = load_trusted()
    key = chapter_url.rstrip("/")

    if key not in trusted:
        # First time — store the identity
        trusted[key] = {
            "chapter_id": chapter_id,
            "chapter_name": chapter_name,
            "public_key": public_key,
        }
        save_trusted(trusted)
        return "new", f"First connection to {chapter_name}. Identity stored."

    stored = trusted[key]

    # Check if identity matches
    if public_key and stored.get("public_key"):
        if public_key == stored["public_key"]:
            return "trusted", f"{chapter_name} identity verified."
        else:
            return "warning", (
                f"WARNING: {chapter_name} public key has CHANGED.\n"
                f"  Stored:  {stored['public_key'][:20]}...\n"
                f"  Current: {public_key[:20]}...\n"
                f"  This could be a key rotation or a man-in-the-middle attack.\n"
                f"  Verify with the chapter operator before proceeding."
            )

    if stored.get("chapter_id") != chapter_id:
        return "warning", (
            f"WARNING: Chapter identity changed.\n  Expected: {stored.get('chapter_id')}\n  Got: {chapter_id}"
        )

    return "trusted", f"{chapter_name} identity matches."


def reset_trust(chapter_url: str):
    """Remove trust for a chapter (after user confirms key change is legitimate)."""
    trusted = load_trusted()
    key = chapter_url.rstrip("/")
    trusted.pop(key, None)
    save_trusted(trusted)
