"""Built-in 'draft' skill — write a short message/email from an intent.

Uses the agent's own configured LLM (local Ollama works). Part of the Team
pack. Returns a draft the human reviews and sends — it does NOT send anything.
"""

from __future__ import annotations


def _draft(args: dict) -> dict:
    intent = str((args or {}).get("intent", "")).strip()
    if not intent:
        return {"error": "intent is required (what the message should say / accomplish)"}
    tone = str((args or {}).get("tone", "") or "warm and professional").strip()
    fmt = str((args or {}).get("format", "") or "email").strip().lower()

    from community_member.llm_client import chat_or_error

    draft, err = chat_or_error(
        [
            {
                "role": "system",
                "content": (
                    f"You draft a short {fmt} for the user to review and send. Tone: {tone}. "
                    "Keep it concise. Output only the draft (with a subject line if it's an "
                    "email) — no commentary."
                ),
            },
            {"role": "user", "content": intent},
        ],
        max_tokens=600,
    )
    if err:
        return {"error": err}
    return {"draft": draft, "format": fmt}


TOOLS = [
    {
        "name": "draft",
        "description": "Draft a short message or email from an intent (you review + send it).",
        "parameters": {
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "What the message should say or accomplish.",
                },
                "tone": {
                    "type": "string",
                    "description": "Desired tone (default: warm and professional).",
                },
                "format": {
                    "type": "string",
                    "description": "'email' or 'message' (default: email).",
                },
            },
            "required": ["intent"],
        },
        "fn": _draft,
    },
]
