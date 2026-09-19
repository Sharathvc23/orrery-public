"""Built-in 'summarize' skill — condense text with the agent's own LLM.

Offline in the sense that matters: it uses the user's configured provider
(which can be a local Ollama), nothing new. Part of the Team pack.
"""

from __future__ import annotations

_MAX_INPUT = 12000


def _summarize(args: dict) -> dict:
    text = str((args or {}).get("text", "")).strip()
    if not text:
        return {"error": "text is required"}
    sentences = (args or {}).get("sentences")
    try:
        n = max(1, min(10, int(sentences))) if sentences is not None else 3
    except (TypeError, ValueError):
        n = 3

    from community_member.llm_client import chat_or_error

    summary, err = chat_or_error(
        [
            {
                "role": "system",
                "content": (
                    f"Summarize the user's text in at most {n} sentences. Be faithful and "
                    "concise; output only the summary, no preamble."
                ),
            },
            {"role": "user", "content": text[:_MAX_INPUT]},
        ],
        max_tokens=400,
    )
    if err:
        return {"error": err}
    return {"summary": summary}


TOOLS = [
    {
        "name": "summarize",
        "description": "Summarize a block of text in a few sentences.",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The text to summarize."},
                "sentences": {
                    "type": "integer",
                    "description": "Target sentence count (1-10, default 3).",
                },
            },
            "required": ["text"],
        },
        "fn": _summarize,
    },
]
