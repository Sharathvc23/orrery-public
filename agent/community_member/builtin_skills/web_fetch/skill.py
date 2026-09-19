"""Built-in 'web-fetch' skill — fetch one URL over HTTP(S).

Declares the ``net.http`` capability. That capability is *grantable* but NOT in
``HIGH_RISK_CAPABILITIES`` (which is reserved for ``net.arbitrary`` — raw
sockets / non-HTTP egress), so once granted it runs without a per-call consent
prompt. Built-in skills are auto-granted their declared capabilities at load.

Safety posture: only ``http``/``https`` schemes, a hard timeout, a capped
response size, and a crude HTML→text reduction so the model gets readable text
rather than markup. This is deliberately a *fetch*, not a browser — no JS, no
auth, no following non-HTTP redirects.
"""

from __future__ import annotations

import re

_MAX_CHARS = 6000
_TIMEOUT_S = 20.0


def _html_to_text(html: str) -> str:
    # Drop script/style bodies, strip tags, collapse whitespace. Good enough
    # to hand an LLM the readable content without a full HTML parser dep.
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def _fetch(args: dict) -> dict:
    url = str((args or {}).get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must start with http:// or https://"}

    import httpx

    try:
        resp = httpx.get(
            url,
            timeout=_TIMEOUT_S,
            follow_redirects=True,
            headers={"User-Agent": "orrery-agent/1.0 (+web-fetch skill)"},
        )
    except Exception as exc:
        return {"error": f"fetch failed: {type(exc).__name__}: {exc}"}

    ctype = resp.headers.get("content-type", "")
    body = resp.text
    text = _html_to_text(body) if "html" in ctype.lower() else body.strip()
    truncated = len(text) > _MAX_CHARS
    return {
        "status": resp.status_code,
        "url": str(resp.url),
        "content_type": ctype,
        "truncated": truncated,
        "text": text[:_MAX_CHARS],
    }


TOOLS = [
    {
        "name": "fetch",
        "description": "Fetch a single HTTP(S) URL and return its text content (HTML reduced to text).",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The http(s):// URL to fetch.",
                },
            },
            "required": ["url"],
        },
        "fn": _fetch,
    },
]
