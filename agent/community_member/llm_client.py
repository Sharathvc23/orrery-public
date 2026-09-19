"""Build a chat completion from the local agent's configured LLM.

Shared by the LLM-using built-in skills (summarize, draft) so they call the
user's OWN model — the same provider/model/key the dashboard's Settings page
sets, including a local Ollama — with no extra configuration. Nothing here
reaches a third-party service the user didn't already configure.
"""

from __future__ import annotations

from community_member import llm_runtime as _llm_runtime


def strict_enabled() -> bool:
    """Whether a client may be built without a usable credential.

    The agent's reader for LLM_STRICT. The server reads the same variable
    through ``env_flags.security_flag``, which is a server module — this tree has
    no equivalent, so the parse lives here rather than being duplicated at each
    call site. Same spellings, same default: OFF, which is today's behaviour.
    """
    import os

    raw = (os.environ.get("LLM_STRICT") or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    return False


# THE TABLE IS GONE. It was one of five that disagreed about base URLs, key
# variables and default models; llm_runtime.PROVIDERS is the union of all of them
# and the only one left. These two names are kept because this module's callers
# read them, and they now derive from the registry rather than restating it.
_PROVIDER_BASE_URLS = {name: p.base_url for name, p in _llm_runtime.PROVIDERS.items()}
_LOCAL_PROVIDERS = set(_llm_runtime.LOCAL_PROVIDERS)


def llm_is_configured(provider: str | None, api_key: str | None) -> bool:
    """Whether this agent has a usable LLM.

    THE one definition. `chat_or_error` below already enforced this rule and
    refused cleanly; the autonomous think loop did not, and instead built a
    client with `base_url` defaulting to xAI and `api_key="local"` — so a
    keyless install issued a 400 to a third party on every tick, forever
    (~17k/day/agent). Both paths now ask the same question here.

    A local provider needs no key (that is the point of a local provider).
    Anything else needs both a known provider and a key.
    """
    prov = (provider or "").strip().lower()
    if prov in _LOCAL_PROVIDERS:
        return True
    return bool(prov) and bool((api_key or "").strip())


def base_url_for(provider: str | None) -> str | None:
    """The provider's OpenAI-compatible base URL, or None if unknown.

    Returns None rather than guessing. The previous `dict.get(provider,
    "https://api.x.ai/v1")` meant an EMPTY provider silently addressed xAI.
    """
    return _PROVIDER_BASE_URLS.get((provider or "").strip().lower())


def chat_or_error(
    messages: list[dict],
    *,
    max_tokens: int = 400,
    temperature: float = 0.3,
) -> tuple[str | None, str | None]:
    """Run one chat completion with the agent's configured LLM.

    Returns ``(text, None)`` on success, or ``(None, reason)`` when no usable
    LLM is configured or the call fails — so a skill surfaces a clean message
    instead of crashing the turn loop.
    """
    from community_member.config import Config

    cfg = Config.load()
    provider = (getattr(cfg, "provider", "") or "").lower()
    model = getattr(cfg, "model", "") or ""
    api_key = getattr(cfg, "api_key", "") or ""
    is_local = provider in _LOCAL_PROVIDERS

    if not api_key and not is_local:
        return None, "no LLM configured — set a provider + key in Settings"
    if not model:
        return None, "no model configured — set one in Settings"

    try:
        from community_member import llm_runtime

        # One construction where there were two. The ternary chose between a
        # client with a base_url and one without, and the second reached
        # OpenAI's default endpoint for any provider whose base_url lookup came
        # back empty — carrying whatever key had been resolved.
        client = llm_runtime.build_client(
            llm_runtime.resolve(provider, model=model),
            api_key=api_key,
        )
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return (resp.choices[0].message.content or "").strip(), None
    except Exception as e:
        return None, f"LLM call failed: {type(e).__name__}: {e}"
