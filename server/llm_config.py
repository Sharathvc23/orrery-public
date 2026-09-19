"""The chapter's LLM configuration — a SHIM over ``llm_runtime``.

This module used to own a provider table, a resolution order and a client
factory. It owns none of them now: ``llm_runtime`` is the one registry and the
one factory, and everything below re-exports from it.

The public surface is unchanged on purpose. Twenty-three call sites read the
single client built at ``chapter_agent.py`` and never construct one of their
own, and ``PROVIDER`` / ``BASE_URL`` / ``API_KEY`` / ``DEFAULT_MODEL`` /
``build_client`` / ``planner_enabled`` are read across the tree — so this stays a
stable name rather than becoming a thirty-site edit.

Provider-agnostic LLM configuration for the chapter.

The chapter talks to LLMs through an OpenAI-shaped client (``chat.completions``).
Anthropic, xAI, OpenAI, Groq and Ollama all expose OpenAI-compatible endpoints,
so switching providers is just base_url + api_key + model — no call-site changes.

Resolution order:
  1. ``LLM_PROVIDER`` env (explicit) — anthropic | xai | openai | groq | ollama.
  2. else auto-detect from whichever provider key is set, preferring Anthropic.
     So a chapter that has ``ANTHROPIC_API_KEY`` defaults to Claude; one that still
     only has ``XAI_API_KEY`` keeps working on Grok — no surprise migration.

Key comes from ``LLM_API_KEY`` else the provider's conventional env var. Model
comes from ``LLM_MODEL`` (or legacy ``DEFAULT_LLM_MODEL``) else the provider
default. A missing key is NON-FATAL: the chapter boots (portal/surfaces still
work) and LLM calls fail at runtime with a clear auth error, instead of crashing
the whole process at import — important for self-hosting (bring your own key).
"""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

import env_flags
import llm_runtime

# THE PROVIDER TABLE IS GONE. It was one of five that disagreed with each other
# about base URLs, key variables and default models. ``llm_runtime.PROVIDERS`` is
# the union of all of them and the only one left.
_DETECT_ORDER = ("anthropic", "xai", "openai", "groq")
_DEFAULT_PROVIDER = "anthropic"


def strict_enabled() -> bool:
    """Whether a client may be built without a usable credential.

    A SECURITY GATE, and declared as one: it decides whether member names, skill
    lists and federation peer names leave the box when nobody configured a
    provider. A keyless chapter used to POST all three under
    ``Authorization: Bearer MISSING`` while the configuration documentation
    promised it made no request at all.

    SHIPS AT FALSE for one release. Off is today's behaviour exactly, plus a log
    line saying what On would have refused, so the difference can be read off
    deployed servers before it changes on every service at once. Turning it on is
    an environment change and turning it back off is the rollback — neither needs
    a code revert.
    """
    return env_flags.security_flag("LLM_STRICT", default=False)


def autodetect_enabled() -> bool:
    """Whether a provider may be inferred from whichever key is in the environment.

    Also a security gate: with no ``LLM_PROVIDER`` set, detection picks a real
    remote provider from an ambient key, so an operator who configured nothing
    still gets a client aimed at a third party. Defaults to True, which is
    today's behaviour; ``LLM_AUTODETECT=0`` requires an explicit provider.
    """
    return env_flags.security_flag("LLM_AUTODETECT", default=True)


def _resolve() -> tuple[str, str, str, str]:
    """Resolve (provider, base_url, api_key, model) for this process.

    The resolution ORDER is this module's — explicit LLM_PROVIDER, else
    auto-detect from whichever provider key is set — but every value it produces
    comes from the shared registry rather than from a table kept here.
    """
    explicit = llm_runtime.normalise_provider(os.environ.get("LLM_PROVIDER"))
    if explicit:
        if explicit in llm_runtime.PROVIDERS:
            provider = explicit
        else:
            provider = _DEFAULT_PROVIDER
            print(f"[llm] unknown LLM_PROVIDER={explicit!r}; falling back to {provider}")
    elif autodetect_enabled():
        provider = next(
            (p for p in _DETECT_ORDER if os.environ.get(llm_runtime.PROVIDERS[p].key_env, "").strip()),
            _DEFAULT_PROVIDER,
        )
    else:
        # Ambient detection off: the operator must name a provider. Falling
        # through to the default here would pick one from whichever key happened
        # to be in the environment, which is the behaviour this flag exists to
        # let an operator switch off.
        provider = _DEFAULT_PROVIDER
    spec = llm_runtime.PROVIDERS[provider]
    api_key = os.environ.get("LLM_API_KEY", "").strip() or os.environ.get(spec.key_env, "").strip()
    base_url = os.environ.get("LLM_BASE_URL", "").strip() or spec.base_url
    # DEFAULT_LLM_MODEL kept for back-compat with existing deployments.
    model = (
        os.environ.get("LLM_MODEL", "").strip()
        or os.environ.get("DEFAULT_LLM_MODEL", "").strip()
        or spec.models[llm_runtime.TIER_BALANCED]
    )
    return provider, base_url, api_key, model


PROVIDER, BASE_URL, API_KEY, DEFAULT_MODEL = _resolve()

if not API_KEY:
    print(
        f"⚠️  [llm] no API key resolved for provider {PROVIDER!r} — LLM features will fail until "
        f"{llm_runtime.PROVIDERS[PROVIDER].key_env} (or LLM_API_KEY) is set"
    )
else:
    print(f"[llm] provider={PROVIDER} model={DEFAULT_MODEL} base_url={BASE_URL}")


def build_client() -> Any:
    """An OpenAI-shaped client for the resolved provider.

    Constructed by ``llm_runtime.build_client``, so this client carries the
    capped retry count and the explicit timeout rather than the SDK defaults
    every previous construction site ran.

    An explicitly configured ``LLM_BASE_URL`` still wins: a chapter pointed at a
    self-hosted or proxied endpoint is correctly configured, and the registry's
    address for the provider is not a reason to override the operator's.

    The key may still be empty here — importing or booting the chapter must not
    crash on a missing one, and call sites ask ``planner_enabled()`` first.
    """
    resolution = llm_runtime.resolve(PROVIDER, model=DEFAULT_MODEL)
    if BASE_URL and BASE_URL != resolution.base_url:
        resolution = replace(
            resolution,
            provider=replace(resolution.provider, base_url=BASE_URL),
        )
    # THE "MISSING" SUBSTITUTION STAYS AT LLM_STRICT=0, DELIBERATELY.
    #
    # Passing the empty key instead would make a keyless chapter refuse at
    # construction with the flag OFF — which is the right end state and the wrong
    # release to do it in. Off must be today's behaviour exactly, or the
    # report-only release reports nothing and eighteen services change at once.
    #
    # Under LLM_STRICT the placeholder is what build_client refuses, and the
    # refusal names it.
    return llm_runtime.build_client(
        resolution, api_key=API_KEY or "MISSING", strict=strict_enabled()
    )


#: Hosts that are this machine. A base URL pointing at one of these reaches no
#: third party, so a provider served there needs no key to be usable — Ollama,
#: LM Studio, llama.cpp and vLLM are all configured this way.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _is_local(base_url: str) -> bool:
    """Whether ``base_url`` addresses this machine.

    Read off the URL, not resolved through DNS: the question is what the operator
    configured, and a name that happens to resolve to loopback today is not a
    promise about tomorrow.
    """
    from urllib.parse import urlparse

    host = (urlparse(base_url).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.endswith(".localhost")


def planner_enabled() -> bool:
    """Whether an LLM call can be made without contacting a third party the
    operator did not configure.

    Provider detection falls through to a default when no key is set, so an
    unconfigured chapter still resolves a real, remote ``base_url``. Calling it
    anyway sends the request — and whatever prompt text it carries — to that
    provider, which then rejects it. An operator who set no key has not chosen a
    provider and would not expect the traffic.

    So: enabled when a key is configured, or when the endpoint is on this machine
    (a local model needs no key). Otherwise the planner is off and callers serve
    their deterministic output instead of making the request.
    """
    return bool(API_KEY) or _is_local(BASE_URL)


# ── tiering ──────────────────────────────────────────────────────────────────
#
# ⚠️ CALL SITES NAME A TIER; THEY DO NOT NAME A MODEL. Every site used to read the
# one module-global ``DEFAULT_MODEL``, so a barber-facing 60-token reply and a
# planning call that must produce a tool call ran the same model — the expensive
# one, because the planner needed it. Measured on a driven 720-tick day, 360 of
# 486 daily calls cap output at 100 tokens or fewer.
#
# ⚠️ WHAT IS NOT TIERED, AND WHY IT IS A MEASUREMENT RATHER THAN A PREFERENCE.
# Sites that force ``tool_choice`` stay on the default. The committed probe found
# a model that honours a forced tool_choice 2 OF 5 TIMES; moving a planning call
# onto a fast tier could therefore produce sporadic empty plans that read as bad
# luck. ``planner_llm`` and ``surface_composer.compose`` are those sites and they
# stay deep. Everything tiered here forces no tool_choice at all — asserted, not
# assumed, in server/tests/test_llm_tiering.py.
#
# An operator's explicit ``LLM_MODEL`` still wins over every tier: they pinned a
# model, and a tier is this code's opinion about cost, not theirs about capability.

_EXPLICIT_MODEL = (
    os.environ.get("LLM_MODEL", "").strip() or os.environ.get("DEFAULT_LLM_MODEL", "").strip()
)


def _caps_lookup(model: str) -> Any:
    """Measured capabilities for ``model``; all-unknown when nothing measured it."""
    try:
        import llm_caps
    except ImportError:  # the server tree may run without the agent package
        return None
    return llm_caps.caps_for(model)


def tier_choice(tier: str) -> llm_runtime.TierChoice:
    """Resolve ``tier`` for this process's provider, honouring an explicit pin."""
    if _EXPLICIT_MODEL:
        return llm_runtime.TierChoice(
            model=_EXPLICIT_MODEL,
            tier=tier,
            requested_tier=tier,
            refused_reason="",
        )
    return llm_runtime.model_for_tier(PROVIDER, tier, caps_lookup=_caps_lookup)


def model_for(tier: str) -> str:
    """The model a call site of ``tier`` should use. The one call sites make."""
    return tier_choice(tier).model


# Named so a call site reads as a decision rather than a lookup.
FAST_MODEL = model_for(llm_runtime.TIER_FAST)
DEEP_MODEL = model_for(llm_runtime.TIER_DEEP)

if FAST_MODEL != DEFAULT_MODEL or DEEP_MODEL != DEFAULT_MODEL:
    _choice = tier_choice(llm_runtime.TIER_FAST)
    if _choice.refused_reason:
        print(f"[llm] fast tier DECLINED: {_choice.refused_reason}")
    else:
        print(f"[llm] tiers: fast={FAST_MODEL} balanced={DEFAULT_MODEL} deep={DEEP_MODEL}")
