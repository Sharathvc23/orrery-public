#!/usr/bin/env python3
"""Measure what an OpenAI-compatible endpoint actually does with the request
shapes shipped code depends on.

WHY THIS EXISTS. Every provider is reached through the OpenAI-compatible client
(``from openai import OpenAI`` + a ``base_url``) — one client across
anthropic/openai/xai/groq/ollama. That is deliberate. But "OpenAI-compatible"
is a claim about the request shape, not about the behaviour, and two of the
shapes this codebase relies on are honoured by some endpoints and quietly
dropped by others.

  FORCED ``tool_choice``  — ``planner_llm.plan_from_llm`` and
      ``surface_composer.compose`` both send
      ``tool_choice={"type": "function", "function": {"name": ...}}`` and read
      ``message.tool_calls``. A provider that IGNORES the constraint returns
      HTTP 200 with free text and no tool call. ``plan_from_llm`` turns that
      into an empty Plan — no exception, no log line above INFO — and the agent
      loops at its normal rate producing nothing. Nothing in the stack
      distinguishes "the model had no work to propose" from "the model never
      saw the constraint".

  ``response_format={"type": "json_object"}`` — ``agent/community_member/server.py``
      (two call sites) and ``server/digest.py`` parse the reply as JSON. An
      endpoint that drops the field returns prose, and the parse fails.

Both of those are silent at the call site, which is why they need measuring
rather than asserting.

It also keeps the endpoint questions the file was written for: whether a
non-default ``temperature`` is rejected, and whether a tight ``max_tokens``
budget leaves room for any text (``think_cycle.py`` budgets 50/60/80 tokens and
the call sites swallow an empty result).

REPEATED TRIALS, AND WHY THE COUNT IS THE POINT. Each capability case runs
``--trials`` times (default 5) and a capability is recorded ``supported`` only
if EVERY trial honoured it. One call cannot classify an endpoint: a model
measured here honoured forced ``tool_choice`` on two consecutive calls and
dropped it on the third, from an identical request. A single-shot probe would
have reported ``supported`` two times in three. An intermittent failure is
worse than a consistent one, because the consistent one gets noticed on the
first run.

THE FOUR VERDICTS ARE NOT A BOOLEAN, and the distinction is load-bearing:

  ``supported``  every trial honoured the constraint.
  ``ignored``    the endpoint answered 200 and did not honour it. The dangerous
                 one: no error to branch on, and the caller degrades silently.
  ``rejected``   the endpoint refused with a 4xx. Loud, and therefore safe — a
                 caller finds out immediately.
  ``unknown``    the endpoint could not be reached, or the model did not answer
                 the control case. Never a guess.

``partial`` counts as ``ignored``: an endpoint that honours a constraint most
of the time cannot be relied on to honour it, and the trial counts are kept in
the record so the difference stays visible.

CREDENTIALS — environment only::

    export ANTHROPIC_API_KEY=sk-ant-...     # or LLM_API_KEY

Never pass a key as a command-line argument (argv is world-readable). This
script prints no key material: results carry status codes, finish reasons and
text lengths only. A local provider needs no key at all — ``--provider ollama``
talks to a loopback endpoint and sends a placeholder, which is what makes this
runnable in CI without a hosted account.

USAGE::

    scripts/probe_llm_compat.py --provider ollama --models llama3.1:8b
    scripts/probe_llm_compat.py --provider ollama --discover \
        --out docs/integrations/llm-compat-probe.json
    scripts/probe_llm_compat.py --provider anthropic         # needs a key

Each hosted case costs real tokens: ``--trials`` calls per capability case, at
most ``--max-tokens`` output each.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# ── Providers ────────────────────────────────────────────────────────
#
# A provider is a base_url plus whether a real key is required. Nothing here
# has a default that reaches a hosted endpoint: --provider must be stated, and
# the models must be stated or discovered.

#: provider name -> (base_url, key_required)
PROVIDERS: dict[str, tuple[str, bool]] = {
    "anthropic": ("https://api.anthropic.com/v1/", True),
    "openai": ("https://api.openai.com/v1/", True),
    "ollama": ("http://localhost:11434/v1/", False),
}

#: Env vars consulted, in order. Read from the environment ONLY.
KEY_ENVS = ("ANTHROPIC_API_KEY", "LLM_API_KEY")

#: Sent as the key when a provider does not require one. The OpenAI client
#: refuses to construct without something; a local endpoint ignores the value.
PLACEHOLDER_KEY = "not-a-secret-local-endpoint"

#: The tool the forced-tool_choice case forces. Deliberately shaped like
#: planner_llm.PROPOSE_ACTIONS_SCHEMA — a named function with a required array
#: argument — so the measurement matches the request shape shipped code sends.
PROBE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "propose_actions",
        "description": "Propose the actions to take.",
        "parameters": {
            "type": "object",
            "properties": {
                "actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Short action descriptions.",
                }
            },
            "required": ["actions"],
        },
    },
}

FORCED_TOOL_NAME = "propose_actions"

SUPPORTED = "supported"
IGNORED = "ignored"
REJECTED = "rejected"
UNKNOWN = "unknown"


def resolve_key(provider: str) -> str | None:
    """The API key from the environment, or None.

    Unset and empty are the same. A provider that does not require a key gets
    the placeholder rather than None, so a local run never depends on a
    hosted account being configured.
    """
    for name in KEY_ENVS:
        raw = os.environ.get(name)
        if raw and raw.strip():
            return raw.strip()
    _, key_required = PROVIDERS.get(provider, ("", True))
    return None if key_required else PLACEHOLDER_KEY


@dataclass
class CaseResult:
    """One probe call. Carries no key material and no request headers."""

    model: str
    case: str
    question: str
    trial: int = 0
    ok: bool | None = None
    status: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    finish_reason: str | None = None
    content_chars: int | None = None
    completion_tokens: int | None = None
    reasoning_tokens: int | None = None
    tool_call_count: int | None = None
    tool_call_name: str | None = None
    tool_args_parse_ok: bool | None = None
    content_parses_as_json: bool | None = None
    note: str = ""
    raw_usage: dict[str, Any] = field(default_factory=dict)


def _call(
    client: Any,
    *,
    model: str,
    max_tokens: int,
    messages: list[dict[str, str]],
    **extra: Any,
) -> CaseResult:
    """One chat.completions call, with the outcome flattened into a CaseResult."""
    result = CaseResult(model=model, case="", question="")
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            **extra,
        )
    except Exception as exc:  # noqa: BLE001 — the failure IS the measurement
        result.ok = False
        result.error_type = type(exc).__name__
        result.status = getattr(exc, "status_code", None)
        # Keep the provider's own message: it is the evidence. It contains no key.
        result.error_message = str(exc)[:600]
        return result

    result.ok = True
    result.status = 200
    choices = getattr(resp, "choices", None) or []
    choice = choices[0] if choices else None
    result.finish_reason = getattr(choice, "finish_reason", None) if choice else None
    message = getattr(choice, "message", None) if choice else None
    content = (getattr(message, "content", None) or "") if message else ""
    result.content_chars = len(content.strip())
    # Recorded on every case, not only the json_object one: a provider that
    # returns JSON when it was not asked to is as much a fact as one that
    # returns prose when it was.
    stripped = content.strip()
    if stripped:
        try:
            json.loads(stripped)
            result.content_parses_as_json = True
        except Exception:  # noqa: BLE001 — not-JSON is the measurement
            result.content_parses_as_json = False
    else:
        result.content_parses_as_json = False

    tool_calls = (getattr(message, "tool_calls", None) or []) if message else []
    result.tool_call_count = len(tool_calls)
    if tool_calls:
        fn = getattr(tool_calls[0], "function", None)
        result.tool_call_name = getattr(fn, "name", None)
        raw_args = getattr(fn, "arguments", None) or ""
        try:
            json.loads(raw_args)
            result.tool_args_parse_ok = True
        except Exception:  # noqa: BLE001 — an unparseable argument blob is a result
            result.tool_args_parse_ok = False

    usage = getattr(resp, "usage", None)
    if usage is not None:
        result.completion_tokens = getattr(usage, "completion_tokens", None)
        details = getattr(usage, "completion_tokens_details", None)
        if details is not None:
            result.reasoning_tokens = getattr(details, "reasoning_tokens", None)
        try:
            result.raw_usage = usage.model_dump()
        except Exception:  # noqa: BLE001 — usage shape varies by provider
            result.raw_usage = {}
    return result


def probe_model(
    client: Any,
    model: str,
    *,
    tight_max_tokens: int,
    trials: int,
) -> list[CaseResult]:
    """Every case, for one model. Capability cases repeat ``trials`` times."""
    cases: list[CaseResult] = []
    sea = [{"role": "user", "content": "Reply with one short sentence about the sea."}]

    # Control: no special params. If this fails, nothing else for this model is
    # interpretable, and every capability lands on 'unknown' rather than a
    # verdict derived from an endpoint that was simply down.
    r = _call(client, model=model, max_tokens=256, messages=sea)
    r.case, r.question = "baseline", "Does a plain call succeed at all?"
    r.note = (
        "control — if this fails, every other case for this model is uninterpretable"
    )
    cases.append(r)

    r = _call(client, model=model, max_tokens=256, messages=sea, temperature=0.5)
    r.case, r.question = (
        "temperature_non_default",
        "Is a non-default temperature rejected?",
    )
    r.note = "chronicle.py sets 0.5, digest.py 0.4, llm_client.py defaults to 0.3"
    cases.append(r)

    # Distinguishes a value-based rule from a parameter-based one: if 1.0 (the
    # documented default) passes while 0.5 400s, a call site may keep passing
    # the parameter.
    r = _call(client, model=model, max_tokens=256, messages=sea, temperature=1.0)
    r.case, r.question = (
        "temperature_default_value",
        "Is temperature=1.0 (the default) accepted?",
    )
    r.note = "distinguishes a value-based rule from a parameter-based one"
    cases.append(r)

    r = _call(client, model=model, max_tokens=tight_max_tokens, messages=sea)
    r.case, r.question = (
        "tight_budget",
        f"Under max_tokens={tight_max_tokens}, does usable text come back?",
    )
    r.note = (
        "mirrors think_cycle.py's 50/60/80-token budgets; content_chars==0 with "
        "finish_reason=='length' means thinking consumed the budget"
    )
    cases.append(r)

    # ── forced tool_choice ──
    # The shape planner_llm.plan_from_llm and surface_composer.compose send.
    # Repeated, because the failure observed in practice is intermittent.
    for trial in range(1, trials + 1):
        r = _call(
            client,
            model=model,
            max_tokens=300,
            messages=[
                {
                    "role": "system",
                    "content": "You propose actions. Answer in English.",
                },
                {"role": "user", "content": "Greet two new members."},
            ],
            tools=[PROBE_TOOL],
            tool_choice={"type": "function", "function": {"name": FORCED_TOOL_NAME}},
        )
        r.case, r.question = (
            "forced_tool_choice",
            "Is a forced tool_choice honoured on every attempt?",
        )
        r.trial = trial
        r.note = (
            "planner_llm.py and surface_composer.py force this; a 200 with no "
            "tool call yields an empty Plan and a full-rate zero-output loop"
        )
        cases.append(r)

    # ── response_format json_object ──
    for trial in range(1, trials + 1):
        r = _call(
            client,
            model=model,
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Return a JSON object with a key 'sea' whose value is one "
                        "short sentence."
                    ),
                }
            ],
            response_format={"type": "json_object"},
        )
        r.case, r.question = (
            "json_object_response_format",
            "Does response_format=json_object yield parseable JSON every time?",
        )
        r.trial = trial
        r.note = (
            "agent server.py (two sites) and server/digest.py parse the reply as JSON"
        )
        cases.append(r)

    return cases


def _classify(
    attempts: list[CaseResult],
    honoured: list[bool],
    *,
    baseline_ok: bool,
) -> tuple[str, dict[str, Any]]:
    """One capability's verdict, plus the counts it was derived from.

    Conservative by construction: ``supported`` requires every attempt to have
    honoured the constraint. Anything short of that is ``ignored`` — an
    endpoint that honours a constraint four times in five cannot be relied on
    to honour it, and the counts stay in the record so the shape of the failure
    is not lost behind the label.
    """
    detail: dict[str, Any] = {
        "trials": len(attempts),
        "honoured": sum(1 for h in honoured if h),
    }
    if not attempts:
        return UNKNOWN, detail
    if not baseline_ok:
        detail["reason"] = "baseline call failed; capability not interpretable"
        return UNKNOWN, detail

    refusals = [a for a in attempts if a.ok is False]
    if refusals:
        # A 4xx is the endpoint saying no. Record its own words: that message is
        # what tells an operator whether the model, the endpoint or the request
        # was the problem.
        first = refusals[0]
        detail["status"] = first.status
        detail["error_type"] = first.error_type
        detail["error_message"] = first.error_message
        return REJECTED, detail

    if all(honoured):
        return SUPPORTED, detail
    detail["reason"] = (
        "answered 200 without honouring the constraint on "
        f"{detail['trials'] - detail['honoured']} of {detail['trials']} attempts"
    )
    return IGNORED, detail


def interpret(results: list[CaseResult]) -> dict[str, dict[str, Any]]:
    """Raw cases -> one caps record per model.

    Nothing is inferred from a case that did not run: an absent case leaves its
    capability at ``unknown`` rather than defaulting to supported.
    """
    models: list[str] = []
    for r in results:
        if r.model not in models:
            models.append(r.model)

    out: dict[str, dict[str, Any]] = {}
    for model in models:
        mine = [r for r in results if r.model == model]
        baseline = next((r for r in mine if r.case == "baseline"), None)
        baseline_ok = bool(baseline and baseline.ok)

        forced = [r for r in mine if r.case == "forced_tool_choice"]
        forced_honoured = [
            bool(r.ok and r.tool_call_count and r.tool_call_name == FORCED_TOOL_NAME)
            for r in forced
        ]
        forced_verdict, forced_detail = _classify(
            forced, forced_honoured, baseline_ok=baseline_ok
        )

        jsonmode = [r for r in mine if r.case == "json_object_response_format"]
        json_honoured = [bool(r.ok and r.content_parses_as_json) for r in jsonmode]
        json_verdict, json_detail = _classify(
            jsonmode, json_honoured, baseline_ok=baseline_ok
        )

        temp_non_default = next(
            (r for r in mine if r.case == "temperature_non_default"), None
        )
        temp_default = next(
            (r for r in mine if r.case == "temperature_default_value"), None
        )
        tight = next((r for r in mine if r.case == "tight_budget"), None)

        def _temp(r: CaseResult | None) -> str:
            if r is None or r.ok is None:
                return UNKNOWN
            return "accepted" if r.ok else "rejected"

        out[model] = {
            "baseline_ok": baseline_ok,
            "caps": {
                "forced_tool_choice": forced_verdict,
                "json_object_response_format": json_verdict,
                "temperature_non_default": _temp(temp_non_default),
                "temperature_default_value": _temp(temp_default),
                "tight_budget_returns_text": (
                    bool(tight.content_chars) if (tight and tight.ok) else UNKNOWN
                ),
            },
            "evidence": {
                "forced_tool_choice": forced_detail,
                "json_object_response_format": json_detail,
                "reasoning_tokens_reported": (
                    tight.reasoning_tokens
                    if (tight and tight.reasoning_tokens is not None)
                    else "absent"
                ),
            },
        }
    return out


def discover_models(client: Any) -> list[str]:
    """Model ids the endpoint itself advertises. Empty on any failure."""
    try:
        listing = client.models.list()
    except Exception as exc:  # noqa: BLE001 — discovery is best-effort
        print(f"model discovery failed: {type(exc).__name__}", file=sys.stderr)
        return []
    ids: list[str] = []
    for item in getattr(listing, "data", None) or []:
        model_id = getattr(item, "id", None)
        if model_id:
            ids.append(str(model_id))
    return sorted(ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure what an OpenAI-compatible endpoint does with the "
        "request shapes shipped code depends on.",
        epilog="Credentials come from ANTHROPIC_API_KEY / LLM_API_KEY only — never argv.",
    )
    parser.add_argument(
        "--provider",
        default="ollama",
        choices=sorted(PROVIDERS),
        help="which endpoint to measure (default: ollama, which needs no key)",
    )
    parser.add_argument(
        "--base-url", help="override the provider's base_url (for a local shim)"
    )
    parser.add_argument("--models", nargs="+", help="model ids to probe")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="probe every model the endpoint advertises",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=5,
        help="attempts per capability case; a capability is 'supported' only if "
        "every attempt honours it (default 5)",
    )
    parser.add_argument(
        "--tight-max-tokens",
        type=int,
        default=50,
        help="the budget think_cycle.py uses at its tightest (default 50)",
    )
    parser.add_argument("--out", help="write JSON results here (default: stdout only)")
    args = parser.parse_args(argv)

    base_url = args.base_url or PROVIDERS[args.provider][0]
    key = resolve_key(args.provider)
    if key is None:
        print(
            f"SKIP: provider '{args.provider}' needs a key and none is set "
            f"({' or '.join(KEY_ENVS)}).\nNo request was made. This is a clean "
            "skip, not a failure.",
            file=sys.stderr,
        )
        return 0

    try:
        from openai import OpenAI
    except ImportError:
        print("SKIP: the `openai` package is not installed.", file=sys.stderr)
        return 0

    client = OpenAI(api_key=key, base_url=base_url)

    models = list(args.models or [])
    if args.discover or not models:
        discovered = discover_models(client)
        if not discovered:
            print(
                "SKIP: no models given and none discovered at "
                f"{base_url} — is the endpoint running?",
                file=sys.stderr,
            )
            return 0
        models = discovered if args.discover else models or discovered

    results: list[CaseResult] = []
    for model in models:
        print(f"probing {model} ...", file=sys.stderr)
        results.extend(
            probe_model(
                client,
                model,
                tight_max_tokens=args.tight_max_tokens,
                trials=args.trials,
            )
        )

    verdicts = interpret(results)
    payload = {
        "schema": "llm-compat-probe/1",
        "provider": args.provider,
        "base_url": base_url,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trials": args.trials,
        "tight_max_tokens": args.tight_max_tokens,
        "models": verdicts,
        "cases": [asdict(r) for r in results],
    }

    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nwrote {args.out}", file=sys.stderr)

    print("\n── caps ──", file=sys.stderr)
    for model, entry in sorted(verdicts.items()):
        print(f"  {model}:", file=sys.stderr)
        for name, value in entry["caps"].items():
            print(f"      {name}: {value}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
