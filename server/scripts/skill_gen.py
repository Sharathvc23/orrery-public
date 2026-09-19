#!/usr/bin/env python3
"""Skill-generator — agent-written OpenClaw skills from an OpenAPI spec.

Fetches an OpenAPI spec, asks the configured LLM (provider-agnostic via the
chapter's ``llm_config`` — anthropic / openai / xai / groq / ollama, BYO key)
to draft a skill manifest + helpers, sanitizes the output, and writes a
*candidate* to disk. Generation NEVER auto-publishes: candidates land in
``candidate-skills/`` with ``meta.json.approved_at = null`` until a human
approves them.

Usage:
    python scripts/skill_gen.py \\
        --spec-url https://api.github.com/openapi.json \\
        --description "GitHub issue creator for chapter members" \\
        --output-dir candidate-skills/

Output layout:
    candidate-skills/{slug}/
        SKILL.md              — generated skill manifest
        helpers/              — any helper scripts the LLM emitted
        meta.json             — generation metadata: timestamp, score,
                                approved_at, approved_by, spec_url
        eval_report.json      — if run through smoke eval

Approval → publish (never automatic):
    A generated skill is a candidate until a human approves it. Run
    ``scripts/approve_candidate.py <candidate-dir> --approved-by <name>`` to
    review-gate it: that CLI re-validates the manifest, stamps ``approved_at``
    + ``approved_by`` in meta.json, and moves the skill into the publish dir.

Tests: tests/test_skill_gen_scaffold.py (CLI / output layout / manifest /
approval-flag state) and tests/test_skill_gen_llm_wire.py (the LLM wiring,
mocked — no network or tokens in CI).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# skill_gen lives in server/scripts/; put server/ on sys.path so it can import
# the chapter's provider-agnostic ``llm_config`` when run as a standalone script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@dataclass
class GenerationMetadata:
    """Tracks provenance of a generated skill candidate."""

    slug: str
    spec_url: str
    description: str
    generated_at: int
    generator_version: str = "0.1.0"
    # Approval flow — None until approve_candidate.py flips it
    approved_at: int | None = None
    approved_by: str | None = None
    # Eval flow — None until smoke-eval runs
    eval_score: float | None = None
    eval_report_path: str | None = None
    # LLM accountability
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_tokens_used: int = 0
    # Errors during generation
    errors: list[str] = field(default_factory=list)


def slugify(description: str) -> str:
    """Turn a free-text description into a filesystem/ClawHub-safe slug.

    Rules: lowercase, ASCII, dashes only, no leading/trailing dash,
    max 48 chars.
    """
    s = description.lower().strip()
    # Replace non-alphanumeric with dashes
    s = re.sub(r"[^a-z0-9]+", "-", s)
    # Collapse runs of dashes
    s = re.sub(r"-+", "-", s)
    # Trim
    s = s.strip("-")
    # Length cap
    return s[:48] or "unnamed-skill"


def validate_manifest(manifest: dict) -> list[str]:
    """Return a list of validation errors (empty = valid).

    Checks SKILL.md frontmatter requirements against the shape declared in
    nanda-openclaw-skill/SKILL.md. Keep this pure so it can be run on
    LLM output before writing to disk.
    """
    errors: list[str] = []
    required = {"name", "version", "description", "author", "license"}
    missing = required - set(manifest.keys())
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")

    # Name must match slug pattern
    name = manifest.get("name", "")
    if name and not re.match(r"^[a-z][a-z0-9-]{0,47}$", name):
        errors.append(f"name {name!r} does not match ^[a-z][a-z0-9-]{{0,47}}$")

    # Version must be semver-ish
    version = manifest.get("version", "")
    if version and not re.match(r"^\d+\.\d+\.\d+(-[a-z0-9.]+)?$", version):
        errors.append(f"version {version!r} is not semver")

    # Capability allowlist — reject high-risk capabilities for OpenClaw
    # skill generation (policy: we never auto-generate shell/fs.any
    # capabilities; a human must add those by hand).
    caps = manifest.get("capabilities", [])
    if not isinstance(caps, list):
        errors.append("capabilities must be a list")
    else:
        banned = {"shell.exec", "net.arbitrary", "fs.any", "eval.code"}
        bad = [c for c in caps if c in banned]
        if bad:
            errors.append(f"cannot auto-generate skill with banned capabilities: {bad}")

    return errors


def write_candidate(output_dir: Path, meta: GenerationMetadata, skill_md: str, helpers: dict[str, str]) -> Path:
    """Write a generated skill candidate to disk.

    Layout:
        {output_dir}/{slug}/SKILL.md
        {output_dir}/{slug}/meta.json
        {output_dir}/{slug}/helpers/*.py   (if helpers is non-empty)

    Returns the slug directory path. Creates parent dirs as needed.
    Refuses to overwrite an existing candidate — must be deleted first.
    """
    out = output_dir / meta.slug
    if out.exists():
        raise FileExistsError(f"candidate already exists: {out}")
    out.mkdir(parents=True)

    (out / "SKILL.md").write_text(skill_md)
    (out / "meta.json").write_text(json.dumps(asdict(meta), indent=2))

    if helpers:
        helpers_dir = out / "helpers"
        helpers_dir.mkdir()
        for fname, content in helpers.items():
            if "/" in fname or fname.startswith("."):
                raise ValueError(f"unsafe helper filename: {fname!r}")
            (helpers_dir / fname).write_text(content)

    return out


SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "skill_gen" / "system.md"
DEFAULT_MAX_TOKENS = 8000
MAX_SPEC_BODY_CHARS = 150_000  # truncate OpenAPI spec if huge


def _load_system_prompt() -> str:
    if not SYSTEM_PROMPT_PATH.exists():
        raise RuntimeError(f"system prompt missing at {SYSTEM_PROMPT_PATH}")
    return SYSTEM_PROMPT_PATH.read_text()


def _fetch_openapi(spec_url: str, timeout: float = 15.0) -> str:
    """Fetch an OpenAPI spec. Does NOT parse — just gets the bytes.

    Returns the (possibly truncated) body as string. Raises RuntimeError
    if fetch fails.
    """
    try:
        import httpx
    except ImportError as e:
        raise RuntimeError(f"httpx required: {e}") from e
    try:
        resp = httpx.get(spec_url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"spec fetch failed: {type(e).__name__}: {e}") from e
    body = resp.text
    if len(body) > MAX_SPEC_BODY_CHARS:
        body = body[:MAX_SPEC_BODY_CHARS] + "\n\n...[truncated]"
    return body


def _extract_json_object(text: str) -> dict:
    """Extract a single JSON object from the LLM response.

    Handles the common case where the model wraps its output in ```json``
    fences or adds prose before/after. Raises on failure.
    """
    # Strip markdown code fences
    stripped = text.strip()
    if stripped.startswith("```"):
        # Find the first { and last }
        first = stripped.find("{")
        last = stripped.rfind("}")
        if first == -1 or last == -1 or last <= first:
            raise ValueError("no JSON object in fenced response")
        return json.loads(stripped[first : last + 1])
    # Try parsing whole string first
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        # Fall back to first-{ to last-} extraction
        first = stripped.find("{")
        last = stripped.rfind("}")
        if first == -1 or last == -1 or last <= first:
            raise
        return json.loads(stripped[first : last + 1])


def _call_llm(
    system: str,
    user_prompt: str,
    *,
    model: str = "",
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> tuple[str, int]:
    """Call the configured LLM through the provider-agnostic OpenAI-compatible
    client (``llm_config`` — anthropic / openai / xai / groq / ollama, selected
    by ``LLM_PROVIDER`` + the matching key). Returns (text, tokens_used)."""
    import llm_config

    client = llm_config.build_client()
    resp = client.chat.completions.create(
        model=model or llm_config.DEFAULT_MODEL,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
    )
    text = resp.choices[0].message.content or ""
    usage = getattr(resp, "usage", None)
    tokens = int(usage.prompt_tokens + usage.completion_tokens) if usage else 0
    return text, tokens


def generate_skill(
    spec_url: str,
    description: str,
    *,
    author: str = "anonymous",
    model: str = "",
) -> tuple[str, dict[str, str], GenerationMetadata]:
    """Core generation — fetches spec, calls LLM, validates output.

    Returns (skill_md_content, helper_files_dict, metadata).

    Raises RuntimeError for infrastructure failures (spec fetch,
    missing API key, malformed LLM output). Validation errors from the
    generated manifest are attached to metadata.errors — caller decides
    whether to still write_candidate.
    """
    import llm_config

    resolved_model = model or llm_config.DEFAULT_MODEL
    meta = GenerationMetadata(
        slug=slugify(description),
        spec_url=spec_url,
        description=description,
        generated_at=int(time.time()),
        llm_provider=llm_config.PROVIDER,
        llm_model=resolved_model,
    )

    # 1. Load system prompt
    system = _load_system_prompt()

    # 2. Fetch the OpenAPI spec
    try:
        spec_body = _fetch_openapi(spec_url)
    except Exception as e:
        meta.errors.append(f"spec_fetch: {e}")
        raise

    # 3. Build user prompt
    user_prompt = (
        f"OpenAPI spec URL: {spec_url}\n\n"
        f"OpenAPI spec (fetched, possibly truncated):\n```\n{spec_body}\n```\n\n"
        f"Description: {description}\n\n"
        f"Author: {author}\n\n"
        "Generate the skill now. Return ONLY the JSON object with skill_md, helpers, rationale. No prose before or after."
    )

    # 4. Call LLM
    try:
        text, tokens = _call_llm(system, user_prompt, model=resolved_model)
    except Exception as e:
        meta.errors.append(f"llm_call: {type(e).__name__}: {e}")
        raise RuntimeError(f"LLM call failed: {e}") from e
    meta.llm_tokens_used = tokens

    # 5. Parse structured output
    try:
        parsed = _extract_json_object(text)
    except Exception as e:
        meta.errors.append(f"parse: {type(e).__name__}: {e}")
        raise RuntimeError(f"LLM output was not valid JSON: {e}\n\nRaw: {text[:500]}") from e

    skill_md = parsed.get("skill_md")
    helpers = parsed.get("helpers") or {}
    if not isinstance(skill_md, str) or not skill_md.startswith("---"):
        meta.errors.append("parse: skill_md missing or doesn't start with frontmatter")
        raise RuntimeError("LLM did not return a valid skill_md")
    if not isinstance(helpers, dict):
        meta.errors.append("parse: helpers is not a dict")
        helpers = {}

    # 6. Sanitize helper filenames + contents
    sanitized_helpers: dict[str, str] = {}
    for fname, content in helpers.items():
        if not isinstance(fname, str) or not isinstance(content, str):
            continue
        if "/" in fname or fname.startswith("."):
            meta.errors.append(f"helpers: unsafe filename {fname!r} — dropped")
            continue
        if len(content) > 32 * 1024:  # 32 KiB per helper cap
            meta.errors.append(f"helpers: {fname} >32KiB — dropped")
            continue
        sanitized_helpers[fname] = content

    # 7. Validate manifest — attach errors but don't raise
    fm = _parse_frontmatter(skill_md)
    validation_errors = validate_manifest(fm)
    if validation_errors:
        meta.errors.extend(validation_errors)
        # Caller decides whether to write a candidate with errors attached

    return skill_md, sanitized_helpers, meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--spec-url", required=True, help="OpenAPI spec URL to generate against")
    p.add_argument("--description", required=True, help="One-line description of the skill")
    p.add_argument("--author", default="anonymous", help="Author name / github handle")
    p.add_argument("--model", default="", help="override the LLM model (default: the configured provider's model)")
    p.add_argument("--output-dir", default="candidate-skills", help="Where to write the candidate")
    args = p.parse_args(argv)

    try:
        skill_md, helpers, meta = generate_skill(args.spec_url, args.description, author=args.author, model=args.model)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if meta.errors:
        print(f"WARN: generation produced errors: {meta.errors}", file=sys.stderr)
        # Don't refuse — a human reviewer can still look at the output

    out = write_candidate(Path(args.output_dir), meta, skill_md, helpers)
    print(f"Wrote candidate: {out}")
    print(f"Tokens used: {meta.llm_tokens_used}")
    if meta.errors:
        print(f"Errors logged to meta.json: {meta.errors}")
    print("Review the skill, then decide whether to publish.")
    return 0 if not meta.errors else 4


def _parse_frontmatter(md: str) -> dict:
    """Minimal YAML-ish frontmatter parser. Matches `---`-delimited block
    at the top and parses `key: value` pairs. Not a full YAML parser —
    sufficient for the shape skill manifests take.
    """
    if not md.startswith("---"):
        return {}
    try:
        end = md.index("\n---\n", 4)
    except ValueError:
        return {}
    frontmatter = md[4:end]
    out: dict = {}
    current_list_key: str | None = None
    for raw_line in frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            continue
        if current_list_key and line.startswith("  - "):
            out.setdefault(current_list_key, []).append(line[4:].strip())
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                # Possibly a list start
                current_list_key = key
                out[key] = []
            else:
                current_list_key = None
                out[key] = val
    return out


if __name__ == "__main__":
    raise SystemExit(main())
