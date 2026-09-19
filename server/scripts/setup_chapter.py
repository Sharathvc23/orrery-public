#!/usr/bin/env python3
"""
Chapter setup wizard — the 5-minute onboarding path for chapter operators.

Mirrors community-member's member wizard. Three paths:
  1. New chapter    — fresh setup; write .env, apply the schema, smoke test
  2. Reconfigure    — load existing .env, update fields, verify
  3. Import backup  — restore from a portable chapter-state JSON (future)

Produces a working `.env` in the repo root plus optional side effects:
  - tests the Postgres connection
  - smoke-tests the LLM key with a tiny completion
  - runs the OpenClaw demo harness after startup to prove end-to-end

No network writes without confirmation. Safe to re-run — idempotent.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

console = Console()

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"


# ═══════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════


def header(text: str) -> None:
    console.print()
    console.print(Panel(f"[bold]{text}[/bold]", border_style="bright_blue"))


def ok(text: str) -> None:
    console.print(f"  [green]✓[/green] {text}")


def warn(text: str) -> None:
    console.print(f"  [yellow]![/yellow] {text}")


def fail(text: str) -> None:
    console.print(f"  [red]✗[/red] {text}")


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env_file(path: Path, values: dict[str, str]) -> None:
    """Write the env file back in a consistent order with section comments."""
    sections = [
        ("Agent identity", ["AGENT_ID", "AGENT_NAME", "AGENT_DESCRIPTION", "AGENT_CAPABILITIES", "AGENT_FOCUS"]),
        ("Server", ["PORT", "PUBLIC_URL"]),
        ("Postgres", ["DATABASE_URL"]),
        (
            "LLM providers (at least one required)",
            ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY", "GROQ_API_KEY"],
        ),
        ("NEST + NANDA Index", ["REGISTRY_URL", "AUTO_REGISTER", "NANDA_INDEX_URL"]),
        ("Federation peers", ["KNOWN_CHAPTER_ENDPOINTS"]),
        ("Tuning", ["THINK_CYCLE_INTERVAL", "MAX_MEMBERS"]),
    ]
    lines: list[str] = []
    written_keys: set[str] = set()
    for section_name, keys in sections:
        lines.append(f"# {section_name}")
        for k in keys:
            if k in values:
                v = values[k]
                lines.append(f"{k}={v}")
                written_keys.add(k)
        lines.append("")
    # Preserve any unknown keys the wizard didn't manage
    extras = {k: v for k, v in values.items() if k not in written_keys}
    if extras:
        lines.append("# Other")
        for k, v in sorted(extras.items()):
            lines.append(f"{k}={v}")
    path.write_text("\n".join(lines).rstrip() + "\n")


def valid_agent_id(candidate: str) -> bool:
    """Agent IDs must be DNS-safe: lowercase letters, digits, hyphens."""
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{1,62}[a-z0-9]", candidate))


# ═══════════════════════════════════════════════════════════════
# Steps
# ═══════════════════════════════════════════════════════════════


def step_identity(env: dict[str, str]) -> None:
    header("Step 1 · Chapter identity")

    console.print("  Your org gets a unique ID used in NANDA AgentFacts.")
    console.print("  Format: lowercase letters, digits, hyphens. 3–64 chars.")
    console.print()

    while True:
        agent_id = Prompt.ask("  Chapter ID (e.g. acme-chapter)", default=env.get("AGENT_ID", "")).strip().lower()
        if valid_agent_id(agent_id):
            break
        fail(f"'{agent_id}' is not a valid chapter ID — use lowercase letters, digits, and hyphens.")

    default_name = env.get("AGENT_NAME") or agent_id.replace("-", " ").title()
    name = Prompt.ask("  Display name", default=default_name).strip()

    default_desc = env.get("AGENT_DESCRIPTION") or f"NANDA chapter for {name}"
    description = Prompt.ask("  One-line description", default=default_desc).strip()

    default_focus = env.get("AGENT_FOCUS") or "Community"
    focus = Prompt.ask("  Focus areas (comma-separated tags)", default=default_focus).strip()

    env["AGENT_ID"] = agent_id
    env["AGENT_NAME"] = name
    env["AGENT_DESCRIPTION"] = description
    env["AGENT_FOCUS"] = focus
    env["AGENT_CAPABILITIES"] = env.get("AGENT_CAPABILITIES") or "conversation,community-knowledge"
    ok(f"Chapter ID: [bold]{agent_id}[/bold]")


def step_postgres(env: dict[str, str]) -> None:
    header("Step 2 · Postgres")

    console.print("  The org stores its state in Postgres, accessed directly via DATABASE_URL.")
    console.print(
        "  `docker compose up` provisions one for you (schema from [bold]infra/init.sql[/bold]);"
    )
    console.print("  or point at any Postgres 15+ instance you run yourself.")
    console.print()

    url = Prompt.ask(
        "  DATABASE_URL (postgres://user:pass@host:5432/orrery)",
        default=env.get("DATABASE_URL", ""),
        password=True,
    ).strip()

    env["DATABASE_URL"] = url

    # Test connection with the same driver the runtime uses (pg_store → asyncpg).
    async def _probe() -> str:
        import asyncpg

        conn = await asyncpg.connect(url, timeout=10.0)
        try:
            await conn.fetchval("SELECT agent_id FROM agents LIMIT 1")
            return "ok"
        except asyncpg.UndefinedTableError:
            return "no-table"
        finally:
            await conn.close()

    try:
        import asyncio

        result = asyncio.run(_probe())
        if result == "ok":
            ok("Postgres reachable, `agents` table exists")
        else:
            warn("Postgres reachable but `agents` table is missing.")
            console.print("    → Apply the bundled schema:")
            console.print("    [dim]psql \"$DATABASE_URL\" -f infra/init.sql[/dim]")
    except Exception as e:
        fail(f"Couldn't reach Postgres: {e}")
        if not Confirm.ask("  Continue anyway?", default=False):
            sys.exit(1)


def step_llm(env: dict[str, str]) -> None:
    header("Step 3 · LLM provider")

    providers = [
        ("Anthropic Claude", "ANTHROPIC_API_KEY", "sk-ant-..."),
        ("OpenAI", "OPENAI_API_KEY", "sk-..."),
        ("xAI Grok", "XAI_API_KEY", "xai-..."),
        ("Groq", "GROQ_API_KEY", "gsk_..."),
    ]

    table = Table(show_header=False, pad_edge=False, box=None)
    for i, (name, _, _) in enumerate(providers, 1):
        table.add_row(f"  [{i}]", name)
    console.print(table)
    console.print()

    choice = IntPrompt.ask(
        "  Choose provider",
        choices=[str(i) for i in range(1, len(providers) + 1)],
        default=1,
    )
    provider_name, env_key, example = providers[choice - 1]
    key = Prompt.ask(f"  Paste your {provider_name} API key", default=env.get(env_key, ""), password=True).strip()

    if not key:
        fail("An LLM API key is required — the chapter uses it for think cycles.")
        sys.exit(1)

    env[env_key] = key
    ok(f"Configured {provider_name}")


def step_public_url(env: dict[str, str]) -> None:
    header("Step 4 · Public URL")

    console.print("  The org needs a public URL so members + peer orgs can reach it.")
    console.print("  Options: Railway, Fly.io, Render, self-host with ngrok, or a public IP.")
    console.print()

    default_url = env.get("PUBLIC_URL", "http://localhost:7000")
    url = Prompt.ask("  Public URL", default=default_url).strip().rstrip("/")

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    if url.startswith("http://localhost") or url.startswith("http://127"):
        warn("Using a localhost URL — NANDA Index / peer chapters won't be able to reach you.")
        console.print(
            "    → For Railway: run [dim]railway up -d[/dim] after this wizard, grab the URL, re-run this step."
        )

    env["PUBLIC_URL"] = url
    env["PORT"] = env.get("PORT", "7000")


def step_federation(env: dict[str, str]) -> None:
    header("Step 5 · Federation + registry")

    console.print("  Federation lets your org exchange knowledge with other orgs")
    console.print("  and lets your members discover people across the network.")
    console.print("  A registry is optional. Leave it empty and this org publishes")
    console.print("  nowhere and discovers peers only from the seed list below.")
    console.print()

    # No default: an empty answer means no registry. The old default here was a
    # public NANDA registry, so pressing Enter published the org to a directory
    # the operator never named.
    default_registry = env.get("REGISTRY_URL", "")
    registry = Prompt.ask("  Registry URL (empty = none)", default=default_registry).strip().rstrip("/")
    env["REGISTRY_URL"] = registry

    if Confirm.ask("  Also register on the NANDA Index (if URL is public)?", default=False):
        index_url = Prompt.ask(
            "  NANDA Index URL(s) — comma-separated",
            default=env.get("NANDA_INDEX_URL", ""),
        ).strip()
        env["NANDA_INDEX_URL"] = index_url
    else:
        env["NANDA_INDEX_URL"] = env.get("NANDA_INDEX_URL", "")

    if Confirm.ask("  Connect to existing peer chapters (federation seed)?", default=True):
        default_peers = env.get("KNOWN_CHAPTER_ENDPOINTS", "https://org.example.com")
        console.print()
        console.print(f"  [dim]Default seed: {default_peers}[/dim]")
        console.print("  [dim](The Bay Area org is the reference production deployment.)[/dim]")
        peers = Prompt.ask("  Peer endpoints (comma-separated, or leave default)", default=default_peers).strip()
        env["KNOWN_CHAPTER_ENDPOINTS"] = peers
    else:
        env["KNOWN_CHAPTER_ENDPOINTS"] = ""

    env["AUTO_REGISTER"] = env.get("AUTO_REGISTER", "true")


def step_tuning(env: dict[str, str]) -> None:
    header("Step 6 · Operational tuning")

    console.print("  Sensible defaults — only change if you know what you're doing.")
    console.print()

    env["THINK_CYCLE_INTERVAL"] = env.get("THINK_CYCLE_INTERVAL") or str(
        IntPrompt.ask("  Think cycle interval (seconds)", default=120)
    )
    env["MAX_MEMBERS"] = env.get("MAX_MEMBERS") or str(
        IntPrompt.ask("  Max members this chapter will admit", default=40)
    )


def step_write_and_register(env: dict[str, str]) -> None:
    header("Step 7 · Write config + register")

    console.print(f"  Writing [bold]{ENV_PATH}[/bold]")
    write_env_file(ENV_PATH, env)
    ok(".env saved")

    if not Confirm.ask("  Register on NEST now (POST /api/agents)?", default=True):
        console.print()
        warn("Skipped NEST registration. Run later: [dim]bash scripts/register.sh[/dim]")
        return

    payload = {
        "agent_id": env["AGENT_ID"],
        "name": env["AGENT_NAME"],
        "endpoint": env["PUBLIC_URL"],
        "facts_url": f"{env['PUBLIC_URL']}/agentfacts.json",
        "description": env.get("AGENT_DESCRIPTION", ""),
        "capabilities": [c.strip() for c in env.get("AGENT_CAPABILITIES", "").split(",") if c.strip()],
        "agent_type": "skill",
        "status": "running",
    }

    try:
        resp = httpx.post(f"{env['REGISTRY_URL']}/api/agents", json=payload, timeout=10.0)
        if resp.status_code < 300:
            ok(f"Registered on NEST ({resp.status_code})")
        else:
            warn(f"Registration returned {resp.status_code}: {resp.text[:120]}")
    except Exception as e:
        fail(f"Registration failed: {e}")


def step_verify(env: dict[str, str]) -> None:
    header("Step 8 · Verify the stack (optional)")

    if not Confirm.ask("  Start the chapter agent locally and run the OpenClaw demo?", default=False):
        return

    console.print("  [dim]This starts `python chapter_agent.py` in the background and runs the harness.[/dim]")
    console.print("  [dim]Press Ctrl-C to skip if it hangs.[/dim]")

    # Best-effort: start agent, wait a few seconds, run demo, kill agent
    try:
        proc = subprocess.Popen(
            [sys.executable, "chapter_agent.py"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, **env},
        )
        import time

        for _ in range(20):
            time.sleep(1)
            try:
                r = httpx.get(f"http://localhost:{env.get('PORT', '7000')}/health", timeout=2.0)
                if r.status_code == 200:
                    ok("Chapter agent is responding on /health")
                    break
            except Exception:  # noqa: S112 — polling /health while server boots; per-attempt errors are expected and noisy
                continue
        else:
            warn("Chapter agent didn't come up within 20s — check manually with `python chapter_agent.py`.")
            proc.kill()
            return

        demo_url = f"http://localhost:{env.get('PORT', '7000')}"
        result = subprocess.run(  # noqa: S603 — argv is fully literal; demo_url is locally constructed http://localhost
            [sys.executable, "scripts/openclaw_demo.py", "--chapter", demo_url],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if "DONE → ok" in result.stdout:
            ok("OpenClaw demo ran end-to-end — chapter is healthy")
        else:
            warn("Demo exited without final 'DONE → ok'. Last lines:")
            console.print(result.stdout[-400:])
    finally:
        try:
            proc.kill()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# Paths
# ═══════════════════════════════════════════════════════════════


def new_chapter_flow() -> None:
    env: dict[str, str] = {}
    step_identity(env)
    step_postgres(env)
    step_llm(env)
    step_public_url(env)
    step_federation(env)
    step_tuning(env)
    step_write_and_register(env)
    step_verify(env)
    final_recap(env)


def reconfigure_flow() -> None:
    env = parse_env_file(ENV_PATH)
    if not env:
        fail(f"No existing .env at {ENV_PATH} — use option 1 instead.")
        sys.exit(1)

    console.print(f"  Loaded existing config: [bold]{env.get('AGENT_ID', '?')}[/bold]")
    console.print()

    steps = {
        "1": ("Chapter identity", step_identity),
        "2": ("Postgres", step_postgres),
        "3": ("LLM provider", step_llm),
        "4": ("Public URL", step_public_url),
        "5": ("Federation", step_federation),
        "6": ("Tuning", step_tuning),
        "all": ("Re-run every step", None),
    }
    table = Table(show_header=False, pad_edge=False, box=None)
    for k, (label, _) in steps.items():
        table.add_row(f"  [{k}]", label)
    console.print(table)

    choice = Prompt.ask("  Which step to update?", choices=list(steps.keys()), default="all")

    if choice == "all":
        for _, fn in list(steps.values())[:-1]:
            fn(env)
    else:
        steps[choice][1](env)

    write_env_file(ENV_PATH, env)
    ok(".env updated")


def final_recap(env: dict[str, str]) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold]Your chapter is configured[/bold]\n\n"
            f"  ID:      {env.get('AGENT_ID')}\n"
            f"  Name:    {env.get('AGENT_NAME')}\n"
            f"  Public:  {env.get('PUBLIC_URL')}\n"
            f"  NEST:    {env.get('REGISTRY_URL')}\n\n"
            f"Next steps:\n"
            f"  [dim]python chapter_agent.py[/dim]        — start locally on port {env.get('PORT', '7000')}\n"
            f"  [dim]railway up -d[/dim]                  — deploy to Railway\n"
            f"  [dim]bash scripts/register.sh[/dim]       — re-register (if you skipped)\n"
            f"  Pair with [link][/link] for the web portal.",
            title="Done",
            border_style="green",
        )
    )


# ═══════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════


def main() -> None:
    console.print()
    console.print(
        Panel(
            "[bold]NANDA Chapter Setup Wizard[/bold]\n\n"
            "[dim]This wizard configures a new NANDA chapter, or reconfigures an existing one.\n"
            "It writes .env, tests your Postgres + LLM keys, and optionally registers with NEST.[/dim]",
            border_style="bright_blue",
        )
    )
    console.print()

    choices = {
        "1": "Set up a new chapter",
        "2": "Reconfigure an existing chapter",
    }
    table = Table(show_header=False, pad_edge=False, box=None)
    for k, label in choices.items():
        table.add_row(f"  [{k}]", label)
    console.print(table)
    console.print()

    default_choice = "2" if ENV_PATH.exists() else "1"
    choice = Prompt.ask("  Choose", choices=list(choices.keys()), default=default_choice)

    try:
        if choice == "1":
            new_chapter_flow()
        else:
            reconfigure_flow()
    except KeyboardInterrupt:
        console.print()
        fail("Wizard cancelled — no changes saved to .env.")
        sys.exit(130)


if __name__ == "__main__":
    main()
