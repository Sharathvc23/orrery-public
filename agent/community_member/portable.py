"""Cross-device portability — bundle the agent's full local state into
a single file the user can carry to a different machine, and restore it
there.

The wizard already exposes a thin ``export_agent`` that writes
``agent.json`` only. That's the identity tip of the iceberg — losing
everything below the line:

* the Ed25519 private key (the actual identity proof)
* private notes (``memory.json``)
* consent ledger (``consent.db`` — hash-chained, every approval +
  denial in agent history)
* learned habit posteriors (``habits.db``)
* graduated capabilities (``graduations.db``)

This module exports / imports the whole picture as one bundle so an
agent on machine A becomes the same agent on machine B with the same
trust score, the same learned approvals, the same private memory.

Bundle format v1 — single JSON, base64 for binary blobs:
    {
      "format_version": 1,
      "exported_at": "<ISO8601>",
      "agent_id": "...",
      "name": "...",
      "config": {<config.json minus private_key + api_key>},
      "public_key": "<base64>",
      "private_key": "<base64>",
      "agent_state": {<agent.json>},
      "memory": [<list of memory notes>],
      "consent_db": "<base64-of-sqlite-file>",
      "habits_db": "<base64-of-sqlite-file>",
      "graduations_db": "<base64-of-sqlite-file>"
    }

LLM api_key is intentionally NOT included — the user re-enters on the
new machine (~30s) and the key never lives in a plaintext-on-disk
copy outside their original encrypted config.

Security note: the bundle contains the Ed25519 private key. Anyone
with the bundle can act as this agent. Encrypt the bundle file
yourself (``gpg --symmetric``) before transferring; future versions
of this module may add built-in passphrase encryption.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from .config import CONFIG_DIR, Config

BUNDLE_FORMAT_VERSION = 1

console = Console()


def _read_b64(path: Path) -> str | None:
    """Read a binary file (SQLite, etc.) and return base64 of its bytes,
    or None if the file doesn't exist yet (fresh install)."""
    if not path.exists():
        return None
    return base64.b64encode(path.read_bytes()).decode("ascii")


def _write_b64(path: Path, b64: str | None) -> None:
    """Write a base64 blob back to disk. Skip if blob is None."""
    if not b64:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.b64decode(b64))
    path.chmod(0o600)


def build_bundle(config: Config) -> dict[str, Any]:
    """Read every state file under CONFIG_DIR into a single dict."""
    from . import keystore

    # Private key lives in the keystore, NOT in config.json.
    pk = keystore.load_private_key(config.agent_id) or ""

    # Strip the secrets that travel separately + the ones we
    # intentionally don't ship (api_key, etc.).
    config_dict = {
        "agent_id": config.agent_id,
        "name": config.name,
        "description": config.description,
        "skills": config.skills,
        "interests": config.interests,
        "chapter_url": config.chapter_url,
        "provider": config.provider,
        "model": config.model,
        "linkedin_url": config.linkedin_url,
        "public_key": config.public_key,
    }

    try:
        agent_state = config.load_agent_state()
    except Exception:
        agent_state = {}

    memory_file = CONFIG_DIR / "memory.json"
    memory: list[dict[str, Any]] = []
    if memory_file.exists():
        try:
            memory = json.loads(memory_file.read_text())
        except Exception:
            memory = []

    return {
        "format_version": BUNDLE_FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "agent_id": config.agent_id,
        "name": config.name,
        "config": config_dict,
        "public_key": config.public_key,
        "private_key": pk,  # base64-encoded Ed25519
        "agent_state": agent_state,
        "memory": memory,
        "consent_db": _read_b64(CONFIG_DIR / "consent.db"),
        "habits_db": _read_b64(CONFIG_DIR / "habits.db"),
        "graduations_db": _read_b64(CONFIG_DIR / "graduations.db"),
    }


def restore_bundle(bundle: dict[str, Any]) -> Config:
    """Restore an agent bundle into CONFIG_DIR. Returns the new Config."""
    if bundle.get("format_version") != BUNDLE_FORMAT_VERSION:
        raise ValueError(
            f"Unsupported bundle format_version "
            f"{bundle.get('format_version')!r} (this build expects "
            f"{BUNDLE_FORMAT_VERSION})"
        )

    from . import keystore

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    cfg_in = bundle.get("config") or {}
    config = Config()
    for k in (
        "agent_id",
        "name",
        "description",
        "skills",
        "interests",
        "chapter_url",
        "provider",
        "model",
        "linkedin_url",
        "public_key",
    ):
        if k in cfg_in:
            setattr(config, k, cfg_in[k])

    private_key_b64 = bundle.get("private_key", "")
    if private_key_b64:
        keystore.store_private_key(config.agent_id, private_key_b64)
        config.private_key = private_key_b64

    config.save()

    agent_state = bundle.get("agent_state") or {}
    if agent_state:
        config.save_agent_state(agent_state)

    memory = bundle.get("memory") or []
    if memory:
        memory_file = CONFIG_DIR / "memory.json"
        memory_file.write_text(json.dumps(memory, indent=2))
        memory_file.chmod(0o600)

    _write_b64(CONFIG_DIR / "consent.db", bundle.get("consent_db"))
    _write_b64(CONFIG_DIR / "habits.db", bundle.get("habits_db"))
    _write_b64(CONFIG_DIR / "graduations.db", bundle.get("graduations_db"))

    return config


def _cmd_export(args) -> int:
    """`community-member export [--output PATH]` — write the bundle."""
    config = Config.load()
    if not config.agent_id:
        console.print("[red]No agent configured to export.[/red] Run [bold]community-member[/bold] first.")
        return 1

    bundle = build_bundle(config)

    out_path: Path
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = Path.cwd() / f"community-member-{config.agent_id}-{ts}.json"

    out_path.write_text(json.dumps(bundle, indent=2))
    out_path.chmod(0o600)

    size_kb = out_path.stat().st_size / 1024
    console.print(
        Panel(
            f"[bold]Exported @{config.agent_id}[/bold]\n\n"
            f"  File: {out_path}\n"
            f"  Size: {size_kb:.1f} KB\n"
            f"  Permissions: 0600\n\n"
            f"  [yellow]This file contains your Ed25519 private key.[/yellow]\n"
            f"  Anyone with this file can act as @{config.agent_id}.\n"
            f"  Encrypt it before transferring (e.g. [bold]gpg --symmetric[/bold]).\n",
            border_style="green",
        )
    )
    return 0


def _cmd_import(args) -> int:
    """`community-member import <PATH>` — restore from a bundle."""
    src_path = Path(args.bundle_path).expanduser().resolve()
    if not src_path.exists():
        console.print(f"[red]File not found:[/red] {src_path}")
        return 1

    try:
        bundle = json.loads(src_path.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Could not parse bundle JSON:[/red] {e}")
        return 1

    existing = Config.load()
    if existing.agent_id and existing.agent_id != bundle.get("agent_id"):
        console.print(
            f"[yellow]Warning:[/yellow] this CONFIG_DIR currently holds "
            f"@{existing.agent_id}, importing will replace it with "
            f"@{bundle.get('agent_id')}. Use COMMUNITY_MEMBER_HOME to "
            f"keep them side-by-side."
        )
        if not args.yes:
            console.print("  Pass [bold]--yes[/bold] to confirm, or set COMMUNITY_MEMBER_HOME to a fresh path.")
            return 2

    try:
        config = restore_bundle(bundle)
    except ValueError as e:
        console.print(f"[red]Restore failed:[/red] {e}")
        return 1

    console.print(
        Panel(
            f"[bold]Imported @{config.agent_id}[/bold]\n\n"
            f"  Identity: {config.agent_id}\n"
            f"  Chapter: {config.chapter_url}\n"
            f"  Provider: {config.provider} / {config.model}\n"
            f"  Notes: {len(bundle.get('memory') or [])}\n"
            f"  Keys: restored to keystore\n"
            f"  Consent / habits / graduations DBs: restored\n\n"
            f"  [yellow]Next: set your LLM api_key[/yellow] (it does NOT travel\n"
            f"  in the bundle). Run [bold]community-member[/bold] to enter it,\n"
            f"  then this agent picks up exactly where you left off.\n",
            border_style="green",
        )
    )
    return 0


def register_subcommands(sub) -> None:
    """Wire ``export`` + ``import`` into the main CLI argparser.

    Called from cli.py::_build_parser.
    """
    p_export = sub.add_parser(
        "export",
        help="Export the current agent's full state to a portable bundle.",
        description=__doc__,
    )
    p_export.add_argument(
        "--output",
        "-o",
        help="Output path (default: ./community-member-<agent_id>-<ts>.json)",
    )
    p_export.set_defaults(func=_cmd_export)

    p_import = sub.add_parser(
        "import",
        help="Import an agent bundle from another machine.",
    )
    p_import.add_argument(
        "bundle_path",
        help="Path to the .json bundle to restore from.",
    )
    p_import.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation when overwriting an existing CONFIG_DIR.",
    )
    p_import.set_defaults(func=_cmd_import)
