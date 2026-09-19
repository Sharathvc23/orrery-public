"""``community-member admin`` CLI subcommand — sovereign admin ops.

Lets a sovereign member with ``chapter_role='admin'`` perform admin
actions against their chapter from the local SDK, signing each request
with their Ed25519 key. Hits the chapter's ``/admin/api/*`` endpoints
which support the dual-path auth (did:key signed-by-admin OR bearer
break-glass).

Subcommands:

  community-member admin status
      GET /admin/api/status  — chapter id, member count, federation peers.

  community-member admin members [--limit N]
      GET /admin/api/members — paginated member list with roles.

  community-member admin set-role <agent_id> <role>
      POST /admin/api/members/<id>/role  — change a member's chapter_role.
      Role must be one of: member | advisor | mentor | leader | admin.
      Refuses to demote the last admin via the signed path (per E2); use the
      browser /admin/ UI with bearer + force=true if you genuinely need to
      break-glass yourself out.

  community-member admin remove <agent_id>
      DELETE /admin/api/members/<id> — hard-remove from registry.

  community-member admin revoke <agent_id>
      POST /admin/api/keys/revoke/<id> — clear the member's Ed25519
      pubkey (member re-registers via TOFU on next signed request).

All subcommands:

  - Sign with the SDK's stored Ed25519 key (loaded by ``auth.load_keys``
    at SDK startup).
  - Read the chapter URL from ``config.load_config().chapter_url``.
  - Return exit code 0 on success, non-zero on HTTP error or auth
    rejection. Failures print the chapter's error message to stderr.

Discipline preserved:

  - This module is downstream of the chapter's admin primitive
 — it consumes the existing ``/admin/api/*``
    endpoints without modifying them.
  - No bearer-token surface exposed in this CLI. The bearer is for
    bootstrap + break-glass; sovereign admins should always use the
    did:key path (which this CLI exclusively uses).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import httpx

from . import auth, config


def register_subcommands(sub: argparse._SubParsersAction) -> None:
    """Register the ``admin`` subcommand on the SDK's argparse tree.

    Called from cli.py's ``_build_parser`` alongside other module
    subcommands (e.g. ``portable.register_subcommands``).
    """
    p_admin = sub.add_parser(
        "admin",
        help="Sovereign admin ops against your org (requires chapter_role='admin').",
    )
    admin_sub = p_admin.add_subparsers(dest="admin_command", metavar="ACTION")

    p_status = admin_sub.add_parser(
        "status",
        help="Show org status — id, member count, federation peers.",
    )
    p_status.set_defaults(func=lambda args: _cmd_status())

    p_members = admin_sub.add_parser(
        "members",
        help="List members of your org.",
    )
    p_members.add_argument("--limit", type=int, default=100, help="Max members to list (default 100).")
    p_members.set_defaults(func=lambda args: _cmd_members(args.limit))

    p_set_role = admin_sub.add_parser(
        "set-role",
        help="Change a member's chapter_role.",
    )
    p_set_role.add_argument("agent_id", help="Member's agent_id.")
    p_set_role.add_argument(
        "role",
        choices=["member", "advisor", "mentor", "leader", "admin"],
        help="New chapter_role to assign.",
    )
    p_set_role.set_defaults(func=lambda args: _cmd_set_role(args.agent_id, args.role))

    p_remove = admin_sub.add_parser(
        "remove",
        help="Hard-remove a member from the org registry.",
    )
    p_remove.add_argument("agent_id", help="Member's agent_id.")
    p_remove.set_defaults(func=lambda args: _cmd_remove(args.agent_id))

    p_revoke = admin_sub.add_parser(
        "revoke",
        help="Revoke a member's Ed25519 key (forces TOFU re-registration).",
    )
    p_revoke.add_argument("agent_id", help="Member's agent_id.")
    p_revoke.set_defaults(func=lambda args: _cmd_revoke(args.agent_id))


# ── Internal: HTTP helpers ──────────────────────────────────────────


def _resolve_chapter_and_agent() -> tuple[str | None, str | None]:
    """Resolve (chapter_url, agent_id) from SDK config. Returns
    (None, None) on any error — caller surfaces a clean error message."""
    try:
        cfg = config.Config.load()
    except Exception as e:
        print(f"error: could not load SDK config: {e}", file=sys.stderr)
        return None, None

    if not cfg.chapter_url:
        print(
            "error: no chapter_url configured. Run `community-member init` first to register with an org.",
            file=sys.stderr,
        )
        return None, None
    if not cfg.agent_id:
        print(
            "error: no agent_id configured. Run `community-member init` first.",
            file=sys.stderr,
        )
        return None, None

    # Ensure auth module has loaded keys for signing
    try:
        if not getattr(auth, "is_loaded", lambda: True)():
            auth.load_keys()
    except Exception as e:
        print(f"error: could not load SDK signing keys: {e}", file=sys.stderr)
        return None, None

    return cfg.chapter_url.rstrip("/"), cfg.agent_id


def _signed_request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | str]:
    """Make a signed HTTP request to the chapter. Returns
    ``(status_code, parsed_body_or_text)``. status=0 indicates
    pre-flight failure (config / network); caller surfaces."""
    chapter, agent_id = _resolve_chapter_and_agent()
    if not chapter or not agent_id:
        return 0, "config missing"

    body_str = json.dumps(body or {}, separators=(",", ":")) if body is not None else ""
    headers = auth.sign_request_body(
        body=body_str,
        agent_id=agent_id,
        method=method,
        url_path=path,
    )
    headers["Content-Type"] = "application/json"

    url = chapter + path
    try:
        with httpx.Client(timeout=20.0) as client:
            if method == "GET":
                r = client.get(url, headers=headers)
            elif method == "DELETE":
                r = client.delete(url, headers=headers)
            else:
                r = client.request(method, url, headers=headers, content=body_str)
    except httpx.HTTPError as e:
        print(f"error: HTTP request failed: {e}", file=sys.stderr)
        return 0, str(e)

    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text


def _surface_error(status: int, body: Any) -> int:
    """Print a useful error message for a non-2xx response. Returns
    exit code for the CLI."""
    if status == 0:
        return 2  # Already printed a config / network error
    if isinstance(body, dict):
        err = body.get("error", "")
        hint = body.get("hint", "")
        remediation = body.get("remediation", "")
        print(f"{status} — {err or body}", file=sys.stderr)
        if hint:
            print(f"      hint: {hint}", file=sys.stderr)
        if remediation:
            print(f"      remediation: {remediation}", file=sys.stderr)
    else:
        print(f"{status} — {body}", file=sys.stderr)
    return 1


# ── Subcommand handlers ─────────────────────────────────────────────


def _cmd_status() -> int:
    status, body = _signed_request("GET", "/admin/api/status")
    if status == 200 and isinstance(body, dict):
        print(json.dumps(body, indent=2))
        return 0
    return _surface_error(status, body)


def _cmd_members(limit: int) -> int:
    limit = max(1, min(500, int(limit)))
    status, body = _signed_request("GET", f"/admin/api/members?limit={limit}")
    if status != 200 or not isinstance(body, dict):
        return _surface_error(status, body)
    members = body.get("members", [])
    total = body.get("total", len(members))
    print(f"{total} members ({len(members)} shown)")
    print(f"{'agent_id':<30} {'name':<30} skills")
    print("-" * 90)
    for m in members:
        skills = ", ".join((m.get("skills") or [])[:4])
        agent_id = (m.get("agent_id") or "")[:30]
        name = (m.get("name") or "")[:30]
        print(f"{agent_id:<30} {name:<30} {skills[:30]}")
    return 0


def _cmd_set_role(agent_id: str, role: str) -> int:
    status, body = _signed_request(
        "POST",
        f"/admin/api/members/{agent_id}/role",
        body={"role": role},
    )
    if status == 200 and isinstance(body, dict):
        print(f"OK — @{agent_id} → chapter_role={body.get('chapter_role', role)}")
        return 0
    return _surface_error(status, body)


def _cmd_remove(agent_id: str) -> int:
    confirm = input(f"Remove @{agent_id}? This is irreversible. Type 'yes' to confirm: ").strip()
    if confirm != "yes":
        print("aborted")
        return 1
    status, body = _signed_request("DELETE", f"/admin/api/members/{agent_id}")
    if status == 200 and isinstance(body, dict):
        print(f"OK — @{body.get('removed', agent_id)} removed")
        return 0
    return _surface_error(status, body)


def _cmd_revoke(agent_id: str) -> int:
    confirm = input(
        f"Revoke @{agent_id}'s Ed25519 key? They will re-register via TOFU on next signed "
        "request. Type 'yes' to confirm: "
    ).strip()
    if confirm != "yes":
        print("aborted")
        return 1
    status, body = _signed_request("POST", f"/admin/api/keys/revoke/{agent_id}")
    if status == 200 and isinstance(body, dict):
        print(f"OK — @{body.get('agent_id', agent_id)} key revoked")
        if body.get("hint"):
            print(f"     {body['hint']}")
        return 0
    return _surface_error(status, body)
