"""Generate or rotate the chapter's admin token.

Usage::

    python -m chapter.scripts.setup_admin            # idempotent — generates iff absent
    python -m chapter.scripts.setup_admin --rotate   # force a new token
    python -m chapter.scripts.setup_admin --print    # print existing (no generate)

The admin token grants system-level operator authority on this chapter
(see ``chapter/admin.py`` for the security model). This wizard is the
recommended way to initialize it because:

  1. It's idempotent — re-running on a chapter with an existing token
     is a no-op.
  2. It writes to both the on-disk token file AND an ``.env`` file in
     the chapter directory (creating the .env if missing), so the next
     chapter restart picks up the token from either source.
  3. It prints next-step instructions: how to use the token with
     ``curl``, how to open the admin UI, how to rotate later.

Idiomatic Python — no third-party deps. Run from the repo root or any
directory; resolves the chapter dir relative to this file.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Import the admin module from the chapter package. This script can be
# invoked two ways:
#   python -m chapter.scripts.setup_admin   (package import, normal)
#   python chapter/scripts/setup_admin.py   (file import, also OK)
# Both paths need ``chapter/`` on sys.path so ``import admin`` resolves.
HERE = Path(__file__).resolve()
CHAPTER_DIR = HERE.parent.parent  # chapter/
if str(CHAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(CHAPTER_DIR))

import admin as admin_mod  # noqa: E402


def _env_file_path() -> Path:
    return CHAPTER_DIR / ".env"


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _write_env_file(path: Path, kvs: dict[str, str]) -> None:
    lines: list[str] = []
    if path.exists():
        # Preserve existing comments + structure; replace only changed keys.
        for raw in path.read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if not s or s.startswith("#") or "=" not in s:
                lines.append(raw)
                continue
            k = s.split("=", 1)[0].strip()
            if k in kvs:
                lines.append(f"{k}={kvs[k]}")
                kvs = {k2: v for k2, v in kvs.items() if k2 != k}
            else:
                lines.append(raw)
    # Append any remaining new keys
    for k, v in kvs.items():
        lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Force a new token. Old token becomes invalid immediately.",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_only",
        help="Print the existing token without generating a new one. Fails if absent.",
    )
    args = parser.parse_args()

    if args.print_only:
        if args.rotate:
            print("error: --print and --rotate are mutually exclusive", file=sys.stderr)
            return 2
        token_file = admin_mod._resolve_token_file()
        existing = admin_mod._load_token_from_file(token_file)
        if not existing:
            print(f"no token found at {token_file}", file=sys.stderr)
            return 1
        print(existing)
        return 0

    token, freshly = admin_mod.init(force_regenerate=args.rotate)

    if args.rotate:
        action = "rotated"
    elif freshly:
        action = "generated"
    else:
        action = "loaded (already present)"

    # Mirror the token into .env if present or being created. This makes
    # the chapter restart-stable without depending on the on-disk token
    # file (some deployment targets reset the working dir between runs).
    env_path = _env_file_path()
    kvs = _read_env_file(env_path)
    if kvs.get("ORG_ADMIN_TOKEN") != token:
        kvs["ORG_ADMIN_TOKEN"] = token
        _write_env_file(env_path, kvs)
        env_msg = f"  Mirrored into {env_path}\n"
    else:
        env_msg = ""

    print(
        f"\n{action.upper()}:\n"
        f"  Token:    {token}\n"
        f"  File:     {admin_mod.token_file_path()}\n"
        f"{env_msg}\n"
        "Next steps:\n"
        "  1. Capture the token in a password manager NOW. The on-disk\n"
        "     and .env copies are operator-convenience, not authoritative.\n"
        "  2. Restart the chapter so the new token takes effect:\n"
        "       railway redeploy   (or your equivalent)\n"
        "  3. Verify the token works:\n"
        f"       curl -H 'X-Admin-Token: {token}' "
        f"{os.environ.get('PUBLIC_URL', 'http://localhost:7000')}/admin/api/status\n"
        "  4. Open the admin UI:\n"
        f"       {os.environ.get('PUBLIC_URL', 'http://localhost:7000')}/admin/\n"
        "     Paste the token; it's stored in localStorage.\n"
        "  5. To rotate later: python -m chapter.scripts.setup_admin --rotate\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
