#!/usr/bin/env python3
"""
Chapter skill author tool — init, sign, publish.

Usage
-----

    # Scaffold a new skill directory
    python scripts/sign_skill.py init my-skill

    # Build a signed .nandaskill package from a skill directory
    python scripts/sign_skill.py sign my-skill/

    # Publish a signed .nandaskill to a chapter
    python scripts/sign_skill.py publish my-skill.nandaskill \\
        --chapter https://org.example.com

    # One-shot: sign + publish in a single command
    python scripts/sign_skill.py ship my-skill/ \\
        --chapter https://org.example.com

A skill directory must contain:
    manifest.json   — {name, version, description, capabilities, author_did}
    skill.py        — the implementation (not executed at publish time)
    README.md       — optional, rendered as Markdown in the chapter's UI

Signing uses Ed25519. The keypair lives at ~/.chapter-skill-keys/<did>.json.
First run auto-generates a keypair and prints the did:key for you to copy
into manifest.json's `author_did` field.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tarfile
from io import BytesIO
from pathlib import Path

import httpx

try:
    import base58
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: install pynacl and base58 for signing", file=sys.stderr)
    print("  pip install pynacl base58", file=sys.stderr)
    sys.exit(2)


KEYS_DIR = Path.home() / ".chapter-skill-keys"
ED25519_MULTICODEC_PREFIX = b"\xed\x01"


# ═══════════════════════════════════════════════════════════════
# Key management
# ═══════════════════════════════════════════════════════════════


def build_did_key(pubkey_bytes: bytes) -> str:
    """did:key:z{base58btc(multicodec(0xed01) || pubkey)} — W3C did-method-key."""
    prefixed = ED25519_MULTICODEC_PREFIX + pubkey_bytes
    return f"did:key:z{base58.b58encode(prefixed).decode()}"


def load_or_create_keypair(alias: str | None = None) -> tuple[SigningKey, str]:
    """Return (signing_key, did:key). Creates a new keypair if none on disk."""
    KEYS_DIR.mkdir(exist_ok=True, parents=True, mode=0o700)

    # Pick a keypair file. If alias is provided, use <alias>.json; otherwise use default.json.
    fname = f"{alias}.json" if alias else "default.json"
    kpath = KEYS_DIR / fname

    if kpath.exists():
        data = json.loads(kpath.read_text())
        sk = SigningKey(base64.b64decode(data["private_key"]))
        did = data["did"]
        return sk, did

    sk = SigningKey.generate()
    pub_bytes = sk.verify_key.encode()
    did = build_did_key(pub_bytes)
    kpath.write_text(
        json.dumps(
            {
                "private_key": base64.b64encode(sk.encode()).decode(),
                "public_key": base64.b64encode(pub_bytes).decode(),
                "did": did,
            },
            indent=2,
        )
    )
    kpath.chmod(0o600)
    print(f"✓ Generated new keypair at {kpath}")
    print(f"  did: {did}")
    print("  (copy this into your skill's manifest.json as author_did)")
    return sk, did


# ═══════════════════════════════════════════════════════════════
# init — scaffold a skill directory
# ═══════════════════════════════════════════════════════════════


DEFAULT_MANIFEST = """{
  "name": "__NAME__",
  "version": "0.1.0",
  "description": "Describe your skill in one line.",
  "capabilities": [],
  "author_did": "did:key:z6Mk..."
}
"""

DEFAULT_SKILL = """# __NAME__
#
# Your skill implementation lives here. Exported tools should follow
# the chapter's tool contract — accept a JSON payload, return a JSON
# response. Implementation layer is coming in W5-6 of the roadmap.


def run(params: dict) -> dict:
    return {"ok": True, "skill": "__NAME__", "received": params}
"""

DEFAULT_README = """# __NAME__

One-line description.

## What it does

Describe the skill here. Supports Markdown.

## Declared capabilities

List what the skill needs at runtime (e.g. `fs.read`, `net.http`).
"""


def cmd_init(args: argparse.Namespace) -> int:
    name = args.name.strip().lower()
    import re

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
        print(f"ERROR: invalid skill name {name!r} — must match ^[a-z][a-z0-9-]*$", file=sys.stderr)
        return 2

    target = Path(name)
    if target.exists():
        print(f"ERROR: {target} already exists", file=sys.stderr)
        return 1

    target.mkdir(parents=True)
    (target / "manifest.json").write_text(DEFAULT_MANIFEST.replace("__NAME__", name))
    (target / "skill.py").write_text(DEFAULT_SKILL.replace("__NAME__", name))
    (target / "README.md").write_text(DEFAULT_README.replace("__NAME__", name))

    print(f"✓ Scaffolded {target}/")
    print("  Edit manifest.json (especially author_did + capabilities + description)")
    print(f"  Then: python {sys.argv[0]} sign {target}/")
    return 0


# ═══════════════════════════════════════════════════════════════
# sign — package + sign a skill directory
# ═══════════════════════════════════════════════════════════════


def _package_dir(src: Path) -> bytes:
    """Build a deterministic tar.gz of src/. Returns the bytes."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tf:
        for path in sorted(src.rglob("*")):
            if path.is_file() and not any(p.startswith(".") for p in path.parts):
                # Strip src prefix; keep stable ordering.
                arcname = str(path.relative_to(src))
                tf.add(str(path), arcname=arcname, recursive=False)
    return buf.getvalue()


def cmd_sign(args: argparse.Namespace) -> int:
    src = Path(args.dir)
    if not src.is_dir():
        print(f"ERROR: {src} is not a directory", file=sys.stderr)
        return 1

    manifest_path = src / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())

    # Load readme into manifest if present so it surfaces in the registry UI.
    readme_path = src / "README.md"
    if readme_path.exists() and "readme_markdown" not in manifest:
        manifest["readme_markdown"] = readme_path.read_text()

    # Keypair.
    sk, did = load_or_create_keypair(args.key_alias)

    # If author_did is the placeholder, fill it with our keypair's did.
    if not manifest.get("author_did") or manifest["author_did"].startswith("did:key:z6Mk..."):
        manifest["author_did"] = did
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"✓ Filled manifest.json author_did = {did}")

    # Package + sha256 + sign.
    package_bytes = _package_dir(src)
    sha256_hex = hashlib.sha256(package_bytes).hexdigest()
    signed = sk.sign(sha256_hex.encode("utf-8"))
    signature_b64 = base64.b64encode(signed.signature).decode()

    # Write outputs.
    skill_pkg = src.with_suffix(".nandaskill")
    skill_pkg.write_bytes(package_bytes)

    sidecar = {
        "manifest": manifest,
        "content_sha256": sha256_hex,
        "signature": signature_b64,
        "signing_key_did": did,
    }
    sidecar_path = src.with_suffix(".nandaskill.json")
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n")

    print(f"✓ Wrote  {skill_pkg}  ({len(package_bytes)} bytes)")
    print(f"✓ Wrote  {sidecar_path}")
    print(f"  sha256 = {sha256_hex}")
    print(f"  signer = {did}")
    return 0


# ═══════════════════════════════════════════════════════════════
# publish — POST a signed skill to a chapter
# ═══════════════════════════════════════════════════════════════


def cmd_publish(args: argparse.Namespace) -> int:
    pkg = Path(args.package)
    if not pkg.exists():
        print(f"ERROR: {pkg} not found", file=sys.stderr)
        return 1

    # Expect a sidecar .nandaskill.json next to the package (written by `sign`).
    sidecar_path = pkg.with_suffix(".nandaskill.json")
    if pkg.suffix == ".nandaskill":
        sidecar_path = pkg.with_suffix(".nandaskill.json")
    elif pkg.suffix == ".json":
        sidecar_path = pkg
    if not sidecar_path.exists():
        print(f"ERROR: sidecar {sidecar_path} not found — run `sign` first", file=sys.stderr)
        return 1

    sidecar = json.loads(sidecar_path.read_text())

    chapter_url = args.chapter.rstrip("/")
    payload = {
        "manifest": sidecar["manifest"],
        "signature": sidecar["signature"],
        "signing_key_did": sidecar["signing_key_did"],
        "content_sha256": sidecar["content_sha256"],
    }

    print(f"→ POST {chapter_url}/api/skills/publish")
    try:
        resp = httpx.post(f"{chapter_url}/api/skills/publish", json=payload, timeout=20.0)
    except httpx.HTTPError as e:
        print(f"✗ Network error: {e}", file=sys.stderr)
        return 1

    if resp.status_code >= 400:
        print(f"✗ {resp.status_code}: {resp.text[:400]}", file=sys.stderr)
        return 1

    skill = resp.json().get("skill", {})
    print(f"✓ Published {skill.get('id')} to {chapter_url}")
    print(f"  View: {chapter_url}/api/skills/{skill.get('id')}")
    return 0


# ═══════════════════════════════════════════════════════════════
# ship — sign then publish
# ═══════════════════════════════════════════════════════════════


def cmd_ship(args: argparse.Namespace) -> int:
    rc = cmd_sign(args)
    if rc != 0:
        return rc
    src = Path(args.dir)
    args.package = str(src.with_suffix(".nandaskill"))
    return cmd_publish(args)


# ═══════════════════════════════════════════════════════════════
# update — bump version + re-sign + publish
# ═══════════════════════════════════════════════════════════════


def _bump_semver(version: str, level: str) -> str:
    import re

    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        raise ValueError(f"version {version!r} is not semver — cannot bump")
    major, minor, patch = (int(x) for x in m.groups())
    if level == "major":
        major += 1
        minor = 0
        patch = 0
    elif level == "minor":
        minor += 1
        patch = 0
    else:  # patch
        patch += 1
    return f"{major}.{minor}.{patch}"


def cmd_update(args: argparse.Namespace) -> int:
    src = Path(args.dir)
    if not src.is_dir():
        print(f"ERROR: {src} is not a directory", file=sys.stderr)
        return 1

    manifest_path = src / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())

    old_version = manifest.get("version", "0.0.0")
    try:
        new_version = _bump_semver(old_version, args.bump)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    manifest["version"] = new_version
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"✓ Bumped version {old_version} → {new_version}")

    rc = cmd_sign(args)
    if rc != 0:
        return rc
    args.package = str(src.with_suffix(".nandaskill"))
    return cmd_publish(args)


# ═══════════════════════════════════════════════════════════════
# review — post a review for an installed skill
# ═══════════════════════════════════════════════════════════════


def cmd_review(args: argparse.Namespace) -> int:
    if not (1 <= int(args.rating) <= 5):
        print("ERROR: rating must be in 1..5", file=sys.stderr)
        return 2

    chapter_url = args.chapter.rstrip("/")
    payload = {
        "reviewer_agent_id": args.agent_id,
        "rating": int(args.rating),
        "review_text": args.text,
        "signed_install_proof": args.install_proof,
    }
    print(f"→ POST {chapter_url}/api/skills/{args.skill_id}/review")
    try:
        resp = httpx.post(
            f"{chapter_url}/api/skills/{args.skill_id}/review",
            json=payload,
            timeout=15.0,
        )
    except httpx.HTTPError as e:
        print(f"✗ Network error: {e}", file=sys.stderr)
        return 1

    if resp.status_code >= 400:
        print(f"✗ {resp.status_code}: {resp.text[:400]}", file=sys.stderr)
        return 1

    print(f"✓ Review posted on {args.skill_id}")
    return 0


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Scaffold a skill directory")
    p_init.add_argument("name")
    p_init.set_defaults(func=cmd_init)

    p_sign = sub.add_parser("sign", help="Build + sign a .nandaskill package")
    p_sign.add_argument("dir", help="Skill source directory")
    p_sign.add_argument("--key-alias", default=None, help="Named keypair (default: 'default')")
    p_sign.set_defaults(func=cmd_sign)

    p_pub = sub.add_parser("publish", help="Publish a signed .nandaskill to a chapter")
    p_pub.add_argument("package", help="Path to .nandaskill or .nandaskill.json")
    p_pub.add_argument("--chapter", required=True, help="Chapter URL")
    p_pub.set_defaults(func=cmd_publish)

    p_ship = sub.add_parser("ship", help="Sign + publish in one shot")
    p_ship.add_argument("dir", help="Skill source directory")
    p_ship.add_argument("--chapter", required=True, help="Chapter URL")
    p_ship.add_argument("--key-alias", default=None)
    p_ship.set_defaults(func=cmd_ship)

    p_update = sub.add_parser("update", help="Bump version + re-sign + publish")
    p_update.add_argument("dir", help="Skill source directory")
    p_update.add_argument("--chapter", required=True, help="Chapter URL")
    p_update.add_argument(
        "--bump",
        choices=["patch", "minor", "major"],
        default="patch",
        help="SemVer bump level (default: patch)",
    )
    p_update.add_argument("--key-alias", default=None)
    p_update.set_defaults(func=cmd_update)

    p_review = sub.add_parser("review", help="Post a review for a skill you've installed")
    p_review.add_argument("skill_id", help="e.g. file-ops@1.0.0")
    p_review.add_argument("--chapter", required=True, help="Chapter URL")
    p_review.add_argument("--agent-id", required=True, help="Your member agent id")
    p_review.add_argument("--rating", type=int, required=True, help="1-5")
    p_review.add_argument("--text", default="", help="Review text")
    p_review.add_argument(
        "--install-proof",
        required=True,
        help="signed_install_proof from a prior /install call",
    )
    p_review.set_defaults(func=cmd_review)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
