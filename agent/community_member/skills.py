"""
Local skill loader for community-member.

A member agent can `install_skill(skill_id)` to:
  1. POST /api/skills/{id}/install on its chapter → get signed_install_proof
  2. Download the .nandaskill package from package_url
  3. Verify sha256(package) == chapter's content_sha256
  4. Verify Ed25519 signature over content_sha256 against skill.signing_key_did
  5. Extract to ~/.community-member/skills/<skill_id>/
  6. Register an entry in ~/.community-member/skills/registry.json
  7. On next agent turn, dynamically load skill.py and expose its TOOLS

Every verification gate is checked twice — publish-time by the chapter,
install-time here. Tampering between the two is detectable. Revocation is
checked at install AND on every agent startup.

Public API
----------
install_skill(chapter_url, skill_id, agent_id, *, download, verify, save)
  — full pipeline
verify_signed_package(content_bytes, content_sha256, signature_b64, did_key)
  — pure crypto layer
load_installed_registry(skills_root) / save_installed_registry(entries, skills_root)
  — local ledger I/O; the registry lives under the skills root it indexes
check_revocations_at_startup(chapter_url, agent_id)
  — batch revocation check; returns list of skill_ids that were revoked remotely
uninstall_skill(skill_id)
  — remove disk + registry entry

Capability enforcement happens at tool-invocation time (not here) — see agent.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import tarfile
from collections.abc import Callable
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

# ── Paths ────────────────────────────────────────────
from community_member.config import CONFIG_DIR

# Skills live under the agent's config dir (~/.community-member/skills), same
# home as identity/consent/habits — overridable via COMMUNITY_MEMBER_HOME.
SKILLS_ROOT = CONFIG_DIR / "skills"
REGISTRY_PATH = SKILLS_ROOT / "registry.json"
HIGH_RISK_CAPABILITIES = frozenset({"shell.exec", "net.arbitrary", "fs.any", "eval.code"})

MAX_PACKAGE_BYTES = 8 * 1024 * 1024  # 8 MiB — skills are code + readme, not blobs
MAX_MANIFEST_BYTES = 64 * 1024

ED25519_MULTICODEC_PREFIX = b"\xed\x01"


# ── Pure crypto (local, no server roundtrip) ────────


def extract_ed25519_pubkey_from_did_key(did_key: str) -> bytes | None:
    """Decode a did:key:z... string to its 32-byte Ed25519 public key.

    Returns None on any malformed input. Pure function — no I/O.
    """
    import base58

    if not did_key or not did_key.startswith("did:key:z"):
        return None
    try:
        encoded = did_key[len("did:key:z") :]
        raw = base58.b58decode(encoded)
        if len(raw) != 34 or raw[:2] != ED25519_MULTICODEC_PREFIX:
            return None
        return raw[2:]
    except Exception:
        return None


def verify_signed_package(
    content_bytes: bytes,
    content_sha256: str,
    signature_b64: str,
    signing_key_did: str,
) -> tuple[bool, str]:
    """The whole verification pipeline in one function.

    1. sha256(content) must equal content_sha256
    2. signing_key_did must decode to an Ed25519 public key
    3. signature_b64 must be a valid Ed25519 sig over the hex sha256

    Returns (ok, reason). Never raises — hostile inputs return False.
    """
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if not content_bytes:
        return False, "empty content"
    if len(content_bytes) > MAX_PACKAGE_BYTES:
        return False, f"package too large (max {MAX_PACKAGE_BYTES} bytes)"
    if not content_sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}", content_sha256):
        return False, "content_sha256 must be a 64-char hex string"

    actual_sha = hashlib.sha256(content_bytes).hexdigest()
    if actual_sha != content_sha256.lower():
        return False, f"sha256 mismatch: chapter said {content_sha256}, got {actual_sha}"

    pubkey_bytes = extract_ed25519_pubkey_from_did_key(signing_key_did)
    if not pubkey_bytes:
        return False, "signing_key_did malformed or not Ed25519"

    try:
        verify_key = VerifyKey(pubkey_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        verify_key.verify(content_sha256.encode("utf-8"), sig_bytes)
        return True, "ok"
    except BadSignatureError:
        return False, "Ed25519 signature verification failed"
    except Exception as e:
        return False, f"signature verification error: {type(e).__name__}"


# ── Local registry I/O ───────────────────────────────


def _registry_path(skills_root: Path | None = None) -> Path:
    """The registry belonging to a given skills root.

    An install pinned to ``skills_root`` writes its files there, so its index
    belongs there too. Reading the process-global registry instead lets two
    pinned roots share one index, where uninstalling from either removes the
    other's entries.
    """
    return (skills_root / "registry.json") if skills_root is not None else REGISTRY_PATH


def load_installed_registry(skills_root: Path | None = None) -> dict[str, dict]:
    """Return {skill_id: entry} from the registry under ``skills_root``.

    Defaults to the process-global skills root. Empty dict if the file doesn't
    exist or is corrupt. Never raises.
    """
    path = _registry_path(skills_root)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_installed_registry(entries: dict[str, dict], skills_root: Path | None = None) -> None:
    root = skills_root if skills_root is not None else SKILLS_ROOT
    path = _registry_path(skills_root)
    root.mkdir(exist_ok=True, parents=True, mode=0o700)
    path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


# ── Install pipeline ────────────────────────────────


def install_skill(
    chapter_url: str,
    skill_id: str,
    agent_id: str,
    *,
    download_fn: Callable[[str], bytes] | None = None,
    chapter_api_fn: Callable[[str, str, dict | None], dict] | None = None,
    skills_root: Path | None = None,
) -> dict:
    """Full install pipeline.

    Default `download_fn` = httpx.get → bytes. Default `chapter_api_fn` = an
    UNSIGNED httpx request (for offline/tests) — the install POST requires an
    Ed25519 signature, so a live caller MUST inject a signed one (the agent
    passes `A2AClient.api_call`). Both injectable so tests run offline.

    Returns {skill_id, installed_at, installed_version, install_proof,
    manifest, signing_key_did, capabilities, path}.

    Raises ValueError on any verification failure — disk is not touched
    unless every gate passes.
    """
    import httpx

    root = skills_root or SKILLS_ROOT
    safe_id = skill_id.strip()
    if not re.fullmatch(r"[a-z][a-z0-9-]*@\d+\.\d+\.\d+", safe_id):
        raise ValueError(f"invalid skill_id format: {safe_id!r}")

    # Step 1: call server to register the install and get install_proof.
    if chapter_api_fn is None:

        def chapter_api_fn(method, path, body=None):
            resp = httpx.request(
                method,
                f"{chapter_url.rstrip('/')}{path}",
                json=body,
                timeout=20.0,
            )
            resp.raise_for_status()
            return resp.json()

    install_response = chapter_api_fn("POST", f"/api/skills/{safe_id}/install", {"agent_id": agent_id})
    install_proof = install_response.get("signed_install_proof")
    if not install_proof or not re.fullmatch(r"[0-9a-f]{64}", install_proof):
        raise ValueError("chapter did not return a valid signed_install_proof")

    # Step 2: fetch skill metadata to get the signature + content_sha256 + package_url.
    skill_detail = chapter_api_fn("GET", f"/api/skills/{safe_id}", None)
    skill = skill_detail.get("skill") or {}
    if not skill:
        raise ValueError(f"chapter returned no skill record for {safe_id!r}")
    if skill.get("revoked_at"):
        raise ValueError(f"skill {safe_id!r} is revoked: {skill.get('revocation_reason') or 'no reason'}")

    content_sha256 = skill.get("content_sha256", "")
    signature_b64 = skill.get("signature", "")
    signing_key_did = skill.get("signing_key_did", "")
    package_url = skill.get("package_url")

    # Step 3: download package bytes.
    # Bootstrap-signed skills (and many MVP skills) don't have a package_url —
    # the manifest IS the package. For those, we canonicalize the manifest and
    # use that as the content bytes.
    if package_url:
        if download_fn is None:

            def download_fn(url):
                resp = httpx.get(url, timeout=30.0)
                resp.raise_for_status()
                return resp.content

        content_bytes = download_fn(package_url)
    else:
        # Manifest-is-package mode: the content bytes are the JCS-canonical JSON
        # of the manifest (RFC 8785: sorted keys, compact separators, UTF-8 /
        # no ASCII escaping) — the same canonical form the rest of the stack uses
        # for signing (cosign receipts). This MUST byte-match the signer
        # (server starter_pack._sign_manifest) or the sha256 differs and every
        # manifest-is-package skill fails verification.
        manifest_with_author = {**skill.get("manifest", {}), "author_did": skill.get("author_did", "")}
        content_bytes = json.dumps(
            manifest_with_author, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    # Step 4: verify sha256 + signature.
    ok, reason = verify_signed_package(
        content_bytes=content_bytes,
        content_sha256=content_sha256,
        signature_b64=signature_b64,
        signing_key_did=signing_key_did,
    )
    if not ok:
        raise ValueError(f"signature verification failed: {reason}")

    # Step 5: extract to ~/.community-member/skills/<skill_id>/ — but only if it looks like a tarball.
    skill_dir = root / safe_id.replace("/", "_").replace("@", "_at_")
    skill_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    is_tarball = False
    if package_url:
        try:
            with tarfile.open(fileobj=BytesIO(content_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    # Refuse path traversal.
                    if member.name.startswith("/") or ".." in Path(member.name).parts:
                        raise ValueError(f"refusing path-traversing tar member: {member.name!r}")
                    # Refuse symlinks — tarballs with links can escape the extract dir.
                    if member.issym() or member.islnk():
                        raise ValueError(f"refusing symlink tar member: {member.name!r}")
                tf.extractall(skill_dir, filter="data")
            is_tarball = True
        except tarfile.ReadError:
            # Not a tarball — store the raw bytes as package.bin for audit.
            (skill_dir / "package.bin").write_bytes(content_bytes)
    else:
        # Manifest-only skills: write the manifest + readme.
        (skill_dir / "manifest.json").write_text(
            json.dumps(skill.get("manifest") or {}, indent=2, sort_keys=True) + "\n"
        )
        readme = (skill.get("manifest") or {}).get("readme_markdown") or skill.get("readme_markdown") or ""
        if readme:
            (skill_dir / "README.md").write_text(readme)

    # Step 6: persist registry entry.
    now = datetime.now(UTC).isoformat()
    entry = {
        "skill_id": safe_id,
        "installed_at": now,
        "installed_version": skill.get("version"),
        "install_proof": install_proof,
        "signing_key_did": signing_key_did,
        "content_sha256": content_sha256,
        "capabilities": list(skill.get("capabilities") or []),
        "path": str(skill_dir),
        "is_tarball": is_tarball,
        "manifest": skill.get("manifest") or {},
    }
    registry = load_installed_registry(skills_root)
    registry[safe_id] = entry
    save_installed_registry(registry, skills_root)

    return entry


# ── Uninstall + revocation ────────────────────────────


def uninstall_skill(skill_id: str, *, skills_root: Path | None = None, hard_delete: bool = False) -> dict:
    """Remove a skill's registry entry. Soft by default (preserves disk for audit)."""
    root = skills_root or SKILLS_ROOT
    registry = load_installed_registry(skills_root)
    if skill_id not in registry:
        raise ValueError(f"skill {skill_id!r} is not installed")

    entry = registry.pop(skill_id)
    save_installed_registry(registry, skills_root)

    if hard_delete:
        path = Path(entry.get("path", ""))
        if path.exists() and path.is_relative_to(root):
            shutil.rmtree(path, ignore_errors=True)

    return {"skill_id": skill_id, "hard_delete": hard_delete}


def check_revocations_at_startup(
    chapter_api_fn: Callable[[str, str, dict | None], dict] | None = None,
    chapter_url: str | None = None,
) -> list[str]:
    """On agent startup, verify every installed skill is still non-revoked.

    Returns the list of skill_ids that have been revoked since install.
    These should be uninstalled (soft) and their tools unregistered.
    """
    import httpx

    if chapter_api_fn is None:
        if not chapter_url:
            return []

        def chapter_api_fn(method, path, body=None):
            try:
                resp = httpx.request(method, f"{chapter_url.rstrip('/')}{path}", json=body, timeout=10.0)
                resp.raise_for_status()
                return resp.json()
            except Exception:
                return {}

    registry = load_installed_registry()
    revoked: list[str] = []
    for sid in list(registry.keys()):
        try:
            detail = chapter_api_fn("GET", f"/api/skills/{sid}", None)
        except Exception as exc:
            # network hiccup — don't mass-uninstall on transient errors
            import logging as _logging

            _logging.getLogger(__name__).debug("skill revocation check skipped for %s: %s", sid, exc)
            continue
        skill = (detail or {}).get("skill") or {}
        if skill.get("revoked_at"):
            revoked.append(sid)
    return revoked
