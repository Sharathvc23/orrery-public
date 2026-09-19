"""
Chapter Skills Registry — Ed25519-signed skill packages.

Every skill in a chapter's registry is signed by its author's did:key.
Signatures are verified at publish time AND re-verified at install time
against a revocation list. No unsigned skills accepted, ever.

In a "private chapter" deployment this is the internal curated catalog;
the same module + flow serves both public and private modes.

Public API
----------
publish_skill(manifest, signature, signing_key_did, ...)  — create entry
list_skills(query, tags, author, trust_min, chapter_id)    — browse
get_skill(skill_id, chapter_id)                             — detail
install_skill(skill_id, agent_id, installed_version)       — record install
review_skill(skill_id, reviewer_agent_id, rating, text,    — post review
             signed_install_proof)
revoke_skill(skill_id, revoked_by_agent_id, reason)        — mark revoked

verify_skill_signature(content_sha256, signature, did)     — pure crypto
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

# ── Config + DI ───────────────────────────────────────────

_pg_request: Callable | None = None
_chapter_id: str = "public"

# Hard limits — keep the registry honest.
MAX_README_BYTES = 256 * 1024  # 256 KiB


class SkillInputError(ValueError):
    """A validation failure whose message is written FOR the caller.

    Exists to separate two things that were indistinguishable at the route
    boundary. Every ``raise`` in this module is authored text a caller needs in
    order to fix their request — "manifest too large (max N bytes)", "bump
    version", "invalid Ed25519 signature over content hash". Echoing those is
    correct and useful.

    But ``except ValueError`` also catches errors nobody wrote for a caller:
    ``json.JSONDecodeError`` and ``binascii.Error`` are both ValueError
    subclasses, so a malformed body or a bad base64 field surfaces library text
    ("Expecting property name enclosed in double quotes: line 1 column 2") through
    the same handler. That is the part of M6 that was real — not a path or a
    stack, but text this project did not write and cannot vouch for.

    Subclassing ValueError keeps every existing caller working; the routes now
    echo this type and answer anything else generically while logging the detail
    server-side.
    """


MAX_MANIFEST_BYTES = 64 * 1024  # 64 KiB
MAX_CAPABILITIES = 32
MAX_DESCRIPTION_LEN = 1000
VALID_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
VALID_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

# Capabilities the agent considers "high risk" — rendered with warnings.
HIGH_RISK_CAPABILITIES = {"shell.exec", "net.arbitrary", "fs.any", "eval.code"}

# ── Agent-Skills interop metadata (additive, all optional) ──────────────
# A NANDA skill stays a *signed, executable* package gated by `capabilities`
# (the canonical sandbox contract). These extra fields make the same manifest
# *also* expressible as a generic agent skill, so it can interoperate with the
# open Agent-Skills ecosystem (Claude Agent Skills / MCP / AgentFacts). They are
# declarative metadata only — they never relax the signing or capability gate —
# and every one is optional, so manifests predating them validate unchanged.
_PERMISSION_KEYS = {"network", "filesystem", "code_execution", "external_api", "user_data_access"}
_SAFETY_LEVELS = {"low", "medium", "high"}
_COMPAT_TARGETS = {"generic_agents", "claude_skills", "chatgpt_skills", "mcp", "nanda_agentfacts"}
_COMPAT_STATUSES = {"supported", "experimental", "not_supported", "unknown"}
MAX_META_LIST_ITEMS = 32
MAX_META_STR_LEN = 200


def init(pg_request_fn: Callable, chapter_id: str = "public") -> None:
    global _pg_request, _chapter_id
    _pg_request = pg_request_fn
    _chapter_id = chapter_id


# ── Pure crypto — no network, no state ──────────────────


def verify_skill_signature(content_sha256: str, signature: str, signing_key_did: str) -> bool:
    """Verify that `signature` is a valid Ed25519 sig over `content_sha256`
    (a hex sha256) by the key embedded in `signing_key_did`.

    Returns False on any malformed input — never raises.
    """
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        from sovereign_identity import extract_ed25519_pubkey_from_did_key
    except ImportError:
        return False

    if not content_sha256 or not signature or not signing_key_did:
        return False
    # content_sha256 must be a 64-char hex string
    if len(content_sha256) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", content_sha256):
        return False

    pubkey_b64 = extract_ed25519_pubkey_from_did_key(signing_key_did)
    if not pubkey_b64:
        return False
    try:
        pubkey_bytes = base64.b64decode(pubkey_b64)
        if len(pubkey_bytes) != 32:
            return False
        verify_key = VerifyKey(pubkey_bytes)
        sig_bytes = base64.b64decode(signature)
        verify_key.verify(content_sha256.encode("utf-8"), sig_bytes)
        return True
    except (BadSignatureError, ValueError, Exception):
        return False


def compute_sha256(data: bytes) -> str:
    """Hex-encoded sha256 of bytes. Used at publish-time to bind signature to content."""
    return hashlib.sha256(data).hexdigest()


def canonical_content_bytes(manifest: dict) -> bytes:
    """The exact byte form a skill's ``content_sha256`` is computed over — sorted
    keys, compact separators, UTF-8. This matches ``starter_pack._sign_manifest``
    and the install-side verifier byte-for-byte. It is NOT the RFC 8785 ``jcs``
    library form; reusing the existing signing input is what keeps a skill
    published via ``/api/skills/publish`` verifiable inside a package unchanged.
    """
    import json as _json

    return _json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Validation ───────────────────────────────────────────


def _validate_manifest(manifest: dict) -> tuple[bool, str]:
    """Return (ok, reason)."""
    if not isinstance(manifest, dict):
        return False, "manifest must be an object"
    name = manifest.get("name")
    version = manifest.get("version")
    if not name or not isinstance(name, str) or not VALID_NAME_RE.match(name):
        return False, "invalid name — must match ^[a-z][a-z0-9-]{0,63}$"
    if not version or not isinstance(version, str) or not VALID_SEMVER_RE.match(version):
        return False, "invalid version — must be semver"
    description = manifest.get("description", "")
    if description and (not isinstance(description, str) or len(description) > MAX_DESCRIPTION_LEN):
        return False, f"description too long (max {MAX_DESCRIPTION_LEN})"
    caps = manifest.get("capabilities", [])
    if caps is None:
        caps = []
    if not isinstance(caps, list) or len(caps) > MAX_CAPABILITIES:
        return False, f"capabilities must be a list of ≤ {MAX_CAPABILITIES}"
    for cap in caps:
        if not isinstance(cap, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", cap):
            return False, f"invalid capability: {cap!r}"
    readme = manifest.get("readme_markdown", "")
    if readme and len(readme.encode("utf-8")) > MAX_README_BYTES:
        return False, f"readme too large (max {MAX_README_BYTES} bytes)"

    # ── Optional Agent-Skills interop metadata ──
    ok, reason = _validate_skill_metadata(manifest)
    if not ok:
        return False, reason
    return True, "ok"


def _validate_skill_metadata(manifest: dict) -> tuple[bool, str]:
    """Validate the optional, additive Agent-Skills interop fields. Each is
    absent-OK (backward compatible); when present its shape is enforced so the
    manifest stays a clean superset of the open skill format."""

    def _str_list(field: str) -> tuple[bool, str]:
        val = manifest.get(field)
        if val is None:
            return True, "ok"
        if not isinstance(val, list) or len(val) > MAX_META_LIST_ITEMS:
            return False, f"{field} must be a list of ≤ {MAX_META_LIST_ITEMS} strings"
        if any(not isinstance(x, str) or not x.strip() or len(x) > MAX_META_STR_LEN for x in val):
            return False, f"{field} entries must be non-empty strings ≤ {MAX_META_STR_LEN} chars"
        return True, "ok"

    category = manifest.get("category")
    if category is not None and (not isinstance(category, str) or not category.strip() or len(category) > 64):
        return False, "category must be a non-empty string ≤ 64 chars"

    for field in ("use_cases", "required_tools", "risk_tags", "tests"):
        ok, reason = _str_list(field)
        if not ok:
            return False, reason

    # inputs / outputs — named I/O contract entries.
    for field in ("inputs", "outputs"):
        val = manifest.get(field)
        if val is None:
            continue
        if not isinstance(val, list) or len(val) > MAX_META_LIST_ITEMS:
            return False, f"{field} must be a list of ≤ {MAX_META_LIST_ITEMS} entries"
        for item in val:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip():
                return False, f"{field} entries must be objects with a non-empty name"

    # permissions — coarse declarative booleans that complement `capabilities`.
    perms = manifest.get("permissions")
    if perms is not None:
        if not isinstance(perms, dict):
            return False, "permissions must be an object"
        for k, v in perms.items():
            if k not in _PERMISSION_KEYS:
                return False, f"unknown permission key: {k!r}"
            if not isinstance(v, bool):
                return False, f"permission {k!r} must be a boolean"

    sl = manifest.get("safety_level")
    if sl is not None and sl not in _SAFETY_LEVELS:
        return False, f"safety_level must be one of {sorted(_SAFETY_LEVELS)}"

    compat = manifest.get("compatibility")
    if compat is not None:
        if not isinstance(compat, dict):
            return False, "compatibility must be an object"
        for k, v in compat.items():
            if k not in _COMPAT_TARGETS:
                return False, f"unknown compatibility target: {k!r}"
            if v not in _COMPAT_STATUSES:
                return False, f"compatibility[{k!r}] must be one of {sorted(_COMPAT_STATUSES)}"

    lic = manifest.get("license")
    if lic is not None and (not isinstance(lic, str) or not lic.strip() or len(lic) > 64):
        return False, "license must be a non-empty string ≤ 64 chars"

    maint = manifest.get("maintainers")
    if maint is not None:
        if not isinstance(maint, list) or len(maint) > MAX_META_LIST_ITEMS:
            return False, f"maintainers must be a list of ≤ {MAX_META_LIST_ITEMS}"
        for m in maint:
            if not isinstance(m, dict) or not isinstance(m.get("name"), str) or not m["name"].strip():
                return False, "maintainer entries must be objects with a non-empty name"

    return True, "ok"


def _skill_id(name: str, version: str) -> str:
    return f"{name}@{version}"


# ── Core ops ─────────────────────────────────────────────


async def publish_skill(
    manifest: dict,
    signature: str,
    signing_key_did: str,
    content_sha256: str,
    author_agent_id: str | None = None,
    package_url: str | None = None,
    chapter_id: str | None = None,
) -> dict:
    """Register a new signed skill. Rejects forged / malformed inputs.

    Returns the persisted skill record on success.
    Raises ValueError on any rejection — caller translates to HTTP 4xx.
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized — call init() first")

    ok, reason = _validate_manifest(manifest)
    if not ok:
        raise SkillInputError(f"manifest rejected: {reason}")

    if not isinstance(manifest, dict):
        raise SkillInputError("manifest must be a dict")

    import json as _json

    if len(_json.dumps(manifest).encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise SkillInputError(f"manifest too large (max {MAX_MANIFEST_BYTES} bytes)")

    if not verify_skill_signature(content_sha256, signature, signing_key_did):
        raise SkillInputError("invalid Ed25519 signature over content hash")

    name = manifest["name"]
    version = manifest["version"]
    sid = _skill_id(name, version)

    # Bail if this exact (name, version) already exists and is not revoked.
    existing = await _pg_request(
        "GET",
        "chapter_skills",
        params={"id": f"eq.{sid}", "select": "id,revoked_at"},
    )
    if existing and existing[0].get("revoked_at") is None:
        raise SkillInputError(f"skill {sid!r} already published — bump version")

    # author_did is the key that signed; if manifest declares a different
    # author_did we record BOTH so future signers-on-behalf-of-org work.
    author_did = manifest.get("author_did") or signing_key_did

    row = {
        "id": sid,
        "name": name,
        "version": version,
        "author_did": author_did,
        "author_agent_id": author_agent_id,
        "description": (manifest.get("description") or "")[:MAX_DESCRIPTION_LEN],
        "readme_markdown": manifest.get("readme_markdown") or "",
        "capabilities": manifest.get("capabilities") or [],
        "manifest": manifest,
        "content_sha256": content_sha256,
        "signature": signature,
        "signing_key_did": signing_key_did,
        "package_url": package_url,
        "chapter_id": chapter_id or _chapter_id,
    }

    inserted = await _pg_request("POST", "chapter_skills", body=row)
    if not inserted:
        raise RuntimeError("failed to insert skill")
    return inserted[0] if isinstance(inserted, list) else inserted


async def refresh_skill_signature(
    manifest: dict,
    signature: str,
    signing_key_did: str,
    content_sha256: str,
) -> str:
    """Re-sign an EXISTING (name, version) skill in place when its stored content
    hash has drifted from a freshly-computed one — the first-party escape hatch
    from ``publish_skill``'s strict "bump version" rule, used ONLY by the
    self-seeded starter pack so it can track a code change (e.g. a manifest
    canonicalization fix) without a version bump.

    Verifies the new signature before writing. Never changes (name, version).
    Returns: ``"refreshed"`` (drift updated), ``"unchanged"`` (stored hash already
    matches), or ``"absent"`` (no such live skill — caller should publish fresh).
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized — call init() first")
    if not verify_skill_signature(content_sha256, signature, signing_key_did):
        raise SkillInputError("invalid Ed25519 signature over content hash")
    sid = _skill_id(manifest["name"], manifest["version"])
    existing = await _pg_request(
        "GET", "chapter_skills", params={"id": f"eq.{sid}", "select": "id,content_sha256,revoked_at"}
    )
    if not existing or existing[0].get("revoked_at") is not None:
        return "absent"
    if existing[0].get("content_sha256") == content_sha256:
        return "unchanged"
    await _pg_request(
        "PATCH",
        "chapter_skills",
        params={"id": f"eq.{sid}"},
        body={
            "content_sha256": content_sha256,
            "signature": signature,
            "signing_key_did": signing_key_did,
            "author_did": manifest.get("author_did") or signing_key_did,
            "manifest": manifest,
        },
    )
    return "refreshed"


async def list_skills(
    query: str | None = None,
    tags: list[str] | None = None,
    author: str | None = None,
    trust_min: float = 0,
    chapter_id: str | None = None,
    include_revoked: bool = False,
    limit: int = 50,
) -> list[dict]:
    """Browse the registry. Filter + trust-gate + pagination friendly.

    By default returns THIS chapter's full skill catalog — every skill the
    chapter holds (published here or installed from a portable `.nandaskill`
    package), keyed by `name@version`. The catalog is a per-chapter Postgres
    store: there is no automatic cross-chapter catalog sync, so a chapter sees
    a peer's skill only once that skill's signed package is installed here. The
    packages are portable across chapters (federation-*ready*), but the catalog
    itself is not federated. Pass `chapter_id` to scope a listing to a specific
    publishing chapter (private-chapter isolation in W9 flips this to
    default-scoped).
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized")

    params: dict[str, str] = {
        "order": "trust_score.desc,created_at.desc",
        "limit": str(min(max(int(limit), 1), 200)),
    }
    # Only scope by server when explicitly requested. Unscoped returns this
    # chapter's whole catalog (the default); private servers pass their own id.
    if chapter_id:
        params["chapter_id"] = f"eq.{chapter_id}"
    if not include_revoked:
        params["revoked_at"] = "is.null"
    if trust_min > 0:
        params["trust_score"] = f"gte.{float(trust_min)}"
    if author:
        params["author_did"] = f"eq.{author}"

    rows = await _pg_request("GET", "chapter_skills", params=params) or []

    # Tag + name filtering done server-side would require more PostgREST plumbing;
    # for MVP we filter in Python (results are already capped by `limit`).
    if query:
        q = query.lower()
        rows = [
            r
            for r in rows
            if q in (r.get("name", "").lower())
            or q in (r.get("description", "").lower())
            or q in (r.get("readme_markdown", "").lower())
        ]
    if tags:
        tagset = {t.lower() for t in tags}
        rows = [r for r in rows if tagset & {c.lower() for c in (r.get("capabilities") or [])}]
    return rows


async def get_skill(skill_id: str, chapter_id: str | None = None) -> dict | None:
    """Fetch a skill by `name@version`.

    Skills are globally unique by id — any chapter can resolve any skill.
    `chapter_id` only scopes the lookup to the publishing chapter for
    private-chapter isolation (future W9 feature).
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized")
    params: dict[str, str] = {"id": f"eq.{skill_id}", "limit": "1"}
    if chapter_id:
        params["chapter_id"] = f"eq.{chapter_id}"
    rows = await _pg_request("GET", "chapter_skills", params=params)
    return rows[0] if rows else None


# ── .nandaskill signed package format ───────────────────────────────
#
# A downloadable, portable, signed skill BUNDLE. Additive over the existing
# manifest+content-reference publish path — it reuses the same Ed25519 publisher
# signature (over content_sha256) so a skill published via /api/skills/publish
# packs and re-verifies with its stored signature UNCHANGED. Layout (a zip):
#   manifest.json   — the skill manifest (readable JSON; schema/skill/0.1)
#   content.bin     — the exact signed content bytes (canonical_content_bytes);
#                     sha256(content.bin) == content_sha256
#   signature.json  — JCS-canonical record binding {content_sha256, signature,
#                     signing_key_did}: the detached publisher Ed25519 signature.
# See schema/skill/0.1/skill-package.schema.json.

PACKAGE_FORMAT = "nandaskill/0.1"
_PKG_MANIFEST = "manifest.json"
_PKG_CONTENT = "content.bin"
_PKG_SIGNATURE = "signature.json"
MAX_PACKAGE_BYTES = 2 * 1024 * 1024  # 2 MiB — a manifest-defined bundle is tiny
# hard DECOMPRESSED-byte ceiling. The compressed cap above does NOT bound
# how large a member inflates to — a ~2 MiB DEFLATE bomb can expand ~1000:1 to
# ~GBs and exhaust memory before any signature check runs. All three members are
# small JSON / canonical bytes (content.bin == canonical_content_bytes(manifest)),
# so these caps sit far above any legit bundle and far below a bomb.
MAX_MEMBER_DECOMPRESSED_BYTES = 4 * 1024 * 1024  # 4 MiB per member
MAX_TOTAL_DECOMPRESSED_BYTES = 8 * 1024 * 1024  # 8 MiB across all members read


def _read_member_bounded(zf, name: str, limit: int) -> bytes:
    """Read one zip member with a hard decompressed-byte ceiling.

    Two-stage guard so a bomb is rejected WITHOUT fully inflating it:
      1. reject on the declared uncompressed size (``ZipInfo.file_size``) — cheap,
         no decompression, catches an honest bomb header immediately;
      2. stream at most ``limit + 1`` decompressed bytes — a member whose header
         LIES about its size is still caught, because ``ZipExtFile.read(n)`` inflates
         only ``n`` bytes, never the whole stream.

    Integrity is unaffected: the caller re-checks ``sha256(content.bin)`` against the
    signed ``content_sha256``, so a truncated read can never pass verification.
    """
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise SkillInputError(f"package member {name} too large ({info.file_size} > {limit} decompressed)")
    with zf.open(name) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise SkillInputError(f"package member {name} exceeds decompressed ceiling ({limit})")
    return data


def _signature_json_bytes(content_sha256: str, signature: str, signing_key_did: str) -> bytes:
    """The JCS-canonical signature.json — the signed-statement record. The
    ``signature`` is the publisher's detached Ed25519 over ``content_sha256``
    (the existing NANDA skill signing input), so it is reused verbatim, never
    recomputed (packing needs no private key)."""
    return canonical_content_bytes(
        {
            "package_format": PACKAGE_FORMAT,
            "alg": "ed25519",
            "signing_key_did": signing_key_did,
            "content_sha256": content_sha256,
            "signature": signature,
        }
    )


def _unpack_package(package_bytes: bytes) -> tuple[dict, bytes, dict]:
    """Parse a .nandaskill zip into (manifest, content_bin, signature_meta).
    Raises ValueError on any malformed/oversized/incomplete package — the caller
    (verify) turns any raise into a fail-closed False."""
    import io
    import json as _json
    import zipfile

    if not package_bytes or len(package_bytes) > MAX_PACKAGE_BYTES:
        raise SkillInputError("package empty or too large")
    try:
        zf = zipfile.ZipFile(io.BytesIO(package_bytes))
    except zipfile.BadZipFile as e:
        raise SkillInputError("not a valid zip") from e
    with zf:
        names = set(zf.namelist())
        for required in (_PKG_MANIFEST, _PKG_CONTENT, _PKG_SIGNATURE):
            if required not in names:
                raise SkillInputError(f"package missing {required}")
        # read every member through the bounded reader BEFORE any parse or
        # verify, and hold a running total across members so many mid-sized members
        # can't sum past the ceiling. A decompression bomb is rejected here without
        # being fully inflated.
        budget = MAX_TOTAL_DECOMPRESSED_BYTES

        def _read(member: str) -> bytes:
            nonlocal budget
            limit = min(MAX_MEMBER_DECOMPRESSED_BYTES, budget)
            data = _read_member_bounded(zf, member, limit)
            budget -= len(data)
            return data

        manifest = _json.loads(_read(_PKG_MANIFEST))
        content_bin = _read(_PKG_CONTENT)
        signature_meta = _json.loads(_read(_PKG_SIGNATURE))
    if not isinstance(manifest, dict) or not isinstance(signature_meta, dict):
        raise SkillInputError("package manifest/signature not an object")
    return manifest, content_bin, signature_meta


def verify_package_signature(package_bytes: bytes) -> bool:
    """FAIL-CLOSED verification of a .nandaskill bundle. True only when the
    package is well-formed AND:

      1. the packed content bytes hash to the declared ``content_sha256``,
      2. the readable ``manifest.json`` canonicalizes byte-for-byte to that
         signed content (so the manifest is bound, not swappable), and
      3. the Ed25519 ``signature`` verifies over ``content_sha256`` by
         ``signing_key_did`` (the existing publisher-signing path, reused).

    Any malformed/missing/tampered member, hash mismatch, or bad key → False.
    Never raises.
    """
    try:
        manifest, content_bin, meta = _unpack_package(package_bytes)
    except Exception:  # noqa: BLE001 — malformed package is a fail-closed False
        return False
    content_sha256 = meta.get("content_sha256")
    signature = meta.get("signature")
    signing_key_did = meta.get("signing_key_did")
    if not (isinstance(content_sha256, str) and isinstance(signature, str) and isinstance(signing_key_did, str)):
        return False
    if compute_sha256(content_bin) != content_sha256:  # content integrity
        return False
    if canonical_content_bytes(manifest) != content_bin:  # manifest ↔ signed-content binding
        return False
    return verify_skill_signature(content_sha256, signature, signing_key_did)  # publisher signature


async def pack_skill(skill_id: str, chapter_id: str | None = None) -> bytes:
    """Pack a published skill into a signed, portable ``.nandaskill`` bundle
    (bytes of a zip). Reuses the skill's STORED publisher signature — no
    re-signing, no private key — so the bundle carries the exact signature the
    skill was published under.

    Raises ValueError if the skill is absent/revoked, or if the stored
    ``content_sha256`` doesn't match the manifest's canonical bytes (the signed
    content isn't the manifest, so a self-contained bundle can't be built here).
    """
    skill = await get_skill(skill_id, chapter_id)
    if not skill:
        raise SkillInputError(f"skill {skill_id!r} not found")
    if skill.get("revoked_at") is not None:
        raise SkillInputError(f"skill {skill_id!r} is revoked")

    manifest = skill["manifest"]
    content_sha256 = skill["content_sha256"]
    signature = skill["signature"]
    signing_key_did = skill["signing_key_did"]

    content_bin = canonical_content_bytes(manifest)
    if compute_sha256(content_bin) != content_sha256:
        raise SkillInputError(
            f"skill {skill_id!r}: stored content_sha256 does not match the manifest's canonical bytes "
            "— its signed content is not the manifest and cannot be self-contained-packed"
        )

    import io
    import json as _json
    import zipfile

    manifest_readable = _json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
    members = (
        (_PKG_MANIFEST, manifest_readable),
        (_PKG_CONTENT, content_bin),
        (_PKG_SIGNATURE, _signature_json_bytes(content_sha256, signature, signing_key_did)),
    )
    buf = io.BytesIO()
    # Deterministic zip: fixed member order + fixed timestamp, so packing the
    # same skill twice yields byte-identical bundles.
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


async def publish_skill_from_package(
    package_bytes: bytes,
    author_agent_id: str | None = None,
    chapter_id: str | None = None,
) -> dict:
    """Verify a ``.nandaskill`` bundle FAIL-CLOSED, then register it via the
    existing ``publish_skill`` path (which independently re-verifies the
    signature). Raises ValueError on a bad/missing/tampered signature or a
    content-hash mismatch — nothing is registered unless the bundle verifies.
    """
    if not verify_package_signature(package_bytes):
        raise SkillInputError("package verification failed: bad/missing/tampered signature or content_sha256 mismatch")
    manifest, _content, meta = _unpack_package(package_bytes)
    return await publish_skill(
        manifest=manifest,
        signature=meta["signature"],
        signing_key_did=meta["signing_key_did"],
        content_sha256=meta["content_sha256"],
        author_agent_id=author_agent_id,
        chapter_id=chapter_id,
    )


async def install_skill(skill_id: str, agent_id: str, chapter_id: str | None = None) -> dict:
    """Record that `agent_id` has installed `skill_id`.

    Re-verifies the skill's signature + revocation status before persisting.
    Returns an install record including a signed_install_proof token the
    installer can later surface when posting a review.
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized")

    skill = await get_skill(skill_id, chapter_id=chapter_id)
    if not skill:
        raise SkillInputError(f"skill {skill_id!r} not found")
    if skill.get("revoked_at"):
        raise SkillInputError(f"skill {skill_id!r} is revoked — refusing install")

    # Re-verify signature at install time in case data was tampered with.
    if not verify_skill_signature(skill["content_sha256"], skill["signature"], skill["signing_key_did"]):
        raise SkillInputError(f"signature verification failed at install — skill {skill_id!r} blocked")

    # Proof token — hash(agent_id || skill_id || installed_at) so reviews can
    # prove the reviewer actually installed this skill.
    now_iso = datetime.now(UTC).isoformat()
    proof = compute_sha256(f"{agent_id}|{skill_id}|{now_iso}".encode())

    install_row = {
        "agent_id": agent_id,
        "skill_id": skill_id,
        "installed_version": skill["version"],
        "installed_at": now_iso,
    }
    await _pg_request("POST", "chapter_skill_installs", body=install_row)

    return {
        "agent_id": agent_id,
        "skill_id": skill_id,
        "installed_at": now_iso,
        "signed_install_proof": proof,
    }


async def review_skill(
    skill_id: str,
    reviewer_agent_id: str,
    rating: int,
    review_text: str,
    signed_install_proof: str,
) -> dict:
    """Post a review. Requires the reviewer to have installed the skill.

    `signed_install_proof` must match the token returned from install_skill
    (simple HMAC-style proof — for MVP, we require it to be non-empty and
    64-hex; in v1.1 we'll bind it to a short-lived signed JWT).
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized")

    if not (1 <= int(rating) <= 5):
        raise SkillInputError("rating must be in 1..5")
    if not signed_install_proof or not re.fullmatch(r"[0-9a-f]{64}", signed_install_proof):
        raise SkillInputError("invalid or missing signed_install_proof")

    # The reviewer must appear in chapter_skill_installs for this skill.
    install_rows = await _pg_request(
        "GET",
        "chapter_skill_installs",
        params={
            "agent_id": f"eq.{reviewer_agent_id}",
            "skill_id": f"eq.{skill_id}",
            "select": "agent_id",
            "limit": "1",
        },
    )
    if not install_rows:
        raise SkillInputError("reviewer has not installed this skill")

    row = {
        "skill_id": skill_id,
        "reviewer_agent_id": reviewer_agent_id,
        "rating": int(rating),
        "review_text": (review_text or "")[:4000],
        "signed_install_proof": signed_install_proof,
    }
    inserted = await _pg_request("POST", "chapter_skill_reviews", body=row)
    return inserted[0] if isinstance(inserted, list) and inserted else row


async def revoke_skill(skill_id: str, revoked_by_agent_id: str, reason: str) -> dict:
    """Mark a skill revoked. Future installs refuse.

    Authorization (who may revoke) is enforced by the caller — this module
    is the mechanism, not the policy.
    """
    if _pg_request is None:
        raise RuntimeError("skill_registry not initialized")

    patch = {
        "revoked_at": datetime.now(UTC).isoformat(),
        "revocation_reason": (reason or "")[:500],
        "revoked_by_agent_id": revoked_by_agent_id,
    }
    await _pg_request(
        "PATCH",
        "chapter_skills",
        params={"id": f"eq.{skill_id}"},
        body=patch,
    )
    skill = await get_skill(skill_id)
    if not skill:
        raise SkillInputError(f"skill {skill_id!r} not found")
    return skill


# ── Annotations for A2UI surfaces ───────────────────────


def describe_risk(capabilities: list[str]) -> dict[str, Any]:
    """Classify a capability list for display — surfaces use this to render warning callouts.

    Returns {"level": "low|medium|high", "high_risk": [...]}.
    """
    caps = set(capabilities or [])
    hits = caps & HIGH_RISK_CAPABILITIES
    if not hits:
        return {"level": "low", "high_risk": []}
    if len(hits) == 1:
        return {"level": "medium", "high_risk": sorted(hits)}
    return {"level": "high", "high_risk": sorted(hits)}


# ── Open Agent-Skills export (interop, declarative view) ────────────────


def _derive_permissions(capabilities: list[str], explicit: dict | None) -> dict[str, bool]:
    """Coarse permission booleans derived from `capabilities`, overlaid with any
    explicit `permissions` block. Capabilities remain the executable gate; this
    is the declarative projection for the open format."""
    caps = set(capabilities or [])

    def _any(prefixes: tuple[str, ...]) -> bool:
        return any(c == p or c.startswith(p) for c in caps for p in prefixes)

    derived = {
        "network": _any(("net.", "http", "api.")),
        "filesystem": _any(("fs.",)),
        "code_execution": bool(caps & {"shell.exec", "eval.code"}) or _any(("exec", "shell")),
        "external_api": _any(("net.", "api.", "http")),
        "user_data_access": _any(("data.", "user.", "memory")),
    }
    if isinstance(explicit, dict):
        for k in _PERMISSION_KEYS:
            if isinstance(explicit.get(k), bool):
                derived[k] = explicit[k]
    return derived


def _named_entries(items: list, kind: str) -> list[dict]:
    """Coerce our (name, optional-description) entries into the open format's
    (name, non-empty description) shape."""
    out = []
    for it in items or []:
        if isinstance(it, dict) and it.get("name"):
            out.append({"name": it["name"], "description": it.get("description") or f"Skill {kind}: {it['name']}."})
    return out or [{"name": kind, "description": f"Skill {kind}."}]


def to_open_skill(
    manifest: dict, *, author_did: str = "", package_url: str = "", default_license: str = "NOASSERTION"
) -> dict:
    """Project a NANDA skill manifest into the open Agent-Skills shape so the same
    skill is expressible outside NANDA.

    The Ed25519 signature + capability sandbox gate are NANDA-side and have no
    slot in the open *declarative* format — they stay in our registry; this export
    is the declarative view. It always marks ``compatibility.nanda_agentfacts:
    supported`` and fills every required open field, deriving sensible defaults so
    the result is a complete, valid open skill.
    """
    name = (manifest.get("name") or "skill").strip()
    version = manifest.get("version") or "0.0.0"
    category = (manifest.get("category") or "nanda").strip() or "nanda"
    cat_slug = re.sub(r"[^a-z0-9-]+", "-", category.lower()).strip("-") or "nanda"
    description = manifest.get("description") or f"{name} skill"
    caps = list(manifest.get("capabilities") or [])
    risk = describe_risk(caps)
    safety_level = manifest.get("safety_level") or risk["level"]

    maintainers = list(manifest.get("maintainers") or [])
    if not maintainers:
        maintainers = [{"name": author_did or "NANDA author", "contact": author_did or package_url or "n/a"}]

    compatibility = {
        "generic_agents": "supported",
        "claude_skills": "unknown",
        "chatgpt_skills": "unknown",
        "mcp": "unknown",
    }
    compatibility.update(manifest.get("compatibility") or {})
    compatibility["nanda_agentfacts"] = "supported"

    return {
        "id": f"{cat_slug}.{name}",
        "name": name,
        "version": version,
        "category": category,
        "description": description,
        "use_cases": list(manifest.get("use_cases") or []) or [description],
        "inputs": _named_entries(manifest.get("inputs") or [], "input"),
        "outputs": _named_entries(manifest.get("outputs") or [], "output"),
        "required_tools": list(manifest.get("required_tools") or []),
        "permissions": _derive_permissions(caps, manifest.get("permissions")),
        "safety_level": safety_level if safety_level in _SAFETY_LEVELS else "medium",
        "risk_tags": list(manifest.get("risk_tags") or risk["high_risk"]),
        "compatibility": compatibility,
        "provenance": {
            "author": author_did or manifest.get("author_did") or "unknown",
            "source": "Exported from an Orrery skill registry.",
            "references": [r for r in (package_url,) if r],
        },
        "license": manifest.get("license") or default_license,
        "maintainers": maintainers,
        "tests": list(manifest.get("tests") or ["none"]),
    }


def to_open_skill_yaml(manifest: dict, **kwargs) -> str:
    """``to_open_skill`` serialized as YAML. JSON is a valid YAML subset, so this
    needs no YAML dependency and parses with any YAML reader."""
    import json as _json

    return _json.dumps(to_open_skill(manifest, **kwargs), indent=2, ensure_ascii=False)


def tier_from_trust_score(score: float) -> str:
    """Mirror of the member trust tier ladder — reused for skill authors."""
    s = float(score or 0)
    if s >= 75:
        return "power"
    if s >= 50:
        return "trusted"
    if s >= 20:
        return "established"
    return "newcomer"


# ── Marketplace polish helpers (W6) ─────────────────────────


def author_reputation(skills_by_author: dict[str, list[dict]]) -> list[dict]:
    """Rank skill authors by a composite reputation signal.

    Score = 0.4 * log(total_installs + 1) * 10
          + 0.3 * avg_rating * 20
          + 0.2 * skill_count * 5
          + 0.1 * non_revoked_ratio * 100

    Returns a sorted list: [{author_did, skill_count, total_installs,
    avg_rating, non_revoked_ratio, score, tier}, ...]
    """
    import math

    out: list[dict] = []
    for did, skills in skills_by_author.items():
        if not skills:
            continue
        skill_count = len(skills)
        total_installs = sum(int(s.get("install_count") or 0) for s in skills)
        rated = [s for s in skills if s.get("avg_rating") is not None]
        avg_rating = sum(float(s["avg_rating"]) for s in rated) / len(rated) if rated else 0.0
        non_revoked = len([s for s in skills if not s.get("revoked_at")])
        non_revoked_ratio = non_revoked / skill_count

        score = (
            0.4 * math.log(total_installs + 1) * 10
            + 0.3 * avg_rating * 20
            + 0.2 * skill_count * 5
            + 0.1 * non_revoked_ratio * 100
        )
        out.append(
            {
                "author_did": did,
                "skill_count": skill_count,
                "total_installs": total_installs,
                "avg_rating": round(avg_rating, 2) if rated else None,
                "non_revoked_ratio": round(non_revoked_ratio, 2),
                "score": round(score, 1),
                "tier": tier_from_trust_score(score),
            }
        )
    out.sort(key=lambda r: r["score"], reverse=True)
    return out


def featured_skills(skills: list[dict], limit: int = 4) -> list[dict]:
    """Pick the highest-signal skills to surface in a Featured row.

    Prefers: non-revoked, has reviews, install_count >= 1, avg_rating >= 4.
    Falls back to just install_count ordering if no rated skills exist.
    """
    active = [s for s in skills if not s.get("revoked_at")]
    scored = [s for s in active if s.get("avg_rating") and s.get("install_count")]
    if scored:
        scored.sort(
            key=lambda s: (float(s.get("avg_rating") or 0), int(s.get("install_count") or 0)),
            reverse=True,
        )
        return scored[:limit]
    # Fallback — just by install count.
    active.sort(key=lambda s: int(s.get("install_count") or 0), reverse=True)
    return active[:limit]


def category_chips(skills: list[dict]) -> list[dict]:
    """Derive category chips from declared capabilities.

    Returns [{label, value, count}] grouped by top-level capability prefix
    (`fs.*`, `net.*`, `os.*`, `shell.*`, `oauth.*`, ...).
    """
    counts: dict[str, int] = {}
    for s in skills:
        for cap in s.get("capabilities") or []:
            prefix = cap.split(".")[0] if "." in cap else cap
            counts[prefix] = counts.get(prefix, 0) + 1
    return [
        {"label": f"{pref} ({n})", "value": pref, "count": n}
        for pref, n in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    ]
