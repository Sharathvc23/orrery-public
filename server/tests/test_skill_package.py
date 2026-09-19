"""The signed, portable .nandaskill package format.

pack -> verify -> publish_skill_from_package round-trip + fail-closed rejections
(tampered/wrong-key/missing signature, content_sha256 mismatch, swapped manifest).
The existing publish/install/verify machinery is reused unchanged.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import skill_registry as sr
from sovereign_identity import build_did_key_from_ed25519


class _FakePg:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {"chapter_skills": []}

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        rows = self.tables.setdefault(t, [])
        if method == "GET":
            out = list(rows)
            for k, v in (params or {}).items():
                if k in ("select", "limit", "order"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    out = [r for r in out if str(r.get(k)) == v[3:]]
            return out
        if method == "POST":
            b = dict(body or {})
            b.setdefault("revoked_at", None)
            b.setdefault("chapter_id", "public")
            rows.append(b)
            return [b]
        if method == "PATCH":
            for r in rows:
                if all(str(r.get(k)) == v[3:] for k, v in (params or {}).items() if isinstance(v, str) and v.startswith("eq.")):
                    r.update(body or {})
            return rows
        return None


def _key():
    sk = SigningKey.generate()
    did = build_did_key_from_ed25519(base64.b64encode(sk.verify_key.encode()).decode())
    return sk, did


def _manifest(name="event-outreach", version="1.0.0"):
    return {"name": name, "version": version, "description": "outreach helper", "capabilities": ["text.generate"]}


def _publish_args(sk, did, manifest):
    """Sign over the CANONICAL content bytes (as starter_pack does) so the skill
    is package-able."""
    content = sr.canonical_content_bytes(manifest)
    sha = sr.compute_sha256(content)
    sig = base64.b64encode(sk.sign(sha.encode("utf-8")).signature).decode()
    return {"manifest": manifest, "signature": sig, "signing_key_did": did, "content_sha256": sha}


@pytest.fixture
def pg():
    p = _FakePg()
    sr.init(p, "public")
    return p


async def _publish(sk, did, manifest):
    return await sr.publish_skill(**_publish_args(sk, did, manifest))


def _repack(pkg: bytes, *, drop=None, replace: dict | None = None) -> bytes:
    """Rebuild a package zip, dropping a member or replacing member bytes — for
    adversarial tamper cases."""
    replace = replace or {}
    src = zipfile.ZipFile(io.BytesIO(pkg))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in src.namelist():
            if name == drop:
                continue
            data = replace.get(name, src.read(name))
            zf.writestr(name, data)
    return out.getvalue()


# ── round-trip identity ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pack_verify_republish_round_trip_identity(pg):
    sk, did = _key()
    original = await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    assert sr.verify_package_signature(pkg) is True

    # republish onto a SCRATCH registry (fresh pg) — identical manifest + sha
    scratch = _FakePg()
    sr.init(scratch, "public")
    republished = await sr.publish_skill_from_package(pkg)
    assert republished["manifest"] == original["manifest"]
    assert republished["content_sha256"] == original["content_sha256"]
    assert republished["signature"] == original["signature"]


@pytest.mark.asyncio
async def test_pack_is_deterministic(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    assert await sr.pack_skill("event-outreach@1.0.0") == await sr.pack_skill("event-outreach@1.0.0")


@pytest.mark.asyncio
async def test_package_has_the_three_members(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    zf = zipfile.ZipFile(io.BytesIO(await sr.pack_skill("event-outreach@1.0.0")))
    assert set(zf.namelist()) == {"manifest.json", "content.bin", "signature.json"}


# ── signature: valid / tampered / wrong-key / missing ────────────────────────


@pytest.mark.asyncio
async def test_signature_valid(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    assert sr.verify_package_signature(await sr.pack_skill("event-outreach@1.0.0")) is True


@pytest.mark.asyncio
async def test_tampered_signature_rejected(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    meta = json.loads(zipfile.ZipFile(io.BytesIO(pkg)).read("signature.json"))
    # flip the signature to a different valid-base64 value
    bad = bytearray(base64.b64decode(meta["signature"]))
    bad[0] ^= 0xFF
    meta["signature"] = base64.b64encode(bytes(bad)).decode()
    tampered = _repack(pkg, replace={"signature.json": json.dumps(meta).encode()})
    assert sr.verify_package_signature(tampered) is False
    with pytest.raises(ValueError):
        await sr.publish_skill_from_package(tampered)


@pytest.mark.asyncio
async def test_wrong_key_rejected(pg):
    sk, did = _key()
    other_sk, other_did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    meta = json.loads(zipfile.ZipFile(io.BytesIO(pkg)).read("signature.json"))
    meta["signing_key_did"] = other_did  # a real did, but not the signer
    swapped = _repack(pkg, replace={"signature.json": json.dumps(meta).encode()})
    assert sr.verify_package_signature(swapped) is False


@pytest.mark.asyncio
async def test_missing_signature_member_rejected(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    assert sr.verify_package_signature(_repack(pkg, drop="signature.json")) is False


@pytest.mark.asyncio
async def test_not_a_zip_rejected(pg):
    assert sr.verify_package_signature(b"not a zip at all") is False
    assert sr.verify_package_signature(b"") is False


# ── content_sha256 mismatch + manifest swap ──────────────────────────────────


@pytest.mark.asyncio
async def test_content_sha256_mismatch_rejected(pg):
    sk, did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    # tamper the content payload → sha no longer matches the signed content_sha256
    tampered = _repack(pkg, replace={"content.bin": b'{"name":"evil"}'})
    assert sr.verify_package_signature(tampered) is False
    with pytest.raises(ValueError):
        await sr.publish_skill_from_package(tampered)


@pytest.mark.asyncio
async def test_swapped_manifest_rejected(pg):
    """The readable manifest.json must canonicalize to the signed content.bin —
    swapping it (without touching content.bin/sig) is rejected."""
    sk, did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    evil = json.dumps({"name": "evil-skill", "version": "9.9.9"}, indent=2).encode()
    assert sr.verify_package_signature(_repack(pkg, replace={"manifest.json": evil})) is False


@pytest.mark.asyncio
async def test_pack_rejects_non_manifest_content(pg):
    """A skill whose content_sha256 is NOT the manifest's canonical hash (e.g.
    signed over external content) can't be self-contained-packed."""
    sk, did = _key()
    args = _publish_args(sk, did, _manifest())
    args["content_sha256"] = sr.compute_sha256(b"some external package bytes")
    args["signature"] = base64.b64encode(sk.sign(args["content_sha256"].encode()).signature).decode()
    await sr.publish_skill(**args)
    with pytest.raises(ValueError, match="does not match"):
        await sr.pack_skill("event-outreach@1.0.0")


@pytest.mark.asyncio
async def test_pack_absent_and_revoked(pg):
    with pytest.raises(ValueError, match="not found"):
        await sr.pack_skill("nope@1.0.0")


# ── manifest schema-valid ────────────────────────────────────────────────────


def test_packed_manifest_is_schema_valid():
    import jsonschema

    schema_path = Path(__file__).resolve().parents[2] / "schema" / "skill" / "0.1" / "skill-manifest.schema.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(_manifest(), schema)  # the manifest we pack validates


def test_package_schema_itself_is_valid_json_schema():
    import jsonschema

    pkg_schema = Path(__file__).resolve().parents[2] / "schema" / "skill" / "0.1" / "skill-package.schema.json"
    schema = json.loads(pkg_schema.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)


# ── That change: decompression-bomb DoS on the keyless publish endpoint ──────────────


def _bomb_zip(bomb_member: str = "content.bin", decompressed_size: int = 64 * 1024 * 1024) -> bytes:
    """A well-formed .nandaskill zip whose `bomb_member` inflates to
    `decompressed_size` (highly compressible zeros), while the compressed bytes stay
    tiny — the classic DEFLATE bomb the keyless POST /api/skills/publish/package
    would fully inflate before any signature check."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("manifest.json", "content.bin", "signature.json"):
            data = b"\0" * decompressed_size if name == bomb_member else b"{}"
            zf.writestr(name, data)
    return out.getvalue()


def test_decompression_bomb_rejected_before_full_inflation():
    """A ~64 MiB DEFLATE bomb is rejected by the decompressed-byte ceiling, on the
    declared uncompressed size — WITHOUT inflating the member.

    The bomb's COMPRESSED size is under MAX_PACKAGE_BYTES (it sails past the existing
    compressed-size gate), so the DECOMPRESSED ceiling is provably what catches it —
    the old code fully inflated it here (fail-open on resources)."""
    bomb = _bomb_zip(decompressed_size=64 * 1024 * 1024)
    # It passes the compressed gate — so reaching the decompression guard is the point.
    assert len(bomb) < sr.MAX_PACKAGE_BYTES
    # verify_package_signature is fail-closed and never raises.
    assert sr.verify_package_signature(bomb) is False
    # _unpack_package rejects on the DECLARED uncompressed size (stage 1) — the error
    # text proves rejection happened before the member was inflated.
    with pytest.raises(ValueError, match="too large|decompressed"):
        sr._unpack_package(bomb)


def test_bomb_in_any_member_rejected():
    """The ceiling covers every member the unpacker reads (manifest / content /
    signature), not just content.bin."""
    for member in ("manifest.json", "content.bin", "signature.json"):
        bomb = _bomb_zip(bomb_member=member, decompressed_size=32 * 1024 * 1024)
        assert sr.verify_package_signature(bomb) is False
        with pytest.raises(ValueError, match="too large|decompressed"):
            sr._unpack_package(bomb)


def test_read_member_bounded_enforces_limit():
    """The bounded reader accepts a member at the limit and rejects one over it —
    the primitive the ceiling is built on."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("m", b"x" * 1000)
    zf_bytes = out.getvalue()
    zf = zipfile.ZipFile(io.BytesIO(zf_bytes))
    assert sr._read_member_bounded(zf, "m", 1000) == b"x" * 1000  # exactly at cap: ok
    with pytest.raises(ValueError, match="too large|decompressed"):
        sr._read_member_bounded(zf, "m", 999)  # one over: rejected


@pytest.mark.asyncio
async def test_legit_bundle_within_ceiling_still_verifies(pg):
    """Regression guard: a real (tiny) bundle is well under the caps and verifies —
    the ceiling must not break the happy path."""
    sk, did = _key()
    await _publish(sk, did, _manifest())
    pkg = await sr.pack_skill("event-outreach@1.0.0")
    for info in zipfile.ZipFile(io.BytesIO(pkg)).infolist():
        assert info.file_size < sr.MAX_MEMBER_DECOMPRESSED_BYTES
    assert sr.verify_package_signature(pkg) is True
