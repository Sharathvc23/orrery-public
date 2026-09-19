"""
Prosecution-grade tests for community_member.skills — local skill loader.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL

Every signature gate, every size bound, every revocation check, every
path-traversal defense gets a hostile test. This module's thesis is
"no unsigned, tampered, or revoked skill ever installs" — so the tests
must prove those rejections are real.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from community_member import skills as sk

# ─── Helpers ───────────────────────────────────────────


def _make_keypair() -> tuple[SigningKey, str]:
    """Return a test keypair + its did:key."""
    sk_key = SigningKey.generate()
    pub_b64 = base64.b64encode(sk_key.verify_key.encode()).decode()
    # Reuse production did:key builder so we're testing the real decoder.
    from community_member.crypto import build_did_key

    return sk_key, build_did_key(pub_b64)


def _sign_over(sk_key: SigningKey, hex_sha: str) -> str:
    signed = sk_key.sign(hex_sha.encode("utf-8"))
    return base64.b64encode(signed.signature).decode()


def _manifest_bytes(name: str = "file-ops", version: str = "1.0.0", **extra) -> bytes:
    manifest = {
        "name": name,
        "version": version,
        "description": "sandboxed file operations",
        "capabilities": ["fs.read", "fs.write"],
        "author_did": extra.get("author_did", "did:key:z6MkPlaceholder"),
    }
    manifest.update({k: v for k, v in extra.items() if k != "author_did"})
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


@pytest.fixture
def tmp_skills_root(tmp_path, monkeypatch):
    """Isolate ~/.nanda/skills to a per-test temp directory."""
    root = tmp_path / "skills"
    monkeypatch.setattr(sk, "SKILLS_ROOT", root)
    monkeypatch.setattr(sk, "REGISTRY_PATH", root / "registry.json")
    return root


# ═══════════════════════════════════════════════════════════════
# extract_ed25519_pubkey_from_did_key
# ═══════════════════════════════════════════════════════════════


def test_extract_pubkey_happy():
    _, did = _make_keypair()
    pubkey = sk.extract_ed25519_pubkey_from_did_key(did)
    assert pubkey is not None
    assert len(pubkey) == 32


def test_extract_pubkey_rejects_none_and_empty():
    assert sk.extract_ed25519_pubkey_from_did_key("") is None
    assert sk.extract_ed25519_pubkey_from_did_key(None) is None  # type: ignore[arg-type]


def test_extract_pubkey_rejects_wrong_prefix():
    assert sk.extract_ed25519_pubkey_from_did_key("did:web:example.com") is None
    assert sk.extract_ed25519_pubkey_from_did_key("did:key:zINVALID") is None


def test_extract_pubkey_rejects_short_payload():
    # Valid did:key prefix but too-short base58 — decodes to wrong length.
    assert sk.extract_ed25519_pubkey_from_did_key("did:key:zQ3") is None


# ═══════════════════════════════════════════════════════════════
# verify_signed_package — the whole gate
# ═══════════════════════════════════════════════════════════════


def test_verify_happy():
    sk_key, did = _make_keypair()
    content = _manifest_bytes()
    sha = hashlib.sha256(content).hexdigest()
    sig = _sign_over(sk_key, sha)
    ok, reason = sk.verify_signed_package(content, sha, sig, did)
    assert ok, reason


def test_verify_rejects_tampered_content():
    """ADVERSARIAL: attacker swaps content but keeps the signature."""
    sk_key, did = _make_keypair()
    content_good = _manifest_bytes()
    content_bad = _manifest_bytes(description="malicious payload")
    sha_good = hashlib.sha256(content_good).hexdigest()
    sig_over_good = _sign_over(sk_key, sha_good)
    ok, reason = sk.verify_signed_package(content_bad, sha_good, sig_over_good, did)
    assert ok is False
    assert "mismatch" in reason


def test_verify_rejects_sha_mismatch_from_chapter():
    """ADVERSARIAL: chapter says sha=X, we compute sha=Y — refuse."""
    sk_key, did = _make_keypair()
    content = _manifest_bytes()
    actual_sha = hashlib.sha256(content).hexdigest()
    fake_sha = "f" * 64
    sig = _sign_over(sk_key, fake_sha)
    ok, reason = sk.verify_signed_package(content, fake_sha, sig, did)
    assert ok is False
    assert "mismatch" in reason
    assert actual_sha in reason  # good diagnostic


def test_verify_rejects_forged_signature_from_wrong_key():
    """ADVERSARIAL: signature made by Alice's key, did claims Bob's key."""
    sk_alice, _ = _make_keypair()
    _, did_bob = _make_keypair()
    content = _manifest_bytes()
    sha = hashlib.sha256(content).hexdigest()
    sig_by_alice = _sign_over(sk_alice, sha)
    ok, reason = sk.verify_signed_package(content, sha, sig_by_alice, did_bob)
    assert ok is False
    assert "signature" in reason.lower()


def test_verify_rejects_random_signature_bytes():
    """ADVERSARIAL: attacker submits random 64 bytes as signature."""
    _, did = _make_keypair()
    content = _manifest_bytes()
    sha = hashlib.sha256(content).hexdigest()
    forged = base64.b64encode(b"A" * 64).decode()
    ok, reason = sk.verify_signed_package(content, sha, forged, did)
    assert ok is False


def test_verify_rejects_malformed_sha():
    sk_key, did = _make_keypair()
    content = _manifest_bytes()
    sig = _sign_over(sk_key, "f" * 64)
    for bad_sha in ["", "short", "Z" * 64, "not-hex!" * 8]:
        ok, reason = sk.verify_signed_package(content, bad_sha, sig, did)
        assert ok is False, f"accepted malformed sha: {bad_sha!r}"


def test_verify_rejects_empty_content():
    sk_key, did = _make_keypair()
    sha = hashlib.sha256(b"").hexdigest()
    sig = _sign_over(sk_key, sha)
    ok, reason = sk.verify_signed_package(b"", sha, sig, did)
    assert ok is False
    assert "empty" in reason.lower()


def test_verify_rejects_oversized_content():
    """ADVERSARIAL: 16 MiB content rejected (limit is 8 MiB)."""
    sk_key, did = _make_keypair()
    huge = b"x" * (16 * 1024 * 1024)
    sha = hashlib.sha256(huge).hexdigest()
    sig = _sign_over(sk_key, sha)
    ok, reason = sk.verify_signed_package(huge, sha, sig, did)
    assert ok is False
    assert "too large" in reason


def test_verify_rejects_malformed_did():
    content = _manifest_bytes()
    sha = hashlib.sha256(content).hexdigest()
    for bad_did in ["", "did:web:a", "did:key:bogus", "not-a-did"]:
        ok, _ = sk.verify_signed_package(content, sha, "irrelevant", bad_did)
        assert ok is False


# ═══════════════════════════════════════════════════════════════
# Registry I/O
# ═══════════════════════════════════════════════════════════════


def test_load_registry_empty_when_missing(tmp_skills_root):
    assert sk.load_installed_registry() == {}


def test_save_and_load_roundtrip(tmp_skills_root):
    entries = {"file-ops@1.0.0": {"skill_id": "file-ops@1.0.0", "capabilities": ["fs.read"]}}
    sk.save_installed_registry(entries)
    assert sk.load_installed_registry() == entries


def test_load_registry_survives_corrupt_file(tmp_skills_root):
    """EDGE: corrupt registry.json — don't crash the agent, return empty."""
    tmp_skills_root.mkdir(parents=True, exist_ok=True)
    (tmp_skills_root / "registry.json").write_text("{not valid json")
    assert sk.load_installed_registry() == {}


def test_registry_file_permissions(tmp_skills_root):
    """ADVERSARIAL: registry file must be mode 0600 — it contains install proofs."""
    sk.save_installed_registry({"x": {}})
    mode = sk.REGISTRY_PATH.stat().st_mode & 0o777
    assert mode == 0o600, f"registry.json mode is {oct(mode)}, expected 0o600"


# ═══════════════════════════════════════════════════════════════
# install_skill — end-to-end with injected chapter API
# ═══════════════════════════════════════════════════════════════


def _fake_chapter_api(skills_db: dict[str, dict]):
    """Return a chapter_api_fn that mimics /api/skills endpoints from a dict."""
    call_log: list[tuple] = []

    def api(method: str, path: str, body=None):
        call_log.append((method, path, body))
        if method == "POST" and "/install" in path:
            skill_id = path.replace("/api/skills/", "").replace("/install", "")
            if skill_id not in skills_db:
                raise RuntimeError(f"skill_not_found: {skill_id}")
            return {
                "agent_id": body["agent_id"],
                "skill_id": skill_id,
                "signed_install_proof": hashlib.sha256(f"{body['agent_id']}|{skill_id}|install".encode()).hexdigest(),
            }
        if method == "GET" and path.startswith("/api/skills/"):
            skill_id = path.replace("/api/skills/", "")
            if skill_id not in skills_db:
                return {"skill": None}
            return {"skill": skills_db[skill_id]}
        return {}

    api.call_log = call_log  # type: ignore[attr-defined]
    return api


def _published_skill(sk_key: SigningKey, did: str, manifest_overrides: dict | None = None) -> dict:
    """Build a skill record as it would appear in /api/skills/{id}."""
    manifest = {
        "name": "file-ops",
        "version": "1.0.0",
        "description": "safe file operations",
        "capabilities": ["fs.read", "fs.write"],
        "author_did": did,
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    canonical = {**manifest, "author_did": did}
    content = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(content).hexdigest()
    sig = _sign_over(sk_key, sha)
    return {
        "id": f"{manifest['name']}@{manifest['version']}",
        "name": manifest["name"],
        "version": manifest["version"],
        "manifest": manifest,
        "author_did": did,
        "capabilities": manifest["capabilities"],
        "content_sha256": sha,
        "signature": sig,
        "signing_key_did": did,
        "package_url": None,  # manifest-is-package mode
        "revoked_at": None,
    }


def test_install_happy(tmp_skills_root):
    sk_key, did = _make_keypair()
    skill_record = _published_skill(sk_key, did)
    api = _fake_chapter_api({"file-ops@1.0.0": skill_record})

    entry = sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=api,
        skills_root=tmp_skills_root,
    )
    assert entry["skill_id"] == "file-ops@1.0.0"
    assert entry["installed_version"] == "1.0.0"
    assert len(entry["install_proof"]) == 64
    assert Path(entry["path"]).exists()
    # Registry persisted.
    registry = sk.load_installed_registry()
    assert "file-ops@1.0.0" in registry


def test_install_refuses_invalid_skill_id_format():
    with pytest.raises(ValueError, match="invalid skill_id"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="BAD ID",
            agent_id="alice",
            chapter_api_fn=lambda *a: {},
        )


def test_install_refuses_revoked_skill(tmp_skills_root):
    sk_key, did = _make_keypair()
    skill_record = _published_skill(sk_key, did)
    skill_record["revoked_at"] = "2026-04-20T00:00:00Z"
    skill_record["revocation_reason"] = "CVE-2026-XXX"
    api = _fake_chapter_api({"file-ops@1.0.0": skill_record})

    with pytest.raises(ValueError, match="revoked"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="file-ops@1.0.0",
            agent_id="alice",
            chapter_api_fn=api,
            skills_root=tmp_skills_root,
        )
    assert sk.load_installed_registry() == {}


def test_install_refuses_tampered_manifest(tmp_skills_root):
    """ADVERSARIAL: chapter returns a manifest with the sig from a DIFFERENT manifest."""
    sk_key, did = _make_keypair()
    skill_record = _published_skill(sk_key, did)
    # Mutate the manifest description but keep the old signature/sha.
    skill_record["manifest"]["description"] = "evil payload"
    api = _fake_chapter_api({"file-ops@1.0.0": skill_record})

    with pytest.raises(ValueError, match="signature verification failed"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="file-ops@1.0.0",
            agent_id="alice",
            chapter_api_fn=api,
            skills_root=tmp_skills_root,
        )


def test_install_refuses_forged_signing_key(tmp_skills_root):
    """ADVERSARIAL: skill claims one did:key, signature made by another."""
    sk_alice, did_alice = _make_keypair()
    _, did_bob = _make_keypair()
    skill_record = _published_skill(sk_alice, did_alice)
    skill_record["signing_key_did"] = did_bob  # lie: say Bob signed it
    api = _fake_chapter_api({"file-ops@1.0.0": skill_record})

    with pytest.raises(ValueError, match="signature verification failed"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="file-ops@1.0.0",
            agent_id="alice",
            chapter_api_fn=api,
            skills_root=tmp_skills_root,
        )


def test_install_refuses_missing_install_proof(tmp_skills_root):
    """FAILURE: chapter response lacks install_proof — refuse before downloading."""
    sk_key, did = _make_keypair()
    skill_record = _published_skill(sk_key, did)

    def bad_api(method, path, body=None):
        if "install" in path:
            return {"agent_id": "alice", "skill_id": "file-ops@1.0.0"}  # no proof
        return {"skill": skill_record}

    with pytest.raises(ValueError, match="install_proof"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="file-ops@1.0.0",
            agent_id="alice",
            chapter_api_fn=bad_api,
            skills_root=tmp_skills_root,
        )


def test_install_with_tarball_rejects_path_traversal(tmp_skills_root):
    """ADVERSARIAL: tarball with '../' members must be refused."""
    sk_key, did = _make_keypair()

    # Build a real tarball with a path-traversing member.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("../../../etc/passwd")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"evil\n"))
    evil_tarball = buf.getvalue()
    sha = hashlib.sha256(evil_tarball).hexdigest()
    sig = _sign_over(sk_key, sha)

    skill_record = {
        "id": "malicious@1.0.0",
        "name": "malicious",
        "version": "1.0.0",
        "manifest": {"name": "malicious", "version": "1.0.0", "capabilities": []},
        "author_did": did,
        "capabilities": [],
        "content_sha256": sha,
        "signature": sig,
        "signing_key_did": did,
        "package_url": "https://example.com/malicious.nandaskill",
        "revoked_at": None,
    }

    api = _fake_chapter_api({"malicious@1.0.0": skill_record})

    with pytest.raises(ValueError, match="path-traversing"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="malicious@1.0.0",
            agent_id="alice",
            chapter_api_fn=api,
            download_fn=lambda _url: evil_tarball,
            skills_root=tmp_skills_root,
        )


def test_install_with_tarball_rejects_symlink(tmp_skills_root):
    """ADVERSARIAL: tarball containing a symlink member must be refused."""
    sk_key, did = _make_keypair()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    evil = buf.getvalue()
    sha = hashlib.sha256(evil).hexdigest()
    sig = _sign_over(sk_key, sha)

    skill_record = {
        "id": "sneaky@1.0.0",
        "name": "sneaky",
        "version": "1.0.0",
        "manifest": {"name": "sneaky", "version": "1.0.0", "capabilities": []},
        "author_did": did,
        "capabilities": [],
        "content_sha256": sha,
        "signature": sig,
        "signing_key_did": did,
        "package_url": "https://example.com/sneaky.nandaskill",
        "revoked_at": None,
    }

    api = _fake_chapter_api({"sneaky@1.0.0": skill_record})

    with pytest.raises(ValueError, match="symlink"):
        sk.install_skill(
            chapter_url="https://chapter.example",
            skill_id="sneaky@1.0.0",
            agent_id="alice",
            chapter_api_fn=api,
            download_fn=lambda _url: evil,
            skills_root=tmp_skills_root,
        )


# ═══════════════════════════════════════════════════════════════
# uninstall + revocation
# ═══════════════════════════════════════════════════════════════


def test_uninstall_soft_preserves_disk(tmp_skills_root):
    sk_key, did = _make_keypair()
    api = _fake_chapter_api({"file-ops@1.0.0": _published_skill(sk_key, did)})
    entry = sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=api,
        skills_root=tmp_skills_root,
    )
    path = Path(entry["path"])
    sk.uninstall_skill("file-ops@1.0.0", skills_root=tmp_skills_root)

    # Registry entry gone, disk preserved.
    assert "file-ops@1.0.0" not in sk.load_installed_registry()
    assert path.exists()


def test_uninstall_hard_deletes_disk(tmp_skills_root):
    sk_key, did = _make_keypair()
    api = _fake_chapter_api({"file-ops@1.0.0": _published_skill(sk_key, did)})
    entry = sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=api,
        skills_root=tmp_skills_root,
    )
    path = Path(entry["path"])
    sk.uninstall_skill("file-ops@1.0.0", skills_root=tmp_skills_root, hard_delete=True)

    assert "file-ops@1.0.0" not in sk.load_installed_registry()
    assert not path.exists()


def test_uninstall_unknown_skill_raises(tmp_skills_root):
    with pytest.raises(ValueError, match="not installed"):
        sk.uninstall_skill("ghost@9.9.9", skills_root=tmp_skills_root)


def test_check_revocations_detects_revoked(tmp_skills_root):
    """HAPPY: skill installed, chapter later revokes it, startup check catches."""
    sk_key, did = _make_keypair()
    skill = _published_skill(sk_key, did)
    api = _fake_chapter_api({"file-ops@1.0.0": skill})

    sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=api,
        skills_root=tmp_skills_root,
    )

    # Chapter revokes the skill.
    skill["revoked_at"] = "2026-04-20T00:00:00Z"

    revoked = sk.check_revocations_at_startup(chapter_api_fn=api)
    assert revoked == ["file-ops@1.0.0"]


def test_check_revocations_survives_chapter_outage(tmp_skills_root):
    """EDGE: chapter unreachable — don't mass-uninstall on transient errors."""
    sk_key, did = _make_keypair()
    api = _fake_chapter_api({"file-ops@1.0.0": _published_skill(sk_key, did)})
    sk.install_skill(
        chapter_url="https://chapter.example",
        skill_id="file-ops@1.0.0",
        agent_id="alice",
        chapter_api_fn=api,
        skills_root=tmp_skills_root,
    )

    def broken_api(*a, **kw):
        raise ConnectionError("chapter offline")

    revoked = sk.check_revocations_at_startup(chapter_api_fn=broken_api)
    assert revoked == []  # transient — don't unregister anything
