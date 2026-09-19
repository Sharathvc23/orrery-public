"""
Prosecution-grade tests for skill_registry.py — signed skill catalog.

Every feature is paired with forgery / malformed / revocation tests.
The registry's whole thesis is "no unsigned skills, ever" — so a
passing test suite has to prove those rejections are real.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

import pytest
from nacl.signing import SigningKey

import skill_registry as sr
from sovereign_identity import build_did_key_from_ed25519

# ─── Test infrastructure ────────────────────────────────


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "chapter_skills": [],
            "chapter_skill_reviews": [],
            "chapter_skill_installs": [],
        }
        self.calls_log: list[tuple] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        self.calls_log.append((method, table_or_path, params, body))
        table = table_or_path.split("?")[0]

        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows

        if method == "POST":
            body = dict(body or {})
            body.setdefault("id", body.get("id") or f"id-{len(self.tables[table]) + 1}")
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            body.setdefault("install_count", 0)
            body.setdefault("trust_score", 0)
            body.setdefault("revoked_at", None)
            body.setdefault("chapter_id", body.get("chapter_id") or "public")
            # Emulate trigger: bump install_count when install row added.
            if table == "chapter_skill_installs":
                for s in self.tables["chapter_skills"]:
                    if s["id"] == body.get("skill_id"):
                        s["install_count"] += 1
            self.tables.setdefault(table, []).append(body)
            return [body]

        if method == "PATCH":
            filters = self._parse_path_filters(table_or_path, params)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched

        return None

    @staticmethod
    def _parse_path_filters(path, params):
        out: dict[str, str] = {}
        if "?" in path:
            _, qs = path.split("?", 1)
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    out[k] = v
        if params:
            for k, v in params.items():
                if k not in ("select", "order", "limit"):
                    out[k] = str(v)
        return out

    def _filter(self, rows, params):
        out = []
        for row in rows:
            ok = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                if not self._match(row, k, v):
                    ok = False
                    break
            if ok:
                out.append(row)
        order = params.get("order") if params else None
        if order:
            key = order.split(",")[0].split(".")[0]
            reverse = "desc" in order
            out.sort(key=lambda r: r.get(key) or "", reverse=reverse)
        limit = params.get("limit") if params else None
        if limit:
            out = out[: int(limit)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in str(predicate):
            return row.get(key) == predicate
        op, val = str(predicate).split(".", 1)
        rv = row.get(key)
        if op == "eq":
            return str(rv) == val
        if op == "is" and val == "null":
            return rv is None
        if op == "gte":
            try:
                return float(rv or 0) >= float(val)
            except (TypeError, ValueError):
                return False
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    sr.init(pg_request_fn=sb, chapter_id="public")
    return sb


# ─── Crypto helpers for the test itself ──────────────────


def _make_signing_key() -> tuple[SigningKey, str]:
    """Return a test keypair + its did:key."""
    sk = SigningKey.generate()
    pub_b64 = base64.b64encode(sk.verify_key.encode()).decode()
    return sk, build_did_key_from_ed25519(pub_b64)


def _sign_sha(sk: SigningKey, sha256_hex: str) -> str:
    signed = sk.sign(sha256_hex.encode("utf-8"))
    return base64.b64encode(signed.signature).decode()


def _valid_manifest(name="file-ops", version="1.0.0", **overrides) -> dict:
    m = {
        "name": name,
        "version": version,
        "description": "safe file operations",
        "capabilities": ["fs.read", "fs.write"],
        "readme_markdown": "# file-ops\n\nRead and write files in a sandbox.",
    }
    m.update(overrides)
    return m


def _publish_args(sk: SigningKey, did: str, manifest: dict | None = None) -> dict:
    manifest = manifest or _valid_manifest()
    content = str(manifest).encode("utf-8")
    sha = hashlib.sha256(content).hexdigest()
    sig = _sign_sha(sk, sha)
    return {
        "manifest": manifest,
        "signature": sig,
        "signing_key_did": did,
        "content_sha256": sha,
    }


# ═══════════════════════════════════════════════════════
# verify_skill_signature — pure crypto layer
# ═══════════════════════════════════════════════════════


def test_verify_valid_signature():
    sk, did = _make_signing_key()
    sha = hashlib.sha256(b"whatever").hexdigest()
    sig = _sign_sha(sk, sha)
    assert sr.verify_skill_signature(sha, sig, did) is True


def test_verify_rejects_wrong_content():
    """ADVERSARIAL: signature valid for sha_A, presented with sha_B → reject."""
    sk, did = _make_signing_key()
    sha_a = hashlib.sha256(b"a").hexdigest()
    sha_b = hashlib.sha256(b"b").hexdigest()
    sig_a = _sign_sha(sk, sha_a)
    assert sr.verify_skill_signature(sha_b, sig_a, did) is False


def test_verify_rejects_wrong_key():
    """ADVERSARIAL: signature by key_A, did of key_B → reject."""
    sk_a, _ = _make_signing_key()
    _, did_b = _make_signing_key()
    sha = hashlib.sha256(b"x").hexdigest()
    sig = _sign_sha(sk_a, sha)
    assert sr.verify_skill_signature(sha, sig, did_b) is False


def test_verify_rejects_malformed_sha():
    sk, did = _make_signing_key()
    sig = _sign_sha(sk, "a" * 64)
    # Not-hex sha
    assert sr.verify_skill_signature("Z" * 64, sig, did) is False
    # Wrong length
    assert sr.verify_skill_signature("abcd", sig, did) is False
    # Empty
    assert sr.verify_skill_signature("", sig, did) is False


def test_verify_rejects_malformed_did():
    sk, _ = _make_signing_key()
    sha = hashlib.sha256(b"z").hexdigest()
    sig = _sign_sha(sk, sha)
    assert sr.verify_skill_signature(sha, sig, "not-a-did-key") is False
    assert sr.verify_skill_signature(sha, sig, "") is False
    assert sr.verify_skill_signature(sha, sig, "did:key:zBAD") is False


def test_verify_rejects_forged_signature_bytes():
    """ADVERSARIAL: random bytes presented as signature → reject."""
    _, did = _make_signing_key()
    sha = hashlib.sha256(b"x").hexdigest()
    forged = base64.b64encode(b"A" * 64).decode()
    assert sr.verify_skill_signature(sha, forged, did) is False


# ═══════════════════════════════════════════════════════
# publish_skill — registration + validation
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_publish_happy(env):
    sk, did = _make_signing_key()
    args = _publish_args(sk, did)
    result = await sr.publish_skill(**args)
    assert result["id"] == "file-ops@1.0.0"
    assert result["author_did"] == did
    assert result["signing_key_did"] == did
    assert result["capabilities"] == ["fs.read", "fs.write"]
    assert env.tables["chapter_skills"][0]["id"] == "file-ops@1.0.0"


@pytest.mark.asyncio
async def test_publish_rejects_forged_signature(env):
    """ADVERSARIAL: signed by key A but claims did of key B → reject."""
    sk_a, _ = _make_signing_key()
    _, did_b = _make_signing_key()
    args = _publish_args(sk_a, did_b)
    with pytest.raises(ValueError, match="invalid Ed25519 signature"):
        await sr.publish_skill(**args)
    assert env.tables["chapter_skills"] == []


@pytest.mark.asyncio
async def test_publish_rejects_signature_over_different_content(env):
    """ADVERSARIAL: signature is valid for some content but not the declared sha."""
    sk, did = _make_signing_key()
    sig = _sign_sha(sk, hashlib.sha256(b"other").hexdigest())
    with pytest.raises(ValueError, match="invalid Ed25519 signature"):
        await sr.publish_skill(
            manifest=_valid_manifest(),
            signature=sig,
            signing_key_did=did,
            content_sha256=hashlib.sha256(b"declared").hexdigest(),
        )


@pytest.mark.asyncio
async def test_publish_rejects_bad_name(env):
    sk, did = _make_signing_key()
    for bad_name in ["Bad-Name", "UPPERCASE", "1leading-digit", "with space", "-start-dash"]:
        m = _valid_manifest(name=bad_name)
        args = _publish_args(sk, did, manifest=m)
        with pytest.raises(ValueError, match="invalid name"):
            await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_rejects_bad_version(env):
    sk, did = _make_signing_key()
    for bad in ["1", "1.0", "v1.0.0", "1.0.0.0", "latest"]:
        m = _valid_manifest(version=bad)
        args = _publish_args(sk, did, manifest=m)
        with pytest.raises(ValueError, match="invalid version"):
            await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_rejects_too_many_capabilities(env):
    """EDGE: 33 capabilities exceeds the cap of 32."""
    sk, did = _make_signing_key()
    m = _valid_manifest(capabilities=[f"cap.{i}" for i in range(33)])
    args = _publish_args(sk, did, manifest=m)
    with pytest.raises(ValueError, match="capabilities"):
        await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_rejects_bad_capability_format(env):
    sk, did = _make_signing_key()
    m = _valid_manifest(capabilities=["BAD CAP", "fs.read"])
    args = _publish_args(sk, did, manifest=m)
    with pytest.raises(ValueError, match="invalid capability"):
        await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_rejects_oversized_readme(env):
    """ADVERSARIAL: 257 KiB readme exceeds the hard limit."""
    sk, did = _make_signing_key()
    huge = "x" * (257 * 1024)
    m = _valid_manifest(readme_markdown=huge)
    args = _publish_args(sk, did, manifest=m)
    with pytest.raises(ValueError, match="readme too large"):
        await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_rejects_duplicate_version(env):
    """FAILURE: publishing the same name@version twice without bumping → error."""
    sk, did = _make_signing_key()
    args = _publish_args(sk, did)
    await sr.publish_skill(**args)
    with pytest.raises(ValueError, match="already published"):
        await sr.publish_skill(**args)


@pytest.mark.asyncio
async def test_publish_allows_bumped_version(env):
    sk, did = _make_signing_key()
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(version="1.0.0")))
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(version="1.0.1")))
    assert len(env.tables["chapter_skills"]) == 2


# ═══════════════════════════════════════════════════════
# list / get — browsing
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_list_returns_non_revoked_only_by_default(env):
    sk, did = _make_signing_key()
    a = await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="a")))
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="b")))
    await sr.revoke_skill(a["id"], revoked_by_agent_id="admin", reason="vulnerability")

    results = await sr.list_skills()
    names = {s["name"] for s in results}
    assert "b" in names
    assert "a" not in names


@pytest.mark.asyncio
async def test_list_with_include_revoked(env):
    sk, did = _make_signing_key()
    a = await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="revoked-a")))
    await sr.revoke_skill(a["id"], revoked_by_agent_id="admin", reason="r")
    results = await sr.list_skills(include_revoked=True)
    assert any(s["name"] == "revoked-a" for s in results)


@pytest.mark.asyncio
async def test_list_query_filters_name(env):
    sk, did = _make_signing_key()
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="email-read")))
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="slack-send")))
    email_only = await sr.list_skills(query="email")
    assert [s["name"] for s in email_only] == ["email-read"]


@pytest.mark.asyncio
async def test_list_tags_filters_by_capability(env):
    sk, did = _make_signing_key()
    await sr.publish_skill(
        **_publish_args(sk, did, manifest=_valid_manifest(name="net-one", capabilities=["net.http"]))
    )
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="fs-only", capabilities=["fs.read"])))
    net_only = await sr.list_skills(tags=["net.http"])
    assert {s["name"] for s in net_only} == {"net-one"}


@pytest.mark.asyncio
async def test_list_empty_chapter_returns_empty(env):
    results = await sr.list_skills()
    assert results == []


@pytest.mark.asyncio
async def test_list_is_global_by_default(env):
    """HAPPY: skills published by one chapter are visible to all (mesh catalog).

    Our skill_id is globally unique (name@version). Every chapter on the
    mesh should see every published skill unless an explicit chapter_id
    filter is passed (private-chapter isolation, W9).
    """
    sk, did = _make_signing_key()
    # Publish as Bay Area
    await sr.publish_skill(**_publish_args(sk, did), chapter_id="bayarea")
    # Boston's registry (instance init'd with chapter_id='boston') — should still see it.
    sr.init(pg_request_fn=env, chapter_id="boston")
    results = await sr.list_skills()
    assert len(results) == 1
    assert results[0]["chapter_id"] == "bayarea"


@pytest.mark.asyncio
async def test_list_scoped_to_chapter_when_requested(env):
    """EDGE: caller can opt in to per-chapter scoping (private-chapter mode)."""
    sk, did = _make_signing_key()
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="a")), chapter_id="bayarea")
    await sr.publish_skill(**_publish_args(sk, did, manifest=_valid_manifest(name="b")), chapter_id="boston")
    bayarea_only = await sr.list_skills(chapter_id="bayarea")
    assert {s["name"] for s in bayarea_only} == {"a"}
    boston_only = await sr.list_skills(chapter_id="boston")
    assert {s["name"] for s in boston_only} == {"b"}


@pytest.mark.asyncio
async def test_get_is_global_by_default(env):
    """HAPPY: get_skill() resolves regardless of which chapter published the skill."""
    sk, did = _make_signing_key()
    await sr.publish_skill(**_publish_args(sk, did), chapter_id="bayarea")
    sr.init(pg_request_fn=env, chapter_id="boston")
    result = await sr.get_skill("file-ops@1.0.0")
    assert result is not None
    assert result["id"] == "file-ops@1.0.0"


@pytest.mark.asyncio
async def test_get_returns_none_when_missing(env):
    assert await sr.get_skill("not-real@1.0.0") is None


# ═══════════════════════════════════════════════════════
# install_skill
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_install_happy(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))

    install = await sr.install_skill(skill["id"], agent_id="alice-agent")

    assert install["skill_id"] == skill["id"]
    assert install["agent_id"] == "alice-agent"
    assert len(install["signed_install_proof"]) == 64

    installs_table = env.tables["chapter_skill_installs"]
    assert len(installs_table) == 1
    assert installs_table[0]["installed_version"] == "1.0.0"


@pytest.mark.asyncio
async def test_install_refuses_revoked_skill(env):
    """ADVERSARIAL: revoked skill cannot be installed even if it's in the registry."""
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    await sr.revoke_skill(skill["id"], revoked_by_agent_id="admin", reason="bad")
    with pytest.raises(ValueError, match="revoked"):
        await sr.install_skill(skill["id"], agent_id="alice-agent")
    assert env.tables["chapter_skill_installs"] == []


@pytest.mark.asyncio
async def test_install_refuses_unknown_skill(env):
    with pytest.raises(ValueError, match="not found"):
        await sr.install_skill("ghost@1.0.0", agent_id="alice-agent")


@pytest.mark.asyncio
async def test_install_re_verifies_signature(env):
    """ADVERSARIAL: if the stored signature was tampered with post-publish, install
    must refuse — this is the re-verification safety net."""
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    # Tamper: flip the signature in the DB.
    env.tables["chapter_skills"][0]["signature"] = base64.b64encode(b"A" * 64).decode()
    with pytest.raises(ValueError, match="signature verification failed"):
        await sr.install_skill(skill["id"], agent_id="alice-agent")


# ═══════════════════════════════════════════════════════
# review_skill
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_review_happy(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    install = await sr.install_skill(skill["id"], agent_id="alice-agent")

    review = await sr.review_skill(
        skill_id=skill["id"],
        reviewer_agent_id="alice-agent",
        rating=5,
        review_text="Works great.",
        signed_install_proof=install["signed_install_proof"],
    )
    assert review["rating"] == 5


@pytest.mark.asyncio
async def test_review_refuses_non_installer(env):
    """ADVERSARIAL: the reviewer never installed — their review is refused."""
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    # Alice installs, Bob tries to review with a valid-looking proof.
    install = await sr.install_skill(skill["id"], agent_id="alice-agent")
    with pytest.raises(ValueError, match="has not installed"):
        await sr.review_skill(
            skill_id=skill["id"],
            reviewer_agent_id="bob-agent",
            rating=5,
            review_text="lying",
            signed_install_proof=install["signed_install_proof"],
        )


@pytest.mark.asyncio
async def test_review_rejects_missing_proof(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    await sr.install_skill(skill["id"], agent_id="alice-agent")
    with pytest.raises(ValueError, match="signed_install_proof"):
        await sr.review_skill(
            skill_id=skill["id"],
            reviewer_agent_id="alice-agent",
            rating=5,
            review_text="",
            signed_install_proof="",
        )


@pytest.mark.asyncio
async def test_review_rejects_invalid_proof_format(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    await sr.install_skill(skill["id"], agent_id="alice-agent")
    with pytest.raises(ValueError, match="signed_install_proof"):
        await sr.review_skill(
            skill_id=skill["id"],
            reviewer_agent_id="alice-agent",
            rating=5,
            review_text="",
            signed_install_proof="not-hex",
        )


@pytest.mark.asyncio
async def test_review_rejects_out_of_range_rating(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    install = await sr.install_skill(skill["id"], agent_id="alice-agent")
    for bad in [0, 6, -1, 100]:
        with pytest.raises(ValueError, match="rating"):
            await sr.review_skill(
                skill_id=skill["id"],
                reviewer_agent_id="alice-agent",
                rating=bad,
                review_text="",
                signed_install_proof=install["signed_install_proof"],
            )


# ═══════════════════════════════════════════════════════
# revoke_skill + visibility
# ═══════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_revoke_marks_fields(env):
    sk, did = _make_signing_key()
    skill = await sr.publish_skill(**_publish_args(sk, did))
    revoked = await sr.revoke_skill(skill["id"], revoked_by_agent_id="admin", reason="CVE-XXX")
    assert revoked["revoked_at"] is not None
    assert revoked["revocation_reason"] == "CVE-XXX"
    assert revoked["revoked_by_agent_id"] == "admin"


@pytest.mark.asyncio
async def test_revoke_unknown_skill_raises(env):
    with pytest.raises(ValueError, match="not found"):
        await sr.revoke_skill("ghost@1.0.0", revoked_by_agent_id="admin", reason="")


# ═══════════════════════════════════════════════════════
# describe_risk + tier_from_trust_score — surface helpers
# ═══════════════════════════════════════════════════════


def test_describe_risk_low_for_safe_caps():
    r = sr.describe_risk(["fs.read", "net.http"])
    assert r["level"] == "low"
    assert r["high_risk"] == []


def test_describe_risk_medium_for_one_high_risk():
    r = sr.describe_risk(["fs.read", "shell.exec"])
    assert r["level"] == "medium"
    assert r["high_risk"] == ["shell.exec"]


def test_describe_risk_high_for_multiple_high_risk():
    r = sr.describe_risk(["shell.exec", "eval.code", "net.arbitrary"])
    assert r["level"] == "high"
    assert set(r["high_risk"]) >= {"shell.exec", "eval.code", "net.arbitrary"}


def test_describe_risk_empty_caps():
    r = sr.describe_risk([])
    assert r["level"] == "low"


def test_tier_from_trust_score_boundaries():
    """C5: trust tier boundaries mirror the member ladder."""
    assert sr.tier_from_trust_score(0) == "newcomer"
    assert sr.tier_from_trust_score(19.9) == "newcomer"
    assert sr.tier_from_trust_score(20) == "established"
    assert sr.tier_from_trust_score(49.9) == "established"
    assert sr.tier_from_trust_score(50) == "trusted"
    assert sr.tier_from_trust_score(74.9) == "trusted"
    assert sr.tier_from_trust_score(75) == "power"


def test_tier_from_trust_score_none_defaults_to_newcomer():
    assert sr.tier_from_trust_score(None) == "newcomer"  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════
# Marketplace polish helpers (W6)
# ═══════════════════════════════════════════════════════


def test_author_reputation_ranks_productive_authors_higher():
    """HAPPY: more installs + higher ratings + more skills → higher score."""
    data = {
        "did:key:prolific": [
            {"install_count": 50, "avg_rating": 4.5},
            {"install_count": 30, "avg_rating": 4.0},
            {"install_count": 10, "avg_rating": 4.5},
        ],
        "did:key:new": [{"install_count": 1, "avg_rating": 5.0}],
    }
    ranked = sr.author_reputation(data)
    assert ranked[0]["author_did"] == "did:key:prolific"
    assert ranked[0]["skill_count"] == 3
    assert ranked[0]["total_installs"] == 90


def test_author_reputation_penalizes_revocations():
    """HAPPY: revoked skills drag down the non_revoked_ratio."""
    data = {
        "did:key:bad": [
            {"install_count": 10, "avg_rating": 3.0, "revoked_at": "2026-01-01"},
            {"install_count": 10, "avg_rating": 3.0, "revoked_at": "2026-02-01"},
        ],
        "did:key:clean": [
            {"install_count": 10, "avg_rating": 3.0},
            {"install_count": 10, "avg_rating": 3.0},
        ],
    }
    ranked = sr.author_reputation(data)
    clean = next(r for r in ranked if r["author_did"] == "did:key:clean")
    bad = next(r for r in ranked if r["author_did"] == "did:key:bad")
    assert clean["score"] > bad["score"]
    assert bad["non_revoked_ratio"] == 0.0


def test_author_reputation_empty_input():
    assert sr.author_reputation({}) == []


def test_author_reputation_ignores_authors_with_no_skills():
    assert sr.author_reputation({"did:key:lazy": []}) == []


def test_featured_skills_prefers_rated_with_installs():
    skills = [
        {"id": "a@1", "install_count": 100, "avg_rating": None, "revoked_at": None},
        {"id": "b@1", "install_count": 5, "avg_rating": 4.8, "revoked_at": None},
        {"id": "c@1", "install_count": 50, "avg_rating": 4.2, "revoked_at": None},
    ]
    featured = sr.featured_skills(skills, limit=2)
    # 'b' beats 'c' on rating even though 'c' has more installs.
    ids = [s["id"] for s in featured]
    assert ids[0] == "b@1"
    assert ids[1] == "c@1"


def test_featured_skills_falls_back_to_installs_when_none_rated():
    skills = [
        {"id": "x@1", "install_count": 10, "avg_rating": None, "revoked_at": None},
        {"id": "y@1", "install_count": 100, "avg_rating": None, "revoked_at": None},
    ]
    featured = sr.featured_skills(skills)
    assert featured[0]["id"] == "y@1"


def test_featured_skills_excludes_revoked():
    skills = [
        {"id": "a@1", "install_count": 100, "avg_rating": 5.0, "revoked_at": "2026-01-01"},
        {"id": "b@1", "install_count": 10, "avg_rating": 4.0, "revoked_at": None},
    ]
    featured = sr.featured_skills(skills)
    assert [s["id"] for s in featured] == ["b@1"]


def test_category_chips_groups_by_prefix():
    skills = [
        {"capabilities": ["fs.read", "fs.write"]},
        {"capabilities": ["fs.read", "net.http"]},
        {"capabilities": ["shell.exec"]},
    ]
    chips = sr.category_chips(skills)
    by_prefix = {c["value"]: c["count"] for c in chips}
    assert by_prefix["fs"] == 3
    assert by_prefix["net"] == 1
    assert by_prefix["shell"] == 1


def test_category_chips_sorted_by_frequency():
    skills = [
        {"capabilities": ["rare.x"]},
        {"capabilities": ["common.a"]},
        {"capabilities": ["common.b"]},
    ]
    chips = sr.category_chips(skills)
    # 'common' appears twice; should rank first.
    assert chips[0]["value"] == "common"


def test_category_chips_handles_empty():
    assert sr.category_chips([]) == []


def test_category_chips_handles_capability_without_dot():
    """EDGE: bare capability name → grouped under itself."""
    skills = [{"capabilities": ["display"]}]
    chips = sr.category_chips(skills)
    assert chips[0]["value"] == "display"


# ═══════════════════════════════════════════════════════
# Agent-Skills interop metadata (additive, optional)
# ═══════════════════════════════════════════════════════


def _rich_manifest(**overrides) -> dict:
    m = {
        "name": "file-ops",
        "version": "1.0.0",
        "description": "safe file operations",
        "capabilities": ["fs.read", "fs.write"],
        "readme_markdown": "# file-ops",
        "category": "agent-infra",
        "use_cases": ["Read a file", "Write a file"],
        "inputs": [{"name": "path", "description": "file path"}],
        "outputs": [{"name": "contents", "description": "file bytes"}],
        "required_tools": ["fs"],
        "permissions": {
            "network": False,
            "filesystem": True,
            "code_execution": False,
            "external_api": False,
            "user_data_access": False,
        },
        "safety_level": "medium",
        "risk_tags": ["filesystem"],
        "compatibility": {
            "generic_agents": "supported",
            "claude_skills": "experimental",
            "mcp": "not_supported",
            "nanda_agentfacts": "supported",
        },
        "license": "CC0-1.0",
        "maintainers": [{"name": "Maintainer", "contact": "https://example/issues"}],
        "tests": ["tests/basic.yaml"],
    }
    m.update(overrides)
    return m


def test_metadata_full_manifest_validates():  # HAPPY
    ok, reason = sr._validate_manifest(_rich_manifest())
    assert ok, reason


def test_metadata_is_backward_compatible():  # EDGE — a manifest with none of the new fields still validates
    minimal = {"name": "x", "version": "1.0.0", "capabilities": ["fs.read"]}
    ok, reason = sr._validate_manifest(minimal)
    assert ok, reason


def test_metadata_rejects_bad_safety_level():  # FAILURE
    ok, reason = sr._validate_manifest(_rich_manifest(safety_level="critical"))
    assert not ok and "safety_level" in reason


def test_metadata_rejects_unknown_compatibility_target():  # ADVERSARIAL
    ok, reason = sr._validate_manifest(_rich_manifest(compatibility={"made_up_runtime": "supported"}))
    assert not ok and "compatibility" in reason


def test_metadata_rejects_bad_compatibility_status():  # FAILURE
    ok, reason = sr._validate_manifest(_rich_manifest(compatibility={"mcp": "kinda"}))
    assert not ok and "compatibility" in reason


def test_metadata_rejects_unknown_permission_key():  # ADVERSARIAL
    ok, reason = sr._validate_manifest(_rich_manifest(permissions={"root_access": True}))
    assert not ok and "permission" in reason


def test_metadata_rejects_non_boolean_permission():  # FAILURE
    ok, reason = sr._validate_manifest(_rich_manifest(permissions={"network": "yes"}))
    assert not ok and "boolean" in reason


def test_metadata_rejects_input_without_name():  # FAILURE
    ok, reason = sr._validate_manifest(_rich_manifest(inputs=[{"description": "no name"}]))
    assert not ok and "inputs" in reason


def test_metadata_rejects_oversized_use_cases():  # EDGE — list cap
    ok, reason = sr._validate_manifest(_rich_manifest(use_cases=[f"u{i}" for i in range(33)]))
    assert not ok and "use_cases" in reason


def test_metadata_rejects_maintainer_without_name():  # FAILURE
    ok, reason = sr._validate_manifest(_rich_manifest(maintainers=[{"contact": "x"}]))
    assert not ok and "maintainer" in reason


# ═══════════════════════════════════════════════════════
# Published schema ↔ runtime validator alignment
# ═══════════════════════════════════════════════════════


def _load_skill_schema() -> dict:
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[2] / "schema" / "skill" / "0.1" / "skill-manifest.schema.json"
    return json.loads(p.read_text(encoding="utf-8"))


def test_published_schema_accepts_rich_manifest():  # HAPPY — the interop contract accepts our canonical shape
    import jsonschema

    jsonschema.validate(_rich_manifest(), _load_skill_schema())  # raises on mismatch


def test_published_schema_accepts_minimal_manifest():  # EDGE — backward-compatible minimal skill
    import jsonschema

    jsonschema.validate({"name": "x", "version": "1.0.0"}, _load_skill_schema())


def test_published_schema_rejects_what_runtime_rejects():  # alignment — both gates agree
    import jsonschema

    bad = _rich_manifest(safety_level="critical")
    assert not sr._validate_manifest(bad)[0]  # runtime rejects
    with pytest.raises(jsonschema.ValidationError):  # published schema rejects too
        jsonschema.validate(bad, _load_skill_schema())


# ═══════════════════════════════════════════════════════
# Open Agent-Skills export (interop, declarative view)
# ═══════════════════════════════════════════════════════

# Required fields of the open Agent-Skills format — encoded here so the export
# test does not depend on any external schema file.
_OPEN_REQUIRED = {
    "id",
    "name",
    "version",
    "category",
    "description",
    "use_cases",
    "inputs",
    "outputs",
    "required_tools",
    "permissions",
    "safety_level",
    "risk_tags",
    "compatibility",
    "provenance",
    "license",
    "maintainers",
    "tests",
}


def test_export_has_all_open_required_fields():  # HAPPY — result is a complete open skill
    out = sr.to_open_skill(_rich_manifest(), author_did="did:key:zAuthor")
    assert _OPEN_REQUIRED <= set(out)
    # Required open fields that must be non-empty / well-formed.
    assert out["use_cases"] and out["inputs"] and out["outputs"] and out["maintainers"] and out["tests"]
    assert out["safety_level"] in {"low", "medium", "high"}
    assert set(out["permissions"]) == {"network", "filesystem", "code_execution", "external_api", "user_data_access"}


def test_export_always_marks_nanda_agentfacts_supported():  # HAPPY — it IS a NANDA skill
    out = sr.to_open_skill({"name": "x", "version": "1.0.0"})
    assert out["compatibility"]["nanda_agentfacts"] == "supported"


def test_export_fills_required_fields_from_minimal_manifest():  # EDGE — defaults make a valid open skill
    out = sr.to_open_skill({"name": "x", "version": "1.0.0"})
    assert out["use_cases"] and out["inputs"] and out["outputs"]
    assert out["maintainers"][0]["name"] and out["maintainers"][0]["contact"]
    assert out["tests"] == ["none"]


def test_export_derives_permissions_from_capabilities():  # HAPPY
    out = sr.to_open_skill({"name": "x", "version": "1.0.0", "capabilities": ["fs.write", "net.http"]})
    perms = out["permissions"]
    assert perms["filesystem"] is True
    assert perms["network"] is True
    assert perms["code_execution"] is False


def test_export_code_execution_for_high_risk_caps():  # EDGE
    out = sr.to_open_skill({"name": "x", "version": "1.0.0", "capabilities": ["shell.exec"]})
    assert out["permissions"]["code_execution"] is True
    assert out["safety_level"] in {"medium", "high"}  # derived from high-risk cap


def test_export_explicit_permissions_override_derived():  # EDGE
    out = sr.to_open_skill(
        {"name": "x", "version": "1.0.0", "capabilities": ["fs.write"], "permissions": {"filesystem": False}}
    )
    assert out["permissions"]["filesystem"] is False  # explicit wins


def test_export_id_is_namespaced_and_slugified():  # EDGE — open id pattern needs a dotted, lowercased id
    out = sr.to_open_skill({"name": "file-ops", "version": "1.0.0", "category": "Agent Infra"})
    assert out["id"] == "agent-infra.file-ops"


def test_export_yaml_is_parseable():  # HAPPY — JSON is valid YAML; round-trips
    import json

    text = sr.to_open_skill_yaml(_rich_manifest())
    assert json.loads(text)["compatibility"]["nanda_agentfacts"] == "supported"


# ── M6: which error text reaches a caller ────────────────────────────────────
# The routes caught bare ValueError and echoed str(e). Every raise in
# skill_registry is authored FOR the caller, so echoing those is correct — but
# json.JSONDecodeError and binascii.Error are ALSO ValueError subclasses, so a
# malformed body reached the same handler and returned library text this project
# did not write. SkillInputError separates the two.


def test_authored_validation_errors_are_a_caller_facing_type():
    """HAPPY: every authored raise is the echoable type, not a bare ValueError."""
    import skill_registry as sr

    assert issubclass(sr.SkillInputError, ValueError), "must stay a ValueError for existing callers"
    from pathlib import Path

    src = (Path(sr.__file__)).read_text(encoding="utf-8")
    assert "raise ValueError(" not in src, (
        "an authored raise slipped back to bare ValueError — it would be "
        "indistinguishable from library text at the route boundary"
    )
    assert src.count("raise SkillInputError(") >= 20


def test_library_valueerrors_are_not_the_caller_facing_type():
    """ADVERSARIAL: the errors whose text nobody wrote for a caller.

    These are the ones that were being echoed. If either stops being a plain
    ValueError subclass — or starts being a SkillInputError — the boundary this
    finding is about has moved and the routes need rechecking.
    """
    import binascii
    import json

    import skill_registry as sr

    assert issubclass(json.JSONDecodeError, ValueError)
    assert issubclass(binascii.Error, ValueError)
    assert not issubclass(json.JSONDecodeError, sr.SkillInputError)
    assert not issubclass(binascii.Error, sr.SkillInputError)


def test_routes_answer_library_errors_generically():
    """ADVERSARIAL: the route boundary echoes authored text and nothing else."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "routes" / "skills.py").read_text(encoding="utf-8")
    assert src.count("except sr.SkillInputError as e:") == 5, "every handler must split the two cases"
    assert src.count('detail="malformed request"') == 5, "library errors must answer generically"
    # Every surviving echo sits under the authored type, never under bare ValueError.
    for block in src.split("except ")[1:]:
        if block.startswith("ValueError as e:"):
            assert "detail=str(e)" not in block.split("except ")[0], (
                "a bare ValueError handler still echoes str(e) — that is the M6 leak"
            )
