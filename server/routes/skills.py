"""Skill registry routes — publish / list / get / install / review / revoke.

Extracted from chapter_agent.py. Backs onto skill_registry (+ the seeded
non-profit starter pack). Request models live here (skills-only). Shared
sanitizers and the members map are read live from chapter_agent via `ca`.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from routes import ca

logger = logging.getLogger(__name__)

router = APIRouter()


class SkillPublishRequest(BaseModel):
    manifest: dict
    signature: str
    signing_key_did: str
    content_sha256: str
    author_agent_id: str | None = None
    package_url: str | None = None


class SkillReviewRequest(BaseModel):
    reviewer_agent_id: str
    rating: int
    review_text: str = ""
    signed_install_proof: str


class SkillInstallRequest(BaseModel):
    agent_id: str


class SkillRevokeRequest(BaseModel):
    revoked_by_agent_id: str
    reason: str = ""


def _require_publishing_member(caller: str) -> str:
    """The registered member whose signature this publication rides on.

    Two conditions, both the handler's own even though the middleware enforces
    them too: a verified caller (``ca._resolve_caller`` at the call site — the
    actor-binding guard reads for that primitive), and one that is a member of
    this org. A signature alone is possession of a key, not membership.
    """
    if not caller or caller not in ca.members:
        raise HTTPException(status_code=401, detail="publishing a skill requires a registered member's signature")
    return caller


@router.post("/api/skills/publish")
async def skill_publish(req: SkillPublishRequest, request: Request):
    """Register a new signed skill, by a REGISTERED MEMBER. Signature is
    verified at publish time.

    The manifest signature proves the SKILL is authentic; it says nothing about
    who is putting it in this org's registry. That used to be nobody in
    particular — the route was open, so any keypair on the internet could list
    a package here. Publication now requires a registered member's request
    signature (the middleware refuses anyone else; the check below is the
    handler's own), and ``author_agent_id`` is that member — never the request
    body, which is a field anyone can set to anyone.
    """
    import skill_registry as sr

    author = _require_publishing_member(ca.sanitize_agent_id(ca._resolve_caller(request)))

    try:
        skill = await sr.publish_skill(
            manifest=req.manifest,
            signature=req.signature,
            signing_key_did=req.signing_key_did,
            content_sha256=req.content_sha256,
            author_agent_id=author,
            package_url=req.package_url,
        )
    except sr.SkillInputError as e:
        # Authored in skill_registry FOR the caller — safe to echo verbatim.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        # NOT authored here. json.JSONDecodeError and binascii.Error are both
        # ValueError subclasses, so a malformed body or a bad base64 field
        # arrives carrying library text this project did not write. Log it,
        # answer generically (M6).
        logger.warning("skills: rejected a malformed request: %s", e)
        raise HTTPException(status_code=400, detail="malformed request") from e
    return {"skill": skill}


@router.post("/api/skills/publish/package")
async def skill_publish_package(request: Request):
    """Register a signed skill from a downloadable ``.nandaskill`` bundle
    (application/zip body). Verified FAIL-CLOSED before anything is registered —
    a bad/missing/tampered signature or a content-hash mismatch is a 400 and
    persists nothing. The package signature is the authority on what the
    skill IS; a registered member's request signature is what puts it in this
    org's registry, exactly as for /api/skills/publish. The registration is
    attributed to that member — the ``author_agent_id`` query parameter used
    to be honoured verbatim, which on an open route was a label anyone could
    set to anyone; it is ignored now."""
    import skill_registry as sr

    author = _require_publishing_member(ca.sanitize_agent_id(ca._resolve_caller(request)))
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty package body")
    if len(body) > sr.MAX_PACKAGE_BYTES:
        raise HTTPException(status_code=413, detail="package too large")
    try:
        skill = await sr.publish_skill_from_package(body, author_agent_id=author)
    except sr.SkillInputError as e:
        # Authored in skill_registry FOR the caller — safe to echo verbatim.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        # NOT authored here. json.JSONDecodeError and binascii.Error are both
        # ValueError subclasses, so a malformed body or a bad base64 field
        # arrives carrying library text this project did not write. Log it,
        # answer generically (M6).
        logger.warning("skills: rejected a malformed request: %s", e)
        raise HTTPException(status_code=400, detail="malformed request") from e
    return {"skill": skill}


@router.get("/api/skills")
async def skills_list(
    query: str | None = None,
    tag: str | None = None,
    author: str | None = None,
    trust_min: float = 0,
    include_revoked: bool = False,
    limit: int = 50,
):
    import skill_registry as sr

    rows = await sr.list_skills(
        query=ca.sanitize_text(query, max_length=200) if query else None,
        tags=[ca.sanitize_text(tag, max_length=64)] if tag else None,
        author=ca.sanitize_text(author, max_length=200) if author else None,
        trust_min=float(trust_min),
        include_revoked=bool(include_revoked),
        limit=min(max(int(limit), 1), 200),
    )
    return {"skills": rows, "count": len(rows)}


@router.get("/api/skills/{skill_id}")
async def skill_get(skill_id: str):
    import skill_registry as sr

    # skill_id format name@version; allow ":" too since PyPI ecosystem uses that
    safe_id = ca.sanitize_text(skill_id, max_length=128)
    skill = await sr.get_skill(safe_id)
    if not skill:
        raise HTTPException(status_code=404, detail="skill_not_found")
    risk = sr.describe_risk(skill.get("capabilities") or [])
    author_tier = sr.tier_from_trust_score(skill.get("trust_score") or 0)
    return {"skill": skill, "risk": risk, "author_tier": author_tier}


@router.get("/api/skills/{skill_id}/package")
async def skill_get_package(skill_id: str):
    """Download the signed, portable ``.nandaskill`` bundle for a skill
    (application/zip). Keyless, like the other skill reads — the bundle carries
    its own Ed25519 publisher signature so trust travels with the file."""
    import skill_registry as sr

    safe_id = ca.sanitize_text(skill_id, max_length=128)
    try:
        package = await sr.pack_skill(safe_id)
    except sr.SkillInputError as e:
        # Authored in skill_registry FOR the caller — safe to echo verbatim.
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        # NOT authored here. json.JSONDecodeError and binascii.Error are both
        # ValueError subclasses, so a malformed body or a bad base64 field
        # arrives carrying library text this project did not write. Log it,
        # answer generically (M6).
        logger.warning("skills: rejected a malformed request: %s", e)
        raise HTTPException(status_code=400, detail="malformed request") from e
    filename = f"{safe_id.replace('@', '-').replace('/', '-')}.nandaskill"
    return Response(
        content=package,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/api/skills/{skill_id}/install")
async def skill_install(skill_id: str, req: SkillInstallRequest, request: Request):
    """Install a skill for the calling member.

    The installer IS the auth-verified caller. An ``agent_id`` naming anyone else
    is refused rather than ignored, so a client sending the wrong one is told
    instead of having its request silently rewritten. An install is not a
    private note: it is the record ``review_skill`` requires before it accepts a
    review, so an install recorded against another identity lets one member post
    reviews as that member.

    Membership is required as well as a signature. A valid signature alone does
    not make the caller part of this org — first-contact signers are accepted
    elsewhere by design — and an install grants standing to review, which is a
    public reputation signal for the skill.
    """
    import skill_registry as sr

    installer = ca._bind_actor_to_caller(request, req.agent_id or "", field="agent_id")
    if installer not in ca.members:
        raise HTTPException(
            status_code=403,
            detail=f"{installer} is not a member of this org; join it before installing skills",
        )

    safe_id = ca.sanitize_text(skill_id, max_length=128)
    try:
        result = await sr.install_skill(skill_id=safe_id, agent_id=installer)
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg) from e
        raise HTTPException(status_code=400, detail=msg) from e
    return result


@router.post("/api/skills/{skill_id}/review")
async def skill_review(skill_id: str, req: SkillReviewRequest, request: Request):
    import skill_registry as sr

    # The reviewer IS the auth-verified caller — never the body-claimed
    # ``reviewer_agent_id`` (which is accepted-but-ignored). Otherwise any
    # signed member could post a review under someone else's identity.
    reviewer = ca._resolve_caller(request)
    if not reviewer:
        raise HTTPException(status_code=401, detail="authentication required")

    safe_id = ca.sanitize_text(skill_id, max_length=128)
    try:
        review = await sr.review_skill(
            skill_id=safe_id,
            reviewer_agent_id=ca.sanitize_agent_id(reviewer),
            rating=int(req.rating),
            review_text=ca.sanitize_text(req.review_text, max_length=4000),
            signed_install_proof=req.signed_install_proof,
        )
    except sr.SkillInputError as e:
        # Authored in skill_registry FOR the caller — safe to echo verbatim.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        # NOT authored here. json.JSONDecodeError and binascii.Error are both
        # ValueError subclasses, so a malformed body or a bad base64 field
        # arrives carrying library text this project did not write. Log it,
        # answer generically (M6).
        logger.warning("skills: rejected a malformed request: %s", e)
        raise HTTPException(status_code=400, detail="malformed request") from e
    return {"review": review}


@router.post("/api/skills/{skill_id}/revoke")
async def skill_revoke(skill_id: str, req: SkillRevokeRequest, request: Request):
    """Mark a skill revoked. Only the author or a chapter leader/admin may revoke.

    Authorization enforced at this layer; the registry module is the
    mechanism, not the policy. The revoker is the AUTH-VERIFIED caller, never
    the body-claimed ``revoked_by_agent_id`` — otherwise any signed member
    could revoke any skill by naming the author/a leader in the body.
    """
    import skill_registry as sr

    revoker = ca._resolve_caller(request)
    if not revoker:
        raise HTTPException(status_code=401, detail="authentication required")

    safe_id = ca.sanitize_text(skill_id, max_length=128)
    skill = await sr.get_skill(safe_id)
    if not skill:
        raise HTTPException(status_code=404, detail="skill_not_found")

    revoker = ca.sanitize_agent_id(revoker)
    revoker_member = ca.members.get(revoker) or {}
    is_author = skill.get("author_agent_id") == revoker or skill.get("author_did") == revoker_member.get("did")
    is_leader = revoker_member.get("chapter_role") in ("leader", "admin")
    if not (is_author or is_leader):
        raise HTTPException(status_code=403, detail="only author or chapter leader may revoke")

    try:
        revoked = await sr.revoke_skill(
            skill_id=safe_id,
            revoked_by_agent_id=revoker,
            reason=ca.sanitize_text(req.reason, max_length=500),
        )
    except sr.SkillInputError as e:
        # Authored in skill_registry FOR the caller — safe to echo verbatim.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        # NOT authored here. json.JSONDecodeError and binascii.Error are both
        # ValueError subclasses, so a malformed body or a bad base64 field
        # arrives carrying library text this project did not write. Log it,
        # answer generically (M6).
        logger.warning("skills: rejected a malformed request: %s", e)
        raise HTTPException(status_code=400, detail="malformed request") from e
    return {"skill": revoked}
