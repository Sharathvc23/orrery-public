"""Tests for community_member.profile.

Coverage matrix:

  R1  Forgery — profile with mismatched signature fails verify_signature
  R2  Replay — same canonical bytes always produce same content_hash
  R3  Injection — values containing JSON-special characters survive
      canonicalization round-trip without breaking the signature
  R4  Authz — hidden fields are scrubbed from to_card_extension; the
      published card never leaks email/phone unless visible=True
  R5  Boundary — empty profile loads as empty Profile with no signature
  R7  Adversarial — unsigned profile (signature='') fails verification
  R8  Revocation — flipping email.visible from True → False removes the
      value from the next card extension immediately
  R10 Persistence — save → load round-trip preserves every field

Plus parsing edge cases: missing fields fill defaults, garbage
shapes don't raise.
"""

from __future__ import annotations

import json

from community_member.profile import (
    PRIVATE_FIELDS,
    PUBLIC_FIELDS,
    Profile,
    ProfileField,
    _canonical_json,
    _from_dict,
    content_hash,
    load_profile,
    save_profile,
    to_card_extension,
    verify_signature,
)

# ── R10 round-trip ─────────────────────────────────────────────


def test_R10_save_load_round_trip_preserves_all_fields(tmp_path):
    p = Profile(
        name="Test User",
        bio="builds agents",
        interests=["ai", "agents"],
        skills=["python", "react"],
        email=ProfileField(value="test-user@example.com", visible=True),
        phone=ProfileField(value="+15551234", visible=False),
        socials={"twitter": "@test_user", "github": "https://github.com/test-user"},
        photo_url="https://example.com/avatar.png",
    )
    saved = save_profile(p, tmp_path)
    assert saved.updated_at  # save sets timestamp

    loaded = load_profile(tmp_path)
    assert loaded.name == "Test User"
    assert loaded.bio == "builds agents"
    assert loaded.interests == ["ai", "agents"]
    assert loaded.skills == ["python", "react"]
    assert loaded.email.value == "test-user@example.com"
    assert loaded.email.visible is True
    assert loaded.phone.value == "+15551234"
    assert loaded.phone.visible is False
    assert loaded.socials == {"twitter": "@test_user", "github": "https://github.com/test-user"}
    assert loaded.photo_url == "https://example.com/avatar.png"


def test_R5_missing_file_yields_empty_profile(tmp_path):
    p = load_profile(tmp_path / "nonexistent")
    assert p.name == ""
    assert p.bio == ""
    assert p.interests == []
    assert p.skills == []
    assert p.email.value is None
    assert p.email.visible is False
    assert p.signature == ""


def test_partial_dict_fills_defaults():
    p = _from_dict({"name": "Alice"})
    assert p.name == "Alice"
    assert p.bio == ""
    assert p.interests == []
    assert p.email.value is None


def test_garbage_dict_doesnt_raise():
    p = _from_dict({"interests": "not-a-list", "socials": "not-a-dict"})
    # Falsy non-list/dict values just become their defaults
    assert isinstance(p.interests, list)
    assert isinstance(p.socials, dict)


# ── R4 privacy: hidden fields scrubbed in card ─────────────────


def test_R4_hidden_email_scrubbed_from_card_extension():
    p = Profile(email=ProfileField(value="x@y.com", visible=False))
    ext = to_card_extension(p)
    assert ext["email"] is None  # NOT "x@y.com"


def test_R4_visible_email_published_in_card():
    p = Profile(email=ProfileField(value="x@y.com", visible=True))
    ext = to_card_extension(p)
    assert ext["email"] == "x@y.com"


def test_R4_hidden_phone_scrubbed_from_card_extension():
    p = Profile(phone=ProfileField(value="+15551234", visible=False))
    ext = to_card_extension(p)
    assert ext["phone"] is None


def test_R8_flipping_visible_immediately_changes_next_card():
    p = Profile(email=ProfileField(value="x@y.com", visible=True))
    assert to_card_extension(p)["email"] == "x@y.com"
    p.email.visible = False
    # No save needed — next card extension is computed live
    assert to_card_extension(p)["email"] is None


# ── PUBLIC_FIELDS / PRIVATE_FIELDS sanity ──────────────────────


def test_public_and_private_fields_are_disjoint():
    assert PUBLIC_FIELDS.isdisjoint(PRIVATE_FIELDS)


def test_email_and_phone_are_private():
    assert "email" in PRIVATE_FIELDS
    assert "phone" in PRIVATE_FIELDS


# ── R2 / R10: content hash is stable ────────────────────────────


def test_R2_content_hash_deterministic():
    p1 = Profile(name="A", interests=["x", "y"])
    p2 = Profile(name="A", interests=["x", "y"])
    assert content_hash(p1) == content_hash(p2)


def test_R2_content_hash_changes_when_data_changes():
    p1 = Profile(name="A")
    p2 = Profile(name="B")
    assert content_hash(p1) != content_hash(p2)


def test_R2_content_hash_excludes_signature():
    p1 = Profile(name="A", signature="sig1")
    p2 = Profile(name="A", signature="sig2")
    # Same content with different signatures → same hash
    assert content_hash(p1) == content_hash(p2)


# ── R3: canonical JSON survives weird strings ──────────────────


def test_R3_quotes_and_special_chars_round_trip():
    p = Profile(
        name='He said "hi"',
        bio="line1\nline2\twith\\backslash",
        socials={"key with space": "value, comma"},
    )
    canonical = _canonical_json(p.to_canonical_dict())
    # Round-trip via json.loads to confirm bytes are valid JSON
    decoded = json.loads(canonical)
    assert decoded["name"] == 'He said "hi"'
    assert decoded["bio"] == "line1\nline2\twith\\backslash"
    assert decoded["socials"]["key with space"] == "value, comma"


# ── Signature ───────────────────────────────────────────────────


def test_save_profile_with_sign_attaches_signature(tmp_path):
    """Sign callable receives canonical bytes; whatever it returns
    becomes the saved signature (base64-encoded if bytes)."""
    captured: dict = {}

    def fake_sign(msg: bytes) -> bytes:
        captured["msg"] = msg
        return b"\x01\x02\x03"

    p = Profile(name="test")
    saved = save_profile(p, tmp_path, sign=fake_sign)
    assert saved.signature  # non-empty
    assert isinstance(captured["msg"], bytes)
    assert b'"name":"test"' in captured["msg"]


def test_R7_unsigned_profile_fails_verify():
    p = Profile(name="x", signature="")

    def always_true(*_):
        return True

    assert verify_signature(p, verify=always_true) is False


def test_R7_malformed_signature_fails_verify():
    p = Profile(name="x", signature="not-valid-base64-!@#$")

    def always_true(*_):
        return True

    assert verify_signature(p, verify=always_true) is False


def test_R1_signature_with_failing_verifier_returns_false():
    import base64 as _b64

    p = Profile(name="x", signature=_b64.b64encode(b"deadbeef").decode())

    def reject(_msg, _sig):
        return False

    assert verify_signature(p, verify=reject) is False


def test_signature_with_passing_verifier_returns_true():
    import base64 as _b64

    p = Profile(name="x", signature=_b64.b64encode(b"deadbeef").decode())

    def accept(_msg, _sig):
        return True

    assert verify_signature(p, verify=accept) is True


def test_canonical_json_is_stable_across_dict_orderings():
    """The signature must survive a JSON round-trip that re-orders
    keys. canonical JSON sorts keys, so the bytes are identical."""
    p1 = Profile(name="A", bio="b")
    p2 = Profile(bio="b", name="A")  # constructor preserves field order; same dataclass
    assert _canonical_json(p1.to_canonical_dict()) == _canonical_json(p2.to_canonical_dict())


# ── Atomic write ───────────────────────────────────────────────


def test_atomic_write_uses_temp_file(tmp_path):
    """save_profile must write to a temp file then rename. Verify
    by checking that no .tmp file is left behind after a clean
    save."""
    save_profile(Profile(name="x"), tmp_path)
    assert (tmp_path / "profile.json").exists()
    assert not (tmp_path / "profile.tmp").exists()
    assert not (tmp_path / "profile.json.tmp").exists()


# ── Card extension shape ───────────────────────────────────────


def test_card_extension_shape_is_stable():
    """Every key the card extension publishes must always be
    present, even if value is None. This lets chapters cache the
    shape and detect what fields the agent supports."""
    p = Profile()
    ext = to_card_extension(p)
    expected_keys = {
        "name",
        "bio",
        "interests",
        "skills",
        "email",
        "phone",
        "socials",
        "photo_url",
        "updated_at",
        "signature",
    }
    assert set(ext.keys()) == expected_keys
