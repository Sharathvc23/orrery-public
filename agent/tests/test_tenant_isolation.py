"""B2a — many sovereign tenants, one process, fully isolated stores.

The community-member runtime used to assume one agent per process (a global
``CONFIG_DIR``). ``AgentContext`` is the per-tenant isolation seam the
multi-tenant SMB host (B2b) is built on. These tests stand up TWO tenants in
ONE process with distinct homes and prove there is no cross-tenant leakage of
identity, keys, receipts, or bookings — and that omitting ``home`` leaves the
legacy single-agent behavior byte-for-byte unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import arp, keystore
from community_member import config as cm_config
from community_member.config import Config
from community_member.tenant import AgentContext


@pytest.fixture
def device_keystore(monkeypatch: pytest.MonkeyPatch):
    """Pin the device backend so the store is deterministic regardless of the
    host's OS keyring / tty, and reset the backend cache before + after."""
    monkeypatch.setenv("COMMUNITY_MEMBER_KEYSTORE", "device")
    keystore.reset_for_tests()
    yield
    keystore.reset_for_tests()


def test_two_tenants_have_distinct_identities(tmp_path: Path, device_keystore):
    home_a = tmp_path / "acme"
    home_b = tmp_path / "globex"

    ctx_a = AgentContext.load(home_a)
    ctx_b = AgentContext.load(home_b)

    did_a = ctx_a.ensure_identity("acme-agent")
    did_b = ctx_b.ensure_identity("globex-agent")

    assert did_a and did_b
    assert did_a.startswith("did:key:z") and did_b.startswith("did:key:z")
    assert did_a != did_b

    # Each tenant's key is derivable only from its own home, and they differ.
    assert ctx_a.private_key_seed is not None
    assert ctx_b.private_key_seed is not None
    assert ctx_a.private_key_seed != ctx_b.private_key_seed

    # Vault files are physically separate — no shared store dir.
    assert (home_a / "keystore.enc").exists()
    assert (home_b / "keystore.enc").exists()

    # Tenant A's key is NOT present in tenant B's vault, and vice-versa.
    assert keystore.load_private_key("acme-agent", dir=home_a) is not None
    assert keystore.load_private_key("acme-agent", dir=home_b) is None
    assert keystore.load_private_key("globex-agent", dir=home_a) is None


def test_booking_receipt_lands_only_in_that_tenants_log(tmp_path: Path, device_keystore):
    home_a = tmp_path / "acme"
    home_b = tmp_path / "globex"

    ctx_a = AgentContext.load(home_a)
    ctx_b = AgentContext.load(home_b)
    did_a = ctx_a.ensure_identity("acme-agent")
    ctx_b.ensure_identity("globex-agent")

    out = ctx_a.book_appointment(
        service="haircut",
        provider="Sharp Cuts",
        datetime="2026-08-01T14:30:00Z",
        notes="trim only",
    )
    receipt_id = out["receipt_id"]
    assert receipt_id, out

    # (a) Booking persisted ONLY under tenant A's home.
    assert (home_a / "bookings.json").exists()
    assert "Sharp Cuts" in (home_a / "bookings.json").read_text()
    assert not (home_b / "bookings.json").exists()

    # (b) The receipt is in A's Agency Log, issued under A's did, strict-verifies.
    log_a = arp.AgencyLog(home_a)
    receipt = log_a.get(receipt_id)
    assert receipt is not None
    assert receipt["issuer_did"] == did_a
    assert receipt["action"]["category"] == "appointment_booked"
    res = arp.verify_receipt(receipt)
    assert res.ok and res.stage == "accepted"
    assert arp.verify_receipt_signature(receipt)

    # (c) Tenant B's Agency Log is completely unaffected — no leakage.
    log_b = arp.AgencyLog(home_b)
    assert log_b.count() == 0
    assert log_a.count() == 1

    # (d) A's receipt does not claim to be B's — issuer is A, not B.
    assert receipt["issuer_did"] != ctx_b.did


def test_interleaved_bookings_stay_partitioned(tmp_path: Path, device_keystore):
    """Both tenants act in the same process; each log holds only its own."""
    ctx_a = AgentContext.load(tmp_path / "acme")
    ctx_b = AgentContext.load(tmp_path / "globex")
    ctx_a.ensure_identity("acme-agent")
    ctx_b.ensure_identity("globex-agent")

    ctx_a.book_appointment(service="haircut", provider="Sharp Cuts", datetime="2026-08-01T14:30:00Z")
    ctx_b.book_appointment(service="consult", provider="Globex Advisors", datetime="2026-08-02T09:00:00Z")
    ctx_a.book_appointment(service="color", provider="Sharp Cuts", datetime="2026-08-03T10:00:00Z")

    log_a = arp.AgencyLog(ctx_a.home)
    log_b = arp.AgencyLog(ctx_b.home)
    assert log_a.count() == 2
    assert log_b.count() == 1

    # Every receipt in A's log is issued by A; every one in B's by B.
    assert all(r["issuer_did"] == ctx_a.did for r in log_a.list_recent())
    assert all(r["issuer_did"] == ctx_b.did for r in log_b.list_recent())

    # A's bookings.json holds 2 rows, B's holds 1 — stores never mixed.
    import json

    assert len(json.loads((ctx_a.home / "bookings.json").read_text())) == 2
    assert len(json.loads((ctx_b.home / "bookings.json").read_text())) == 1


def test_keyless_tenant_books_but_skips_receipt(tmp_path: Path, device_keystore):
    """A tenant with no identity is still valid: it books, receipt skipped."""
    ctx = AgentContext.load(tmp_path / "keyless")
    assert ctx.did is None
    out = ctx.book_appointment(service="consult", provider="Acme", datetime="2026-08-02T09:00:00Z")
    assert out["booked"]["id"] == 1
    assert out["receipt_id"] is None
    assert "receipt_note" in out
    assert arp.AgencyLog(ctx.home).count() == 0


def test_backward_compat_no_home_uses_global_config_dir(tmp_path: Path, device_keystore, monkeypatch):
    """With no explicit home, Config + the booking tool use the module-global
    CONFIG_DIR exactly as before — proving the single-agent path is unchanged."""
    from community_member.builtin_skills.booking.skill import book_appointment

    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)

    # Global Config() (no home) resolves home to the module-global CONFIG_DIR.
    cfg = Config()
    assert cfg.home == tmp_path
    cfg.agent_id = "legacy-agent"
    cfg.ensure_keypair()
    cfg.save()

    # The built-in tool (home=None) books into the global dir.
    out = book_appointment({"service": "haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T14:30:00Z"})
    assert out["receipt_id"]
    assert (tmp_path / "bookings.json").exists()
    assert arp.AgencyLog(tmp_path).count() == 1
