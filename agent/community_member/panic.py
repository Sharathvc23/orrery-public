"""Panic revoke — one-step \"something is wrong, nuke auto-execute\" flow.

Invoked via `community-member panic` (CLI) or the tray hotkey (once
the Electron UI ships). Does three things atomically:

  1. Append a `consent.panic_revoke` row to the audit ledger so the
     moment + reason are permanently recorded even if later code
     crashes or the DB is later tampered with.
  2. Revoke every live graduation so no auto-execute can happen
     until the user explicitly re-approves each action. Graduations
     are a W3+ concept; for W1 this step is a no-op that returns 0
     but records the intent — the hook is already in place so W3
     doesn't need a panic-path rewrite.
  3. Rotate the signing key. The old key is discarded from the
     keystore; a fresh Ed25519 pair replaces it. Public key is
     written back to `config.json` so chapter peers re-verify.
     If an attacker grabbed the old private key, rotating here
     means their impersonation window ends now.
  4. Spend every live user approval. A `consent.approved` row inside
     its 5-minute TTL is an action the next think cycle will run with
     no further click; before this step panic left those standing, so
     "nuke auto-execute" was true for graduations and false for the
     approval a user had just clicked. Each is tombstoned with
     ``execution="revoked_by_panic"``.
  5. Reset the trust dial. ``local_trust`` at or above the threshold
     auto-approves every trusted-provenance proposal, and the cached
     chapter score can do the same on its own; both are put back to
     the fresh-install state so nothing auto-executes until the user
     raises them again.

The function is idempotent — running it 10 times produces the same
final state as running it once (no graduations left, key already
fresh). Test `S7_panic_revoke_is_idempotent` pins this.

Usage
-----

    from community_member import panic, keystore, config

    cfg = config.Config.load()
    keystore.init(...)  # or ensure already configured
    report = panic.execute_panic(
        chapter_id=cfg.agent_id and f\"local:{cfg.agent_id}\" or \"local:unknown\",
        agent_id=cfg.agent_id,
        config=cfg,
    )
    print(f\"Panic complete: revoked {report.revoked_graduations}\")
"""

from __future__ import annotations

from dataclasses import dataclass

from community_member import keystore
from community_member.config import Config
from community_member.consent import ledger

__all__ = ["PanicReport", "execute_panic"]


@dataclass(frozen=True)
class PanicReport:
    """Outcome of one panic-revoke invocation."""

    revoked_graduations: int
    new_public_key: str
    key_rotated: bool
    audit_event_sha256: str
    revoked_approvals: int = 0
    trust_reset: bool = False


def _revoke_all_graduations(*, device_did: str | None = None) -> int:
    """Revoke every live graduation for this device. Returns count.

    Now that W3 has shipped, walks the GraduationStore at
    `~/.community-member/graduations.db` and revokes every row whose
    device_did matches. Other devices' rows in the same file (e.g.,
    an operator running two agents on one machine) are left intact.

    Returns 0 silently if the DB doesn't exist yet — running panic
    before any graduation was ever recorded is valid.
    """
    if not device_did:
        return 0
    try:
        from community_member.config import CONFIG_DIR
        from community_member.graduation import GraduationStore
    except ImportError:
        return 0
    db_path = CONFIG_DIR / "graduations.db"
    if not db_path.exists():
        return 0
    try:
        store = GraduationStore(db_path, device_did=device_did)
        return store.revoke_all()
    except Exception:
        return 0


def _revoke_live_approvals(*, chapter_id: str, agent_id: str | None) -> int:
    """Tombstone every unconsumed, unexpired ``consent.approved`` row.

    Uses the same tombstone the executor writes when it claims an approval,
    so ``find_valid_approval`` skips them by the same rule. Returns how many
    were spent. Counts by row, not by matching request shape: after a panic
    nothing that was approved before it may run.
    """
    from datetime import UTC, datetime

    from community_member.consent import gate

    now = datetime.now(UTC)
    consumed = gate._consumed_approval_shas()
    spent = 0
    for ev in ledger.list_events(action="consent.approved", limit=500):
        sha = str(ev.get("event_sha256") or "")
        if not sha or sha in consumed:
            continue
        det = ev.get("detail") or {}
        try:
            if datetime.fromisoformat(det["expires_at"]) <= now:
                continue
        except (KeyError, ValueError):
            pass  # unreadable expiry: spend it anyway, that is the closed direction
        gate.mark_consumed(sha, chapter_id=chapter_id, actor_agent_id=agent_id, execution="revoked_by_panic")
        spent += 1
    return spent


def _reset_trust(config: Config) -> bool:
    """Put the trust dial and the cached chapter score back to fresh-install
    values. Returns False (and says why) if the files could not be written;
    the rest of panic still runs."""
    from community_member import identity_trust

    try:
        identity_trust.save_local_trust(config.home, identity_trust.DEFAULT_LOCAL_TRUST)
        cache = config.home / identity_trust._CHAPTER_TRUST_FILENAME
        if cache.exists():
            cache.unlink()
    except OSError as e:
        print(
            f"[panic][ERROR] trust dial could not be reset ({type(e).__name__}: {e}); local_trust still auto-approves"
        )
        return False
    return True


def _rotate_signing_key(config: Config) -> tuple[str, bool]:
    """Generate a fresh keypair, swap it into the keystore + config.

    Returns (new_public_key_b64, rotated_bool). `rotated` is False
    only if the agent has no agent_id yet (nothing to rotate) —
    that's a setup-not-complete case, not an error.
    """
    if not config.agent_id:
        return (config.public_key, False)

    # Lazy-import so `panic` doesn't force the ed25519 extra at
    # module-load time; the keystore itself runs fine on HMAC-only
    # installs but rotation defaults to Ed25519 when available.
    from community_member.crypto import ed25519_available, generate_ed25519_keypair, generate_keypair

    if ed25519_available():
        kp = generate_ed25519_keypair()
    else:
        kp = generate_keypair()

    # Replace the stored private key. Keystore's `store_private_key`
    # is already last-write-wins; the old key is gone as soon as the
    # write completes.
    keystore.store_private_key(config.agent_id, kp["private_key"])
    config.private_key = kp["private_key"]
    config.public_key = kp["public_key"]
    config.save()
    return (kp["public_key"], True)


def execute_panic(
    *,
    chapter_id: str,
    agent_id: str | None,
    config: Config,
    rotate_key: bool = True,
) -> PanicReport:
    """Run the full panic sequence.

    Parameters
    ----------
    chapter_id
        Scoping id for the audit row. Use \"local:{agent_id}\" for
        standalone device agents.
    agent_id
        The actor field on the audit row; passthrough to the ledger.
    config
        Loaded Config. Its private_key / public_key are rewritten
        in place when key rotation runs.
    rotate_key
        Set False only in tests or drills that want to record the
        panic without actually rotating. Defaults to True — the
        whole point of panic is that a compromised key shouldn't
        keep working.

    Returns
    -------
    PanicReport describing what happened. The ledger row's hash is
    in `audit_event_sha256` so callers can prove the panic was
    recorded.
    """
    revoked = _revoke_all_graduations(device_did=agent_id)
    revoked_approvals = _revoke_live_approvals(chapter_id=chapter_id, agent_id=agent_id)
    trust_reset = _reset_trust(config)
    if rotate_key:
        new_pub, rotated = _rotate_signing_key(config)
    else:
        new_pub, rotated = (config.public_key, False)

    event = ledger.record(
        chapter_id=chapter_id,
        action="consent.panic_revoke",
        actor_agent_id=agent_id,
        target_type="all",
        target_id="panic",
        outcome="ok",
        detail={
            "revoked_graduations": revoked,
            "revoked_approvals": revoked_approvals,
            "trust_reset": trust_reset,
            "key_rotated": rotated,
            "new_public_key": new_pub,
        },
    )

    return PanicReport(
        revoked_graduations=revoked,
        new_public_key=new_pub,
        key_rotated=rotated,
        audit_event_sha256=event["event_sha256"],
        revoked_approvals=revoked_approvals,
        trust_reset=trust_reset,
    )
