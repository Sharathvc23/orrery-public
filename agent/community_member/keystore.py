"""Key storage — OS keychain · user passphrase · device fingerprint. Never plaintext.

The sovereign agent's Ed25519 private key never exists on disk in
plaintext. Three at-rest protection backends are available; the
keystore selects one at runtime based on capability and operator
preference.

Backends
--------

  1. **OS keychain** (``BACKEND_KEYRING``) — uses the `keyring` package.
     Linux Secret Service on GNOME/KDE, macOS Keychain Services,
     Windows DPAPI. Highest-trust default. Zero session friction.

  2. **User passphrase** (``BACKEND_PASSPHRASE``) — HMAC-SHA256
     encrypt-then-MAC (``crypto.encrypt_value``; not AES) with a key derived
     (PBKDF2-HMAC-SHA256, 100k iterations) from a passphrase the user enters
     interactively via getpass. Defeats
     even root on the same machine, because the passphrase never
     touches disk. Cost: one prompt per process lifetime; cached in
     RAM so subsequent operations are silent.

  3. **Device fingerprint** (``BACKEND_DEVICE``) — same encryption
     primitives as ``passphrase`` but the passphrase is derived from
     a stable machine fingerprint (hostname + home + ``/etc/machine-id``).
     Defeats backup/rsync leakage; does NOT defeat root or a sibling
     process running as the same user. Used for headless / CI /
     no-tty environments where a passphrase prompt is impossible.

Selection
---------

Default (``auto``) prefers ``keyring`` → ``passphrase`` (if the process
has a tty) → ``device``. The user can override at install time via the
wizard's ``--keystore=<keyring|passphrase|device>`` flag, or per-process
via ``COMMUNITY_MEMBER_KEYSTORE=<backend>``. The choice is recorded in
``keystore.meta.json`` so the next process resolves the same backend
without re-prompting.

A backend transition (``device → passphrase``, ``passphrase → keyring``,
etc.) is handled by ``rotate_backend(target_backend)`` which decrypts
the existing vault with the old credential, re-encrypts with the new,
and updates the meta file atomically.

On-disk layout
--------------

  ~/.community-member/
    keystore.enc           # AES/HMAC ciphertext, 0600
    keystore.meta.json     # {"current_backend": "...", "agents": {...}}

The vault is a JSON map ``{agent_id → private_key_b64}``, encrypted as
a single blob. Per-call cost is negligible — a 32-byte key per agent.

Threat-model summary
--------------------

| Attacker                                      | keyring | passphrase | device |
| --------------------------------------------- | :-----: | :--------: | :----: |
| Disk image / backup / rsync                   | ✓       | ✓          | ✓      |
| Different OS user account                     | ✓       | ✓          | ✓      |
| Root on the same machine                      | ✓ *    | ✓          | ✗      |
| Sibling process running as the same user      | ~ †    | ✓          | ✗      |
| Compromised running agent process             | ✗       | ✗          | ✗      |

  * macOS Keychain prompts on access; Windows DPAPI binds to login
    creds; Linux Secret Service lifecycle depends on the daemon.
  † keyring access requires the daemon to consider the caller
    authorized — varies by platform.

Hardware-backed signing (TPM, YubiKey, Secure Enclave) is the only
backend that defends against a compromised running agent process. See
``docs/HARDWARE_KEYSTORE.md`` for the v0.4 implementation spec.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

from community_member import crypto

__all__ = [
    "BACKEND_DEVICE",
    "BACKEND_KEYRING",
    "BACKEND_PASSPHRASE",
    "KEYSTORE_DIR",
    "SERVICE_NAME",
    "WrongPassphraseError",
    "clear_passphrase_cache",
    "current_backend",
    "delete_private_key",
    "has_private_key",
    "load_private_key",
    "migrate_plaintext_key",
    "reset_for_tests",
    "rotate_backend",
    "set_passphrase_for_tests",
    "store_private_key",
]

SERVICE_NAME = "community-member"

# Backend identifiers — these strings are persisted to keystore.meta.json,
# treat as a stable wire format.
BACKEND_KEYRING = "keyring"
BACKEND_PASSPHRASE = "passphrase"
BACKEND_DEVICE = "device"
# Legacy meta value, kept readable for backward compatibility with vaults
# written before BACKEND_DEVICE was named explicitly.
_LEGACY_ENCRYPTED_FILE = "encrypted_file"


class WrongPassphraseError(ValueError):
    """Raised when an interactive unlock fails three times.

    The cleartext passphrase never touches disk; on a wrong-passphrase
    failure we emit this typed error so the CLI can surface a useful
    remediation hint instead of the generic ``ValueError`` from the
    decrypt layer.
    """


def _resolve_keystore_dir() -> Path:
    """Resolve the keystore directory, honoring COMMUNITY_MEMBER_HOME.

    Mirrors community_member.config._resolve_config_dir so that running
    the SDK with a non-default home (test isolation, multi-tenant on one
    box) puts every artefact under the same root. Without this, the
    config + keystore drift apart and the wizard's freshly-generated
    keypair lands in two different places.
    """
    override = os.environ.get("COMMUNITY_MEMBER_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".community-member"


KEYSTORE_DIR = _resolve_keystore_dir()

# Module-level cache so the keyring probe only runs once per process.
_backend: str | None = None

# In-RAM passphrase cache for BACKEND_PASSPHRASE — keyed by KEYSTORE_DIR
# string so multiple agents on one box (different COMMUNITY_MEMBER_HOME
# values) each prompt independently. Never persisted; cleared on process
# exit. ``set_passphrase_for_tests`` is the only test entry point.
_passphrase_cache: dict[str, str] = {}


# ── Test hooks ──────────────────────────────────────────────────────


def reset_for_tests(dir_override: Path | None = None) -> None:
    """Reset the backend cache + optionally redirect the keystore dir.

    Used in tests to force a clean probe and avoid clobbering the
    developer's actual keystore at `~/.community-member/`. NOT for
    production use — changing KEYSTORE_DIR at runtime is otherwise
    undefined behavior.
    """
    global _backend, KEYSTORE_DIR
    _backend = None
    _passphrase_cache.clear()
    if dir_override is not None:
        KEYSTORE_DIR = dir_override


def set_passphrase_for_tests(passphrase: str) -> None:
    """Seed the passphrase cache so tests don't need a tty.

    Call AFTER ``reset_for_tests`` so the cache is fresh. Production
    code MUST NOT call this — it bypasses the unlock prompt that is
    the entire point of BACKEND_PASSPHRASE.
    """
    _passphrase_cache[str(KEYSTORE_DIR)] = passphrase


def clear_passphrase_cache() -> None:
    """Wipe any cached passphrase. Call on logout / panic / lock screen.

    After this the next signed call that needs the keystore will
    re-prompt via getpass. The cache is in-process anyway, so a
    crash also clears it implicitly.
    """
    _passphrase_cache.clear()


# ── Backend probe + selection ──────────────────────────────────────


def _probe_keyring() -> bool:
    """Return True if the OS keyring is installed AND functional."""
    try:
        import keyring
    except ImportError:
        return False
    try:
        keyring.set_password(SERVICE_NAME, "_keystore_probe_", "ok")
        assert keyring.get_password(SERVICE_NAME, "_keystore_probe_") == "ok"
        keyring.delete_password(SERVICE_NAME, "_keystore_probe_")
        return True
    except Exception:
        return False


def _read_meta(dir: Path | None = None) -> dict[str, Any]:
    """Read keystore.meta.json or return ``{}`` if absent / corrupt.

    Corruption is treated as "no preference recorded" rather than
    raising — the backend probe will pick a safe default and rewrite
    the meta on the next store. We log to stderr so an operator
    inspecting fresh-install behavior can see the override path.
    """
    path = _meta_path(dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (ValueError, json.JSONDecodeError):
        print(
            f"[keystore] meta file unreadable at {path} — falling back to default backend",
            file=sys.stderr,
        )
        return {}


def _selected_backend() -> str | None:
    """Return the backend selected by env or persisted preference, or None."""
    override = (os.environ.get("COMMUNITY_MEMBER_KEYSTORE") or "").strip().lower()
    if override:
        if override in (BACKEND_KEYRING, BACKEND_PASSPHRASE, BACKEND_DEVICE):
            return override
        if override in ("auto", ""):
            return None
        print(
            f"[keystore] ignoring unknown COMMUNITY_MEMBER_KEYSTORE={override!r}; "
            f"valid: keyring · passphrase · device · auto",
            file=sys.stderr,
        )
    persisted = _read_meta().get("current_backend")
    if persisted == _LEGACY_ENCRYPTED_FILE:
        # Pre-rename vaults are device-fingerprint encrypted.
        return BACKEND_DEVICE
    if persisted in (BACKEND_KEYRING, BACKEND_PASSPHRASE, BACKEND_DEVICE):
        return persisted
    return None


def _auto_backend() -> str:
    """Pick the strongest backend the host can support without prompting.

    keyring (no friction, strongest) → passphrase (prompt cost) →
    device (no friction, weakest). We use ``passphrase`` only when
    the process has a tty for the prompt; in headless / CI / sidecar
    contexts we fall to device-fingerprint so we never hang waiting
    for input that will never come.
    """
    if _probe_keyring():
        return BACKEND_KEYRING
    if sys.stdin.isatty() and sys.stderr.isatty():
        return BACKEND_PASSPHRASE
    return BACKEND_DEVICE


def current_backend() -> str:
    """Report the active backend.

    Resolution order:
      1. Persisted preference in ``keystore.meta.json``.
      2. Env override ``COMMUNITY_MEMBER_KEYSTORE``.
      3. Auto-pick: keyring if available, else passphrase if tty, else device.

    Memoized for the process lifetime so repeated calls are cheap and
    the backend never silently changes mid-run.
    """
    global _backend
    if _backend is None:
        _backend = _selected_backend() or _auto_backend()
    return _backend


# ── Device fingerprint (for BACKEND_DEVICE) ────────────────────────


def _device_fingerprint() -> str:
    """Stable machine-bound string fed into the passphrase derivation.

    Intentionally deterministic: if the user copies `keystore.enc` to
    a different machine it cannot be decrypted. Closes the rsync/backup
    leak vector. Does NOT protect against root or sibling-user-process
    on the same host — those attackers can recompute the fingerprint.
    """
    parts = [
        socket.gethostname() or "unknown-host",
        os.path.expanduser("~") or "unknown-home",
    ]
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            data = Path(p).read_text().strip()
            if data:
                parts.append(data)
                break
        except OSError:
            continue
    return "|".join(parts)


# ── Passphrase prompt (for BACKEND_PASSPHRASE) ─────────────────────


_PROMPT_NEW = "New keystore passphrase (≥10 chars, won't echo): "
_PROMPT_CONFIRM = "Confirm passphrase: "
_PROMPT_UNLOCK = "Keystore passphrase: "
_MIN_PASSPHRASE = 10


def _prompt_for_new_passphrase() -> str:
    """Prompt the user for a new passphrase with confirmation.

    Used on first store under BACKEND_PASSPHRASE, when no vault yet
    exists. Three retries on mismatch / too-short, then raises.
    """
    for _ in range(3):
        first = getpass.getpass(_PROMPT_NEW)
        if len(first) < _MIN_PASSPHRASE:
            print(
                f"  passphrase must be at least {_MIN_PASSPHRASE} characters",
                file=sys.stderr,
            )
            continue
        confirm = getpass.getpass(_PROMPT_CONFIRM)
        if first != confirm:
            print("  passphrases do not match — try again", file=sys.stderr)
            continue
        return first
    raise WrongPassphraseError("could not collect a valid passphrase after 3 attempts")


def _prompt_for_unlock_passphrase() -> str:
    """Prompt the user to unlock an existing passphrase-encrypted vault.

    Caller is expected to verify (by attempting decrypt) and retry
    on failure. We raise here only if the prompt fails outright
    (no tty, EOF).
    """
    try:
        return getpass.getpass(_PROMPT_UNLOCK)
    except (EOFError, KeyboardInterrupt) as e:
        raise WrongPassphraseError(
            "passphrase unlock cancelled — set COMMUNITY_MEMBER_KEYSTORE=device "
            "for non-interactive environments, or migrate to keyring"
        ) from e


def _passphrase_for_backend(backend: str, dir: Path | None = None) -> str:
    """Return the passphrase fed into ``crypto.encrypt_value`` for ``backend``.

    BACKEND_DEVICE: SHA-256 of the device fingerprint, hex.
    BACKEND_PASSPHRASE: user passphrase, prompted once and cached in RAM.
    BACKEND_KEYRING: not applicable (this backend stores via keyring API,
        never touches the encrypted-file path).

    ``dir`` scopes the vault-existence check and the RAM passphrase cache to a
    single tenant's home, so two tenants each unlock their own vault. ``None``
    resolves to the process-global ``KEYSTORE_DIR`` (unchanged single-agent
    behavior).

    The function is the single point where we decide what bytes feed
    into ``crypto.derive_key``; do not inline this logic elsewhere.
    """
    if backend == BACKEND_DEVICE:
        return hashlib.sha256(_device_fingerprint().encode("utf-8")).hexdigest()

    if backend == BACKEND_PASSPHRASE:
        cache_key = str(_resolve_dir(dir))
        cached = _passphrase_cache.get(cache_key)
        if cached:
            return cached

        # Headless / Railway: an explicit env passphrase replaces the getpass
        # prompt entirely, so COMMUNITY_MEMBER_KEYSTORE=passphrase +
        # COMMUNITY_MEMBER_PASSPHRASE yields a stable identity unlockable with no
        # tty (the vault must persist — mount a volume at COMMUNITY_MEMBER_HOME).
        # Interactive behavior is unchanged when the env var is unset.
        env_pass = os.environ.get("COMMUNITY_MEMBER_PASSPHRASE", "")
        if env_pass:
            if _vault_path(dir).exists():
                # Verify against the existing vault and fail LOUD on mismatch,
                # never silently fall through to a prompt that can't run.
                try:
                    crypto.decrypt_value(json.loads(_vault_path(dir).read_text()), env_pass)
                except (ValueError, json.JSONDecodeError) as e:
                    raise WrongPassphraseError(
                        "COMMUNITY_MEMBER_PASSPHRASE does not unlock the existing keystore vault"
                    ) from e
            elif len(env_pass) < _MIN_PASSPHRASE:
                raise WrongPassphraseError(f"COMMUNITY_MEMBER_PASSPHRASE must be at least {_MIN_PASSPHRASE} characters")
            _passphrase_cache[cache_key] = env_pass
            return env_pass

        # First call this session. If a vault already exists we need to
        # unlock it (one prompt + verify). If it doesn't, we need to
        # set a fresh passphrase (prompt + confirm).
        if _vault_path(dir).exists():
            for _ in range(3):
                attempt = _prompt_for_unlock_passphrase()
                # Verify by attempting to decrypt the existing vault.
                try:
                    crypto.decrypt_value(json.loads(_vault_path(dir).read_text()), attempt)
                except (ValueError, json.JSONDecodeError):
                    print("  wrong passphrase — try again", file=sys.stderr)
                    continue
                _passphrase_cache[cache_key] = attempt
                return attempt
            raise WrongPassphraseError("3 wrong passphrase attempts")
        else:
            new_pass = _prompt_for_new_passphrase()
            _passphrase_cache[cache_key] = new_pass
            return new_pass

    raise ValueError(f"_passphrase_for_backend called with non-file backend: {backend!r}")


def _passphrase() -> str:
    """Backwards-compatible alias — resolves to the device-fingerprint
    passphrase, which is what the legacy single-backend code expected.
    Kept so external callers (none today, but defensively) don't break;
    new code MUST call ``_passphrase_for_backend(current_backend())``.
    """
    return _passphrase_for_backend(BACKEND_DEVICE)


# ── Vault I/O (encrypted_file backend) ──────────────────────────────


def _resolve_dir(dir: Path | None) -> Path:
    """Return the keystore dir for a call: the explicit per-tenant ``dir`` if
    given, else the process-global ``KEYSTORE_DIR``.

    Passing an explicit ``dir`` is how multiple sovereign tenants coexist in one
    process (B2a per-tenant isolation): each tenant's encrypted vault + meta live
    under its own ``COMMUNITY_MEMBER_HOME``. ``dir=None`` reproduces the exact
    single-agent behavior (and honors ``reset_for_tests(dir_override=...)``), so
    every existing call site is unchanged.
    """
    return dir if dir is not None else KEYSTORE_DIR


def _vault_path(dir: Path | None = None) -> Path:
    return _resolve_dir(dir) / "keystore.enc"


def _meta_path(dir: Path | None = None) -> Path:
    return _resolve_dir(dir) / "keystore.meta.json"


def _read_vault(backend: str | None = None, dir: Path | None = None) -> dict[str, str]:
    path = _vault_path(dir)
    if not path.exists():
        return {}
    backend = backend or current_backend()
    try:
        payload = json.loads(path.read_text())
        plaintext = crypto.decrypt_value(payload, _passphrase_for_backend(backend, dir))
        data = json.loads(plaintext)
        vault = data if isinstance(data, dict) else {}
    except (ValueError, json.JSONDecodeError):
        # A corrupt vault is a hard failure — the user should re-run
        # recovery rather than have the agent silently proceed with
        # no key. Raise, don't paper over.
        raise
    # S2 stage 2: a successfully-opened legacy (version-less) vault is
    # re-encrypted as a v2 blob on the spot, so it carries its KDF params from
    # now on and future cipher/cost upgrades can't brick it.
    if crypto.is_legacy_blob(payload):
        _write_vault(vault, backend, dir)
    return vault


def _write_vault(vault: dict[str, str], backend: str | None = None, dir: Path | None = None) -> None:
    target = _resolve_dir(dir)
    target.mkdir(parents=True, exist_ok=True)
    backend = backend or current_backend()
    plaintext = json.dumps(vault, sort_keys=True)
    payload = crypto.encrypt_value(plaintext, _passphrase_for_backend(backend, dir))
    path = _vault_path(dir)
    path.write_text(json.dumps(payload))
    try:
        path.chmod(0o600)
    except OSError:
        # Windows / non-POSIX filesystems: best effort.
        pass


def _write_meta(agent_id: str, backend: str, dir: Path | None = None) -> None:
    _resolve_dir(dir).mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {}
    if _meta_path(dir).exists():
        try:
            meta = json.loads(_meta_path(dir).read_text())
        except (ValueError, json.JSONDecodeError):
            meta = {}
    meta.setdefault("agents", {})[agent_id] = {"backend": backend}
    meta["current_backend"] = backend
    _meta_path(dir).write_text(json.dumps(meta, indent=2, sort_keys=True))


# ── Public API ──────────────────────────────────────────────────────


def store_private_key(agent_id: str, private_key_b64: str, dir: Path | None = None) -> str:
    """Store `private_key_b64` under `agent_id`. Returns the backend used.

    ``dir`` selects the per-tenant vault (its ``COMMUNITY_MEMBER_HOME``); ``None``
    uses the process-global ``KEYSTORE_DIR`` — the unchanged single-agent path.
    Note: the KEYRING backend stores in the OS keychain keyed by ``agent_id``
    only, so it is isolated per identity but not per ``dir``; file-backed vaults
    (device / passphrase) are fully ``dir``-isolated.

    Raises ValueError if agent_id is empty or the key is falsy — a
    missing key is a bug, not a condition to silently ignore.
    """
    if not agent_id or not isinstance(agent_id, str):
        raise ValueError("agent_id is required")
    if not private_key_b64:
        raise ValueError("private_key_b64 is required")

    backend = current_backend()
    if backend == BACKEND_KEYRING:
        import keyring

        keyring.set_password(SERVICE_NAME, agent_id, private_key_b64)
    else:  # BACKEND_PASSPHRASE or BACKEND_DEVICE — both use the encrypted vault
        vault = _read_vault(backend, dir)
        vault[agent_id] = private_key_b64
        _write_vault(vault, backend, dir)
    _write_meta(agent_id, backend, dir)
    return backend


def load_private_key(agent_id: str, dir: Path | None = None) -> str | None:
    """Return the stored key for `agent_id`, or None if absent.

    ``dir`` scopes the lookup to a per-tenant vault; ``None`` uses the global
    ``KEYSTORE_DIR`` (unchanged single-agent behavior).
    """
    if not agent_id:
        return None
    backend = current_backend()
    if backend == BACKEND_KEYRING:
        import keyring

        val = keyring.get_password(SERVICE_NAME, agent_id)
        return val or None
    vault = _read_vault(backend, dir)
    return vault.get(agent_id)


def has_private_key(agent_id: str, dir: Path | None = None) -> bool:
    return load_private_key(agent_id, dir) is not None


def delete_private_key(agent_id: str, dir: Path | None = None) -> None:
    """Remove the stored key. Safe to call if no key exists."""
    if not agent_id:
        return
    backend = current_backend()
    if backend == BACKEND_KEYRING:
        import keyring

        try:
            keyring.delete_password(SERVICE_NAME, agent_id)
        except Exception:
            pass
        return
    vault = _read_vault(backend, dir)
    if agent_id in vault:
        del vault[agent_id]
        if vault:
            _write_vault(vault, backend, dir)
        else:
            # Last entry — remove the file entirely so rotation is clean.
            try:
                _vault_path(dir).unlink()
            except OSError:
                pass


# ── One-time migration ──────────────────────────────────────────────


def migrate_plaintext_key(agent_id: str, plaintext_key_b64: str, dir: Path | None = None) -> bool:
    """Migrate a plaintext key (from the pre-keystore config.json) into
    the keystore. Returns True if a migration occurred, False if the
    keystore already had a key for this agent.

    Caller is responsible for clearing the plaintext from config.json
    AFTER this function returns True.
    """
    if has_private_key(agent_id, dir):
        return False
    store_private_key(agent_id, plaintext_key_b64, dir)
    return True


def rotate_backend(target_backend: str, new_passphrase: str | None = None) -> dict[str, Any]:
    """Migrate the entire keystore from the current backend to ``target_backend``.

    When ``target_backend == BACKEND_PASSPHRASE``, the caller MUST supply
    ``new_passphrase`` (the wizard / CLI collects this from the user with
    confirmation before invoking us). When migrating away from
    BACKEND_PASSPHRASE, the existing cached passphrase is used to decrypt
    the source vault one last time.

    Flow:

      1. Read every (agent_id, private_key) pair under the current backend.
      2. Switch the resolved backend to ``target_backend``.
      3. Seed the passphrase cache with ``new_passphrase`` if applicable.
      4. Write each pair through the new backend.
      5. Tear down the old storage:
         - keyring → device/passphrase: keyring entries deleted.
         - device/passphrase → keyring: encrypted vault file removed.
         - device → passphrase or vice-versa: vault re-encrypted in place.

    Returns a summary dict suitable for surfacing to the wizard / CLI.
    """
    global _backend
    if target_backend not in (BACKEND_KEYRING, BACKEND_PASSPHRASE, BACKEND_DEVICE):
        raise ValueError(
            f"unknown target backend {target_backend!r}; "
            f"valid: {BACKEND_KEYRING} · {BACKEND_PASSPHRASE} · {BACKEND_DEVICE}"
        )
    if target_backend == BACKEND_KEYRING and not _probe_keyring():
        raise RuntimeError(
            "keyring backend requested but the OS keychain is not available — "
            "install the 'keychain' extra or set up Secret Service / Keychain / DPAPI"
        )

    source_backend = current_backend()
    if source_backend == target_backend:
        return {"migrated": 0, "source": source_backend, "target": target_backend, "noop": True}

    # 1. Read everything under the source. The current backend's
    # passphrase cache is still valid here — we read first, then swap.
    if source_backend == BACKEND_KEYRING:
        # keyring lacks an enumerate API; use the meta file's agents map
        # as the source of truth for "which agent_ids we wrote keyring rows for".
        meta = _read_meta()
        agent_ids = list((meta.get("agents") or {}).keys())
        import keyring as _kr

        pairs = {aid: _kr.get_password(SERVICE_NAME, aid) for aid in agent_ids}
        pairs = {aid: val for aid, val in pairs.items() if val}
    else:
        pairs = _read_vault(source_backend)

    # 2. Flip the active backend so subsequent calls resolve through the new one.
    _backend = target_backend

    # 3. Seed the passphrase cache for the new backend (if applicable).
    # Wipe any stale entry first so a wrong cached passphrase from the
    # source backend doesn't accidentally satisfy the new one.
    _passphrase_cache.pop(str(KEYSTORE_DIR), None)
    if target_backend == BACKEND_PASSPHRASE:
        if not new_passphrase:
            raise WrongPassphraseError(
                "rotate_backend(target=passphrase) requires new_passphrase — "
                "the caller (wizard / CLI) collects + confirms it from the user before "
                "invoking the rotation"
            )
        _passphrase_cache[str(KEYSTORE_DIR)] = new_passphrase

    # 4. Tear down the old storage BEFORE writing the new one. Otherwise
    # store_private_key on the new backend would read the still-extant
    # old vault (encrypted under the source passphrase) as part of its
    # read-then-write cycle and fail decryption.
    if source_backend == BACKEND_KEYRING:
        import keyring as _kr

        for aid in pairs:
            try:
                _kr.delete_password(SERVICE_NAME, aid)
            except Exception:
                pass
    else:
        # File-backed source. Drop the old vault so the new backend
        # writes from a clean slate (re-encrypted under new credentials).
        try:
            _vault_path().unlink()
        except OSError:
            pass

    # 5. Write each pair through the new backend.
    migrated = 0
    for aid, key in pairs.items():
        store_private_key(aid, key)
        migrated += 1

    # Stamp the meta so a fresh process picks up the new backend.
    meta = _read_meta()
    meta["current_backend"] = target_backend
    _meta_path().write_text(json.dumps(meta, indent=2, sort_keys=True))

    return {
        "migrated": migrated,
        "source": source_backend,
        "target": target_backend,
        "noop": False,
    }
