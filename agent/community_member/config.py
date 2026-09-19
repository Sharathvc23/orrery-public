"""
Config — persistent configuration for the community member agent.

Stored under the agent's config dir (defaults to ``~/.community-member/``,
override via the ``COMMUNITY_MEMBER_HOME`` env var so multiple sovereign
agents can run side-by-side on one machine for different purposes —
each with its own keys, profile, audit ledger, and habits.db):

  config.json     — chapter URL, agent ID, LLM provider
  agent.json      — exported agent state (portable)
  memory.json     — private notes (never leaves your machine)
  profile.json    — local profile (lean-chapter migration)
  consent.db      — hash-chained consent audit ledger
  habits.db       — Bayesian habit posteriors
  graduations.db  — auto-execute state machine

Multi-agent example::

    # Personal agent
    COMMUNITY_MEMBER_HOME=~/.community-member \
    COMMUNITY_MEMBER_PORT=7799 python run_agent.py &

    # Work agent — fresh keys, fresh everything
    COMMUNITY_MEMBER_HOME=~/.community-member-work \
    COMMUNITY_MEMBER_PORT=7800 python run_agent.py &

The path is resolved at import time so test harnesses that monkeypatch
``CONFIG_DIR`` continue to work; the env var is read once at module
load. To change between agents within one process, instantiate a fresh
``Config()`` after setting the env var (or use the ``home`` constructor
arg explicitly).
"""

import json
import os
from pathlib import Path


def _resolve_config_dir() -> Path:
    """Read COMMUNITY_MEMBER_HOME at import time; fallback to default."""
    override = os.environ.get("COMMUNITY_MEMBER_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".community-member"


CONFIG_DIR = _resolve_config_dir()


class Config:
    def __init__(self, home: str | Path | None = None):
        # Per-instance home. When ``home`` is omitted, ``self.home`` resolves
        # dynamically to the module-global ``CONFIG_DIR`` on every access, so
        # single-agent behavior (and test monkeypatching of ``CONFIG_DIR``) is
        # byte-for-byte unchanged.
        #
        # When ``home`` is given, these stores are pinned to that directory:
        # config.json, agent.json, memory.json, consent.db, the keystore vault
        # (call sites pass ``dir=config._home``) and the booking store.
        #
        # These are NOT pinned — they resolve to the process-global
        # ``CONFIG_DIR``, fixed when this module was first imported:
        # trusted_chapters.json, the skills root and its registry, inbox.jsonl,
        # channel_secrets.json. Two Config instances with different homes share
        # all four. Isolation is therefore partial, and a second tenant in one
        # process is not yet safe to run; see ``tenant.py``, which no caller
        # currently uses.
        #
        # The list above is asserted by
        # ``agent/tests/test_pinned_home_is_followed.py``, which derives the
        # stores from this package rather than from this comment, so a store
        # added later is classified there or fails the suite.
        self._home: Path | None = Path(home).expanduser().resolve() if home is not None else None
        self.agent_id: str = ""
        self.name: str = ""
        self.description: str = ""
        self.skills: list[str] = []
        self.interests: list[str] = []
        self.chapter_url: str = ""
        self.provider: str = ""
        self.api_key: str = ""
        # No vendor default. This used to be "grok-3-mini" regardless of
        # provider, so a keyless install reported a model it had no provider or
        # key for — which is how the busy-loop defect read as "configured".
        self.model: str = ""
        self.linkedin_url: str = ""
        self.private_key: str = ""
        self.public_key: str = ""
        self._api_key_encrypted: dict | None = None
        self._passphrase: str = ""

    @property
    def home(self) -> Path:
        """This Config's home directory.

        Explicit per-instance home if one was passed to ``__init__``; otherwise
        the current module-global ``CONFIG_DIR`` (read live so a late
        ``COMMUNITY_MEMBER_HOME`` / monkeypatch is still honored).
        """
        return self._home if self._home is not None else CONFIG_DIR

    def is_configured(self) -> bool:
        """True once the agent has an IDENTITY (agent_id + public key). The ORG
        and the LLM key are both OPTIONAL: a standalone, keyless agent is valid
        and serveable — it runs, joins orgs, and serves its surfaces; an LLM key
        only lights up the generative extras (the "keyless install is complete
        and working" posture the README describes). Add a key or join an org any
        time from the dashboard's Settings."""
        return bool(self.agent_id and self.public_key)

    def has_keypair(self) -> bool:
        return bool(self.private_key and self.public_key)

    def ensure_keypair(self):
        """Generate a keypair if one doesn't exist.

        Prefers Ed25519 — that's the scheme `auth.sign_request_body` uses
        for the wire and the scheme the chapter verifies against. The
        legacy `generate_keypair()` is HMAC-SHA256, where ``public_key``
        is just sha256(private_key) — not a real asymmetric public key.
        Falling back to that path would produce a keypair where the chapter
        records a hash instead of an Ed25519 verify-key, and every
        subsequent signed request fails verification. Mirror panic's
        ``_rotate_signing_key`` which already does this correctly.
        """
        if not self.has_keypair():
            from .crypto import ed25519_available, generate_ed25519_keypair, generate_keypair

            kp = generate_ed25519_keypair() if ed25519_available() else generate_keypair()
            self.private_key = kp["private_key"]
            self.public_key = kp["public_key"]

    @classmethod
    def load(cls, home: str | Path | None = None) -> "Config":
        config = cls(home=home)
        config_file = config.home / "config.json"
        if config_file.exists():
            try:
                data = json.loads(config_file.read_text())
                for key, value in data.items():
                    if key == "api_key_encrypted":
                        config._api_key_encrypted = value
                    elif hasattr(config, key) and not key.startswith("_"):
                        setattr(config, key, value)
            except Exception:
                pass

        # Keystore takes precedence over any plaintext private_key in
        # config.json. If the config still has a plaintext key (legacy
        # install, pre-keystore), migrate it now and clear the plaintext.
        if config.agent_id:
            from community_member import keystore

            stored = keystore.load_private_key(config.agent_id, dir=config._home)
            if stored:
                config.private_key = stored
            elif config.private_key:
                # Legacy plaintext on disk — move it into the keystore
                # and clear the plaintext on the next save().
                keystore.migrate_plaintext_key(config.agent_id, config.private_key, dir=config._home)
                # Save immediately so the plaintext is gone before any
                # crash or snapshot can capture it.
                try:
                    config.save()
                except Exception:
                    pass
        return config

    def set_api_key(self, api_key: str, passphrase: str):
        """Encrypt and store the API key."""
        from .crypto import encrypt_value

        self.api_key = ""  # Clear plaintext
        self._api_key_encrypted = encrypt_value(api_key, passphrase)
        self._passphrase = passphrase

    def get_api_key(self, passphrase: str = "") -> str:
        """Get the API key, decrypting if necessary."""
        if self.api_key:
            return self.api_key
        if self._api_key_encrypted and passphrase:
            from .crypto import decrypt_value

            return decrypt_value(self._api_key_encrypted, passphrase)
        return ""

    def save(self):
        self.home.mkdir(parents=True, exist_ok=True)

        # Private key is stored in the keystore (OS keychain or encrypted
        # file), never in config.json. The public key is safe to store in
        # plaintext since it is, by definition, public.
        from community_member import keystore

        if self.agent_id and self.private_key:
            keystore.store_private_key(self.agent_id, self.private_key, dir=self._home)

        data = {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "skills": self.skills,
            "interests": self.interests,
            "chapter_url": self.chapter_url,
            "provider": self.provider,
            "api_key": "" if self._api_key_encrypted else self.api_key,
            "api_key_encrypted": self._api_key_encrypted,
            "model": self.model,
            "linkedin_url": self.linkedin_url,
            "private_key": "",  # never persisted to disk plaintext
            "public_key": self.public_key,
        }
        (self.home / "config.json").write_text(json.dumps(data, indent=2))

    def save_agent_state(self, state: dict):
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / "agent.json").write_text(json.dumps(state, indent=2))

    def load_agent_state(self) -> dict:
        agent_file = self.home / "agent.json"
        if agent_file.exists():
            try:
                return json.loads(agent_file.read_text())
            except Exception:
                pass
        return {}

    def save_private_memory(self, key: str, value: str, memory_type: str = "note"):
        self.home.mkdir(parents=True, exist_ok=True)
        memory_file = self.home / "memory.json"
        memories = []
        if memory_file.exists():
            try:
                memories = json.loads(memory_file.read_text())
            except Exception:
                pass
        memories.append({"type": memory_type, "key": key, "value": value})
        memory_file.write_text(json.dumps(memories, indent=2))

    def load_private_memory(self) -> list[dict]:
        memory_file = self.home / "memory.json"
        if memory_file.exists():
            try:
                return json.loads(memory_file.read_text())
            except Exception:
                pass
        return []
