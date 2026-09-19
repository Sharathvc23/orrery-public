"""AgentContext — one sovereign tenant, fully isolated, in a shared process.

Milestone B2a. The community-member runtime historically assumed a single
agent per process: its home came from a module-global ``CONFIG_DIR`` read once
at import, and every store (keystore vault, Agency Log, bookings, consent
ledger, private memory) keyed off that one directory. That made it impossible
to run two sovereign agents side-by-side in one process.

``AgentContext`` is the small per-tenant object the multi-tenant SMB host (B2b)
instantiates once per tenant. It bundles the four things a tenant runtime path
needs — ``{home, config, identity, agency_log}`` — and pins every store it
touches to that tenant's ``home``:

    ctx_a = AgentContext.load("~/tenants/acme")
    ctx_b = AgentContext.load("~/tenants/globex")
    ctx_a.ensure_identity("acme-agent")     # distinct did:key, own keystore vault
    ctx_b.ensure_identity("globex-agent")
    ctx_a.book_appointment(service="haircut", provider="Sharp Cuts",
                           datetime="2026-08-01T14:30:00Z")
    # → booking + signed receipt land ONLY under ctx_a.home; ctx_b is untouched.

Isolation guarantees
--------------------
* **Identity / keys** — the Ed25519 seed lives in a keystore vault under this
  tenant's ``home`` (device / passphrase backends are ``dir``-isolated; the OS
  keyring backend isolates per ``agent_id``). ``did`` is derived from the seed.
* **Agency Log** — receipts go to ``home/agency-log.sqlite`` only.
* **Bookings** — the booking skill writes ``home/bookings.json`` only.
* **Private memory / agent state** — via this tenant's ``Config``.
* **Consent ledger** — this tenant's DB path is ``home/consent.db``. The consent
  ledger MODULE is still a process-global singleton (see ``activate_consent``);
  the *data* is per-tenant, the *active pointer* is not — B2b re-activates the
  ledger at the start of a tenant turn.

This object deliberately does NOT own the host loop, HTTP surface, or scheduler
— those are B2b. It is the isolation seam B2b builds on.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from community_member import arp, keystore
from community_member.config import Config


@dataclass
class AgentContext:
    """One sovereign tenant's isolated home + config + identity + Agency Log."""

    home: Path
    config: Config

    # ── construction ────────────────────────────────────────────────

    @classmethod
    def load(cls, home: str | Path) -> AgentContext:
        """Load (or start) a tenant rooted at ``home``.

        Reads ``home/config.json`` if present (idempotent — safe to call every
        turn); the tenant may still be keyless until :meth:`ensure_identity`.
        """
        resolved = Path(home).expanduser().resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        config = Config.load(home=resolved)
        return cls(home=resolved, config=config)

    # ── identity ────────────────────────────────────────────────────

    def ensure_identity(self, agent_id: str) -> str:
        """Ensure this tenant has an Ed25519 identity; return its ``did:key``.

        Generates + persists a keypair (into this tenant's keystore vault and
        ``config.json``) if one is not already present. Idempotent: a second
        call with the same ``agent_id`` reuses the stored key. ``agent_id`` is
        this tenant's local handle and the keystore lookup key; it must be
        stable across calls for one tenant.
        """
        if not agent_id:
            raise ValueError("agent_id is required to establish a tenant identity")
        self.config.agent_id = agent_id
        # Reuse an already-stored key for this identity; otherwise mint one.
        stored = keystore.load_private_key(agent_id, dir=self.home)
        if stored:
            self.config.private_key = stored
        else:
            self.config.ensure_keypair()
        self.config.save()  # writes config.json + stores the seed in THIS home's vault
        did = self.did
        if did is None:
            # The key was just generated + stored; a missing did here means the
            # keystore write did not round-trip — a hard failure, not silent.
            raise RuntimeError(f"identity for {agent_id!r} was not persisted to {self.home}")
        return did

    @property
    def private_key_seed(self) -> bytes | None:
        """This tenant's 32-byte Ed25519 seed, or None if keyless / invalid."""
        if not self.config.agent_id:
            return None
        priv_b64 = keystore.load_private_key(self.config.agent_id, dir=self.home)
        if not priv_b64:
            return None
        try:
            seed = base64.b64decode(priv_b64)
        except (ValueError, TypeError):
            return None
        return seed if len(seed) == 32 else None

    @property
    def did(self) -> str | None:
        """This tenant's issuer ``did:key``, or None if it has no valid seed."""
        seed = self.private_key_seed
        return arp.did_from_private_key(seed) if seed is not None else None

    # ── stores ──────────────────────────────────────────────────────

    @property
    def agency_log(self) -> arp.AgencyLog:
        """This tenant's local Agency Log (``home/agency-log.sqlite``)."""
        return arp.AgencyLog(self.home)

    @property
    def consent_db_path(self) -> Path:
        """Path to this tenant's consent ledger DB (not the active pointer)."""
        return self.home / "consent.db"

    def activate_consent(self) -> None:
        """Point the (process-global) consent-ledger singleton at THIS tenant.

        The consent-ledger module keeps a single active DB path per process, so
        B2b must call this at the start of a tenant turn to bind the ledger — and
        the AAE envelope emitter — to this tenant's ``home`` before recording
        consent events. Signs rows with this tenant's key when it has one.
        """
        from community_member.consent import ledger as _ledger

        seed = self.private_key_seed
        signing_key_b64 = base64.b64encode(seed).decode("ascii") if seed is not None else None
        _ledger.init(self.consent_db_path, signing_key_b64=signing_key_b64)

    # ── actions ─────────────────────────────────────────────────────

    def book_appointment(
        self,
        *,
        service: str,
        provider: str,
        datetime: str,
        notes: str = "",
        contact: Any = None,
        business_name: str = "",
    ) -> dict:
        """Book an appointment for THIS tenant via the built-in booking skill.

        The booking is written to ``home/bookings.json`` and a signed
        ``appointment_booked`` receipt is minted into THIS tenant's Agency Log
        (and pushed to its chapter when one is configured). No other tenant's
        stores are touched.

        ``contact`` is the channel this tenant's business receives bookings on.
        The caller supplies it because the tenant home records the business, not
        the routing: passing it through keeps one delivery path for every caller
        rather than a second one inside the host.
        """
        from community_member.builtin_skills.booking.skill import book_appointment

        return book_appointment(
            {
                "service": service,
                "provider": provider,
                "datetime": datetime,
                "notes": notes,
            },
            home=self.home,
            contact=contact,
            business_name=business_name,
        )

    # ── private memory (delegates to this tenant's Config) ───────────

    def save_private_memory(self, key: str, value: str, memory_type: str = "note") -> None:
        self.config.save_private_memory(key, value, memory_type)

    def load_private_memory(self) -> list[dict]:
        return self.config.load_private_memory()


__all__ = ["AgentContext"]
