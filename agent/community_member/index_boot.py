"""Boot-time index registration — claim this agent's own name, if asked to.

At startup, when ``NANDA_INDEX_V3_URL`` names an index, the agent claims
``urn:ai:key:<its own public key>`` there and points it at its agent card. Off
by default: an agent should not publish itself to a third party because it
happened to start.

Honesty contract
----------------

* **Self-registration only.** The v3 ``key`` anchor admits exactly
  ``urn:ai:key:<subject_key>`` and paths beneath it, and the signature is made
  by the key that name *is*. Nothing here can register any agent but this one,
  which is the property that makes the name mean something.

* **One key, three views.** The key signing this is the one ``auth`` signs
  requests with and the one ``arp`` derives ``did:key`` from for receipts. The
  index name, the card's DID and every receipt's issuer are one key in three
  encodings — asserted in ``tests/test_index_v3.py``, not assumed.

* **Registers only when the index has nothing current.** A v3 record expires and
  *revocation is non-renewal*, so re-registering on start is the lifecycle
  rather than an exception to it. Doing it unconditionally would turn a restart
  loop into a run of entries in a log that cannot be edited, so this resolves
  first and writes only when the record is missing or close to lapsing.

* **Never fatal.** An index that is unreachable or refusing must not stop the
  agent serving peers that already know where it is. Failures are logged with
  what happened and the agent carries on.

* **Refuses to publish a pointer it cannot address.** Without a public base URL
  there is nothing truthful to register: a ``next_hop`` guessed from a local
  bind address sends every resolver somewhere it cannot reach.

Lifespan, not module import, for the same reason ``conformance_boot`` is —
building the app in a unit test must not register anything with a live index.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

__all__ = ["announce_to_index"]

URL_ENV = "NANDA_INDEX_V3_URL"
BASE_URL_ENV = "AGENT_PUBLIC_URL"
PATH_ENV = "NANDA_INDEX_V3_PATH"
CARD_PATH = "/.well-known/agent-card.json"


def announce_to_index(config) -> dict | None:
    """Claim this agent's index name. Returns the outcome, or ``None`` if off.

    ``config`` is the agent config; its ``private_key`` is the base64 seed the
    rest of the runtime signs with.
    """
    index_url = os.environ.get(URL_ENV, "").strip()
    if not index_url:
        return None

    base_url = os.environ.get(BASE_URL_ENV, "").strip()
    if not base_url:
        log.warning(
            "%s is set but %s is not; not registering a pointer this agent cannot be reached at",
            URL_ENV,
            BASE_URL_ENV,
        )
        return {"action": "skipped", "detail": f"{BASE_URL_ENV} unset"}

    private_key = getattr(config, "private_key", "") or ""
    if not private_key:
        # Without a keypair there is no name to claim: the identifier IS the key.
        log.warning("no signing key on this agent; nothing to register")
        return {"action": "skipped", "detail": "no signing key"}

    from .index_v3 import ensure_registered

    result = ensure_registered(
        index_url=index_url,
        private_key_b64=private_key,
        next_hop=f"{base_url.rstrip('/')}{CARD_PATH}",
        path=os.environ.get(PATH_ENV, "").strip() or "agent",
    )
    log.info("index v3: %s %s", result.get("action"), result.get("id", ""))
    return result


# ── keeping the name, not just claiming it ──────────────────────────────────

#: How often to re-check the registration. A v3 record lives three days and
#: ``ensure_registered`` renews inside the last twelve hours, so hourly is far
#: more often than strictly needed — and that is the point: a tick that only just
#: keeps up has no margin for the hours an index is unreachable, and the check
#: costs one resolve when nothing is due.
RENEW_INTERVAL_SECONDS = 3600.0


async def renew_forever(config, *, interval: float = RENEW_INTERVAL_SECONDS, sleep=None) -> None:
    """Re-announce on a clock, forever.

    ⚠️ WITHOUT THIS THE NAME LAPSES AND THE AGENT STOPS BEING A PEER.

    A v3 record lives three days and ``announce_to_index`` ran once, at startup.
    So an agent stayed resolvable for exactly as long as it had been running, and
    on the fourth day its name expired — at which point a counterparty that
    requires an index-resolvable caller refuses it. Measured on the live estate:
    every record expired within 61 hours of being read, and the only reason
    nothing had broken was that deploys kept restarting the clock.

    ``announce_to_index`` already knows the whole rule — it resolves first,
    renews only when the record is close to lapsing, and returns ``current``
    otherwise. The log is append-only, so an agent that re-registered every tick
    would write a run of identical entries into a history nobody can edit. This
    supplies the clock and nothing else.

    Never raises. An index that is down is somebody else's outage, and turning it
    into this agent's crash would take the agent off the air for the one reason
    renewal exists to prevent.
    """
    import asyncio

    nap = sleep or asyncio.sleep
    while True:
        await nap(interval)
        try:
            result = await asyncio.to_thread(announce_to_index, config)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - an outage is not a crash
            log.warning("[index] renewal could not reach the index: %s", exc)
            continue
        if result is None:
            continue
        action = result.get("action")
        if action in ("renewed", "registered"):
            # The moment the agent would otherwise have lapsed. An operator
            # reading logs should be able to see that it did not.
            log.info("[index] %s seq=%s expires=%s", action, result.get("seq"), result.get("expires_at"))
        elif action not in ("current", "skipped"):
            log.warning("[index] renewal %s: %s", action, str(result.get("detail", ""))[:200])
