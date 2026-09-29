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
