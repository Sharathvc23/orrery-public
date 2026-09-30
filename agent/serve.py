"""Headless launcher for a Railway-deployed community-member agent.

Unlike ``run_agent.py`` (binds 127.0.0.1, no registry announce, expects an
interactive config), this is the PUBLIC-service entrypoint:

  * binds ``0.0.0.0:$PORT`` (Railway injects ``PORT``; ``BIND_HOST`` overrides
    the interface, e.g. ``127.0.0.1`` for a local two-agent run),
  * builds the agent's identity from env on first boot and a STABLE identity on
    every redeploy (keystore unlocked headlessly via
    ``COMMUNITY_MEMBER_KEYSTORE=passphrase`` + ``COMMUNITY_MEMBER_PASSPHRASE``),
  * joins its chapter once (TOFU self-signed; org ``join_policy=open``),
  * runs the A2A server + the NEST/Index announce loop (``AGENT_PUBLIC_URL``).

IDENTITY PERSISTENCE IS A HARD REQUIREMENT: mount a persistent volume at
``COMMUNITY_MEMBER_HOME`` (default ``~/.community-member``). The passphrase makes
a *persisted* keystore vault unlockable with no tty; it does NOT by itself make
identity stable — without the volume the vault is gone and every redeploy
re-mints a new did:key, orphaning the org/NEST/host39 registrations.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys

import uvicorn

from community_member import (
    CHANNEL_PORT,
    DASHBOARD_PORT,
    channel_receiver,
    channel_secrets,
    crypto,
    keystore,
    registry,
    think_interval_seconds,
)
from community_member.agent import LocalAgent
from community_member.auth import init_keys
from community_member.config import Config
from community_member.server import create_app


def _resolve_port() -> int:
    """Railway injects ``PORT``; fall back to the SDK dashboard port locally."""
    raw = os.environ.get("PORT", "").strip()
    if raw.isdigit():
        return int(raw)
    return DASHBOARD_PORT


def apply_pack_env() -> list[str]:
    """Install the skill packs this deployment names, and report what is active.

    ``AGENT_PACKS=hospitality,team``

    WHY THIS EXISTS. A pack's installed state lives in ``packs.json`` on the
    agent's volume, and nothing seeded it from the deployment — so the only way
    to give a remote agent a capability was to reach into its volume by hand.
    That makes a fleet unreproducible: a fresh deploy of the same service comes
    up without the capabilities its predecessor had, and nothing says so.

    This is the same contract ``AGENT_SKILLS`` already has. Skills describe what
    an agent claims; packs decide which tools it actually holds. Both now come
    from the deployment.

    ADDITIVE, deliberately. It installs and never uninstalls, because an
    operator who added a pack through the dashboard should not have it removed
    by an unrelated redeploy. The trade is that env is not the whole truth, so
    the effective set is printed rather than assumed.

    A named pack that does not exist is reported loudly. A typo here is an agent
    that comes up quietly unable to do its job, which is the failure mode worth
    the noise.
    """
    from community_member import skill_runtime

    wanted = [p.strip() for p in os.environ.get("AGENT_PACKS", "").split(",") if p.strip()]
    if wanted:
        known = set(skill_runtime.load_pack_manifests())
        for pack_id in wanted:
            if pack_id not in known:
                print(
                    f"[serve] pack {pack_id!r} is not a known pack — this agent will NOT have its "
                    f"tools. Known: {', '.join(sorted(known))}",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            skill_runtime.set_pack_installed(pack_id, True)

    active = sorted(skill_runtime.active_pack_skill_dirs())
    print(f"[serve] skill packs → requested={wanted or '(none)'} active_skills={active}", flush=True)
    return active


def report_index_announce(config) -> dict | None:
    """Claim this agent's index name, and SAY WHAT HAPPENED.

    `create_app`'s lifespan already calls `announce_to_index`, and its outcome
    goes to `log.info` — which uvicorn's log config does not surface, so on a
    real deploy the result was invisible. An agent that silently did not register
    looks identical to one that did, and the only symptom is a counterparty
    refusing it later for a reason that points somewhere else entirely.

    Idempotent: `ensure_registered` resolves before writing, so being called
    from both here and the lifespan claims nothing twice. Never fatal — an
    agent that cannot register is still an agent.
    """
    if not os.environ.get("NANDA_INDEX_V3_URL", "").strip():
        # "Off" and "silent" are different facts, and an operator debugging a
        # refusal needs to know which one they are looking at.
        print("[serve] index v3 → off (NANDA_INDEX_V3_URL unset)", flush=True)
        return None
    try:
        from community_member.index_boot import announce_to_index

        outcome = announce_to_index(config)
        print(f"[serve] index v3 → {outcome}", flush=True)
        return outcome
    except Exception as exc:  # noqa: BLE001 — loud, keep serving
        print(
            f"[serve] index v3 registration failed (still serving): {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return {"action": "failed", "detail": f"{type(exc).__name__}: {exc}"}


def _build_config() -> Config:
    """Load (disk) → overlay env → restore the persisted identity → save.

    The identity must survive redeploys. The keystore is keyed on ``agent_id``,
    which the env may only just have supplied on a fresh, config.json-less
    deploy, so we restore the private key AFTER the env overlay — then DERIVE the
    public key from it before ``ensure_keypair`` (otherwise an empty public_key
    makes ``has_keypair()`` False and ``ensure_keypair`` re-mints a NEW identity).
    """
    config = Config.load()

    # Env overlay — Railway provides identity via env on the first boot.
    config.agent_id = os.environ.get("AGENT_ID", "").strip() or config.agent_id
    config.name = os.environ.get("AGENT_NAME", "").strip() or config.name
    config.description = os.environ.get("AGENT_DESCRIPTION", "").strip() or config.description
    config.chapter_url = os.environ.get("CHAPTER_URL", "").strip() or config.chapter_url
    skills_env = os.environ.get("AGENT_SKILLS", "").strip()
    if skills_env:
        config.skills = [s.strip() for s in skills_env.split(",") if s.strip()]

    # LLM BYOK — non-secret provider/model overlay (safe to persist).
    # The API key is overlaid AFTER save() below so the plaintext secret stays
    # in-memory only. Each overrides only when its env var is set.
    config.provider = os.environ.get("AGENT_PROVIDER", "").strip() or config.provider
    config.model = os.environ.get("AGENT_MODEL", "").strip() or config.model

    # Restore the persisted private key (keystore keyed on the now-set agent_id).
    if config.agent_id and not config.private_key:
        stored = keystore.load_private_key(config.agent_id)
        if stored:
            config.private_key = stored

    # Derive the public key from the restored private key BEFORE ensure_keypair,
    # so a redeploy without config.json doesn't silently re-mint the identity.
    if config.private_key and not config.public_key:
        try:
            config.public_key = crypto.ed25519_public_from_private(config.private_key)
        except Exception as exc:  # noqa: BLE001 — loud, never silent
            print(f"[serve] could not derive public key from stored private key: {exc}", file=sys.stderr)

    config.ensure_keypair()  # mints ONLY on a genuine first boot (no keypair yet)
    config.save()  # persist keypair (keystore) + config.json on the volume

    # BYOK API key from env, set AFTER save() so the plaintext key is NEVER
    # written to the volume's config.json (it would outlive an env-var rotation
    # and is readable by anyone with volume access). The Railway env var is the
    # secret store; this keeps the key in-memory for is_configured() + the LLM
    # client. Accept ANTHROPIC_API_KEY as an alias.
    api_key_env = os.environ.get("AGENT_API_KEY", "").strip() or os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key_env:
        config.api_key = api_key_env
    return config


def main() -> int:
    config = _build_config()
    if not config.agent_id:
        print("[serve] AGENT_ID is required (set it in the env).", file=sys.stderr)
        return 1
    if not config.has_keypair():
        print(
            "[serve] no Ed25519 keypair — keystore unlock failed (check COMMUNITY_MEMBER_PASSPHRASE).", file=sys.stderr
        )
        return 1

    init_keys(config.private_key, config.public_key)
    agent = LocalAgent(config)
    app = create_app(config, agent)

    port = _resolve_port()
    # Every interface by default (a Railway service has to be reachable); a
    # host running several agents for itself can keep them on loopback.
    bind_host = os.environ.get("BIND_HOST", "").strip() or "0.0.0.0"
    advertised = registry.public_endpoint(f"http://localhost:{port}")
    print(f"[serve] @{config.agent_id} on {bind_host}:{port} → {advertised}", flush=True)
    print(f"[serve] chapter: {config.chapter_url or '(none)'}", flush=True)

    def _shutdown(*_):
        print("[serve] stopping…", flush=True)
        agent.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    async def _join_once() -> None:
        """Join the chapter once at startup (headless: no LLM/user to trigger
        the join_chapter tool). Off the event loop so the server binds first;
        non-fatal so a momentarily-unreachable chapter never blocks serving."""
        if not config.chapter_url:
            return
        # W11 TOFU: pin the chapter's identity on connect; warn loudly (but keep
        # serving) if its key/id changed since first contact (rotation / MITM).
        try:
            status, msg = await asyncio.to_thread(agent.client.tofu_verify_chapter)
            if status == "warning":
                print(f"[serve] CHAPTER TRUST WARNING: {msg}", file=sys.stderr, flush=True)
            else:
                print(f"[serve] chapter trust [{status}]: {msg}", flush=True)
        except Exception as exc:  # noqa: BLE001 — never block serving
            print(f"[serve] chapter TOFU skipped: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        try:
            result = await asyncio.to_thread(
                lambda: agent.client.join_chapter(
                    config.agent_id,
                    config.name,
                    config.description,
                    config.skills,
                    # advertise the public URL so a host39-less org can
                    # resolve this member to its own served agent.json.
                    endpoint=advertised,
                )
            )
            print(f"[serve] join → {result}", flush=True)
        except Exception as exc:  # noqa: BLE001 — loud, keep serving
            print(
                f"[serve] join_chapter failed (still serving): {type(exc).__name__}: {exc}", file=sys.stderr, flush=True
            )

    # Claim this agent's index name, and SAY WHAT HAPPENED.
    #
    # `create_app`'s lifespan already calls this, and its outcome goes to
    # `log.info` — which uvicorn's log config does not surface, so on a real
    # deploy the result was invisible. An agent that silently does not register
    # looks identical to one that did, and the only symptom is a counterparty
    # refusing it later for a reason that points at the wrong thing.
    #
    # Reported here the way every other boot step reports, and idempotent:
    # `ensure_registered` resolves before writing, so calling it twice claims
    # nothing twice.
    # Packs before anything reads the tool set: an agent that registers and
    # starts thinking before its capabilities are installed advertises less than
    # it has.
    apply_pack_env()
    report_index_announce(config)

    # Think-loop cadence. 300s is the production default; the override
    # exists so live-process tests (tests/e2e/) can drive full
    # planner→gate→executor cycles without five-minute waits.
    think_interval = think_interval_seconds()

    async def _settings_sync_once() -> None:
        """W11: pull the member's settings from the chapter and replay any
        writes queued in the offline outbox while disconnected. Off the event
        loop so serving isn't blocked; non-fatal so a momentarily-unreachable
        chapter never blocks startup (settings_sync degrades to the cache)."""
        if not config.chapter_url:
            return
        try:
            from community_member import outbox, settings_sync

            await asyncio.to_thread(settings_sync.sync_on_startup, config.agent_id, agent.client)
            await outbox.drain(config.agent_id, agent.client)
        except Exception as exc:  # noqa: BLE001 — loud, keep serving
            print(f"[serve] settings sync skipped: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

    # W11: inbound channel receiver on CHANNEL_PORT — started only when a channel
    # is configured locally (a stored per-connection secret). Platforms POST
    # webhooks here directly; verified events land in a shared inbox the agent
    # loop drains.
    channel_server = None
    if channel_secrets.has_any():
        channel_inbox = channel_receiver.Inbox()
        agent.inbox = channel_inbox
        channel_app = channel_receiver.build_app(inbox=channel_inbox, secret_resolver=channel_secrets.get_secret)
        channel_server = uvicorn.Server(
            uvicorn.Config(channel_app, host="0.0.0.0", port=CHANNEL_PORT, log_level="info")
        )
        print(f"[serve] inbound channel receiver on 0.0.0.0:{CHANNEL_PORT}", flush=True)

    async def _run() -> None:
        server = uvicorn.Server(uvicorn.Config(app, host=bind_host, port=port, log_level="info"))
        tasks = [
            server.serve(),
            _join_once(),
            _settings_sync_once(),
            agent.run(interval=think_interval),
            registry.announce_loop(config, local_url=f"http://localhost:{port}"),
        ]
        if channel_server is not None:
            tasks.append(channel_server.serve())
        await asyncio.gather(*tasks)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
