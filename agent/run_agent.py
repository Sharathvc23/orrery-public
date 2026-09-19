"""Headless launcher — skips the interactive wizard.

Loads the existing config from ~/.community-member/, builds the agent +
FastAPI app, and runs uvicorn. Honors COMMUNITY_MEMBER_PORT.
"""

import asyncio
import signal
import sys

import uvicorn

from community_member import CHANNEL_PORT, DASHBOARD_PORT, channel_receiver, channel_secrets
from community_member.agent import LocalAgent
from community_member.auth import init_keys
from community_member.config import Config
from community_member.server import create_app


def main() -> int:
    config = Config.load()
    if not config.is_configured():
        print("not configured — run `community-member` once to set up.")
        return 1
    init_keys(config.private_key, config.public_key)

    agent = LocalAgent(config)
    app = create_app(config, agent)

    port = DASHBOARD_PORT
    print(f"@{config.agent_id} → http://127.0.0.1:{port}")
    print(f"chapter: {config.chapter_url}")
    print(f"provider: {config.provider} ({config.model})")

    def _shutdown(*_):
        print("\nstopping…")
        agent.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    async def _settings_sync_once() -> None:
        """W11: TOFU-pin the chapter, then pull settings + replay the offline
        outbox. Off the event loop, non-fatal (settings_sync degrades to the
        cache; a chapter-trust change warns but never blocks)."""
        if not config.chapter_url:
            return
        try:
            status, msg = await asyncio.to_thread(agent.client.tofu_verify_chapter)
            if status == "warning":
                print(f"CHAPTER TRUST WARNING: {msg}", file=sys.stderr, flush=True)
        except Exception as exc:  # noqa: BLE001 — never block startup
            print(f"chapter TOFU skipped: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        try:
            from community_member import outbox, settings_sync

            await asyncio.to_thread(settings_sync.sync_on_startup, config.agent_id, agent.client)
            await outbox.drain(config.agent_id, agent.client)
        except Exception as exc:  # noqa: BLE001 — loud, keep serving
            print(f"settings sync skipped: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

    # W11: inbound channel receiver on CHANNEL_PORT (localhost) — only when a
    # channel is configured locally. Verified events land in a shared inbox the
    # agent loop drains.
    channel_server = None
    if channel_secrets.has_any():
        channel_inbox = channel_receiver.Inbox()
        agent.inbox = channel_inbox
        channel_app = channel_receiver.build_app(inbox=channel_inbox, secret_resolver=channel_secrets.get_secret)
        channel_server = uvicorn.Server(
            uvicorn.Config(channel_app, host="127.0.0.1", port=CHANNEL_PORT, log_level="info")
        )
        print(f"channel receiver → http://127.0.0.1:{CHANNEL_PORT}")

    async def _run():
        cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
        server = uvicorn.Server(cfg)
        tasks = [server.serve(), _settings_sync_once(), agent.run(interval=300)]
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
