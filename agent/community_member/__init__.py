"""community-member — Your sovereign AI agent for an org of accountable agents.

Naming: the product calls this the agent and the org server an org; this
package name and the protocol noun in wire ids (``chapter_id``) are frozen —
see docs/ARCHITECTURE.md § Two nouns.
"""

import os as _os
import socket as _socket

__version__ = "0.8.0"

# Preferred dashboard port. This is just the *starting* preference — the agent
# auto-picks a free port at launch (see find_free_port), so it still runs even
# when 7777 is already taken. Set COMMUNITY_MEMBER_PORT to change the preference.
DASHBOARD_PORT = int(_os.environ.get("COMMUNITY_MEMBER_PORT", "7777"))
CHANNEL_PORT = int(_os.environ.get("COMMUNITY_MEMBER_CHANNEL_PORT", "7778"))

# Seconds between autonomous think cycles. Read here rather than at each
# entry point so the `community-member` command and the container
# entrypoint (agent/serve.py) cannot end up honouring the variable on one
# path and ignoring it on the other.
THINK_INTERVAL_ENV_VAR = "COMMUNITY_MEMBER_THINK_INTERVAL"
DEFAULT_THINK_INTERVAL_SECONDS = 300


def think_interval_seconds() -> int:
    """Seconds between think cycles, from the environment.

    Read at call time so a process that sets the variable after import is
    honoured. A value that is not a positive integer falls back to the
    default rather than crashing the loop or spinning at zero.
    """
    raw = _os.environ.get(THINK_INTERVAL_ENV_VAR, "").strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_THINK_INTERVAL_SECONDS
    return value if value > 0 else DEFAULT_THINK_INTERVAL_SECONDS


# Host interface the dashboard listens on. The dashboard serves
# ``/api/local/*``, which carries no authentication and can change the consent
# gate's settings, so it defaults to loopback. Set COMMUNITY_MEMBER_BIND_HOST
# (for example ``0.0.0.0``) only when something else provides access control in
# front of it. This governs the ``community-member`` command; the container
# entrypoint (agent/serve.py) binds all interfaces because Compose publishes its
# port on the host address given by AGENT_BIND_HOST.
DASHBOARD_BIND_HOST = _os.environ.get("COMMUNITY_MEMBER_BIND_HOST", "").strip() or "127.0.0.1"


def find_free_port(preferred: int | None = None, host: str | None = None) -> int:
    """Return a usable TCP port so the dashboard 'just works' even when the
    preferred one is busy.

    Tries ``preferred`` (default: ``DASHBOARD_PORT``), then the next 63 ports
    above it, then falls back to an OS-assigned free port. The agent runs on
    whatever this returns — never crashing with "address already in use".

    ``host`` defaults to :data:`DASHBOARD_BIND_HOST`. The probe binds the same
    address the server will, so a port held on another interface does not make
    this skip a port that is free on the bind host.
    """
    start = preferred or DASHBOARD_PORT
    bind_host = host or DASHBOARD_BIND_HOST
    for port in range(start, start + 64):
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            try:
                s.bind((bind_host, port))
                return port
            except OSError:
                continue
    # Nothing free near the preference — let the OS assign one.
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind((bind_host, 0))
        return s.getsockname()[1]
