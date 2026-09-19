"""Reality guards for deploy-surface claims the audit found broken.

Classification: DEPLOY↔DOC PARITY / CONTRACT.
"""

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]


def _installer() -> ModuleType:
    loader = SourceFileLoader("orrery_up_test", str(REPO / "orrery-up"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _render_compose(
    extra_env: dict[str, str] | None = None,
    compose_files: tuple[str, ...] = (),
    *,
    env_file: Path | None = None,
) -> dict:
    env = os.environ.copy()
    env.update(
        {
            "POSTGRES_PASSWORD": "compose-test-password",
            # Required by the db service: the non-superuser role the server connects as.
            "APP_DB_PASSWORD": "compose-test-app-password",
            "ORRERY_KEY_SECRET": "compose-test-key",
            "COMMUNITY_MEMBER_PASSPHRASE": "compose-test-passphrase",
            "SERVER_BIND_HOST": "",
            "AGENT_BIND_HOST": "",
        }
    )
    env.update(extra_env or {})
    command = ["docker", "compose"]
    if env_file is not None:
        command.extend(["--env-file", str(env_file)])
    for path in compose_files:
        command.extend(["-f", path])
    # The profiles the installer itself runs, read out of `orrery-up` rather
    # than spelled out here: these assertions are about what a real install
    # renders, and a hardcoded profile list would keep passing while a service
    # the installer starts went unexamined — which is what happened when the
    # renderer became a service and this helper still rendered `agent` alone.
    command.extend([*_installer().PROFILES, "config", "--format", "json"])
    result = subprocess.run(
        command,
        cwd=REPO,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


SUPPORTED_SERVER_CONFIG = {
    "ORRERY_PROFILE": "dev",
    "LLM_PROVIDER": "openai",
    "LLM_MODEL": "compose-model-sentinel",
    "LLM_BASE_URL": "https://llm.example.invalid/v1",
    "ORG_RETENTION_SWEEP_ENABLED": "false",
    "ORG_RETENTION_SWEEP_DRY_RUN": "true",
    "ORG_ADMIN_TOKEN": "admin-token-sentinel",
    "KLAVIYO_LIVE_SENDS": "ture",
    "KLAVIYO_API_KEY": "klaviyo-key-sentinel",
}

SUPPORTED_SERVER_DEFAULTS = {
    "ORRERY_PROFILE": "prod",
    "LLM_PROVIDER": "",
    "LLM_MODEL": "",
    "LLM_BASE_URL": "",
    "ORG_RETENTION_SWEEP_ENABLED": "true",
    "ORG_RETENTION_SWEEP_DRY_RUN": "false",
    "ORG_ADMIN_TOKEN": "",
    "KLAVIYO_LIVE_SENDS": "false",
    "KLAVIYO_API_KEY": "",
}


def _rendered_server_environment(
    extra_env: dict[str, str] | None = None,
    *,
    env_file: Path | None = None,
) -> dict[str, str]:
    return _render_compose(extra_env, env_file=env_file)["services"]["server"]["environment"]


def test_supported_server_settings_reach_the_compose_container() -> None:
    environment = _rendered_server_environment(SUPPORTED_SERVER_CONFIG)
    actual = {key: environment.get(key) for key in SUPPORTED_SERVER_CONFIG}
    assert actual == SUPPORTED_SERVER_CONFIG


def test_supported_server_settings_keep_safe_compose_defaults() -> None:
    empty_inputs = {key: "" for key in SUPPORTED_SERVER_DEFAULTS}
    environment = _rendered_server_environment(empty_inputs)
    actual = {key: environment.get(key) for key in SUPPORTED_SERVER_DEFAULTS}
    assert actual == SUPPORTED_SERVER_DEFAULTS


def test_supported_server_settings_keep_safe_defaults_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in SUPPORTED_SERVER_DEFAULTS:
        monkeypatch.delenv(key, raising=False)
    empty_env_file = tmp_path / "empty.env"
    empty_env_file.write_text("")

    environment = _rendered_server_environment(env_file=empty_env_file)
    actual = {key: environment.get(key) for key in SUPPORTED_SERVER_DEFAULTS}

    assert actual == SUPPORTED_SERVER_DEFAULTS


def test_compose_excludes_unresolved_alias_and_container_owned_settings() -> None:
    excluded = {
        "TRUSTED_PROXY_HOPS": "2",
        "FORWARDED_ALLOW_IPS": "10.20.30.40",
        "NANDA_INDEX_URL": "https://index.example.invalid",
        "INDEX_ACCOUNT_EMAIL": "operator@example.invalid",
        "INDEX_ACCOUNT_PASSWORD": "index-password-sentinel",
        "INDEX_ORG_ID": "compose-org-sentinel",
        "ORG_DOMAIN": "org.example.invalid",
        "ORG_CONTACT_EMAIL": "contact@example.invalid",
        "ORG_HOME": "/tmp/operator-org-home",
        "CHAPTER_HOME": "/tmp/legacy-org-home",
        "CHAPTER_ADMIN_TOKEN": "legacy-admin-token",
        "CHAPTER_RETENTION_SWEEP_ENABLED": "false",
        "CHAPTER_RETENTION_SWEEP_DRY_RUN": "true",
        "DEFAULT_LLM_MODEL": "legacy-model",
        "ORRERY_LISTING_ENABLED": "true",
    }
    environment = _rendered_server_environment(excluded)
    assert excluded.keys().isdisjoint(environment)
    assert environment["MEMBER_PERSIST_OUTBOX_PATH"] == "/app/server/.org/member_persist_outbox.jsonl"


def _compose_server_hash(
    extra_env: dict[str, str] | None = None,
    *,
    env_file: Path,
) -> str:
    env = os.environ.copy()
    env.update(
        {
            "POSTGRES_PASSWORD": "compose-test-password",
            # Required by the db service: the non-superuser role the server connects as.
            "APP_DB_PASSWORD": "compose-test-app-password",
            "ORRERY_KEY_SECRET": "compose-test-key",
            "COMMUNITY_MEMBER_PASSPHRASE": "compose-test-passphrase",
            "SERVER_BIND_HOST": "",
            "AGENT_BIND_HOST": "",
        }
    )
    env.update(extra_env or {})
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "--profile",
            "agent",
            "config",
            "--hash",
            "server",
        ],
        cwd=REPO,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_compose_preserves_single_quoted_dollars_in_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KLAVIYO_API_KEY", raising=False)
    quoted_env_file = tmp_path / "quoted.env"
    quoted_env_file.write_text("KLAVIYO_API_KEY='literal$dollar$value'\n")
    empty_env_file = tmp_path / "empty.env"
    empty_env_file.write_text("")

    quoted_hash = _compose_server_hash(env_file=quoted_env_file)
    direct_hash = _compose_server_hash({"KLAVIYO_API_KEY": "literal$dollar$value"}, env_file=empty_env_file)
    empty_hash = _compose_server_hash({"KLAVIYO_API_KEY": ""}, env_file=empty_env_file)

    assert quoted_hash == direct_hash
    assert quoted_hash != empty_hash


def test_installer_keeps_its_explicit_local_development_profile() -> None:
    installer = _installer()
    args = SimpleNamespace(
        org_id="test-org",
        org_name="Test Org",
        agent_id="test-agent",
        agent_name="Test Agent",
        provider="",
        api_key="",
        model="",
        server_port=7000,
        agent_port=8080,
        renderer_port=8600,
    )

    generated = installer.parse_env(installer.render_env(args))

    assert generated["ORRERY_PROFILE"] == "dev"


@pytest.mark.parametrize("service", ["server", "agent", "renderer"])
def test_default_host_ports_are_loopback_only(service: str) -> None:
    rendered = _render_compose()
    [published_port] = rendered["services"][service]["ports"]
    assert published_port["host_ip"] == "127.0.0.1"


def test_server_and_agent_bind_hosts_can_be_overridden_independently() -> None:
    rendered = _render_compose({"SERVER_BIND_HOST": "0.0.0.0", "AGENT_BIND_HOST": "127.0.0.2"})
    [server_port] = rendered["services"]["server"]["ports"]
    [agent_port] = rendered["services"]["agent"]["ports"]
    assert server_port["host_ip"] == "0.0.0.0"
    assert agent_port["host_ip"] == "127.0.0.2"


def test_bind_host_defaults_are_visible_in_env_example() -> None:
    env_example = (REPO / ".env.example").read_text()
    assert "SERVER_BIND_HOST=127.0.0.1" in env_example
    assert "AGENT_BIND_HOST=127.0.0.1" in env_example


def test_aws_ec2_alb_path_opts_into_external_server_bind() -> None:
    deploy_aws = (REPO / "docs" / "DEPLOY_AWS.md").read_text()
    path_a = deploy_aws.split("## Path A — the compose stack on one EC2 instance", maxsplit=1)[1].split(
        "## Path B — ECS Fargate + RDS", maxsplit=1
    )[0]
    procedure = path_a.split("1. **Instance.**", maxsplit=1)[1].split("### Keeping it up", maxsplit=1)[0]

    assert "SERVER_BIND_HOST=0.0.0.0" in path_a
    assert procedure.index("4. **Write `.env` before the first `up`**") < procedure.index("`./orrery-up`")


def test_local_e2e_second_server_is_loopback_only() -> None:
    rendered = _render_compose(compose_files=("docker-compose.yml", "infra/compose.e2e-federation.yml"))
    [published_port] = rendered["services"]["server2"]["ports"]
    assert published_port["host_ip"] == "127.0.0.1"


def test_installer_checks_the_actual_bind_addresses(monkeypatch) -> None:
    installer = _installer()
    bound: list[tuple[str, int]] = []
    families: list[int] = []

    class BindablePort:
        def __init__(self, family: int = socket.AF_INET, socket_type: int = socket.SOCK_STREAM):
            families.append(family)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, address: tuple[str, int]) -> None:
            bound.append(address)

        def connect_ex(self, address: tuple[str, int]) -> int:
            pytest.fail("port availability must be tested by binding, not connecting")

    monkeypatch.setattr(installer, "_run", lambda *args, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(socket, "socket", BindablePort)

    env = {
        "SERVER_BIND_HOST": "10.0.0.5",
        "SERVER_PORT": "7100",
        "AGENT_BIND_HOST": "0.0.0.0",
        "AGENT_PORT": "8180",
        "RENDERER_BIND_HOST": "10.0.0.6",
        "RENDERER_PORT": "8600",
    }
    unnamed = SimpleNamespace(server_port=None, agent_port=None, renderer_port=None)
    installer.check_ports(installer.resolve_ports(unnamed, env))

    # Every port the installer PUBLISHES is a port it verifies, on the address
    # the operator configured. All three are pinned in this .env, so all three
    # are checked — an allocated port needs no second verdict because finding
    # it meant binding it.
    assert bound == [("10.0.0.5", 7100), ("0.0.0.0", 8180), ("10.0.0.6", 8600)]
    assert families == [socket.AF_INET, socket.AF_INET, socket.AF_INET]


def test_installer_rejects_an_occupied_wildcard_bind(monkeypatch) -> None:
    installer = _installer()

    class OccupiedPort:
        def __init__(self, family: int = socket.AF_INET, socket_type: int = socket.SOCK_STREAM):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, address: tuple[str, int]) -> None:
            raise OSError("address already in use")

    monkeypatch.setattr(installer, "_run", lambda *args, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(socket, "socket", OccupiedPort)

    # Pinned in .env, so resolution reuses it and check_ports gives the verdict.
    # A wildcard bind that cannot be taken is refused, not routed around: the
    # org is already publishing this port inside its did:web.
    resolved = installer.resolve_ports(
        SimpleNamespace(server_port=None, agent_port=None, renderer_port=None),
        {
            "SERVER_BIND_HOST": "0.0.0.0",
            "SERVER_PORT": "7100",
            "AGENT_BIND_HOST": "127.0.0.1",
            "AGENT_PORT": "8180",
            "RENDERER_BIND_HOST": "127.0.0.1",
            "RENDERER_PORT": "8600",
        },
    )
    with pytest.raises(SystemExit):
        installer.check_ports(resolved)


def test_installer_refuses_a_busy_renderer_port_and_names_its_flag(capsys) -> None:
    """Same refusal shape as the other two ports: what could not be bound, the
    OS error, and the flag that moves it. A third port checked but described
    with the wrong flag sends the operator to edit the wrong setting."""
    installer = _installer()

    class OccupiedPort:
        def __init__(self, family: int = socket.AF_INET, socket_type: int = socket.SOCK_STREAM):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, address: tuple[str, int]) -> None:
            if address[1] == 8600:
                raise OSError("address already in use")

    installer._run = lambda *args, **kwargs: SimpleNamespace(stdout="")
    env = {
        "SERVER_BIND_HOST": "127.0.0.1",
        "SERVER_PORT": "7100",
        "AGENT_BIND_HOST": "127.0.0.1",
        "AGENT_PORT": "8180",
        "RENDERER_BIND_HOST": "127.0.0.1",
        "RENDERER_PORT": "8600",
    }
    named = SimpleNamespace(server_port=None, agent_port=None, renderer_port=8600)
    resolved = installer.resolve_ports(named, env)
    original = socket.socket
    socket.socket = OccupiedPort
    try:
        with pytest.raises(SystemExit):
            installer.check_ports(resolved)
    finally:
        socket.socket = original

    message = capsys.readouterr().err
    assert "127.0.0.1:8600" in message
    assert "reference renderer" in message
    assert "--renderer-port" in message


def test_a_pinned_port_is_reused_rather_than_reallocated() -> None:
    """THE IDENTITY PROPERTY. The org publishes `did:web:<host>:<port>:agents:<id>`
    and every endpoint under the same origin, so a port re-chosen on each run
    would rename the org on each run. A port already in `.env` is therefore
    reused unconditionally — including when it is busy, where the honest answer
    is to refuse rather than to quietly move the org's name."""
    installer = _installer()
    unnamed = SimpleNamespace(server_port=None, agent_port=None, renderer_port=None)

    resolved = {
        c["service"]: c
        for c in installer.resolve_ports(
            unnamed, {"SERVER_PORT": "7123", "AGENT_PORT": "8123", "RENDERER_PORT": "8623"}
        )
    }
    assert [resolved[s]["port"] for s in ("server", "agent", "renderer")] == [7123, 8123, 8623]
    assert {c["source"] for c in resolved.values()} == {"pinned"}


def test_a_named_port_outranks_a_pinned_one_and_is_never_reassigned() -> None:
    """Allocation is the default, not an override of intent. An operator who
    names a port means that port, so it wins over `.env` — and a collision on it
    is a refusal, because silently substituting another answers a question
    nobody asked."""
    installer = _installer()
    named = SimpleNamespace(server_port=7999, agent_port=None, renderer_port=None)

    resolved = {c["service"]: c for c in installer.resolve_ports(named, {"SERVER_PORT": "7123", "AGENT_PORT": "8123"})}
    assert resolved["server"]["port"] == 7999 and resolved["server"]["source"] == "flag"
    assert resolved["agent"]["source"] == "pinned", "naming one port must not disturb the others"


def test_a_running_service_does_not_excuse_a_port_it_does_not_hold(monkeypatch, capsys) -> None:
    """`check_ports` skips addresses a running stack already binds — and the
    skip has to match the ADDRESS, not the service name.

    Driven at the branch head before this assertion existed: with the stack up
    on 7001, `./orrery-up --server-port 7000` was ACCEPTED while an unrelated
    process held 7000, because `server` was in the running set. The operator was
    told nothing and compose would have failed to publish the port. The skip now
    compares against what `.env` pinned, which is the address the running stack
    was actually started on.
    """
    installer = _installer()

    class OccupiedPort:
        def __init__(self, family: int = socket.AF_INET, socket_type: int = socket.SOCK_STREAM):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, address: tuple[str, int]) -> None:
            if address[1] == 7000:
                raise OSError("address already in use")

    # every service reports as running
    monkeypatch.setattr(installer, "_run", lambda *a, **k: SimpleNamespace(stdout="server\nagent\nrenderer\n"))
    monkeypatch.setattr(socket, "socket", OccupiedPort)
    env = {"SERVER_PORT": "7001", "AGENT_PORT": "8083", "RENDERER_PORT": "8601"}

    # the port the running stack holds is skipped...
    installer.check_ports(
        installer.resolve_ports(SimpleNamespace(server_port=None, agent_port=None, renderer_port=None), env)
    )

    # ...but a DIFFERENT port, named by the operator, is not excused by it.
    with pytest.raises(SystemExit):
        installer.check_ports(
            installer.resolve_ports(SimpleNamespace(server_port=7000, agent_port=None, renderer_port=None), env)
        )
    assert "127.0.0.1:7000" in capsys.readouterr().err


def test_installer_teardown_names_every_profile_it_starts() -> None:
    """THE LIFECYCLE PROPERTY, asserted where it is cheap to assert.

    The renderer is a Compose service so that `./orrery-up down` stops it. That
    only holds while teardown names the profile the service lives in — a
    service in a profile `down` does not name is a container the installer
    walks past, which is exactly the leaked listener the service shape exists
    to prevent. `PROFILES` is the single list every compose invocation uses, so
    this asserts the renderer's profile is in it and that `compose()` builds
    its command from it rather than spelling one out.

    The end-to-end form of this runs against a live stack in
    ``scripts/installer_lifecycle_check.py``; this is the offline half.
    """
    installer = _installer()
    source = (REPO / "orrery-up").read_text()

    assert "ui" in installer.PROFILES, "the renderer's profile must be in PROFILES or down walks past it"
    assert "agent" in installer.PROFILES

    compose_body = source.split("def compose(")[1].split("\ndef ")[0]
    assert "*PROFILES" in compose_body, (
        "compose() must build its command from PROFILES; a spelled-out profile "
        "list is a second copy that drifts from the one teardown uses"
    )

    down_branch = source.split('if args.command == "down":')[1].split("return 0")[0]
    assert "compose(" in down_branch, "down must go through compose(), which carries PROFILES"


def test_installer_drill_uses_the_configured_bind_addresses() -> None:
    """Both halves of the drill honour the operator's bind addresses.

    The banner is the second half and used not to be here at all: this test
    recorded `_poll` alone, so the URLs the drill PRINTED were invisible to it
    while the URLs it POLLED were pinned exactly. That gap is how the banner
    came to advertise `/api/members` — a line nothing probed and nothing
    compared against the polled set — so the banner's own probe is recorded and
    asserted alongside them.
    """
    installer = _installer()
    probed: list[str] = []
    banner_probed: list[str] = []

    def record_probe(desc: str, url: str, ok, budget_s: float) -> dict:
        probed.append(url)
        return {}

    def record_banner_probe(url: str, timeout: float = 5.0) -> int:
        # Stubbed because the addresses above are deliberately unroutable; the
        # real anonymous GET is asserted against a live stack by the installer
        # CI job. What this pins is WHICH urls the banner reaches for.
        banner_probed.append(url)
        return 200

    installer._poll = record_probe
    installer._status = record_banner_probe
    installer.say = lambda message: None

    installer.drill(
        {
            "SERVER_BIND_HOST": "10.0.0.5",
            "SERVER_PORT": "7100",
            "AGENT_BIND_HOST": "0.0.0.0",
            "AGENT_PORT": "8180",
            "RENDERER_BIND_HOST": "10.0.0.6",
            "AGENT_ID": "probe-agent",
        }
    )

    # /health appears THREE times on purpose: the liveness check, the
    # rate-limit persistence assertion, and the membership probe. The
    # persistence poll exists because a fresh install booted with the flag
    # false for as long as the feature existed and nothing looked. The
    # membership probe used to be /api/agents/probe-agent/profile, which
    # answered for every member whether or not they had agreed to be published
    # — using it to ask "has the agent joined?" was using a membership oracle.
    # The profile is now consent-gated and 404s by default, so the installer
    # reads the org's member COUNT instead: open, authoritative, and silent
    # about WHO joined.
    assert probed == [
        "http://10.0.0.5:7100/health",
        "http://10.0.0.5:7100/health",
        "http://10.0.0.5:7100/.well-known/conformance.json",
        "http://10.0.0.5:7100/health",
        "http://127.0.0.1:8180/.well-known/agent.json",
    ]
    assert banner_probed == [
        "http://10.0.0.5:7100/health",
        "http://10.0.0.5:7100/.well-known/conformance.json",
        "http://10.0.0.5:7100/api/surfaces/dashboard",
        "http://127.0.0.1:8180/.well-known/agent.json",
        "http://10.0.0.6:8600/",
    ]


def test_installer_banner_refuses_to_print_a_url_it_could_not_read() -> None:
    """`verify_banner` is a check, not a formality: a banner entry that does not
    answer 200 to an anonymous caller stops the installer. Without this, the
    stub above would pass just as happily against a function that probed
    nothing."""
    installer = _installer()
    installer.say = lambda message: None
    installer._status = lambda url, timeout=5.0: 401 if url.endswith("/api/members") else 200

    with pytest.raises(SystemExit):
        installer.verify_banner(
            [("org", "http://127.0.0.1:7000/health"), ("members", "http://127.0.0.1:7000/api/members")]
        )
    installer.verify_banner([("org", "http://127.0.0.1:7000/health")])


def test_installer_formats_ipv6_probe_origins() -> None:
    installer = _installer()

    assert (
        installer._service_origin({"SERVER_BIND_HOST": "::", "SERVER_PORT": "7100"}, "SERVER", "7000")
        == "http://[::1]:7100"
    )
    assert (
        installer._service_origin({"SERVER_BIND_HOST": "[::1]", "SERVER_PORT": "7100"}, "SERVER", "7000")
        == "http://[::1]:7100"
    )


def test_documented_aws_bind_survives_env_parsing() -> None:
    installer = _installer()
    deploy_aws = (REPO / "docs" / "DEPLOY_AWS.md").read_text()
    bind_line = next(line.strip() for line in deploy_aws.splitlines() if line.strip().startswith("SERVER_BIND_HOST="))

    env = installer.parse_env(bind_line)

    assert installer._service_origin(env, "SERVER", "7000") == "http://127.0.0.1:7000"


def test_installer_get_bypasses_environment_proxies(monkeypatch) -> None:
    installer = _installer()
    opened: list[str] = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b'{"status":"ok"}'

    class DirectOpener:
        def open(self, url: str, timeout: float):
            opened.append(url)
            return Response()

    monkeypatch.setattr(installer, "_NO_PROXY_OPENER", DirectOpener(), raising=False)
    monkeypatch.setattr(
        installer.urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("installer probes must not use the proxy-aware urlopen"),
    )

    status, body = installer._get("http://10.0.0.5:7100/health")

    assert status == 200
    assert body == {"status": "ok"}
    assert opened == ["http://10.0.0.5:7100/health"]


def test_installer_e2e_uses_configured_origins_and_bypasses_proxies(tmp_path, monkeypatch) -> None:
    installer = _installer()
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "SERVER_BIND_HOST=10.0.0.5",
                "SERVER_PORT=7100",
                "AGENT_BIND_HOST=0.0.0.0",
                "AGENT_PORT=8180",
            ]
        )
    )
    calls: list[tuple[list[str], dict]] = []

    def record_run(command: list[str], **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer, "REPO", tmp_path)
    monkeypatch.setattr(installer, "ENV_PATH", env_path)
    monkeypatch.setattr(installer, "preflight", lambda: None)
    monkeypatch.setattr(installer, "ensure_env", lambda args, resolved=None: None)
    monkeypatch.setattr(installer, "check_ports", lambda resolved: None)
    monkeypatch.setattr(installer, "git_commit", lambda: "test-commit")
    monkeypatch.setattr(installer, "say", lambda message: None)
    monkeypatch.setattr(installer.subprocess, "run", record_run)
    monkeypatch.setattr(sys, "argv", ["orrery-up", "e2e"])

    assert installer.main() == 0

    command, kwargs = next(
        (command, kwargs) for command, kwargs in calls if any(str(part).endswith("e2e_probes.py") for part in command)
    )
    assert command[command.index("--server") + 1] == "http://10.0.0.5:7100"
    assert command[command.index("--agent") + 1] == "http://127.0.0.1:8180"
    assert command[command.index("--server2") + 1] == "http://localhost:7001"

    probe_env = kwargs.get("env")
    assert probe_env is not None
    no_proxy = set(probe_env["NO_PROXY"].split(","))
    assert {"localhost", "127.0.0.1", "::1", "10.0.0.5"} <= no_proxy


# ── /metrics gate is inert unless compose passes the token through ──


def _server_env_block() -> str:
    compose = (REPO / "docker-compose.yml").read_text()
    # the `server:` service's `environment:` block up to the next dedented key
    m = re.search(r"\n  server:\n(?:.*\n)*?    environment:\n((?:      .*\n)+)", compose)
    assert m, "could not locate the server service environment block"
    return m.group(1)


def test_metrics_bearer_token_is_passed_through_compose():
    """The /metrics handler honors METRICS_BEARER_TOKEN, but the gate is inert
    unless compose actually forwards the var to the container."""
    assert "METRICS_BEARER_TOKEN" in _server_env_block(), (
        "docker-compose.yml server service must pass METRICS_BEARER_TOKEN through, "
        "or /metrics is silently open even when an operator sets the token"
    )


def test_metrics_token_documented_in_env_example():
    assert "METRICS_BEARER_TOKEN" in (REPO / ".env.example").read_text()


# ── Manual-install instructions must remain executable and narrowly scoped ──


def test_compose_header_points_to_the_required_manual_setup():
    """The Compose file is often the first surface an operator reads.

    It must not resurrect the broken copy-and-start sequence: the shipped
    template deliberately has no sealing key and carries a public database
    password until the documented setup replaces both values.
    """
    header = (REPO / "docker-compose.yml").read_text().split("\nservices:", 1)[0]
    install = (REPO / "docs/INSTALL.md").read_text()
    assert "docs/INSTALL.md#quick-start-manual" in header
    assert "## Quick start (manual)" in install
    assert "POSTGRES_PASSWORD" in header
    assert "ORRERY_KEY_SECRET" in header
    assert "cp .env.example .env      # set ORG_NAME to taste" not in header


def test_prod_profile_is_not_claimed_as_complete_public_hardening():
    """Selecting prod changes two app surfaces; it is not a deployment review."""
    configuration = (REPO / "docs/CONFIGURATION.md").read_text()
    normalized = " ".join(configuration.split())
    assert "safe for public exposure out of the box" not in configuration
    assert "does not by itself make an install ready for public exposure" in normalized
    assert "INSTALL.md#going-to-production" in configuration
    assert "## Going to production" in (REPO / "docs/INSTALL.md").read_text()
    assert "safe for public" not in (REPO / ".env.example").read_text()


def test_manual_env_is_restricted_before_secrets_are_added():
    """The manual flow must lock the copied template before it becomes secret-bearing."""
    install = (REPO / "docs/INSTALL.md").read_text()
    copied = install.index("cp .env.example .env")
    restricted = install.index("chmod 600 .env", copied)
    first_secret = install.index("openssl rand -hex", copied)
    assert copied < restricted < first_secret


# ── That change: rotate returns proper HTTP status on failure ──


@pytest.fixture
def rotate_env(monkeypatch):
    import auth_verify
    import chapter_agent

    auth_verify._agent_keys.clear()
    yield chapter_agent
    auth_verify._agent_keys.clear()


@pytest.mark.asyncio
async def test_rotate_bad_fields_is_400(rotate_env):
    """Malformed rotation input → 400, not a 200 with an error body."""
    resp = await rotate_env.rotate_member_key({"agent_id": "nobody"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_rotate_unknown_agent_is_400(rotate_env):
    resp = await rotate_env.rotate_member_key(
        {
            "agent_id": "ghost",
            "new_public_key_b64": "x",
            "chapter_id": "c",
            "timestamp": 1,
            "nonce": "n",
            "signature": "s",
        }
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_rotate_rejected_attestation_is_401(rotate_env, monkeypatch):
    """A known member with a stored key but a bad attestation → 401 (auth
    failure), never 200."""
    ca = rotate_env
    monkeypatch.setitem(ca.members, "rot-x", {"origin": "sovereign", "public_key": "c3RvcmVka2V5"})

    async def _reject(attestation, stored_key):
        return {"error": "attestation signature invalid"}

    import member_rotation

    monkeypatch.setattr(member_rotation, "accept_rotation", _reject)
    resp = await ca.rotate_member_key(
        {
            "agent_id": "rot-x",
            "new_public_key_b64": "y",
            "chapter_id": "c",
            "timestamp": 1,
            "nonce": "n",
            "signature": "s",
        }
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rotate_success_is_200(rotate_env, monkeypatch):
    ca = rotate_env
    monkeypatch.setitem(ca.members, "rot-ok", {"origin": "sovereign", "public_key": "b2xka2V5"})

    async def _ok(attestation, stored_key):
        return {"new_public_key_b64": "bmV3a2V5"}

    import member_rotation

    monkeypatch.setattr(member_rotation, "accept_rotation", _ok)
    resp = await ca.rotate_member_key(
        {
            "agent_id": "rot-ok",
            "new_public_key_b64": "bmV3a2V5",
            "chapter_id": "c",
            "timestamp": 1,
            "nonce": "n",
            "signature": "s",
        }
    )
    assert resp.status_code == 200
    import json

    assert json.loads(bytes(resp.body))["rotated"] is True


# ── PR4: a stock install must be incapable of reaching a live registry ──
#
# The empty-vs-unset change fixed the EMPTY case (`REGISTRY_URL=` no longer substitutes the live
# default, because compose uses `${VAR-}` not `${VAR:-}`). It did not fix the
# UNSET case: the default itself WAS the live registry, and `orrery-up` never
# wrote the key, so every stock install landed in exactly the unset branch.
# Phase 0 put `TEST-phase0-parity` into the live NEST registry through it.
#
# Both cases are pinned below by name, because a fix to one that leaves the
# other is what happened last time.

LIVE_REGISTRY_HOSTS = ("nest.projectnanda.org", "api.nandaindex.org")


def _registry_url_line() -> str:
    line = next(
        (ln for ln in (REPO / "docker-compose.yml").read_text().splitlines() if ln.strip().startswith("REGISTRY_URL:")),
        None,
    )
    assert line, "docker-compose.yml no longer sets REGISTRY_URL"
    return line


def test_registry_url_unset_resolves_to_publish_nowhere():
    """THE UNSET CASE. `${REGISTRY_URL-<default>}`: with no value in .env the
    default is what the container gets. A live host here means a stock install
    publishes to production."""
    line = _registry_url_line()
    m = re.search(r"\$\{REGISTRY_URL-([^}]*)\}", line)
    assert m, f"expected ${{REGISTRY_URL-...}} substitution, got: {line.strip()}"
    assert m.group(1).strip() == "", (
        f"compose defaults REGISTRY_URL to {m.group(1)!r} — an install that sets nothing "
        "publishes there. The default must be empty; reaching a registry is an opt-in."
    )


def test_registry_url_empty_stays_empty():
    """THE EMPTY CASE (the empty-vs-unset fix's fix, kept). `:-` would substitute the default for
    an explicitly empty value, silently overriding an operator who wrote
    `REGISTRY_URL=` to mean 'publish nowhere'."""
    line = _registry_url_line()
    assert "${REGISTRY_URL:-" not in line, (
        "compose uses `:-`, so an explicit `REGISTRY_URL=` would be replaced by the default — this is the regression"
    )


def test_orrery_up_writes_registry_url_explicitly():
    """render_env must EMIT the key. Relying on the compose default means the
    answer lives in another file, which is how the unset case went unnoticed."""
    text = (REPO / "orrery-up").read_text()
    assert re.search(r'^\s*"REGISTRY_URL=",\s*$', text, re.M), (
        "orrery-up's render_env does not write REGISTRY_URL= — a generated .env that omits it "
        "leaves publication to a shell default in docker-compose.yml"
    )


@pytest.mark.parametrize("path", ["docker-compose.yml", ".env.example", "orrery-up"])
def test_no_live_registry_is_shipped_as_a_default(path):
    """Belt and braces across every file an install is built from.

    A live registry host may be MENTIONED (docs, a comment telling an operator
    what to set) but must never appear as an assigned value — `.env.example` is
    copied verbatim into real installs, so a live URL there is a live URL in
    production.
    """
    for lineno, line in enumerate((REPO / path).read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue  # a comment naming the URL is guidance, not configuration
        for host in LIVE_REGISTRY_HOSTS:
            if host in stripped:
                raise AssertionError(f"{path}:{lineno} ships a live registry as configuration: {stripped!r}")
