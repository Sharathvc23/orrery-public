"""SERVER_PORT and PUBLIC_URL cannot disagree silently.

`.env` spells the org's public origin twice: `SERVER_PORT` is the host port
Compose publishes, `PUBLIC_URL` is the origin the org writes into its did:web
and into every endpoint of its AgentFacts. Before this guard, `ensure_env`
appended and never rewrote, so an operator who edited `SERVER_PORT` by hand
had an org that PUBLISHED one port and LISTENED on another — and the only
thing standing between them was a refusal message telling them to edit both.

The rule the installer now enforces, and this module pins:

  * a `PUBLIC_URL` of the installer's own shape — http, a loopback host, an
    explicit port — is a PROJECTION of `SERVER_PORT` and follows it on every
    run, whether the port moved by `--server-port` or by hand in the file;
  * any other `PUBLIC_URL` — a real hostname, https, no port at all — names an
    origin the operator owns (a proxy in front of the container, whose forward
    port the installer cannot know) and is never rewritten;
  * an `.env` that needs no change is not written at all, so a re-run leaves
    it byte-identical — the identity property from the port-pinning work.

Offline and stdlib-only, so it runs in the always-on doc-guards job: the
installer's other tests live under `server/tests/`, which an edit to
`orrery-up` alone does not wake.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]

UNNAMED = SimpleNamespace(server_port=None, agent_port=None, renderer_port=None)


def _load_installer():
    spec = importlib.util.spec_from_loader(
        "orrery_up_public_url",
        importlib.machinery.SourceFileLoader(
            "orrery_up_public_url", str(REPO / "orrery-up")
        ),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def installer(tmp_path, monkeypatch):
    module = _load_installer()
    monkeypatch.setattr(module, "ENV_PATH", tmp_path / ".env")
    # keep the test output free of the installer's own banner lines
    monkeypatch.setattr(module, "say", lambda *_a, **_k: None)
    return module


BASE = (
    "# operator comment, must survive untouched\n"
    "ORG_ID=keep-me\n"
    "POSTGRES_PASSWORD=realpass123456789012345\n"
    "APP_DB_PASSWORD=fixture-app-role-password\n"
    "ORRERY_KEY_SECRET=" + "a" * 64 + "\n"
    "COMMUNITY_MEMBER_PASSPHRASE=passphrase-passphrase-passphrase\n"
    "PUBLIC_URL={public_url}\n"
    "SERVER_PORT={server_port}\n"
    "AGENT_PORT=8080\n"
    "RENDERER_PORT=8600\n"
)


def _run(installer, args=UNNAMED) -> str:
    """One installer pass over the existing .env: resolve, then ensure."""
    env = installer.parse_env(installer.ENV_PATH.read_text())
    resolved = installer.resolve_ports(args, env)
    installer.ensure_env(args, resolved)
    return installer.ENV_PATH.read_text()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ── G1: a hand-edited SERVER_PORT is not left contradicting PUBLIC_URL ──────


def test_g1_public_url_follows_a_hand_edited_server_port(installer):
    """THE DEFECT. SERVER_PORT edited from 7000 to 7100 in .env, PUBLIC_URL left
    at 7000: the org would publish `did:web:localhost:7000:…` and listen on
    7100. The re-run must make the URL follow the port."""
    installer.ENV_PATH.write_text(
        BASE.format(public_url="http://localhost:7000", server_port="7100")
    )

    after = installer.parse_env(_run(installer))

    assert after["SERVER_PORT"] == "7100"
    assert after["PUBLIC_URL"] == "http://localhost:7100", (
        "PUBLIC_URL still names 7000 while SERVER_PORT is 7100 — the org publishes a port it is not listening on"
    )


def test_g1_the_rewrite_touches_only_the_public_url_line(installer):
    """Following the port is a one-line change. The operator's comment, key
    order and every other value come through byte-for-byte."""
    before = BASE.format(public_url="http://localhost:7000", server_port="7100")
    installer.ENV_PATH.write_text(before)

    after = _run(installer)

    expected = before.replace(
        "PUBLIC_URL=http://localhost:7000", "PUBLIC_URL=http://localhost:7100"
    )
    assert after == expected


@pytest.mark.parametrize(
    ("spelled", "followed"),
    [
        ("http://127.0.0.1:7000", "http://127.0.0.1:7100"),
        ("http://[::1]:7000", "http://[::1]:7100"),
        ("http://localhost:7000/", "http://localhost:7100/"),
    ],
)
def test_g1_the_host_is_kept_as_the_operator_spelled_it(installer, spelled, followed):
    """Every loopback spelling the installer might have written, or the
    operator might have chosen, follows the port with the host untouched."""
    installer.ENV_PATH.write_text(BASE.format(public_url=spelled, server_port="7100"))
    assert installer.parse_env(_run(installer))["PUBLIC_URL"] == followed


def test_g1_a_named_port_rewrites_the_pin_and_the_url_follows(installer):
    """`--server-port 7999` on an install pinned at 7000. Compose reads .env,
    not this process, so a flag that only changed what the installer bind-checked
    would leave Compose publishing 7000 — the pin is rewritten, and PUBLIC_URL
    follows the rewritten pin."""
    installer.ENV_PATH.write_text(
        BASE.format(public_url="http://localhost:7000", server_port="7000")
    )

    after = installer.parse_env(
        _run(
            installer,
            SimpleNamespace(server_port=7999, agent_port=None, renderer_port=None),
        )
    )

    assert after["SERVER_PORT"] == "7999"
    assert after["PUBLIC_URL"] == "http://localhost:7999"
    assert after["AGENT_PORT"] == "8080", "naming one port must not disturb the others"


def test_g1_an_install_without_public_url_gets_one_naming_its_port(installer):
    """An .env predating PUBLIC_URL, pinned off the default: Compose's own
    fallback is `http://localhost:7000`, so the omission IS the disagreement.
    The key is appended, naming the pinned port."""
    text = BASE.format(public_url="", server_port="7100").replace("PUBLIC_URL=\n", "")
    assert "PUBLIC_URL" not in text
    installer.ENV_PATH.write_text(text)

    assert installer.parse_env(_run(installer))["PUBLIC_URL"] == "http://localhost:7100"


# ── G2: an origin the operator named is theirs ─────────────────────────────


@pytest.mark.parametrize(
    "external",
    [
        "https://org.example",  # proxy, TLS, no port — the documented production shape
        "http://org.example",  # proxy on :80
        "https://org.example:8443",  # proxy on an explicit port that is not the container's
        "http://10.0.0.5:7000",  # a LAN address; not loopback, so not the installer's
        "http://localhost",  # loopback but no port: something local answers on :80
    ],
)
def test_g2_an_external_public_url_is_left_exactly_as_written(installer, external):
    """SERVER_PORT is 7100; none of these embed 7100; none may be touched. The
    installer cannot know what port a proxy forwards to, so it does not guess."""
    before = BASE.format(public_url=external, server_port="7100")
    installer.ENV_PATH.write_text(before)

    after = _run(installer)

    assert after == before, (
        f"{external} was rewritten; it names an origin the operator owns"
    )
    assert installer.public_url_follows_port(external) is False


def test_g2_the_classifier_names_exactly_the_installer_shape(installer):
    """The rule in one place: http + loopback host + explicit port, nothing else."""
    follows = installer.public_url_follows_port
    assert follows("http://localhost:7000")
    assert follows("http://127.0.0.1:7001")
    assert follows("http://[::1]:7002")
    assert follows("HTTP://LOCALHOST:7000")
    assert not follows("https://localhost:7000"), (
        "TLS on loopback is a terminator the operator runs"
    )
    assert not follows("http://localhost")
    assert not follows("http://org.example:7000")
    assert not follows("")
    assert not follows("http://[::1:7000"), (
        "unparseable is not the installer's shape either"
    )


# ── G3: an unchanged .env is not rewritten ─────────────────────────────────


@pytest.mark.parametrize("public_url", ["http://localhost:7100", "https://org.example"])
def test_g3_an_agreeing_env_is_byte_identical_across_re_runs(installer, public_url):
    """The port-pinning identity property, re-driven: with nothing to change the
    file is not written at all, so its bytes AND its mtime survive the run."""
    installer.ENV_PATH.write_text(
        BASE.format(public_url=public_url, server_port="7100")
    )
    first = _run(installer)
    # Pinned to a fixed past instant rather than read back, because the kernel's
    # file-time clock is coarse enough that two runs inside a few milliseconds
    # share an mtime, and an unconditional rewrite went unnoticed when this was
    # first planted.
    stamp = 1_000_000_000_000_000_000
    os.utime(installer.ENV_PATH, ns=(stamp, stamp))

    second = _run(installer)

    assert _sha(second) == _sha(first)
    assert installer.ENV_PATH.stat().st_mtime_ns == stamp, (
        "the file was rewritten with identical content"
    )


def test_g3_following_the_port_converges_in_one_run(installer):
    """After the URL has followed the port, the next run finds nothing to do."""
    installer.ENV_PATH.write_text(
        BASE.format(public_url="http://localhost:7000", server_port="7100")
    )
    first = _run(installer)
    assert _run(installer) == first


# ── the rewrite primitive ──────────────────────────────────────────────────


def test_rewrite_env_replaces_the_last_uncommented_occurrence(installer):
    """`parse_env` and Compose both honour the LAST `KEY=` line, so that is the
    one a rewrite must hit; a commented-out copy is not a key at all."""
    text = "# PUBLIC_URL=http://commented:1\nPUBLIC_URL=http://first:1\nX=1\nPUBLIC_URL=http://last:1\n"
    out = installer.rewrite_env(text, {"PUBLIC_URL": "http://new:2"})
    assert (
        out
        == "# PUBLIC_URL=http://commented:1\nPUBLIC_URL=http://first:1\nX=1\nPUBLIC_URL=http://new:2\n"
    )
    with pytest.raises(KeyError):
        installer.rewrite_env(text, {"MISSING": "1"})


def test_a_fresh_env_derives_public_url_from_the_same_helper(installer):
    """`render_env` and the re-run path derive the URL through one function, so
    a first run and a hundredth agree on the shape."""
    args = SimpleNamespace(
        org_id="o",
        org_name="O",
        agent_id="a",
        agent_name="A",
        provider="",
        api_key="",
        model="",
        server_port=7100,
        agent_port=8080,
        renderer_port=8600,
    )
    env = installer.parse_env(installer.render_env(args))
    assert (
        env["PUBLIC_URL"] == installer.public_url_for(7100) == "http://localhost:7100"
    )
    assert env["SERVER_PORT"] == "7100"
