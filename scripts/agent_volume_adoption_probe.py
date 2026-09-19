#!/usr/bin/env python3
"""Boot the agent image against a volume it did not write, and prove it adopts it.

WHY THIS EXISTS AND WHY THE PYTEST SUITE CANNOT COVER IT
--------------------------------------------------------
The agent image declared ``USER orrery`` (uid 10001) and chowned ``/data`` at
BUILD time, with a comment claiming a mounted volume would inherit that uid. It
does not. At build time ``/data`` is an empty directory inside the image; at
runtime the platform mounts a volume over it carrying the ownership of whatever
wrote it. Agents shipped before the image went non-root ran as root and left
``keystore.enc`` as ``root:root`` mode ``0600``, so uid 10001 could not read it
and every one of them would have crashed on its next deploy with

    PermissionError: [Errno 13] Permission denied:
    '/data/.community-member/keystore.enc'

Every existing test builds a FRESH volume, so the ownership of the mount always
matched the process and the defect was invisible to all of them. A container
change that would have taken down every deployed agent passed every gate. This
probe is the missing case: an UPGRADE over a volume written by a different uid.

It is deliberately not a pytest: it needs a real image build, a real named
volume and a real mount, none of which a unit test should carry.

Exit status:
    0 — the image adopted a volume owned by another uid, read it unchanged, and
        still ran the agent as a non-root user
    1 — at least one of those did not hold; what failed is printed
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "agent" / "infra" / "Dockerfile.agent"
CONTEXT = REPO / "agent"

# Written into the seeded vault so the probe can prove the file was READ, not
# replaced. A keystore that could not be read must never be silently re-minted.
SENTINEL = f"probe-{uuid.uuid4().hex}"

AGENT_UID = "10001"
HOME_DIR = "/data/.community-member"


def run(args: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, **kw)  # type: ignore[call-overload,no-any-return]


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return run(["docker", *args])


def seed_volume(volume: str, uid: str = "0", mode: str = "600") -> None:
    """Create a volume whose keystore is owned by ``uid`` — root by default.

    Root:root 0600 is exactly what the pre-hardening image left behind, which is
    the state every deployed agent's volume is in.
    """
    docker("volume", "rm", "-f", volume)
    docker("volume", "create", volume)
    script = (
        f"mkdir -p {HOME_DIR} && "
        f"printf '%s' '{SENTINEL}' > {HOME_DIR}/keystore.enc && "
        f"chmod {mode} {HOME_DIR}/keystore.enc && "
        f"chown -R {uid}:{uid} {HOME_DIR}"
    )
    result = docker("run", "--rm", "-v", f"{volume}:/data", "alpine", "sh", "-c", script)
    if result.returncode != 0:
        raise SystemExit(f"could not seed the volume: {result.stderr.strip()}")


def read_as_agent(image: str, volume: str, *, read_only: bool = False) -> subprocess.CompletedProcess[str]:
    """Ask the image to report its uid and the vault's contents.

    The ENTRYPOINT wraps this command, so the adoption preamble runs exactly as
    it does for the real agent and then execs this instead of the server. That
    keeps the probe deterministic — it does not depend on the agent booting, only
    on whether the identity volume is usable by the user the agent runs as.
    """
    mount = f"{volume}:/data:ro" if read_only else f"{volume}:/data"
    return docker(
        "run", "--rm", "-v", mount, image,
        "sh", "-c", f'printf "uid=%s\\n" "$(id -u)"; cat {HOME_DIR}/keystore.enc',
    )


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        for line in detail.strip().splitlines()[-6:]:
            print(f"        {line}")
    return ok


def main() -> int:
    if docker("version").returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 1

    image = f"orrery-agent-probe:{uuid.uuid4().hex[:8]}"
    print(f"building {image} from {DOCKERFILE.relative_to(REPO)}")
    build = run(["docker", "build", "-q", "-f", str(DOCKERFILE), "-t", image, str(CONTEXT)])
    if build.returncode != 0:
        print(build.stderr[-2000:], file=sys.stderr)
        return 1

    passed = True
    volume = f"orrery-probe-{uuid.uuid4().hex[:8]}"
    try:
        # ── the production case: a volume written by root, read by uid 10001 ──
        seed_volume(volume)
        first = read_as_agent(image, volume)
        passed &= check(
            "a volume owned by another uid is adopted, not refused",
            first.returncode == 0,
            first.stderr,
        )
        passed &= check(
            "the agent process is NOT root",
            f"uid={AGENT_UID}" in first.stdout,
            f"stdout: {first.stdout!r}",
        )
        passed &= check(
            "the vault was read, not replaced",
            SENTINEL in first.stdout,
            f"stdout: {first.stdout!r}",
        )
        passed &= check(
            "adoption is reported, not silent",
            "adopting" in first.stderr,
            f"stderr: {first.stderr!r}",
        )

        # ── idempotent and cheap: an already-owned volume is not re-adopted ──
        second = read_as_agent(image, volume)
        passed &= check(
            "a volume already owned correctly is not chowned again",
            second.returncode == 0 and "adopting" not in second.stderr,
            f"stderr: {second.stderr!r}",
        )

        # ── a fresh volume still works, which is all CI used to cover ──
        fresh = f"{volume}-fresh"
        docker("volume", "rm", "-f", fresh)
        docker("volume", "create", fresh)
        empty = docker(
            "run", "--rm", "-v", f"{fresh}:/data", image,
            "sh", "-c", f'printf "uid=%s\\n" "$(id -u)"; touch {HOME_DIR}/writable && echo ok',
        )
        passed &= check(
            "a fresh volume is created and writable by the agent",
            empty.returncode == 0 and "ok" in empty.stdout and f"uid={AGENT_UID}" in empty.stdout,
            f"{empty.stdout!r} {empty.stderr!r}",
        )
        docker("volume", "rm", "-f", fresh)

        # ── a problem it cannot fix must be named, not masked ──
        ro_volume = f"{volume}-ro"
        seed_volume(ro_volume)
        refused = read_as_agent(image, ro_volume, read_only=True)
        passed &= check(
            "an unadoptable volume refuses loudly instead of starting",
            refused.returncode != 0 and "FATAL" in refused.stderr,
            f"rc={refused.returncode} stderr: {refused.stderr!r}",
        )
        docker("volume", "rm", "-f", ro_volume)
    finally:
        docker("volume", "rm", "-f", volume)
        docker("image", "rm", "-f", image)

    print()
    if passed:
        print("OK — the image adopts a volume it did not write, and still runs as a non-root user.")
        return 0
    print("the agent image cannot take over a volume written by an earlier one.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
