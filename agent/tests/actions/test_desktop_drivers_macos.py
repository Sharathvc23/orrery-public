"""Tests for ``MacosDesktopDriver`` — fully mocked at the subprocess seam.

Coverage matches the LinuxDesktopDriver suite as closely as the
platform allows (no $DISPLAY equivalent on macOS; Accessibility
permission is a system-level concern that surfaces as an
osascript-level rc≠0 rather than a pre-flight check).

  R1  Forgery — driver refuses to dispatch when osascript is missing
      (an attacker can't pretend to be macOS without it)
  R3  Injection — AppleScript escape handles backslash + double-quote
  R4  Authz — driver doesn't bypass cliclick requirement for clicks
  R5  Boundary — coordinate clamping (shared with Linux); button
      whitelist (left/right only on macOS)
  R7  Adversarial — cliclick missing forces clear DesktopUnavailable
      rather than silent no-op
  R8  Revocation — osascript timeout / FileNotFoundError both surface
  R10 Persistence — screencapture stdout passes through verbatim
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from community_member.actions.desktop import DesktopUnavailable, FocusInfo
from community_member.actions.desktop_drivers import (
    MacosDesktopDriver,
    _applescript_escape,
)


@dataclass
class FakeProc:
    returncode: int = 0
    stdout: bytes = b""
    stderr: bytes = b""


class FakeRun:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.scripts: dict[str, FakeProc | Exception] = {}
        self.default = FakeProc(returncode=1, stderr=b"unscripted")

    def script_osa(self, fragment: str, result: FakeProc | Exception) -> None:
        """Match by AppleScript text fragment (osascript -e SCRIPT)."""
        self.scripts[f"osa::{fragment}"] = result

    def script_argv(self, key: str, result: FakeProc | Exception) -> None:
        """Match by argv last-token contains (cliclick c:x,y, etc.)."""
        self.scripts[f"argv::{key}"] = result

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProc:
        self.calls.append(list(argv))
        # osascript -e SCRIPT shape.
        if len(argv) >= 3 and argv[-2] == "-e":
            script = argv[-1]
            for prefix, value in self.scripts.items():
                if not prefix.startswith("osa::"):
                    continue
                fragment = prefix[len("osa::") :]
                if fragment in script:
                    if isinstance(value, Exception):
                        raise value
                    return value
            return self.default
        # argv-substring shape.
        last = argv[-1] if argv else ""
        for prefix, value in self.scripts.items():
            if not prefix.startswith("argv::"):
                continue
            needle = prefix[len("argv::") :]
            if needle in last or any(needle in a for a in argv):
                if isinstance(value, Exception):
                    raise value
                return value
        return self.default


# ── focus ────────────────────────────────────────────────────────


def test_focus_uses_bundle_id_when_available():
    run = FakeRun()
    run.script_osa("bundle identifier", FakeProc(stdout=b"com.apple.Safari\n"))
    run.script_osa("get name of first application process", FakeProc(stdout=b"Safari\n"))
    run.script_osa("get unix id", FakeProc(stdout=b"4242\n"))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        screencapture_path="/usr/sbin/screencapture",
        run=run,
    )
    info = drv.focus()
    assert isinstance(info, FocusInfo)
    assert info.descriptor == "com.apple.Safari"
    assert info.pid == 4242


def test_focus_falls_back_to_app_name_when_bundle_blank():
    run = FakeRun()
    run.script_osa("bundle identifier", FakeProc(stdout=b""))
    run.script_osa("get name of first application process", FakeProc(stdout=b"Finder\n"))
    run.script_osa("get unix id", FakeProc(stdout=b""))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        screencapture_path="/usr/sbin/screencapture",
        run=run,
    )
    info = drv.focus()
    assert info.descriptor == "Finder"
    assert info.pid is None


def test_R1_no_osascript_raises():
    drv = MacosDesktopDriver(osascript_path=None, run=FakeRun())
    with pytest.raises(DesktopUnavailable, match="osascript not on PATH"):
        drv.focus()


def test_focus_no_frontmost_app_raises():
    run = FakeRun()
    run.script_osa("bundle identifier", FakeProc(stdout=b""))
    run.script_osa("get name of first application process", FakeProc(stdout=b""))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        run=run,
    )
    with pytest.raises(DesktopUnavailable, match="no frontmost app"):
        drv.focus()


# ── click ────────────────────────────────────────────────────────


def test_click_dispatches_cliclick_argv_for_left():
    run = FakeRun()
    run.script_argv("c:200,300", FakeProc())
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        run=run,
    )
    drv.click(x=200, y=300, button="left")
    assert run.calls[-1] == ["/usr/local/bin/cliclick", "c:200,300"]


def test_click_dispatches_cliclick_argv_for_right():
    run = FakeRun()
    run.script_argv("rc:10,20", FakeProc())
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        run=run,
    )
    drv.click(x=10, y=20, button="right")
    assert run.calls[-1][-1] == "rc:10,20"


def test_R7_no_cliclick_raises_helpful_error():
    """Without cliclick we explicitly refuse rather than fall back to
    the AppleScript path that's known unreliable. The error message
    points the user at `brew install cliclick`."""
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path=None,
        run=FakeRun(),
    )
    with pytest.raises(DesktopUnavailable, match="cliclick required"):
        drv.click(x=10, y=20, button="left")


def test_R5_unknown_button_rejected_macos():
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        run=FakeRun(),
    )
    with pytest.raises(DesktopUnavailable, match="left/right"):
        drv.click(x=1, y=1, button="middle")


def test_R5_negative_coords_clamped():
    run = FakeRun()
    run.script_argv("c:0,0", FakeProc())
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        run=run,
    )
    drv.click(x=-10, y=-50, button="left")
    assert run.calls[-1][-1] == "c:0,0"


# ── type_text ────────────────────────────────────────────────────


def test_type_uses_cliclick_t_prefix():
    run = FakeRun()
    run.script_argv("t:hello", FakeProc())
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path="/usr/local/bin/cliclick",
        run=run,
    )
    drv.type_text(text="hello")
    assert run.calls[-1] == ["/usr/local/bin/cliclick", "t:hello"]


def test_type_falls_back_to_osascript_when_cliclick_absent():
    run = FakeRun()
    run.script_osa("keystroke", FakeProc())
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        cliclick_path=None,
        run=run,
    )
    drv.type_text(text="abc")
    # Last call should be osascript -e TELL ... keystroke "abc"
    assert run.calls[-1][0] == "/usr/bin/osascript"
    assert "keystroke" in run.calls[-1][-1]


def test_type_no_tools_raises():
    drv = MacosDesktopDriver(osascript_path=None, cliclick_path=None, run=FakeRun())
    with pytest.raises(DesktopUnavailable, match="neither cliclick nor osascript"):
        drv.type_text(text="x")


# ── read_screen ──────────────────────────────────────────────────


def test_R10_read_screen_returns_screencapture_bytes():
    run = FakeRun()
    run.script_argv("png", FakeProc(stdout=b"PNGBYTES_MACOS"))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        screencapture_path="/usr/sbin/screencapture",
        run=run,
    )
    assert drv.read_screen() == b"PNGBYTES_MACOS"


def test_read_screen_no_tool_raises():
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        screencapture_path=None,
        run=FakeRun(),
    )
    with pytest.raises(DesktopUnavailable, match="screencapture missing"):
        drv.read_screen()


def test_read_screen_failure_surfaces():
    run = FakeRun()
    run.script_argv("png", FakeProc(returncode=2, stderr=b"permission denied"))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        screencapture_path="/usr/sbin/screencapture",
        run=run,
    )
    with pytest.raises(DesktopUnavailable, match="screencapture failed"):
        drv.read_screen()


# ── Timeouts → DesktopUnavailable ────────────────────────────────


def test_R8_screencapture_timeout_surfaces():
    run = FakeRun()
    run.script_argv("png", subprocess.TimeoutExpired(cmd=["screencapture"], timeout=10))
    drv = MacosDesktopDriver(
        osascript_path="/usr/bin/osascript",
        screencapture_path="/usr/sbin/screencapture",
        run=run,
    )
    with pytest.raises(DesktopUnavailable, match="timed out"):
        drv.read_screen()


# ── R3 escape helper ─────────────────────────────────────────────


def test_R3_applescript_escape_double_quotes_and_backslashes():
    assert _applescript_escape('say "hi"') == 'say \\"hi\\"'
    assert _applescript_escape("a\\b") == "a\\\\b"


def test_R3_applescript_escape_newlines():
    assert _applescript_escape("a\nb") == "a\\nb"
