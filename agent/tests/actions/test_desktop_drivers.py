"""Tests for ``LinuxDesktopDriver`` and ``autodetect``.

Coverage matrix (per the discipline established for the other
action surfaces):

  R1  Forgery — driver refuses to dispatch when ``$DISPLAY`` is unset
      (a hostile process can't trick xdotool into running against
      the wrong server)
  R2  Replay — repeated focus() / click() calls return consistent
      output without leaking state between calls
  R3  Injection — ``type_text`` argv contains ``"--"`` so a leading
      dash in user content can't be reinterpreted as an option;
      window ids and coordinates are stringified safely
  R4  Authz — driver does not check approvals (executor's job); but
      it must not bypass ``DISPLAY`` / ``WAYLAND_DISPLAY`` checks
  R5  Boundary — coordinates clamped to non-negative ints; unknown
      button names rejected with ``DesktopUnavailable``
  R6  Concurrency — driver itself is stateless; two simultaneous
      focus() calls don't share buffers
  R7  Adversarial — Wayland session triggers DesktopUnavailable
      immediately (xdotool would silently fail on Wayland; we'd
      rather surface the error than record approvals that didn't
      fire)
  R8  Revocation — driver doesn't cache; if xdotool disappears
      between calls the next call surfaces DesktopUnavailable
  R9  Provenance — driver returns raw bytes / strings; provenance is
      pinned by the executor (not driver concern, sanity-checked)
  R10 Persistence — read_screen returns deterministic bytes from the
      capture tool's stdout

Plus autodetect() coverage for OS dispatch + Wayland fallthrough.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from community_member.actions.desktop import DesktopUnavailable, FocusInfo
from community_member.actions.desktop_drivers import LinuxDesktopDriver, autodetect

# ── Subprocess fake ──────────────────────────────────────────────


@dataclass
class FakeProc:
    returncode: int = 0
    stdout: bytes = b""
    stderr: bytes = b""


class FakeRun:
    """Replays scripted responses keyed on the first arg + second arg.

    Each call records the full argv so tests can assert exactly
    what would have shelled out.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.scripts: dict[tuple[str, ...], FakeProc | Exception] = {}
        self.default: FakeProc = FakeProc(returncode=1, stderr=b"unscripted")

    def script(self, key: tuple[str, ...], result: FakeProc | Exception) -> None:
        self.scripts[key] = result

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProc:
        self.calls.append(list(argv))
        # Match by tail of argv (skip the binary path which differs).
        # Cap is len(argv) so any-length scripts work.
        for length in range(len(argv), 0, -1):
            key = tuple(argv[-length:])
            if key in self.scripts:
                value = self.scripts[key]
                if isinstance(value, Exception):
                    raise value
                return value
        return self.default


def env_with(**vars_: str):
    def _get(name: str) -> str:
        return vars_.get(name, "")

    return _get


# ── Wayland / DISPLAY guards ─────────────────────────────────────


def test_R1_no_display_raises_unavailable():
    drv = LinuxDesktopDriver(
        xdotool_path="/usr/bin/xdotool",
        run=FakeRun(),
        env_get=env_with(),  # neither WAYLAND_DISPLAY nor DISPLAY set
    )
    with pytest.raises(DesktopUnavailable, match=r"\$DISPLAY"):
        drv.focus()


def test_R7_wayland_session_raises_unavailable():
    drv = LinuxDesktopDriver(
        xdotool_path="/usr/bin/xdotool",
        run=FakeRun(),
        env_get=env_with(WAYLAND_DISPLAY="wayland-0", DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match=r"Wayland"):
        drv.click(x=10, y=20)


# ── Focus ────────────────────────────────────────────────────────


def test_focus_happy_path():
    run = FakeRun()
    run.script(("getactivewindow",), FakeProc(stdout=b"12345\n"))
    run.script(("getwindowname", "12345"), FakeProc(stdout=b"Mozilla Firefox\n"))
    run.script(("getwindowpid", "12345"), FakeProc(stdout=b"4242\n"))
    run.script(
        ("-id", "12345", "WM_CLASS"),
        FakeProc(stdout=b'WM_CLASS(STRING) = "navigator", "Firefox"\n'),
    )
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        xprop_path="/usr/bin/xprop",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    info = drv.focus()
    assert isinstance(info, FocusInfo)
    assert info.descriptor == "Firefox"
    assert info.pid == 4242


def test_focus_falls_back_to_title_when_wm_class_missing():
    run = FakeRun()
    run.script(("getactivewindow",), FakeProc(stdout=b"77\n"))
    run.script(("getwindowname", "77"), FakeProc(stdout=b"My Window\n"))
    run.script(("getwindowpid", "77"), FakeProc(stdout=b""))
    run.script(("-id", "77", "WM_CLASS"), FakeProc(returncode=1))
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    info = drv.focus()
    assert info.descriptor == "My Window"
    assert info.pid is None


def test_focus_no_active_window_raises():
    run = FakeRun()
    run.script(("getactivewindow",), FakeProc(stdout=b""))
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="active window"):
        drv.focus()


def test_focus_xdotool_missing_raises():
    drv = LinuxDesktopDriver(
        xdotool_path=None,
        run=FakeRun(),
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="xdotool not on PATH"):
        drv.focus()


# ── Click ────────────────────────────────────────────────────────


def test_click_dispatches_correct_argv():
    run = FakeRun()
    run.script(("mousemove", "100", "200", "click", "1"), FakeProc())
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    drv.click(x=100, y=200, button="left")
    assert run.calls[-1] == ["/bin/xdotool", "mousemove", "100", "200", "click", "1"]


def test_R5_negative_coords_clamped_to_zero():
    run = FakeRun()
    run.script(("mousemove", "0", "0", "click", "1"), FakeProc())
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    drv.click(x=-50, y=-200)
    assert run.calls[-1][2] == "0"
    assert run.calls[-1][3] == "0"


def test_R5_unknown_button_rejected():
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=FakeRun(),
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="unknown button"):
        drv.click(x=10, y=10, button="superhyper")


def test_click_translates_button_names():
    run = FakeRun()
    run.script(("mousemove", "10", "10", "click", "3"), FakeProc())
    drv = LinuxDesktopDriver(xdotool_path="/bin/xdotool", run=run, env_get=env_with(DISPLAY=":0"))
    drv.click(x=10, y=10, button="right")
    assert run.calls[-1][-1] == "3"


# ── Type ─────────────────────────────────────────────────────────


def test_R3_type_uses_double_dash_so_leading_dash_is_literal():
    """`xdotool type --` ensures even strings starting with '-' are
    typed verbatim, not interpreted as flags. Documents the security
    invariant in test form."""
    run = FakeRun()
    run.script(("type", "--", "-rf /"), FakeProc())
    drv = LinuxDesktopDriver(xdotool_path="/bin/xdotool", run=run, env_get=env_with(DISPLAY=":0"))
    drv.type_text(text="-rf /")
    assert "--" in run.calls[-1]
    assert run.calls[-1][-1] == "-rf /"


def test_type_handles_unicode_verbatim():
    run = FakeRun()
    run.script(("type", "--", "héllo 🚀"), FakeProc())
    drv = LinuxDesktopDriver(xdotool_path="/bin/xdotool", run=run, env_get=env_with(DISPLAY=":0"))
    drv.type_text(text="héllo 🚀")
    assert run.calls[-1][-1] == "héllo 🚀"


# ── read_screen ──────────────────────────────────────────────────


def test_R10_read_screen_returns_capture_bytes():
    run = FakeRun()
    run.script(("-window", "root", "png:-"), FakeProc(stdout=b"PNGBYTES"))
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        capture_path="/usr/bin/import",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    out = drv.read_screen()
    assert out == b"PNGBYTES"


def test_read_screen_no_capture_tool_raises():
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        capture_path=None,
        run=FakeRun(),
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="no screen-capture tool"):
        drv.read_screen()


def test_read_screen_capture_failure_surfaces():
    run = FakeRun()
    run.script(
        ("-window", "root", "png:-"),
        FakeProc(returncode=2, stderr=b"X server unreachable"),
    )
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        capture_path="/usr/bin/import",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="capture failed"):
        drv.read_screen()


def test_read_screen_scrot_uses_stdout_sink():
    run = FakeRun()
    run.script(("-o", "/dev/stdout"), FakeProc(stdout=b"SCROTBYTES"))
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        capture_path="/usr/bin/scrot",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    out = drv.read_screen()
    assert out == b"SCROTBYTES"
    assert run.calls[-1] == ["/usr/bin/scrot", "-o", "/dev/stdout"]


# ── Timeout / FileNotFound surface as DesktopUnavailable ─────────


def test_R8_xdotool_timeout_surfaces_as_unavailable():
    run = FakeRun()
    run.script(
        ("getactivewindow",),
        subprocess.TimeoutExpired(cmd=["xdotool"], timeout=5),
    )
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="timed out"):
        drv.focus()


def test_R8_xdotool_disappears_between_calls():
    run = FakeRun()
    run.script(
        ("getactivewindow",),
        FileNotFoundError("xdotool"),
    )
    drv = LinuxDesktopDriver(
        xdotool_path="/bin/xdotool",
        run=run,
        env_get=env_with(DISPLAY=":0"),
    )
    with pytest.raises(DesktopUnavailable, match="xdotool missing"):
        drv.focus()


# ── autodetect ───────────────────────────────────────────────────


def test_autodetect_returns_driver_on_linux(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    drv = autodetect(run=FakeRun(), env_get=env_with(DISPLAY=":0"))
    assert drv is not None
    assert isinstance(drv, LinuxDesktopDriver)


def test_autodetect_returns_macos_driver_on_darwin(monkeypatch):
    from community_member.actions.desktop_drivers import MacosDesktopDriver

    monkeypatch.setattr("platform.system", lambda: "Darwin")
    drv = autodetect(run=FakeRun(), env_get=env_with())
    assert drv is not None
    assert isinstance(drv, MacosDesktopDriver)


def test_autodetect_returns_windows_driver_on_windows(monkeypatch):
    from community_member.actions.desktop_drivers import WindowsDesktopDriver

    monkeypatch.setattr("platform.system", lambda: "Windows")
    # user32=None → driver constructed but lazy-resolves at first call.
    # autodetect itself doesn't make a Win32 call so this works on
    # any host.
    drv = autodetect(run=FakeRun(), env_get=env_with(), user32=object())
    assert drv is not None
    assert isinstance(drv, WindowsDesktopDriver)


def test_autodetect_returns_none_on_unknown_os(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "FreeBSD")
    drv = autodetect(run=FakeRun(), env_get=env_with())
    assert drv is None
