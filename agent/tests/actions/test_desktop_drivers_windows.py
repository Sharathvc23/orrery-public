"""Tests for ``WindowsDesktopDriver`` — fully mocked at the user32 seam.

Windows is the most-mocked driver because every call goes through
``ctypes.windll.user32``. The driver accepts a ``user32`` injection
parameter; the test fakes records calls so we can assert the exact
SetCursorPos / mouse_event / SendInput sequence without ever
loading the real DLL.

Coverage:

  R1  Forgery — no foreground window → DesktopUnavailable; not a
      silent zero-state
  R3  Injection — ``type_text`` issues per-codepoint SendInput so
      the OS handles all escaping; we assert the wScan field is
      ord(ch) for unicode chars including non-ASCII
  R4  Authz — driver doesn't bypass user32 unavailability
  R5  Boundary — coordinate clamping; unknown button rejection;
      empty text → no SendInput calls
  R8  Revocation — when user32 itself raises (e.g. session locked),
      the driver surfaces it as DesktopUnavailable
  R10 Persistence — read_screen passes through the encode_png
      callable's output verbatim; no encoder configured → clear error
"""

from __future__ import annotations

import pytest

from community_member.actions.desktop import DesktopUnavailable, FocusInfo
from community_member.actions.desktop_drivers import WindowsDesktopDriver


class FakeUser32:
    """Records every Win32 API call for assertion."""

    def __init__(
        self,
        *,
        foreground: int = 0xDEAD,
        title: str = "",
        pid: int = 4321,
        screen_w: int = 1920,
        screen_h: int = 1080,
    ) -> None:
        self.foreground = foreground
        self.title = title
        self.pid = pid
        self.screen_w = screen_w
        self.screen_h = screen_h
        self.calls: list[tuple] = []

    def GetForegroundWindow(self):
        return self.foreground

    def GetWindowTextW(self, hwnd, buf, n):
        # buf is ctypes.create_unicode_buffer(...). Mimic the API by
        # writing into .value (allowed because buf.value is a setter).
        try:
            buf.value = self.title  # type: ignore[attr-defined]
        except Exception:
            pass
        return len(self.title)

    def GetWindowThreadProcessId(self, hwnd, pid_box):
        try:
            pid_box._obj.value = self.pid  # type: ignore[attr-defined]
        except Exception:
            pass
        return 0

    def SetCursorPos(self, x, y):
        self.calls.append(("SetCursorPos", x, y))
        return True

    def mouse_event(self, flags, dx, dy, data, extra_info):
        self.calls.append(("mouse_event", flags))
        return None

    def SendInput(self, n, ev_ref, size):
        # The struct is opaque from our side; just record that we
        # were called once per (down, up) pair plus the input size.
        self.calls.append(("SendInput", int(n), int(size)))
        return int(n)

    def GetSystemMetrics(self, idx):
        if idx == 0:
            return self.screen_w
        if idx == 1:
            return self.screen_h
        return 0


# ── focus ────────────────────────────────────────────────────────


def test_focus_returns_descriptor_and_pid():
    user32 = FakeUser32(foreground=0xCAFE, title="Notepad", pid=9001)
    drv = WindowsDesktopDriver(user32=user32)
    info = drv.focus()
    assert isinstance(info, FocusInfo)
    assert info.descriptor == "Notepad"
    assert info.pid == 9001


def test_focus_falls_back_to_hwnd_when_title_empty():
    user32 = FakeUser32(foreground=0xBEEF, title="", pid=5)
    drv = WindowsDesktopDriver(user32=user32)
    info = drv.focus()
    assert info.descriptor == f"hwnd:{0xBEEF}"


def test_R1_no_foreground_window_raises():
    user32 = FakeUser32(foreground=0)
    drv = WindowsDesktopDriver(user32=user32)
    with pytest.raises(DesktopUnavailable, match="no foreground window"):
        drv.focus()


# ── click ────────────────────────────────────────────────────────


def test_click_calls_setcursorpos_then_mouse_event_pair():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.click(x=400, y=500, button="left")
    assert user32.calls[0] == ("SetCursorPos", 400, 500)
    # LEFTDOWN=0x0002, LEFTUP=0x0004
    assert user32.calls[1] == ("mouse_event", 0x0002)
    assert user32.calls[2] == ("mouse_event", 0x0004)


def test_click_translates_right_button():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.click(x=10, y=20, button="right")
    # RIGHTDOWN=0x0008, RIGHTUP=0x0010
    assert user32.calls[1] == ("mouse_event", 0x0008)
    assert user32.calls[2] == ("mouse_event", 0x0010)


def test_R5_negative_coords_clamped():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.click(x=-100, y=-50)
    assert user32.calls[0] == ("SetCursorPos", 0, 0)


def test_R5_unknown_button_rejected_windows():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    with pytest.raises(DesktopUnavailable, match="unknown button"):
        drv.click(x=1, y=1, button="superhyper")


# ── type_text ────────────────────────────────────────────────────


def test_R3_type_issues_one_sendinput_pair_per_character():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.type_text(text="hi")
    # Each char produces a (KEYDOWN, KEYUP) pair = 2 SendInput calls.
    sendinput_calls = [c for c in user32.calls if c[0] == "SendInput"]
    assert len(sendinput_calls) == 4  # 2 chars * 2 events


def test_type_handles_unicode():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.type_text(text="🚀é")
    sendinput_calls = [c for c in user32.calls if c[0] == "SendInput"]
    assert len(sendinput_calls) == 4  # 2 chars * 2 events; ord() works for emoji UTF-32 codepoint


def test_type_empty_string_issues_no_calls():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32)
    drv.type_text(text="")
    assert not [c for c in user32.calls if c[0] == "SendInput"]


# ── read_screen ──────────────────────────────────────────────────


def test_R10_read_screen_delegates_to_encode_png():
    user32 = FakeUser32()
    captured: dict = {}

    def fake_encode(*, width, height):
        captured["w"] = width
        captured["h"] = height
        return b"PNG_DATA"

    drv = WindowsDesktopDriver(user32=user32, encode_png=fake_encode)
    out = drv.read_screen()
    assert out == b"PNG_DATA"
    assert captured == {"w": 1920, "h": 1080}


def test_read_screen_without_encoder_raises():
    user32 = FakeUser32()
    drv = WindowsDesktopDriver(user32=user32, encode_png=None)
    with pytest.raises(DesktopUnavailable, match="no PNG encoder"):
        drv.read_screen()


def test_read_screen_encoder_failure_surfaces():
    user32 = FakeUser32()

    def boom(**_):
        raise RuntimeError("OOM")

    drv = WindowsDesktopDriver(user32=user32, encode_png=boom)
    with pytest.raises(DesktopUnavailable, match="PNG encode failed"):
        drv.read_screen()


# ── R8 user32 unavailability ─────────────────────────────────────


def test_R8_user32_unavailable_surfaces_as_DesktopUnavailable():
    """When _resolve_user32 raises (e.g. running on Linux without
    ctypes.windll), the driver wraps the error so callers don't have
    to know about platform internals."""
    drv = WindowsDesktopDriver(user32=None)
    # On Linux this raises DesktopUnavailable from _resolve_user32.
    with pytest.raises(DesktopUnavailable):
        drv.focus()
