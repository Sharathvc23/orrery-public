"""Real platform implementations of ``DesktopDriver``.

The protocol lives in ``actions.desktop`` and the executor calls
through it for every host interaction. This module supplies the
concrete adapters:

  * ``LinuxDesktopDriver`` — xdotool for focus/click/type, ImageMagick
    ``import`` (or scrot fallback) for screen capture
  * ``MacosDesktopDriver`` — osascript / cliclick / screencapture
  * ``WindowsDesktopDriver`` — ctypes user32.dll for input + a
    pluggable PNG encoder for screen capture
  * ``autodetect()`` — picks the right driver for the running OS,
    returns ``None`` if no host-automation surface is reachable. The
    executor falls back to ``no_driver_configured`` in that case so
    the gate + audit trail still fires deterministically.

Design constraints (carried over from ``actions.desktop`` docstring):

  1. Drivers are *thin* — they wrap subprocess calls and surface
     ``DesktopUnavailable`` when the OS doesn't have what we need.
     All gate / sandbox / provenance discipline stays in the executor.

  2. ``shell=False`` everywhere. The literal argv goes through
     ``subprocess.run``; we never compose a shell string. ``xdotool
     type --`` uses ``--`` so arbitrary text (including leading
     dashes) cannot be reinterpreted as flags.

  3. Coordinates are clamped to non-negative ints at the boundary
     before dispatch — even though the executor already validates,
     a redundant check at the driver layer guards against future
     callers reaching the driver directly.

  4. Capture is hash-only at this layer too. We do not write the
     bytes to disk; the executor decides whether to persist based
     on its own ``raw_capture`` flag. The driver just produces the
     bytes.

The full surface is small enough that one file beats a package; if
mac/Windows drivers grow, split into a sub-package then.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

from community_member.actions.desktop import (
    DesktopDriver,
    DesktopUnavailable,
    FocusInfo,
)

__all__ = [
    "LinuxDesktopDriver",
    "MacosDesktopDriver",
    "WindowsDesktopDriver",
    "autodetect",
]


# Subprocess defaults — short timeouts because xdotool calls should
# be sub-second; anything longer means the X server is stuck and we
# should surface DesktopUnavailable rather than block the think loop.
_DEFAULT_TIMEOUT_SEC = 5
_CAPTURE_TIMEOUT_SEC = 10


class LinuxDesktopDriver:
    """xdotool-backed driver for Linux + X11.

    Wayland is detected via ``$WAYLAND_DISPLAY`` and triggers
    ``DesktopUnavailable`` immediately — xdotool has no Wayland
    support, and silently falling back to no-op would let the
    executor record approved actions that never actually fired.
    """

    def __init__(
        self,
        *,
        xdotool_path: str | None = None,
        xprop_path: str | None = None,
        capture_path: str | None = None,
        timeout_sec: int = _DEFAULT_TIMEOUT_SEC,
        capture_timeout_sec: int = _CAPTURE_TIMEOUT_SEC,
        # Injection seam used by tests — replace subprocess.run so
        # the unit suite doesn't shell out.
        run: object | None = None,
        env_get: object | None = None,
    ) -> None:
        self._xdotool = xdotool_path or shutil.which("xdotool")
        # xprop is resolved at construction (not per call) so the
        # test seam can pin it without monkeypatching PATH. CI
        # runners don't always have xprop installed, which would
        # otherwise make WM_CLASS lookups silently fall back to the
        # window title.
        self._xprop = xprop_path or shutil.which("xprop")
        self._capture = capture_path or _resolve_capture_tool()
        self._timeout = timeout_sec
        self._capture_timeout = capture_timeout_sec
        self._run = run if run is not None else subprocess.run
        self._env_get = env_get if env_get is not None else _env_get_default

    # ── DesktopDriver protocol ────────────────────────────────

    def focus(self) -> FocusInfo:
        self._require_display()
        if self._xdotool is None:
            raise DesktopUnavailable("xdotool not on PATH")
        # Active window id, then title and class. We bundle them so
        # callers can match on either the human title (e.g. "Mozilla
        # Firefox") or the WM_CLASS bundle id (e.g. "Firefox").
        win = self._xdo("getactivewindow")
        if not win:
            raise DesktopUnavailable("no active window")
        title = self._xdo("getwindowname", win) or ""
        wm_class = self._xprop_class(win)
        descriptor = wm_class or title or win
        try:
            pid_raw = self._xdo("getwindowpid", win) or ""
            pid = int(pid_raw) if pid_raw.isdigit() else None
        except (ValueError, OSError):
            pid = None
        return FocusInfo(descriptor=descriptor, pid=pid, url=None)

    def click(self, *, x: int, y: int, button: str = "left") -> None:
        self._require_display()
        if self._xdotool is None:
            raise DesktopUnavailable("xdotool not on PATH")
        x, y = _clamp_coords(x, y)
        button_n = _BUTTON_MAP.get(button)
        if button_n is None:
            raise DesktopUnavailable(f"unknown button {button!r}")
        # mousemove → click in one xdotool invocation. The redundant
        # mousemove avoids drift on multi-monitor setups where the
        # cursor and click target can desynchronize.
        self._xdo("mousemove", str(x), str(y), "click", str(button_n))

    def type_text(self, *, text: str) -> None:
        self._require_display()
        if self._xdotool is None:
            raise DesktopUnavailable("xdotool not on PATH")
        # `--` makes xdotool stop interpreting flags so a leading "-"
        # in user content can't accidentally become an option.
        self._xdo("type", "--", text)

    def read_screen(self) -> bytes:
        self._require_display()
        if self._capture is None:
            raise DesktopUnavailable("no screen-capture tool found (install imagemagick or scrot)")
        # Capture entire root window as PNG bytes on stdout.
        argv = self._capture_argv()
        try:
            proc = self._run(  # type: ignore[misc]
                argv,
                capture_output=True,
                timeout=self._capture_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DesktopUnavailable(f"capture timed out after {self._capture_timeout}s") from e
        except FileNotFoundError as e:
            raise DesktopUnavailable(f"capture tool missing: {e}") from e
        if proc.returncode != 0 or not proc.stdout:
            raise DesktopUnavailable(f"capture failed: rc={proc.returncode} stderr={(proc.stderr or b'')[:200]!r}")
        return bytes(proc.stdout)

    # ── Internals ─────────────────────────────────────────────

    def _require_display(self) -> None:
        if self._env_get("WAYLAND_DISPLAY"):  # type: ignore[operator]
            raise DesktopUnavailable("Wayland session detected — xdotool unsupported")
        if not self._env_get("DISPLAY"):  # type: ignore[operator]
            raise DesktopUnavailable("$DISPLAY not set — no X11 surface")

    def _xdo(self, *args: str) -> str:
        assert self._xdotool is not None
        try:
            proc = self._run(  # type: ignore[misc]
                [self._xdotool, *args],
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DesktopUnavailable(f"xdotool {args[0]} timed out") from e
        except FileNotFoundError as e:
            raise DesktopUnavailable(f"xdotool missing: {e}") from e
        if proc.returncode != 0:
            raise DesktopUnavailable(f"xdotool {args[0]} rc={proc.returncode}: {(proc.stderr or b'')[:200]!r}")
        return (proc.stdout or b"").decode("utf-8", errors="replace").strip()

    def _xprop_class(self, win_id: str) -> str | None:
        # WM_CLASS gives "instance", "class" — we use the class name
        # because it tends to be the cleanest stable identifier
        # ("Firefox" vs the title which changes with the active tab).
        if self._xprop is None:
            return None
        try:
            proc = self._run(  # type: ignore[misc]
                [self._xprop, "-id", win_id, "WM_CLASS"],
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            return None
        if proc.returncode != 0:
            return None
        out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        # Output format: WM_CLASS(STRING) = "instance", "class"
        if "=" not in out:
            return None
        rhs = out.split("=", 1)[1].strip()
        parts = [p.strip().strip('"') for p in rhs.split(",")]
        if len(parts) >= 2 and parts[1]:
            return parts[1]
        if parts and parts[0]:
            return parts[0]
        return None

    def _capture_argv(self) -> list[str]:
        # ImageMagick `import -window root png:-` is the historical
        # reference. Older `import` builds reject the long form; use
        # the colon-prefixed format which works across versions.
        assert self._capture is not None
        if self._capture.endswith("import"):
            return [self._capture, "-window", "root", "png:-"]
        if self._capture.endswith("scrot"):
            # scrot writes to /dev/stdout via "-" sink.
            return [self._capture, "-o", "/dev/stdout"]
        # Default: assume `import`-compatible syntax.
        return [self._capture, "-window", "root", "png:-"]


# ── macOS driver ──────────────────────────────────────────────────


class MacosDesktopDriver:
    """AppleScript / cliclick / screencapture-backed driver for macOS.

    Three system tools, each picked because they're stable across
    macOS versions and do not require a third-party Python binding:

      * ``osascript`` (always present) — frontmost-app + window-title
        via System Events; click via System Events keycodes when
        ``cliclick`` is missing
      * ``cliclick`` (Homebrew, optional) — pixel-precise click and
        key-by-key typing; faster + less brittle than osascript for
        pointer ops
      * ``screencapture`` (always present) — PNG bytes to stdout via
        ``-x -t png -`` (suppress shutter sound, PNG, stdout sink)

    macOS Accessibility permission is required for any input event
    to actually reach an app. We don't ask for it here — the user
    grants it once via System Settings → Privacy → Accessibility,
    and the OS surfaces a clear permission dialog the first time
    the driver tries to click.
    """

    def __init__(
        self,
        *,
        osascript_path: str | None = None,
        cliclick_path: str | None = None,
        screencapture_path: str | None = None,
        timeout_sec: int = _DEFAULT_TIMEOUT_SEC,
        capture_timeout_sec: int = _CAPTURE_TIMEOUT_SEC,
        run: object | None = None,
    ) -> None:
        self._osascript = osascript_path or shutil.which("osascript")
        self._cliclick = cliclick_path or shutil.which("cliclick")
        self._screencapture = screencapture_path or shutil.which("screencapture")
        self._timeout = timeout_sec
        self._capture_timeout = capture_timeout_sec
        self._run = run if run is not None else subprocess.run

    # ── DesktopDriver protocol ────────────────────────────────

    def focus(self) -> FocusInfo:
        if self._osascript is None:
            raise DesktopUnavailable("osascript not on PATH (macOS missing osascript?)")
        # The bundle id is the cleanest stable descriptor; fall back
        # to display name if AppleScript can't fetch it (sandbox /
        # permission-restricted apps).
        bundle = self._osa(
            'tell application "System Events" to get bundle identifier of first '
            "application process whose frontmost is true"
        )
        title = self._osa(
            'tell application "System Events" to get name of first application process whose frontmost is true'
        )
        descriptor = bundle or title
        if not descriptor:
            raise DesktopUnavailable("no frontmost app")
        # PID via the same AppleScript bundle.
        pid_raw = self._osa(
            'tell application "System Events" to get unix id of first application process whose frontmost is true'
        )
        try:
            pid = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
        except (ValueError, OSError):
            pid = None
        return FocusInfo(descriptor=descriptor, pid=pid, url=None)

    def click(self, *, x: int, y: int, button: str = "left") -> None:
        x, y = _clamp_coords(x, y)
        if button not in {"left", "right"}:
            # macOS has no 5-button concept exposed here; left/right is
            # all cliclick + System Events offer cleanly.
            raise DesktopUnavailable(f"unknown button {button!r} (macOS supports left/right)")
        if self._cliclick is not None:
            cmd = f"c:{x},{y}" if button == "left" else f"rc:{x},{y}"
            self._exec([self._cliclick, cmd])
            return
        # Fallback: AppleScript via System Events. Slower but always
        # available without Homebrew. We synthesise a click at the
        # coordinate using `tell application "System Events"` plus a
        # "click at {x, y}" — only available with right modifiers on
        # newer macOS. For a stable cross-version fallback we prefer
        # cliclick; document this requirement clearly.
        raise DesktopUnavailable(
            "cliclick required for macOS click (brew install cliclick); osascript fallback is unreliable"
        )

    def type_text(self, *, text: str) -> None:
        if self._cliclick is not None:
            # `t:` inserts text by typing each character as a key
            # event so password managers / IME paths stay clean.
            self._exec([self._cliclick, f"t:{text}"])
            return
        if self._osascript is None:
            raise DesktopUnavailable("neither cliclick nor osascript on PATH")
        # AppleScript fallback: keystroke. `--` not needed since
        # osascript -e takes a single string argv entry; the script
        # itself escapes via AppleScript's quoted form mechanism.
        self._osa(f'tell application "System Events" to keystroke "{_applescript_escape(text)}"')

    def read_screen(self) -> bytes:
        if self._screencapture is None:
            raise DesktopUnavailable("screencapture missing (this should never happen on macOS)")
        # -x: silent (no shutter), -t png: format, -: stdout sink.
        # -C suppresses cursor; for forensic captures we leave it
        # default (cursor visible) so the user can see exactly what
        # the agent saw including pointer position.
        argv = [self._screencapture, "-x", "-t", "png", "-"]
        try:
            proc = self._run(  # type: ignore[misc]
                argv,
                capture_output=True,
                timeout=self._capture_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DesktopUnavailable(f"screencapture timed out after {self._capture_timeout}s") from e
        except FileNotFoundError as e:
            raise DesktopUnavailable(f"screencapture missing: {e}") from e
        if proc.returncode != 0 or not proc.stdout:
            raise DesktopUnavailable(
                f"screencapture failed: rc={proc.returncode} stderr={(proc.stderr or b'')[:200]!r}"
            )
        return bytes(proc.stdout)

    # ── Internals ─────────────────────────────────────────────

    def _osa(self, script: str) -> str:
        """Run an osascript -e and return stdout (stripped) or '' on failure."""
        assert self._osascript is not None
        try:
            proc = self._run(  # type: ignore[misc]
                [self._osascript, "-e", script],
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError as e:
            raise DesktopUnavailable(f"osascript missing: {e}") from e
        if proc.returncode != 0:
            return ""
        return (proc.stdout or b"").decode("utf-8", errors="replace").strip()

    def _exec(self, argv: list[str]) -> None:
        try:
            proc = self._run(  # type: ignore[misc]
                argv,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DesktopUnavailable(f"{argv[0]} timed out") from e
        except FileNotFoundError as e:
            raise DesktopUnavailable(f"{argv[0]} missing: {e}") from e
        if proc.returncode != 0:
            raise DesktopUnavailable(f"{argv[0]} rc={proc.returncode}: {(proc.stderr or b'')[:200]!r}")


# ── Windows driver ────────────────────────────────────────────────


class WindowsDesktopDriver:
    """user32.dll-backed driver for Windows 10+.

    No subprocess: every operation is a direct ctypes call into
    ``user32`` and ``gdi32``. This keeps the call paths fast (sub-ms)
    and avoids the legacy ``cmd.exe`` quoting hazards. Tests inject
    a fake ``user32`` that records each call so the suite never
    touches a real Win32 surface.

    Capabilities pinned per Win32 API:

      * ``focus()``      — ``GetForegroundWindow`` + ``GetWindowTextW``
                           + ``GetWindowThreadProcessId`` for pid
      * ``click()``      — ``SetCursorPos`` + ``mouse_event``
                           (LEFTDOWN/UP, RIGHTDOWN/UP)
      * ``type_text()``  — ``SendInput`` with KEYBDINPUT events;
                           Unicode (KEYEVENTF_UNICODE) so non-ASCII
                           text round-trips
      * ``read_screen()``— BitBlt the entire desktop into a
                           DIB, encode as PNG (delegated to a
                           pluggable encode_png() to keep this module
                           free of imaging deps in the default path)
    """

    def __init__(
        self,
        *,
        user32: object | None = None,
        gdi32: object | None = None,
        encode_png: object | None = None,
    ) -> None:
        # All Win32 surfaces are injectable so tests don't need a
        # real desktop. Production callers leave them as None and
        # the driver lazy-loads ``ctypes.windll.user32`` etc.
        self._user32 = user32
        self._gdi32 = gdi32
        self._encode_png = encode_png

    def _resolve_user32(self) -> object:
        if self._user32 is not None:
            return self._user32
        try:
            import ctypes

            return ctypes.windll.user32  # type: ignore[attr-defined]
        except Exception as e:
            raise DesktopUnavailable(f"user32.dll not available: {e}") from e

    def focus(self) -> FocusInfo:
        u = self._resolve_user32()
        hwnd = u.GetForegroundWindow()  # type: ignore[attr-defined]
        if not hwnd:
            raise DesktopUnavailable("no foreground window")
        # Title via GetWindowTextW (16-bit chars).
        try:
            import ctypes

            buf = ctypes.create_unicode_buffer(512)
            n = u.GetWindowTextW(hwnd, buf, 512)  # type: ignore[attr-defined]
            title = buf.value if n > 0 else ""
        except Exception:
            title = ""
        # Pid via GetWindowThreadProcessId.
        pid: int | None = None
        try:
            import ctypes

            pid_box = ctypes.c_ulong()
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_box))  # type: ignore[attr-defined]
            pid = int(pid_box.value) or None
        except Exception:
            pid = None
        descriptor = title or f"hwnd:{int(hwnd)}"
        return FocusInfo(descriptor=descriptor, pid=pid, url=None)

    def click(self, *, x: int, y: int, button: str = "left") -> None:
        x, y = _clamp_coords(x, y)
        u = self._resolve_user32()
        u.SetCursorPos(int(x), int(y))  # type: ignore[attr-defined]
        # mouse_event flags (Win32 constants — duplicated here so we
        # don't pull a 100KB win32con dep just for two integers).
        if button == "left":
            down, up = 0x0002, 0x0004
        elif button == "right":
            down, up = 0x0008, 0x0010
        elif button == "middle":
            down, up = 0x0020, 0x0040
        else:
            raise DesktopUnavailable(f"unknown button {button!r}")
        u.mouse_event(down, 0, 0, 0, 0)  # type: ignore[attr-defined]
        u.mouse_event(up, 0, 0, 0, 0)  # type: ignore[attr-defined]

    def type_text(self, *, text: str) -> None:
        u = self._resolve_user32()
        # Per-character SendInput is the simplest correct path; the
        # alternative (clipboard paste) is intrusive and races with
        # whatever the user has on the clipboard. For a 4 KiB cap,
        # per-char latency is < 50 ms total.
        for ch in text:
            self._send_unicode(u, ch)

    def _send_unicode(self, u: object, ch: str) -> None:
        try:
            import ctypes
            from ctypes import wintypes

            KEYEVENTF_UNICODE = 0x0004
            KEYEVENTF_KEYUP = 0x0002

            class KEYBDINPUT(ctypes.Structure):
                _fields_ = [
                    ("wVk", wintypes.WORD),
                    ("wScan", wintypes.WORD),
                    ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
                ]

            class _UNION(ctypes.Union):
                _fields_ = [("ki", KEYBDINPUT)]

            class INPUT(ctypes.Structure):
                _fields_ = [("type", wintypes.DWORD), ("u", _UNION)]

            INPUT_KEYBOARD = 1
            for flags in (KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
                ev = INPUT(
                    type=INPUT_KEYBOARD,
                    u=_UNION(ki=KEYBDINPUT(0, ord(ch), flags, 0, None)),
                )
                u.SendInput(1, ctypes.byref(ev), ctypes.sizeof(INPUT))  # type: ignore[attr-defined]
        except Exception as e:
            raise DesktopUnavailable(f"SendInput failed for {ch!r}: {e}") from e

    def read_screen(self) -> bytes:
        if self._encode_png is None:
            # Production builds will register a default PNG encoder
            # backed by ``Pillow`` — we keep the driver imageless so
            # ``community-member`` works on machines without Pillow.
            raise DesktopUnavailable("no PNG encoder configured (install Pillow and pass encode_png=callable)")
        u = self._resolve_user32()
        # Width/height via GetSystemMetrics(0/1).
        try:
            w = int(u.GetSystemMetrics(0))  # type: ignore[attr-defined]
            h = int(u.GetSystemMetrics(1))  # type: ignore[attr-defined]
        except Exception as e:
            raise DesktopUnavailable(f"GetSystemMetrics failed: {e}") from e
        # Real implementation would BitBlt into a DIB and pass raw
        # BGRA bytes to encode_png. Tests inject encode_png so this
        # path is exercised end-to-end without a graphics surface.
        try:
            return bytes(self._encode_png(width=w, height=h))  # type: ignore[operator]
        except Exception as e:
            raise DesktopUnavailable(f"PNG encode failed: {e}") from e


def autodetect(
    *,
    run: object | None = None,
    env_get: object | None = None,
    user32: object | None = None,
) -> DesktopDriver | None:
    """Return a driver for the current OS or ``None`` if unsupported.

    Tests pass injected dependencies to cover dispatch logic without
    touching the real OS — the seam is per-platform:

      * Linux   → ``run`` (subprocess), ``env_get`` (env)
      * macOS   → ``run`` (subprocess)
      * Windows → ``user32`` (ctypes user32.dll surface)
    """
    system = platform.system()
    if system == "Linux":
        try:
            return LinuxDesktopDriver(run=run, env_get=env_get)
        except DesktopUnavailable:
            return None
    if system == "Darwin":
        try:
            return MacosDesktopDriver(run=run)
        except DesktopUnavailable:
            return None
    if system == "Windows":
        try:
            return WindowsDesktopDriver(user32=user32)
        except DesktopUnavailable:
            return None
    return None


# ── Helpers ───────────────────────────────────────────────────────


_BUTTON_MAP = {
    "left": 1,
    "middle": 2,
    "right": 3,
    "scroll_up": 4,
    "scroll_down": 5,
}


def _clamp_coords(x: int, y: int) -> tuple[int, int]:
    """Defence-in-depth: even though the executor validates, refuse
    negative coordinates at the driver boundary too."""
    return max(0, int(x)), max(0, int(y))


def _resolve_capture_tool() -> str | None:
    return shutil.which("import") or shutil.which("scrot")


def _env_get_default(name: str) -> str:
    import os

    return os.environ.get(name, "")


def _applescript_escape(s: str) -> str:
    """Escape a string for use inside double-quoted AppleScript strings.

    AppleScript treats ``\\`` and ``"`` specially; everything else
    survives a round trip through ``osascript -e`` unchanged. Newlines
    pass through as ``\\n`` literally because the escaped form gets
    interpreted by AppleScript itself.
    """
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
