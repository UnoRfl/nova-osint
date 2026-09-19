"""Window shell: boot screen, then the scan console."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

from ..core.logging_config import get_logger
from . import theme
from .boot import BootScreen
from .console import ConsoleScreen

log = get_logger("gui")

TITLE = "NOVA — open source intel"


class NovaApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(TITLE)
        self.minsize(1040, 660)
        self._centre(1280, 800)
        self.configure(bg=theme.BG)
        self.fonts = theme.install(self)
        self._set_icon()

        self.container = ttk.Frame(self, style="Space.TFrame")
        self.container.pack(fill="both", expand=True)

        self.screen: ttk.Frame | None = None
        self._show(BootScreen(self.container, on_ready=self._enter_console))
        self.protocol("WM_DELETE_WINDOW", self._close)

    def report_callback_exception(self, exc, value, tb) -> None:  # noqa: N802
        """Tk's own hook for an exception inside a callback.

        The default prints to stderr, and the desktop app is launched with
        ``pythonw``, which has no stderr. So a bug in a button handler left the
        window sitting there with no error and no clue: one wrong mapping made
        every username scan raise inside ``start_scan`` before the worker
        thread was created, and the display stayed at "0% · starting …"
        indefinitely. Nothing was broken on screen, so nothing looked broken.

        Now it goes to the log file and, when the console is up, into the live
        log where the operator is already looking.
        """
        import traceback

        text = "".join(traceback.format_exception(exc, value, tb))
        log.error("unhandled GUI error:\n%s", text)
        screen = self.screen
        reporter = getattr(screen, "report_error", None)
        if callable(reporter):
            try:
                reporter(f"{exc.__name__}: {value}")
                return
            except Exception:  # noqa: BLE001 - the reporter must never recurse
                pass
        try:
            from tkinter import messagebox

            messagebox.showerror(
                "NOVA hit an error",
                f"{exc.__name__}: {value}\n\n"
                f"The details are in the log file.")
        except Exception:  # noqa: BLE001 - no window to show it in
            pass

    def _centre(self, w: int, h: int) -> None:
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(w, sw - 80), min(h, sh - 120)
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(0, (sh - h) // 2 - 20)}")

    def _set_icon(self) -> None:
        # A drawn icon beats shipping a .ico that PyInstaller has to bundle.
        try:
            size = 64
            img = tk.PhotoImage(width=size, height=size)
            img.put(theme.BG, to=(0, 0, size, size))
            cx = cy = size // 2
            for r, colour in ((22, "#2d1f4d"), (7, theme.GOLD), (4, "#fff3cc")):
                for y in range(cy - r, cy + r + 1):
                    for x in range(cx - r, cx + r + 1):
                        d = ((x - cx) ** 2 + ((y - cy) * 2.2) ** 2) ** 0.5
                        if r - 1.2 <= d <= r if r == 22 else d <= r:
                            img.put(colour, to=(x, y, x + 1, y + 1))
            img.put(theme.MAGENTA, to=(cx + 20, cy - 2, cx + 25, cy + 3))
            self.iconphoto(True, img)
            self._icon = img  # Tk drops the image if nothing holds a reference
        except Exception:
            pass

    def _show(self, screen: ttk.Frame) -> None:
        if self.screen is not None:
            self.screen.destroy()
        self.screen = screen
        screen.pack(fill="both", expand=True)

    def _enter_console(self, boot: dict) -> None:
        self._show(ConsoleScreen(self.container, boot))

    def _close(self) -> None:
        # Stop the canvas timers first; an `after` firing mid-teardown throws.
        for widget in self.winfo_children():
            for method in ("stop",):
                if hasattr(widget, method):
                    getattr(widget, method)()
        self.destroy()


def main(argv: list[str] | None = None) -> int:
    try:
        app = NovaApp()
    except tk.TclError as e:
        print(f"NOVA could not open a window: {e}", file=sys.stderr)
        print("On Linux, install python3-tk. Over SSH you need an X display.",
              file=sys.stderr)
        return 1
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
