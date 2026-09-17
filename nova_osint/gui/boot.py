"""The startup sequence.

The progress here is real work, not a timed fake: it imports the module
registry, reads the environment for keys, opens the HTTP transport, pulls the
platform catalogue and probes the upstream sources. If a source is down you
find out on this screen rather than halfway through your first scan.

The screen **waits for you**. Initialisation finishing does not advance it;
pressing Enter (or Space, or the button) does. The point of showing the boot
log is that you can read it - if crt.sh is down or a key was rejected, that
line is on screen until you have actually seen it.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from collections.abc import Callable
from tkinter import ttk

from ..core import dns as dnsmod
from ..core.config import DEFAULT_CACHE, Config, runtime_config
from ..core.http import Fetcher
from ..core.registry import all_modules
from . import theme
from .orbit import OrbitCanvas, Wordmark

#: How fast the "press ENTER" hint breathes, in milliseconds per step.
HINT_PULSE_MS = 90


class BootScreen(ttk.Frame):
    def __init__(self, master, on_ready: Callable[[dict], None]) -> None:
        super().__init__(master, style="Space.TFrame")
        self.on_ready = on_ready
        self.queue: queue.Queue = queue.Queue()
        self.payload: dict = {}
        self.started = time.monotonic()
        self._done = False

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.orbit = OrbitCanvas(self, width=720, height=330, star_count=150)
        self.orbit.grid(row=0, column=0, sticky="nsew")
        self.orbit.start()

        panel = ttk.Frame(self, style="Space.TFrame", padding=(0, 0, 0, 22))
        panel.grid(row=1, column=0)

        Wordmark(panel, scale=10).pack()
        ttk.Label(panel, text="o p e n   s o u r c e   i n t e l   ·   b y   u n o",
                  style="Space.TLabel").pack(pady=(2, 16))

        self.bar = ttk.Progressbar(panel, style="Nova.Horizontal.TProgressbar",
                                   length=520, maximum=100)
        self.bar.pack()

        self.log = tk.Text(panel, height=7, width=74, bg=theme.BG, fg=theme.INK_DIM,
                           relief="flat", highlightthickness=0, bd=0,
                           font=("Consolas", 9), spacing1=2, cursor="arrow")
        self.log.pack(pady=(14, 10))
        self.log.tag_configure("ok", foreground=theme.OK)
        self.log.tag_configure("warn", foreground=theme.NOTABLE)
        self.log.tag_configure("label", foreground=theme.INK)
        self.log.tag_configure("detail", foreground=theme.INK_FAINT)
        self.log.tag_configure("accent", foreground=theme.ORCHID)
        self.log.configure(state="disabled")

        self.enter = ttk.Button(panel, text="ENTER  ▸", style="Accent.TButton",
                                command=self._advance, state="disabled")
        self.enter.pack()

        # Stays empty until initialisation finishes, then breathes so it is
        # obvious the screen is waiting rather than stuck.
        self.hint = tk.Label(panel, text="", bg=theme.BG, fg=theme.INK_FAINT,
                             font=("Segoe UI", 9))
        self.hint.pack(pady=(10, 0))
        self._pulse = 0

        threading.Thread(target=self._work, daemon=True).start()
        self.after(60, self._drain)

    # ------------------------------------------------------------------ worker

    def _step(self, label: str, detail: str, ok: bool = True, pct: int = 0) -> None:
        self.queue.put(("step", label, detail, ok, pct))

    def _work(self) -> None:
        """Runs off the UI thread. Never touches a widget directly."""
        try:
            modules = all_modules()
            self._step("core online", f"{len(modules)} instruments registered", True, 12)

            config = runtime_config(cache_dir=DEFAULT_CACHE / "http")
            keys = config.available_keys
            self._step(
                "credentials",
                f"{len(keys)} key(s): {', '.join(keys)}" if keys
                else "none set - every key-free module still runs",
                bool(keys), 24,
            )

            http = Fetcher(concurrency=12, cache_dir=config.cache_dir,
                           cache_ttl=config.cache_ttl)
            self._step("transport open", "rate-limited, cached, 12 workers", True, 36)

            answers = dnsmod.resolve(http, "cloudflare.com", "A")
            self._step("DNS-over-HTTPS", f"resolver answered ({len(answers)} record(s))"
                       if answers else "no answer - DNS modules will be blind",
                       bool(answers), 50)

            from ..modules.username import load_sites

            sites, origin = load_sites(http)
            self._step("platform catalogue", origin, bool(sites), 72)

            reachable = self._probe(http)
            live = sum(1 for ok in reachable.values() if ok)
            down = [n for n, ok in reachable.items() if not ok]
            self._step("upstream sources",
                       f"{live}/{len(reachable)} reachable"
                       + (f" - down: {', '.join(down)}" if down else ""),
                       not down, 92)

            ready = [m for m in modules if not m(http, config).skip_reason()]
            self._step("instruments armed",
                       f"{len(ready)} ready, {len(modules) - len(ready)} waiting on keys",
                       True, 100)

            self.queue.put(("done", {"config": config, "http": http,
                                     "sites": len(sites), "modules": modules}))
        except Exception as e:  # a broken boot must still reach the console
            self.queue.put(("step", "startup problem", f"{type(e).__name__}: {e}",
                            False, 100))
            self.queue.put(("done", {"config": Config.from_env(), "http": None,
                                     "sites": 0, "modules": []}))

    def _probe(self, http: Fetcher) -> dict[str, bool]:
        checks = {
            "rdap.org": "https://rdap.org/domain/example.com",
            "crt.sh": "https://crt.sh/?q=example.com&output=json",
            "hibp": "https://haveibeenpwned.com/api/v3/breaches?Domain=example.com",
            "shodan": "https://internetdb.shodan.io/1.1.1.1",
            "archive.org": "https://archive.org/",
        }
        results = http.map(lambda kv: (kv[0], http.get(kv[1], timeout=8).status > 0),
                           list(checks.items()))
        return {name: ok for pair in results if pair for name, ok in [pair]}

    # ---------------------------------------------------------------------- ui

    def _drain(self) -> None:
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "step":
                    _, label, detail, ok, pct = item
                    self._write(label, detail, ok)
                    if pct:
                        self.bar["value"] = pct
                else:
                    self.payload = item[1]
                    self._finish()
        except queue.Empty:
            pass
        if not self._done:
            self.after(60, self._drain)

    def _write(self, label: str, detail: str, ok: bool) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", "  ✓  " if ok else "  !  ", "ok" if ok else "warn")
        self.log.insert("end", f"{label:<22}", "label")
        self.log.insert("end", f"{detail}\n", "detail")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _finish(self) -> None:
        """Initialisation is done. Now wait - nothing advances on a timer."""
        elapsed = time.monotonic() - self.started
        self._write("ready", f"initialised in {elapsed:.1f}s", True)
        self.bar["value"] = 100

        self.enter.configure(state="normal")
        self.enter.focus_set()
        top = self.winfo_toplevel()
        for sequence in ("<Return>", "<KP_Enter>", "<space>"):
            top.bind(sequence, self._advance)
        self._breathe()

    def _breathe(self) -> None:
        """Fade the hint in and out so a finished screen never looks frozen."""
        if self._done:
            return
        self._pulse = (self._pulse + 1) % 40
        # A triangle wave: 0 -> 1 -> 0 across the cycle.
        phase = self._pulse / 20 if self._pulse < 20 else (40 - self._pulse) / 20
        self.hint.configure(
            text="press  ENTER  to continue",
            fg=theme.blend(theme.ORCHID, theme.BG, 0.55 - 0.45 * phase),
        )
        self.after(HINT_PULSE_MS, self._breathe)

    def _advance(self, _event: object = None) -> None:
        # Guarded because the button, three key bindings and a stray repeat can
        # all fire this, and the console must only be built once.
        if self._done or str(self.enter["state"]) == "disabled":
            return
        self._done = True
        top = self.winfo_toplevel()
        for sequence in ("<Return>", "<KP_Enter>", "<space>"):
            try:
                top.unbind(sequence)
            except tk.TclError:
                pass
        self.orbit.stop()
        self.on_ready(self.payload)
