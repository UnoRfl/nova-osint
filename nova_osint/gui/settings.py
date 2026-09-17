"""The settings window: keys, network behaviour and which instruments run.

Everything here writes to the same ``config.json`` the CLI reads, through the
same :class:`~nova_osint.core.config.ConfigManager`, so the GUI and the command
line can never drift apart.

Two rules the UI enforces, both about not lying to you:

* **A stored key is never rendered.** A field with a value shows dots that are
  not the key - they are a placeholder. Leave it alone and the stored value is
  kept; type in it and the new value replaces it. Nothing can screenshot a
  secret out of this window.
* **An environment variable wins, and the row says so.** If ``GITHUB_TOKEN`` is
  exported, that field is disabled with the reason on it, because typing a
  different key into the file would silently do nothing.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
import webbrowser
from collections.abc import Callable
from tkinter import messagebox, ttk

from ..core.config import KEY_ENV, ConfigManager, key_info
from ..core.registry import all_modules
from . import theme

#: What a key field shows when a value is already stored. Never a real key.
MASK = "•" * 14

#: Network settings: (config path, label, hint, kind).
NETWORK_FIELDS = (
    ("settings.timeout", "Timeout", "seconds to wait for one request", "float"),
    ("settings.max_concurrent_tasks", "Concurrency", "parallel requests (1-128)", "int"),
    ("settings.request_delay_min", "Delay min", "seconds between hits on one host", "float"),
    ("settings.request_delay_max", "Delay max", "upper end of that range", "float"),
    ("settings.max_retries", "Retries", "on 429, 503 and timeouts", "int"),
    ("settings.cache_ttl", "Cache lifetime", "seconds a cached response stays fresh", "float"),
    ("settings.max_sites", "Max sites", "cap on username sites (0 = no cap)", "int"),
    ("settings.user_agent", "User-Agent", "blank = NOVA-OSINT/<version>", "str"),
    ("settings.output_directory", "Output folder", "where reports are written", "str"),
)

TOGGLES = (
    ("settings.cache_enabled", "Cache responses on disk",
     "re-running a scan will not re-hit the same source"),
    ("settings.verify_tls", "Verify TLS certificates",
     "turn this off only for a host you know has a broken cert"),
    ("settings.passive_only", "Passive by default",
     "never send a packet to the target's own infrastructure"),
)


class _Scroller(tk.Frame):
    """A scrollable column. Tk has no such widget, so: canvas plus inner frame."""

    def __init__(self, master, **kw) -> None:
        super().__init__(master, bg=theme.BG, **kw)
        self.canvas = tk.Canvas(self, bg=theme.BG, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")

        self.body = tk.Frame(self.canvas, bg=theme.BG)
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._resize)
        self.canvas.bind("<Configure>", self._stretch)
        # Wheel binding is per-widget on Windows, so bind on enter/leave rather
        # than globally - otherwise the window steals every other wheel event.
        self.canvas.bind("<Enter>", lambda _e: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.canvas.bind("<Leave>", lambda _e: self.canvas.unbind_all("<MouseWheel>"))

    def _resize(self, _e=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _stretch(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)

    def _wheel(self, event) -> None:
        self.canvas.yview_scroll(-int(event.delta / 120), "units")

    def to_top(self) -> None:
        """Scroll back to the first row once the tab is populated."""
        self.update_idletasks()
        self._resize()
        self.canvas.yview_moveto(0.0)


class SettingsWindow(tk.Toplevel):
    """Modal settings editor backed by ``config.json``."""

    def __init__(self, master, on_saved: Callable[[], None] | None = None) -> None:
        super().__init__(master)
        self.on_saved = on_saved
        self.manager = ConfigManager().load()
        self.title("NOVA  ·  Settings")
        self.configure(bg=theme.BG)
        self.geometry("760x620")
        self.minsize(640, 480)
        self.transient(master)

        self.key_entries: dict[str, tk.Entry] = {}
        self.key_dirty: dict[str, bool] = {}
        self.field_vars: dict[str, tk.StringVar] = {}
        self.toggle_vars: dict[str, tk.BooleanVar] = {}
        self.module_vars: dict[str, tk.BooleanVar] = {}

        self._build()
        # Map the window before grabbing. A grab on an unmapped window raises
        # on Windows, and a transient whose owner is withdrawn (which is how
        # the tests build it) never maps at all - so neither is allowed to be
        # the thing that kills the dialog.
        self.update_idletasks()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.focus_set()
        self.bind("<Escape>", lambda _e: self.destroy())

    # ------------------------------------------------------------------ layout

    def _build(self) -> None:
        head = tk.Frame(self, bg=theme.BG, padx=20, pady=16)
        head.pack(fill="x")
        tk.Label(head, text="Settings", bg=theme.BG, fg=theme.INK,
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(head, text="Saved to config.json. The command line reads the same file.",
                 bg=theme.BG, fg=theme.INK_FAINT, font=("Segoe UI", 9)).pack(anchor="w")
        theme.Rule(self, theme.LINE).pack(fill="x")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=12)
        self._keys_tab(nb)
        self._network_tab(nb)
        self._instruments_tab(nb)

        theme.Rule(self, theme.LINE).pack(fill="x")
        foot = tk.Frame(self, bg=theme.BG_PANEL, padx=18, pady=12)
        foot.pack(fill="x")

        # Buttons are packed FIRST. A long config path is wider than the window,
        # so a left-packed label claims every pixel and squeezes anything packed
        # after it to 1x1 - which is exactly how Save ended up invisible.
        ttk.Button(foot, text="Save", style="Accent.TButton",
                   command=self._save).pack(side="right", padx=(8, 0))
        ttk.Button(foot, text="Cancel", command=self.destroy).pack(side="right")

        path = tk.Label(foot, text=_shorten(str(self.manager.path)), bg=theme.BG_PANEL,
                        fg=theme.INK_FAINT, font=("Consolas", 8), cursor="hand2",
                        anchor="w")
        path.pack(side="left", fill="x", expand=True)
        path.bind("<Button-1>", lambda _e: self._reveal())
        _hover(path, theme.INK_FAINT, theme.ORCHID)

    # ------------------------------------------------------------------- keys

    def _keys_tab(self, nb: ttk.Notebook) -> None:
        scroller = _Scroller(nb)
        nb.add(scroller, text="  API keys  ")
        body = scroller.body

        tk.Label(
            body,
            text="Every module works without a key; keys raise limits or unlock a source.\n"
                 "An environment variable always overrides what is saved here.",
            bg=theme.BG, fg=theme.INK_DIM, font=("Segoe UI", 9),
            justify="left", padx=18, pady=14,
        ).pack(anchor="w")

        stored = self.manager.get("api_keys", {})
        stored = stored if isinstance(stored, dict) else {}

        # Keys that actually do something first; the dead ones last, labelled.
        names = sorted(KEY_ENV, key=lambda n: (not key_info(n)["modules"], n))
        for name in names:
            self._key_row(body, name, bool(str(stored.get(name, "")).strip()))
        scroller.to_top()

    def _key_row(self, parent: tk.Frame, name: str, has_stored: bool) -> None:
        info = key_info(name)
        env_name = KEY_ENV[name]
        from_env = bool(os.environ.get(env_name, "").strip())
        unused = not info["modules"]

        card = tk.Frame(parent, bg=theme.BG_PANEL if not unused else theme.BG,
                        padx=16, pady=12,
                        highlightthickness=1,
                        highlightbackground=theme.LINE_SOFT)
        card.pack(fill="x", padx=18, pady=5)

        top = tk.Frame(card, bg=card["bg"])
        top.pack(fill="x")
        tk.Label(top, text=info["label"], bg=card["bg"],
                 fg=theme.INK_FAINT if unused else theme.INK,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(top, text=f"  {env_name}", bg=card["bg"], fg=theme.INK_FAINT,
                 font=("Consolas", 8)).pack(side="left")
        tk.Label(top, text=info["cost"], bg=card["bg"],
                 fg=theme.OK if "free" in info["cost"] else theme.NOTABLE,
                 font=("Segoe UI", 8)).pack(side="right")

        tk.Label(card, text=info["unlocks"], bg=card["bg"],
                 fg=theme.INK_FAINT if unused else theme.INK_DIM,
                 font=("Segoe UI", 8), wraplength=620, justify="left").pack(
            anchor="w", pady=(3, 8))

        row = tk.Frame(card, bg=card["bg"])
        row.pack(fill="x")
        entry = tk.Entry(row, bg=theme.BG_INPUT, fg=theme.INK, relief="flat",
                         font=("Consolas", 10), show="•", bd=0,
                         highlightthickness=1, highlightbackground=theme.LINE,
                         insertbackground=theme.MAGENTA,
                         disabledbackground=theme.BG_PANEL,
                         disabledforeground=theme.INK_FAINT)
        entry.pack(side="left", fill="x", expand=True, ipady=6, ipadx=8)
        if has_stored:
            entry.insert(0, MASK)
        self.key_entries[name] = entry
        self.key_dirty[name] = False
        # Any real keystroke means the field now holds a new value, not the mask.
        entry.bind("<Key>", lambda _e, n=name: self._touch(n))

        if from_env:
            entry.delete(0, "end")
            entry.configure(show="", state="disabled")
            entry.insert(0, "set in the environment")

        ttk.Button(row, text="Clear", width=6,
                   command=lambda n=name: self._clear(n)).pack(side="left", padx=(8, 0))
        if info["url"]:
            ttk.Button(row, text="Get a key", width=10,
                       command=lambda u=info["url"]: webbrowser.open(u)).pack(
                side="left", padx=(6, 0))

        if from_env:
            note, colour = f"{env_name} is exported - that value wins over this file", theme.CYAN
        elif unused:
            note, colour = "no module reads this key yet - setting it does nothing", theme.INK_FAINT
        else:
            note, colour = ("used by: " + ", ".join(info["modules"])
                            + ("  (module is skipped without it)" if info["required"] else ""),
                            theme.INK_FAINT)
        tk.Label(card, text=note, bg=card["bg"], fg=colour,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(7, 0))

    def _touch(self, name: str) -> None:
        if not self.key_dirty[name]:
            self.key_dirty[name] = True
            entry = self.key_entries[name]
            if entry.get() == MASK:
                entry.delete(0, "end")

    def _clear(self, name: str) -> None:
        entry = self.key_entries[name]
        if str(entry["state"]) == "disabled":
            messagebox.showinfo(
                "NOVA",
                f"{KEY_ENV[name]} is set in your environment.\n\n"
                "Clear it there instead - a value in the file cannot override it.",
                parent=self,
            )
            return
        entry.delete(0, "end")
        self.key_dirty[name] = True

    # ---------------------------------------------------------------- network

    def _network_tab(self, nb: ttk.Notebook) -> None:
        scroller = _Scroller(nb)
        nb.add(scroller, text="  Network  ")
        body = scroller.body

        grid = tk.Frame(body, bg=theme.BG, padx=20, pady=18)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)

        for row, (path, label, hint, _kind) in enumerate(NETWORK_FIELDS):
            tk.Label(grid, text=label, bg=theme.BG, fg=theme.INK,
                     font=("Segoe UI", 9)).grid(row=row * 2, column=0, sticky="w",
                                                pady=(8, 0))
            var = tk.StringVar(value=str(self.manager.get(path, "")))
            self.field_vars[path] = var
            tk.Entry(grid, textvariable=var, bg=theme.BG_INPUT, fg=theme.INK,
                     relief="flat", font=("Consolas", 10), bd=0, highlightthickness=1,
                     highlightbackground=theme.LINE, insertbackground=theme.MAGENTA
                     ).grid(row=row * 2, column=1, sticky="ew", padx=(16, 0),
                            ipady=5, ipadx=8, pady=(8, 0))
            tk.Label(grid, text=hint, bg=theme.BG, fg=theme.INK_FAINT,
                     font=("Segoe UI", 8)).grid(row=row * 2 + 1, column=1, sticky="w",
                                                padx=(16, 0))

        theme.Rule(body, theme.LINE_SOFT).pack(fill="x", padx=20, pady=(14, 0))
        box = tk.Frame(body, bg=theme.BG, padx=20, pady=14)
        box.pack(fill="x")
        for path, label, hint in TOGGLES:
            var = tk.BooleanVar(value=bool(self.manager.get(path, True)))
            self.toggle_vars[path] = var
            ttk.Checkbutton(box, text=label, variable=var).pack(anchor="w", pady=(6, 0))
            tk.Label(box, text=hint, bg=theme.BG, fg=theme.INK_FAINT,
                     font=("Segoe UI", 8)).pack(anchor="w", padx=(22, 0))

        tk.Label(body, text="Out-of-range values are clamped on load, not rejected - "
                            "a bad number here can never stop a scan.",
                 bg=theme.BG, fg=theme.INK_FAINT, font=("Segoe UI", 8),
                 wraplength=620, justify="left").pack(anchor="w", padx=20, pady=(4, 18))

    # ------------------------------------------------------------ instruments

    def _instruments_tab(self, nb: ttk.Notebook) -> None:
        scroller = _Scroller(nb)
        nb.add(scroller, text="  Instruments  ")
        body = scroller.body

        tk.Label(body, text="Unticked instruments never run, on the CLI or here.",
                 bg=theme.BG, fg=theme.INK_DIM, font=("Segoe UI", 9),
                 padx=20, pady=14).pack(anchor="w")

        grid = tk.Frame(body, bg=theme.BG, padx=20)
        grid.pack(fill="x")
        for cls in all_modules():
            var = tk.BooleanVar(value=self.manager.module_enabled(cls.name))
            self.module_vars[cls.name] = var
            line = tk.Frame(grid, bg=theme.BG)
            line.pack(fill="x", pady=2)
            ttk.Checkbutton(line, text="", variable=var).pack(side="left")
            tk.Label(line, text=cls.name, bg=theme.BG,
                     fg=theme.module_colour(cls.name), font=("Consolas", 9, "bold"),
                     width=16, anchor="w").pack(side="left")
            tk.Label(line, text=cls.description, bg=theme.BG, fg=theme.INK_FAINT,
                     font=("Segoe UI", 8), anchor="w").pack(side="left", fill="x",
                                                            expand=True)

        theme.Rule(body, theme.LINE_SOFT).pack(fill="x", padx=20, pady=(16, 0))
        opts = tk.Frame(body, bg=theme.BG, padx=20, pady=14)
        opts.pack(fill="x")
        tk.Label(opts, text="SecurityTrails depth", bg=theme.BG, fg=theme.INK,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.st_depth = tk.StringVar(
            value=str(self.manager.get("module_options.securitytrails_depth", "basic"))
        )
        ttk.Combobox(opts, textvariable=self.st_depth, values=["basic", "full"],
                     state="readonly", width=12).pack(anchor="w", pady=(5, 0))
        tk.Label(opts, text="basic = 1 query per scan.  full = 3 (adds the subdomain list "
                            "and historical WHOIS).\nQueries are metered per month on every "
                            "SecurityTrails plan, so basic is the safe default.",
                 bg=theme.BG, fg=theme.INK_FAINT, font=("Segoe UI", 8),
                 justify="left").pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------------------- save

    def _save(self) -> None:
        problems: list[str] = []

        for path, label, _hint, kind in NETWORK_FIELDS:
            raw = self.field_vars[path].get().strip()
            if kind == "str":
                self.manager.set(path, raw)
                continue
            if not raw:
                continue
            try:
                self.manager.set(path, int(raw) if kind == "int" else float(raw))
            except ValueError:
                problems.append(f"{label}: '{raw}' is not a number")

        for path, var in self.toggle_vars.items():
            self.manager.set(path, bool(var.get()))

        # Only the keys the user actually typed into are touched; the rest keep
        # whatever is already on disk, which is how the mask stays honest.
        keys = dict(self.manager.get("api_keys", {}) or {})
        for name, entry in self.key_entries.items():
            if not self.key_dirty.get(name):
                continue
            keys[name] = entry.get().strip()
        self.manager.set("api_keys", keys)

        self.manager.set("modules_enabled",
                         {name: bool(var.get()) for name, var in self.module_vars.items()})
        self.manager.set("module_options.securitytrails_depth", self.st_depth.get())

        if problems:
            messagebox.showwarning(
                "NOVA", "Not saved:\n\n" + "\n".join(problems), parent=self)
            return
        if not self.manager.save():
            messagebox.showerror(
                "NOVA",
                "Could not write the configuration file:\n\n"
                + "\n".join(self.manager.problems),
                parent=self,
            )
            return

        if self.on_saved is not None:
            self.on_saved()
        self.destroy()

    def _reveal(self) -> None:
        """Open the folder holding config.json, or fall back to showing the path."""
        folder = self.manager.path.parent
        try:
            if sys.platform == "win32":
                os.startfile(folder)  # noqa: S606 - a user-initiated folder open
            else:
                webbrowser.open(folder.as_uri())
        except OSError:
            messagebox.showinfo("NOVA", str(self.manager.path), parent=self)


def _hover(widget: tk.Widget, normal: str, active: str) -> None:
    widget.bind("<Enter>", lambda _e: widget.configure(fg=active))
    widget.bind("<Leave>", lambda _e: widget.configure(fg=normal))


def _shorten(path: str, limit: int = 64) -> str:
    """Keep a long path from dominating the footer. Clicking it still works."""
    return path if len(path) <= limit else "..." + path[-(limit - 3):]
