"""The scan console: pick a target, pick instruments, watch results arrive.

Tk is not thread-safe, so the scan runs on a worker thread and communicates
only through a queue that the UI drains on a timer. Nothing off the main thread
touches a widget.

Every instrument gets its own hue from ``theme.module_colour``, used for its
group header in the results, its tag in the live log and its pill in the
activity strip, so you can follow one source through all three without reading
a word.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..core import report as reporting
from ..core.art import glyph
from ..core.config import KEY_ENV, Config
from ..core.engine import Engine
from ..core.models import Investigation, ScanResult, Severity, TargetType
from ..core.registry import detect_type, modules_for
from . import theme
from .orbit import OrbitCanvas

PLACEHOLDER = "domain, email, username, IP, phone or URL"
GLYPH_FONT = ("Segoe UI Symbol", 10)

PRESETS = [
    ("Domain", "example.com"),
    ("Email", "name@example.com"),
    ("Username", "octocat"),
    ("IP", "8.8.8.8"),
    ("Phone", "+14155552671"),
]

TYPE_COLOUR = {
    TargetType.DOMAIN: theme.ORCHID,
    TargetType.EMAIL: theme.OK,
    TargetType.USERNAME: theme.MAGENTA,
    TargetType.IP: theme.CYAN,
    TargetType.PHONE: "#f9a8d4",
    TargetType.URL: theme.VIOLET,
    TargetType.UNKNOWN: theme.INK_FAINT,
}


class ConsoleScreen(ttk.Frame):
    def __init__(self, master, boot: dict) -> None:
        super().__init__(master, style="Space.TFrame")
        self.config_obj: Config = boot.get("config") or Config.from_env()
        self.queue: queue.Queue = queue.Queue()
        self.investigation: Investigation | None = None
        self.scanning = False
        self.started = 0.0
        self.module_vars: dict[str, tk.BooleanVar] = {}
        self.current_type: TargetType | None = None
        self._url_by_item: dict[str, str] = {}
        self._tagged: set[str] = set()
        self._pills: dict[str, tk.Label] = {}

        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_results()
        self._build_status()
        self._on_target_change()

        self.after(90, self._drain)

    # ------------------------------------------------------------------ layout

    def _build_header(self) -> None:
        head = tk.Frame(self, bg=theme.BG)
        head.grid(row=0, column=0, columnspan=2, sticky="ew")
        head.columnconfigure(1, weight=1)

        inner = tk.Frame(head, bg=theme.BG, padx=18, pady=12)
        inner.pack(fill="x")
        inner.columnconfigure(1, weight=1)

        self.mini = OrbitCanvas(inner, width=140, height=72, star_count=24,
                                show_rings=False, speed=0.7)
        self.mini.grid(row=0, column=0, rowspan=2, padx=(0, 18))
        self.mini.start()

        row = tk.Frame(inner, bg=theme.BG)
        row.grid(row=0, column=1, sticky="ew")
        row.columnconfigure(0, weight=1)

        # A 1px frame behind the entry gives it a coloured border that follows
        # focus, which a bare tk.Entry highlight cannot do convincingly.
        self.entry_border = tk.Frame(row, bg=theme.LINE, padx=1, pady=1)
        self.entry_border.grid(row=0, column=0, sticky="ew")
        self.target = tk.StringVar()
        self.entry = tk.Entry(
            self.entry_border, textvariable=self.target, bg=theme.BG_INPUT,
            fg=theme.INK_FAINT, insertbackground=theme.MAGENTA, relief="flat",
            font=("Consolas", 15), highlightthickness=0, bd=0,
        )
        self.entry.pack(fill="x", ipady=10, ipadx=12)
        self.entry.insert(0, PLACEHOLDER)
        self.entry.bind("<FocusIn>", self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self.entry.bind("<Return>", lambda _e: self.start_scan())
        self.target.trace_add("write", lambda *_: self._on_target_change())

        self.chip = tk.Label(row, text="—", bg=theme.BG_RAISED, fg=theme.INK_FAINT,
                             font=("Consolas", 10, "bold"), padx=16, pady=11,
                             width=9)
        self.chip.grid(row=0, column=1, padx=(12, 12))

        self.scan_btn = ttk.Button(row, text="◉   SCAN", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.grid(row=0, column=2)

        # Second row: presets on the left, live activity pills on the right.
        sub = tk.Frame(inner, bg=theme.BG)
        sub.grid(row=1, column=1, sticky="ew", pady=(9, 0))
        sub.columnconfigure(1, weight=1)

        presets = tk.Frame(sub, bg=theme.BG)
        presets.grid(row=0, column=0, sticky="w")
        tk.Label(presets, text="try", bg=theme.BG, fg=theme.INK_FAINT,
                 font=("Segoe UI", 8)).pack(side="left", padx=(2, 9))
        for label, example in PRESETS:
            b = tk.Label(presets, text=label, bg=theme.BG_PANEL, fg=theme.INK_DIM,
                         font=("Segoe UI", 8), padx=11, pady=4, cursor="hand2")
            b.pack(side="left", padx=3)
            b.bind("<Button-1>", lambda _e, ex=example: self._use_example(ex))
            b.bind("<Enter>", lambda e: e.widget.configure(bg=theme.BG_HOVER,
                                                           fg=theme.ORCHID))
            b.bind("<Leave>", lambda e: e.widget.configure(bg=theme.BG_PANEL,
                                                           fg=theme.INK_DIM))

        self.activity = tk.Frame(sub, bg=theme.BG)
        self.activity.grid(row=0, column=1, sticky="e")

        theme.Rule(head, theme.LINE).pack(fill="x")

    def _build_sidebar(self) -> None:
        side = tk.Frame(self, bg=theme.BG_PANEL, padx=16, pady=16)
        side.grid(row=1, column=0, sticky="nsw")
        side.rowconfigure(2, weight=1)
        side.configure(width=236)
        side.grid_propagate(False)

        self._section(side, "INSTRUMENTS", 0)
        self.modbox = tk.Frame(side, bg=theme.BG_PANEL)
        self.modbox.grid(row=2, column=0, sticky="nsew", pady=(8, 16))

        self._section(side, "OPTIONS", 3, top=10)
        opts = tk.Frame(side, bg=theme.BG_PANEL)
        opts.grid(row=5, column=0, sticky="ew", pady=(8, 0))

        self.passive = tk.BooleanVar(value=False)
        self.verify = tk.BooleanVar(value=True)
        self.pivot = tk.BooleanVar(value=False)
        self.nsfw = tk.BooleanVar(value=False)
        for text, var, hint in (
            ("Passive only", self.passive, "never touch the target's own servers"),
            ("Verify username hits", self.verify, "kills soft-404 false positives"),
            ("Follow pivots", self.pivot, "also scan what it finds, one level deep"),
            ("Include adult sites", self.nsfw, "username results only"),
        ):
            cb = ttk.Checkbutton(opts, text=text, variable=var)
            cb.pack(anchor="w", pady=2)
            _tooltip(cb, hint)

        cap = tk.Frame(side, bg=theme.BG_PANEL)
        cap.grid(row=6, column=0, sticky="ew", pady=(14, 0))
        tk.Label(cap, text="Max sites", bg=theme.BG_PANEL, fg=theme.INK_DIM,
                 font=("Segoe UI", 9)).pack(side="left")
        self.max_sites = tk.StringVar(value="0")
        tk.Spinbox(cap, from_=0, to=500, increment=25, width=6,
                   textvariable=self.max_sites, bg=theme.BG_INPUT, fg=theme.INK,
                   buttonbackground=theme.BG_RAISED, relief="flat", bd=0,
                   highlightthickness=1, highlightbackground=theme.LINE,
                   insertbackground=theme.MAGENTA,
                   font=("Consolas", 9)).pack(side="right")
        tk.Label(side, text="0 = no cap · lower it for a quick pass",
                 bg=theme.BG_PANEL, fg=theme.INK_FAINT, font=("Segoe UI", 8),
                 wraplength=200, justify="left").grid(row=7, column=0, sticky="w",
                                                      pady=(5, 0))

        self._section(side, "API KEYS", 8, top=14)
        keys = self.config_obj.available_keys
        tk.Label(
            side,
            text=", ".join(keys) if keys
            else "none set — key-free modules still run.\n\nExport "
                 + ", ".join(sorted(KEY_ENV.values())[:2]) + " …\nbefore launching to add more.",
            bg=theme.BG_PANEL, fg=theme.OK if keys else theme.INK_FAINT,
            font=("Segoe UI", 8), wraplength=200, justify="left",
        ).grid(row=10, column=0, sticky="w", pady=(6, 0))

        theme.Rule(self, theme.LINE).place(in_=side, relx=1.0, rely=0, relheight=1.0,
                                           width=1, anchor="ne")

    def _section(self, parent, text: str, row: int, top: int = 0) -> None:
        holder = tk.Frame(parent, bg=theme.BG_PANEL)
        holder.grid(row=row, column=0, sticky="ew", pady=(top, 0))
        tk.Label(holder, text=text, bg=theme.BG_PANEL, fg=theme.ORCHID,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        rule = theme.Rule(holder, theme.LINE_SOFT)
        rule.pack(side="left", fill="x", expand=True, padx=(10, 0), pady=(7, 0))

    def _build_results(self) -> None:
        wrap = tk.Frame(self, bg=theme.BG, padx=14, pady=12)
        wrap.grid(row=1, column=1, sticky="nsew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        nb = ttk.Notebook(wrap)
        nb.grid(row=0, column=0, sticky="nsew")
        self.notebook = nb

        # --- findings
        findings = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(findings, text="  Findings  ")
        findings.rowconfigure(0, weight=1)
        findings.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(findings, columns=("value", "src"),
                                 show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="  FIELD", anchor="w")
        self.tree.heading("value", text="VALUE", anchor="w")
        self.tree.heading("src", text="SOURCE", anchor="w")
        self.tree.column("#0", width=300, minwidth=170, stretch=False)
        self.tree.column("value", width=580, minwidth=200)
        self.tree.column("src", width=130, minwidth=80, stretch=False)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.tag_configure("high", foreground=theme.HIGH)
        self.tree.tag_configure("notable", foreground=theme.NOTABLE)
        self.tree.tag_configure("info", foreground=theme.INK)
        self.tree.tag_configure("error", foreground=theme.NOTABLE)
        self.tree.bind("<Double-1>", self._open_link)
        self.tree.bind("<Return>", self._open_link)

        sb = ttk.Scrollbar(findings, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)

        self.empty = tk.Label(
            findings, bg=theme.BG_PANEL, fg=theme.INK_FAINT, justify="center",
            font=("Segoe UI", 10),
            text="nothing scanned yet\n\nenter a target above and press SCAN",
        )
        self.empty.place(relx=0.5, rely=0.45, anchor="center")

        # --- pivots
        pivots = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(pivots, text="  Pivots  ")
        pivots.rowconfigure(0, weight=1)
        pivots.columnconfigure(0, weight=1)
        self.pivot_tree = ttk.Treeview(pivots, columns=("type", "why"),
                                       show="tree headings", selectmode="browse")
        self.pivot_tree.heading("#0", text="  TARGET", anchor="w")
        self.pivot_tree.heading("type", text="TYPE", anchor="w")
        self.pivot_tree.heading("why", text="FOUND BY", anchor="w")
        self.pivot_tree.column("#0", width=320, stretch=False)
        self.pivot_tree.column("type", width=100, stretch=False)
        self.pivot_tree.grid(row=0, column=0, sticky="nsew")
        for ttype, colour in TYPE_COLOUR.items():
            self.pivot_tree.tag_configure(ttype.value, foreground=colour)
        # Double-clicking a pivot loads it as the next target: the whole point
        # of surfacing them.
        self.pivot_tree.bind("<Double-1>", self._scan_pivot)
        tk.Label(pivots, text="  double-click a row to make it the next target",
                 bg=theme.BG_PANEL, fg=theme.INK_FAINT,
                 font=("Segoe UI", 8)).grid(row=1, column=0, sticky="w", pady=6)

        # --- live log
        logs = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(logs, text="  Live log  ")
        logs.rowconfigure(0, weight=1)
        logs.columnconfigure(0, weight=1)
        self.logbox = tk.Text(logs, bg=theme.BG_PANEL, fg=theme.INK_DIM,
                              relief="flat", highlightthickness=0, bd=0,
                              font=("Consolas", 9), wrap="none",
                              padx=14, pady=12, spacing1=1, cursor="arrow")
        self.logbox.grid(row=0, column=0, sticky="nsew")
        logsb = ttk.Scrollbar(logs, orient="vertical", command=self.logbox.yview)
        logsb.grid(row=0, column=1, sticky="ns")
        self.logbox.configure(yscrollcommand=logsb.set)
        for name, colour in (("time", theme.INK_FAINT), ("ok", theme.OK),
                             ("warn", theme.NOTABLE), ("fail", theme.HIGH),
                             ("run", theme.ORCHID), ("plain", theme.INK_DIM),
                             ("bright", theme.INK), ("count", theme.CYAN)):
            self.logbox.tag_configure(name, foreground=colour)
        self.logbox.configure(state="disabled")

    def _build_status(self) -> None:
        theme.Rule(self, theme.LINE).grid(row=2, column=0, columnspan=2, sticky="ew")
        bar = tk.Frame(self, bg=theme.BG_PANEL, padx=16, pady=10)
        bar.grid(row=3, column=0, columnspan=2, sticky="ew")
        bar.columnconfigure(1, weight=1)

        self.status = tk.Label(bar, text="ready", bg=theme.BG_PANEL,
                               fg=theme.INK_DIM, font=("Consolas", 9))
        self.status.grid(row=0, column=0, sticky="w")

        self.bar = ttk.Progressbar(bar, style="Nova.Horizontal.TProgressbar",
                                   mode="determinate", length=280)
        self.bar.grid(row=0, column=1, sticky="e", padx=16)

        btns = tk.Frame(bar, bg=theme.BG_PANEL)
        btns.grid(row=0, column=2, sticky="e")
        tk.Label(btns, text="export", bg=theme.BG_PANEL, fg=theme.INK_FAINT,
                 font=("Segoe UI", 8)).pack(side="left", padx=(0, 8))
        self.export_btns = []
        for label, fmt in (("HTML", "html"), ("JSON", "json"),
                           ("CSV", "csv"), ("MD", "markdown")):
            b = ttk.Button(btns, text=label, width=6,
                           command=lambda f=fmt: self._export(f), state="disabled")
            b.pack(side="left", padx=2)
            self.export_btns.append(b)

    # ------------------------------------------------------------------ target

    def _focus_in(self, _e=None) -> None:
        self.entry_border.configure(bg=theme.PURPLE)
        if self.entry.get() == PLACEHOLDER:
            self.entry.delete(0, "end")
            self.entry.configure(fg=theme.INK)

    def _focus_out(self, _e=None) -> None:
        self.entry_border.configure(bg=theme.LINE)
        if not self.entry.get().strip():
            self.entry.insert(0, PLACEHOLDER)
            self.entry.configure(fg=theme.INK_FAINT)

    def _use_example(self, example: str) -> None:
        self.entry.configure(fg=theme.INK)
        self.entry.delete(0, "end")
        self.entry.insert(0, example)
        self.entry.focus_set()

    def _value(self) -> str:
        raw = self.entry.get().strip()
        return "" if raw == PLACEHOLDER else raw

    def _on_target_change(self) -> None:
        value = self._value()
        ttype = detect_type(value) if value else TargetType.UNKNOWN
        colour = TYPE_COLOUR[ttype]
        self.chip.configure(
            text=ttype.value if ttype != TargetType.UNKNOWN else "—",
            fg=colour,
            bg=theme.blend(colour, theme.BG, 0.88) if ttype != TargetType.UNKNOWN
            else theme.BG_RAISED,
        )
        if ttype != self.current_type:
            self.current_type = ttype
            self._rebuild_modules(ttype)
        self.scan_btn.configure(
            state="disabled" if (self.scanning or ttype == TargetType.UNKNOWN)
            else "normal")

    def _rebuild_modules(self, ttype: TargetType) -> None:
        for child in self.modbox.winfo_children():
            child.destroy()
        self.module_vars.clear()
        if ttype == TargetType.UNKNOWN:
            tk.Label(self.modbox, bg=theme.BG_PANEL, fg=theme.INK_FAINT,
                     font=("Segoe UI", 8), justify="left", wraplength=200,
                     text="type a target above and the matching instruments "
                          "appear here").pack(anchor="w")
            return
        for cls in modules_for(ttype):
            probe = cls(None, self.config_obj)  # type: ignore[arg-type]
            reason = probe.skip_reason()
            var = tk.BooleanVar(value=reason is None)
            self.module_vars[cls.name] = var

            line = tk.Frame(self.modbox, bg=theme.BG_PANEL)
            line.pack(fill="x", pady=1)
            cb = ttk.Checkbutton(line, text="", variable=var, width=0,
                                 state="disabled" if reason else "normal")
            cb.pack(side="left")
            colour = theme.module_colour(cls.name) if not reason else theme.INK_FAINT
            tk.Label(line, text=glyph(cls.name), bg=theme.BG_PANEL, fg=colour,
                     font=GLYPH_FONT, width=2).pack(side="left", padx=(2, 4))
            tk.Label(line, text=cls.name, bg=theme.BG_PANEL,
                     fg=theme.INK if not reason else theme.INK_FAINT,
                     font=("Consolas", 9)).pack(side="left")
            hint = f"{cls.description}\n\n({reason})" if reason else cls.description
            for w in (cb, line, *line.winfo_children()):
                _tooltip(w, hint)

    # -------------------------------------------------------------------- scan

    def start_scan(self) -> None:
        target = self._value()
        if self.scanning or not target:
            return
        ttype = detect_type(target)
        if ttype == TargetType.UNKNOWN:
            messagebox.showwarning("NOVA", f"Cannot work out what '{target}' is.")
            return
        chosen = [n for n, v in self.module_vars.items() if v.get()]
        if not chosen:
            messagebox.showwarning("NOVA", "Select at least one instrument.")
            return

        self.scanning = True
        self.started = time.monotonic()
        self.scan_btn.configure(state="disabled", text="◌   SCANNING")
        for b in self.export_btns:
            b.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.pivot_tree.delete(*self.pivot_tree.get_children())
        self._url_by_item.clear()
        self.empty.place_forget()
        self._clear_pills()
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")
        self.bar.configure(maximum=len(chosen), value=0)

        self._log_raw("  ", ("plain",))
        self._log_raw(f"{target}", ("bright",))
        self._log_raw("  ·  ", ("plain",))
        self._log_raw(f"{ttype.value}", ("run",))
        self._log_raw(f"  ·  {len(chosen)} instruments\n\n", ("plain",))

        cfg = Config.from_env(
            passive_only=self.passive.get(),
            max_sites=int(self.max_sites.get() or 0),
        )
        cfg._verify_hits = self.verify.get()        # type: ignore[attr-defined]
        cfg._include_nsfw = self.nsfw.get()         # type: ignore[attr-defined]
        cfg._refresh_sites = False                  # type: ignore[attr-defined]

        threading.Thread(
            target=self._run, args=(target, ttype, chosen, cfg), daemon=True
        ).start()

    def _run(self, target: str, ttype: TargetType, chosen: list[str],
             cfg: Config) -> None:
        try:
            with Engine(cfg, progress=lambda m, s: self.queue.put(("prog", m, s))) as e:
                inv = e.scan(target, only=chosen, target_type=ttype,
                             on_result=lambda r: self.queue.put(("result", r)))
                if self.pivot.get():
                    self.queue.put(("prog", "pivots", "start"))
                    for extra in e.follow_pivots(inv, limit=4):
                        inv.results.extend(extra.results)
                    self.queue.put(("prog", "pivots", "done"))
                self.queue.put(("done", inv))
        except Exception as exc:
            self.queue.put(("fail", f"{type(exc).__name__}: {exc}"))

    # ------------------------------------------------------------------- pills

    def _pill(self, module: str) -> None:
        if module in self._pills:
            return
        colour = theme.module_colour(module)
        lab = tk.Label(self.activity, text=f"{glyph(module)} {module}",
                       bg=theme.blend(colour, theme.BG, 0.86), fg=colour,
                       font=("Segoe UI Symbol", 8), padx=8, pady=3)
        lab.pack(side="left", padx=3)
        self._pills[module] = lab

    def _unpill(self, module: str) -> None:
        lab = self._pills.pop(module, None)
        if lab is not None:
            lab.destroy()

    def _clear_pills(self) -> None:
        for lab in self._pills.values():
            lab.destroy()
        self._pills.clear()

    # ------------------------------------------------------------------ drain

    def _drain(self) -> None:
        try:
            while True:
                item = self.queue.get_nowait()
                kind = item[0]
                if kind == "prog":
                    _, module, state = item
                    if state == "start":
                        self._pill(module)
                        self.status.configure(text=f"running  {module} …")
                        self._log_event(module, "run", "running")
                    else:
                        self._unpill(module)
                        self.bar["value"] = self.bar["value"] + 1
                elif kind == "result":
                    self._add_result(item[1])
                elif kind == "done":
                    self._finish(item[1])
                elif kind == "fail":
                    self._log_event("scan", "fail", item[1])
                    self._reset()
        except queue.Empty:
            pass
        self.after(90, self._drain)

    def _module_tag(self, module: str) -> str:
        tag = f"mod:{module}"
        if tag not in self._tagged:
            colour = theme.module_colour(module)
            self.tree.tag_configure(tag, foreground=colour)
            self.logbox.tag_configure(tag, foreground=colour)
            self._tagged.add(tag)
        return tag

    def _add_result(self, res: ScanResult) -> None:
        tag = self._module_tag(res.module)
        if res.findings or res.errors:
            node = self.tree.insert(
                "", "end",
                text=f" {glyph(res.module)}  {res.module}",
                values=(f"{len(res.findings)} finding(s)", f"{res.duration:.1f}s"),
                open=True, tags=(tag,),
            )
            for f in res.findings:
                value = f.value
                if isinstance(value, (list, tuple, set)):
                    items = list(value)
                    value = ", ".join(str(i) for i in items[:8])
                    if len(items) > 8:
                        value += f"   (+{len(items) - 8} more)"
                item = self.tree.insert(node, "end", text=f"    {f.label}",
                                        values=(str(value), f.source),
                                        tags=(f.severity.value,))
                if f.url:
                    self._url_by_item[item] = f.url
            for err in res.errors:
                self.tree.insert(node, "end", text="    warning",
                                 values=(err, res.module), tags=("error",))

        high = len([f for f in res.findings if f.severity == Severity.HIGH])
        detail = f"{len(res.findings)} findings"
        if high:
            detail += f", {high} high"
        self._log_event(res.module, "warn" if res.errors else "ok", detail,
                        secs=res.duration)
        for err in res.errors:
            self._log_event(res.module, "warn", err, indent=True)

    def _finish(self, inv: Investigation) -> None:
        self.investigation = inv
        for p in inv.pivots:
            self.pivot_tree.insert("", "end", text=f"  {p.target}",
                                   values=(p.target_type.value, p.reason),
                                   tags=(p.target_type.value,))
        high = len([f for f in inv.findings if f.severity == Severity.HIGH])
        elapsed = time.monotonic() - self.started
        self.status.configure(
            text=f"done   {len(inv.findings)} findings · {high} high · "
                 f"{len(inv.pivots)} pivots · {elapsed:.1f}s")
        self._log_raw("\n  ")
        self._log_raw("complete", ("ok",))
        self._log_raw("  ")
        self._log_raw(f"{len(inv.findings)}", ("count",))
        self._log_raw(" findings  ", ("plain",))
        self._log_raw(f"{high}", ("fail" if high else "count",))
        self._log_raw(" high interest  ", ("plain",))
        self._log_raw(f"{elapsed:.1f}s\n", ("time",))
        self._clear_pills()
        if not inv.findings:
            self.empty.configure(text="no findings\n\nnothing public turned up "
                                      "for this target")
            self.empty.place(relx=0.5, rely=0.45, anchor="center")
        for b in self.export_btns:
            b.configure(state="normal")
        self._reset()

    def _reset(self) -> None:
        self.scanning = False
        self.scan_btn.configure(text="◉   SCAN")
        self._on_target_change()

    # --------------------------------------------------------------------- log

    def _log_event(self, module: str, status: str, message: str,
                   secs: float | None = None, indent: bool = False) -> None:
        """One colour-coded line: time, module tag in its own hue, then detail."""
        mark = {"ok": "✓", "warn": "!", "fail": "✕", "run": "▸"}.get(status, "·")
        self._log_raw(f"  {time.monotonic() - self.started:6.1f}s ", ("time",))
        self._log_raw(f"{mark} ", (status,))
        if indent:
            self._log_raw(f"{'':<14}", ("plain",))
        else:
            self._log_raw(f"{module:<14}", (self._module_tag(module),))
        self._log_raw(message, ("plain" if status != "fail" else "fail",))
        if secs is not None:
            self._log_raw(f"   {secs:.1f}s", ("time",))
        self._log_raw("\n")

    def _log_raw(self, text: str, tags: tuple[str, ...] = ()) -> None:
        self.logbox.configure(state="normal")
        self.logbox.insert("end", text, tags)
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    # ----------------------------------------------------------------- actions

    def _open_link(self, _e=None) -> None:
        sel = self.tree.focus()
        url = self._url_by_item.get(sel)
        if not url:
            values = self.tree.item(sel, "values")
            if values and str(values[0]).startswith(("http://", "https://")):
                url = str(values[0])
        if url:
            webbrowser.open(url)

    def _scan_pivot(self, _e=None) -> None:
        sel = self.pivot_tree.focus()
        if not sel:
            return
        target = self.pivot_tree.item(sel, "text").strip()
        if target:
            self._use_example(target)
            self.notebook.select(0)
            self.start_scan()

    def _export(self, fmt: str) -> None:
        if not self.investigation:
            return
        ext = {"html": ".html", "json": ".json", "csv": ".csv", "markdown": ".md"}[fmt]
        safe = "".join(c if c.isalnum() or c in "-._" else "_"
                       for c in self.investigation.target)
        path = filedialog.asksaveasfilename(
            title="Save report", defaultextension=ext,
            initialfile=f"nova-{safe}{ext}",
            filetypes=[(fmt.upper(), f"*{ext}"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            written = reporting.write(self.investigation, Path(path), fmt)
        except Exception as e:
            messagebox.showerror("NOVA", f"Could not write the report:\n{e}")
            return
        self._log_event("export", "ok", f"wrote {written}")
        if fmt == "html" and messagebox.askyesno("NOVA", "Open the report now?"):
            webbrowser.open(written.as_uri())


def _tooltip(widget, text: str) -> None:
    """Minimal hover tip. ttk has none and the instrument list needs one."""
    tip: dict[str, tk.Toplevel | None] = {"win": None}

    def show(_e=None):
        if tip["win"] or not text:
            return
        x = widget.winfo_rootx() + widget.winfo_width() + 14
        y = widget.winfo_rooty() - 4
        win = tk.Toplevel(widget)
        win.wm_overrideredirect(True)
        win.wm_geometry(f"+{x}+{y}")
        frame = tk.Frame(win, bg=theme.PLUM, padx=1, pady=1)
        frame.pack()
        tk.Label(frame, text=text, bg=theme.BG_RAISED, fg=theme.INK,
                 font=("Segoe UI", 8), justify="left", padx=10, pady=7,
                 wraplength=290).pack()
        tip["win"] = win

    def hide(_e=None):
        if tip["win"] is not None:
            tip["win"].destroy()
            tip["win"] = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")
