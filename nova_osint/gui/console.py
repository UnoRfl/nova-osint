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
from ..core.config import Config, runtime_config
from ..core.engine import Engine
from ..core.models import Investigation, ScanResult, Severity, TargetType
from ..core.registry import detect_type, modules_for
from . import orbit, theme
from .settings import SettingsWindow

PLACEHOLDER = "domain, email, username, IP, phone or URL"
GLYPH_FONT = ("Segoe UI Symbol", 10)

PRESETS = [
    ("Domain", "example.com"),
    ("Email", "name@example.com"),
    ("Username", "octocat"),
    ("IP", "8.8.8.8"),
    ("Phone", "+14155552671"),
]

#: ``(what the menu says, the key the brief parser wants)``. Ordered by how
#: often you actually know the thing, not alphabetically - the point is that
#: the first two entries cover most of what a user has in hand.
BRIEF_KINDS = [
    ("full name", "name"),
    ("city", "city"),
    ("employer", "employer"),
    ("email", "email"),
    ("handle", "handle"),
    ("phone", "phone"),
    ("job title", "role"),
    ("born", "born"),
    ("country", "country"),
    ("school", "school"),
    ("website", "domain"),
    ("profile URL", "url"),
    ("language", "language"),
    ("keyword", "keyword"),
]

#: What the typed target amounts to as a claim.
def _brief_kinds_for_types() -> dict[TargetType, str]:
    """Which claim kind describes a target of each type.

    Derived by inverting ``brief.SEEDABLE`` rather than written out again.
    The hand-written version had ``USERNAME: "handle"`` and there is no
    ``handle`` claim kind - it is ``username`` - so assembling the brief threw
    ``ValueError`` for every handle typed into the box. That happens inside a
    Tk callback in ``start_scan``, before the worker thread is created, and
    ``pythonw`` has nowhere to print a traceback: the window simply sat at
    "0% · starting …" with no instruments running and no error, forever.

    Inverting the real table means the two cannot drift again, and a claim
    kind added to ``brief.py`` is picked up here for free.
    """
    from ..core.brief import SEEDABLE

    return {ttype: kind.value for kind, ttype in SEEDABLE.items()}


_BRIEF_KIND_FOR_TYPE = _brief_kinds_for_types()

TYPE_COLOUR = {
    TargetType.DOMAIN: theme.ORCHID,
    TargetType.EMAIL: theme.OK,
    TargetType.USERNAME: theme.MAGENTA,
    # A name is its own type and it was missing here, so typing one into the
    # target box raised KeyError on every keystroke - the trace fires per
    # character - and the window died before the scan button was ever reached.
    TargetType.PERSON: "#fbbf24",
    TargetType.IP: theme.CYAN,
    TargetType.PHONE: "#f9a8d4",
    TargetType.URL: theme.VIOLET,
    TargetType.UNKNOWN: theme.INK_FAINT,
}


class ConsoleScreen(ttk.Frame):
    def __init__(self, master, boot: dict) -> None:
        super().__init__(master, style="Space.TFrame")
        self.config_obj: Config = boot.get("config") or runtime_config()
        self.queue: queue.Queue = queue.Queue()
        self.investigation: Investigation | None = None
        #: tag name -> url, for the clickable links in the Profile tab.
        self._profile_links: dict[str, str] = {}
        self._dossier_links: dict[str, str] = {}
        #: Progress bookkeeping for the status bar.
        self._total = 0
        self._running_modules: list[str] = []
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

        # Not the solar system: at 140x72 five orbits, a sun and the NOVA tag
        # all landed on top of each other. One ringed world with a moon is what
        # a strip this size can hold and still look like something.
        self.mini = orbit.RingedPlanet(inner, width=140, height=72, star_count=30)
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

        self._build_brief_row(inner)
        theme.Rule(head, theme.LINE).pack(fill="x")

    def _build_brief_row(self, parent) -> None:
        """"What else do you know?" - the row that makes the scan discriminate.

        Directly under the target box on purpose. One seed can only produce
        candidates; a second fact is what tells them apart, and a user who
        never finds this control never gets the answer they came for. Putting
        it in the sidebar with the other options would have hidden the most
        valuable thing on the screen behind a scroll.
        """
        wrap = tk.Frame(parent, bg=theme.BG)
        wrap.grid(row=2, column=1, sticky="ew", pady=(10, 0))
        wrap.columnconfigure(1, weight=1)

        entry_row = tk.Frame(wrap, bg=theme.BG)
        entry_row.grid(row=0, column=0, columnspan=2, sticky="ew")

        tk.Label(entry_row, text="also know", bg=theme.BG, fg=theme.INK_FAINT,
                 font=("Segoe UI", 8)).pack(side="left", padx=(2, 9))

        self.brief_kind = tk.StringVar(value=BRIEF_KINDS[0][0])
        kinds = ttk.Combobox(entry_row, textvariable=self.brief_kind,
                             values=[label for label, _ in BRIEF_KINDS],
                             state="readonly", width=12,
                             font=("Segoe UI", 8))
        kinds.pack(side="left")
        kinds.bind("<<ComboboxSelected>>", lambda _e: self._swap_value_widget())

        # The value input is swapped for the kind rather than being one box for
        # everything. A date typed freehand arrives in six formats and half of
        # them do not parse; a country typed freehand arrives as "UK", "U.K."
        # or "England" and only some of those match. Offering the answers is
        # what makes the field answerable.
        self._value_mode = "text"
        self.brief_value = tk.StringVar()
        self.brief_day = tk.StringVar(value="—")
        self.brief_month = tk.StringVar(value="—")
        self.brief_year = tk.StringVar(value="—")
        self.value_holder = tk.Frame(entry_row, bg=theme.BG)
        self.value_holder.pack(side="left", padx=(8, 8))
        self._swap_value_widget()

        self.brief_sure = tk.BooleanVar(value=True)
        ttk.Checkbutton(entry_row, text="sure", variable=self.brief_sure).pack(
            side="left", padx=(0, 8))

        add = tk.Label(entry_row, text="+ add", bg=theme.BG_RAISED,
                       fg=theme.ORCHID, font=("Segoe UI", 8, "bold"),
                       padx=12, pady=5, cursor="hand2")
        add.pack(side="left")
        add.bind("<Button-1>", lambda _e: self._add_brief_fact())
        add.bind("<Enter>", lambda e: e.widget.configure(bg=theme.BG_HOVER))
        add.bind("<Leave>", lambda e: e.widget.configure(bg=theme.BG_RAISED))

        self.brief_hint = tk.Label(
            entry_row,
            text="a second fact is what tells forty results apart",
            bg=theme.BG, fg=theme.INK_FAINT, font=("Segoe UI", 8))
        self.brief_hint.pack(side="left", padx=(12, 0))

        #: The claims themselves. Held as a list rather than rebuilt from the
        #: chips so the uncertainty flag survives a redraw.
        self.brief_facts: list[tuple[str, str, bool]] = []
        self.brief_chips = tk.Frame(wrap, bg=theme.BG)
        self.brief_chips.grid(row=1, column=0, columnspan=2, sticky="w",
                              pady=(7, 0))

    def _swap_value_widget(self) -> None:
        """Rebuild the value input to suit the fact being entered."""
        from ..core import vocab

        for child in self.value_holder.winfo_children():
            child.destroy()
        kind = dict(BRIEF_KINDS)[self.brief_kind.get()]

        if kind == "born":
            self._value_mode = "date"
            self.brief_day.set("—")
            self.brief_month.set("—")
            self.brief_year.set("—")
            # Year first and required; day and month optional, because knowing
            # only the year is the ordinary case and a picker that demands a
            # full date makes the user invent one. The resolver already
            # compares only as much as both sides state.
            for var, values, width in (
                (self.brief_year, ["—", *vocab.years()], 6),
                (self.brief_month, ["—", *vocab.MONTHS], 10),
                (self.brief_day, ["—", *(str(d) for d in range(1, 32))], 4),
            ):
                ttk.Combobox(self.value_holder, textvariable=var, values=values,
                             state="readonly", width=width,
                             font=("Segoe UI", 8)).pack(side="left", padx=(0, 4))
            return

        choices = {"country": vocab.COUNTRIES, "language": vocab.LANGUAGES,
                   "role": vocab.ROLES}.get(kind)
        if choices:
            self._value_mode = "choice"
            self.brief_value.set("")
            box = ttk.Combobox(self.value_holder, textvariable=self.brief_value,
                               values=list(choices), width=24,
                               font=("Segoe UI", 8))
            box.pack(side="left")
            box.bind("<Return>", lambda _e: self._add_brief_fact())
            # Typing narrows the list. With 195 countries an unfiltered
            # dropdown is a scroll, not a choice - and the box stays editable
            # so anything missing can still be typed.
            # noqa: B006 - the default is the late-binding capture idiom, not a
            # shared accumulator: `all_values` is read and never mutated, and
            # binding it here is what stops every dropdown in the loop closing
            # over the last `choices`.
            def narrow(_event, box=box, all_values=list(choices)) -> None:  # noqa: B006
                typed = self.brief_value.get().strip().casefold()
                box.configure(values=[v for v in all_values
                                      if typed in v.casefold()] or all_values)
            box.bind("<KeyRelease>", narrow)
            return

        self._value_mode = "text"
        self.brief_value.set("")
        border = tk.Frame(self.value_holder, bg=theme.LINE, padx=1, pady=1)
        border.pack(side="left")
        entry = tk.Entry(border, textvariable=self.brief_value, width=26,
                         bg=theme.BG_INPUT, fg=theme.INK, relief="flat",
                         insertbackground=theme.MAGENTA, font=("Consolas", 9),
                         highlightthickness=0, bd=0)
        entry.pack(ipady=4, ipadx=6)
        entry.bind("<Return>", lambda _e: self._add_brief_fact())

    def _read_brief_value(self) -> str:
        """Whatever the active input amounts to, as one string."""
        if self._value_mode != "date":
            return self.brief_value.get().strip()
        from ..core import vocab

        year = self.brief_year.get()
        if year in ("", "—"):
            return ""
        month, day = self.brief_month.get(), self.brief_day.get()
        if month in ("", "—") or day in ("", "—"):
            # Year alone is a real answer, not an incomplete one: it separates
            # two people with the same name born a decade apart, which is most
            # of what a birth date is for here.
            return year
        return f"{year}-{vocab.MONTHS.index(month) + 1:02d}-{int(day):02d}"

    def _add_brief_fact(self) -> None:
        value = self._read_brief_value()
        if not value:
            return
        kind = dict(BRIEF_KINDS)[self.brief_kind.get()]
        self.brief_facts.append((kind, value, bool(self.brief_sure.get())))
        self.brief_value.set("")
        self._redraw_brief_chips()

    def _drop_brief_fact(self, index: int) -> None:
        if 0 <= index < len(self.brief_facts):
            self.brief_facts.pop(index)
            self._redraw_brief_chips()

    def _redraw_brief_chips(self) -> None:
        for child in self.brief_chips.winfo_children():
            child.destroy()
        for i, (kind, value, sure) in enumerate(self.brief_facts):
            colour = theme.ORCHID if sure else theme.INK_DIM
            mark = "" if sure else " ?"
            chip = tk.Label(self.brief_chips, text=f"{kind}: {value}{mark}  ×",
                            bg=theme.blend(colour, theme.BG, 0.86), fg=colour,
                            font=("Segoe UI", 8), padx=9, pady=3,
                            cursor="hand2")
            chip.pack(side="left", padx=(0, 6))
            chip.bind("<Button-1>", lambda _e, n=i: self._drop_brief_fact(n))
        n = len(self.brief_facts)
        self.brief_hint.configure(
            text=("a second fact is what tells forty results apart" if n == 0
                  else f"{n} fact(s) · click a chip to remove · "
                       f"the scan will rank candidates against these"),
            fg=theme.INK_FAINT if n == 0 else theme.ORCHID)

    def _current_brief(self):
        """The brief as the engine wants it, target included.

        The target is folded in as a claim of its own because it is one: an
        address typed above and a city added here are two things known about
        one person, and leaving the address out means the strongest evidence
        on the screen never gets to confirm anything.
        """
        from ..core import brief as briefing

        brief = briefing.Brief(subject_kind="person")
        for kind, value, sure in self.brief_facts:
            brief.add(kind, value, certain=sure)
        target = self._value()
        if target:
            kind = _BRIEF_KIND_FOR_TYPE.get(detect_type(target))
            if kind is not None:
                brief.add(kind, target)
        return brief.expand() if brief else brief

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

        self.passive = tk.BooleanVar(value=self.config_obj.passive_only)
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
        self.max_sites = tk.StringVar(value=str(self.config_obj.max_sites))
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
        self.keys_label = tk.Label(
            side, bg=theme.BG_PANEL, font=("Segoe UI", 8),
            wraplength=200, justify="left",
        )
        self.keys_label.grid(row=10, column=0, sticky="w", pady=(6, 8))

        ttk.Button(side, text="⚙   Settings", command=self.open_settings).grid(
            row=11, column=0, sticky="ew", pady=(2, 0))
        self._refresh_keys_label()

        theme.Rule(self, theme.LINE).place(in_=side, relx=1.0, rely=0, relheight=1.0,
                                           width=1, anchor="ne")

    # ---------------------------------------------------------------- settings

    def open_settings(self) -> None:
        """Open the settings window; reload everything it touched on save."""
        SettingsWindow(self.winfo_toplevel(), on_saved=self._settings_saved)

    def _settings_saved(self) -> None:
        self.config_obj = runtime_config()
        self._refresh_keys_label()
        self.max_sites.set(str(self.config_obj.max_sites))
        self.passive.set(self.config_obj.passive_only)
        # A key that was just added can un-skip an instrument, and a module
        # disabled in the file has to disappear, so force a full rebuild by
        # clearing the cached type first.
        self.current_type = None
        self._on_target_change()
        self.status.configure(text="settings saved · instruments reloaded",
                              fg=theme.OK)

    def _refresh_keys_label(self) -> None:
        keys = self.config_obj.available_keys
        self.keys_label.configure(
            text=", ".join(keys) if keys else "none set — key-free instruments still run",
            fg=theme.OK if keys else theme.INK_FAINT,
        )

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

        # --- identity
        # The answer, when there is a brief to answer against. Ahead of Profile
        # because "which of these is them" is the question, and everything in
        # the other tabs is working.
        ident = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(ident, text="  Identity  ")
        ident.rowconfigure(0, weight=1)
        ident.columnconfigure(0, weight=1)
        self.identbox = tk.Text(
            ident, bg=theme.BG_PANEL, fg=theme.INK, relief="flat",
            highlightthickness=0, bd=0, font=("Consolas", 9), wrap="none",
            padx=14, pady=12, spacing1=1, cursor="arrow")
        self.identbox.grid(row=0, column=0, sticky="nsew")
        isb = ttk.Scrollbar(ident, orient="vertical",
                            command=self.identbox.yview)
        isb.grid(row=0, column=1, sticky="ns")
        self.identbox.configure(yscrollcommand=isb.set)
        for name, colour in (("h1", theme.ORCHID), ("h2", theme.MAGENTA),
                             ("dim", theme.INK_FAINT), ("plain", theme.INK_DIM),
                             ("good", theme.OK), ("bad", theme.HIGH),
                             ("warnrow", theme.NOTABLE),
                             ("lead", theme.CYAN)):
            self.identbox.tag_configure(name, foreground=colour)
        self.identbox.tag_configure("h1", font=("Consolas", 13, "bold"))
        self.identbox.tag_configure("h2", font=("Consolas", 10, "bold"))
        self.identbox.tag_configure("lead", font=("Consolas", 10, "bold"))
        self.identbox.configure(state="disabled")
        self.ident_empty = tk.Label(
            ident, bg=theme.BG_PANEL, fg=theme.INK_FAINT,
            font=("Segoe UI", 10), justify="center",
            text="add what you already know above, then scan\n\n"
                 "one seed can only produce candidates —\n"
                 "a second fact is what tells them apart")
        self.ident_empty.place(relx=0.5, rely=0.45, anchor="center")

        # --- dossier
        # Identity answers "which of these is them". This answers "what do we
        # know about them", consolidated into one subject with every competing
        # value kept beside its source. It sits ahead of Profile because it is
        # the answer and Profile is the working.
        dossier = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(dossier, text="  Dossier  ")
        dossier.rowconfigure(0, weight=1)
        dossier.columnconfigure(0, weight=1)
        self.dossierbox = tk.Text(
            dossier, bg=theme.BG_PANEL, fg=theme.INK, relief="flat",
            highlightthickness=0, bd=0, font=("Consolas", 9), wrap="none",
            padx=14, pady=12, spacing1=1, cursor="arrow")
        self.dossierbox.grid(row=0, column=0, sticky="nsew")
        dsb = ttk.Scrollbar(dossier, orient="vertical",
                            command=self.dossierbox.yview)
        dsb.grid(row=0, column=1, sticky="ns")
        dsbx = ttk.Scrollbar(dossier, orient="horizontal",
                             command=self.dossierbox.xview)
        dsbx.grid(row=1, column=0, sticky="ew")
        self.dossierbox.configure(yscrollcommand=dsb.set, xscrollcommand=dsbx.set)
        for name, colour in (
            ("h1", theme.ORCHID), ("h2", theme.CYAN), ("plain", theme.INK),
            ("dim", theme.INK_FAINT), ("ok", theme.OK), ("warnrow", theme.HIGH),
            ("notable", theme.NOTABLE), ("weak", theme.INK_DIM),
        ):
            self.dossierbox.tag_configure(name, foreground=colour)
        self.dossierbox.tag_configure("h1", font=("Consolas", 12, "bold"))
        self.dossierbox.tag_configure("h2", font=("Consolas", 9, "bold"))
        self.dossierbox.tag_configure("link", foreground=theme.CYAN,
                                      underline=True)
        self.dossierbox.tag_bind(
            "link", "<Enter>",
            lambda _e: self.dossierbox.configure(cursor="hand2"))
        self.dossierbox.tag_bind(
            "link", "<Leave>",
            lambda _e: self.dossierbox.configure(cursor="arrow"))
        self.dossierbox.tag_bind("link", "<Button-1>", self._open_dossier_link)
        self.dossierbox.configure(state="disabled")
        self.dossier_empty = tk.Label(
            dossier, bg=theme.BG_PANEL, fg=theme.INK_FAINT, justify="center",
            font=("Segoe UI", 10),
            text="no dossier yet\n\nrun a scan and this consolidates it")
        self.dossier_empty.place(relx=0.5, rely=0.45, anchor="center")

        # --- profile
        # Findings answers "what did each module say". This answers "who is
        # this" - the same investigation grouped by subject, with the social
        # accounts at the top because that is what people look for first.
        profile = tk.Frame(nb, bg=theme.BG_PANEL)
        nb.add(profile, text="  Profile  ")
        profile.rowconfigure(0, weight=1)
        profile.columnconfigure(0, weight=1)
        self.profilebox = tk.Text(
            profile, bg=theme.BG_PANEL, fg=theme.INK, relief="flat",
            highlightthickness=0, bd=0, font=("Consolas", 9), wrap="none",
            padx=14, pady=12, spacing1=1, cursor="arrow")
        self.profilebox.grid(row=0, column=0, sticky="nsew")
        psb = ttk.Scrollbar(profile, orient="vertical",
                            command=self.profilebox.yview)
        psb.grid(row=0, column=1, sticky="ns")
        psbx = ttk.Scrollbar(profile, orient="horizontal",
                             command=self.profilebox.xview)
        psbx.grid(row=1, column=0, sticky="ew")
        self.profilebox.configure(yscrollcommand=psb.set, xscrollcommand=psbx.set)
        for name, colour in (
            ("h1", theme.ORCHID), ("h2", theme.CYAN), ("warnrow", theme.HIGH),
            ("ok", theme.OK), ("dim", theme.INK_FAINT), ("plain", theme.INK),
            ("notable", theme.NOTABLE),
        ):
            self.profilebox.tag_configure(name, foreground=colour)
        self.profilebox.tag_configure("h1", font=("Consolas", 11, "bold"))
        self.profilebox.tag_configure("h2", font=("Consolas", 9, "bold"))
        self.profilebox.tag_configure(
            "link", foreground=theme.CYAN, underline=True)
        # A link in a Text widget is a tag, not a widget, so the pointer and the
        # click have to be wired by hand or it looks clickable and is not.
        self.profilebox.tag_bind("link", "<Enter>",
                                 lambda _e: self.profilebox.configure(cursor="hand2"))
        self.profilebox.tag_bind("link", "<Leave>",
                                 lambda _e: self.profilebox.configure(cursor="arrow"))
        self.profilebox.tag_bind("link", "<Button-1>", self._open_profile_link)
        self.profilebox.configure(state="disabled")
        self.profile_empty = tk.Label(
            profile, bg=theme.BG_PANEL, fg=theme.INK_FAINT, justify="center",
            font=("Segoe UI", 10),
            text="no profile yet\n\nrun a scan and this fills in")
        self.profile_empty.place(relx=0.5, rely=0.45, anchor="center")

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
        bar.columnconfigure(1, weight=1)   # the text block takes the slack

        # The same orbit the boot screen draws, shrunk — reusing OrbitCanvas
        # rather than drawing a second spinner means there is one animation in
        # the app and it cannot drift out of step with itself. Seen from
        # straight above rather than at the boot screen's angle: at this size
        # the squashed ellipses collapse into a bar, where concentric circles
        # read immediately as something going round.
        self.spinner = orbit.OrbitCanvas(
            bar, width=44, height=44, star_count=10, show_rings=True,
            speed=2.2, tilt=orbit.TILT_TOP_DOWN)
        self.spinner.configure(bg=theme.BG_PANEL)
        self.spinner.grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.spinner.grid_remove()   # only on screen while something is running

        text = tk.Frame(bar, bg=theme.BG_PANEL)
        text.grid(row=0, column=1, sticky="w")
        self.percent = tk.Label(text, text="", bg=theme.BG_PANEL, fg=theme.ORCHID,
                                font=("Consolas", 13, "bold"), width=5, anchor="w")
        self.percent.pack(side="left")
        self.status = tk.Label(text, text="ready", bg=theme.BG_PANEL,
                               fg=theme.INK_DIM, font=("Consolas", 9),
                               anchor="w", justify="left")
        self.status.pack(side="left")

        self.bar = ttk.Progressbar(bar, style="Nova.Horizontal.TProgressbar",
                                   mode="determinate", length=280)
        self.bar.grid(row=0, column=2, sticky="e", padx=16)

        btns = tk.Frame(bar, bg=theme.BG_PANEL)
        btns.grid(row=0, column=3, sticky="e")
        tk.Label(btns, text="export", bg=theme.BG_PANEL, fg=theme.INK_FAINT,
                 font=("Segoe UI", 8)).pack(side="left", padx=(0, 8))
        self.export_btns = []
        # DOSSIER first: it is what the Dossier tab shows, and exporting the
        # thing on screen should not mean knowing that it is called "markdown".
        for label, fmt in (("DOSSIER", "dossier"), ("HTML", "html"),
                           ("JSON", "json"), ("CSV", "csv"), ("MD", "markdown")):
            # Width per label rather than one fixed 6: a ttk Button clips
            # rather than grows, so "DOSSIER" rendered as "DOSSIE".
            b = ttk.Button(btns, text=label, width=max(6, len(label) + 1),
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
        # .get, not [], so a target type added later cannot take the window
        # down on a keystroke the way PERSON did.
        colour = TYPE_COLOUR.get(ttype, theme.INK_FAINT)
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
        self.profilebox.configure(state="normal")
        self.profilebox.delete("1.0", "end")
        self.profilebox.configure(state="disabled")
        self._profile_links.clear()
        self.profile_empty.place(relx=0.5, rely=0.45, anchor="center")
        self.dossierbox.configure(state="normal")
        self.dossierbox.delete("1.0", "end")
        self.dossierbox.configure(state="disabled")
        self._dossier_links.clear()
        self.dossier_empty.place(relx=0.5, rely=0.45, anchor="center")
        self.identbox.configure(state="normal")
        self.identbox.delete("1.0", "end")
        self.identbox.configure(state="disabled")
        self.ident_empty.place(relx=0.5, rely=0.45, anchor="center")
        self.bar.configure(maximum=len(chosen), value=0)
        self._total = len(chosen)
        self._running_modules = []
        self.spinner.grid()
        self.spinner.start()
        self._show_progress(0, "starting")

        self._log_raw("  ", ("plain",))
        self._log_raw(f"{target}", ("bright",))
        self._log_raw("  ·  ", ("plain",))
        self._log_raw(f"{ttype.value}", ("run",))
        self._log_raw(f"  ·  {len(chosen)} instruments\n\n", ("plain",))

        # config.json first, then the switches on this screen. Using
        # Config.from_env here would silently ignore the settings window.
        cfg = runtime_config(
            passive_only=self.passive.get(),
            max_sites=int(self.max_sites.get() or 0),
        )
        cfg.set_option("verify_hits", self.verify.get())
        cfg.set_option("include_nsfw", self.nsfw.get())
        cfg.set_option("refresh_sites", False)
        # The same bound the CLI applies. Without it the 481-site sweep, with
        # its verification pass and per-host rate limiting, can hold the bar
        # at 90% for minutes with one instrument still lit - which reads as a
        # hang even though it is working.
        cfg.set_option("module_time_limit", 180.0)

        # More than the target itself means there is something to cross-check,
        # and only the expanding walk can do it: it is the one path that puts
        # every seed into a single graph where the evidence can converge.
        # Assembling the brief must never be able to stop a scan. It is an
        # enrichment: the target in the box is what the operator asked for,
        # and a bad extra fact should cost the cross-check, not the run.
        try:
            brief = self._current_brief()
            brief = brief if len(brief) > 1 else None
        except Exception as exc:  # noqa: BLE001 - see report_error
            self.report_error(f"ignoring the 'also know' facts: "
                              f"{type(exc).__name__}: {exc}")
            brief = None
        if brief is not None:
            self._log_raw(f"  cross-checking against {len(brief)} known "
                          f"fact(s)\n\n", ("plain",))

        threading.Thread(
            target=self._run, args=(target, ttype, chosen, cfg, brief), daemon=True
        ).start()

    def _run(self, target: str, ttype: TargetType, chosen: list[str],
             cfg: Config, brief=None) -> None:
        try:
            with Engine(cfg, progress=lambda m, s: self.queue.put(("prog", m, s))) as e:
                if brief is not None:
                    inv = e.investigate(
                        target, only=chosen, target_type=ttype, brief=brief,
                        on_result=lambda r: self.queue.put(("result", r)))
                else:
                    inv = e.scan(target, only=chosen, target_type=ttype,
                                 on_result=lambda r: self.queue.put(("result", r)))
                if self.pivot.get() and brief is None:
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
                        if module not in self._running_modules:
                            self._running_modules.append(module)
                        self._log_event(module, "run", "running")
                    else:
                        self._unpill(module)
                        self.bar["value"] = self.bar["value"] + 1
                        if module in self._running_modules:
                            self._running_modules.remove(module)
                    self._show_progress(int(self.bar["value"]),
                                        ", ".join(self._running_modules[:3]))
                elif kind == "result":
                    self._add_result(item[1])
                elif kind == "done":
                    self._finish(item[1])
                elif kind == "fail":
                    self._log_event("scan", "fail", item[1])
                    self._stop_spinner()
                    self._reset()
        except queue.Empty:
            pass
        self.after(90, self._drain)

    def report_error(self, message: str) -> None:
        """Put an error where the operator is already looking.

        Called by the window's ``report_callback_exception`` hook and by any
        handler that catches something it can carry on from. The live log is
        the right place: under ``pythonw`` there is no console, and a scan
        that quietly never started is worse than one that says why.
        """
        try:
            self._log_event("nova", "fail", message)
        except Exception:  # noqa: BLE001 - never recurse out of an error path
            pass

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
        self._stop_spinner()
        if not inv.findings:
            self.empty.configure(text="no findings\n\nnothing public turned up "
                                      "for this target")
            self.empty.place(relx=0.5, rely=0.45, anchor="center")
        self._render_profile(inv)
        self._render_dossier(inv)
        self._render_identity(inv)
        for b in self.export_btns:
            b.configure(state="normal")
        self._reset()

    # ---------------------------------------------------------------- identity

    def _render_identity(self, inv: Investigation) -> None:
        """Draw the resolution into the Identity tab.

        Rows are built here rather than piped through
        :func:`nova_osint.core.identity.render_text` so each verdict can carry
        its own colour: a contradiction has to be as visible as a confirmation,
        and in a single monospace blob it is not.
        """
        res = getattr(inv, "resolution", None)
        if res is None or not res.candidates:
            return
        from ..core.identity import Verdict

        tag_for = {Verdict.CONFIRMS: "good", Verdict.CONSISTENT: "plain",
                   Verdict.CONTRADICTS: "bad", Verdict.UNCHECKED: "warnrow",
                   Verdict.UNKNOWN: "dim"}
        mark_for = {Verdict.CONFIRMS: "++", Verdict.CONSISTENT: " +",
                    Verdict.CONTRADICTS: "--", Verdict.UNCHECKED: " ?",
                    Verdict.UNKNOWN: "  "}

        rows: list[tuple[str, str]] = [
            (f"  {res.subject}\n", "h1"),
            (f"  {res.reading}\n", "lead"),
        ]
        for i, cand in enumerate(res.candidates):
            rows.append((f"\n  {i + 1}. {cand.label}", "h2"))
            rows.append((f"   ({cand.etype})\n", "dim"))
            rows.append((f"       score {cand.score:+.1f}   "
                         f"p={cand.probability:.2f}   "
                         f"{cand.answered} of {len(cand.checks)} claims tested\n",
                         "dim"))
            if len(cand.members) > 1:
                rows.append((f"       also: {', '.join(cand.members[1:6])}\n",
                             "dim"))
            # Only the leaders get their workings: past the third, the reader
            # is scanning for names, not auditing arithmetic.
            if i < 3:
                for check in sorted(cand.checks, key=lambda c: -abs(c.llr)):
                    if check.verdict is Verdict.UNKNOWN:
                        continue
                    found = f" -> {check.found}" if check.found else ""
                    rows.append(
                        (f"       {mark_for[check.verdict]} "
                         f"{check.claim.kind.value:9} {check.claim.raw}{found}"
                         f"   [{check.llr:+.1f}] {check.why}\n",
                         tag_for[check.verdict]))
        if res.next_check:
            rows.append((f"\n  what would settle it:\n    {res.next_check}\n",
                         "warnrow"))
        if res.untestable:
            rows.append(("\n  nothing in this scan could test:\n", "dim"))
            for note in res.untestable:
                rows.append((f"    {note}\n", "dim"))

        self.ident_empty.place_forget()
        self.identbox.configure(state="normal")
        self.identbox.delete("1.0", "end")
        for text, tag in rows:
            self.identbox.insert("end", text, (tag,))
        self.identbox.configure(state="disabled")

    # ----------------------------------------------------------------- profile

    def _render_profile(self, inv: Investigation) -> None:
        """Draw the dossier into the Profile tab.

        Built from the same :mod:`nova_osint.core.profile` the CLI renders, so
        the desktop app cannot drift into showing something different from what
        ``-f profile`` produces - only styled differently.
        """
        from ..core.profile import build, confidence_line

        try:
            profile = build(inv)
        except Exception as exc:  # noqa: BLE001 - a broken panel must not eat the scan
            self._set_profile([(f"  could not build the profile: {exc}\n", "warnrow")])
            return

        rows: list[tuple[str, str]] = []

        def head(text: str) -> None:
            rows.append((f"\n  {text}\n", "h2"))

        rows.append((f"  {profile.subject}", "h1"))
        rows.append((f"   ({profile.subject_type})\n", "dim"))
        rows.append((f"  {profile.entities} entities · {profile.findings} findings · "
                     f"{len(profile.relationships)} relationships\n", "dim"))

        if profile.ambiguities or profile.candidates:
            head("WHO THIS IS  —  read before anything below")
            for note in profile.ambiguities:
                rows.append((f"    ! {note}\n", "warnrow"))
            for c in profile.candidates:
                rows.append((f"    {c.grade}  {c.value}", "plain"))
                rows.append((f"   [{c.why}]\n", "dim"))
            rows.append(("    NOVA has not decided which of these is your "
                         "subject.\n", "warnrow"))

        if profile.bio:
            # Before the assessment, same as the CLI: a dossier on a person
            # opens with who they are, not with a note on how well evidenced it
            # all is. One block per candidate - merging them invents a person.
            head("WHO")
            for subject in profile.bio:
                if subject.candidate:
                    rows.append((f"    -- if this is {subject.name} --\n",
                                 "notable"))
                for attr in subject.attributes:
                    label = (attr.label + ":").ljust(16)
                    if not attr.established:
                        rows.append((f"      {label} ", "plain"))
                        rows.append(("not established\n", "dim"))
                        continue
                    first, *rest = attr.values
                    rows.append((f"      {label} {first.text}", "plain"))
                    rows.append((f"   [{first.grade} {first.source}]", "dim"))
                    if attr.disputed:
                        rows.append(("  (sources disagree)", "warnrow"))
                    elif attr.multivalued:
                        rows.append(("  (several)", "dim"))
                    rows.append(("\n", "plain"))
                    for value in rest:
                        rows.append((f"      {' ' * 16} {value.text}", "plain"))
                        rows.append((f"   [{value.grade} {value.source}]\n", "dim"))
                    if attr.note:
                        rows.append((f"      {' ' * 16} ({attr.note})\n", "dim"))

        head("ASSESSMENT")
        rows.append((f"    {confidence_line(profile)}\n", "plain"))
        if profile.truncated:
            rows.append((f"    incomplete: the scan stopped on "
                         f"{profile.truncated}\n", "warnrow"))

        head("SOCIAL ACCOUNTS")
        if profile.socials:
            width = max(len(a.platform) for a in profile.socials)
            for a in profile.socials:
                mark = {"confirmed": "+", "declared": "~", "search": "?"}[a.basis]
                tag = {"confirmed": "ok", "declared": "notable",
                       "search": "dim"}[a.basis]
                handle = f"@{a.handle}" if a.handle != "-" else ""
                rows.append((f"    {mark}  {a.platform.ljust(width)}  ", tag))
                rows.append((f"{handle:<22} ", "plain"))
                rows.append((a.url, "link"))
                rows.append(("\n", "plain"))
                if a.note:
                    rows.append((f"       {' ' * width}  {a.note}\n", "dim"))
            rows.append(("\n    + verified by a lookup   ~ declared by a source   "
                         "? not checkable, open by hand\n", "dim"))
        else:
            rows.append(("    (none found)\n", "dim"))

        if profile.relationships:
            head("RELATIONSHIPS")
            indirect = [r for r in profile.relationships if r.indirect]
            direct = [r for r in profile.relationships if not r.indirect]
            if indirect:
                rows.append(("    between other parties:\n", "dim"))
                for r in indirect[:30]:
                    rows.append((f"      {r.grade}  {r.a}  --{r.relation}-->  "
                                 f"{r.b}", "plain"))
                    rows.append((f"   [{r.why}]\n", "dim"))
            if direct:
                rows.append(("    to the subject:\n", "dim"))
                for r in direct[:40]:
                    rows.append((f"      {r.grade}  {r.relation:<18} {r.b}", "plain"))
                    rows.append((f"   [{r.why}] - {r.reading}\n", "dim"))

        from ..core.profile import SECTIONS

        for heading, _kinds, note in SECTIONS:
            entries = profile.sections.get(heading, [])
            head(f"{heading.upper()}   ({len(entries)})")
            rows.append((f"    {note}\n", "dim"))
            if not entries:
                rows.append(("    (none found)\n", "dim"))
                continue
            for e in entries:
                rows.append((f"      {e.grade}  {e.value}", "plain"))
                rows.append((f"   [{e.why}]\n", "dim"))

        if profile.timeline:
            head("TIMELINE")
            for when, what, module in profile.timeline:
                rows.append((f"      {when}  {what}", "plain"))
                rows.append((f"   ({module})\n", "dim"))

        if profile.exposure:
            head("EXPOSURE  —  high interest")
            for label, value, module in profile.exposure[:40]:
                rows.append((f"      {label}: {value}", "notable"))
                rows.append((f"   ({module})\n", "dim"))

        head("COVERAGE GAPS")
        if profile.gaps:
            rows.append(("    these sources did not answer; absence here is not "
                         "evidence of absence\n", "dim"))
            for gap in profile.gaps:
                rows.append((f"      {gap}\n", "warnrow"))
        else:
            rows.append(("    every source answered\n", "ok"))

        self._set_profile(rows)

    def _render_dossier(self, inv: Investigation) -> None:
        """Draw the consolidated dossier into its tab.

        Built from the same :func:`generate_target_dossier` the CLI renders
        with ``-f dossier``, so the desktop app cannot drift into showing a
        different answer from the command line - only a differently styled one.
        """
        from ..core.target_dossier import generate_target_dossier

        try:
            dossier = generate_target_dossier(inv)
        except Exception as exc:  # noqa: BLE001 - a broken panel must not eat the scan
            self._set_dossier([(f"  could not build the dossier: {exc}\n",
                                "warnrow")])
            return

        rows: list[tuple[str, str]] = []
        rows.append((f"\n  {dossier.subject or dossier.input_query}\n", "h1"))
        rows.append((f"  for {dossier.input_query}\n", "dim"))
        if dossier.subject_confidence is not None:
            rows.append((f"  subject match {dossier.subject_confidence:.0%}"
                         f"  {dossier.subject_verdict}\n", "notable"))
        rows.append(("\n", "plain"))

        if dossier.synthetic:
            rows.append(("  CONTAINS SYNTHETIC FIXTURE DATA - not findings\n\n",
                         "warnrow"))

        rows.append(("  IDENTITY\n", "h2"))
        for label, values in (("name", dossier.full_name),
                              ("born", dossier.date_of_birth),
                              ("aliases", dossier.aliases),
                              ("phone", dossier.phones)):
            if not values:
                rows.append((f"    {label:<9}not established\n", "dim"))
                continue
            for index, item in enumerate(values):
                shown = label if index == 0 else ""
                tag = ("ok" if item.confidence >= 0.8
                       else "plain" if item.confidence >= 0.5 else "weak")
                mark = "  (synthetic)" if item.synthetic else ""
                rows.append((f"    {shown:<9}{item.value}{mark}\n", tag))
                rows.append((f"             {item.confidence:.2f}  "
                             f"{', '.join(sorted(set(item.sources)))}\n", "dim"))
        rows.append(("\n", "plain"))

        rows.append(("  BACKGROUND\n", "h2"))
        if dossier.education:
            for record in dossier.education:
                bits = [record.school_name]
                if record.degree:
                    bits.append(record.degree)
                if record.graduation_year:
                    bits.append(record.graduation_year)
                rows.append((f"    school   {'  -  '.join(bits)}\n", "plain"))
        else:
            rows.append(("    school   not established\n", "dim"))
        if dossier.employment:
            for record in dossier.employment:
                rows.append((f"    employer {record.company}\n", "plain"))
                if record.role and record.role_paired:
                    rows.append((f"             {record.role}\n", "dim"))
                elif record.role:
                    rows.append((f"             {record.role}  "
                                 f"(not tied to this employer)\n", "notable"))
        else:
            rows.append(("    employer not established\n", "dim"))
        rows.append(("\n", "plain"))

        rows.append(("  ACCOUNTS\n", "h2"))
        if dossier.linked_accounts:
            for account in dossier.linked_accounts:
                tag = "ok" if account.basis == "confirmed" else (
                    "plain" if account.basis == "declared" else "weak")
                rows.append((f"    {account.platform:<14}", tag))
                rows.append((account.url + "\n", "link"))
                rows.append((f"    {'':<14}{account.basis}\n", "dim"))
        else:
            rows.append(("    none established\n", "dim"))
        rows.append(("\n", "plain"))

        if dossier.exposure_records:
            rows.append(("  EXPOSURE\n", "h2"))
            rows.append(("    context only - no passwords, hashes or tokens\n",
                         "dim"))
            for record in dossier.exposure_records:
                rows.append((f"    {record.get('source_name', 'record')}\n",
                             "notable"))
                if refused := record.get("credential_fields_present"):
                    rows.append((f"      credential fields present, not read: "
                                 f"{', '.join(sorted(set(refused)))}\n", "dim"))
            rows.append(("\n", "plain"))

        if disputes := dossier.disputes:
            rows.append(("  CONFLICTS\n", "h2"))
            rows.append(("    nothing has been chosen for you\n", "dim"))
            for name, values in disputes:
                rows.append((f"    {name.replace('_', ' ')}\n", "notable"))
                for item in values:
                    rows.append((f"      {item.confidence:.2f}  {item.value}"
                                 f"   {item.source}\n", "plain"))
            rows.append(("\n", "plain"))

        rows.append(("  COLLECTION GAPS\n", "h2"))
        if dossier.collection_errors:
            rows.append(("    absence here means unknown, not none\n", "dim"))
            for module, status, reason in dossier.collection_errors:
                # Explicit separators, not padding alone: a status wider than
                # its column ("unavailable" is 11) otherwise runs straight into
                # the reason and the two read as one word.
                rows.append((f"    {module:<14}  {status:<12}  {reason}\n",
                             "warnrow"))
        else:
            rows.append(("    every source answered\n", "ok"))

        self._set_dossier(rows)

    def _set_dossier(self, rows: list[tuple[str, str]]) -> None:
        self.dossier_empty.place_forget()
        self.dossierbox.configure(state="normal")
        self.dossierbox.delete("1.0", "end")
        self._dossier_links.clear()
        for text, tag in rows:
            if tag == "link":
                # Same mechanism as the Profile tab: a link in a Text widget is
                # a tag, so each URL needs its own tag to be clickable.
                name = f"durl{len(self._dossier_links)}"
                self._dossier_links[name] = text
                self.dossierbox.insert("end", text, ("link", name))
            else:
                self.dossierbox.insert("end", text, (tag,))
        self.dossierbox.configure(state="disabled")

    def _open_dossier_link(self, event: object) -> None:
        import webbrowser

        for name in self.dossierbox.tag_names("current"):
            url = self._dossier_links.get(name)
            if url:
                webbrowser.open(url.strip())
                return

    def _set_profile(self, rows: list[tuple[str, str]]) -> None:
        self.profile_empty.place_forget()
        self.profilebox.configure(state="normal")
        self.profilebox.delete("1.0", "end")
        self._profile_links.clear()
        for text, tag in rows:
            if tag == "link":
                # Each link needs its own tag as well as the shared "link" one,
                # so the click handler can tell which URL was hit.
                name = f"url{len(self._profile_links)}"
                self._profile_links[name] = text
                self.profilebox.insert("end", text, ("link", name))
            else:
                self.profilebox.insert("end", text, (tag,))
        self.profilebox.configure(state="disabled")

    def _open_profile_link(self, event: object) -> None:
        import webbrowser

        for name in self.profilebox.tag_names("current"):
            url = self._profile_links.get(name)
            if url:
                webbrowser.open(url)
                return

    def _show_progress(self, done: int, doing: str) -> None:
        """Percentage plus what is in flight, so a long scan never looks stuck.

        The count is of modules finished, which is honest but lumpy - a scan
        with four instruments moves in 25% steps. It is still far better than a
        bar with no number, because the thing a person wants to know during a
        two-minute wait is whether anything is happening at all.
        """
        total = max(1, getattr(self, "_total", 1))
        pct = min(100, int(done * 100 / total))
        self.percent.configure(text=f"{pct:>3}%")
        if doing:
            self.status.configure(text=f"  {doing} …")
        elif done >= total:
            self.status.configure(text="  finishing up …")
        else:
            self.status.configure(text="  waiting on the slow ones …")

    def _stop_spinner(self) -> None:
        try:
            self.spinner.stop()
            self.spinner.grid_remove()
        except tk.TclError:  # the window went away mid-scan
            pass
        self.percent.configure(text="")

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
        ext = {"html": ".html", "json": ".json", "csv": ".csv",
               "markdown": ".md", "dossier": ".md"}[fmt]
        safe = "".join(c if c.isalnum() or c in "-._" else "_"
                       for c in self.investigation.target)
        # The dossier and the plain markdown report are both .md, so they need
        # different default names or one silently offers to overwrite the other.
        stem = f"nova-dossier-{safe}" if fmt == "dossier" else f"nova-{safe}"
        path = filedialog.asksaveasfilename(
            title="Save report", defaultextension=ext,
            initialfile=f"{stem}{ext}",
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
