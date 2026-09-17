"""Palette, fonts and ttk styling for the desktop app.

Black with a violet cast. The background is never pure grey - every neutral
carries a little purple so the accent colours read as light in a dark room
rather than as stickers on a grey card.

Tk has no alpha channel, so anything that needs to look faded is pre-blended
against the background here rather than drawn transparent.
"""

from __future__ import annotations

import tkinter.font as tkfont
from tkinter import ttk

# --- surfaces ---------------------------------------------------------------
BG = "#07040e"          # the void
BG_PANEL = "#0e0a1b"    # cards and lists
BG_RAISED = "#17102b"   # buttons, headers, the things that sit on top
BG_INPUT = "#100b20"
BG_HOVER = "#1f1638"

LINE = "#2d1f4d"
LINE_SOFT = "#1c1333"

# --- text -------------------------------------------------------------------
INK = "#ece7f9"
INK_DIM = "#9d8dc4"
INK_FAINT = "#60507f"

# --- accents ----------------------------------------------------------------
VIOLET = "#8b5cf6"
PURPLE = "#a855f7"
MAGENTA = "#d946ef"
PLUM = "#6d28d9"
ORCHID = "#c084fc"
CYAN = "#22d3ee"        # the one cool note, used sparingly for focus
GOLD = "#fbbf24"

HIGH = "#fb7185"
NOTABLE = "#fbbf24"
OK = "#4ade80"

# Kept for the gradient wordmark: violet through magenta.
NEBULA = ["#7c3aed", "#8b5cf6", "#a855f7", "#c026d3", "#d946ef", "#e879f9"]

SEVERITY = {"high": HIGH, "notable": NOTABLE, "info": INK_DIM}
CONFIDENCE = {"confirmed": OK, "likely": ORCHID, "possible": INK_FAINT}

#: One hue per instrument so a long report stays readable at a glance. Ordered
#: so that modules commonly run together land on visibly different hues rather
#: than three neighbouring purples.
MODULE_PALETTE = (
    "#c084fc", "#22d3ee", "#f472b6", "#a78bfa", "#fbbf24", "#67e8f9",
    "#e879f9", "#818cf8", "#34d399", "#f9a8d4", "#a855f7", "#fb923c",
)

#: Fixed assignments for the modules that ship, so colours do not shuffle when
#: a new one is registered. Anything unlisted falls back to a stable hash.
MODULE_COLOURS = {
    "whois": "#c084fc",
    "dns": "#22d3ee",
    "mailsec": "#f472b6",
    "subdomains": "#a78bfa",
    "headers": "#fbbf24",
    "exposed": "#67e8f9",
    "wayback": "#e879f9",
    "breaches": "#fb7185",
    "pwned": "#fb7185",
    "username": "#a855f7",
    "github": "#818cf8",
    "gists": "#818cf8",
    "email": "#34d399",
    "ip": "#22d3ee",
    "abuseipdb": "#fb923c",
    "phone": "#f9a8d4",
    "dorks": "#9d8dc4",
}


def module_colour(name: str) -> str:
    if name in MODULE_COLOURS:
        return MODULE_COLOURS[name]
    return MODULE_PALETTE[sum(map(ord, name)) % len(MODULE_PALETTE)]


def blend(colour: str, towards: str, amount: float) -> str:
    """Mix ``colour`` toward ``towards``. ``amount`` 0 keeps it, 1 replaces it.

    This is how the orbit trails and the sun's glow fade: Tk cannot do alpha,
    so we compute the colour the pixel would have been.
    """
    a = tuple(int(colour[i : i + 2], 16) for i in (1, 3, 5))
    b = tuple(int(towards[i : i + 2], 16) for i in (1, 3, 5))
    m = (round(x + (y - x) * amount) for x, y in zip(a, b, strict=True))
    return "#{:02x}{:02x}{:02x}".format(*m)


def pick_font(root, candidates: list[str], size: int, **kw) -> tkfont.Font:
    """First installed family wins, so the app looks right without shipping fonts."""
    available = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in available:
            return tkfont.Font(root=root, family=name, size=size, **kw)
    return tkfont.Font(root=root, size=size, **kw)


class Fonts:
    def __init__(self, root) -> None:
        ui = ["Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Arial"]
        mono = ["Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo", "Courier New"]
        self.title = pick_font(root, ui, 22, weight="bold")
        self.h2 = pick_font(root, ui, 11, weight="bold")
        self.section = pick_font(root, ui, 9, weight="bold")
        self.body = pick_font(root, ui, 10)
        self.small = pick_font(root, ui, 9)
        self.tiny = pick_font(root, ui, 8)
        self.mono = pick_font(root, mono, 10)
        self.mono_small = pick_font(root, mono, 9)
        self.mono_tiny = pick_font(root, mono, 8)


def install(root) -> Fonts:
    """Apply the dark theme to ttk and return the font set."""
    fonts = Fonts(root)
    style = ttk.Style(root)
    # 'clam' is the only built-in theme that honours background colours on
    # Windows; the native ones ignore them and you get grey boxes on black.
    style.theme_use("clam")

    style.configure(".", background=BG_PANEL, foreground=INK,
                    fieldbackground=BG_INPUT, borderwidth=0, font=fonts.body)
    style.configure("TFrame", background=BG_PANEL)
    style.configure("Space.TFrame", background=BG)
    style.configure("Card.TFrame", background=BG_PANEL)
    style.configure("Raised.TFrame", background=BG_RAISED)

    style.configure("TLabel", background=BG_PANEL, foreground=INK)
    style.configure("Dim.TLabel", background=BG_PANEL, foreground=INK_DIM,
                    font=fonts.small)
    style.configure("Faint.TLabel", background=BG_PANEL, foreground=INK_FAINT,
                    font=fonts.tiny)
    style.configure("Head.TLabel", background=BG_PANEL, foreground=ORCHID,
                    font=fonts.section)
    style.configure("Space.TLabel", background=BG, foreground=INK_DIM,
                    font=fonts.small)
    style.configure("SpaceFaint.TLabel", background=BG, foreground=INK_FAINT,
                    font=fonts.tiny)

    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=INK,
                    insertcolor=PURPLE, bordercolor=LINE, lightcolor=LINE,
                    darkcolor=LINE, padding=8)
    style.map("TEntry", bordercolor=[("focus", PURPLE)])

    # A combobox needs every one of these. Left alone it draws a white field
    # with near-white text on this theme, which reads as a broken widget - and
    # ``readonly`` is its *resting* state, not an unusual one, so the readonly
    # entry in the map below is the colour it wears almost all the time.
    style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_RAISED,
                    foreground=INK, arrowcolor=ORCHID, bordercolor=LINE,
                    lightcolor=LINE, darkcolor=LINE, padding=5,
                    selectbackground=BG_INPUT, selectforeground=INK)
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG_INPUT), ("disabled", BG_PANEL)],
        foreground=[("readonly", INK), ("disabled", INK_FAINT)],
        background=[("readonly", BG_RAISED), ("active", BG_HOVER)],
        arrowcolor=[("active", MAGENTA)],
        bordercolor=[("focus", PURPLE)],
        selectbackground=[("readonly", BG_INPUT)],
        selectforeground=[("readonly", INK)],
    )
    # The drop-down list is a classic Tk Listbox inside a toplevel, which ttk
    # styling does not reach at all; the option database is the only way in.
    root.option_add("*TCombobox*Listbox.background", BG_INPUT)
    root.option_add("*TCombobox*Listbox.foreground", INK)
    root.option_add("*TCombobox*Listbox.selectBackground", PLUM)
    root.option_add("*TCombobox*Listbox.selectForeground", INK)
    root.option_add("*TCombobox*Listbox.borderWidth", 0)

    style.configure("TButton", background=BG_RAISED, foreground=INK_DIM,
                    bordercolor=LINE, focuscolor=BG_RAISED, padding=(13, 7),
                    font=fonts.small)
    style.map("TButton",
              background=[("pressed", LINE), ("active", BG_HOVER)],
              foreground=[("active", INK), ("disabled", INK_FAINT)])

    style.configure("Accent.TButton", background=PLUM, foreground="#ffffff",
                    padding=(22, 11), font=fonts.h2, bordercolor=PLUM,
                    lightcolor=PLUM, darkcolor=PLUM)
    style.map("Accent.TButton",
              background=[("pressed", "#5b21b6"), ("active", PURPLE),
                          ("disabled", BG_RAISED)],
              foreground=[("disabled", INK_FAINT)],
              lightcolor=[("disabled", BG_RAISED)],
              darkcolor=[("disabled", BG_RAISED)],
              bordercolor=[("disabled", BG_RAISED)])

    style.configure("TCheckbutton", background=BG_PANEL, foreground=INK_DIM,
                    focuscolor=BG_PANEL, font=fonts.small,
                    indicatorbackground=BG_INPUT, indicatorforeground=BG,
                    bordercolor=LINE, lightcolor=LINE, darkcolor=LINE)
    style.map("TCheckbutton",
              background=[("active", BG_PANEL)],
              foreground=[("selected", INK), ("active", INK),
                          ("disabled", INK_FAINT)],
              indicatorbackground=[("selected", PURPLE), ("!selected", BG_INPUT),
                                   ("disabled", BG_PANEL)],
              bordercolor=[("selected", PURPLE)])

    style.configure("TSeparator", background=LINE_SOFT)

    style.configure("Nova.Horizontal.TProgressbar", background=PURPLE,
                    troughcolor=BG_INPUT, bordercolor=BG_INPUT,
                    lightcolor=MAGENTA, darkcolor=PLUM, thickness=3)

    # clam draws a light 3D border on containers unless every one of these is
    # forced to the background colour.
    style.configure("Treeview", background=BG_PANEL, fieldbackground=BG_PANEL,
                    foreground=INK, rowheight=24, borderwidth=0, relief="flat",
                    bordercolor=BG_PANEL, lightcolor=BG_PANEL, darkcolor=BG_PANEL,
                    font=fonts.mono_small)
    style.configure("Treeview.Heading", background=BG_RAISED, foreground=INK_FAINT,
                    relief="flat", font=fonts.tiny, padding=(10, 7),
                    bordercolor=BG_RAISED, lightcolor=BG_RAISED, darkcolor=BG_RAISED)
    style.map("Treeview.Heading", background=[("active", LINE)])
    style.map("Treeview", background=[("selected", "#2a1a4d")],
              foreground=[("selected", INK)])

    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=LINE,
                        troughcolor=BG_PANEL, bordercolor=BG_PANEL,
                        lightcolor=BG_PANEL, darkcolor=BG_PANEL,
                        arrowcolor=INK_FAINT, width=10)
        style.map(f"{orient}.TScrollbar", background=[("active", PLUM)])

    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0,
                    bordercolor=BG, lightcolor=BG, darkcolor=BG)
    style.configure("TNotebook.Tab", background=BG, foreground=INK_FAINT,
                    padding=(18, 9), borderwidth=0, font=fonts.small,
                    bordercolor=BG, lightcolor=BG, darkcolor=BG)
    style.map("TNotebook.Tab",
              background=[("selected", BG_PANEL), ("active", LINE_SOFT)],
              foreground=[("selected", ORCHID), ("active", INK_DIM)])
    # clam's notebook draws a raised client border that no colour option
    # reaches. Replacing the layout with a bare client removes it outright.
    try:
        style.layout("TNotebook", [])
    except Exception:
        pass

    root.configure(bg=BG)
    return fonts


class Rule:
    """A 1px horizontal line that can carry a colour, unlike ttk.Separator."""

    def __new__(cls, master, colour: str = LINE_SOFT, height: int = 1, **kw):
        import tkinter as tk

        return tk.Frame(master, bg=colour, height=height, bd=0,
                        highlightthickness=0, **kw)
