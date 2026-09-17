"""The animated solar system, drawn on a Tk canvas.

Shares its planet table with the terminal art in ``core.art``, so the CLI and
the desktop app show the same system moving at the same relative speeds.

Everything is redrawn each tick rather than moved with ``coords``: at this item
count it is fast enough, and it keeps trail and glow handling trivial.
"""

from __future__ import annotations

import math
import random
import tkinter as tk

from ..core.art import PLANETS
from . import theme

TAU = math.tau

# Radii in core.art are terminal columns. Scaled up for pixels, the outermost
# body would leave the canvas, so orbits are expressed as a fraction of the
# available half-height instead and the table below only supplies the ordering.
PLANET_STYLE = {
    "mercury": {"orbit": 0.20, "size": 2.5, "colour": "#b8a8d0"},
    "venus": {"orbit": 0.36, "size": 4.0, "colour": theme.ORCHID},
    "earth": {"orbit": 0.54, "size": 4.5, "colour": theme.CYAN},
    "mars": {"orbit": 0.74, "size": 3.5, "colour": "#f472b6"},
    "nova": {"orbit": 0.95, "size": 5.0, "colour": theme.MAGENTA},
}

TRAIL = 14  # samples of trail behind each body


class OrbitCanvas(tk.Canvas):
    def __init__(self, master, width: int = 640, height: int = 380,
                 *, star_count: int = 130, show_rings: bool = True,
                 speed: float = 1.0, **kw) -> None:
        super().__init__(master, width=width, height=height, bg=theme.BG,
                         highlightthickness=0, bd=0, **kw)
        self.w, self.h = width, height
        self.speed = speed
        self.show_rings = show_rings
        self._t = 0.0
        self._job: str | None = None
        self._running = False

        rng = random.Random(20260917)
        self.stars = [
            (
                rng.random(),                 # x as a fraction of width
                rng.random(),                 # y as a fraction of height
                rng.choice([0.5, 0.5, 0.7, 1.0, 1.4]),
                rng.uniform(0.25, 0.95),      # base brightness
                rng.uniform(0, TAU),          # twinkle phase
            )
            for _ in range(star_count)
        ]
        self.bind("<Configure>", self._on_resize)

    # ------------------------------------------------------------------ control

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._tick()

    def stop(self) -> None:
        self._running = False
        if self._job is not None:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None

    def destroy(self) -> None:
        self.stop()
        super().destroy()

    def _on_resize(self, event: tk.Event) -> None:
        self.w, self.h = event.width, event.height
        if not self._running:
            self.draw(self._t)

    def _tick(self) -> None:
        if not self._running:
            return
        self._t += 0.030 * self.speed
        self.draw(self._t)
        # ~33fps. Tk redraws get janky much above that and it buys nothing.
        self._job = self.after(30, self._tick)

    # ------------------------------------------------------------------ drawing

    def draw(self, t: float) -> None:
        self.delete("all")
        cx, cy = self.w / 2, self.h / 2
        span = min(self.w * 0.46, self.h * 0.46)

        self._stars(t)
        if self.show_rings:
            self._rings(cx, cy, span)
        self._sun(cx, cy, t)
        self._bodies(cx, cy, span, t)

    def _stars(self, t: float) -> None:
        for fx, fy, size, base, phase in self.stars:
            x, y = fx * self.w, fy * self.h
            # A slow sine per star, each with its own phase, so the field
            # shimmers instead of pulsing in unison.
            brightness = base * (0.62 + 0.38 * math.sin(t * 1.4 + phase))
            colour = theme.blend(theme.INK, theme.BG, 1 - min(brightness, 1.0))
            self.create_oval(x - size, y - size, x + size, y + size,
                             fill=colour, outline="")

    def _rings(self, cx: float, cy: float, span: float) -> None:
        for name, *_ in PLANETS:
            style = PLANET_STYLE[name]
            rx = span * style["orbit"]
            ry = rx * 0.42  # the system is viewed at an angle, not top-down
            self.create_oval(cx - rx, cy - ry, cx + rx, cy + ry,
                             outline=theme.blend(theme.VIOLET, theme.BG, 0.66),
                             width=1, dash=(1, 5))

    def _sun(self, cx: float, cy: float, t: float) -> None:
        pulse = 1.0 + 0.05 * math.sin(t * 2.2)
        # Concentric rings blended toward the background stand in for a glow,
        # which is the only way to fake alpha on a Tk canvas.
        for i in range(9, 0, -1):
            r = i * 3.6 * pulse
            self.create_oval(cx - r, cy - r, cx + r, cy + r,
                             fill=theme.blend(theme.GOLD, theme.BG, 1 - (0.10 / i) * 3.2),
                             outline="")
        r = 5.5 * pulse
        self.create_oval(cx - r, cy - r, cx + r, cy + r, fill="#fff3cc", outline="")

    def _bodies(self, cx: float, cy: float, span: float, t: float) -> None:
        for name, _radius, speed, phase, _glyph, _colour in PLANETS:
            style = PLANET_STYLE[name]
            rx = span * style["orbit"]
            ry = rx * 0.42
            colour = style["colour"]

            for k in range(TRAIL, 0, -1):
                a = t * speed + phase - k * 0.045
                fade = 1 - (k / (TRAIL + 2))
                size = style["size"] * 0.45 * fade
                x, y = cx + rx * math.cos(a), cy + ry * math.sin(a)
                self.create_oval(x - size, y - size, x + size, y + size,
                                 fill=theme.blend(colour, theme.BG, 1 - fade * 0.55),
                                 outline="")

            a = t * speed + phase
            x, y = cx + rx * math.cos(a), cy + ry * math.sin(a)
            s = style["size"]
            # A halo one shade down from the body reads as atmosphere and stops
            # the smaller planets disappearing into the starfield.
            self.create_oval(x - s * 1.9, y - s * 1.9, x + s * 1.9, y + s * 1.9,
                             fill=theme.blend(colour, theme.BG, 0.78), outline="")
            self.create_oval(x - s, y - s, x + s, y + s, fill=colour, outline="")
            self.create_oval(x - s * 0.4, y - s * 0.4, x + s * 0.4, y + s * 0.4,
                             fill=theme.blend(colour, "#ffffff", 0.55), outline="")

            if name == "nova":
                self.create_text(x + s + 9, y - 1, text="NOVA", anchor="w",
                                 fill=theme.blend(colour, theme.BG, 0.35),
                                 font=("Consolas", 7))


WORDMARK = [
    "███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ",
    "████╗  ██║██╔═══██╗██║   ██║██╔══██╗",
    "██╔██╗ ██║██║   ██║██║   ██║███████║",
    "██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║",
    "██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║",
    "╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝",
]


class Wordmark(tk.Canvas):
    """The block-letter NOVA, with the same nebula gradient as the terminal."""

    def __init__(self, master, scale: int = 9, **kw) -> None:
        width = int(len(WORDMARK[0]) * scale * 0.60) + 8
        height = len(WORDMARK) * scale + 8
        super().__init__(master, width=width, height=height, bg=theme.BG,
                         highlightthickness=0, bd=0, **kw)
        ramp = theme.NEBULA
        for i, line in enumerate(WORDMARK):
            self.create_text(
                4, 4 + i * scale, text=line, anchor="nw",
                fill=ramp[min(i * len(ramp) // len(WORDMARK), len(ramp) - 1)],
                font=("Consolas", scale - 2),
            )
