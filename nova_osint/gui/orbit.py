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

#: How far the orbits are squashed vertically. 0.42 is the three-quarter view
#: the boot screen uses; 1.0 looks straight down on the system and the orbits
#: come out as true circles.
TILT_ANGLED = 0.42
TILT_TOP_DOWN = 1.0

#: Above this half-span the absolute pixel sizes below (sun glow, body radii)
#: are used as written; below it they shrink, otherwise a 44px spinner is
#: mostly sun and the inner planet orbits inside it. Deliberately well under
#: the boot screen's span so only the genuinely small instances are touched,
#: and floored so the bodies never drop below a pixel.
REFERENCE_SPAN = 70.0
MIN_SCALE = 0.42


class OrbitCanvas(tk.Canvas):
    def __init__(self, master, width: int = 640, height: int = 380,
                 *, star_count: int = 130, show_rings: bool = True,
                 speed: float = 1.0, show_label: bool | None = None,
                 tilt: float = TILT_ANGLED, **kw) -> None:
        super().__init__(master, width=width, height=height, bg=theme.BG,
                         highlightthickness=0, bd=0, **kw)
        self.w, self.h = width, height
        self.speed = speed
        self.show_rings = show_rings
        self.tilt = tilt
        #: Draw the "NOVA" tag beside the lead planet. Defaults to "only if it
        #: fits": at status-bar size the label is clipped to a couple of stray
        #: letters, which reads as a rendering fault rather than as branding.
        self.show_label = show_label if show_label is not None else width >= 120
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
        # Absolute pixel sizes shrink with the canvas, with a floor so the
        # bodies stay visible rather than dropping below a pixel.
        self._scale = max(MIN_SCALE, min(1.0, span / REFERENCE_SPAN))

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
        # A dashed ring is drawn from a fixed number of dashes, so on a small
        # canvas the gaps close up and the ring reads as a solid disc outline.
        # Dash the wide ones, leave the tight ones plain.
        dash = (1, 5) if span > 60 else None
        for name, *_ in PLANETS:
            style = PLANET_STYLE[name]
            rx = span * style["orbit"]
            ry = rx * self.tilt
            self.create_oval(cx - rx, cy - ry, cx + rx, cy + ry,
                             outline=theme.blend(theme.VIOLET, theme.BG, 0.66),
                             width=1, **({"dash": dash} if dash else {}))

    def _sun(self, cx: float, cy: float, t: float) -> None:
        pulse = (1.0 + 0.05 * math.sin(t * 2.2)) * self._scale
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
            ry = rx * self.tilt
            colour = style["colour"]
            body = style["size"] * self._scale

            for k in range(TRAIL, 0, -1):
                a = t * speed + phase - k * 0.045
                fade = 1 - (k / (TRAIL + 2))
                size = body * 0.45 * fade
                x, y = cx + rx * math.cos(a), cy + ry * math.sin(a)
                self.create_oval(x - size, y - size, x + size, y + size,
                                 fill=theme.blend(colour, theme.BG, 1 - fade * 0.55),
                                 outline="")

            a = t * speed + phase
            x, y = cx + rx * math.cos(a), cy + ry * math.sin(a)
            s = body
            # A halo one shade down from the body reads as atmosphere and stops
            # the smaller planets disappearing into the starfield.
            self.create_oval(x - s * 1.9, y - s * 1.9, x + s * 1.9, y + s * 1.9,
                             fill=theme.blend(colour, theme.BG, 0.78), outline="")
            self.create_oval(x - s, y - s, x + s, y + s, fill=colour, outline="")
            self.create_oval(x - s * 0.4, y - s * 0.4, x + s * 0.4, y + s * 0.4,
                             fill=theme.blend(colour, "#ffffff", 0.55), outline="")

            if name == "nova" and self.show_label:
                self.create_text(x + s + 9, y - 1, text="NOVA", anchor="w",
                                 fill=theme.blend(colour, theme.BG, 0.35),
                                 font=("Consolas", 7))


class RingedPlanet(tk.Canvas):
    """A small ringed world with a moon going round it, for the app header.

    The header used to carry a shrunk copy of the solar system. At 140x72 the
    five orbits overlapped the sun, the planets landed on top of one another
    and the "NOVA" tag was drawn across the middle of the result, so the
    brightest spot in the window read as a smudge. One object with one moon is
    what a strip that size can actually hold.

    The ring is drawn in two halves with the planet between them, which is the
    only reason it reads as a ring around something rather than an ellipse
    behind it. The moon does the same: it goes behind the planet on the far
    half of its orbit and in front on the near half.
    """

    def __init__(self, master, width: int = 140, height: int = 72,
                 *, star_count: int = 30, speed: float = 1.0, **kw) -> None:
        super().__init__(master, width=width, height=height, bg=theme.BG,
                         highlightthickness=0, bd=0, **kw)
        self.w, self.h = width, height
        self.speed = speed
        self._t = 0.0
        self._job: str | None = None
        self._running = False

        rng = random.Random(626)
        self.stars = [
            (
                rng.random(),                  # x as a fraction of width
                rng.random(),                  # y as a fraction of height
                rng.choice([0.6, 0.6, 0.9, 1.3]),
                rng.uniform(0.20, 0.80),       # base brightness
                rng.uniform(0, TAU),           # twinkle phase
                rng.uniform(0.006, 0.022),     # drift, fractions of width/second
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
        self._job = self.after(30, self._tick)

    # ------------------------------------------------------------------ drawing

    def draw(self, t: float) -> None:
        self.delete("all")
        cx, cy = self.w / 2, self.h / 2
        # The planet is sized off the short side so it never touches top or
        # bottom; the ring and the moon spread into the width that is going
        # spare, which is what makes the strip feel filled rather than padded.
        pr = self.h * 0.21
        ring_rx, ring_ry = pr * 2.35, pr * 0.62
        moon_rx, moon_ry = self.w * 0.40, self.h * 0.21

        angle = t * 0.62
        # sin > 0 is the near half of the orbit: y grows downward, so that is
        # the side of the planet closest to the viewer.
        moon_in_front = math.sin(angle) > 0
        mx = cx + moon_rx * math.cos(angle)
        my = cy + moon_ry * math.sin(angle)

        self._stars(t)
        self._ring(cx, cy, ring_rx, ring_ry, back=True)
        if not moon_in_front:
            self._moon(mx, my, pr, front=False)
        self._planet(cx, cy, pr, t)
        self._ring(cx, cy, ring_rx, ring_ry, back=False)
        if moon_in_front:
            self._moon(mx, my, pr, front=True)

    def _stars(self, t: float) -> None:
        for fx, fy, size, base, phase, drift in self.stars:
            # Wrapping rather than respawning: a star that comes back at a new
            # random height reads as a glitch, one that comes back where it
            # left reads as the field moving past.
            x = ((fx - drift * t) % 1.0) * self.w
            y = fy * self.h
            bright = base * (0.55 + 0.45 * math.sin(t * 1.7 + phase))
            colour = theme.blend(theme.INK, theme.BG, 1 - min(bright, 1.0))
            self.create_oval(x - size, y - size, x + size, y + size,
                             fill=colour, outline="")

    def _ring(self, cx: float, cy: float, rx: float, ry: float,
              back: bool) -> None:
        """Half the ring. Tk arcs measure degrees anticlockwise from east, and
        on a canvas y grows downward, so 0..180 is the *upper* half - which is
        the far side of a ring seen slightly from above.
        """
        start, extent = (0, 180) if back else (180, 180)
        for scale, colour, amount in ((1.00, theme.ORCHID, 0.30),
                                      (0.90, theme.MAGENTA, 0.45),
                                      (0.78, theme.VIOLET, 0.55)):
            ex, ey = rx * scale, ry * scale
            self.create_arc(cx - ex, cy - ey, cx + ex, cy + ey,
                            start=start, extent=extent, style=tk.ARC,
                            outline=theme.blend(colour, theme.BG,
                                                amount if back else amount - 0.18),
                            width=1)

    def _planet(self, cx: float, cy: float, pr: float, t: float) -> None:
        # A faint halo first, so the planet sits in the starfield rather than
        # on top of it.
        for i in range(4, 0, -1):
            r = pr * (1 + i * 0.16)
            self.create_oval(cx - r, cy - r, cx + r, cy + r,
                             fill=theme.blend(theme.PURPLE, theme.BG, 1 - 0.09 / i),
                             outline="")
        self.create_oval(cx - pr, cy - pr, cx + pr, cy + pr,
                         fill=theme.blend(theme.VIOLET, theme.BG, 0.30), outline="")

        # Bands drifting across the face stand in for rotation. Each is an oval
        # squashed flat and clipped to the disc by keeping it well inside.
        for k, (offset, squash, colour) in enumerate((
            (-0.42, 0.13, theme.ORCHID),
            (0.02, 0.17, theme.MAGENTA),
            (0.46, 0.11, theme.PURPLE),
        )):
            # Everything is sized off the disc's half-chord at this latitude,
            # and the band plus its drift is kept inside it. Sized off the
            # radius instead, a band near the equator reached past the rim on
            # the far swing of its drift and punched a notch out of the edge -
            # which at header size looks like a rendering fault, not a cloud.
            half_chord = pr * math.sqrt(max(0.0, 1 - offset * offset))
            drift = math.sin(t * 0.5 + k * 1.3) * half_chord * 0.17
            by = cy + pr * offset
            bw = half_chord * 0.76
            bh = pr * squash
            self.create_oval(cx - bw + drift, by - bh, cx + bw + drift, by + bh,
                             fill=theme.blend(colour, theme.BG, 0.42), outline="")

        # No specular highlight and no terminator. Both were tried: a bright
        # spot on the lit side reads as a gold sticker stuck to the planet, and
        # a shaded chord across the unlit side takes a bite out of the disc at
        # this size. The halo above and the bands are enough to make it round.
        #
        # One soft rim instead, just inside the edge, which is cheap and does
        # not cross the face.
        rim = pr * 0.97
        self.create_oval(cx - rim, cy - rim, cx + rim, cy + rim,
                         outline=theme.blend(theme.ORCHID, theme.BG, 0.45),
                         width=1)

    def _moon(self, x: float, y: float, pr: float, front: bool) -> None:
        # Smaller on the far half of the orbit, which is most of what sells the
        # depth - the ring occlusion does the rest.
        r = pr * (0.22 if front else 0.16)
        # A halo of two faint rings, not one opaque disc: a filled halo at this
        # size reads as a second, larger body with a bright dot on it.
        for i in (2, 1):
            g = r * (1 + i * 0.7)
            self.create_oval(x - g, y - g, x + g, y + g,
                             fill=theme.blend(theme.CYAN, theme.BG, 1 - 0.13 / i),
                             outline="")
        self.create_oval(x - r, y - r, x + r, y + r,
                         fill=theme.blend(theme.CYAN, theme.BG,
                                          0.05 if front else 0.42), outline="")


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
