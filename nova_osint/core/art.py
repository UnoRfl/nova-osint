"""ASCII art and colour for the console.

Every banner is plain text with an accompanying colour ramp, so the same art
works in a rich terminal, a dumb terminal, and a log file. Nothing here is
load-bearing: ``--quiet`` skips all of it and the scan output is identical.

The theme is orbital - NOVA sweeps a target the way a survey telescope sweeps a
patch of sky, so modules are "instruments", discovered targets are "bodies in
orbit", and the spinner is a satellite going round.
"""

from __future__ import annotations

import random
import shutil

try:
    from rich.console import Console
    from rich.text import Text

    HAVE_RICH = True
except Exception:  # pragma: no cover
    HAVE_RICH = False

VERSION = "1.0.0"

# Cyan -> violet -> magenta: a nebula ramp that survives both light and dark
# terminal themes because it never goes near the background colours.
NEBULA = ["#4cc9f0", "#4895ef", "#4361ee", "#5f3dc4", "#7209b7", "#b5179e"]
ORBIT_DIM = "#5a6b8c"
STAR = "#e8ecff"

# The ellipse is a real one: dots mirrored about column 20, with the satellite
# (●) sitting on the orbit's right vertex. Getting it symmetrical matters - a
# lopsided ring is the first thing the eye picks up.
MAIN = r"""
   ˙                                  ✦                            ·
              ·  ·  ·  ·  ·
           ·                 ·        ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
  ✦      ·           ◉          ●    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
           ·                 ·        ██╔██╗ ██║██║   ██║██║   ██║███████║
              ·  ·  ·  ·  ·           ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
        ·                       ˙     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
             ·          ✦             ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
                                       o p e n   s o u r c e   i n t e l
                                              b y   u n o
"""

#: Section banners, keyed by target type. Short words keep them terminal-width.
SECTIONS = {
    "username": (
        r"""
██╗   ██╗███████╗███████╗██████╗
██║   ██║██╔════╝██╔════╝██╔══██╗
██║   ██║███████╗█████╗  ██████╔╝
██║   ██║╚════██║██╔══╝  ██╔══██╗
╚██████╔╝███████║███████╗██║  ██║
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝""",
        "handle sweep · one name across every platform in the catalogue",
    ),
    "email": (
        r"""
███╗   ███╗ █████╗ ██╗██╗
████╗ ████║██╔══██╗██║██║
██╔████╔██║███████║██║██║
██║╚██╔╝██║██╔══██║██║██║
██║ ╚═╝ ██║██║  ██║██║███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝""",
        "comet trail · structure, delivery path, breaches and linked profiles",
    ),
    "domain": (
        r"""
██╗  ██╗ ██████╗ ███████╗████████╗
██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
███████║██║   ██║███████╗   ██║
██╔══██║██║   ██║╚════██║   ██║
██║  ██║╚██████╔╝███████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝""",
        "gravity well · registration, DNS, mail posture and the subdomain field",
    ),
    "ip": (
        r"""
███╗   ██╗ ██████╗ ██████╗ ███████╗
████╗  ██║██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║██║   ██║██║  ██║█████╗
██║╚██╗██║██║   ██║██║  ██║██╔══╝
██║ ╚████║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝""",
        "fixed point · geolocation, ASN, reverse DNS and last observed surface",
    ),
    "phone": (
        r"""
██████╗ ██╗ █████╗ ██╗
██╔══██╗██║██╔══██╗██║
██║  ██║██║███████║██║
██║  ██║██║██╔══██║██║
██████╔╝██║██║  ██║███████╗
╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝""",
        "beacon · numbering plan, carrier of record, region and line type",
    ),
    "url": (
        r"""
██╗     ██╗███╗   ██╗██╗  ██╗
██║     ██║████╗  ██║██║ ██╔╝
██║     ██║██╔██╗ ██║█████╔╝
██║     ██║██║╚██╗██║██╔═██╗
███████╗██║██║ ╚████║██║  ██╗
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝""",
        "trajectory · one address, followed to wherever it actually lands",
    ),
}

#: A glyph per module, so a long report stays scannable at a glance.
GLYPHS = {
    "whois": "⬡", "dns": "◉", "mailsec": "✉", "subdomains": "❋",
    "headers": "▣", "exposed": "⌘", "wayback": "↺", "breaches": "☄",
    "pwned": "☄", "username": "✦", "github": "⬢", "gists": "⬣",
    "email": "✉", "ip": "◈", "abuseipdb": "⚠", "phone": "☎", "dorks": "⌖",
}

#: The satellite goes round while the instruments report back.
SPINNER = ("◜", "◠", "◝", "◞", "◡", "◟")

QUIET_SKY = r"""
              ·        ˙          ·
        ˙          ·        ✦            ·
              ·        the sky came back empty
        ·          ˙          ·        ˙
"""


STARS = "·˙✦.oO◉"
ORBIT = "/\\|_-"


def _style_of(ch: str, base: str) -> str:
    if ch in STARS:
        return STAR
    if ch in ORBIT:
        return ORBIT_DIM
    return base


def _gradient(line: str, index: int, total: int) -> Text:
    """Colour one line, emitting one escape sequence per run of same-styled
    characters rather than per character - a 36-column banner is otherwise
    several kilobytes of ANSI for eight lines of art."""
    base = NEBULA[min(index * len(NEBULA) // max(total, 1), len(NEBULA) - 1)]
    text = Text()
    run, run_style = "", _style_of(line[0], base) if line else base
    for ch in line:
        style = _style_of(ch, base)
        if style == run_style:
            run += ch
        else:
            text.append(run, style=run_style)
            run, run_style = ch, style
    if run:
        text.append(run, style=run_style)
    return text


def render(block: str, console: Console | None = None) -> str:
    """Colour an art block into an ANSI string."""
    lines = block.strip("\n").splitlines()
    if not HAVE_RICH:
        return "\n".join(lines) + "\n"
    import io

    buf = io.StringIO()
    out = Console(file=buf, width=max(shutil.get_terminal_size((100, 24)).columns, 80),
                  force_terminal=True)
    for i, line in enumerate(lines):
        out.print(_gradient(line, i, len(lines)))
    return buf.getvalue()


WORDMARK = r"""
        ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
       ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
       ██╔██╗ ██║██║   ██║██║   ██║███████║
       ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
       ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
         o p e n   s o u r c e   i n t e l   ·   b y   u n o
"""

TAGLINES = (
    "every public orbit, one sweep",
    "one target in, the whole sky out",
    "passive by default, loud only when told",
    "survey the footprint before someone else does",
)


def _dim_line(text: str, width: int = 100) -> str:
    if not HAVE_RICH:
        return text + "\n"
    import io

    buf = io.StringIO()
    Console(file=buf, force_terminal=True, width=width).print(f"[{ORBIT_DIM}]{text}[/]")
    return buf.getvalue()


def banner(wordmark_only: bool = False) -> str:
    """The opening art.

    ``wordmark_only`` drops the static orbit, for when the animated scene has
    just played and a second ring underneath it would be noise.
    """
    block = WORDMARK if wordmark_only else MAIN
    return render(block) + _dim_line(f"  NOVA v{VERSION} by uno  ·  {random.choice(TAGLINES)}")


def section(target_type: str) -> str:
    entry = SECTIONS.get(target_type)
    if not entry:
        return ""
    block, subtitle = entry
    return render(block) + _dim_line(f"  {subtitle}", width=110)


def glyph(module: str) -> str:
    return GLYPHS.get(module, "•")


# --------------------------------------------------------------------- orbits

#: name, orbital radius (columns), angular speed, phase, glyph, colour.
#: Speeds are loosely Keplerian - inner bodies come round faster - because a
#: system where everything moves at the same rate reads as a spinning wheel
#: rather than a solar system.
PLANETS = (
    ("mercury", 7.0, 2.30, 0.0, "◦", "#c9b8a8"),
    ("venus", 10.0, 1.55, 1.9, "○", "#f2c078"),
    ("earth", 14.5, 1.10, 3.4, "◉", "#4cc9f0"),
    ("mars", 19.5, 0.82, 0.7, "●", "#e5634d"),
    ("nova", 25.0, 0.55, 2.4, "✦", "#b5179e"),
)

SUN = "☀"
SUN_COLOUR = "#ffd166"
#: Terminal cells are about twice as tall as they are wide, so a circle drawn
#: with equal x and y radii comes out as a tall oval. This also has to keep the
#: outermost ring inside the canvas: 25 * 0.33 = 8.3 rows either side of centre.
ASPECT = 0.33

#: Fixed samples per ring, not "more samples for bigger rings". Sampling an
#: ellipse by angle piles points up along its flat top and bottom, so a
#: radius-proportional count turns the outer orbits into solid bands.
RING_SAMPLES = 26

STARFIELD_SEED = 20260917


class OrbitScene:
    """A tiny solar system rendered into a character grid.

    Frames are computed from the planets' angles rather than stored, so the
    animation loops seamlessly and costs nothing to ship.
    """

    def __init__(self, width: int = 72, height: int = 19) -> None:
        self.w = width
        self.h = height
        self.cx = width // 2
        self.cy = height // 2
        rng = random.Random(STARFIELD_SEED)
        # Background stars use characters the orbit rings never use, so the
        # two layers stay readable on top of each other.
        self.stars = [
            (rng.randrange(width), rng.randrange(height), rng.choice("˙.˙✧"))
            for _ in range(int(width * height * 0.022))
        ]

    def _blank(self) -> list[list[tuple[str, str]]]:
        grid = [[(" ", "")] * self.w for _ in range(self.h)]
        for x, y, ch in self.stars:
            grid[y][x] = (ch, "#39415c")
        return grid

    def _plot(self, grid, x: float, y: float, ch: str, style: str) -> None:
        col, row = int(round(x)), int(round(y))
        if 0 <= row < self.h and 0 <= col < self.w:
            grid[row][col] = (ch, style)

    def frame(self, t: float) -> list[list[tuple[str, str]]]:
        import math

        grid = self._blank()

        # Orbit paths first, so the bodies always draw on top of them.
        for _, radius, _, _, _, _ in PLANETS:
            for i in range(RING_SAMPLES):
                a = 2 * math.pi * i / RING_SAMPLES
                self._plot(
                    grid,
                    self.cx + radius * math.cos(a),
                    self.cy + radius * ASPECT * math.sin(a),
                    "·",
                    ORBIT_DIM,
                )

        self._plot(grid, self.cx, self.cy, SUN, f"bold {SUN_COLOUR}")

        for _, radius, speed, phase, ch, colour in PLANETS:
            a = t * speed + phase
            x = self.cx + radius * math.cos(a)
            y = self.cy + radius * ASPECT * math.sin(a)
            # A short trail behind each body sells the direction of travel.
            for k in (3, 2, 1):
                ta = a - k * 0.055
                self._plot(
                    grid,
                    self.cx + radius * math.cos(ta),
                    self.cy + radius * ASPECT * math.sin(ta),
                    "·",
                    colour,
                )
            self._plot(grid, x, y, ch, f"bold {colour}")
        return grid

    def render(self, t: float) -> str:
        grid = self.frame(t)
        if not HAVE_RICH:
            return "\n".join("".join(ch for ch, _ in row).rstrip() for row in grid)
        import io

        buf = io.StringIO()
        console = Console(file=buf, width=self.w + 2, force_terminal=True)
        for row in grid:
            text = Text()
            run, style = "", row[0][1]
            for ch, st in row:
                if st == style:
                    run += ch
                else:
                    text.append(run, style=style or None)
                    run, style = ch, st
            text.append(run, style=style or None)
            console.print(text)
        return buf.getvalue()


def animate(stream, seconds: float = 2.6, fps: int = 18) -> None:
    """Play the orbit scene in place, then leave the final frame on screen.

    Silently does nothing when the stream is not a terminal, so piping the
    output to a file or another process is unaffected.
    """
    if not getattr(stream, "isatty", lambda: False)():
        return
    import time

    scene = OrbitScene()
    frames = max(1, int(seconds * fps))
    try:
        stream.write("\x1b[?25l")  # hide the cursor while it redraws
        for i in range(frames):
            stream.write(scene.render(i / fps * 1.9))
            stream.flush()
            time.sleep(1 / fps)
            if i < frames - 1:
                stream.write(f"\x1b[{scene.h}A")
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        stream.write("\x1b[?25h")
        stream.flush()


def still(t: float = 1.2) -> str:
    """One frame of the orbit scene, for non-interactive output."""
    return OrbitScene().render(t)


def intro(stream, animated: bool = True) -> None:
    """Play (or print) the opening, then the wordmark, onto ``stream``."""
    if animated and getattr(stream, "isatty", lambda: False)():
        animate(stream)
        stream.write(banner(wordmark_only=True))
    else:
        stream.write(banner())


def gallery() -> str:
    """Everything NOVA can draw, for ``nova art``."""
    parts = [still(), banner(wordmark_only=True)]
    for name in SECTIONS:
        parts.append(section(name))
        parts.append("")
    parts.append(render(QUIET_SKY))
    return "\n".join(parts)
