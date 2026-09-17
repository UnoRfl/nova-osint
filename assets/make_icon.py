"""Generate assets/nova.ico without an imaging library.

An .ico is just a small header plus one or more DIBs, so writing the bytes
directly avoids a Pillow dependency for a file that changes about once a year.
Re-run with: python assets/make_icon.py
"""

from __future__ import annotations

import math
import struct
from pathlib import Path

SIZES = (16, 32, 48, 64, 128, 256)

BG = (0x07, 0x0B, 0x16)
RING = (0x2A, 0x40, 0x70)
SUN_CORE = (0xFF, 0xF3, 0xCC)
SUN = (0xFF, 0xD1, 0x66)
PLANET = (0x4C, 0xC9, 0xF0)
NOVA = (0xB5, 0x17, 0x9E)


def _mix(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b, strict=True))


def render(size: int) -> list[list[tuple[int, int, int]]]:
    px = [[BG] * size for _ in range(size)]
    cx = cy = (size - 1) / 2
    unit = size / 64.0

    def blend(x: int, y: int, colour, alpha: float) -> None:
        if 0 <= x < size and 0 <= y < size and alpha > 0:
            px[y][x] = _mix(px[y][x], colour, min(alpha, 1.0))

    def disc(x0: float, y0: float, r: float, colour, glow: float = 0.0) -> None:
        span = int(r + glow) + 2
        for y in range(int(y0 - span), int(y0 + span) + 1):
            for x in range(int(x0 - span), int(x0 + span) + 1):
                d = math.hypot(x - x0, y - y0)
                if d <= r:
                    blend(x, y, colour, 1.0)
                elif glow and d <= r + glow:
                    blend(x, y, colour, (1 - (d - r) / glow) ** 2 * 0.55)

    # Two tilted orbit ellipses.
    for rx_u, thickness in ((26.0, 1.1), (17.0, 1.0)):
        rx = rx_u * unit
        ry = rx * 0.40
        steps = max(180, size * 8)
        for i in range(steps):
            a = math.tau * i / steps
            blend(round(cx + rx * math.cos(a)), round(cy + ry * math.sin(a)),
                  RING, thickness)

    disc(cx, cy, 6.5 * unit, SUN, glow=6 * unit)
    disc(cx, cy, 3.6 * unit, SUN_CORE)
    disc(cx + 26 * unit * math.cos(0.7), cy + 26 * unit * 0.40 * math.sin(0.7),
         2.8 * unit, NOVA, glow=2 * unit)
    disc(cx + 17 * unit * math.cos(3.6), cy + 17 * unit * 0.40 * math.sin(3.6),
         2.4 * unit, PLANET, glow=1.8 * unit)
    return px


def dib(size: int) -> bytes:
    px = render(size)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    for y in range(size - 1, -1, -1):  # DIBs are stored bottom-up
        rows.append(b"".join(bytes((b, g, r, 255)) for r, g, b in px[y]))
    mask_stride = ((size + 31) // 32) * 4
    mask = b"\x00" * (mask_stride * size)
    return header + b"".join(rows) + mask


def main() -> None:
    images = [(s, dib(s)) for s in SIZES]
    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for size, data in images:
        dim = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in images:
        out += data
    path = Path(__file__).resolve().parent / "nova.ico"
    path.write_bytes(bytes(out))
    print(f"wrote {path} ({len(out) // 1024} KB, sizes: {', '.join(map(str, SIZES))})")


if __name__ == "__main__":
    main()
