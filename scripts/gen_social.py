#!/usr/bin/env python3
"""Generate .github/social-preview.png (and its light twin): the repository
card - scanner-eye badge, wordmark, tagline, and one live-looking scan
line. Renders in the EXPLOIT pairing (lavender + crimson is the only
accent on this canvas); the mode banners carry the other pairings.

Deterministic: fixed layout, no clock, no randomness.

Usage: python3 scripts/gen_social.py
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).parent))
from theme import (MONO, MONO_B, SANS_B, palette)


def hx(c: str) -> tuple:
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def badge(d: ImageDraw.ImageDraw, x: int, y: int, size: int, p: dict) -> None:
    """The scanner-eye mark, raster form: byte matrix, scan arcs, core."""
    s = size
    d.rounded_rectangle((x, y, x + s, y + s), radius=s // 5, fill=hx(p["panel"]),
                        outline=hx(p["edge"]), width=3)
    cx, cy = x + s // 2, y + s // 2
    # byte matrix fading outward
    cell = s // 11
    for row in range(9):
        for col in range(9):
            if (row * 9 + col) % 3 == 0:
                continue
            bx, by = x + s * 0.08 + col * cell, y + s * 0.08 + row * cell
            if (bx - cx) ** 2 + (by - cy) ** 2 < (s * 0.33) ** 2:
                continue
            d.rounded_rectangle((bx, by, bx + cell * 0.55, by + cell * 0.55),
                                radius=2, fill=hx(p["edge"]))
    # scan arcs: two lavender sweeps + the accent sweep
    r = s * 0.36
    d.arc((cx - r, cy - r, cx + r, cy + r), start=-95, end=20, fill=hx(p["lavender"]), width=max(4, s // 26))
    d.arc((cx - r, cy - r, cx + r, cy + r), start=115, end=175, fill=hx(p["lavender"]), width=max(4, s // 26))
    r2 = s * 0.30
    d.arc((cx - r2, cy - r2, cx + r2, cy + r2), start=150, end=250, fill=hx(p["accent"]), width=max(3, s // 38))
    d.ellipse((cx - s * 0.075, cy - s * 0.075, cx + s * 0.075, cy + s * 0.075), fill=hx(p["accent"]))
    d.ellipse((cx - s * 0.02, cy - s * 0.02, cx + s * 0.02, cy + s * 0.02), fill=hx(p["panel"]))


def render(p: dict, out: Path) -> None:
    W, H = 1280, 640
    img = Image.new("RGB", (W, H), hx(p["canvas"]))
    d = ImageDraw.Draw(img)

    badge(d, 84, 164, 312, p)

    mono_b = lambda s: ImageFont.truetype(MONO_B, s)
    sans_b = lambda s: ImageFont.truetype(SANS_B, s)

    d.text((452, 168), "openre", font=mono_b(150), fill=hx(p["text"]))
    d.text((458, 348), "one binary. every target.", font=sans_b(40), fill=hx(p["lavender"]))

    # a live-looking assessment line: lavender finding, one accent severity
    y = 452
    d.rounded_rectangle((452, y - 18, 1196, y + 96), radius=14, fill=hx(p["panel"]), outline=hx(p["edge"]), width=2)
    mono = ImageFont.truetype(MONO, 28)
    d.text((484, y), "$ openre scan https://target", font=mono, fill=hx(p["dim"]))
    d.text((484, y + 44), "28 checks  6 findings  ", font=mono, fill=hx(p["text"]))
    tail = d.textlength("28 checks  6 findings  ", font=mono)
    d.text((484 + tail, y + 44), "poc ready", font=mono, fill=hx(p["accent"]))

    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, optimize=True)
    print(f"wrote {out} ({out.stat().st_size // 1024} KiB)")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    render(palette("exploit", light=False), root / ".github" / "social-preview.png")
    render(palette("exploit", light=True), root / ".github" / "social-preview-light.png")


if __name__ == "__main__":
    main()
