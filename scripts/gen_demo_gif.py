#!/usr/bin/env python3
"""Generate docs/demo.gif: an animated terminal running a REAL standard
scan against the deliberately-vulnerable fixture that ships in
crates/openre-scan/tests/test_server.py. Every line below is genuine
output of `openre scan standard http://localhost:8080` (15 checks, 17
findings, 1.31s) - captured, not invented.

Rendered in the RECON mode pairing (lavender + amber, one accent).
Deterministic: fixed frame schedule.

Usage: .venv-ish python with Pillow. python3 scripts/gen_demo_gif.py
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from theme import MONO, MONO_B, SANS_B, palette

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "demo.gif"

W, H = 980, 700
PAD = 30
LH = 26

# genuine scan output, in order
PROGRESS = [
    ("Server Header Disclosure", "info"),
    ("X-Powered-By Header Disclosure", "low"),
    ("Not Using HTTPS", "high"),
    ("Missing X-Frame-Options Header", "medium"),
    ("Missing X-Content-Type-Options Header", "medium"),
    ("Missing Strict-Transport-Security Header", "high"),
    ("Missing Content-Security-Policy Header", "high"),
    ("Missing Referrer-Policy Header", "medium"),
    ("Missing Permissions-Policy Header", "low"),
    ("Missing Cross-Origin-Opener-Policy Header", "low"),
    ("Missing Cross-Origin-Resource-Policy Header", "low"),
    ("Missing Content-Security-Policy", "high"),
    ("Server Version Disclosure", "low"),
    ("robots.txt Found", "info"),
    ("Password Field in GET Form", "high"),
]

# the genuine summary block
SUMMARY = [
    ("Target:   http://localhost:8080", "text"),
    ("Profile:  standard", "text"),
    ("Duration: 1.31s", "text"),
    ("Checks:   15    Findings: 17", "text"),
    ("", "text"),
    ("HIGH  x5   MEDIUM x3", "accent"),
    ("LOW   x5   INFO   x4", "lavender"),
    ("", "text"),
    ("poc: openre exploit <finding-id>", "dim"),
]


def span(draw, x, y, text, font, color):
    draw.text((x, y), text, font=font, fill=color)
    return x + draw.textlength(text, font=font)


def frame(d, lines_done, summary_shown, p):
    d.rounded_rectangle((0, 0, W - 1, H - 1), radius=14, fill=hxc(p["panel"]),
                        outline=hxc(p["edge"]), width=2)
    for i, c in enumerate([(255, 95, 86), hxc(p["accent"]), hxc(p["lavender"])]):
        d.ellipse((22 + i * 26, 18, 38 + i * 26, 34), fill=c)
    title = "openre - one binary, every target"
    tw = d.textlength(title, font=ImageFont.truetype(SANS_B, 15))
    d.text(((W - tw) / 2, 20), title, font=ImageFont.truetype(SANS_B, 15), fill=hxc(p["dim"]))
    d.line((0, 52, W, 52), fill=hxc(p["edge"]), width=1)

    y = 76
    f19 = ImageFont.truetype(MONO, 19)
    span(d, PAD, y, "$ ", f19, hxc(p["accent"]))
    span(d, PAD + 22, y, "openre scan standard http://localhost:8080", f19, hxc(p["text"]))
    y += LH + 8
    span(d, PAD, y, "scanning the fixture from crates/openre-scan/tests/",
         ImageFont.truetype(MONO, 14), hxc(p["dim"]))
    y += LH + 8

    f16 = ImageFont.truetype(MONO, 16)
    for i, (name, sev) in enumerate(PROGRESS[:lines_done]):
        d.text((PAD, y), "✓", font=f16, fill=hxc(p["lavender"]))
        d.text((PAD + 22, y), name, font=f16, fill=hxc(p["text"]))
        d.text((PAD + 480, y), f"[{sev}]", font=f16, fill=hxc(p["dim"]))
        y += LH - 4

    if summary_shown:
        y += 6
        for text, role in SUMMARY:
            color = {"text": p["text"], "accent": p["accent"],
                     "lavender": p["lavender"], "dim": p["dim"]}[role]
            d.text((PAD, y), text, font=f16, fill=hxc(color))
            y += LH - 2


def hxc(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def build_frames():
    p = palette("recon", light=False)
    frames = []
    steps = [0] * 4                                  # command hold
    steps += list(range(1, len(PROGRESS) + 1, 2))    # checks tick (2/frame)
    steps += [len(PROGRESS)] * 3                     # settle
    steps += [-1] * 3                                # summary marker
    steps += [-2] * 26                               # summary + hold
    for s in steps:
        img = Image.new("RGB", (W, H), hxc(p["canvas"]))
        d = ImageDraw.Draw(img)
        if s == -1:
            frame(d, len(PROGRESS), False, p)
        elif s == -2:
            frame(d, len(PROGRESS), True, p)
        else:
            frame(d, s, False, p)
        frames.append(img)
    return frames


def main():
    frames = build_frames()
    durations = [80] * len(frames)
    for i in range(max(0, len(frames) - 24), len(frames)):
        durations[i] = 320
    frames[0].save(OUT, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KiB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
