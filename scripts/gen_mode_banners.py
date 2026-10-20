#!/usr/bin/env python3
"""Generate the three mode banners (dark + light twins): one banner per
accent mode, each pairing lavender with exactly ONE color - EXPLOIT
crimson, RECON amber, DEFEND slate green. These are the README's theme
gallery; no banner ever shows two accents.

Deterministic. Usage: python3 scripts/gen_mode_banners.py
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).parent))
from theme import MODES, MONO, MONO_B, SANS_B, palette


def hx(c: str) -> tuple:
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


# the one line each mode "shows" - same shape, different accent moment
LINES = {
    "exploit": [("$ openre exploit FND-7f2a", "dim"),
                ("  poc written to ./poc/FND-7f2a.py  ", "text"),
                ("  reproduction: verified", "accent")],
    "recon": [("$ openre scan https://target --profile standard", "dim"),
              ("  28 checks  6 findings  ", "text"),
              ("  surface mapped", "accent")],
    "defend": [("$ openre remediate FND-7f2a", "dim"),
               ("  3 fixes applied  ", "text"),
               ("  regression test added", "accent")],
}


def render(mode: str, light: bool, out: Path) -> None:
    p = palette(mode, light=light)
    W, H = 1280, 640
    img = Image.new("RGB", (W, H), hx(p["canvas"]))
    d = ImageDraw.Draw(img)

    mono_b = lambda s: ImageFont.truetype(MONO_B, s)
    sans_b = lambda s: ImageFont.truetype(SANS_B, s)
    mono = ImageFont.truetype(MONO, 30)

    # mode name as the header: lavender platform, single accent mode
    d.rounded_rectangle((84, 96, 336, 176), radius=40, fill=hx(p["accent"]))
    name = MODES[mode]["name"]
    nw = d.textlength(name, font=mono_b(44))
    d.text((84 + (252 - nw) / 2, 112), name, font=mono_b(44), fill=hx(p["canvas"]))

    d.text((84, 220), "mode", font=sans_b(30), fill=hx(p["dim"]))
    d.text((84, 262), "lavender + one accent,", font=sans_b(46), fill=hx(p["text"]))
    d.text((84, 318), "never two.", font=sans_b(46), fill=hx(p["lavender"]))

    # the terminal strip with this mode's moment
    y = 430
    d.rounded_rectangle((84, y - 22, 1196, y + 132), radius=16, fill=hx(p["panel"]),
                        outline=hx(p["edge"]), width=2)
    yy = y
    for text, role in LINES[mode]:
        color = {"dim": p["dim"], "text": p["text"], "accent": p["accent"]}[role]
        d.text((116, yy), text, font=mono, fill=hx(color))
        yy += 48

    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, optimize=True)
    print(f"wrote {out} ({out.stat().st_size // 1024} KiB)")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    for mode in MODES:
        render(mode, light=False, out=root / "docs" / f"mode-{mode}.png")
        render(mode, light=True, out=root / "docs" / f"mode-{mode}-light.png")


if __name__ == "__main__":
    main()
