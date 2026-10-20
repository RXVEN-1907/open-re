"""openre design tokens - the single source every visual asset renders from.

The system: lavender is the soul and appears everywhere. Each MODE pairs it
with exactly one accent; the other accents never appear on the same screen.

    dark   canvas #0D0E12  text #FFFFFF  lavender #BDB2FF
    light  canvas #FBFBFC  text #111215  lavender #7A6EE6

    EXPLOIT  crimson      (dark #E5484D / light #D13438)
    RECON    amber        (dark #F0A431 / light #B97A0A)
    DEFEND   slate green  (dark #4CC38A / light #218358)

Usage: sys.path.insert(0, str(Path(__file__).parent)); from theme import *
"""

from __future__ import annotations

CANVAS_DARK = "#0D0E12"
CANVAS_LIGHT = "#FBFBFC"
PANEL_DARK = "#16181F"
PANEL_LIGHT = "#F1F1F4"
EDGE_DARK = "#2A2D37"
EDGE_LIGHT = "#D8D8DE"
TEXT_DARK = "#FFFFFF"
TEXT_LIGHT = "#111215"
DIM_DARK = "#8B90A0"
DIM_LIGHT = "#5A5E6A"
LAVENDER_DARK = "#BDB2FF"
LAVENDER_LIGHT = "#7A6EE6"
LAVENDER_DEEP = "#8A7BD8"  # mid stop for gradients, mode-independent

MODES = {
    "exploit": {"name": "EXPLOIT", "dark": "#E5484D", "light": "#D13438"},
    "recon": {"name": "RECON", "dark": "#F0A431", "light": "#B97A0A"},
    "defend": {"name": "DEFEND", "dark": "#4CC38A", "light": "#218358"},
}

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def palette(mode: str = "exploit", light: bool = False) -> dict:
    """Resolve the full palette for one mode on one canvas."""
    m = MODES[mode]
    return {
        "canvas": CANVAS_LIGHT if light else CANVAS_DARK,
        "panel": PANEL_LIGHT if light else PANEL_DARK,
        "edge": EDGE_LIGHT if light else EDGE_DARK,
        "text": TEXT_LIGHT if light else TEXT_DARK,
        "dim": DIM_LIGHT if light else DIM_DARK,
        "lavender": LAVENDER_LIGHT if light else LAVENDER_DARK,
        "accent": m["light"] if light else m["dark"],
        "mode": m["name"],
    }
