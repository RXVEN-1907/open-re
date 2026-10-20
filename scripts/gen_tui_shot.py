#!/usr/bin/env python3
"""Render docs/tui.png (dark) and docs/tui-light.png (light) from REAL openre-tui captures.

How the captures were made (tmux is only used by a human/agent re-capturing, never by
this script):

    tmux -f /dev/null new-session -d -s tuishot -x 134 -y 39 -c /tmp/openre-demo
    tmux send-keys -t tuishot '<path>/target/release/openre-tui --no-mouse' Enter
    sleep; tmux send-keys -t tuishot Tab; tmux send-keys -t tuishot BTab   # panel round-trip
    tmux capture-pane -t tuishot -e -p > docs/tui-capture.ans              # dark theme
    tmux send-keys -t tuishot F2                                           # cycles Dark -> Light
    tmux capture-pane -t tuishot -e -p > docs/tui-capture-light.ans        # light theme

This script deterministically replays the saved ANSI/SGR streams onto a 980x640
rounded terminal panel in the docs/demo.gif frame style (traffic lights, centered
title). The captured terminal colors are remapped onto the openre design system
(scripts/theme.py): lavender for accents, white/near-black for text, dim gray for
muted, the theme panel/canvas/edge tokens for surfaces and borders. The layout and
every glyph come from the captures; only the colors are re-skinned per theme.

Usage:
    <python with Pillow> scripts/gen_tui_shot.py
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from theme import MODES, MONO, MONO_B, SANS_B, palette  # noqa: E402

# ---------------------------------------------------------------------------
# Frame geometry (mirrors docs/demo.gif's panel style)
# ---------------------------------------------------------------------------
WIDTH, HEIGHT = 980, 640
HEADER_H = 52
RADIUS = 12
CELL_W, CELL_H = 7, 14
FONT_SIZE = 11
DOTS_X = (30, 56, 82)
DOT_Y = 26
DOT_R = 8.5
TITLE = "openre-tui - the platform dashboard"

REPO = Path(__file__).resolve().parent.parent
DEFAULTS = {
    (False): (REPO / "docs" / "tui-capture.ans", REPO / "docs" / "tui.png"),
    (True): (REPO / "docs" / "tui-capture-light.ans", REPO / "docs" / "tui-light.png"),
}

# ---------------------------------------------------------------------------
# Captured-color -> design-role tables (exact RGB values emitted by openre-tui)
# ---------------------------------------------------------------------------
# The TUI's own dark theme (Theme::Dark in crates/openre-tui/src/state.rs) emits
# these truecolor SGR values; each maps onto one role in the design system.
DARK_MAP = {
    (220, 220, 220): "text",     # fg
    (120, 120, 120): "dim",      # muted
    (80, 80, 80): "edge",        # border
    (70, 70, 70): "edge",        # panel_border
    (35, 35, 35): "panel",       # panel_bg
    (28, 28, 28): "panel",       # bg
    (0, 180, 180): "accent",     # accent
    (0, 220, 220): "accent",     # accent_bold
    (80, 160, 255): "accent",    # info
    (80, 200, 80): "accent",     # success
    (50, 200, 50): "accent",     # low severity
    (255, 140, 0): "warn",       # high severity
    (255, 215, 0): "warn",       # medium severity
    (255, 200, 0): "warn",       # warning
    (255, 80, 80): "crit",       # error
    (255, 50, 50): "crit",       # critical
    (255, 220, 0): "pill_bg",    # selected_fg (rendered reversed -> pill background)
    (60, 60, 60): "pill_fg",     # selected_bg (rendered reversed -> pill text)
}
LIGHT_MAP = {
    (40, 40, 40): "text",        # fg
    (120, 120, 120): "dim",      # muted
    (180, 180, 180): "edge",     # border
    (200, 200, 200): "pill_fg",  # selected_bg (reversed -> pill text)
    (255, 255, 255): "panel",    # panel_bg
    (245, 245, 245): "panel",    # bg
    (0, 100, 100): "accent",     # accent
    (0, 80, 80): "pill_bg",      # accent_bold / selected_fg (reversed -> pill background)
    (0, 0, 200): "accent",       # info
    (0, 150, 0): "accent",       # success / low severity
    (200, 0, 0): "crit",         # error / critical
    (200, 100, 0): "warn",       # high severity
    (200, 150, 0): "warn",       # medium / warning
}


def role_of(rgb: tuple[int, int, int] | None, light: bool) -> str:
    """Classify one captured color into a design-system role."""
    if rgb is None:
        return "panel"
    table = LIGHT_MAP if light else DARK_MAP
    if rgb in table:
        return table[rgb]
    r, g, b = rgb
    if max(r, g, b) - min(r, g, b) > 40:  # any saturated color is an accent
        return "accent"
    lum = 0.2126 * r + 0.7152 * g + 0.0722 * b
    if light:
        if lum <= 90:
            return "text"
        if lum <= 170:
            return "dim"
        return "edge" if lum <= 215 else "panel"
    if lum >= 150:
        return "text"
    if lum >= 70:
        return "dim"
    return "edge" if lum >= 30 else "panel"


def _hex2rgb(h: str) -> tuple[int, int, int]:
    return tuple(int(h[i : i + 2], 16) for i in (1, 3, 5))


def role_colors(light: bool) -> dict[str, tuple[int, int, int]]:
    """Resolve every design role to an RGB triple from scripts/theme.py."""
    p = palette("exploit", light=light)
    shade = "light" if light else "dark"
    return {
        "canvas": _hex2rgb(p["canvas"]),
        "panel": _hex2rgb(p["panel"]),
        "edge": _hex2rgb(p["edge"]),
        "text": _hex2rgb(p["text"]),
        "dim": _hex2rgb(p["dim"]),
        "accent": _hex2rgb(p["lavender"]),
        "warn": _hex2rgb(MODES["recon"][shade]),
        "crit": _hex2rgb(MODES["exploit"][shade]),
        "pill_bg": _hex2rgb(p["lavender"]),
        "pill_fg": _hex2rgb(p["canvas"]),
    }


# Traffic lights: red, the recon amber, then lavender — the demo.gif dot row.
DOT_COLORS = {
    False: ((0xFF, 0x5F, 0x56), (0xF0, 0xA4, 0x31), (0xBD, 0xB2, 0xFF)),
    True: ((0xE5, 0x48, 0x4D), (0xB9, 0x7A, 0x0A), (0x7A, 0x6E, 0xE6)),
}

SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
CSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _csi_params(match: str) -> list[int]:
    return [int(p) if p.isdigit() else 0 for p in match.split(";") if p != ""] or [0]


def _apply_sgr(params: list[int], style: dict) -> None:
    """Apply one SGR sequence's parameters to the running cell style."""
    i = 0
    while i < len(params):
        p = params[i]
        if p == 0:
            style.update(fg=None, bg=None, bold=False, reverse=False)
        elif p == 1:
            style["bold"] = True
        elif p == 7:
            style["reverse"] = True
        elif p == 22:  # normal intensity: clears bold/dim
            style["bold"] = False
        elif p == 27:
            style["reverse"] = False
        elif 30 <= p <= 37:
            style["fg"] = NAMED[p - 30]
        elif p == 39:
            style["fg"] = None
        elif 40 <= p <= 47:
            style["bg"] = NAMED[p - 40]
        elif p == 49:
            style["bg"] = None
        elif 90 <= p <= 97:
            style["fg"] = NAMED[p - 90 + 8]
        elif 100 <= p <= 107:
            style["bg"] = NAMED[p - 100 + 8]
        elif p in (38, 48) and i + 1 < len(params):
            key = "fg" if p == 38 else "bg"
            if params[i + 1] == 5 and i + 2 < len(params):
                style[key] = _indexed_color(params[i + 2])
                i += 2
            elif params[i + 1] == 2 and i + 4 < len(params):
                style[key] = (params[i + 2], params[i + 3], params[i + 4])
                i += 4
        # dim(2)/italic(3)/underline(4) are not emitted by openre-tui
        i += 1


def disp_width(ch: str) -> int:
    """Terminal display width of one parsed cell (wide chars span two columns)."""
    if not ch:
        return 1  # second half of a wide cell
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def parse_ansi(text: str) -> list[list[tuple[str, dict]]]:
    """Parse a captured pane into rows of (char, style) cells.

    Each style dict carries fg/bg as RGB tuples (None = terminal default), plus
    bold/dim/reverse flags. Wide (East Asian W/F) characters advance two columns.
    """
    rows: list[list[tuple[str, dict]]] = []
    row: list[tuple[str, dict]] = []
    style = {"fg": None, "bg": None, "bold": False, "reverse": False}

    def push(ch: str) -> None:
        row.append((ch, dict(style)))
        if disp_width(ch) == 2:
            row.append(("", dict(style)))  # second half of a wide cell

    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b":
            m = SGR_RE.match(text, i)
            if m:
                _apply_sgr(_csi_params(m.group(1)), style)
                i = m.end()
                continue
            m2 = CSI_RE.match(text, i)
            if m2:
                i = m2.end()
                continue
            i += 1  # stray escape byte
            continue
        if ch == "\n":
            rows.append(row)
            row = []
        elif unicodedata.combining(ch) or ch == "\ufe0f":
            pass  # zero-width: attaches to previous cell, no column advance
        elif ch >= " ":
            push(ch)
        i += 1
    if row:
        rows.append(row)
    return rows


NAMED = {
    0: (0, 0, 0), 1: (128, 0, 0), 2: (0, 128, 0), 3: (128, 128, 0),
    4: (0, 0, 128), 5: (128, 0, 128), 6: (0, 128, 128), 7: (192, 192, 192),
    8: (128, 128, 128), 9: (255, 0, 0), 10: (0, 255, 0), 11: (255, 255, 0),
    12: (0, 0, 255), 13: (255, 0, 255), 14: (0, 255, 255), 15: (255, 255, 255),
}


def _indexed_color(n: int) -> tuple[int, int, int]:
    """The full xterm-256 palette: 16 named, 6x6x6 cube, 24-step grayscale."""
    if n < 16:
        return NAMED[n]
    if n < 232:
        n -= 16
        steps = (0, 95, 135, 175, 215, 255)
        return (steps[n // 36], steps[(n // 6) % 6], steps[n % 6])
    v = 8 + (n - 232) * 10
    return (v, v, v)

# Glyphs DejaVu Sans Mono lacks get a same-family stand-in so the cell grid
# stays aligned; anything else falls back to a blank cell.
SUBSTITUTE = {"📁": "▪", "🔧": "▪", "ℹ": "i", "✅": "✓", "❌": "✗",
              "🔄": "↻", "⏳": "◌", "⚠": "!"}

_NOTDEF = "\U0010FFFC"  # guaranteed-unmapped codepoint: renders as the .notdef box
_COVERAGE: dict = {}


def _covered(font, ch: str) -> bool:
    """True when the font has a real glyph for ch.

    Pillow renders missing glyphs as the .notdef box rather than an empty mask,
    so coverage is decided by comparing against a guaranteed-missing codepoint.
    """
    key = (id(font), ch)
    if key not in _COVERAGE:
        missing = bytes(font.getmask(_NOTDEF, mode="L"))
        _COVERAGE[key] = bytes(font.getmask(ch, mode="L")) != missing
    return _COVERAGE[key]


def render(capture: Path, light: bool, out: Path, mono, mono_b, sans_b) -> Image.Image:
    text = capture.read_text(encoding="utf-8")
    rows = parse_ansi(text)
    while rows and not any(ch for ch, _ in rows[-1]):
        rows.pop()  # trailing newline artifact
    cols = max(
        (sum(disp_width(ch) for ch, _ in r) for r in rows),
        default=0,
    )
    grid_w, grid_h = cols * CELL_W, len(rows) * CELL_H
    if grid_w > WIDTH - 2 * RADIUS or grid_h > HEIGHT - HEADER_H - 2 * RADIUS:
        raise SystemExit(
            f"capture {cols}x{len(rows)} does not fit the {WIDTH}x{HEIGHT} frame"
        )
    left = (WIDTH - grid_w) // 2
    top = HEADER_H + (HEIGHT - HEADER_H - grid_h) // 2

    colors = role_colors(light)
    image = Image.new("RGB", (WIDTH, HEIGHT), colors["canvas"])
    draw = ImageDraw.Draw(image)

    # Rounded terminal panel, header divider, traffic lights, centered title.
    draw.rounded_rectangle(
        [0, 0, WIDTH - 1, HEIGHT - 1], radius=RADIUS,
        fill=colors["panel"], outline=colors["edge"], width=1,
    )
    draw.line([(1, HEADER_H), (WIDTH - 2, HEADER_H)], fill=colors["edge"])
    for cx, dot in zip(DOTS_X, DOT_COLORS[light]):
        draw.ellipse(
            [cx - DOT_R, DOT_Y - DOT_R, cx + DOT_R, DOT_Y + DOT_R], fill=dot
        )
    tw = draw.textlength(TITLE, font=sans_b)
    draw.text(((WIDTH - tw) / 2, DOT_Y - sans_b.size / 2 - 1), TITLE,
              font=sans_b, fill=colors["dim"])

    def effective(cell_style: dict) -> tuple[tuple | None, tuple | None]:
        fg, bg = cell_style["fg"], cell_style["bg"]
        if cell_style["reverse"]:
            fg, bg = bg, fg
        return fg, bg

    # Pass 1: cell backgrounds (anything that is not the plain panel surface).
    for r, row in enumerate(rows):
        y = top + r * CELL_H
        c = 0
        for ch, st in row:
            if c >= cols:
                break
            _, bg = effective(st)
            if bg is not None:
                col = colors[role_of(bg, light)]
                if col != colors["panel"]:
                    draw.rectangle(
                        [left + c * CELL_W, y, left + (c + 1) * CELL_W - 1,
                         y + CELL_H - 1],
                        fill=col,
                    )
            c += disp_width(ch)

    # Pass 2: glyphs, remapped onto the design roles.
    for r, row in enumerate(rows):
        y = top + r * CELL_H
        c = 0
        for ch, st in row:
            if c >= cols:
                break
            fg, _ = effective(st)
            if ch and ch != " ":
                font = mono_b if st["bold"] else mono
                glyph = ch
                if not _covered(font, glyph):
                    glyph = SUBSTITUTE.get(glyph, "")
                if glyph and _covered(font, glyph):
                    color = (colors[role_of(fg, light)] if fg is not None
                             else colors["text"])
                    draw.text((left + c * CELL_W, y), glyph, font=font, fill=color)
            c += disp_width(ch)

    image.save(out, format="PNG")
    return image


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--capture-dark", type=Path, default=DEFAULTS[False][0])
    ap.add_argument("--capture-light", type=Path, default=DEFAULTS[True][0])
    ap.add_argument("--out-dark", type=Path, default=DEFAULTS[False][1])
    ap.add_argument("--out-light", type=Path, default=DEFAULTS[True][1])
    args = ap.parse_args()

    mono = ImageFont.truetype(MONO, FONT_SIZE)
    mono_b = ImageFont.truetype(MONO_B, FONT_SIZE)
    sans_b = ImageFont.truetype(SANS_B, 15)

    render(args.capture_dark, False, args.out_dark, mono, mono_b, sans_b)
    render(args.capture_light, True, args.out_light, mono, mono_b, sans_b)
    print(f"wrote {args.out_dark} and {args.out_light}")


if __name__ == "__main__":
    main()
