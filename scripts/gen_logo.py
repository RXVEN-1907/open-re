#!/usr/bin/env python3
"""Generate the openre logo as SVG: a scanner eye over a binary grid.

The mark: concentric scan arcs (the platform sweeping a target) with one
accent arc, a lavender core, and a faint byte matrix underneath. One file
adapts dark/light by itself through a prefers-color-scheme media query.
Mode variants swap only the accent arc and the core ring - lavender stays
put, and no two mode accents ever share a canvas.

Usage: python3 scripts/gen_logo.py   (writes docs/logo*.svg)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from theme import CANVAS_DARK, CANVAS_LIGHT, LAVENDER_DARK, LAVENDER_LIGHT, MODES

OUT = Path(__file__).resolve().parent.parent / "docs"


def logo_svg(accent_dark: str, accent_light: str) -> str:
    """The mark, 256x256. Colors resolve per color scheme; the accent pair
    is the only thing that changes between modes."""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <style>
    :root {{ --canvas: {CANVAS_DARK}; --lav: {LAVENDER_DARK}; --acc: {accent_dark}; --edge: #2A2D37; --byte: #23262F; }}
    @media (prefers-color-scheme: light) {{
      :root {{ --canvas: {CANVAS_LIGHT}; --lav: {LAVENDER_LIGHT}; --acc: {accent_light}; --edge: #D8D8DE; --byte: #E4E4EA; }}
    }}
  </style>
  <defs>
    <clipPath id="badge"><rect x="8" y="8" width="240" height="240" rx="52"/></clipPath>
  </defs>
  <g clip-path="url(#badge)">
    <rect x="8" y="8" width="240" height="240" fill="var(--canvas)"/>
    <!-- byte matrix: the target's memory, fading toward the core -->
    <g fill="var(--byte)">
      {''.join(f'<rect x="{24 + col * 26}" y="{24 + row * 26}" width="10" height="10" rx="2" opacity="{0.55 - 0.05 * row}"/>'
               for row in range(8) for col in range(8)
               if (row * 8 + col) % 3 != 0)}
    </g>
    <!-- scan arcs: lavender everywhere, one accent sweep -->
    <g fill="none" stroke-linecap="round">
      <circle cx="128" cy="128" r="96" stroke="var(--byte)" stroke-width="3"/>
      <path d="M 128 20 A 108 108 0 0 1 227 91" stroke="var(--lav)" stroke-width="10" opacity="0.95"/>
      <path d="M 236 128 A 108 108 0 0 1 128 236" stroke="var(--lav)" stroke-width="10" opacity="0.55"/>
      <path d="M 20 128 A 108 108 0 0 1 74 34" stroke="var(--acc)" stroke-width="10"/>
      <path d="M 96 42 A 92 92 0 0 1 214 96" stroke="var(--acc)" stroke-width="5" opacity="0.5"/>
      <circle cx="128" cy="128" r="58" stroke="var(--lav)" stroke-width="6" opacity="0.8"/>
    </g>
    <!-- the core: what the scanner found -->
    <circle cx="128" cy="128" r="20" fill="var(--acc)"/>
    <circle cx="128" cy="128" r="30" fill="none" stroke="var(--acc)" stroke-width="3" opacity="0.45"/>
    <circle cx="128" cy="128" r="6" fill="var(--canvas)"/>
    <rect x="8" y="8" width="240" height="240" rx="52" fill="none" stroke="var(--edge)" stroke-width="2"/>
  </g>
</svg>
'''


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "logo.svg").write_text(logo_svg(LAVENDER_DARK, LAVENDER_LIGHT))
    for mode, m in MODES.items():
        (OUT / f"logo-{mode}.svg").write_text(logo_svg(m["dark"], m["light"]))
    for p in sorted(OUT.glob("logo*.svg")):
        print(f"wrote {p.relative_to(OUT.parent)} ({p.stat().st_size} B)")


if __name__ == "__main__":
    main()
