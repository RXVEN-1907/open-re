#!/usr/bin/env python3
"""Generate docs/checks-chart.png and docs/size-chart.png.

Both charts render in the RECON mode pairing (lavender + amber on the
dark canvas) and reuse the panel chrome of docs/demo.gif: rounded panel,
three dots, centered dim title, edge divider. Deterministic: fixed data,
fixed fonts, no timestamps, no randomness - two runs produce byte-identical
files.

Data sources (real, not invented):
  checks  - crates/openre-scan/src/checks.rs get_all_checks() / Check::name(),
            as documented in docs/checks.md
  sizes   - docs/PERFORMANCE.md "Measured results / Binary size"

Usage: a python with Pillow. python3 scripts/gen_charts.py
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from theme import MONO, MONO_B, SANS_B, palette

REPO = Path(__file__).resolve().parent.parent
OUT_CHECKS = REPO / "docs" / "checks-chart.png"
OUT_SIZE = REPO / "docs" / "size-chart.png"


def hxc(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def chrome(d, p, w, title):
    """demo.gif panel chrome: rounded panel, three dots, dim title, divider."""
    d.rounded_rectangle((0, 0, w - 1, CHROME_H - 1 + 40), radius=14,
                        fill=hxc(p["panel"]), outline=hxc(p["edge"]), width=2)
    for i, c in enumerate([(255, 95, 86), hxc(p["accent"]), hxc(p["lavender"])]):
        d.ellipse((22 + i * 26, 18, 38 + i * 26, 34), fill=c)
    tw = d.textlength(title, font=ImageFont.truetype(SANS_B, 15))
    d.text(((w - tw) / 2, 20), title, font=ImageFont.truetype(SANS_B, 15),
           fill=hxc(p["dim"]))
    d.line((0, 52, w, 52), fill=hxc(p["edge"]), width=1)


CHROME_H = 52

# --- checks chart -----------------------------------------------------------
# (name, one-line "detects", in_quick, in_standard, in_full) - membership is
# exactly get_all_checks() in crates/openre-scan/src/checks.rs; order follows
# docs/checks.md.
CHECKS = [
    ("http-headers", "Server / X-Powered-By disclosure", 1, 1, 1),
    ("security-headers", "missing X-Frame-Options, HSTS, CSP, COOP, ...", 1, 1, 1),
    ("cookie-security", "cookies missing Secure / HttpOnly / SameSite", 1, 1, 1),
    ("tls-certificate", "plain-HTTP targets, HTTPS failures", 1, 1, 1),
    ("info-disclosure", "debug headers, Server version strings", 1, 1, 1),
    ("tech-fingerprint", "server/framework signatures in headers + body", 1, 1, 1),
    ("csp", "missing CSP, unsafe-inline/eval, wildcards", 0, 1, 1),
    ("cors", "wildcard Allow-Origin, credentials + wildcard", 0, 1, 1),
    ("robots-txt", "accessible robots.txt, Disallow entries", 0, 1, 1),
    ("sitemap", "accessible sitemap.xml", 0, 1, 1),
    ("dir-listing", "directory-index markers in the body", 0, 1, 1),
    ("sensitive-files", "21 probed paths (.git/, .env, wp-config.php, ...)", 0, 1, 1),
    ("forms", "passwords in GET forms, missing CSRF tokens", 0, 1, 1),
    ("links", "mixed content on HTTPS pages, mailto exposure", 0, 1, 1),
    ("scripts", "external scripts over HTTP, inline counts", 0, 1, 1),
    ("meta-tags", "generator disclosure, meta-refresh", 0, 1, 1),
    ("http-methods", "TRACE/TRACK/PUT/DELETE/PATCH enabled", 0, 0, 1),
    ("ssl-config", "flags HTTPS targets for dedicated tooling", 0, 0, 1),
]

PROFILES = ["quick", "standard", "full"]


def draw_checks(p):
    w = 1060
    row_h = 33
    top = CHROME_H + 74
    bottom_pad = 46
    h = top + len(CHECKS) * row_h + bottom_pad
    img = Image.new("RGB", (w, h), hxc(p["canvas"]))
    d = ImageDraw.Draw(img)
    chrome(d, p, w, "openre - one binary, every target")

    f20 = ImageFont.truetype(SANS_B, 20)
    f13 = ImageFont.truetype(MONO, 13)
    f14 = ImageFont.truetype(MONO, 14)
    f14b = ImageFont.truetype(MONO_B, 14)
    f12 = ImageFont.truetype(MONO, 12)

    d.text((30, CHROME_H + 12), "what each profile runs", font=f20, fill=hxc(p["text"]))
    sub = ("18 checks x 3 scan profiles - a lavender dot means the check runs in that profile")
    d.text((30, CHROME_H + 42), sub, font=f12, fill=hxc(p["dim"]))

    name_x, desc_x = 30, 250
    col_x = [790, 880, 970]  # dot centers
    for label, count, cx in zip(PROFILES, ["6", "16", "18"], col_x):
        gap = 7
        lw = d.textlength(label, font=f14b)
        cw = d.textlength(count, font=f12)
        x0 = cx - (lw + gap + cw) / 2
        d.text((x0, top - 26), label, font=f14b, fill=hxc(p["accent"]))
        d.text((x0 + lw + gap, top - 24), count, font=f12, fill=hxc(p["dim"]))

    y = top
    for name, desc, q, s, f in CHECKS:
        d.text((name_x, y + 1), name, font=f14, fill=hxc(p["text"]))
        d.text((desc_x, y + 2), desc, font=f12, fill=hxc(p["dim"]))
        for cx, on in zip(col_x, (q, s, f)):
            if on:
                d.ellipse((cx - 6, y - 2, cx + 6, y + 10), fill=hxc(p["lavender"]))
            else:
                d.ellipse((cx - 6, y - 2, cx + 6, y + 10),
                          outline=hxc(p["edge"]), width=2)
        y += row_h

    d.text((30, h - 26),
           "source: crates/openre-scan/src/checks.rs get_all_checks() - docs/checks.md",
           font=f12, fill=hxc(p["dim"]))
    return img


# --- size chart -------------------------------------------------------------
# (binary, before bytes, after bytes, pct) - docs/PERFORMANCE.md, measured on
# the same machine and toolchain, baseline vs tuned release profile.
SIZES = [
    ("openre", 2435968, 1954000, "-19.8%"),
    ("openre-tui", 7070176, 5930008, "-16.1%"),
    ("sentinel", 806760, 603728, "-25.2%"),
]


def draw_size(p):
    w = 1000
    top = CHROME_H + 74
    bar_h = 26
    group_gap = 20
    name_x = 30
    bar_x = 210
    bar_max_w = 560
    delta_x = 850
    bottom_pad = 64
    h = top + len(SIZES) * (bar_h * 2 + 8 + group_gap) + bottom_pad
    img = Image.new("RGB", (w, h), hxc(p["canvas"]))
    d = ImageDraw.Draw(img)
    chrome(d, p, w, "openre - one binary, every target")

    f20 = ImageFont.truetype(SANS_B, 20)
    f13 = ImageFont.truetype(MONO, 13)
    f14 = ImageFont.truetype(MONO, 14)
    f14b = ImageFont.truetype(MONO_B, 14)
    f12 = ImageFont.truetype(MONO, 12)

    d.text((30, CHROME_H + 12), "release tuning: 10.3 MB → 8.5 MB, -17.7%",
           font=f20, fill=hxc(p["text"]))
    sub = ("the three release binaries - fat LTO, one codegen unit, symbols "
           "stripped, tokio features trimmed")
    d.text((30, CHROME_H + 42), sub, font=f12, fill=hxc(p["dim"]))

    # legend
    lx = w - 240
    d.rectangle((lx, CHROME_H + 14, lx + 14, CHROME_H + 28), fill=hxc(p["dim"]))
    d.text((lx + 20, CHROME_H + 14), "before", font=f12, fill=hxc(p["dim"]))
    d.rectangle((lx + 90, CHROME_H + 14, lx + 104, CHROME_H + 28),
                fill=hxc(p["lavender"]))
    d.text((lx + 110, CHROME_H + 14), "after", font=f12, fill=hxc(p["dim"]))

    before_max = max(b for _, b, _, _ in SIZES)
    scale = bar_max_w / before_max
    dim = hxc(p["dim"])
    lav = hxc(p["lavender"])
    y = top
    for name, before, after, pct in SIZES:
        d.text((name_x, y + bar_h - 4), name, font=f14b, fill=hxc(p["text"]))
        d.rounded_rectangle((bar_x, y, bar_x + int(before * scale), y + bar_h),
                            radius=4, fill=dim)
        d.text((bar_x + int(before * scale) + 10, y + 5),
               f"{before:,} B", font=f12, fill=dim)
        y += bar_h + 4
        d.rounded_rectangle((bar_x, y, bar_x + int(after * scale), y + bar_h),
                            radius=4, fill=lav)
        d.text((bar_x + int(after * scale) + 10, y + 5),
               f"{after:,} B", font=f12, fill=hxc(p["text"]))
        d.text((delta_x, y + 5), pct, font=f14b, fill=hxc(p["accent"]))
        y += bar_h + group_gap

    d.text((30, h - 42),
           "totals: 10,312,904 B → 8,487,736 B (-17.7%) for these three;",
           font=f12, fill=dim)
    d.text((30, h - 24),
           "the full table incl. openre-scan is 24,838,848 → 19,712,720 B "
           "(-20.6%) - docs/PERFORMANCE.md",
           font=f12, fill=dim)
    return img


def main():
    p = palette("recon", light=False)
    a = draw_checks(p)
    b = draw_size(p)
    a.save(OUT_CHECKS)
    b.save(OUT_SIZE)
    print(f"wrote {OUT_CHECKS} ({OUT_CHECKS.stat().st_size // 1024} KiB, "
          f"{a.size[0]}x{a.size[1]})")
    print(f"wrote {OUT_SIZE} ({OUT_SIZE.stat().st_size // 1024} KiB, "
          f"{b.size[0]}x{b.size[1]})")


if __name__ == "__main__":
    main()
