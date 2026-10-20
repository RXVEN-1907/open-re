#!/usr/bin/env python3
"""Generate docs/analyze-demo.gif: an animated terminal running REAL
binary analysis on target/release/sentinel (the workspace's own
lightweight security-scanner binary, crates/sentinel). Every line below
is genuine output captured on 2026-10-21 from the shipped release build:

    openre analyze info    target/release/sentinel
    openre analyze symbols target/release/sentinel
    openre analyze imports target/release/sentinel
    openre analyze disasm  target/release/sentinel --start 17fa0 --end 17fc0 --count 8 --bytes

sentinel ships without a symbol table, so `analyze symbols` really
returns an empty table and `analyze functions` really reports
"No functions found" - both shown honestly; the scrolling names are the
56 dynamic imports the tool genuinely reports. Totals in the closing
summary are the verbatim Contents line of the info capture.

Rendered in the RECON mode pairing (lavender + amber, one accent),
same terminal chrome as gen_demo_gif.py. Deterministic: fixed frame
schedule, no timestamps.

Usage: python with Pillow. python3 scripts/gen_analyze_gif.py
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from theme import MONO, MONO_B, SANS_B, palette

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "analyze-demo.gif"

W, H = 980, 660
PAD = 30
LH = 22

F_CMD = ImageFont.truetype(MONO_B, 16)
F_OUT = ImageFont.truetype(MONO, 16)
F_NOTE = ImageFont.truetype(MONO, 14)
F_TITLE = ImageFont.truetype(SANS_B, 15)

# genuine `analyze info` output, in order (label spans kept verbatim)
INFO_LINES = [
    [("Binary:", "lavender"), (" target/release/sentinel", "text")],
    [("  Format:", "lavender"), (" Elf X86_64 Bit64 Little", "text")],
    [("  OS:", "lavender"), (" Linux", "text"),
     ("  Confidence:", "lavender"), (" 0.95", "text")],
    [("  Entry point:", "lavender"), (" 0x17fa0", "text")],
    [("  Hardening:", "lavender"),
     (" aslr=false dep/nx=false pie=false relro=None canary=false fortify=false cfi=false", "text")],
    [("  Contents:", "lavender"),
     (" 32 sections, 0 symbols, 56 imports, 0 exports, 0 strings", "text")],
]

# genuine `analyze symbols` output: the empty table, exactly as printed
SYMBOLS_LINES = [
    [("┌──────┬─────────┬──────┬──────┬─────────┐", "dim")],
    [("│ NAME │ ADDRESS │ SIZE │ TYPE │ BINDING │", "dim")],
    [("└──────┴─────────┴──────┴──────┴─────────┘", "dim")],
    [("no symbol table — dynamic import names shown next", "dim")],
]

# first 12 of the 56 genuine `analyze imports` rows, in captured order
IMPORT_NAMES = [
    "__libc_start_main", "malloc", "memcpy", "bcmp", "memmove", "free",
    "strlen", "_Unwind_Resume", "syscall", "realloc", "poll",
    "__errno_location",
]
IMPORT_LINES = [[("· ", "lavender"), (name, "text")] for name in IMPORT_NAMES]

# genuine `analyze disasm ... --bytes` rows: (address, instruction, bytes)
DISASM_ROWS = [
    (0x17FA0, "endbr64", "f3 0f 1e fa"),
    (0x17FA4, "xor ebp, ebp", "31 ed"),
    (0x17FA6, "mov r9, rdx", "49 89 d1"),
    (0x17FA9, "pop rsi", "5e"),
    (0x17FAA, "mov rdx, rsp", "48 89 e2"),
    (0x17FAD, "and rsp, 0xfffffffffffffff0", "48 83 e4 f0"),
    (0x17FB1, "push rax", "50"),
    (0x17FB2, "push rsp", "54"),
]
DISASM_LINES = []
for addr, insn, byts in DISASM_ROWS:
    DISASM_LINES.append([(f"{'0x%x' % addr:>16}", "lavender"), (f"  {insn}", "text")])
    DISASM_LINES.append([(f"{'':>16}  {byts}", "dim")])

# closing summary: verbatim totals + identification facts from the capture
SUMMARY = [
    [("Contents:", "lavender"),
     (" 32 sections, 0 symbols, 56 imports, 0 exports, 0 strings", "text")],
    [("Elf X86_64 · Linux · entry 0x17fa0 · confidence 0.95", "accent")],
    [("0 symbols — no .symtab; the names above come from the dynamic table", "dim")],
    [("more: openre analyze pipeline · strings · segments", "dim")],
]

# (command, caption, output lines) - one command per phase, like a cleared
# terminal between phases
PHASES = [
    ("openre analyze info target/release/sentinel",
     "sentinel — the workspace's own lightweight security scanner",
     INFO_LINES),
    ("openre analyze symbols target/release/sentinel", None, SYMBOLS_LINES),
    ("openre analyze imports target/release/sentinel", None, IMPORT_LINES),
    ("openre analyze disasm target/release/sentinel"
     " --start 17fa0 --end 17fc0 --count 8 --bytes",
     None, DISASM_LINES),
]


def span(d, x, y, text, font, color):
    d.text((x, y), text, font=font, fill=color)
    return x + d.textlength(text, font=font)


def render_line(d, x, y, spans, p):
    fonts = {"text": F_OUT, "dim": F_OUT, "accent": F_OUT, "lavender": F_OUT}
    for text, role in spans:
        x = span(d, x, y, text, fonts[role], hxc(p[role]))


def frame(d, phase, typed, rows, summary_shown, p):
    d.rounded_rectangle((0, 0, W - 1, H - 1), radius=14, fill=hxc(p["panel"]),
                        outline=hxc(p["edge"]), width=2)
    for i, c in enumerate([(255, 95, 86), hxc(p["accent"]), hxc(p["lavender"])]):
        d.ellipse((22 + i * 26, 18, 38 + i * 26, 34), fill=c)
    title = "openre analyze - seeing inside the binary"
    tw = d.textlength(title, font=F_TITLE)
    d.text(((W - tw) / 2, 20), title, font=F_TITLE, fill=hxc(p["dim"]))
    d.line((0, 52, W, 52), fill=hxc(p["edge"]), width=1)

    cmd, caption, lines = PHASES[phase]
    y = 76
    x = span(d, PAD, y, "$ ", F_CMD, hxc(p["accent"]))
    x = span(d, x, y, cmd[:typed], F_CMD, hxc(p["text"]))
    if typed < len(cmd):
        span(d, x, y, "▍", F_CMD, hxc(p["accent"]))
    y += LH + 6

    if caption:
        span(d, PAD, y, caption, F_NOTE, hxc(p["dim"]))
        y += LH + 2

    for spans in lines[:rows]:
        render_line(d, PAD, y, spans, p)
        y += LH

    if summary_shown:
        y += 8
        for spans in SUMMARY:
            render_line(d, PAD, y, spans, p)
            y += LH


def hxc(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def build_frames():
    p = palette("recon", light=False)
    frames = []
    steps = []
    for pi, (cmd, _, lines) in enumerate(PHASES):
        if pi > 0:
            steps += [("prompt", pi, 0)] * 2        # cleared-terminal beat
        for t in range(1, len(cmd) + 1, 3):          # typing, 3 chars/frame
            steps.append(("type", pi, min(t, len(cmd))))
        steps.append(("type", pi, len(cmd)))         # full command, cursor on
        steps.append(("rows", pi, 0))                # settle, cursor gone
        for r in range(1, len(lines) + 1):           # output rows tick in
            steps.append(("rows", pi, r))
        steps += [("rows", pi, len(lines))] * 2      # settle
    steps += [("summary", len(PHASES) - 1, len(PHASES[-1][2]))] * 28
    for kind, pi, arg in steps:
        img = Image.new("RGB", (W, H), hxc(p["canvas"]))
        d = ImageDraw.Draw(img)
        if kind == "type":
            frame(d, pi, arg, 0, False, p)
        elif kind == "prompt":
            frame(d, pi, 0, 0, False, p)
        elif kind == "rows":
            frame(d, pi, len(PHASES[pi][0]), arg, False, p)
        else:
            frame(d, pi, len(PHASES[pi][0]), arg, True, p)
        frames.append(img)
    return frames


def main():
    frames = build_frames()
    durations = []
    for f in frames:
        durations.append(70)
    n = len(frames)
    for i in range(n - 26, n):                       # readable final hold
        durations[i] = 340
    frames[0].save(OUT, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KiB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
