#!/usr/bin/env python3
"""Build the 1200x630 Open Graph / Twitter card PNGs: app/static/og/<slug>.png for every tool plus index.png for the hub.

Brand gradient #2f5bff, the tool name, a one-line benefit (og_line from app/data/content/<slug>.json), a simple
per-category icon and the "BookMyHost Toolbox" wordmark. The PNGs are committed; this script is a build-time tool only
(Pillow lives in requirements-build.txt, never in the runtime image).

    .venv/bin/pip install -r requirements-build.txt
    .venv/bin/python scripts/build_og.py            # all images
    .venv/bin/python scripts/build_og.py spf-checker index

Fonts: DejaVu Sans (Bold + Regular). Point BMH_OG_FONT_DIR at another directory holding DejaVuSans*.ttf if needed.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.core.config import CATEGORIES, SITE_NAME, TOOLS  # noqa: E402

OUT = ROOT / "app" / "static" / "og"
CONTENT = ROOT / "app" / "data" / "content"
W, H = 1200, 630
BRAND = (0x2F, 0x5B, 0xFF)
DEEP = (0x1B, 0x2F, 0xA8)
WHITE = (255, 255, 255)
SOFT = (222, 230, 255)
MAX_BYTES = 80 * 1024
FONT_DIRS = [os.getenv("BMH_OG_FONT_DIR", ""), "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu",
             "C:/Windows/Fonts", "/Library/Fonts"]


def font(bold: bool, size: int) -> ImageFont.FreeTypeFont:
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    for d in FONT_DIRS:
        if d and (Path(d) / name).is_file():
            return ImageFont.truetype(str(Path(d) / name), size)
    sys.exit(f"font {name} not found; set BMH_OG_FONT_DIR")


def gradient() -> Image.Image:
    """Diagonal-ish brand gradient, drawn as horizontal bands (cheap, and it compresses well)."""
    img = Image.new("RGB", (W, H), BRAND)
    d = ImageDraw.Draw(img)
    bands = 42
    for i in range(bands):
        t = i / (bands - 1)
        c = tuple(round(BRAND[k] + (DEEP[k] - BRAND[k]) * t) for k in range(3))
        d.rectangle([0, round(H * i / bands), W, round(H * (i + 1) / bands)], fill=c)
    return img


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt, width: int) -> list[str]:
    lines, cur = [], ""
    for word in text.split():
        trial = f"{cur} {word}".strip()
        if draw.textlength(trial, font=fnt) <= width or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


# ---- icons: drawn with white strokes inside a translucent circle at the right ----
def icon_email(d, cx, cy, r):
    w, h = r * 1.3, r * 0.9
    box = [cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2]
    d.rounded_rectangle(box, radius=14, outline=WHITE, width=9)
    d.line([(box[0] + 6, box[1] + 8), (cx, cy + h * 0.1), (box[2] - 6, box[1] + 8)], fill=WHITE, width=9, joint="curve")


def icon_dns(d, cx, cy, r):
    R = r * 0.62
    d.ellipse([cx - R, cy - R, cx + R, cy + R], outline=WHITE, width=9)
    d.ellipse([cx - R * 0.42, cy - R, cx + R * 0.42, cy + R], outline=WHITE, width=7)
    d.line([(cx - R, cy), (cx + R, cy)], fill=WHITE, width=7)
    d.line([(cx, cy - R), (cx, cy + R)], fill=WHITE, width=7)


def icon_network(d, cx, cy, r):
    pts = [(cx - r * 0.55, cy - r * 0.3), (cx + r * 0.1, cy - r * 0.6), (cx + r * 0.6, cy + r * 0.05), (cx - r * 0.1, cy + r * 0.55)]
    for a, b in [(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)]:
        d.line([pts[a], pts[b]], fill=WHITE, width=7)
    for x, y in pts:
        d.ellipse([x - 22, y - 22, x + 22, y + 22], fill=WHITE)


def icon_web(d, cx, cy, r):
    w, h = r * 1.35, r * 1.0
    box = [cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2]
    d.rounded_rectangle(box, radius=16, outline=WHITE, width=9)
    d.line([(box[0], box[1] + h * 0.26), (box[2], box[1] + h * 0.26)], fill=WHITE, width=8)
    for i in range(3):
        x = box[0] + 30 + i * 28
        d.ellipse([x - 7, box[1] + h * 0.13 - 7, x + 7, box[1] + h * 0.13 + 7], fill=WHITE)
    d.rounded_rectangle([cx - 38, cy + 8, cx + 38, cy + 52], radius=8, fill=WHITE)
    d.arc([cx - 24, cy - 40, cx + 24, cy + 24], 180, 360, fill=WHITE, width=8)


def icon_grid(d, cx, cy, r):
    s, g = r * 0.42, 14
    for dx in (-1, 1):
        for dy in (-1, 1):
            x, y = cx + dx * (s / 2 + g / 2), cy + dy * (s / 2 + g / 2)
            d.rounded_rectangle([x - s / 2, y - s / 2, x + s / 2, y + s / 2], radius=12, fill=WHITE)


ICONS = {"email": icon_email, "dns": icon_dns, "network": icon_network, "web": icon_web, "hub": icon_grid}


def render(slug: str, name: str, line: str, cat: str) -> Image.Image:
    img = gradient().convert("RGBA")
    # soft decorative discs
    over = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(over)
    cx, cy, R = 930, 250, 190
    od.ellipse([cx - R - 90, cy - R - 90, cx + R + 90, cy + R + 90], fill=(255, 255, 255, 22))
    od.ellipse([cx - R, cy - R, cx + R, cy + R], fill=(255, 255, 255, 36))
    img = Image.alpha_composite(img, over)
    d = ImageDraw.Draw(img)
    ICONS[cat](d, cx, cy, R)

    left, text_w = 80, 700
    size = 76
    while True:
        f_name = font(True, size)
        name_lines = wrap(d, name, f_name, text_w)
        if len(name_lines) <= 3 or size <= 52:
            break
        size -= 4
    f_line = font(False, 36)
    line_lines = wrap(d, line, f_line, text_w + 60)
    block = len(name_lines) * int(size * 1.18) + 28 + len(line_lines) * 50
    y = max(70, (H - 150 - block) // 2 + 20)
    for t in name_lines:
        d.text((left, y), t, font=f_name, fill=WHITE)
        y += int(size * 1.18)
    y += 28
    for t in line_lines:
        d.text((left, y), t, font=f_line, fill=SOFT)
        y += 50

    # wordmark bottom-left
    d.rounded_rectangle([left, 520, left + 54, 574], radius=14, fill=WHITE)
    d.rounded_rectangle([left + 13, 533, left + 41, 561], radius=6, outline=BRAND, width=5)
    d.text((left + 74, 524), "BookMyHost ", font=font(True, 36), fill=WHITE)
    wm = d.textlength("BookMyHost ", font=font(True, 36))
    d.text((left + 74 + wm, 524), "Toolbox", font=font(True, 36), fill=SOFT)
    d.text((W - 80, 536), "bookmyhost.com/tools", font=font(False, 28), fill=SOFT, anchor="ra")
    return img.convert("RGB")


def save(img: Image.Image, path: Path) -> int:
    for colors in (96, 64, 48, 32):
        q = img.quantize(colors=colors, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
        q.save(path, optimize=True)
        if path.stat().st_size <= MAX_BYTES:
            break
    return path.stat().st_size


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cat_of = {t["slug"]: t["category"] for t in TOOLS}
    jobs = [("index", f"{SITE_NAME}", "hub")] + [(t["slug"], t["name"], t["category"]) for t in TOOLS]
    only = set(argv)
    bad = 0
    for slug, name, cat in jobs:
        if only and slug not in only:
            continue
        data = json.loads((CONTENT / f"{'hub' if slug == 'index' else slug}.json").read_text(encoding="utf-8"))
        line = data["og_line"]
        if slug == "index":
            name = "Free tools for email, DNS and networks"
        size = save(render(slug, name, line, cat if cat in ICONS else "network"), OUT / f"{slug}.png")
        flag = "" if size <= MAX_BYTES else "  TOO BIG"
        bad += bool(flag)
        print(f"{slug:26} {size / 1024:5.1f} KB{flag}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
