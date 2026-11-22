"""Draw Halte's share image and app icons from the brand fonts and colours.

    python tools/make_brand_images.py

Writes to fastapi_app/static/img/:
  og-image.png          1200x630  link preview (WhatsApp, X, Facebook, iMessage)
  icon-192.png          192x192   web app manifest
  icon-512.png          512x512   web app manifest (also used as maskable)
  apple-touch-icon.png  180x180   iOS "Add to Home Screen"
  favicon-32.png        32x32     browser tab

Needs Pillow and fontTools (with brotli) to read the woff2 fonts. Re-run after
changing the brand colours, the logo mark or the tagline.
"""
from __future__ import annotations

import io
from pathlib import Path

from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "fastapi_app" / "static"
OUT = STATIC / "img"

YELLOW = "#FFE17C"
INK = "#000000"
PAPER = "#FFFFFF"

TAGLINE = "Cape Town bus, shuttle and train times"
NETWORKS = "MyCiTi  ·  UCT Jammie Shuttle  ·  Metrorail"
DOMAIN = "halte.co.za"

# The logo mark's lightning bolt (base.html), in its 24x24 viewBox.
BOLT = [(13, 3), (4, 14), (11, 14), (10, 21), (19, 10), (12, 10)]


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    """Load one of the site's woff2 fonts at a pixel size."""
    ttf = io.BytesIO()
    TTFont(STATIC / "fonts" / name).save(ttf)  # woff2 -> sfnt in memory
    ttf.seek(0)
    return ImageFont.truetype(ttf, size)


def draw_mark(img: Image.Image, box: tuple[int, int, int], radius: int) -> None:
    """Black rounded square with the yellow bolt, at (x, y, size)."""
    x, y, size = box
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([x, y, x + size - 1, y + size - 1], radius=radius, fill=INK)
    scale = size / 24
    d.polygon([(x + px * scale, y + py * scale) for px, py in BOLT], fill=YELLOW)


def og_image() -> Image.Image:
    """1200x630 link preview in the landing page's neo-brutalist style."""
    w, h = 1200, 630
    img = Image.new("RGB", (w, h), YELLOW)
    d = ImageDraw.Draw(img)
    # Card with the hard offset shadow the site uses.
    card = (70, 70, w - 70, h - 70)
    d.rectangle([card[0] + 14, card[1] + 14, card[2] + 14, card[3] + 14], fill=INK)
    d.rectangle(card, fill=PAPER, outline=INK, width=6)

    draw_mark(img, (130, 130, 132), radius=26)
    d.text((290, 112), "Halte", font=font("CabinetGrotesk-Extrabold.woff2", 150), fill=INK)
    d.text((134, 318), TAGLINE, font=font("CabinetGrotesk-Extrabold.woff2", 52), fill=INK)
    d.text((134, 398), NETWORKS, font=font("Satoshi-Medium.woff2", 34), fill=INK)

    # Domain chip, bottom left.
    chip_font = font("Satoshi-Medium.woff2", 32)
    left, top, right, bottom = d.textbbox((0, 0), DOMAIN, font=chip_font)
    cx, cy = 134, 476
    d.rounded_rectangle(
        [cx, cy, cx + (right - left) + 48, cy + (bottom - top) + 30],
        radius=40, fill=YELLOW, outline=INK, width=4,
    )
    d.text((cx + 24 - left, cy + 15 - top), DOMAIN, font=chip_font, fill=INK)
    return img


def icon(size: int, padding: float) -> Image.Image:
    """Square app icon: full-bleed black with the bolt (padding = safe zone)."""
    img = Image.new("RGB", (size, size), INK)
    inner = round(size * (1 - 2 * padding))
    offset = (size - inner) // 2
    d = ImageDraw.Draw(img)
    scale = inner / 24
    d.polygon([(offset + px * scale, offset + py * scale) for px, py in BOLT], fill=YELLOW)
    return img


def main() -> None:
    """Write every image."""
    OUT.mkdir(parents=True, exist_ok=True)
    og_image().save(OUT / "og-image.png", optimize=True)
    # Maskable icons need the artwork inside the central 80% circle.
    icon(512, 0.14).save(OUT / "icon-512.png", optimize=True)
    icon(192, 0.14).save(OUT / "icon-192.png", optimize=True)
    icon(180, 0.12).save(OUT / "apple-touch-icon.png", optimize=True)
    icon(32, 0.04).save(OUT / "favicon-32.png", optimize=True)
    for f in sorted(OUT.glob("*.png")):
        print(f"{f.relative_to(ROOT)}  {Image.open(f).size}  {f.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
