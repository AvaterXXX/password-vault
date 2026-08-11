"""Generate a clean key app icon: transparent bg, bottom-left -> top-right."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).resolve().parent


def make_key(size: int = 512) -> Image.Image:
    # Draw horizontal key (head left, teeth right), rotate +45° so orientation is BL -> TR.
    scale = 4
    W = size * scale
    base = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(base)

    gold = (198, 160, 62, 255)
    gold_edge = (150, 115, 35, 255)
    gold_hi = (230, 205, 120, 180)

    cy = W // 2
    head_r = int(W * 0.145)
    ring = int(W * 0.050)
    shaft_h = int(W * 0.085)
    shaft_len = int(W * 0.40)
    hx = int(W * 0.30)
    hy = cy

    # Head outer ring
    d.ellipse([hx - head_r, hy - head_r, hx + head_r, hy + head_r], fill=gold)
    # Soft highlight on ring
    d.arc(
        [hx - head_r + 6, hy - head_r + 6, hx + head_r - 6, hy + head_r - 6],
        start=200,
        end=320,
        fill=(230, 205, 120, 220),
        width=max(3, ring // 3),
    )

    # Shaft — 从圆环内部伸出，保证与头部实心衔接
    sx0 = hx + int(head_r * 0.15)
    sx1 = hx + head_r + shaft_len
    d.rectangle(
        [sx0, hy - shaft_h // 2, sx1 - shaft_h // 2, hy + shaft_h // 2],
        fill=gold,
    )
    # 杆端圆角
    d.ellipse(
        [sx1 - shaft_h, hy - shaft_h // 2, sx1, hy + shaft_h // 2],
        fill=gold,
    )
    # Shaft highlight
    d.rounded_rectangle(
        [hx + int(head_r * 0.55), hy - shaft_h // 2 + 3, sx1 - 14, hy - max(2, shaft_h // 5)],
        radius=3,
        fill=gold_hi,
    )

    # Key bit (teeth)
    bit_w = int(W * 0.12)
    bit_h = int(W * 0.17)
    bx0 = sx1 - bit_w
    by0 = hy - shaft_h // 2
    teeth = [
        (bx0, by0),
        (sx1, by0),
        (sx1, hy + bit_h),
        (sx1 - bit_w * 0.32, hy + bit_h),
        (sx1 - bit_w * 0.32, hy + bit_h * 0.52),
        (sx1 - bit_w * 0.58, hy + bit_h * 0.52),
        (sx1 - bit_w * 0.58, hy + bit_h * 0.82),
        (bx0 + bit_w * 0.12, hy + bit_h * 0.82),
        (bx0 + bit_w * 0.12, hy + bit_h * 0.38),
        (bx0, hy + bit_h * 0.38),
    ]
    d.polygon(teeth, fill=gold)
    # Small notch shade
    d.rectangle(
        [
            sx1 - bit_w * 0.52,
            hy + bit_h * 0.52,
            sx1 - bit_w * 0.36,
            hy + bit_h * 0.70,
        ],
        fill=gold_edge,
    )

    # Punch transparent hole in head ring
    r, g, b, a = base.split()
    ad = ImageDraw.Draw(a)
    ir = head_r - ring
    ad.ellipse([hx - ir, hy - ir, hx + ir, hy + ir], fill=0)
    base = Image.merge("RGBA", (r, g, b, a))

    # Rotate: head -> bottom-left, tip -> top-right
    rotated = base.rotate(45, resample=Image.Resampling.BICUBIC, expand=True, fillcolor=(0, 0, 0, 0))

    bbox = rotated.getbbox()
    if bbox is None:
        raise RuntimeError("empty icon")
    cropped = rotated.crop(bbox)
    cw, ch = cropped.size
    # Tight square, small padding only (no colored background)
    side = int(max(cw, ch) * 1.08)
    square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    square.paste(cropped, ((side - cw) // 2, (side - ch) // 2), cropped)
    return square.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    master = make_key(512)
    png_path = OUT_DIR / "app_icon.png"
    master.save(png_path)
    print("saved", png_path)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    # 小尺寸从 512 缩放，避免几何精度问题
    images = [master.resize((s, s), Image.Resampling.LANCZOS) for s in sizes]
    ico_path = OUT_DIR / "app.ico"
    images[-1].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[:-1],
    )
    print("saved", ico_path, ico_path.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
