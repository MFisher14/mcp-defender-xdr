"""Crop a headless-Chrome screenshot down to the rendered window plus a margin.

Usage: python trim.py raw1.png out1.png [raw2.png out2.png ...]
"""

import sys

from PIL import Image, ImageChops

PAD = 40


def trim(path: str, out: str) -> None:
    im = Image.open(path).convert("RGB")
    background = Image.new("RGB", im.size, im.getpixel((2, 2)))
    diff = ImageChops.difference(im, background).convert("L").point(lambda v: 255 if v > 12 else 0)
    box = diff.getbbox()
    if box is None:
        raise SystemExit(f"{path}: nothing rendered")
    left, top, right, bottom = box
    im.crop(
        (
            max(left - PAD, 0),
            max(top - PAD, 0),
            min(right + PAD, im.width),
            min(bottom + PAD, im.height),
        )
    ).save(out, optimize=True)
    print(out, Image.open(out).size)


if __name__ == "__main__":
    args = sys.argv[1:]
    for src, dst in zip(args[::2], args[1::2], strict=True):
        trim(src, dst)
