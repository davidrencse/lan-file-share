"""Render the application icon to packaging/lanshare.ico.

The GUI draws its whole icon set with QPainter (see lanshare/gui/icons.py), so
there is no artwork file to ship. Windows executables, however, need a real
.ico -- this renders the same shield mark the app uses at the sizes Explorer,
the taskbar and the Alt-Tab switcher ask for.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from PySide6.QtCore import QRectF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter  # noqa: E402

from lanshare.gui import icons  # noqa: E402
from lanshare.gui.theme import PALETTE  # noqa: E402

SIZES = (16, 24, 32, 48, 64, 128, 256)


def _render(size: int) -> QImage:
    """The shield mark in accent colour on the app's dark background tile."""
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(PALETTE.bg))
    radius = size * 0.22
    p.drawRoundedRect(QRectF(0, 0, size, size), radius, radius)

    # The glyph is authored on a 24x24 grid; inset it so it does not touch the
    # rounded corners.
    glyph = round(size * 0.68)
    pix = icons.icon("shield_check", size=glyph, color=PALETTE.accent).pixmap(glyph, glyph)
    p.drawPixmap(round((size - glyph) / 2), round((size - glyph) / 2), pix)
    p.end()
    return img


def main() -> int:
    app = QGuiApplication([])  # noqa: F841 -- QPainter needs a Qt app alive
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lanshare.ico")
    images = [_render(s) for s in SIZES]
    # QImage.save() writes a single frame; build the multi-size .ico by hand so
    # every target size is a crisp render rather than a downscale of one image.
    _write_ico(out, images)
    print(f"wrote {out} ({', '.join(f'{s}x{s}' for s in SIZES)})")
    return 0


def _write_ico(path: str, images) -> None:
    import struct
    from PySide6.QtCore import QBuffer, QByteArray

    frames = []
    for img in images:
        # Hold the QByteArray in a local: QBuffer does not own it, and a
        # temporary would be freed while the buffer is still writing into it.
        data = QByteArray()
        buf = QBuffer(data)
        buf.open(QBuffer.WriteOnly)
        img.save(buf, "PNG")
        buf.close()
        frames.append((img.width(), img.height(), bytes(data)))

    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = len(header) + 16 * len(frames)
    entries, payload = b"", b""
    for w, h, data in frames:
        entries += struct.pack(
            "<BBBBHHII",
            0 if w >= 256 else w, 0 if h >= 256 else h, 0, 0, 1, 32,
            len(data), offset,
        )
        payload += data
        offset += len(data)

    with open(path, "wb") as fh:
        fh.write(header + entries + payload)


if __name__ == "__main__":
    raise SystemExit(main())
