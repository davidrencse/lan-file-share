"""A small, bespoke line-icon set drawn with QPainter (no external assets).

Every icon is drawn on a 24x24 logical grid with a 2px rounded stroke, in the
style of a modern icon system (Feather/Lucide-like) but hand-drawn here so the
app has zero icon-font/SVG-asset dependencies. Icons are cached per
(name, size, color) so repeated lookups are cheap.
"""

from __future__ import annotations

from typing import Callable, Dict, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

_CACHE: Dict[Tuple[str, int, str], QIcon] = {}

_G = 24  # logical grid size icons are authored against


def _pen(color: QColor, width: float = 1.9) -> QPen:
    pen = QPen(color)
    pen.setWidthF(width)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    return pen


def _computer(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawRoundedRect(QRectF(2.5, 4, 19, 12.5), 2, 2)
    p.drawLine(QPointF(9, 20.5), QPointF(15, 20.5))
    p.drawLine(QPointF(12, 16.5), QPointF(12, 20.5))


def _wifi(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawArc(QRectF(2, 8, 20, 20), 45 * 16, 90 * 16)
    p.drawArc(QRectF(5.5, 11.5, 13, 13), 45 * 16, 90 * 16)
    p.drawArc(QRectF(9, 15, 6, 6), 45 * 16, 90 * 16)
    p.setBrush(pen.color())
    p.drawEllipse(QPointF(12, 19.5), 1.1, 1.1)


def _folder(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(3, 6.5)
    path.lineTo(9, 6.5)
    path.lineTo(11, 8.5)
    path.lineTo(21, 8.5)
    path.lineTo(21, 18)
    path.arcTo(QRectF(19, 16, 2, 2), 90, -90)
    path.lineTo(5, 20)
    path.arcTo(QRectF(3, 16, 2, 2), 0, -90)
    path.lineTo(3, 6.5)
    p.drawPath(path)


def _check(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawPolyline([QPointF(4.5, 12.5), QPointF(9.5, 17.5), QPointF(19.5, 6.5)])


def _check_circle(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawEllipse(QRectF(2.5, 2.5, 19, 19))
    p.drawPolyline([QPointF(7.5, 12.5), QPointF(11, 16), QPointF(17, 8.5)])


def _x(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawLine(QPointF(5.5, 5.5), QPointF(18.5, 18.5))
    p.drawLine(QPointF(18.5, 5.5), QPointF(5.5, 18.5))


def _x_circle(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawEllipse(QRectF(2.5, 2.5, 19, 19))
    p.drawLine(QPointF(8.7, 8.7), QPointF(15.3, 15.3))
    p.drawLine(QPointF(15.3, 8.7), QPointF(8.7, 15.3))


def _chevron_right(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawPolyline([QPointF(9, 5), QPointF(16, 12), QPointF(9, 19)])


def _chevron_left(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawPolyline([QPointF(15, 5), QPointF(8, 12), QPointF(15, 19)])


def _arrow_left(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawLine(QPointF(20, 12), QPointF(5, 12))
    p.drawPolyline([QPointF(11, 6), QPointF(5, 12), QPointF(11, 18)])


def _sliders(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawLine(QPointF(4, 7), QPointF(20, 7))
    p.drawLine(QPointF(4, 12.5), QPointF(20, 12.5))
    p.drawLine(QPointF(4, 18), QPointF(20, 18))
    p.setBrush(QColor("#0c0e12"))
    p.drawEllipse(QPointF(14.5, 7), 2.1, 2.1)
    p.drawEllipse(QPointF(8.5, 12.5), 2.1, 2.1)
    p.drawEllipse(QPointF(16.5, 18), 2.1, 2.1)


def _eye(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(2.2, 12)
    path.cubicTo(5, 6.5, 19, 6.5, 21.8, 12)
    path.cubicTo(19, 17.5, 5, 17.5, 2.2, 12)
    p.drawPath(path)
    p.drawEllipse(QPointF(12, 12), 3, 3)


def _eye_off(p: QPainter, pen: QPen) -> None:
    _eye(p, pen)
    p.setPen(pen)
    p.drawLine(QPointF(4, 4), QPointF(20, 20))


def _copy(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawRoundedRect(QRectF(3.5, 3.5, 12, 12), 2.2, 2.2)
    p.drawRoundedRect(QRectF(8.5, 8.5, 12, 12), 2.2, 2.2)


def _refresh(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawArc(QRectF(4, 4, 16, 16), 40 * 16, 260 * 16)
    p.drawPolyline([QPointF(16.5, 3.8), QPointF(19.6, 6.2), QPointF(15.8, 8.4)])


def _send(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(3, 12.6)
    path.lineTo(20.5, 4)
    path.lineTo(13.2, 21)
    path.lineTo(10.6, 13.4)
    path.lineTo(3, 12.6)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(10.6, 13.4), QPointF(20.5, 4))


def _trash(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawLine(QPointF(4, 7), QPointF(20, 7))
    p.drawLine(QPointF(9, 3.5), QPointF(15, 3.5))
    path = QPainterPath()
    path.moveTo(6, 7)
    path.lineTo(7, 20)
    path.arcTo(QRectF(7, 18, 2, 2), 180, -90)
    path.lineTo(15.5, 20)
    path.arcTo(QRectF(15.5, 18, 2, 2), 90, -90)
    path.lineTo(18, 7)
    p.drawPath(path)
    p.drawLine(QPointF(10, 10.5), QPointF(10.5, 16.5))
    p.drawLine(QPointF(14, 10.5), QPointF(13.5, 16.5))


def _alert_triangle(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(12, 3.3)
    path.lineTo(21.3, 20)
    path.lineTo(2.7, 20)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(12, 9.5), QPointF(12, 14))
    p.setBrush(pen.color())
    p.drawEllipse(QPointF(12, 17), 1.05, 1.05)


def _shield_check(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(12, 2.8)
    path.lineTo(20, 5.6)
    path.lineTo(20, 11.5)
    path.cubicTo(20, 17, 16.5, 20.3, 12, 21.6)
    path.cubicTo(7.5, 20.3, 4, 17, 4, 11.5)
    path.lineTo(4, 5.6)
    path.closeSubpath()
    p.drawPath(path)
    p.drawPolyline([QPointF(8.3, 12), QPointF(11, 14.7), QPointF(16, 9)])


def _plus(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawLine(QPointF(12, 4.5), QPointF(12, 19.5))
    p.drawLine(QPointF(4.5, 12), QPointF(19.5, 12))


def _cloud(p: QPainter, pen: QPen) -> QPainterPath:
    path = QPainterPath()
    path.moveTo(6.5, 18)
    path.cubicTo(3, 18, 2, 15.3, 3.6, 13.4)
    path.cubicTo(2.3, 9.6, 6.4, 6.9, 9.5, 8.8)
    path.cubicTo(11.6, 5.6, 17, 6.4, 17.7, 10.3)
    path.cubicTo(21.2, 10.7, 21.6, 15.7, 18, 17.6)
    path.lineTo(6.5, 18)
    path.closeSubpath()
    p.setPen(pen)
    p.drawPath(path)
    return path


def _upload_cloud(p: QPainter, pen: QPen) -> None:
    _cloud(p, pen)
    p.drawLine(QPointF(12, 20.5), QPointF(12, 12))
    p.drawPolyline([QPointF(8.7, 15), QPointF(12, 11.5), QPointF(15.3, 15)])


def _download_cloud(p: QPainter, pen: QPen) -> None:
    _cloud(p, pen)
    p.drawLine(QPointF(12, 11.5), QPointF(12, 20))
    p.drawPolyline([QPointF(8.7, 16.5), QPointF(12, 20), QPointF(15.3, 16.5)])


def _search(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawEllipse(QRectF(3.5, 3.5, 11, 11))
    p.drawLine(QPointF(12.5, 12.5), QPointF(20, 20))


def _lock(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawRoundedRect(QRectF(4.5, 11, 15, 10.5), 2.4, 2.4)
    p.drawArc(QRectF(7.5, 4, 9, 9), 0, 180 * 16)
    p.drawLine(QPointF(7.5, 8.5), QPointF(7.5, 11))
    p.drawLine(QPointF(16.5, 8.5), QPointF(16.5, 11))
    p.setBrush(pen.color())
    p.drawEllipse(QPointF(12, 15.2), 1.3, 1.3)
    p.drawLine(QPointF(12, 16.3), QPointF(12, 18.2))


def _file(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(6, 2.5)
    path.lineTo(14.5, 2.5)
    path.lineTo(19, 7)
    path.lineTo(19, 21.5)
    path.lineTo(6, 21.5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawPolyline([QPointF(14.5, 2.5), QPointF(14.5, 7), QPointF(19, 7)])


def _inbox(p: QPainter, pen: QPen) -> None:
    p.setPen(pen)
    p.drawPolyline([
        QPointF(3, 13), QPointF(8, 13), QPointF(9.5, 16), QPointF(14.5, 16),
        QPointF(16, 13), QPointF(21, 13),
    ])
    path = QPainterPath()
    path.moveTo(3, 13)
    path.lineTo(6, 4.5)
    path.lineTo(18, 4.5)
    path.lineTo(21, 13)
    path.lineTo(21, 19)
    path.arcTo(QRectF(19, 17, 2, 2), 0, -90)
    path.lineTo(5, 21)
    path.arcTo(QRectF(3, 17, 2, 2), -90, -90)
    path.lineTo(3, 13)
    p.drawPath(path)


_DRAW: Dict[str, Callable[[QPainter, QPen], None]] = {
    "computer": _computer, "wifi": _wifi, "folder": _folder, "check": _check,
    "check_circle": _check_circle, "x": _x, "x_circle": _x_circle,
    "chevron_right": _chevron_right, "chevron_left": _chevron_left,
    "arrow_left": _arrow_left, "sliders": _sliders, "eye": _eye,
    "eye_off": _eye_off, "copy": _copy, "refresh": _refresh, "send": _send,
    "trash": _trash, "alert_triangle": _alert_triangle,
    "shield_check": _shield_check, "plus": _plus,
    "upload_cloud": _upload_cloud, "download_cloud": _download_cloud,
    "search": _search, "lock": _lock, "file": _file, "inbox": _inbox,
}


def icon(name: str, size: int = 20, color: str = "#eef1f6",
        stroke: float = 1.9) -> QIcon:
    key = (name, size, color)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    draw_fn = _DRAW.get(name)
    if draw_fn is None:
        raise KeyError(f"unknown icon: {name!r}")

    scale = 4  # render at 4x for crisp downscaling on any DPI
    px = QPixmap(size * scale, size * scale)
    px.fill(Qt.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size * scale / _G, size * scale / _G)
    pen = _pen(QColor(color), stroke)
    draw_fn(painter, pen)
    painter.end()

    result = QIcon(px)
    _CACHE[key] = result
    return result


def pixmap(name: str, size: int = 20, color: str = "#eef1f6",
          stroke: float = 1.9) -> QPixmap:
    return icon(name, size, color, stroke).pixmap(size, size)
