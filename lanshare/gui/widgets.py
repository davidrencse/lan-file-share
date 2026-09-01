"""Reusable, hand-styled widgets shared across the LANShare GUI pages."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import (
    Property, QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, Qt, Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QFrame, QGraphicsDropShadowEffect, QHBoxLayout, QLabel, QProgressBar,
    QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from . import icons
from .theme import PALETTE, badge_for_extension


def label(text: str, cls: str = "body", parent: Optional[QWidget] = None) -> QLabel:
    lbl = QLabel(text, parent)
    lbl.setProperty("class", cls)
    return lbl


def icon_button(name: str, *, size: int = 20, tooltip: str = "",
                cls: str = "icon", color: str = PALETTE.text_secondary) -> QPushButton:
    btn = QPushButton()
    btn.setProperty("class", cls)
    btn.setIcon(icons.icon(name, size=size, color=color))
    btn.setIconSize(QSize(size, size))
    btn.setCursor(Qt.PointingHandCursor)
    btn.setFixedSize(size + 14, size + 14)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def button(text: str, *, cls: str = "secondary", icon_name: Optional[str] = None,
          icon_color: Optional[str] = None) -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("class", cls)
    btn.setCursor(Qt.PointingHandCursor)
    if icon_name:
        color = icon_color or (PALETTE.text_on_accent if cls == "primary" else PALETTE.text)
        btn.setIcon(icons.icon(icon_name, size=15, color=color))
    return btn


def divider() -> QFrame:
    line = QFrame()
    line.setProperty("class", "divider")
    line.setFrameShape(QFrame.NoFrame)
    return line


class Card(QFrame):
    """An elevated surface panel with a soft drop shadow."""

    def __init__(self, flat: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setProperty("class", "card-flat" if flat else "card")
        if not flat:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(28)
            shadow.setOffset(0, 6)
            shadow.setColor(QColor(0, 0, 0, 110))
            self.setGraphicsEffect(shadow)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(20, 18, 20, 18)
        self.layout_.setSpacing(12)

    def addWidget(self, w: QWidget, stretch: int = 0) -> None:  # noqa: N802 -- Qt-style API
        self.layout_.addWidget(w, stretch)

    def addLayout(self, lay) -> None:  # noqa: N802
        self.layout_.addLayout(lay)


class ToggleSwitch(QWidget):
    """An iOS-style animated toggle switch."""

    toggled = Signal(bool)

    def __init__(self, checked: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(44, 26)
        self.setCursor(Qt.PointingHandCursor)
        self._checked = checked
        self._pos = 1.0 if checked else 0.0
        self._anim = QPropertyAnimation(self, b"knobPos", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def isChecked(self) -> bool:  # noqa: N802
        return self._checked

    def setChecked(self, value: bool, animate: bool = True) -> None:  # noqa: N802
        if value == self._checked:
            return
        self._checked = value
        self._anim.stop()
        if animate:
            self._anim.setStartValue(self._pos)
            self._anim.setEndValue(1.0 if value else 0.0)
            self._anim.start()
        else:
            self._pos = 1.0 if value else 0.0
            self.update()
        self.toggled.emit(value)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.setChecked(not self._checked)

    def _get_knob_pos(self) -> float:
        return self._pos

    def _set_knob_pos(self, value: float) -> None:
        self._pos = value
        self.update()

    knobPos = Property(float, _get_knob_pos, _set_knob_pos)  # noqa: N815

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        track_off = QColor(PALETTE.border_strong)
        track_on = QColor(PALETTE.accent)
        r = QColor(
            int(track_off.red() + (track_on.red() - track_off.red()) * self._pos),
            int(track_off.green() + (track_on.green() - track_off.green()) * self._pos),
            int(track_off.blue() + (track_on.blue() - track_off.blue()) * self._pos),
        )
        p.setPen(Qt.NoPen)
        p.setBrush(r)
        p.drawRoundedRect(QRectF(0, 0, 44, 26), 13, 13)
        knob_x = 3 + self._pos * (44 - 26 + 3 - 3)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QPointF(knob_x + 10, 13), 10, 10)


class Badge(QWidget):
    """A small colored square showing a file's extension, like a file-type tag."""

    def __init__(self, filename: str, size: int = 40, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
        self._text, self._bg, self._fg = badge_for_extension(ext)
        self._size = size

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(self._bg))
        p.drawRoundedRect(QRectF(0, 0, self._size, self._size), 10, 10)
        p.setPen(QColor(self._fg))
        font = QFont()
        font.setBold(True)
        font.setPixelSize(max(9, self._size // 5))
        p.setFont(font)
        p.drawText(self.rect(), Qt.AlignCenter, self._text)


class Spinner(QWidget):
    """A small indeterminate rotating-arc spinner."""

    def __init__(self, size: int = 20, color: str = PALETTE.accent,
                parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._angle = 0
        self._color = color
        self._anim = QPropertyAnimation(self, b"angle", self)
        self._anim.setDuration(900)
        self._anim.setStartValue(0)
        self._anim.setEndValue(360)
        self._anim.setLoopCount(-1)
        self._anim.start()

    def _get_angle(self) -> int:
        return self._angle

    def _set_angle(self, value: int) -> None:
        self._angle = value
        self.update()

    angle = Property(int, _get_angle, _set_angle)

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pen_w = max(2.0, self.width() / 10)
        rect = QRectF(pen_w, pen_w, self.width() - 2 * pen_w, self.height() - 2 * pen_w)
        from PySide6.QtGui import QPen
        pen = QPen(QColor(self._color))
        pen.setWidthF(pen_w)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, -self._angle * 16, 110 * 16)


class ProgressRow(QWidget):
    """A file-name / progress-bar / status row used during send & receive."""

    def __init__(self, filename: str, total_bytes: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.total_bytes = total_bytes
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.badge = Badge(filename, size=30)
        top.addWidget(self.badge)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        self.name_label = label(filename, "body")
        self.name_label.setStyleSheet("font-weight: 600;")
        self.status_label = label("Waiting...", "muted")
        text_col.addWidget(self.name_label)
        text_col.addWidget(self.status_label)
        top.addLayout(text_col, 1)

        self.pct_label = label("0%", "secondary")
        self.pct_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.pct_label.setFixedWidth(72)
        top.addWidget(self.pct_label)
        outer.addLayout(top)

        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        outer.addWidget(self.bar)

    def set_phase(self, phase: str) -> None:
        self.status_label.setText(phase)

    def set_progress(self, sent: int, total: int, rate_mib_s: float = 0.0) -> None:
        total = max(total, 1)
        frac = min(sent / total, 1.0)
        self.bar.setValue(int(frac * 1000))
        self.pct_label.setText(f"{int(frac * 100)}%")
        if rate_mib_s > 0:
            self.status_label.setText(f"{rate_mib_s:.1f} MiB/s")

    def set_done(self, ok: bool, message: str) -> None:
        self.bar.setValue(1000)
        self.bar.setProperty("state", "success" if ok else "danger")
        self.bar.style().unpolish(self.bar)
        self.bar.style().polish(self.bar)
        self.status_label.setText(message)
        self.status_label.setProperty("class", "tag-success" if ok else "tag-danger")
        self.pct_label.setText("")


class EmptyState(QWidget):
    """A muted placeholder shown when a list has nothing in it yet."""

    def __init__(self, icon_name: str, title: str, subtitle: str = "",
                parent: Optional[QWidget] = None):
        super().__init__(parent)
        col = QVBoxLayout(self)
        col.setAlignment(Qt.AlignCenter)
        col.setSpacing(8)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.pixmap(icon_name, size=32, color=PALETTE.text_muted))
        icon_lbl.setAlignment(Qt.AlignCenter)
        col.addWidget(icon_lbl)
        title_lbl = label(title, "secondary")
        title_lbl.setAlignment(Qt.AlignCenter)
        col.addWidget(title_lbl)
        if subtitle:
            sub_lbl = label(subtitle, "muted")
            sub_lbl.setAlignment(Qt.AlignCenter)
            sub_lbl.setWordWrap(True)
            col.addWidget(sub_lbl)
        self.setMinimumHeight(120)


def h_spacer() -> QWidget:
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    return w
