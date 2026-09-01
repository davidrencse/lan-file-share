"""A small custom splash screen shown while the app starts up."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from . import icons
from .theme import PALETTE
from .widgets import Spinner


class SplashScreen(QWidget):
    def __init__(self) -> None:
        super().__init__(
            None, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(360, 220)
        self._center_on_screen()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(12)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.pixmap("shield_check", size=46, color=PALETTE.accent))
        icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_lbl)

        title = QLabel("LANShare")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"color: {PALETTE.text}; font-size: 21px; font-weight: 700; background: transparent;"
        )
        layout.addWidget(title)

        sub = QLabel("Preparing a secure connection...")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(
            f"color: {PALETTE.text_muted}; font-size: 12px; background: transparent;"
        )
        layout.addWidget(sub)

        spinner_row = QHBoxLayout()
        spinner_row.setAlignment(Qt.AlignCenter)
        spinner_row.addWidget(Spinner(size=22))
        layout.addLayout(spinner_row)

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.geometry()
        self.move(geo.center().x() - self.width() // 2,
                 geo.center().y() - self.height() // 2)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(PALETTE.bg_elevated))
        pen = QPen(QColor(PALETTE.border))
        pen.setWidthF(1)
        painter.setPen(pen)
        rect = self.rect().adjusted(1, 1, -1, -1)
        painter.drawRoundedRect(rect, 20, 20)
