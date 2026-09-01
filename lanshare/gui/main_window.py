"""The main application window: sidebar navigation plus the page stack."""

from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget, QVBoxLayout,
    QWidget,
)

from . import icons
from .controller import AppController
from .dialogs import IncomingRequestDialog
from .pages.dashboard import DashboardPage
from .pages.send import SendPage
from .pages.settings import SettingsPage
from .theme import PALETTE
from .widgets import h_spacer, label


class NavButton(QPushButton):
    def __init__(self, text: str, icon_name: str):
        super().__init__(text)
        self.setProperty("class", "navitem")
        self.setProperty("active", "false")
        self._icon_name = icon_name
        self.setIcon(icons.icon(icon_name, size=16, color=PALETTE.text_secondary))
        self.setCursor(Qt.PointingHandCursor)

    def set_active(self, active: bool) -> None:
        color = PALETTE.text if active else PALETTE.text_secondary
        self.setIcon(icons.icon(self._icon_name, size=16, color=color))
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LANShare")
        self.resize(1060, 720)
        self.setMinimumSize(900, 600)

        self.controller = AppController()

        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(self.controller)
        self.send_page = SendPage(self.controller)
        self.settings_page = SettingsPage(self.controller)
        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.send_page)
        self.stack.addWidget(self.settings_page)
        layout.addWidget(self.stack, 1)

        self.dashboard_page.send_requested.connect(self._go_send)
        self.send_page.back_requested.connect(lambda: self._go(0))
        self.settings_page.back_requested.connect(lambda: self._go(0))

        self.controller.incoming_request.connect(self._on_incoming_request)
        self.controller.start_discovery()

        self._go(0)

    # -- sidebar --------------------------------------------------------

    def _build_sidebar(self) -> QWidget:
        sb = QWidget()
        sb.setObjectName("Sidebar")
        sb.setFixedWidth(224)
        col = QVBoxLayout(sb)
        col.setContentsMargins(20, 24, 16, 20)
        col.setSpacing(4)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        brand_icon = QLabel()
        brand_icon.setPixmap(icons.pixmap("shield_check", size=24, color=PALETTE.accent))
        brand_row.addWidget(brand_icon)
        brand_col = QVBoxLayout()
        brand_col.setSpacing(0)
        brand_name = label("LANShare", "body")
        brand_name.setObjectName("SidebarBrand")
        brand_col.addWidget(brand_name)
        sub = label("Local network transfer", "muted")
        sub.setObjectName("SidebarSub")
        brand_col.addWidget(sub)
        brand_row.addLayout(brand_col)
        col.addLayout(brand_row)
        col.addSpacing(28)

        self.nav_buttons: List[Tuple[str, NavButton]] = []
        for key, text, icon_name in (
            ("dashboard", "Dashboard", "computer"),
            ("send", "Send Files", "send"),
            ("settings", "Settings", "sliders"),
        ):
            btn = NavButton(text, icon_name)
            btn.clicked.connect(lambda _checked=False, k=key: self._go_key(k))
            col.addWidget(btn)
            self.nav_buttons.append((key, btn))

        col.addStretch(1)

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.sidebar_status_dot = QLabel()
        self.sidebar_status_dot.setFixedSize(8, 8)
        self.sidebar_status_dot.setObjectName("StatusDotOff")
        status_row.addWidget(self.sidebar_status_dot)
        self.sidebar_status_label = label("Not receiving", "muted")
        status_row.addWidget(self.sidebar_status_label)
        status_row.addWidget(h_spacer())
        col.addLayout(status_row)

        self.controller.receiving_changed.connect(self._on_receiving_changed_sidebar)
        return sb

    def _on_receiving_changed_sidebar(self, on: bool) -> None:
        self.sidebar_status_dot.setObjectName("StatusDotOn" if on else "StatusDotOff")
        self.sidebar_status_dot.style().unpolish(self.sidebar_status_dot)
        self.sidebar_status_dot.style().polish(self.sidebar_status_dot)
        self.sidebar_status_label.setText("Receiving" if on else "Not receiving")

    # -- navigation -------------------------------------------------------

    def _go_key(self, key: str) -> None:
        mapping = {"dashboard": 0, "send": 1, "settings": 2}
        self._go(mapping[key])

    def _go(self, index: int, peer: Optional[object] = None) -> None:
        self.stack.setCurrentIndex(index)
        for i, (_key, btn) in enumerate(self.nav_buttons):
            btn.set_active(i == index)
        if index == 0:
            self.dashboard_page.refresh_device_info()
        elif index == 1:
            self.send_page.reset_and_show(peer)

    def _go_send(self, peer) -> None:
        self._go(1, peer)

    # -- global incoming-transfer dialog ------------------------------------

    def _on_incoming_request(self, info: dict, responder) -> None:
        self.raise_()
        self.activateWindow()
        dlg = IncomingRequestDialog(info, self)
        dlg.exec()
        responder.resolve(dlg.accepted_choice)

    def closeEvent(self, event) -> None:  # noqa: N802
        self.controller.shutdown()
        super().closeEvent(event)
