"""The main application window: sidebar navigation plus the page stack."""

from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget, QVBoxLayout,
    QWidget,
)

from . import icons
from .controller import AppController
from .dialogs import IncomingRequestDialog
from .pages.dashboard import DashboardPage
from .pages.files import FilesPage
from .pages.help import HelpPage
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

        # One declarative registry drives the stack, the sidebar and lookup.
        # These used to be three hand-synchronised lists plus a literal
        # key->index dict, so inserting a page anywhere but the end silently
        # broke navigation.
        self.dashboard_page = DashboardPage(self.controller)
        self.send_page = SendPage(self.controller)
        self.files_page = FilesPage(self.controller)
        self.help_page = HelpPage(self.controller)
        self.settings_page = SettingsPage(self.controller)

        self._pages: List[Tuple[str, str, str, QWidget]] = [
            ("dashboard", "Dashboard", "computer", self.dashboard_page),
            ("send", "Send Files", "send", self.send_page),
            ("files", "Files", "inbox", self.files_page),
            ("help", "Help", "shield_check", self.help_page),
            ("settings", "Settings", "sliders", self.settings_page),
        ]
        self._index_of = {key: i for i, (key, _t, _i, _w) in enumerate(self._pages)}

        layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        for _key, _title, _icon, widget in self._pages:
            self.stack.addWidget(widget)
        layout.addWidget(self.stack, 1)

        self.dashboard_page.send_requested.connect(self._go_send)
        self.dashboard_page.help_requested.connect(lambda: self.go("help"))
        for page in (self.send_page, self.files_page, self.help_page,
                     self.settings_page):
            if hasattr(page, "back_requested"):
                page.back_requested.connect(lambda: self.go("dashboard"))
        self.help_page.wizard_requested.connect(self._run_wizard)

        self.controller.incoming_request.connect(self._on_incoming_request)
        self.controller.start_discovery()

        self.go("dashboard")
        # A brand-new install has nothing configured; walk the user through it
        # rather than dropping them on a dashboard whose toggle refuses to move.
        QTimer.singleShot(250, self._maybe_run_wizard)

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
        for key, text, icon_name, _widget in self._pages:
            btn = NavButton(text, icon_name)
            btn.clicked.connect(lambda _checked=False, k=key: self.go(k))
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

    def go(self, key: str, peer: Optional[object] = None) -> None:
        """Switch to a page by name. Pages opt into refresh via on_show()."""
        index = self._index_of.get(key)
        if index is None:
            return
        self.stack.setCurrentIndex(index)
        for btn_key, btn in self.nav_buttons:
            btn.set_active(btn_key == key)
        widget = self._pages[index][3]
        if key == "send":
            self.send_page.reset_and_show(peer)
        elif hasattr(widget, "on_show"):
            widget.on_show()

    def _go_send(self, peer) -> None:
        self.go("send", peer)

    # -- first-run wizard ---------------------------------------------------

    def _maybe_run_wizard(self) -> None:
        cfg = self.controller.config
        if not self.controller.has_secret() or not cfg.get("wizard_done"):
            self._run_wizard()

    def _run_wizard(self) -> None:
        from .wizard import SetupWizard

        wizard = SetupWizard(self.controller, self)
        wizard.exec()
        self.controller.reload_config()
        self.controller.save_config({"wizard_done": True})
        self.dashboard_page.on_show()

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
