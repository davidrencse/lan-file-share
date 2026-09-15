"""First-run setup wizard.

Without this, a new install drops the user on a dashboard whose Receiving
toggle silently snaps back off (because no secret is set) and whose device list
is permanently empty. This walks through the three things that actually have to
happen, in order.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QLineEdit, QStackedWidget, QVBoxLayout,
    QWidget,
)

from .. import config as cfg_mod
from ..netutil import primary_lan_address
from . import icons
from .controller import AppController
from .theme import FONT_MONO, PALETTE
from .widgets import Card, button, divider, h_spacer, icon_button, label


class SetupWizard(QDialog):
    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Set up LANShare")
        self.setModal(True)
        self.setMinimumWidth(560)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        head = QHBoxLayout()
        from PySide6.QtWidgets import QLabel
        pic = QLabel()
        pic.setPixmap(icons.pixmap("shield_check", size=28, color=PALETTE.accent))
        head.addWidget(pic)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("Welcome to LANShare", "h1"))
        self.subtitle = label("Send files between your devices, over your own "
                              "network.", "secondary")
        title_col.addWidget(self.subtitle)
        head.addLayout(title_col)
        head.addWidget(h_spacer())
        root.addLayout(head)
        root.addWidget(divider())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._step_name())
        self.stack.addWidget(self._step_secret())
        self.stack.addWidget(self._step_receive())
        root.addWidget(self.stack)

        nav = QHBoxLayout()
        self.step_label = label("", "muted")
        nav.addWidget(self.step_label)
        nav.addWidget(h_spacer())
        self.back_btn = button("Back", cls="ghost")
        self.back_btn.clicked.connect(self._back)
        nav.addWidget(self.back_btn)
        self.next_btn = button("Next", cls="primary",
                               icon_color=PALETTE.text_on_accent)
        self.next_btn.clicked.connect(self._next)
        nav.addWidget(self.next_btn)
        root.addLayout(nav)

        self._sync()

    # -- steps --------------------------------------------------------------

    def _step_name(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setSpacing(10)
        col.addWidget(label("What should this device be called?", "h2"))
        col.addWidget(label(
            "Other devices see this name when you send them something.",
            "secondary"))
        self.name_edit = QLineEdit(self.controller.config["device_name"])
        col.addWidget(self.name_edit)
        col.addStretch(1)
        return page

    def _step_secret(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setSpacing(10)
        col.addWidget(label("Pair with your other device", "h2"))
        blurb = label(
            "Both devices must share one secret. Copy the value below, then on "
            "your other device open LANShare → Settings → \"Pair with another "
            "device's secret\" → paste it → Set.", "secondary")
        blurb.setWordWrap(True)
        col.addWidget(blurb)

        secret_card = Card(flat=True)
        row = QHBoxLayout()
        self.secret_value = label("", "mono")
        self.secret_value.setWordWrap(True)
        self.secret_value.setStyleSheet(
            f"font-family: {FONT_MONO}; font-size: 15px; color: {PALETTE.text};")
        row.addWidget(self.secret_value, 1)
        copy_btn = icon_button("copy", size=16, tooltip="Copy secret")
        copy_btn.clicked.connect(self._copy_secret)
        row.addWidget(copy_btn)
        secret_card.addLayout(row)
        col.addWidget(secret_card)

        self.secret_id_label = label("", "secondary")
        self.secret_id_label.setWordWrap(True)
        col.addWidget(self.secret_id_label)
        self.copied_note = label("", "tag-success")
        col.addWidget(self.copied_note)
        col.addStretch(1)
        return page

    def _step_receive(self) -> QWidget:
        page = QWidget()
        col = QVBoxLayout(page)
        col.setSpacing(10)
        col.addWidget(label("You're set up", "h2"))
        body = label(
            "To receive files, switch Receiving on from the Dashboard — a "
            "device is only visible to others while that is on, and every "
            "incoming file still asks for your approval.\n\n"
            "To send, open Send Files, pick the device, choose your files.",
            "secondary")
        body.setWordWrap(True)
        col.addWidget(body)

        self.addr_label = label("", "muted")
        self.addr_label.setWordWrap(True)
        col.addWidget(self.addr_label)

        note = label(
            "The first time you switch Receiving on, your firewall may ask "
            "whether to allow LANShare. Allow it on private networks, or the "
            "other device will never see this one.", "secondary")
        note.setWordWrap(True)
        col.addWidget(note)
        col.addStretch(1)
        return page

    # -- behaviour ----------------------------------------------------------

    def _copy_secret(self) -> None:
        secret = cfg_mod.load_secret()
        if secret:
            QApplication.clipboard().setText(secret.decode("utf-8", "replace"))
            self.copied_note.setText("Copied — now paste it on your other device.")

    def _ensure_secret(self) -> None:
        if not cfg_mod.load_secret():
            cfg_mod.save_secret(cfg_mod.generate_secret())
        secret = cfg_mod.load_secret() or b""
        self.secret_value.setText(secret.decode("utf-8", "replace"))
        self.secret_id_label.setText(
            f"Secret ID: {cfg_mod.secret_fingerprint()} — the other device must "
            f"show this same ID once you have pasted the secret there.")

    def _sync(self) -> None:
        index = self.stack.currentIndex()
        self.step_label.setText(f"Step {index + 1} of 3")
        self.back_btn.setEnabled(index > 0)
        self.next_btn.setText("Finish" if index == 2 else "Next")
        if index == 1:
            self._ensure_secret()
        if index == 2:
            addr = primary_lan_address()
            port = self.controller.config["port"]
            self.addr_label.setText(
                f"If discovery is blocked on your network, the other device can "
                f"reach this one directly at {addr}, port {port}."
                if addr else "No network address detected yet.")

    def _back(self) -> None:
        self.stack.setCurrentIndex(max(0, self.stack.currentIndex() - 1))
        self._sync()

    def _next(self) -> None:
        index = self.stack.currentIndex()
        if index == 0:
            name = self.name_edit.text().strip()
            if name:
                self.controller.save_config({"device_name": name})
        if index == 2:
            self.controller.save_config({"wizard_done": True})
            self.accept()
            return
        self.stack.setCurrentIndex(index + 1)
        self._sync()
