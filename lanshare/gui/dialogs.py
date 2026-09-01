"""Modal dialogs: incoming-transfer approval, TOFU fingerprint warnings, and
manual host entry."""

from __future__ import annotations

from typing import Any, Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLineEdit, QSpinBox, QVBoxLayout, QWidget,
)

from . import icons
from ..safety import human_size
from .theme import PALETTE
from .widgets import Badge, button, divider, h_spacer, label


class _BaseDialog(QDialog):
    def __init__(self, title: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.setModal(True)
        self.setWindowFlag(Qt.FramelessWindowHint, False)
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(24, 22, 24, 22)
        self._root.setSpacing(16)

    def body(self) -> QVBoxLayout:
        return self._root


class IncomingRequestDialog(_BaseDialog):
    """Asks the user to accept or decline one incoming file transfer."""

    def __init__(self, info: Dict[str, Any], parent: Optional[QWidget] = None):
        super().__init__("Incoming file", parent)
        self.accepted_choice = False

        header = QHBoxLayout()
        from PySide6.QtWidgets import QLabel
        pic = QLabel()
        pic.setPixmap(icons.pixmap("download_cloud", size=26, color=PALETTE.accent))
        header.addWidget(pic)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("Incoming file transfer", "h2"))
        sub = f"From {info['peer_name']}  ·  {info['peer_ip']}"
        title_col.addWidget(label(sub, "secondary"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        self.body().addLayout(header)

        self.body().addWidget(divider())

        file_row = QHBoxLayout()
        file_row.setSpacing(12)
        file_row.addWidget(Badge(info["safe_name"], size=44))
        file_col = QVBoxLayout()
        file_col.setSpacing(2)
        name_lbl = label(info["safe_name"], "h3")
        name_lbl.setWordWrap(True)
        file_col.addWidget(name_lbl)
        if info["safe_name"] != info["raw_name"]:
            file_col.addWidget(label(f"sent as “{info['raw_name']}”", "muted"))
        file_col.addWidget(label(human_size(info["size"]), "secondary"))
        file_row.addLayout(file_col, 1)
        self.body().addLayout(file_row)

        dest_lbl = label(f"Will be saved to:  {info['download_dir']}", "muted")
        dest_lbl.setWordWrap(True)
        self.body().addWidget(dest_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        decline_btn = button("Decline", cls="secondary", icon_name="x")
        accept_btn = button("Accept", cls="primary", icon_name="check",
                            icon_color=PALETTE.text_on_accent)
        decline_btn.clicked.connect(self._decline)
        accept_btn.clicked.connect(self._accept)
        btn_row.addWidget(decline_btn)
        btn_row.addWidget(accept_btn)
        self.body().addLayout(btn_row)

        accept_btn.setDefault(True)
        accept_btn.setAutoDefault(True)

    def _accept(self) -> None:
        self.accepted_choice = True
        self.accept()

    def _decline(self) -> None:
        self.accepted_choice = False
        self.reject()


class TofuWarningDialog(_BaseDialog):
    """Warns that a known device's identity fingerprint has changed."""

    def __init__(self, peer_name: str, known_fpr: str, new_fpr: str,
                parent: Optional[QWidget] = None):
        super().__init__("Identity changed", parent)
        self.proceed = False

        header = QHBoxLayout()
        from PySide6.QtWidgets import QLabel
        pic = QLabel()
        pic.setPixmap(icons.pixmap("alert_triangle", size=26, color=PALETTE.warning))
        header.addWidget(pic)
        header.addWidget(label("This device's identity changed", "h2"))
        header.addWidget(h_spacer())
        self.body().addLayout(header)

        msg = (
            f"'{peer_name}' previously connected with a different security "
            f"identity. This can happen if that device was reinstalled or its "
            f"data was reset -- but it could also mean another device on this "
            f"network is impersonating it."
        )
        msg_lbl = label(msg, "secondary")
        msg_lbl.setWordWrap(True)
        self.body().addWidget(msg_lbl)

        for text, value in (("Previously", known_fpr), ("Now", new_fpr)):
            row = QHBoxLayout()
            row.addWidget(label(f"{text}:", "muted"))
            fpr_lbl = label(_pretty_fpr(value), "mono")
            fpr_lbl.setWordWrap(True)
            row.addWidget(fpr_lbl, 1)
            self.body().addLayout(row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        cancel_btn = button("Cancel Send", cls="primary")
        proceed_btn = button("Continue Anyway", cls="danger")
        cancel_btn.clicked.connect(self._cancel)
        proceed_btn.clicked.connect(self._proceed)
        btn_row.addWidget(proceed_btn)
        btn_row.addWidget(h_spacer())
        btn_row.addWidget(cancel_btn)
        self.body().addLayout(btn_row)

        cancel_btn.setDefault(True)

    def _proceed(self) -> None:
        self.proceed = True
        self.accept()

    def _cancel(self) -> None:
        self.proceed = False
        self.reject()


def _pretty_fpr(hex_fpr: str) -> str:
    return ":".join(hex_fpr[i:i + 2] for i in range(0, len(hex_fpr), 2))


class ManualTargetDialog(_BaseDialog):
    """Lets the user type an IP address and port directly."""

    def __init__(self, default_port: int, parent: Optional[QWidget] = None):
        super().__init__("Enter device address", parent)
        self.host = ""
        self.port = default_port

        self.body().addWidget(label("Connect by IP address", "h2"))
        self.body().addWidget(
            label("Use this if the device doesn't show up automatically.", "muted")
        )

        row = QHBoxLayout()
        row.setSpacing(10)
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("e.g. 192.168.1.42")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(default_port)
        self.port_spin.setFixedWidth(90)
        row.addWidget(self.host_edit, 1)
        row.addWidget(self.port_spin)
        self.body().addLayout(row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        cancel_btn = button("Cancel", cls="secondary")
        ok_btn = button("Continue", cls="primary", icon_name="chevron_right",
                        icon_color=PALETTE.text_on_accent)
        cancel_btn.clicked.connect(self.reject)
        ok_btn.clicked.connect(self._confirm)
        btn_row.addWidget(h_spacer())
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(ok_btn)
        self.body().addLayout(btn_row)
        self.host_edit.returnPressed.connect(self._confirm)
        self.host_edit.setFocus()

    def _confirm(self) -> None:
        text = self.host_edit.text().strip()
        if not text:
            self.host_edit.setStyleSheet(f"border: 1px solid {PALETTE.danger};")
            return
        self.host = text
        self.port = self.port_spin.value()
        self.accept()
