"""The home page: this device's info, the receiving toggle, and discovered
peers on the network."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
)

from .. import icons
from ..controller import AppController
from ..dialogs import ManualTargetDialog
from ..theme import PALETTE
from ..widgets import (
    Badge, Card, EmptyState, ProgressRow, ToggleSwitch, button, divider,
    h_spacer, icon_button, label,
)
from ... import identity
from ...netutil import local_ipv4_addresses


def _fpr_short(fpr: str) -> str:
    pretty = identity.fingerprint_pretty(fpr) if fpr else ""
    return pretty[:23] + "…" if len(pretty) > 23 else pretty


class PeerRow(QWidget):
    send_clicked = Signal(object)

    def __init__(self, peer, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.peer = peer
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.pixmap("computer", size=22, color=PALETTE.text_secondary))
        icon_lbl.setFixedWidth(28)
        row.addWidget(icon_lbl)

        col = QVBoxLayout()
        col.setSpacing(1)
        col.addWidget(label(peer.name, "body"))
        col.addWidget(label(f"{peer.ip}:{peer.port}", "muted"))
        row.addLayout(col, 1)

        send_btn = button("Send files", cls="secondary", icon_name="send")
        send_btn.clicked.connect(lambda: self.send_clicked.emit(self.peer))
        row.addWidget(send_btn)


class DashboardPage(QWidget):
    send_requested = Signal(object)  # Peer or None

    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller

        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(20)

        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("DASHBOARD", "eyebrow"))
        title_col.addWidget(label("LANShare", "h1"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        send_btn = button("Send Files", cls="primary", icon_name="send",
                          icon_color=PALETTE.text_on_accent)
        send_btn.setMinimumHeight(38)
        send_btn.clicked.connect(lambda: self.send_requested.emit(None))
        header.addWidget(send_btn)
        outer.addLayout(header)

        outer.addWidget(self._build_device_card())
        outer.addWidget(self._build_receiving_card())
        outer.addWidget(self._build_peers_card(), 1)

        controller.receiving_changed.connect(self._on_receiving_changed)
        controller.receiver_error.connect(self._on_receiver_error)
        controller.receive_progress.connect(self._on_progress)
        controller.peers_changed.connect(self._on_peers)

    # -- cards ------------------------------------------------------------

    def _build_device_card(self) -> Card:
        card = Card()
        row = QHBoxLayout()
        row.setSpacing(14)
        pic = QLabel()
        pic.setPixmap(icons.pixmap("shield_check", size=30, color=PALETTE.accent))
        row.addWidget(pic)

        col = QVBoxLayout()
        col.setSpacing(2)
        self.name_label = label(self.controller.config["device_name"], "h2")
        col.addWidget(self.name_label)
        addrs = local_ipv4_addresses()
        addr_txt = ", ".join(addrs) if addrs else "no network address detected"
        col.addWidget(label(f"{addr_txt}  ·  port {self.controller.config['port']}",
                            "secondary"))
        row.addLayout(col, 1)

        fpr_col = QVBoxLayout()
        fpr_col.setAlignment(Qt.AlignRight)
        fpr_col.setSpacing(2)
        fpr_col.addWidget(label("IDENTITY FINGERPRINT", "eyebrow"))
        fpr_row = QHBoxLayout()
        self.fpr_label = label(_fpr_short(self.controller.fingerprint), "mono")
        fpr_row.addWidget(self.fpr_label)
        copy_btn = icon_button("copy", size=14, tooltip="Copy full fingerprint")
        copy_btn.clicked.connect(self._copy_fingerprint)
        fpr_row.addWidget(copy_btn)
        fpr_col.addLayout(fpr_row)
        row.addLayout(fpr_col)

        card.addLayout(row)
        return card

    def _build_receiving_card(self) -> Card:
        card = Card()
        row = QHBoxLayout()
        row.setSpacing(14)

        col = QVBoxLayout()
        col.setSpacing(2)
        head = QHBoxLayout()
        head.setSpacing(8)
        self.status_dot = QLabel()
        self.status_dot.setFixedSize(9, 9)
        self.status_dot.setObjectName("StatusDotOff")
        head.addWidget(self.status_dot)
        self.receiving_title = label("Not receiving", "h3")
        head.addWidget(self.receiving_title)
        head.addWidget(h_spacer())
        col.addLayout(head)
        self.receiving_sub = label(
            f"Turn this on to accept incoming files on port "
            f"{self.controller.config['port']}.", "muted")
        self.receiving_sub.setWordWrap(True)
        col.addWidget(self.receiving_sub)
        row.addLayout(col, 1)

        self.toggle = ToggleSwitch(checked=False)
        self.toggle.toggled.connect(self._on_toggle)
        row.addWidget(self.toggle, 0, Qt.AlignTop)
        card.addLayout(row)

        self.progress_container = QVBoxLayout()
        card.addLayout(self.progress_container)
        self._progress_row: Optional[ProgressRow] = None

        return card

    def _build_peers_card(self) -> Card:
        card = Card()
        head = QHBoxLayout()
        head_col = QVBoxLayout()
        head_col.setSpacing(2)
        head_col.addWidget(label("DEVICES ON YOUR NETWORK", "eyebrow"))
        head_col.addWidget(label("Discovered automatically over the LAN", "muted"))
        head.addLayout(head_col)
        head.addWidget(h_spacer())
        refresh_btn = icon_button("refresh", size=16, tooltip="Refresh now")
        refresh_btn.clicked.connect(self.controller.refresh_discovery)
        head.addWidget(refresh_btn)
        manual_btn = button("Enter IP", cls="ghost", icon_name="plus")
        manual_btn.clicked.connect(self._enter_manual)
        head.addWidget(manual_btn)
        card.addLayout(head)
        card.addWidget(divider())

        self.peers_col = QVBoxLayout()
        self.peers_col.setSpacing(10)
        card.addLayout(self.peers_col)

        self.empty_state = EmptyState(
            "wifi", "No devices found yet",
            "Make sure the other device is on and connected to this Wi-Fi/LAN.")
        self.peers_col.addWidget(self.empty_state)

        return card

    # -- behaviour ----------------------------------------------------------

    def _on_toggle(self, checked: bool) -> None:
        if checked:
            if not self.controller.has_secret():
                self.toggle.setChecked(False, animate=False)
                self.receiving_sub.setText(
                    "No shared secret is set yet -- set one in Settings first.")
                return
            self.controller.start_receiving()
        else:
            self.controller.stop_receiving()

    def _on_receiving_changed(self, on: bool) -> None:
        self.toggle.setChecked(on, animate=False)
        self.status_dot.setObjectName("StatusDotOn" if on else "StatusDotOff")
        self.status_dot.style().unpolish(self.status_dot)
        self.status_dot.style().polish(self.status_dot)
        self.receiving_title.setText("Receiving" if on else "Not receiving")
        port = self.controller.config["port"]
        if on:
            self.receiving_sub.setText(f"Listening on port {port}. Files need your approval.")
        else:
            self.receiving_sub.setText(
                f"Turn this on to accept incoming files on port {port}.")

    def _on_receiver_error(self, msg: str) -> None:
        self.receiving_sub.setText(f"Could not start receiving: {msg}")

    def _on_progress(self, filename: str, received: int, total: int) -> None:
        if self._progress_row is None or self._progress_row.name_label.text() != filename:
            if self._progress_row is not None:
                self._progress_row.setParent(None)
            self._progress_row = ProgressRow(filename, total)
            self.progress_container.addWidget(self._progress_row)
        self._progress_row.set_phase("Receiving...")
        self._progress_row.set_progress(received, total)
        if received >= total:
            self._progress_row.set_done(True, "Saved")

    def _on_peers(self, peers) -> None:
        while self.peers_col.count():
            item = self.peers_col.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        if not peers:
            self.peers_col.addWidget(self.empty_state)
            return
        for peer in peers:
            row = PeerRow(peer)
            row.send_clicked.connect(lambda p: self.send_requested.emit(p))
            self.peers_col.addWidget(row)

    def _copy_fingerprint(self) -> None:
        QApplication.clipboard().setText(self.controller.fingerprint)

    def _enter_manual(self) -> None:
        dlg = ManualTargetDialog(int(self.controller.config["port"]), self)
        if dlg.exec():
            from ...discovery import Peer
            peer = Peer(name=dlg.host, ip=dlg.host, port=dlg.port, fingerprint="")
            self.send_requested.emit(peer)

    def refresh_device_info(self) -> None:
        self.controller.reload_config()
        self.name_label.setText(self.controller.config["device_name"])
        self.fpr_label.setText(_fpr_short(self.controller.fingerprint))
