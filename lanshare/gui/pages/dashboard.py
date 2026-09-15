"""The home page: this device's info, the receiving toggle, and discovered
peers on the network."""

from __future__ import annotations

from collections import OrderedDict
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
    Card, EmptyState, ProgressRow, ToggleSwitch, button, divider,
    h_spacer, icon_button, label,
)
from ... import config as cfg_mod
from ... import identity
from ...netutil import describe_addresses, primary_lan_address


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
    help_requested = Signal()

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
        folder_btn = button("Downloads folder", cls="secondary", icon_name="folder")
        folder_btn.setMinimumHeight(38)
        folder_btn.clicked.connect(self._open_downloads)
        header.addWidget(folder_btn)
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
        controller.receive_complete.connect(self._on_receive_complete)
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
        # One address, not a list. This used to print every adapter -- Wi-Fi,
        # WSL and VirtualBox alike -- leaving no way to tell which one another
        # computer should actually be given.
        addr_row = QHBoxLayout()
        addr_row.setSpacing(6)
        addr_row.addWidget(label("Others reach you at", "secondary"))
        self.addr_label = label("", "mono")
        self.addr_label.setStyleSheet(f"color: {PALETTE.text}; font-size: 13px;")
        addr_row.addWidget(self.addr_label)
        copy_addr = icon_button("copy", size=13, tooltip="Copy this address")
        copy_addr.clicked.connect(
            lambda: QApplication.clipboard().setText(self._primary_addr or ""))
        addr_row.addWidget(copy_addr)
        addr_row.addWidget(h_spacer())
        col.addLayout(addr_row)
        self.other_addr_label = label("", "muted")
        self.other_addr_label.setWordWrap(True)
        col.addWidget(self.other_addr_label)
        row.addLayout(col, 1)

        ids_col = QVBoxLayout()
        ids_col.setAlignment(Qt.AlignRight)
        ids_col.setSpacing(2)
        ids_col.addWidget(label("SECRET ID (MUST MATCH)", "eyebrow"))
        sid_row = QHBoxLayout()
        self.secret_id_label = label("", "mono")
        self.secret_id_label.setStyleSheet(
            f"color: {PALETTE.text}; font-size: 15px; font-weight: 600;")
        sid_row.addWidget(self.secret_id_label)
        sid_copy = icon_button("copy", size=13, tooltip="Copy Secret ID")
        sid_copy.clicked.connect(
            lambda: QApplication.clipboard().setText(self.secret_id_label.text()))
        sid_row.addWidget(sid_copy)
        ids_col.addLayout(sid_row)
        self.fpr_label = label(_fpr_short(self.controller.fingerprint), "mono")
        self.fpr_label.setToolTip("This device's TLS identity fingerprint")
        ids_col.addWidget(self.fpr_label)
        row.addLayout(ids_col)

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
        self._progress_rows: "OrderedDict[str, ProgressRow]" = OrderedDict()

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

        self.empty_state = self._build_empty_state()
        self.peers_col.addWidget(self.empty_state)

        return card

    def _build_empty_state(self) -> QWidget:
        """Empty state that offers a way forward instead of a dead end."""
        wrap = QWidget()
        col = QVBoxLayout(wrap)
        col.setSpacing(10)
        col.addWidget(EmptyState(
            "wifi", "No devices found yet",
            "A device appears here only while it has Receiving switched on, "
            "and both devices must show the same Secret ID."))
        btn_row = QHBoxLayout()
        btn_row.addWidget(h_spacer())
        trouble = button("Why can't I see my other device?", cls="secondary",
                         icon_name="alert_triangle")
        trouble.clicked.connect(self._open_troubleshoot)
        btn_row.addWidget(trouble)
        btn_row.addWidget(h_spacer())
        col.addLayout(btn_row)
        return wrap

    def _open_troubleshoot(self) -> None:
        from ..dialogs import TroubleshootDialog

        TroubleshootDialog(self.controller, self).exec()
        self.on_show()

    # -- behaviour ----------------------------------------------------------

    def _on_toggle(self, checked: bool) -> None:
        if checked:
            if not self.controller.has_secret():
                # Snapping the toggle back with a one-line explanation was a
                # dead end; send the user somewhere that can fix it.
                self.toggle.setChecked(False, animate=False)
                self.receiving_sub.setText(
                    "No shared secret yet — open Help to set this device up.")
                self.help_requested.emit()
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
        # Keyed per file: the receiver can now serve several transfers at once,
        # and a single shared row would flicker between them.
        row = self._progress_rows.get(filename)
        if row is None:
            row = ProgressRow(filename, total)
            self._progress_rows[filename] = row
            self.progress_container.addWidget(row)
            self._trim_progress_rows()
        row.set_phase("Receiving...")
        row.set_progress(received, total)
        if received >= total:
            # All bytes are in, but the checksum has not been checked yet.
            # The real outcome arrives via _on_receive_complete().
            row.set_phase("Verifying...")

    def _trim_progress_rows(self, keep: int = 4) -> None:
        """Drop the oldest finished rows so the card cannot grow without bound."""
        while len(self._progress_rows) > keep:
            oldest_name = next(iter(self._progress_rows))
            widget = self._progress_rows.pop(oldest_name)
            widget.setParent(None)

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

    def _open_downloads(self) -> None:
        from .files import open_path

        open_path(cfg_mod.get_download_dir(self.controller.config))

    def _on_receive_complete(self, info: dict) -> None:
        """Final, truthful state for a received file.

        Previously the row flipped to "Saved" as soon as the byte count was
        reached -- before the checksum was verified and before the file was
        moved into place -- so it could claim success for a transfer that then
        failed.
        """
        row = self._progress_rows.get(info.get("name", ""))
        if row is None:
            return
        ok = info.get("status") == "ok"
        row.set_done(ok, "Saved" if ok else "Failed")

    def _enter_manual(self) -> None:
        dlg = ManualTargetDialog(int(self.controller.config["port"]), self)
        if dlg.exec():
            from ...discovery import Peer
            peer = Peer(name=dlg.host, ip=dlg.host, port=dlg.port, fingerprint="")
            self.send_requested.emit(peer)

    def on_show(self) -> None:
        """Re-read everything that can change while the app is open.

        The address in particular used to be computed once in the constructor,
        so it went stale as soon as the machine changed network.
        """
        self.controller.reload_config()
        self.name_label.setText(self.controller.config["device_name"])
        self.fpr_label.setText(_fpr_short(self.controller.fingerprint))
        self.secret_id_label.setText(cfg_mod.secret_fingerprint() or "not set")

        self._primary_addr = primary_lan_address()
        port = self.controller.config["port"]
        self.addr_label.setText(
            f"{self._primary_addr}  ·  port {port}" if self._primary_addr
            else "no network address detected")
        others = [f"{ip} ({role})" for ip, role in describe_addresses()
                  if role != "primary" and "loopback" not in role]
        self.other_addr_label.setText(
            "other adapters: " + ", ".join(others) if others else "")

    # Kept for callers that used the old name.
    refresh_device_info = on_show
