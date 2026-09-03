"""Modal dialogs: incoming-transfer approval, TOFU fingerprint warnings, and
manual host entry."""

from __future__ import annotations

from typing import Any, Dict, Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLineEdit, QSpinBox, QVBoxLayout, QWidget,
)

from . import icons
from .. import config as cfg_mod
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
    """Asks the user to accept or decline one incoming transfer.

    A folder arrives as a single request covering everything inside it, so the
    dialog says how many files and how much data that is -- the user is
    approving all of it at once, and should be told so.
    """

    def __init__(self, info: Dict[str, Any], parent: Optional[QWidget] = None,
                 timeout_seconds: int = 120):
        is_folder = info.get("kind") == "folder"
        super().__init__("Incoming folder" if is_folder else "Incoming file", parent)
        self.accepted_choice = False

        header = QHBoxLayout()
        from PySide6.QtWidgets import QLabel
        pic = QLabel()
        pic.setPixmap(icons.pixmap("folder" if is_folder else "download_cloud",
                                   size=26, color=PALETTE.accent))
        header.addWidget(pic)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label(
            "Incoming folder transfer" if is_folder else "Incoming file transfer",
            "h2"))
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
        if is_folder:
            count = int(info.get("count", 0))
            file_col.addWidget(label(
                f"{count} file{'s' if count != 1 else ''}  ·  "
                f"{human_size(info['size'])}", "secondary"))
        else:
            file_col.addWidget(label(human_size(info["size"]), "secondary"))
        file_row.addLayout(file_col, 1)
        self.body().addLayout(file_row)

        dest_note = f"Will be saved to:  {info['download_dir']}"
        if is_folder:
            dest_note += f"  (in a new “{info['safe_name']}” folder)"
        dest_lbl = label(dest_note, "muted")
        dest_lbl.setWordWrap(True)
        self.body().addWidget(dest_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self._countdown_label = label("", "muted")
        btn_row.addWidget(self._countdown_label)
        btn_row.addWidget(h_spacer())
        decline_btn = button("Decline", cls="secondary", icon_name="x")
        accept_btn = button("Accept", cls="primary", icon_name="check",
                            icon_color=PALETTE.text_on_accent)
        decline_btn.clicked.connect(self._decline)
        accept_btn.clicked.connect(self._accept)
        btn_row.addWidget(decline_btn)
        btn_row.addWidget(accept_btn)
        self.body().addLayout(btn_row)

        # Decline by ourselves before the waiting transfer thread gives up, so
        # the dialog can never linger over an offer that has already timed out
        # (clicking Accept then would appear to work but deliver nothing).
        self._remaining = int(timeout_seconds)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._tick()
        self._timer.start()

        decline_btn.setDefault(True)
        decline_btn.setAutoDefault(True)

    def _tick(self) -> None:
        if self._remaining <= 0:
            self._countdown_label.setText("expired")
            self._timer.stop()
            self._decline()
            return
        self._countdown_label.setText(f"auto-declines in {self._remaining}s")
        self._remaining -= 1

    def _accept(self) -> None:
        self._timer.stop()
        self.accepted_choice = True
        self.accept()

    def _decline(self) -> None:
        self._timer.stop()
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


class TroubleshootDialog(_BaseDialog):
    """Reports what this device can actually check, and states what it can't.

    Authenticated discovery means a wrong secret produces silence that looks
    exactly like an empty network, so the app has to explain the difference
    rather than leaving the user to guess between three invisible causes.
    """

    def __init__(self, controller, parent: Optional[QWidget] = None):
        super().__init__("Why can't I see my other device?", parent)
        self.controller = controller
        self.setMinimumWidth(560)

        self.body().addWidget(label("Checks on this device", "h2"))
        self._rows = QVBoxLayout()
        self.body().addLayout(self._rows)
        self.body().addWidget(divider())

        other = label(
            "This device cannot check the other one for you. On that device, "
            "confirm: LANShare is open, Receiving is switched on, and the "
            "Secret ID shown on its dashboard is identical to this one.",
            "secondary")
        other.setWordWrap(True)
        self.body().addWidget(other)

        self._action_row = QHBoxLayout()
        self.body().addLayout(self._action_row)

        btns = QHBoxLayout()
        btns.addWidget(h_spacer())
        recheck = button("Re-check", cls="secondary", icon_name="refresh")
        recheck.clicked.connect(self._run_checks)
        btns.addWidget(recheck)
        close = button("Close", cls="primary", icon_color=PALETTE.text_on_accent)
        close.clicked.connect(self.accept)
        btns.addWidget(close)
        self.body().addLayout(btns)

        self._run_checks()

    def _add(self, ok: Optional[bool], title: str, detail: str) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)
        from PySide6.QtWidgets import QLabel
        mark = QLabel()
        name, colour = (("check_circle", PALETTE.success) if ok is True else
                        ("x_circle", PALETTE.danger) if ok is False else
                        ("alert_triangle", PALETTE.warning))
        mark.setPixmap(icons.pixmap(name, size=16, color=colour))
        mark.setFixedWidth(20)
        row.addWidget(mark, 0)
        col = QVBoxLayout()
        col.setSpacing(1)
        col.addWidget(label(title, "body"))
        det = label(detail, "muted")
        det.setWordWrap(True)
        col.addWidget(det)
        row.addLayout(col, 1)
        holder = QWidget()
        holder.setLayout(row)
        self._rows.addWidget(holder)

    def _clear(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)

    def _run_checks(self) -> None:
        from ..netutil import describe_local_networks, primary_lan_address

        self._clear(self._rows)
        self._clear(self._action_row)
        self.controller.reload_config()

        secret_id = cfg_mod.secret_fingerprint()
        self._add(secret_id is not None, "Shared secret",
                  f"Secret ID {secret_id} — the other device must show exactly "
                  f"this." if secret_id else
                  "No secret set on this device. Open Help and run setup.")

        receiving = self.controller.is_receiving()
        self._add(receiving, "Receiving",
                  "On — this device is visible to others." if receiving else
                  "Off. Other devices cannot see this one, and cannot send to "
                  "it, while Receiving is off.")

        receiver = self.controller.live_receiver()
        disc_err = getattr(receiver, "discovery_error", None) if receiver else None
        if not receiving:
            self._add(None, "Discovery", "Not running (Receiving is off).")
        elif disc_err:
            self._add(False, "Discovery",
                      f"Could not start: {disc_err}. Others will not find this "
                      f"device automatically, but can still connect by IP.")
        else:
            self._add(True, "Discovery", "Answering queries on the network.")

        addr = primary_lan_address()
        port = self.controller.config["port"]
        self._add(addr is not None, "This device's address",
                  f"{addr}, port {port} — type this into 'Enter IP' on the "
                  f"other device if discovery is blocked." if addr else
                  "No network address detected. Are you connected to Wi-Fi?")

        self._add(None, "Networks treated as local", describe_local_networks())

        refused = dict(getattr(receiver, "refused_addresses", {}) or {}) if receiver else {}
        if refused:
            listing = ", ".join(f"{ip} ({n}x)" for ip, n in list(refused.items())[:4])
            self._add(False, "Refused connections",
                      f"Turned away {listing} — not on a network this device "
                      f"recognises as local. If that is your other computer, "
                      f"trust its network below.")
            trust = button("Trust these networks", cls="secondary",
                           icon_name="shield_check")
            trust.clicked.connect(lambda: self._trust(list(refused)))
            self._action_row.addWidget(h_spacer())
            self._action_row.addWidget(trust)

    def _trust(self, addresses) -> None:
        """Add the /24 around each refused address to the allow list."""
        import ipaddress

        cfg = self.controller.config
        nets = list(cfg.get("extra_local_networks") or [])
        for addr in addresses:
            try:
                net = ipaddress.ip_network(f"{addr}/24", strict=False)
            except ValueError:
                continue
            if str(net) not in nets:
                nets.append(str(net))
        self.controller.save_config({"extra_local_networks": nets})
        receiver = self.controller.live_receiver()
        if receiver is not None:
            receiver.refused_addresses.clear()
        self._run_checks()


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
