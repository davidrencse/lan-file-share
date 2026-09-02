"""The Help page: setup steps, this device's details, and troubleshooting."""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QScrollArea, QVBoxLayout, QWidget,
)

from ... import config as cfg_mod
from ... import identity
from ...netutil import describe_local_networks, primary_lan_address
from ..controller import AppController
from ..theme import FONT_MONO, PALETTE
from ..widgets import Card, button, divider, h_spacer, icon_button, label


def firewall_hint() -> tuple:
    """(description, command) for opening the ports on this OS."""
    if os.name == "nt":
        return (
            "Windows blocks incoming connections until you allow them. If the "
            "prompt never appeared, run this in an Administrator PowerShell:",
            'New-NetFirewallRule -DisplayName "LANShare" -Direction Inbound '
            '-Protocol TCP -LocalPort 51888 -Action Allow -Profile Private\n'
            'New-NetFirewallRule -DisplayName "LANShare discovery" -Direction '
            'Inbound -Protocol UDP -LocalPort 51889 -Action Allow -Profile Private',
        )
    return (
        "If you run a firewall (ufw is the usual one on Arch), allow the two "
        "ports on your local network:",
        "sudo ufw allow from 192.168.0.0/16 to any port 51888 proto tcp\n"
        "sudo ufw allow from 192.168.0.0/16 to any port 51889 proto udp",
    )


class _Step(QWidget):
    def __init__(self, number: int, title: str, body: str,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        num = label(str(number), "h2")
        num.setFixedWidth(24)
        num.setStyleSheet(f"color: {PALETTE.accent};")
        row.addWidget(num, 0)
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(label(title, "h3"))
        body_lbl = label(body, "secondary")
        body_lbl.setWordWrap(True)
        col.addWidget(body_lbl)
        row.addLayout(col, 1)


def _mono_block(text: str) -> QWidget:
    box = label(text, "mono")
    box.setWordWrap(True)
    box.setTextInteractionFlags(Qt.TextSelectableByMouse)  # let users copy it
    box.setStyleSheet(
        f"background: {PALETTE.surface_alt}; border: 1px solid {PALETTE.border};"
        f" border-radius: 8px; padding: 10px; font-family: {FONT_MONO};")
    return box


class HelpPage(QWidget):
    back_requested = Signal()
    wizard_requested = Signal()

    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        content = QWidget()
        outer = QVBoxLayout(content)
        outer.setContentsMargins(32, 28, 32, 40)
        outer.setSpacing(20)
        scroll.setWidget(content)
        page = QVBoxLayout(self)
        page.setContentsMargins(0, 0, 0, 0)
        page.addWidget(scroll)

        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("HELP", "eyebrow"))
        title_col.addWidget(label("How to set this up", "h1"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        again = button("Run setup again", cls="secondary", icon_name="refresh")
        again.clicked.connect(self.wizard_requested.emit)
        header.addWidget(again)
        outer.addLayout(header)

        outer.addWidget(self._steps_card())
        outer.addWidget(self._this_device_card())
        outer.addWidget(self._trouble_card())
        outer.addStretch(1)

    def _steps_card(self) -> Card:
        card = Card()
        card.addWidget(label("PAIRING TWO DEVICES", "eyebrow"))
        card.addWidget(label(
            "LANShare needs the same shared secret on both devices. Do this "
            "once; after that they find each other automatically.", "muted"))
        card.addWidget(divider())
        steps = [
            ("Install LANShare on both devices",
             "They must be on the same Wi-Fi or LAN."),
            ("Copy the shared secret from this device",
             "It is on this page below, and in Settings. Copy the whole value."),
            ("Paste it on the other device",
             "Open LANShare there → Settings → 'Pair with another device's "
             "secret' → paste → Set."),
            ("Check the Secret ID matches on both",
             "Both devices show a short Secret ID. If they differ, the secret "
             "was not pasted correctly — that is the single most common cause "
             "of devices not appearing."),
            ("Turn on Receiving on whichever device should receive",
             "A device is only visible to others while Receiving is on."),
            ("Send",
             "On the other device open Send Files, pick the target, choose "
             "files, and approve the transfer on the receiving side."),
        ]
        for i, (title, body) in enumerate(steps, start=1):
            card.addWidget(_Step(i, title, body))
        return card

    def _this_device_card(self) -> Card:
        card = Card()
        card.addWidget(label("THIS DEVICE", "eyebrow"))
        self._rows = {}
        for key, caption in (("name", "Device name"),
                             ("address", "Address for other devices"),
                             ("secret_id", "Secret ID (must match)"),
                             ("networks", "Networks treated as local")):
            row = QHBoxLayout()
            cap = label(caption, "secondary")
            cap.setFixedWidth(210)
            row.addWidget(cap)
            value = label("", "mono")
            value.setWordWrap(True)
            row.addWidget(value, 1)
            if key in ("address", "secret_id"):
                copy = icon_button("copy", size=14, tooltip="Copy")
                copy.clicked.connect(
                    lambda _c=False, k=key: QApplication.clipboard().setText(
                        self._rows[k].text()))
                row.addWidget(copy)
            self._rows[key] = value
            card.addLayout(row)
        self.on_show()
        return card

    def _trouble_card(self) -> Card:
        card = Card()
        card.addWidget(label("IF DEVICES DON'T APPEAR", "eyebrow"))
        for cause, fix in (
            ("The other device isn't receiving",
             "A device only shows up while its Receiving toggle is on."),
            ("The Secret IDs don't match",
             "Re-copy the secret and paste it again on the other device."),
            ("A firewall is blocking it",
             "See the command below; the receiving device needs TCP 51888 and "
             "UDP 51889 allowed."),
            ("The network blocks broadcast",
             "Guest Wi-Fi and many company networks do. Use 'Enter IP' on the "
             "Send page with the address shown above."),
            ("They're on different networks",
             "One on Wi-Fi and one on Ethernet/VPN often cannot reach each "
             "other. Put both on the same Wi-Fi."),
        ):
            row = QVBoxLayout()
            row.setSpacing(1)
            row.addWidget(label(f"• {cause}", "body"))
            detail = label(f"   {fix}", "muted")
            detail.setWordWrap(True)
            row.addWidget(detail)
            card.addLayout(row)

        card.addWidget(divider())
        desc, command = firewall_hint()
        desc_lbl = label(desc, "secondary")
        desc_lbl.setWordWrap(True)
        card.addWidget(desc_lbl)
        card.addWidget(_mono_block(command))
        copy_row = QHBoxLayout()
        copy_row.addWidget(h_spacer())
        copy_cmd = button("Copy command", cls="secondary", icon_name="copy")
        copy_cmd.clicked.connect(
            lambda: QApplication.clipboard().setText(command))
        copy_row.addWidget(copy_cmd)
        card.addLayout(copy_row)
        return card

    def on_show(self) -> None:
        self.controller.reload_config()
        addr = primary_lan_address()
        port = self.controller.config["port"]
        self._rows["name"].setText(self.controller.config["device_name"])
        self._rows["address"].setText(
            f"{addr}   (port {port})" if addr else "no network address detected")
        self._rows["secret_id"].setText(
            cfg_mod.secret_fingerprint() or "no secret set yet")
        self._rows["networks"].setText(describe_local_networks())
