"""Settings: device identity, network options, shared secret, self-test."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from typing import Optional

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QLineEdit, QMessageBox,
    QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

from ... import config as cfg_mod
from ... import identity
from ...safety import human_size, parse_size
from .. import icons
from ..controller import AppController
from ..theme import PALETTE
from ..widgets import Card, ToggleSwitch, button, divider, h_spacer, icon_button, label


class SelfTestThread(QThread):
    done = Signal(bool, str)

    def run(self) -> None:
        from ...selftest import run_selftest

        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                code = run_selftest()
            self.done.emit(code == 0, buf.getvalue())
        except Exception as exc:  # noqa: BLE001
            self.done.emit(False, f"{buf.getvalue()}\n{exc}")


class SettingsPage(QWidget):
    back_requested = Signal()

    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller
        self._selftest_thread: Optional[SelfTestThread] = None

        outer_scroll = QScrollArea()
        outer_scroll.setWidgetResizable(True)
        content = QWidget()
        outer = QVBoxLayout(content)
        outer.setContentsMargins(32, 28, 32, 40)
        outer.setSpacing(20)
        outer_scroll.setWidget(content)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(outer_scroll)

        header = QHBoxLayout()
        back_btn = icon_button("arrow_left", size=18, tooltip="Back to dashboard")
        back_btn.clicked.connect(self.back_requested.emit)
        header.addWidget(back_btn)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("SETTINGS", "eyebrow"))
        title_col.addWidget(label("Settings", "h1"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        outer.addLayout(header)

        outer.addWidget(self._build_general_card())
        outer.addWidget(self._build_security_card())
        outer.addWidget(self._build_selftest_card())
        outer.addStretch(1)

    # -- general ------------------------------------------------------------

    def _build_general_card(self) -> Card:
        cfg = self.controller.config
        card = Card()
        card.addWidget(label("GENERAL", "eyebrow"))

        card.addWidget(label("Device name", "secondary"))
        self.name_edit = QLineEdit(cfg["device_name"])
        card.addWidget(self.name_edit)

        card.addWidget(label("Download folder", "secondary"))
        dl_row = QHBoxLayout()
        self.dir_edit = QLineEdit(str(cfg_mod.get_download_dir(cfg)))
        dl_row.addWidget(self.dir_edit, 1)
        browse_btn = button("Browse...", cls="secondary")
        browse_btn.clicked.connect(self._browse_dir)
        dl_row.addWidget(browse_btn)
        card.addLayout(dl_row)

        row2 = QHBoxLayout()
        row2.setSpacing(24)

        port_col = QVBoxLayout()
        port_col.addWidget(label("TCP port", "secondary"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(int(cfg["port"]))
        port_col.addWidget(self.port_spin)
        row2.addLayout(port_col)

        size_col = QVBoxLayout()
        size_col.addWidget(label("Max accepted file size", "secondary"))
        self.max_size_edit = QLineEdit(human_size(int(cfg["max_file_bytes"])).replace(" ", ""))
        size_col.addWidget(self.max_size_edit)
        row2.addLayout(size_col)

        disc_col = QVBoxLayout()
        disc_col.addWidget(label("LAN discovery", "secondary"))
        disc_row = QHBoxLayout()
        self.discovery_toggle = ToggleSwitch(checked=bool(cfg.get("discovery_enabled", True)))
        disc_row.addWidget(self.discovery_toggle)
        disc_row.addWidget(label("Let other devices find you by name", "muted"))
        disc_col.addLayout(disc_row)
        row2.addLayout(disc_col, 1)

        card.addLayout(row2)
        card.addWidget(divider())

        save_row = QHBoxLayout()
        self.save_status = label("", "muted")
        save_row.addWidget(self.save_status)
        save_row.addWidget(h_spacer())
        save_btn = button("Save changes", cls="primary", icon_name="check",
                          icon_color=PALETTE.text_on_accent)
        save_btn.clicked.connect(self._save_general)
        save_row.addWidget(save_btn)
        card.addLayout(save_row)
        return card

    def _browse_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose download folder", self.dir_edit.text())
        if d:
            self.dir_edit.setText(d)

    def _save_general(self) -> None:
        name = self.name_edit.text().strip() or self.controller.config["device_name"]
        try:
            max_bytes = parse_size(self.max_size_edit.text())
        except ValueError:
            self.save_status.setText("Invalid max size (e.g. 500M, 20G).")
            self.save_status.setProperty("class", "tag-danger")
            return
        self.controller.save_config({
            "device_name": name,
            "download_dir": self.dir_edit.text().strip(),
            "port": self.port_spin.value(),
            "max_file_bytes": max_bytes,
            "discovery_enabled": self.discovery_toggle.isChecked(),
        })
        identity.ensure_identity(name)
        note = " (restart receiving to apply)" if self.controller.is_receiving() else ""
        self.save_status.setProperty("class", "tag-success")
        self.save_status.setText(f"Saved{note}.")
        self.save_status.style().unpolish(self.save_status)
        self.save_status.style().polish(self.save_status)

    # -- security -------------------------------------------------------

    def _build_security_card(self) -> Card:
        card = Card()
        card.addWidget(label("SECURITY", "eyebrow"))

        card.addWidget(label(
            "The shared secret authenticates devices to each other. Use the "
            "same value on every device you want to pair with.", "muted"))

        secret_row = QHBoxLayout()
        has_secret = cfg_mod.load_secret() is not None
        self.secret_edit = QLineEdit(self._current_secret_display() if has_secret else "")
        if not has_secret:
            self.secret_edit.setPlaceholderText("(none set)")
        self.secret_edit.setEchoMode(QLineEdit.Password if has_secret else QLineEdit.Normal)
        self.secret_edit.setReadOnly(True)
        self.secret_edit.setProperty("class", "mono")
        secret_row.addWidget(self.secret_edit, 1)
        self.eye_btn = icon_button("eye", size=15, tooltip="Show secret")
        self.eye_btn.clicked.connect(self._toggle_secret_visibility)
        self.eye_btn.setEnabled(has_secret)
        secret_row.addWidget(self.eye_btn)
        self.copy_secret_btn = icon_button("copy", size=15, tooltip="Copy secret")
        self.copy_secret_btn.clicked.connect(self._copy_secret)
        self.copy_secret_btn.setEnabled(has_secret)
        secret_row.addWidget(self.copy_secret_btn)
        card.addLayout(secret_row)

        gen_row = QHBoxLayout()
        gen_btn = button("Generate new secret", cls="danger", icon_name="refresh",
                         icon_color=PALETTE.danger)
        gen_btn.clicked.connect(self._regenerate_secret)
        gen_row.addWidget(gen_btn)
        gen_row.addWidget(h_spacer())
        card.addLayout(gen_row)
        card.addWidget(divider())

        card.addWidget(label("Pair with another device's secret", "secondary"))
        pair_row = QHBoxLayout()
        self.pair_edit = QLineEdit()
        self.pair_edit.setPlaceholderText("Paste the secret shown on the other device")
        pair_row.addWidget(self.pair_edit, 1)
        pair_btn = button("Set", cls="secondary")
        pair_btn.clicked.connect(self._set_secret)
        pair_row.addWidget(pair_btn)
        card.addLayout(pair_row)
        card.addWidget(divider())

        card.addWidget(label("Identity fingerprint (shown to devices you connect to)",
                             "secondary"))
        fpr_row = QHBoxLayout()
        fpr = identity.fingerprint_pretty(self.controller.fingerprint) if \
            self.controller.fingerprint else "(not generated yet)"
        self.fpr_edit = QLineEdit(fpr)
        self.fpr_edit.setReadOnly(True)
        self.fpr_edit.setProperty("class", "mono")
        fpr_row.addWidget(self.fpr_edit, 1)
        fpr_copy_btn = icon_button("copy", size=15, tooltip="Copy fingerprint")
        fpr_copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.controller.fingerprint))
        fpr_row.addWidget(fpr_copy_btn)
        card.addLayout(fpr_row)

        self.security_status = label("", "muted")
        card.addWidget(self.security_status)
        return card

    def _current_secret_display(self) -> str:
        secret = cfg_mod.load_secret()
        return secret.decode("utf-8", "replace") if secret else "(none set)"

    def _toggle_secret_visibility(self) -> None:
        showing = self.secret_edit.echoMode() == QLineEdit.Normal
        self.secret_edit.setEchoMode(QLineEdit.Password if showing else QLineEdit.Normal)
        self.eye_btn.setIcon(icons.icon(
            "eye" if showing else "eye_off", size=15, color=PALETTE.text_secondary))

    def _activate_secret_field(self, value: str) -> None:
        """Switch the secret field from its empty/placeholder state to showing
        a real (masked) secret, enabling the eye/copy controls."""
        self.secret_edit.setEchoMode(QLineEdit.Password)
        self.secret_edit.setPlaceholderText("")
        self.secret_edit.setText(value)
        self.eye_btn.setEnabled(True)
        self.copy_secret_btn.setEnabled(True)

    def _copy_secret(self) -> None:
        secret = cfg_mod.load_secret()
        if secret:
            QApplication.clipboard().setText(secret.decode("utf-8", "replace"))
            self._flash_security("Copied to clipboard.")

    def _regenerate_secret(self) -> None:
        reply = QMessageBox.question(
            self, "Generate new secret",
            "This invalidates the current secret. Every paired device will need "
            "the new value before it can send or receive with this device. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        new_secret = cfg_mod.generate_secret()
        cfg_mod.save_secret(new_secret)
        self._activate_secret_field(new_secret)
        self._flash_security("New secret generated -- share it with your other devices.")

    def _set_secret(self) -> None:
        value = self.pair_edit.text().strip()
        if len(value) < 8:
            self._flash_security("Secret must be at least 8 characters.", danger=True)
            return
        cfg_mod.save_secret(value)
        self._activate_secret_field(value)
        self.pair_edit.clear()
        self._flash_security("Secret updated.")

    def _flash_security(self, msg: str, danger: bool = False) -> None:
        self.security_status.setText(msg)
        self.security_status.setProperty("class", "tag-danger" if danger else "tag-success")
        self.security_status.style().unpolish(self.security_status)
        self.security_status.style().polish(self.security_status)

    # -- self-test ------------------------------------------------------

    def _build_selftest_card(self) -> Card:
        card = Card()
        card.addWidget(label("DIAGNOSTICS", "eyebrow"))
        row = QHBoxLayout()
        row.addWidget(label(
            "Runs a full loopback transfer on this machine to verify TLS, "
            "authentication and file handling all work.", "muted"))
        row.addWidget(h_spacer())
        self.selftest_btn = button("Run self-test", cls="secondary", icon_name="shield_check")
        self.selftest_btn.clicked.connect(self._run_selftest)
        row.addWidget(self.selftest_btn)
        card.addLayout(row)
        self.selftest_result = label("", "muted")
        card.addWidget(self.selftest_result)
        return card

    def _run_selftest(self) -> None:
        self.selftest_btn.setEnabled(False)
        self.selftest_result.setText("Running...")
        self.selftest_result.setProperty("class", "muted")
        thread = SelfTestThread(self)
        thread.done.connect(self._on_selftest_done)
        self._selftest_thread = thread
        thread.start()

    def _on_selftest_done(self, ok: bool, output: str) -> None:
        self.selftest_btn.setEnabled(True)
        self.selftest_result.setProperty("class", "tag-success" if ok else "tag-danger")
        self.selftest_result.setText("Self-test passed." if ok else "Self-test failed -- see logs.")
        self.selftest_result.style().unpolish(self.selftest_result)
        self.selftest_result.style().polish(self.selftest_result)
        if not ok:
            print(output)
