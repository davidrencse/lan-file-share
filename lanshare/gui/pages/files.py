"""The Files page: everything this device has sent or received."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from ... import config as cfg_mod
from ... import history
from ...safety import human_size
from .. import icons
from ..controller import AppController
from ..theme import PALETTE
from ..widgets import (
    Badge, Card, EmptyState, button, divider, h_spacer, icon_button, label,
)


def open_path(path: Path) -> bool:
    """Open a file or folder with the desktop's default handler."""
    return QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


def reveal_in_folder(path: Path) -> bool:
    """Show a file selected inside the system file manager.

    Falls back to simply opening the containing directory, which is the part
    that reliably works everywhere -- selecting the item is a nicety and the
    mechanism differs per platform and per file manager.
    """
    try:
        if os.name == "nt":
            # Explorer needs /select and the path as ONE argument with the path
            # quoted inside it. Passing a list lets subprocess quote the whole
            # "/select,C:\\some path\\file" as a single quoted token, which
            # Explorer does not parse -- it silently opens Documents instead.
            subprocess.Popen(f'explorer /select,"{path}"')
            return True
        if sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(path)])
            return True
        # Linux: the freedesktop FileManager1 interface selects the item when
        # the running file manager implements it (Nautilus, Dolphin, Thunar).
        subprocess.Popen([
            "dbus-send", "--session", "--dest=org.freedesktop.FileManager1",
            "--type=method_call", "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowItems",
            f"array:string:{QUrl.fromLocalFile(str(path)).toString()}",
            "string:",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, ValueError):
        pass
    return open_path(path.parent)


class HistoryRow(QWidget):
    def __init__(self, rec: history.Record, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.rec = rec
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)

        arrow = QLabel()
        sent = rec.direction == history.SENT
        arrow.setPixmap(icons.pixmap(
            "send" if sent else "download_cloud", size=16,
            color=PALETTE.text_muted))
        arrow.setFixedWidth(20)
        outer.addWidget(arrow)
        outer.addWidget(Badge(rec.name, size=34))

        col = QVBoxLayout()
        col.setSpacing(1)
        name_lbl = label(rec.name, "body")
        name_lbl.setToolTip(rec.path or rec.name)
        col.addWidget(name_lbl)
        verb = "to" if sent else "from"
        detail = f"{human_size(rec.size)} · {verb} {rec.peer_name} · {history.relative_time(rec.at)}"
        col.addWidget(label(detail, "muted"))
        outer.addLayout(col, 1)

        if rec.status != history.OK:
            tag = label(
                "declined" if rec.status == history.DECLINED else "failed",
                "tag-warning" if rec.status == history.DECLINED else "tag-danger")
            tag.setToolTip(rec.error or "")
            outer.addWidget(tag)

        # Only a received file that actually landed has somewhere to open.
        if not sent and rec.status == history.OK and rec.path:
            exists = Path(rec.path).exists()
            open_btn = icon_button("folder", size=15,
                                   tooltip="Show in folder" if exists else "File has moved")
            open_btn.setEnabled(exists)
            open_btn.clicked.connect(lambda: reveal_in_folder(Path(rec.path)))
            outer.addWidget(open_btn)
            run_btn = button("Open", cls="secondary")
            run_btn.setEnabled(exists)
            run_btn.clicked.connect(lambda: open_path(Path(rec.path)))
            outer.addWidget(run_btn)


class FilesPage(QWidget):
    back_requested = Signal()

    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller
        self._filter = "all"

        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(20)

        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("FILES", "eyebrow"))
        title_col.addWidget(label("Sent & received", "h1"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        folder_btn = button("Open downloads folder", cls="secondary",
                            icon_name="folder")
        folder_btn.clicked.connect(self._open_downloads)
        header.addWidget(folder_btn)
        outer.addLayout(header)

        card = Card()
        controls = QHBoxLayout()
        controls.setSpacing(8)
        self._filter_buttons = {}
        for key, text in (("all", "All"), ("received", "Received"), ("sent", "Sent")):
            btn = button(text, cls="ghost")
            btn.clicked.connect(lambda _c=False, k=key: self._set_filter(k))
            controls.addWidget(btn)
            self._filter_buttons[key] = btn
        controls.addWidget(h_spacer())
        refresh_btn = icon_button("refresh", size=16, tooltip="Refresh")
        refresh_btn.clicked.connect(self.on_show)
        controls.addWidget(refresh_btn)
        clear_btn = button("Clear history", cls="danger", icon_name="trash",
                           icon_color=PALETTE.danger)
        clear_btn.clicked.connect(self._clear)
        controls.addWidget(clear_btn)
        card.addLayout(controls)
        card.addWidget(divider())

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        self.list_widget = QWidget()
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setSpacing(10)
        self.list_layout.addStretch(1)
        self.scroll.setWidget(self.list_widget)
        card.addWidget(self.scroll, 1)
        outer.addWidget(card, 1)

        self._set_filter("all")

    # -- behaviour ----------------------------------------------------------

    def _open_downloads(self) -> None:
        open_path(cfg_mod.get_download_dir(self.controller.config))

    def _set_filter(self, key: str) -> None:
        self._filter = key
        for btn_key, btn in self._filter_buttons.items():
            btn.setProperty("class", "secondary" if btn_key == key else "ghost")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self.on_show()

    def _clear(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        reply = QMessageBox.question(
            self, "Clear history",
            "Forget the list of sent and received files?\n\n"
            "This only clears the list — the files themselves are not deleted.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            history.clear()
            self.on_show()

    def on_show(self) -> None:
        """Reload from disk. Called whenever this page becomes visible."""
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)

        records: List[history.Record] = history.load()
        if self._filter != "all":
            records = [r for r in records if r.direction == self._filter]

        if not records:
            if self._filter == "sent":
                empty = EmptyState("send", "Nothing sent yet",
                                   "Files you send will be listed here.")
            elif self._filter == "received":
                empty = EmptyState("inbox", "Nothing received yet",
                                   "Turn on Receiving so other devices can send to you.")
            else:
                empty = EmptyState(
                    "inbox", "No transfers yet",
                    "Once you send or receive a file it will appear here, "
                    "with a shortcut to open it.")
            self.list_layout.insertWidget(0, empty)
            return

        for rec in records:
            self.list_layout.insertWidget(self.list_layout.count() - 1,
                                          HistoryRow(rec))
