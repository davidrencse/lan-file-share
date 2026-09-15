"""The send flow: pick files/folders, pick a target device, watch progress,
see results."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QPlainTextEdit, QScrollArea,
    QStackedWidget, QVBoxLayout, QWidget,
)

from ... import discovery as discovery_mod
from ...safety import human_size
from .. import icons
from ..controller import AppController
from ..dialogs import ManualTargetDialog, TofuWarningDialog
from ..theme import FONT_MONO, PALETTE
from ..widgets import (
    Badge, Card, EmptyState, ProgressRow, Spinner, button, divider, h_spacer,
    icon_button, label,
)
from ..workers import SendThread

# The results screen builds one widget per row; a folder send can return
# thousands of results, so only this many are rendered.
_MAX_RESULT_ROWS = 100


def folder_summary(folder: Path) -> str:
    """A "N files - size" summary for a folder, or why it cannot be sent.

    Walking a large tree is not instant, so callers must keep this off the UI
    thread for anything that might be big.
    """
    count = 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(folder, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            try:
                total += path.stat().st_size
            except OSError:
                continue
            count += 1
    if not count:
        return "empty folder"
    return f"{count} file{'s' if count != 1 else ''}  ·  {human_size(total)}"


class FileRow(QWidget):
    removed = Signal(object)

    def __init__(self, path: Path, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.path = path
        is_folder = path.is_dir()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        if is_folder:
            badge = QLabel()
            badge.setFixedSize(36, 36)
            badge.setAlignment(Qt.AlignCenter)
            badge.setPixmap(icons.pixmap("folder", size=20,
                                         color=PALETTE.text_secondary))
            row.addWidget(badge)
        else:
            row.addWidget(Badge(path.name, size=36))
        col = QVBoxLayout()
        col.setSpacing(1)
        name_lbl = label(path.name, "body")
        col.addWidget(name_lbl)
        self.detail_lbl = label("counting files..." if is_folder else "", "muted")
        if is_folder:
            # Summarised on a worker: a folder on a slow disk (or a huge one)
            # must not freeze the window while it is measured.
            self._summary = _FolderSummaryThread(path, self)
            self._summary.done.connect(self.detail_lbl.setText)
            self._summary.start()
            size_txt = None
        else:
            try:
                size_txt = human_size(path.stat().st_size)
            except OSError:
                size_txt = "unavailable"
        if size_txt is not None:
            self.detail_lbl.setText(size_txt)
        col.addWidget(self.detail_lbl)
        row.addLayout(col, 1)
        remove_btn = icon_button("x", size=14, tooltip="Remove")
        remove_btn.clicked.connect(lambda: self.removed.emit(self.path))
        row.addWidget(remove_btn)


class _FolderSummaryThread(QThread):
    """Counts a folder's files and bytes without blocking the UI thread."""

    done = Signal(str)

    def __init__(self, folder: Path, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._folder = folder

    def run(self) -> None:
        try:
            self.done.emit(folder_summary(self._folder))
        except OSError as exc:
            self.done.emit(f"cannot be read ({exc.strerror or exc})")


class TargetRow(QWidget):
    picked = Signal(object)

    def __init__(self, peer, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.peer = peer
        self.setCursor(Qt.PointingHandCursor)
        self._selected = False
        self._frame = Card(flat=True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._frame)

        row = QHBoxLayout()
        row.setContentsMargins(4, 2, 4, 2)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.pixmap("computer", size=20, color=PALETTE.text_secondary))
        row.addWidget(icon_lbl)
        col = QVBoxLayout()
        col.setSpacing(0)
        col.addWidget(label(peer.name, "body"))
        col.addWidget(label(f"{peer.ip}:{peer.port}", "muted"))
        row.addLayout(col, 1)
        self._check = QLabel()
        self._check.setFixedSize(18, 18)
        row.addWidget(self._check)
        self._frame.addLayout(row)
        self.set_selected(False)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self.picked.emit(self.peer)

    def set_selected(self, value: bool) -> None:
        self._selected = value
        if value:
            self._frame.setStyleSheet(
                f"QFrame {{ border: 1px solid {PALETTE.accent}; background: {PALETTE.accent_soft}; }}"
            )
            self._check.setPixmap(icons.pixmap("check_circle", size=17, color=PALETTE.accent))
        else:
            self._frame.setStyleSheet("")
            self._check.clear()


class SendPage(QWidget):
    back_requested = Signal()

    def __init__(self, controller: AppController, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller
        self.selected_files: List[Path] = []
        self.selected_target = None
        self._target_rows: List[TargetRow] = []
        self._progress_rows: Dict[str, ProgressRow] = {}
        self._send_thread: Optional[SendThread] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(20)

        header = QHBoxLayout()
        back_btn = icon_button("arrow_left", size=18, tooltip="Back to dashboard")
        back_btn.clicked.connect(self.back_requested.emit)
        header.addWidget(back_btn)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(label("SEND", "eyebrow"))
        title_col.addWidget(label("Send files", "h1"))
        header.addLayout(title_col)
        header.addWidget(h_spacer())
        outer.addLayout(header)

        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_pick_screen())
        self.stack.addWidget(self._build_sending_screen())
        self.stack.addWidget(self._build_done_screen())

        controller.peers_changed.connect(self._on_peers)

    # -- screen 1: pick files + target ------------------------------------

    def _build_pick_screen(self) -> QWidget:
        screen = QWidget()
        row = QHBoxLayout(screen)
        row.setSpacing(20)

        files_card = Card()
        files_card.addWidget(label("FILES AND FOLDERS TO SEND", "eyebrow"))

        self.drop_area = QWidget()
        self.drop_area.setAcceptDrops(True)
        self.drop_area.setMinimumHeight(90)
        self.drop_area.setStyleSheet(
            f"background: {PALETTE.surface_alt}; border: 1.5px dashed {PALETTE.border_strong};"
            f" border-radius: 12px;"
        )
        self.drop_area.dragEnterEvent = self._drag_enter  # type: ignore[assignment]
        self.drop_area.dropEvent = self._drop  # type: ignore[assignment]
        drop_layout = QVBoxLayout(self.drop_area)
        drop_layout.setAlignment(Qt.AlignCenter)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icons.pixmap("upload_cloud", size=26, color=PALETTE.text_muted))
        icon_lbl.setAlignment(Qt.AlignCenter)
        drop_layout.addWidget(icon_lbl)
        drop_layout.addWidget(label("Drag files or folders here, or click Browse",
                                    "muted"))
        files_card.addWidget(self.drop_area)

        browse_row = QHBoxLayout()
        browse_btn = button("Browse files...", cls="secondary", icon_name="plus")
        browse_btn.clicked.connect(self._browse_files)
        browse_row.addWidget(browse_btn)
        folder_btn = button("Add folder...", cls="secondary", icon_name="folder")
        folder_btn.clicked.connect(self._browse_folder)
        browse_row.addWidget(folder_btn)
        browse_row.addWidget(h_spacer())
        self.files_count_label = label("Nothing selected", "muted")
        browse_row.addWidget(self.files_count_label)
        files_card.addLayout(browse_row)
        files_card.addWidget(divider())

        self.files_scroll = QScrollArea()
        self.files_scroll.setWidgetResizable(True)
        self.files_list_widget = QWidget()
        self.files_list_layout = QVBoxLayout(self.files_list_widget)
        self.files_list_layout.setSpacing(8)
        self.files_list_layout.addStretch(1)
        self.files_scroll.setWidget(self.files_list_widget)
        files_card.addWidget(self.files_scroll)

        target_card = Card()
        target_card.addWidget(label("SEND TO", "eyebrow"))
        manual_btn = button("Enter IP address manually", cls="ghost", icon_name="plus")
        manual_btn.clicked.connect(self._enter_manual)
        target_card.addWidget(manual_btn)
        target_card.addWidget(divider())

        self.targets_scroll = QScrollArea()
        self.targets_scroll.setWidgetResizable(True)
        self.targets_list_widget = QWidget()
        self.targets_list_layout = QVBoxLayout(self.targets_list_widget)
        self.targets_list_layout.setSpacing(8)
        self.targets_empty = EmptyState("wifi", "Searching for devices...",
                                        "They'll appear here once found.")
        self.targets_list_layout.addWidget(self.targets_empty)
        self.targets_list_layout.addStretch(1)
        self.targets_scroll.setWidget(self.targets_list_widget)
        target_card.addWidget(self.targets_scroll)

        row.addWidget(files_card, 1)
        row.addWidget(target_card, 1)

        wrapper = QWidget()
        wrap_layout = QVBoxLayout(wrapper)
        wrap_layout.setContentsMargins(0, 0, 0, 0)
        wrap_layout.addWidget(screen, 1)

        bottom = QHBoxLayout()
        bottom.addWidget(h_spacer())
        self.send_btn = button("Send files", cls="primary", icon_name="send",
                               icon_color=PALETTE.text_on_accent)
        self.send_btn.setMinimumHeight(40)
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self._start_send)
        bottom.addWidget(self.send_btn)
        wrap_layout.addLayout(bottom)
        return wrapper

    def _drag_enter(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def _drop(self, event) -> None:
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile()]
        self._add_files(paths)

    def _browse_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to send")
        self._add_files([Path(f) for f in files])

    def _browse_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select a folder to send")
        if folder:
            self._add_files([Path(folder)])

    def _add_files(self, paths: List[Path]) -> None:
        for p in paths:
            # Folders are kept as folders: the sender walks them and the
            # receiver rebuilds the tree, so the structure survives.
            if (p.is_file() or p.is_dir()) and p not in self.selected_files:
                self.selected_files.append(p)
        self._rebuild_file_list()

    def _remove_file(self, path: Path) -> None:
        self.selected_files = [p for p in self.selected_files if p != path]
        self._rebuild_file_list()

    def _rebuild_file_list(self) -> None:
        while self.files_list_layout.count() > 1:
            item = self.files_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        for path in self.selected_files:
            row = FileRow(path)
            row.removed.connect(self._remove_file)
            self.files_list_layout.insertWidget(self.files_list_layout.count() - 1, row)
        files = sum(1 for p in self.selected_files if not p.is_dir())
        folders = len(self.selected_files) - files
        parts = []
        if files:
            parts.append(f"{files} file{'s' if files != 1 else ''}")
        if folders:
            parts.append(f"{folders} folder{'s' if folders != 1 else ''}")
        self.files_count_label.setText(
            "Nothing selected" if not parts else " + ".join(parts) + " selected")
        self._update_send_enabled()

    def _on_peers(self, peers) -> None:
        while self.targets_list_layout.count() > 1:
            item = self.targets_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        self._target_rows = []
        if not peers:
            self.targets_empty.setParent(None)
            self.targets_empty = EmptyState(
                "wifi", "No devices found yet",
                "Make sure the other device is on and connected to this Wi-Fi/LAN.")
            self.targets_list_layout.insertWidget(0, self.targets_empty)
            return
        for peer in peers:
            row = TargetRow(peer)
            row.picked.connect(self._pick_target)
            row.set_selected(self.selected_target is not None
                            and self.selected_target.ip == peer.ip
                            and self.selected_target.port == peer.port)
            self._target_rows.append(row)
            self.targets_list_layout.insertWidget(
                self.targets_list_layout.count() - 1, row)

    def _pick_target(self, peer) -> None:
        self.selected_target = peer
        for row in self._target_rows:
            row.set_selected(row.peer.ip == peer.ip and row.peer.port == peer.port)
        self._update_send_enabled()

    def _enter_manual(self) -> None:
        dlg = ManualTargetDialog(int(self.controller.config["port"]), self)
        if dlg.exec():
            peer = discovery_mod.Peer(name=dlg.host, ip=dlg.host, port=dlg.port,
                                      fingerprint="")
            self.preselect_target(peer)

    def _update_send_enabled(self) -> None:
        self.send_btn.setEnabled(bool(self.selected_files) and self.selected_target is not None)

    # -- screen 2: sending -------------------------------------------------

    def _build_sending_screen(self) -> QWidget:
        screen = QWidget()
        col = QVBoxLayout(screen)
        col.setSpacing(16)

        card = Card()
        head = QHBoxLayout()
        self.sending_spinner = Spinner(size=18)
        head.addWidget(self.sending_spinner)
        self.sending_title = label("Connecting...", "h2")
        head.addWidget(self.sending_title)
        head.addWidget(h_spacer())
        card.addLayout(head)
        card.addWidget(divider())

        self.sending_rows_scroll = QScrollArea()
        self.sending_rows_scroll.setWidgetResizable(True)
        self.sending_rows_widget = QWidget()
        self.sending_rows_layout = QVBoxLayout(self.sending_rows_widget)
        self.sending_rows_layout.setSpacing(14)
        self.sending_rows_layout.addStretch(1)
        self.sending_rows_scroll.setWidget(self.sending_rows_widget)
        card.addWidget(self.sending_rows_scroll, 1)
        col.addWidget(card, 1)

        log_card = Card(flat=True)
        self.send_log = QPlainTextEdit()
        self.send_log.setReadOnly(True)
        self.send_log.setMaximumHeight(90)
        self.send_log.setStyleSheet(
            f"QPlainTextEdit {{ background: transparent; border: none; "
            f"color: {PALETTE.text_muted}; font-family: {FONT_MONO}; font-size: 11px; }}"
        )
        log_card.addWidget(self.send_log)
        col.addWidget(log_card)

        bottom = QHBoxLayout()
        bottom.addWidget(h_spacer())
        self.cancel_btn = button("Cancel", cls="danger", icon_name="x")
        self.cancel_btn.clicked.connect(self._cancel_send)
        bottom.addWidget(self.cancel_btn)
        col.addLayout(bottom)
        return screen

    def _start_send(self) -> None:
        target = self.selected_target
        if target is None or not self.selected_files:
            return
        self._progress_rows.clear()
        while self.sending_rows_layout.count() > 1:
            item = self.sending_rows_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        self.send_log.clear()
        self.sending_title.setText(f"Sending to {target.name}...")
        self.stack.setCurrentIndex(1)

        for path in self.selected_files:
            if path.is_dir():
                # A folder's per-file rows appear as the sender reports them;
                # there can be thousands, so they are not pre-created.
                continue
            try:
                total = path.stat().st_size
            except OSError:
                total = 0   # vanished since it was picked; the send will say so
            pr = ProgressRow(path.name, total)
            self._progress_rows[path.name] = pr
            self.sending_rows_layout.insertWidget(self.sending_rows_layout.count() - 1, pr)

        thread = SendThread(target.ip, target.port, [str(p) for p in self.selected_files], self,
                            expect_fingerprint=getattr(target, "fingerprint", "") or None)
        thread.progress.connect(self._on_send_progress)
        thread.log.connect(self._on_send_log)
        thread.tofu_conflict.connect(self._on_tofu_conflict)
        thread.finished_ok.connect(self._on_send_finished)
        thread.failed.connect(self._on_send_failed)
        self._send_thread = thread
        thread.start()

    def _on_send_progress(self, filename: str, sent: int, total: int, phase: str) -> None:
        row = self._progress_rows.get(filename)
        if row is None:
            row = ProgressRow(filename, total)
            self._progress_rows[filename] = row
            self.sending_rows_layout.insertWidget(
                self.sending_rows_layout.count() - 1, row)
            self._trim_progress_rows()
        row.set_phase("Computing checksum..." if phase == "hashing" else "Sending...")
        row.set_progress(sent, total)

    def _trim_progress_rows(self, keep: int = 6) -> None:
        """Drop the oldest rows: a folder can hold thousands of files."""
        while len(self._progress_rows) > keep:
            oldest = next(iter(self._progress_rows))
            widget = self._progress_rows.pop(oldest)
            widget.setParent(None)

    def _on_send_log(self, msg: str) -> None:
        self.send_log.appendPlainText(msg.strip())

    def _on_tofu_conflict(self, peer_name: str, known_fpr: str, new_fpr: str, responder) -> None:
        dlg = TofuWarningDialog(peer_name, known_fpr, new_fpr, self)
        dlg.exec()
        responder.resolve(dlg.proceed)

    def _cancel_send(self) -> None:
        if self._send_thread is not None:
            self._send_thread.cancel()
            self.sending_title.setText("Cancelling...")

    def _on_send_finished(self, results: List[dict]) -> None:
        self._show_done(results, None)

    def _on_send_failed(self, error: str) -> None:
        self._show_done(None, error)

    # -- screen 3: results --------------------------------------------------

    def _build_done_screen(self) -> QWidget:
        screen = QWidget()
        col = QVBoxLayout(screen)
        col.setAlignment(Qt.AlignCenter)
        col.setSpacing(16)

        self.done_icon = QLabel()
        self.done_icon.setAlignment(Qt.AlignCenter)
        col.addWidget(self.done_icon)
        self.done_title = label("", "h1")
        self.done_title.setAlignment(Qt.AlignCenter)
        col.addWidget(self.done_title)

        self.done_scroll = QScrollArea()
        self.done_scroll.setWidgetResizable(True)
        self.done_scroll.setMinimumWidth(460)
        self.done_scroll.setMaximumWidth(520)
        self.done_scroll.setMaximumHeight(260)
        self.done_scroll.setFrameShape(QScrollArea.NoFrame)
        self.done_list_widget = QWidget()
        self.done_list_layout = QVBoxLayout(self.done_list_widget)
        self.done_list_layout.setContentsMargins(12, 8, 12, 8)
        self.done_list_layout.setSpacing(10)
        self.done_scroll.setWidget(self.done_list_widget)
        col.addWidget(self.done_scroll, 0, Qt.AlignCenter)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        again_btn = button("Send more files", cls="secondary", icon_name="plus")
        again_btn.clicked.connect(self._reset_to_pick)
        done_btn = button("Back to dashboard", cls="primary",
                          icon_color=PALETTE.text_on_accent)
        done_btn.clicked.connect(self.back_requested.emit)
        btn_row.addWidget(again_btn)
        btn_row.addWidget(done_btn)
        col.addLayout(btn_row)
        return screen

    def _show_done(self, results: Optional[List[dict]], error: Optional[str]) -> None:
        while self.done_list_layout.count():
            item = self.done_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

        if error is not None:
            cancelled = "cancelled" in error.lower()
            self.done_icon.setPixmap(icons.pixmap(
                "x_circle" if not cancelled else "alert_triangle", size=48,
                color=PALETTE.text_muted if cancelled else PALETTE.danger))
            self.done_title.setText("Send cancelled" if cancelled else "Send failed")
            if not cancelled:
                err_lbl = label(error, "secondary")
                err_lbl.setAlignment(Qt.AlignCenter)
                err_lbl.setWordWrap(True)
                self.done_list_layout.addWidget(err_lbl)
        else:
            results = results or []
            ok_count = sum(1 for r in results if r.get("sent"))
            all_ok = ok_count == len(results) and len(results) > 0
            self.done_icon.setPixmap(icons.pixmap(
                "check_circle" if all_ok else "alert_triangle", size=48,
                color=PALETTE.success if all_ok else PALETTE.warning))
            self.done_title.setText(f"{ok_count}/{len(results)} file(s) delivered")
            # Failures first, and only a screenful: a folder send can produce
            # thousands of results and building a widget for each one would
            # lock up the window for seconds to show a list nobody can read.
            ordered = sorted(results, key=lambda r: bool(r.get("sent")))
            shown = ordered[:_MAX_RESULT_ROWS]
            for r in shown:
                row = QHBoxLayout()
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(10)
                # For a folder this is "photos/2024/beach.jpg" -- the bare
                # base name would not say which of several same-named files
                # this row is about.
                name = str(r.get("name") or Path(r["file"]).name)
                ok = bool(r.get("sent"))
                ic = QLabel()
                ic.setFixedWidth(18)
                ic.setPixmap(icons.pixmap(
                    "check_circle" if ok else "x_circle", size=16,
                    color=PALETTE.success if ok else PALETTE.danger))
                row.addWidget(ic)
                row.addWidget(label(name, "body"), 1)
                if not ok:
                    row.addWidget(label(str(r.get("reason", "failed")), "muted"))
                wrap = QWidget()
                wrap.setLayout(row)
                self.done_list_layout.addWidget(wrap)
            if len(ordered) > len(shown):
                more = label(f"...and {len(ordered) - len(shown)} more "
                             f"(see the Files page for the full list)", "muted")
                more.setWordWrap(True)
                self.done_list_layout.addWidget(more)

        self.stack.setCurrentIndex(2)

    def _reset_to_pick(self) -> None:
        self.selected_files = []
        self._rebuild_file_list()
        self.stack.setCurrentIndex(0)

    # -- external API -------------------------------------------------------

    def preselect_target(self, peer) -> None:
        # Prefer an already-rendered row so its selected highlight updates too.
        match = next((r.peer for r in self._target_rows
                     if r.peer.ip == peer.ip and r.peer.port == peer.port), None)
        if match is not None:
            self._pick_target(match)
        else:
            self.selected_target = peer
            self._update_send_enabled()
            self._on_peers(self.controller.latest_peers + [peer])

    def reset_and_show(self, peer=None) -> None:
        self.stack.setCurrentIndex(0)
        if peer is not None:
            self.preselect_target(peer)
