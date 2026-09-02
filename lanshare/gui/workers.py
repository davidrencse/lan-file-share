"""Background QThread workers that run the networking backend and report back
to the GUI thread via Qt signals.

The receiver and sender backends (:mod:`lanshare.receiver`, :mod:`lanshare.sender`)
are synchronous/blocking by design -- they call a plain Python callback and
wait for a return value (e.g. "did the user accept this file?"). To bridge that
with Qt's async, single-GUI-thread model, a blocking callback emits a signal
carrying a :class:`Responder` and then blocks on a `threading.Event`; the GUI
thread's slot shows a dialog and calls ``responder.resolve(...)`` when the user
answers, which wakes the worker thread back up.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QThread, Signal


class Responder:
    """A one-shot rendezvous between a worker thread and the GUI thread."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.result: Any = None

    def resolve(self, value: Any) -> None:
        self.result = value
        self._event.set()

    def wait(self, timeout: Optional[float] = None) -> Any:
        self._event.wait(timeout)
        return self.result


class ReceiverThread(QThread):
    """Runs Receiver.serve_forever() and bridges approval prompts to the GUI."""

    log = Signal(str)
    incoming_request = Signal(dict, object)   # info, Responder(bool)
    progress = Signal(str, int, int)          # filename, received, total
    file_saved = Signal(str)
    error = Signal(str)

    # Slightly longer than the dialog's own countdown so the dialog always
    # decides first and the two can never disagree about the outcome.
    APPROVAL_TIMEOUT = 120
    _APPROVAL_GRACE = 15

    def __init__(self, config: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.config = config
        self._receiver = None
        self._pending: set = set()
        self._pending_lock = threading.Lock()

    def run(self) -> None:
        from ..receiver import Receiver

        self._receiver = Receiver(
            self.config,
            approval=self._approval,
            progress_cb=lambda name, received, total: self.progress.emit(
                name, received, total
            ),
            log_cb=self._on_log,
        )
        try:
            self._receiver.serve_forever()
        except Exception as exc:  # noqa: BLE001 -- surface any failure to the GUI
            self.error.emit(str(exc))

    def _on_log(self, msg: str) -> None:
        self.log.emit(msg)
        if msg.strip().startswith("Saved '"):
            self.file_saved.emit(msg)

    def _approval(self, info: Dict[str, Any]) -> bool:
        responder = Responder()
        with self._pending_lock:
            self._pending.add(responder)
        try:
            self.incoming_request.emit(info, responder)
            result = responder.wait(
                timeout=self.APPROVAL_TIMEOUT + self._APPROVAL_GRACE)
        finally:
            with self._pending_lock:
                self._pending.discard(responder)
        return bool(result)

    def request_stop(self) -> None:
        # Release anything blocked on a prompt first, otherwise the transfer
        # thread would sit in responder.wait() and outlive the application.
        with self._pending_lock:
            pending = list(self._pending)
        for responder in pending:
            responder.resolve(False)
        if self._receiver is not None:
            self._receiver.stop()


class DiscoveryPoller(QThread):
    """Periodically broadcasts a discovery query and reports found peers."""

    peers_found = Signal(list)

    def __init__(self, discovery_port: int, interval: float = 4.0, parent=None):
        super().__init__(parent)
        self.discovery_port = discovery_port
        self.interval = interval
        self._stop = threading.Event()
        self._wake = threading.Event()

    def run(self) -> None:
        from .. import config as cfg_mod
        from ..discovery import discover

        while not self._stop.is_set():
            try:
                # Re-read each round so re-pairing takes effect without a restart.
                peers = discover(self.discovery_port, cfg_mod.load_secret(),
                                 timeout=1.5)
            except OSError:
                peers = []
            if self._stop.is_set():
                break
            self.peers_found.emit(peers)
            self._wake.wait(self.interval)
            self._wake.clear()

    def refresh_now(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


class SendThread(QThread):
    """Runs sender.send_files() for one batch and reports progress/results."""

    log = Signal(str)
    progress = Signal(str, int, int, str)      # filename, sent, total, phase
    tofu_conflict = Signal(str, str, str, object)  # peer, known_fpr, new_fpr, Responder(bool)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(self, host: str, port: int, files: List[str], parent=None,
                 expect_fingerprint: Optional[str] = None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.files = files
        self.expect_fingerprint = expect_fingerprint
        self.cancel_event = threading.Event()

    def run(self) -> None:
        from ..sender import SendError, send_files

        try:
            results = send_files(
                self.host, self.port, self.files,
                interactive=False, show_progress=False,
                progress_cb=lambda name, sent, total, phase: self.progress.emit(
                    name, sent, total, phase
                ),
                log_cb=lambda msg: self.log.emit(msg),
                tofu_confirm_cb=self._tofu_confirm,
                cancel_event=self.cancel_event,
                expect_fingerprint=self.expect_fingerprint,
            )
            self.finished_ok.emit(results)
        except SendError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))

    def _tofu_confirm(self, peer_name: str, known_fpr: str, new_fpr: str) -> bool:
        responder = Responder()
        self.tofu_conflict.emit(peer_name, known_fpr, new_fpr, responder)
        result = responder.wait(timeout=120)
        return bool(result)

    def cancel(self) -> None:
        self.cancel_event.set()
