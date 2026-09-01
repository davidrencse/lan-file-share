"""Central app state shared by every page: config, the receiver thread, and
the background discovery poller."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, Signal

from .. import config as cfg_mod
from .. import identity
from .workers import DiscoveryPoller, ReceiverThread


class AppController(QObject):
    receiving_changed = Signal(bool)
    receiver_log = Signal(str)
    incoming_request = Signal(dict, object)
    receive_progress = Signal(str, int, int)
    receiver_error = Signal(str)
    peers_changed = Signal(list)

    def __init__(self) -> None:
        super().__init__()
        self.config: Dict[str, Any] = cfg_mod.load_config()
        identity.ensure_identity(self.config["device_name"])
        self.receiver_thread: Optional[ReceiverThread] = None
        self.discovery_poller: Optional[DiscoveryPoller] = None
        self.latest_peers: List = []

    # -- identity / config ---------------------------------------------

    @property
    def fingerprint(self) -> str:
        return identity.own_fingerprint() or ""

    def reload_config(self) -> None:
        self.config = cfg_mod.load_config()

    def save_config(self, updates: Dict[str, Any]) -> None:
        self.config.update(updates)
        cfg_mod.save_config(self.config)

    def has_secret(self) -> bool:
        return cfg_mod.load_secret() is not None

    # -- receiving --------------------------------------------------------

    def is_receiving(self) -> bool:
        return bool(self.receiver_thread and self.receiver_thread.isRunning())

    def start_receiving(self) -> None:
        if self.is_receiving():
            return
        self.reload_config()
        thread = ReceiverThread(dict(self.config))
        thread.log.connect(self.receiver_log)
        thread.incoming_request.connect(self.incoming_request)
        thread.progress.connect(self.receive_progress)
        thread.error.connect(self._on_receiver_error)
        thread.finished.connect(self._on_receiver_finished)
        self.receiver_thread = thread
        thread.start()
        self.receiving_changed.emit(True)

    def stop_receiving(self) -> None:
        if self.receiver_thread is not None:
            self.receiver_thread.request_stop()

    def _on_receiver_error(self, msg: str) -> None:
        self.receiver_error.emit(msg)

    def _on_receiver_finished(self) -> None:
        self.receiving_changed.emit(False)

    # -- discovery ----------------------------------------------------

    def start_discovery(self) -> None:
        if self.discovery_poller is not None:
            return
        poller = DiscoveryPoller(int(self.config["discovery_port"]))
        poller.peers_found.connect(self._on_peers)
        self.discovery_poller = poller
        poller.start()

    def _on_peers(self, peers: List) -> None:
        own_fpr = self.fingerprint
        peers = [p for p in peers if not (own_fpr and p.fingerprint == own_fpr)]
        self.latest_peers = peers
        self.peers_changed.emit(peers)

    def refresh_discovery(self) -> None:
        if self.discovery_poller is not None:
            self.discovery_poller.refresh_now()

    # -- lifecycle ------------------------------------------------------

    def shutdown(self) -> None:
        if self.receiver_thread is not None:
            self.receiver_thread.request_stop()
            self.receiver_thread.wait(2000)
        if self.discovery_poller is not None:
            self.discovery_poller.stop()
            self.discovery_poller.wait(2000)
