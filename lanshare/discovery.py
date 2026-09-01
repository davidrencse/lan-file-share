"""Optional LAN peer discovery over UDP broadcast.

This is a *convenience* layer only: it lets a sender find receivers without
knowing their IP. Nothing here is trusted for security -- the TLS handshake,
fingerprint pinning, shared-secret auth and the receiver's approval prompt are
what actually protect a transfer. Discovery replies only go to LAN addresses.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .netutil import is_lan_address

_MAGIC = "lanshare-discovery-v1"
_MAX_UDP = 2048


@dataclass
class Peer:
    name: str
    ip: str
    port: int
    fingerprint: str

    def key(self) -> str:
        return f"{self.ip}:{self.port}"


class DiscoveryResponder:
    """Answers discovery queries with this device's connection details."""

    def __init__(self, device_name: str, tcp_port: int, discovery_port: int,
                 fingerprint: str):
        self._name = device_name
        self._tcp_port = tcp_port
        self._disc_port = discovery_port
        self._fpr = fingerprint
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self._disc_port))
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._loop, name="discovery", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        assert self._sock is not None
        reply = json.dumps({
            "magic": _MAGIC,
            "kind": "reply",
            "name": self._name,
            "port": self._tcp_port,
            "fpr": self._fpr,
        }).encode("utf-8")
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(_MAX_UDP)
            except socket.timeout:
                continue
            except OSError:
                break
            if not is_lan_address(addr[0]):
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if msg.get("magic") == _MAGIC and msg.get("kind") == "query":
                try:
                    self._sock.sendto(reply, addr)
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


def discover(discovery_port: int, timeout: float = 2.0,
             on_found: Optional[Callable[[Peer], None]] = None) -> List[Peer]:
    """Broadcast a discovery query and collect replies for *timeout* seconds."""
    query = json.dumps({"magic": _MAGIC, "kind": "query"}).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.4)
    try:
        sock.bind(("", 0))
        for target in ("255.255.255.255", "<broadcast>"):
            try:
                sock.sendto(query, (target, discovery_port))
            except OSError:
                pass

        found: Dict[str, Peer] = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(_MAX_UDP)
            except socket.timeout:
                continue
            except OSError:
                break
            if not is_lan_address(addr[0]):
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if msg.get("magic") != _MAGIC or msg.get("kind") != "reply":
                continue
            try:
                port = int(msg.get("port"))
            except (TypeError, ValueError):
                continue
            if not (0 < port < 65536):
                continue
            peer = Peer(
                name=str(msg.get("name", "unknown"))[:64],
                ip=addr[0],
                port=port,
                fingerprint=str(msg.get("fpr", ""))[:128],
            )
            if peer.key() not in found:
                found[peer.key()] = peer
                if on_found:
                    on_found(peer)
        return list(found.values())
    finally:
        sock.close()
