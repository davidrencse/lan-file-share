"""LAN peer discovery over UDP broadcast, authenticated with the shared secret.

Discovery is a convenience layer -- the TLS handshake, fingerprint pinning and
the receiver's approval prompt are what actually protect a transfer -- but it
is still authenticated, for three reasons:

  * an unauthenticated responder would tell anyone on the network this
    machine's hostname, port and certificate fingerprint;
  * it would answer spoofed queries, making the service a (small) reflection
    amplifier;
  * anyone could forge a reply and lure a sender into connecting to them.

So a query must carry an HMAC proving knowledge of the shared secret before it
gets any reply at all, and the reply carries an HMAC over the querier's nonce
so a forged reply is discarded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .netutil import is_lan_address, local_ipv4_addresses, set_exclusive_bind
from .safety import sanitize_display_text

_MAGIC = "lanshare-discovery-v2"
_MAX_UDP = 2048
_NONCE_LEN = 16
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


@dataclass
class Peer:
    name: str
    ip: str
    port: int
    fingerprint: str

    def key(self) -> str:
        return f"{self.ip}:{self.port}"


def _mac(secret: bytes, kind: str, nonce: bytes, *fields: object) -> bytes:
    """HMAC over length-prefixed fields (so no field can impersonate another)."""
    h = hmac.new(secret, digestmod=hashlib.sha256)
    h.update(_MAGIC.encode("ascii") + b"|" + kind.encode("ascii") + b"|" + nonce)
    for field in fields:
        raw = str(field).encode("utf-8")
        h.update(struct.pack(">I", len(raw)) + raw)
    return h.digest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: object) -> bytes:
    if not isinstance(text, str):
        return b""
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        return b""


class DiscoveryResponder:
    """Answers *authenticated* discovery queries with this device's details."""

    def __init__(self, device_name: str, tcp_port: int, discovery_port: int,
                 fingerprint: str, secret: bytes):
        self._name = device_name
        self._tcp_port = tcp_port
        self._disc_port = discovery_port
        self._fpr = fingerprint
        self._secret = secret
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        set_exclusive_bind(sock)
        sock.bind(("", self._disc_port))
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._loop, name="discovery", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(_MAX_UDP)
            except socket.timeout:
                continue
            except OSError:
                break
            if not is_lan_address(addr[0]):
                continue
            reply = self._build_reply(data)
            if reply is None:
                continue  # unauthenticated: stay completely silent
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass

    def _build_reply(self, data: bytes) -> Optional[bytes]:
        try:
            msg = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(msg, dict):
            return None
        if msg.get("magic") != _MAGIC or msg.get("kind") != "query":
            return None
        nonce = _unb64(msg.get("nonce"))
        if len(nonce) != _NONCE_LEN:
            return None
        if not hmac.compare_digest(_unb64(msg.get("mac")),
                                   _mac(self._secret, "query", nonce)):
            return None
        mac = _mac(self._secret, "reply", nonce,
                   self._name, self._tcp_port, self._fpr)
        return json.dumps({
            "magic": _MAGIC,
            "kind": "reply",
            "name": self._name,
            "port": self._tcp_port,
            "fpr": self._fpr,
            "mac": _b64(mac),
        }).encode("utf-8")

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


def _broadcast_sockets() -> List[socket.socket]:
    """One broadcast socket per local IPv4 interface, plus a wildcard fallback.

    Sending only from the default route misses peers on machines with several
    interfaces -- VirtualBox, WSL, Docker and VPN adapters all create extra
    ones -- and can advertise an address the far side cannot reach. Binding a
    socket to each local address forces a query out of every interface.
    """
    socks: List[socket.socket] = []
    for source in [""] + local_ipv4_addresses():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((source, 0))
            s.setblocking(False)
            socks.append(s)
        except OSError:
            continue
    return socks


def discover(discovery_port: int, secret: Optional[bytes], timeout: float = 2.0,
             ) -> List[Peer]:
    """Broadcast an authenticated query and collect verified replies.

    Returns an empty list if no shared secret is configured -- without one a
    query cannot be authenticated and no peer will answer it.
    """
    if not secret:
        return []

    nonce = secrets.token_bytes(_NONCE_LEN)
    query = json.dumps({
        "magic": _MAGIC,
        "kind": "query",
        "nonce": _b64(nonce),
        "mac": _b64(_mac(secret, "query", nonce)),
    }).encode("utf-8")

    socks = _broadcast_sockets()
    if not socks:
        return []
    try:
        for s in socks:
            try:
                s.sendto(query, ("255.255.255.255", discovery_port))
            except OSError:
                pass

        found: Dict[str, Peer] = {}
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select(socks, [], [], min(remaining, 0.4))
            for s in readable:
                try:
                    data, addr = s.recvfrom(_MAX_UDP)
                except OSError:
                    continue
                peer = _parse_reply(data, addr, secret, nonce)
                if peer is not None and peer.key() not in found:
                    found[peer.key()] = peer
        return list(found.values())
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def _parse_reply(data: bytes, addr: Sequence, secret: bytes,
                 nonce: bytes) -> Optional[Peer]:
    if not is_lan_address(addr[0]):
        return None
    try:
        msg = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict):
        return None
    if msg.get("magic") != _MAGIC or msg.get("kind") != "reply":
        return None
    try:
        port = int(msg.get("port"))
    except (TypeError, ValueError):
        return None
    if not (0 < port < 65536):
        return None
    raw_name = str(msg.get("name", "unknown"))[:64]
    fpr = str(msg.get("fpr", ""))[:128]
    if fpr and not _HEX64.fullmatch(fpr):
        return None
    # Bound to *our* nonce, so a replayed or forged reply is rejected. Verified
    # against the raw name, before any display-oriented rewriting of it.
    if not hmac.compare_digest(_unb64(msg.get("mac")),
                               _mac(secret, "reply", nonce, raw_name, port, fpr)):
        return None
    return Peer(name=sanitize_display_text(raw_name), ip=addr[0], port=port,
                fingerprint=fpr)
