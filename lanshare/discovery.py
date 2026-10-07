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

Unlike the transfer handshake (a SPAKE2 PAKE, see :mod:`lanshare.auth`),
discovery is a single-shot UDP exchange with no room for a round-trip key
agreement, so it still authenticates with an HMAC -- and an HMAC keyed directly
on the shared secret would hand a passive eavesdropper a transcript to attack
*offline*. To blunt that, the HMAC key is not the secret itself but a key
**stretched from it with scrypt** (:func:`_discovery_key`). Verifying one
guessed secret against a captured packet then costs a full scrypt evaluation
rather than a single SHA-256, turning a fast offline search into a slow one.
The derived key is computed once and cached, so stretching never happens on the
packet path.
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

# Bumped from v2 when the HMAC key moved from the raw secret to a scrypt-
# stretched key: the construction is incompatible, so the version guards a peer
# from silently failing MAC checks against a differently-keyed counterpart.
_MAGIC = "lanshare-discovery-v3"
_MAX_UDP = 2048
_NONCE_LEN = 16
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")

# scrypt work factor for stretching the shared secret into the discovery HMAC
# key. n=2**15, r=8, p=1 is a standard interactive cost (~tens of ms, tens of
# MiB) -- negligible once, cached, for the honest side, but multiplied across a
# brute-force search it is what makes an offline attack on a weak secret slow.
# The salt is a fixed application constant: both peers must derive the *same*
# key from the *same* secret with no shared state to exchange a random salt, so
# it domain-separates LANShare from other scrypt users rather than per-install.
_SCRYPT_N = 1 << 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT = b"lanshare-discovery-kdf-v1"
_SCRYPT_DKLEN = 32
# scrypt needs ~128*r*n bytes; give it headroom so the call is never refused.
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * 2 + (1 << 20)

_key_lock = threading.Lock()
_key_cache: Dict[bytes, bytes] = {}


def _discovery_key(secret: bytes) -> bytes:
    """Stretch *secret* into the discovery HMAC key with scrypt (cached).

    Cached on the secret itself: the honest side derives one key per distinct
    secret and reuses it for every packet, while an offline attacker testing a
    dictionary pays the full scrypt cost for each distinct guess.
    """
    with _key_lock:
        cached = _key_cache.get(secret)
        if cached is not None:
            return cached
    key = hashlib.scrypt(
        secret, salt=_SCRYPT_SALT, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM,
    )
    with _key_lock:
        # One secret in normal use; bound the map so a pathological caller that
        # feeds many secrets cannot grow it without limit.
        if len(_key_cache) > 16:
            _key_cache.clear()
        _key_cache[secret] = key
    return key


@dataclass
class Peer:
    name: str
    ip: str
    port: int
    fingerprint: str

    def key(self) -> str:
        return f"{self.ip}:{self.port}"


def _mac(secret: bytes, kind: str, nonce: bytes, *fields: object) -> bytes:
    """HMAC over length-prefixed fields (so no field can impersonate another).

    Keyed on the scrypt-stretched secret, not the secret itself, so a captured
    query or reply cannot be used for a fast offline guess of the secret.
    """
    h = hmac.new(_discovery_key(secret), digestmod=hashlib.sha256)
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
