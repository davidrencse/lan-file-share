"""Low-level network helpers: LAN-only checks and framed JSON messaging."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


def set_exclusive_bind(sock: socket.socket) -> None:
    """Make a listening socket's port un-stealable by other local processes.

    On Windows ``SO_REUSEADDR`` does *not* mean what it means on POSIX: it lets
    any other process -- including one running as a different user -- bind a
    port that is already in use and hijack the traffic. ``SO_EXCLUSIVEADDRUSE``
    is the correct flag there. On POSIX ``SO_REUSEADDR`` is safe and is what
    allows an immediate rebind after restart, so keep it.
    """
    if os.name == "nt":
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            return
        except (AttributeError, OSError):
            pass  # fall through; better to bind than to fail outright
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# 4-byte big-endian length prefix; hard cap keeps a malicious peer from asking
# us to buffer an enormous "control" message. File *content* is streamed
# separately and never goes through this path.
_LEN = struct.Struct(">I")
MAX_CONTROL_BYTES = 1 * 1024 * 1024  # 1 MiB is far more than any control msg


class ProtocolError(Exception):
    """Raised when a peer sends something malformed or oversized."""


def is_lan_address(ip: str) -> bool:
    """True if *ip* is on a network this machine can reasonably call "local".

    Three things qualify:

    1. loopback and link-local addresses;
    2. RFC1918 / ULA private space;
    3. **any network this host actually has an interface on.**

    (3) matters more than it sounds. Testing only for "private range" is a
    common shortcut and it is wrong: a real home Wi-Fi observed while building
    this hands out ``172.1.140.16/20``, which is public address space, so the
    private-range test refused every peer on the user's own network -- inbound
    connections, outbound connections and discovery alike.

    Genuinely remote hosts are still rejected, because they are neither private
    nor inside one of our own interface subnets.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return True
    return _on_a_local_network(addr)


def _on_a_local_network(addr) -> bool:
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    from .localnet import local_ipv4_networks

    for net in local_ipv4_networks():
        if addr in net:
            return True
    for net in _extra_local_networks():
        if addr in net:
            return True
    return False


_EXTRA_TTL = 15.0  # matches localnet's interface cache
_extra_lock = threading.Lock()
_extra_cache: Optional[List[ipaddress.IPv4Network]] = None
_extra_at = 0.0


def _extra_local_networks() -> List[ipaddress.IPv4Network]:
    """Networks the user has explicitly declared local, from the config file.

    Cached briefly. This is consulted for every address that is not obviously
    private -- including every UDP discovery packet on a network that hands out
    public-range addresses -- and reading and parsing config.json each time
    turned a packet into a disk read.
    """
    global _extra_cache, _extra_at
    now = time.monotonic()
    with _extra_lock:
        if _extra_cache is not None and (now - _extra_at) < _EXTRA_TTL:
            return list(_extra_cache)
    try:
        from . import config as cfg_mod

        raw = cfg_mod.load_config().get("extra_local_networks") or []
    except Exception:  # noqa: BLE001 -- config problems must not break the check
        return []
    nets = []
    for item in raw:
        try:
            nets.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    with _extra_lock:
        _extra_cache = nets
        _extra_at = now
    return nets


def invalidate_network_cache() -> None:
    """Forget the cached trusted networks (call after changing settings)."""
    global _extra_cache
    with _extra_lock:
        _extra_cache = None


def describe_local_networks() -> str:
    """Human-readable summary of what counts as local, for diagnostics."""
    from .localnet import local_ipv4_networks

    nets = [str(n) for n in local_ipv4_networks()]
    extra = [str(n) for n in _extra_local_networks()]
    parts = []
    if nets:
        parts.append("interfaces: " + ", ".join(nets))
    if extra:
        parts.append("manually trusted: " + ", ".join(extra))
    return "; ".join(parts) or "no local networks detected"


def primary_lan_address() -> Optional[str]:
    """The address other devices should use to reach this machine.

    Found by asking the kernel which local address it would use to reach the
    outside world. ``connect()`` on a UDP socket only sets the peer for the
    routing table lookup -- no packet is sent and nothing is contacted.

    This is the single answer to "which IP do I type on the other computer?",
    a question the app previously answered with an unordered list of every
    address including VirtualBox and WSL adapters.
    """
    for target in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((target, 9))
                addr = s.getsockname()[0]
            finally:
                s.close()
        except OSError:
            continue
        if addr and addr != "0.0.0.0" and not addr.startswith("127."):
            return addr
    return None


_ADDR_TTL = 10.0
_addr_lock = threading.Lock()
_addr_cache: Optional[List[str]] = None
_addr_at = 0.0


def local_ipv4_addresses(force: bool = False) -> List[str]:
    """This host's own IPv4 addresses, primary first, then the rest sorted.

    Cached for a few seconds: resolving the hostname can block for as long as
    the DNS resolver takes, and the discovery poller asks for this on every
    round to decide which interfaces to broadcast from.
    """
    global _addr_cache, _addr_at
    now = time.monotonic()
    with _addr_lock:
        if not force and _addr_cache is not None and (now - _addr_at) < _ADDR_TTL:
            return list(_addr_cache)

    addrs: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addrs.add(info[4][0])
    except (socket.gaierror, UnicodeError):
        pass
    primary = primary_lan_address()
    if primary:
        addrs.add(primary)
    addrs.discard("0.0.0.0")
    rest = sorted(a for a in addrs if a and a != primary)
    result = ([primary] if primary else []) + rest
    with _addr_lock:
        _addr_cache = result
        _addr_at = now
    return list(result)


# Ranges belonging to hypervisors and container runtimes. Only used to explain
# a secondary address to the user -- never to make a security decision.
_VIRTUAL_HINTS = (
    (ipaddress.ip_network("192.168.56.0/24"), "VirtualBox"),
    (ipaddress.ip_network("192.168.99.0/24"), "Docker Machine"),
    (ipaddress.ip_network("172.17.0.0/16"), "Docker/WSL"),
    (ipaddress.ip_network("172.18.0.0/16"), "Docker"),
)


def describe_addresses() -> List[Tuple[str, str]]:
    """Each local address paired with a short role label, primary first."""
    primary = primary_lan_address()
    out: List[Tuple[str, str]] = []
    for addr in local_ipv4_addresses():
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if addr == primary:
            label = "primary"
        elif parsed.is_loopback:
            label = "loopback"
        elif parsed.is_link_local:
            label = "link-local (no network)"
        else:
            label = "other adapter"
            for net, name in _VIRTUAL_HINTS:
                if parsed in net:
                    label = f"{name} (virtual)"
                    break
        out.append((addr, label))
    return out


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes or raise ProtocolError on short/closed stream."""
    chunks: List[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise ProtocolError("connection closed mid-message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_msg(sock: socket.socket, obj: Dict[str, Any]) -> None:
    """Send a length-prefixed JSON control message."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_CONTROL_BYTES:
        raise ProtocolError("control message too large to send")
    sock.sendall(_LEN.pack(len(payload)) + payload)


def recv_msg(sock: socket.socket) -> Dict[str, Any]:
    """Receive a length-prefixed JSON control message."""
    (length,) = _LEN.unpack(recv_exact(sock, _LEN.size))
    if length > MAX_CONTROL_BYTES:
        raise ProtocolError(f"control message too large: {length} bytes")
    payload = recv_exact(sock, length)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"malformed control message: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("control message was not a JSON object")
    return obj
