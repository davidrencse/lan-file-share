"""Low-level network helpers: LAN-only checks and framed JSON messaging."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
from typing import Any, Dict, List


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
    """True if *ip* is loopback, link-local, or RFC1918/ULA private space.

    Public / routable addresses are rejected so the service only ever talks to
    machines on the local network.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private  # includes RFC1918 and IPv6 ULA (fc00::/7)
    )


def local_ipv4_addresses() -> List[str]:
    """Best-effort list of this host's own IPv4 addresses (for display)."""
    addrs: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addrs.add(info[4][0])
    except socket.gaierror:
        pass
    # The "connect a UDP socket to a public IP" trick reveals the primary
    # outbound interface address without sending anything.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.255.255", 9))
            addrs.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    addrs.discard("0.0.0.0")
    return sorted(a for a in addrs if a)


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
