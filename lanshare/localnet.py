"""Discovering which IPv4 networks this machine is actually attached to.

"Is this address in a private range?" is *not* the same question as "is this
address on my local network". Plenty of routers, ISPs, campus and hotel
networks hand out addresses outside RFC1918 -- a real example this was written
for is a home Wi-Fi handing out ``172.1.140.16/20``, which is public address
space and was therefore refused by the app on the user's own network.

So we ask the operating system what it is attached to. Everything here is
best-effort: if the prefix length cannot be determined we assume /24 for that
address rather than failing closed, and every platform path degrades to simply
returning nothing.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from typing import List, Optional

_CACHE_TTL = 15.0  # interface lists change rarely; this is checked per connection
_cache_lock = threading.Lock()
_cache: Optional[List[ipaddress.IPv4Network]] = None
_cache_at = 0.0


def local_ipv4_networks(force: bool = False) -> List[ipaddress.IPv4Network]:
    """The IPv4 networks this host has an interface on, e.g. 192.168.1.0/24."""
    global _cache, _cache_at
    now = time.monotonic()
    with _cache_lock:
        if not force and _cache is not None and (now - _cache_at) < _CACHE_TTL:
            return list(_cache)
    nets = _discover_networks()
    with _cache_lock:
        _cache = nets
        _cache_at = now
    return list(nets)


def invalidate_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


def _discover_networks() -> List[ipaddress.IPv4Network]:
    for probe in (_windows_networks, _posix_networks):
        try:
            nets = probe()
        except Exception:  # noqa: BLE001 -- never let interface probing break a transfer
            nets = []
        if nets:
            return _dedupe(nets)
    return _dedupe(_fallback_networks())


def _dedupe(nets: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    seen, out = set(), []
    for net in nets:
        if net.prefixlen == 32 or net.is_loopback:
            continue
        if str(net) not in seen:
            seen.add(str(net))
            out.append(net)
    return out


def _net_from(addr: str, prefixlen: int) -> Optional[ipaddress.IPv4Network]:
    try:
        return ipaddress.ip_network(f"{addr}/{prefixlen}", strict=False)
    except ValueError:
        return None


# --- Windows ---------------------------------------------------------------

def _windows_networks() -> List[ipaddress.IPv4Network]:
    if os.name != "nt":
        return []
    import ctypes
    import ctypes.wintypes as wt

    AF_INET = 2
    # Skip everything except the unicast addresses we need. NB 0x01 is
    # SKIP_UNICAST -- including it here would discard the whole point.
    GAA_FLAG_SKIP_ANYCAST = 0x02
    GAA_FLAG_SKIP_MULTICAST = 0x04
    GAA_FLAG_SKIP_DNS_SERVER = 0x08
    GAA_FLAG_SKIP_FRIENDLY_NAME = 0x20
    GAA_SKIP = (GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME)
    ERROR_BUFFER_OVERFLOW = 111

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(ctypes.c_ubyte)),
                    ("iSockaddrLength", ctypes.c_int)]

    class UNICAST(ctypes.Structure):
        pass

    # Only the leading fields are declared; the OS writes the full structure
    # into our buffer and we read the prefix of it, which is layout-stable.
    UNICAST._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", wt.DWORD),
        ("Next", ctypes.POINTER(UNICAST)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class ADAPTER(ctypes.Structure):
        pass

    ADAPTER._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", ctypes.c_ulong),
        ("Next", ctypes.POINTER(ADAPTER)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(UNICAST)),
    ]

    get_adapters = ctypes.windll.iphlpapi.GetAdaptersAddresses
    size = ctypes.c_ulong(15 * 1024)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        rc = get_adapters(AF_INET, GAA_SKIP, None,
                          ctypes.cast(buf, ctypes.POINTER(ADAPTER)),
                          ctypes.byref(size))
        if rc == ERROR_BUFFER_OVERFLOW:
            continue
        if rc != 0:
            return []
        break
    else:
        return []

    nets: List[ipaddress.IPv4Network] = []
    node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
    while node:
        adapter = node.contents
        ua = adapter.FirstUnicastAddress
        while ua:
            entry = ua.contents
            sa = entry.Address.lpSockaddr
            if sa and entry.Address.iSockaddrLength >= 8:
                raw = bytes(bytearray(sa[i] for i in range(8)))
                family = struct.unpack("<H", raw[0:2])[0]
                if family == AF_INET:
                    addr = socket.inet_ntoa(raw[4:8])
                    prefix = int(entry.OnLinkPrefixLength)
                    if not 0 < prefix <= 32:
                        prefix = 24
                    net = _net_from(addr, prefix)
                    if net:
                        nets.append(net)
            ua = entry.Next
        node = adapter.Next
    return nets


# --- POSIX -----------------------------------------------------------------

def _posix_networks() -> List[ipaddress.IPv4Network]:
    """Interfaces and their prefixes on any POSIX system.

    Prefers ``getifaddrs(3)`` -- which exists on Linux *and* macOS/BSD and
    reports the netmask directly -- and only falls back to the Linux ``ioctl``
    path if that is somehow unavailable. The ioctl path alone used to return
    nothing on macOS (its request numbers and ``ifreq`` layout are Linux-only),
    so a Mac silently assumed /24 for every interface.
    """
    if os.name == "nt":
        return []
    nets = _getifaddrs_networks()
    if nets:
        return nets
    return _posix_ioctl_networks()


# True on macOS/BSD, where a sockaddr begins with a 1-byte length then the
# family, versus Linux where the family is a 2-byte field at offset 0.
_BSD_SOCKADDR = sys.platform == "darwin" or "bsd" in sys.platform


def _sockaddr_ipv4(sa_ptr) -> Optional[bytes]:
    """The 4 address bytes of an ``AF_INET`` sockaddr, or None for anything else.

    The IPv4 address sits at offset 4 of ``sockaddr_in`` on every platform
    (family/port come first); only the location of the family byte differs, so
    that is the single thing we special-case between Linux and BSD.
    """
    import ctypes

    if not sa_ptr:
        return None
    raw = ctypes.cast(sa_ptr, ctypes.POINTER(ctypes.c_ubyte))
    family = raw[1] if _BSD_SOCKADDR else (raw[0] | (raw[1] << 8))
    if family != socket.AF_INET:
        return None
    return bytes(raw[i] for i in range(4, 8))


def _getifaddrs_networks() -> List[ipaddress.IPv4Network]:
    """Portable POSIX probe via ``getifaddrs(3)`` (Linux and macOS/BSD)."""
    try:
        import ctypes
        import ctypes.util
    except ImportError:
        return []

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return []
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except OSError:
        return []
    if not hasattr(libc, "getifaddrs"):
        return []

    class _sockaddr(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_byte * 14)]

    class _ifaddrs(ctypes.Structure):
        pass

    # Only the leading fields are declared; they share the same layout and order
    # on Linux and macOS, and the list is walked through ``ifa_next``.
    _ifaddrs._fields_ = [
        ("ifa_next", ctypes.POINTER(_ifaddrs)),
        ("ifa_name", ctypes.c_char_p),
        ("ifa_flags", ctypes.c_uint),
        ("ifa_addr", ctypes.POINTER(_sockaddr)),
        ("ifa_netmask", ctypes.POINTER(_sockaddr)),
    ]

    head = ctypes.POINTER(_ifaddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        return []
    nets: List[ipaddress.IPv4Network] = []
    try:
        node = head
        while node:
            entry = node.contents
            node = entry.ifa_next
            addr = _sockaddr_ipv4(entry.ifa_addr)
            mask = _sockaddr_ipv4(entry.ifa_netmask)
            if not addr or not mask:
                continue
            try:
                prefix = bin(int.from_bytes(mask, "big")).count("1")
                net = _net_from(socket.inet_ntoa(addr), prefix)
            except (ValueError, OSError):
                continue
            if net:
                nets.append(net)
    finally:
        libc.freeifaddrs(head)
    return nets


def _posix_ioctl_networks() -> List[ipaddress.IPv4Network]:
    """Linux-only fallback using SIOCGIF* ioctls (request numbers are Linux's)."""
    try:
        import fcntl
    except ImportError:
        return []

    SIOCGIFADDR = 0x8915      # Linux
    SIOCGIFNETMASK = 0x891B

    nets: List[ipaddress.IPv4Network] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _index, name in socket.if_nameindex():
            ifreq = struct.pack("16s16x", name.encode("utf-8")[:15])
            try:
                addr_raw = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
                mask_raw = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)
            except OSError:
                continue  # interface has no IPv4, or the ioctl is unsupported
            try:
                addr = socket.inet_ntoa(addr_raw[20:24])
                mask = socket.inet_ntoa(mask_raw[20:24])
                prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
            except (ValueError, OSError):
                continue
            net = _net_from(addr, prefix)
            if net:
                nets.append(net)
    finally:
        sock.close()
    return nets


# --- last resort -----------------------------------------------------------

def _fallback_networks() -> List[ipaddress.IPv4Network]:
    """No prefix information available: assume a /24 around each local address.

    Wrong for a /16 or /22 network, but far better than treating the user's
    real network as remote and refusing every connection on it.
    """
    from .netutil import local_ipv4_addresses

    nets = []
    for addr in local_ipv4_addresses():
        net = _net_from(addr, 24)
        if net:
            nets.append(net)
    return nets
