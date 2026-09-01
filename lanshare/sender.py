"""Sender side: connect to a receiver over TLS, authenticate, and stream files
that the remote user approves."""

from __future__ import annotations

import hashlib
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import PROTOCOL_VERSION
from . import config as cfg_mod
from . import identity
from .auth import AuthError, client_authenticate
from .netutil import ProtocolError, is_lan_address, recv_msg, send_msg
from .tlsctx import client_context

_CONNECT_TIMEOUT = 15.0
_CONTROL_TIMEOUT = 120.0
_CHUNK = 1024 * 1024


class SendError(Exception):
    pass


def _server_fingerprint(tls: ssl.SSLSocket) -> str:
    der = tls.getpeercert(binary_form=True)
    if not der:
        raise SendError("receiver did not present a TLS certificate")
    return identity.fingerprint_from_der(der)


def _check_tofu(peer_name: str, fpr: str, *, interactive: bool) -> None:
    """Trust-on-first-use pinning: warn if a known device's key changed."""
    known = cfg_mod.load_known_peers()  # {fingerprint: name}
    if fpr in known:
        return  # recognised device
    # Has this *name* been seen before under a different fingerprint?
    for known_fpr, known_name in known.items():
        if known_name == peer_name and known_fpr != fpr:
            print(
                f"\n  WARNING: device named '{peer_name}' presented a NEW identity\n"
                f"    previously: {identity.fingerprint_pretty(known_fpr)}\n"
                f"    now       : {identity.fingerprint_pretty(fpr)}\n"
                f"  This is expected if the device was reinstalled, but could also\n"
                f"  indicate someone impersonating it.",
                file=sys.stderr,
            )
            if interactive:
                ans = input("  Continue anyway? [y/N] ").strip().lower()
                if ans not in {"y", "yes"}:
                    raise SendError("aborted by user after fingerprint change")
            break
    else:
        print(f"  New device '{peer_name}' "
              f"({identity.fingerprint_pretty(fpr)}); trusting on first use.")
    known[fpr] = peer_name
    cfg_mod.save_known_peers(known)


def send_files(host: str, port: int, files: Sequence[str], *,
               secret: Optional[bytes] = None, device_name: Optional[str] = None,
               interactive: bool = True, show_progress: bool = True) -> List[Dict[str, Any]]:
    """Send one or more files to a receiver. Returns a per-file result list."""
    cfg = cfg_mod.load_config()
    device_name = device_name or cfg["device_name"]
    secret = secret if secret is not None else cfg_mod.load_secret()
    if not secret:
        raise SendError("No shared secret set. Run 'lanshare set-secret' first.")

    paths: List[Path] = []
    for f in files:
        p = Path(f).expanduser()
        if not p.exists() or not p.is_file():
            raise SendError(f"not a readable file: {f}")
        paths.append(p)
    if not paths:
        raise SendError("no files to send")

    # Resolve the address and confirm it is on the local network.
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SendError(f"cannot resolve host {host!r}: {exc}") from exc
    resolved_ip = infos[0][4][0]
    if not is_lan_address(resolved_ip):
        raise SendError(f"refusing to connect to non-LAN address {resolved_ip}")

    ctx = client_context()
    raw = socket.create_connection((resolved_ip, port), timeout=_CONNECT_TIMEOUT)
    tls: Optional[ssl.SSLSocket] = None
    try:
        raw.settimeout(_CONTROL_TIMEOUT)
        tls = ctx.wrap_socket(raw, server_hostname=None)
        server_fpr = _server_fingerprint(tls)

        client_authenticate(tls, secret, server_fpr)

        send_msg(tls, {"type": "hello", "device_name": device_name,
                       "protocol": PROTOCOL_VERSION})
        hello = recv_msg(tls)
        if hello.get("type") != "hello":
            raise SendError("unexpected reply to hello")
        peer_name = str(hello.get("device_name", "unknown"))[:64]

        _check_tofu(peer_name, server_fpr, interactive=interactive)
        print(f"  Connected to '{peer_name}' at {resolved_ip}:{port}")

        results: List[Dict[str, Any]] = []
        for path in paths:
            results.append(_send_one(tls, path, peer_name, show_progress))

        send_msg(tls, {"type": "bye"})
        return results
    except AuthError as exc:
        raise SendError(f"authentication failed: {exc}") from exc
    finally:
        if tls is not None:
            try:
                tls.close()
            except OSError:
                pass
        else:
            raw.close()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _send_one(tls: ssl.SSLSocket, path: Path, peer_name: str,
              show_progress: bool) -> Dict[str, Any]:
    size = path.stat().st_size
    digest = _sha256_file(path)

    send_msg(tls, {"type": "offer", "name": path.name, "size": size, "sha256": digest})
    decision = recv_msg(tls)
    if decision.get("type") != "decision":
        raise SendError("unexpected reply to offer")
    if not decision.get("accept"):
        reason = decision.get("reason", "declined")
        print(f"  '{path.name}' was not accepted: {reason}")
        return {"file": str(path), "sent": False, "reason": reason}

    stored_as = decision.get("stored_as", path.name)
    print(f"  Sending '{path.name}' -> '{stored_as}' ...")

    sent = 0
    start = time.monotonic()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            tls.sendall(chunk)
            sent += len(chunk)
            if show_progress and size:
                _progress(sent, size, start)
    if show_progress:
        sys.stdout.write("\n")
        sys.stdout.flush()

    result = recv_msg(tls)
    if result.get("type") != "result":
        raise SendError("unexpected reply after sending file")
    if not result.get("ok"):
        raise SendError(f"receiver reported failure: {result.get('error')}")
    if result.get("sha256", "").lower() != digest.lower():
        raise SendError("receiver's sha256 did not match; transfer may be corrupt")

    print(f"  Done: '{stored_as}' delivered and verified.")
    return {"file": str(path), "sent": True, "stored_as": stored_as, "sha256": digest}


def _progress(sent: int, total: int, start: float) -> None:
    pct = sent * 100 // total
    elapsed = max(time.monotonic() - start, 1e-6)
    rate = sent / elapsed / (1024 * 1024)
    bar_len = 30
    filled = bar_len * sent // total
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\r    [{bar}] {pct:3d}%  {rate:6.1f} MiB/s")
    sys.stdout.flush()
