"""Sender side: connect to a receiver over TLS, authenticate, and stream files
that the remote user approves."""

from __future__ import annotations

import hashlib
import hmac
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import PROTOCOL_VERSION
from . import config as cfg_mod
from . import identity
from .auth import AuthError, client_authenticate
from .netutil import ProtocolError, is_lan_address, recv_msg, send_msg
from .safety import sanitize_display_text
from .tlsctx import client_context

_CONNECT_TIMEOUT = 15.0
_CONTROL_TIMEOUT = 120.0
_CHUNK = 1024 * 1024

# Progress callback: (file_name, bytes_sent, total_bytes, phase) where
# phase is "hashing" (pre-flight sha256) or "sending".
ProgressFn = Callable[[str, int, int, str], None]
# Log callback: a human-readable status line (also always printed to console).
LogFn = Callable[[str], None]
# Called on a TOFU fingerprint mismatch; return True to proceed anyway.
TofuConfirmFn = Callable[[str, str, str], bool]


class SendError(Exception):
    pass


class Cancelled(SendError):
    pass


def _server_fingerprint(tls: ssl.SSLSocket) -> str:
    der = tls.getpeercert(binary_form=True)
    if not der:
        raise SendError("receiver did not present a TLS certificate")
    return identity.fingerprint_from_der(der)


def _check_tofu(peer_name: str, fpr: str, *, interactive: bool,
                log: LogFn, tofu_confirm_cb: Optional[TofuConfirmFn]) -> None:
    """Trust-on-first-use pinning: warn if a known device's key changed."""
    known = cfg_mod.load_known_peers()  # {fingerprint: name}
    if fpr in known:
        return  # recognised device
    # Has this *name* been seen before under a different fingerprint?
    for known_fpr, known_name in known.items():
        if known_name == peer_name and known_fpr != fpr:
            warning = (
                f"WARNING: device named '{peer_name}' presented a NEW identity. "
                f"Previously: {identity.fingerprint_pretty(known_fpr)}  "
                f"Now: {identity.fingerprint_pretty(fpr)}. This is expected if the "
                f"device was reinstalled, but could also indicate impersonation."
            )
            log(warning)
            if tofu_confirm_cb is not None:
                if not tofu_confirm_cb(peer_name, known_fpr, fpr):
                    raise SendError("aborted by user after fingerprint change")
            elif interactive:
                ans = input("  Continue anyway? [y/N] ").strip().lower()
                if ans not in {"y", "yes"}:
                    raise SendError("aborted by user after fingerprint change")
            break
    else:
        log(f"New device '{peer_name}' "
            f"({identity.fingerprint_pretty(fpr)}); trusting on first use.")
    known[fpr] = peer_name
    cfg_mod.save_known_peers(known)


def send_files(host: str, port: int, files: Sequence[str], *,
               secret: Optional[bytes] = None, device_name: Optional[str] = None,
               interactive: bool = True, show_progress: bool = True,
               progress_cb: Optional[ProgressFn] = None,
               log_cb: Optional[LogFn] = None,
               tofu_confirm_cb: Optional[TofuConfirmFn] = None,
               cancel_event: Optional[threading.Event] = None,
               expect_fingerprint: Optional[str] = None) -> List[Dict[str, Any]]:
    """Send one or more files to a receiver. Returns a per-file result list."""

    def log(msg: str) -> None:
        print(msg)
        if log_cb:
            try:
                log_cb(msg)
            except Exception:  # noqa: BLE001 -- a broken UI callback must not abort a send
                pass

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

        # When we already know which certificate to expect (discovery replies
        # are authenticated and carry the peer's fingerprint), verify it before
        # authenticating. The auth step necessarily reveals an HMAC computed
        # with the shared secret, so refusing here means a device that lured us
        # into connecting never gets material it could attack offline.
        if expect_fingerprint and not hmac.compare_digest(
                server_fpr.lower(), expect_fingerprint.strip().lower()):
            raise SendError(
                "receiver's TLS identity does not match the one it advertised "
                "over discovery -- aborting before authenticating"
            )

        client_authenticate(tls, secret, server_fpr)

        send_msg(tls, {"type": "hello", "device_name": device_name,
                       "protocol": PROTOCOL_VERSION})
        hello = recv_msg(tls)
        if hello.get("type") != "hello":
            raise SendError("unexpected reply to hello")
        peer_name = sanitize_display_text(hello.get("device_name", "unknown"))

        _check_tofu(peer_name, server_fpr, interactive=interactive, log=log,
                   tofu_confirm_cb=tofu_confirm_cb)
        log(f"  Connected to '{peer_name}' at {resolved_ip}:{port}")

        results: List[Dict[str, Any]] = []
        for path in paths:
            if cancel_event is not None and cancel_event.is_set():
                results.append({"file": str(path), "sent": False, "reason": "cancelled"})
                continue
            results.append(_send_one(tls, path, peer_name, show_progress, log,
                                     progress_cb, cancel_event))

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


def _sha256_file(path: Path, progress_cb: Optional[ProgressFn],
                 cancel_event: Optional[threading.Event]) -> str:
    h = hashlib.sha256()
    size = path.stat().st_size
    done = 0
    with open(path, "rb") as fh:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise Cancelled("cancelled by user")
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress_cb:
                try:
                    progress_cb(path.name, done, size, "hashing")
                except Exception:  # noqa: BLE001
                    pass
    return h.hexdigest()


def _send_one(tls: ssl.SSLSocket, path: Path, peer_name: str, show_progress: bool,
             log: LogFn, progress_cb: Optional[ProgressFn],
             cancel_event: Optional[threading.Event]) -> Dict[str, Any]:
    size = path.stat().st_size
    digest = _sha256_file(path, progress_cb, cancel_event)

    send_msg(tls, {"type": "offer", "name": path.name, "size": size, "sha256": digest})
    decision = recv_msg(tls)
    if decision.get("type") != "decision":
        raise SendError("unexpected reply to offer")
    if not decision.get("accept"):
        reason = decision.get("reason", "declined")
        log(f"  '{path.name}' was not accepted: {reason}")
        return {"file": str(path), "sent": False, "reason": reason}

    stored_as = decision.get("stored_as", path.name)
    log(f"  Sending '{path.name}' -> '{stored_as}' ...")

    sent = 0
    start = time.monotonic()
    with open(path, "rb") as fh:
        # Send exactly the number of bytes we declared in the offer. If the file
        # changed underneath us since stat(), sending more would desynchronise
        # the stream and sending fewer would hang the receiver until its
        # timeout, so bail out loudly instead.
        while sent < size:
            if cancel_event is not None and cancel_event.is_set():
                raise Cancelled("cancelled by user")
            chunk = fh.read(min(_CHUNK, size - sent))
            if not chunk:
                raise SendError(
                    f"'{path.name}' shrank while it was being sent "
                    f"({sent} of {size} bytes available); transfer aborted"
                )
            tls.sendall(chunk)
            sent += len(chunk)
            if show_progress and size:
                _console_progress(sent, size, start)
            if progress_cb:
                try:
                    progress_cb(path.name, sent, size, "sending")
                except Exception:  # noqa: BLE001
                    pass
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

    log(f"  Done: '{stored_as}' delivered and verified.")
    return {"file": str(path), "sent": True, "stored_as": stored_as, "sha256": digest}


def _console_progress(sent: int, total: int, start: float) -> None:
    pct = sent * 100 // total
    elapsed = time.monotonic() - start
    bar_len = 30
    filled = bar_len * sent // total
    bar = "#" * filled + "-" * (bar_len - filled)
    # Below ~150 ms the elapsed time is mostly noise and the derived rate is
    # meaningless (it used to print things like "1907348.6 MiB/s").
    if elapsed >= 0.15:
        rate = sent / elapsed / (1024 * 1024)
        sys.stdout.write(f"\r    [{bar}] {pct:3d}%  {rate:6.1f} MiB/s")
    else:
        sys.stdout.write(f"\r    [{bar}] {pct:3d}%")
    sys.stdout.flush()
