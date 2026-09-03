"""Sender side: connect to a receiver over TLS, authenticate, and stream files
that the remote user approves.

A folder is sent as a *batch*: one ``batch`` message describing the whole
folder, one approval from the remote user, then an ``offer``/data exchange per
file carrying its path relative to the folder root. That needs protocol 2 on
the receiving side; against an older receiver a folder send is refused, and
plain-file sends are unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import PROTOCOL_VERSION
from . import config as cfg_mod
from . import history
from . import identity
from .auth import AuthError, client_authenticate
from .netutil import ProtocolError, is_lan_address, recv_msg, send_msg
from .safety import human_size, sanitize_display_text
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


# One thing to send: an absolute path, the name that goes on the wire (relative
# to its folder root, or a bare name for a lone file), and the name shown to the
# user and recorded in history.
_Entry = Tuple[Path, str, str]


def _walk_folder(folder: Path, skipped: List[str]) -> Tuple[List[_Entry], int]:
    """Collect the files inside *folder*, relative to it, plus their total size.

    Symlinks are skipped rather than followed: a link can point outside the
    folder the user chose, so following it would send something they never
    selected, and a link back into the tree would loop.
    """
    entries: List[_Entry] = []
    total = 0
    root_name = folder.name or "folder"
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                skipped.append(str(path))
                continue
            try:
                total += path.stat().st_size
            except OSError:
                skipped.append(str(path))
                continue
            wire = path.relative_to(folder).as_posix()
            entries.append((path, wire, root_name + "/" + wire))
    return entries, total


def _collect(files: Sequence[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Turn the user's arguments into groups: one per folder, one per lone file."""
    groups: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for f in files:
        p = Path(f).expanduser()
        if p.is_dir() and not p.is_symlink():
            entries, total = _walk_folder(p, skipped)
            if not entries:
                raise SendError(f"folder has no files to send: {f}")
            groups.append({"folder": p.name or "folder", "entries": entries,
                           "total": total})
        elif p.is_file():
            try:
                total = p.stat().st_size
            except OSError as exc:
                raise SendError(f"cannot read {f}: {exc}") from exc
            groups.append({"folder": None,
                           "entries": [(p, p.name, p.name)], "total": total})
        else:
            raise SendError(f"not a readable file or folder: {f}")
    if not groups:
        raise SendError("no files to send")
    return groups, skipped


def send_files(host: str, port: int, files: Sequence[str], *,
               secret: Optional[bytes] = None, device_name: Optional[str] = None,
               interactive: bool = True, show_progress: bool = True,
               progress_cb: Optional[ProgressFn] = None,
               log_cb: Optional[LogFn] = None,
               tofu_confirm_cb: Optional[TofuConfirmFn] = None,
               cancel_event: Optional[threading.Event] = None,
               expect_fingerprint: Optional[str] = None) -> List[Dict[str, Any]]:
    """Send files and/or folders to a receiver. Returns a per-file result list."""

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

    groups, skipped = _collect(files)

    # Resolve the address and confirm it is on the local network.
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SendError(f"cannot resolve host {host!r}: {exc}") from exc
    resolved_ip = infos[0][4][0]
    if not is_lan_address(resolved_ip):
        from .netutil import describe_local_networks

        raise SendError(
            f"{resolved_ip} is not on a network this device recognises as "
            f"local, so the connection was not attempted ({describe_local_networks()}). "
            f"If that really is your other computer -- some networks put Wi-Fi "
            f"and Ethernet on separate subnets -- add its network under "
            f"Settings, or with: lanshare config "
            f"--trust-network {resolved_ip}/24"
        )

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

        peer_protocol = hello.get("protocol")
        peer_protocol = peer_protocol if isinstance(peer_protocol, int) else 1
        if any(g["folder"] for g in groups) and peer_protocol < 2:
            raise SendError(
                f"'{peer_name}' is running an older version of LANShare "
                f"(protocol {peer_protocol}), which can only receive individual "
                f"files. Update LANShare on that device to send folders, or "
                f"select the files inside the folder instead."
            )

        for skipped_path in skipped:
            log(f"  Skipping '{skipped_path}' (not a regular file)")

        results: List[Dict[str, Any]] = []
        for group in groups:
            results.extend(_send_group(tls, group, peer_name, show_progress, log,
                                       progress_cb, cancel_event))

        _record_history(results, peer_name, resolved_ip)
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


def _send_group(tls: ssl.SSLSocket, group: Dict[str, Any], peer_name: str,
                show_progress: bool, log: LogFn,
                progress_cb: Optional[ProgressFn],
                cancel_event: Optional[threading.Event]) -> List[Dict[str, Any]]:
    """Send one folder (as a single approved batch) or one lone file."""
    entries: List[_Entry] = group["entries"]
    folder = group["folder"]
    results: List[Dict[str, Any]] = []

    if folder:
        log(f"  Offering folder '{folder}' "
            f"({len(entries)} files, {human_size(group['total'])}) ...")
        send_msg(tls, {"type": "batch", "name": folder,
                       "count": len(entries), "total_size": group["total"]})
        decision = recv_msg(tls)
        if decision.get("type") != "decision":
            raise SendError("unexpected reply to folder offer")
        if not decision.get("accept"):
            reason = sanitize_display_text(decision.get("reason", "declined"), limit=120)
            log(f"  Folder '{folder}' was not accepted: {reason}")
            return [{"file": str(path), "name": display, "sent": False,
                     "reason": reason} for path, _wire, display in entries]

    try:
        for path, wire, display in entries:
            if cancel_event is not None and cancel_event.is_set():
                results.append({"file": str(path), "name": display,
                                "sent": False, "reason": "cancelled"})
                continue
            results.append(_send_one(tls, path, wire, display, peer_name,
                                     show_progress, log, progress_cb, cancel_event))
    finally:
        # Always close the batch, even on cancellation or failure, so the
        # receiver never holds an approval open for whatever we send next.
        if folder:
            try:
                send_msg(tls, {"type": "batch_end"})
            except (OSError, ssl.SSLError, ProtocolError):
                pass
    return results


def _record_history(results: List[Dict[str, Any]], peer_name: str,
                    peer_ip: str) -> None:
    """Log each outcome so the Files page can show what we sent, and where."""
    for result in results:
        path = Path(result["file"])
        # For a folder transfer this is "photos/2024/beach.jpg", so the Files
        # page shows where the file sat rather than a bare name.
        name = str(result.get("name") or path.name)
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if result.get("sent"):
            history.record_sent(name, size, peer_name, peer_ip,
                                status=history.OK)
        else:
            reason = str(result.get("reason", "not accepted"))
            status = history.DECLINED if "declin" in reason.lower() else history.FAILED
            history.record_sent(name, size, peer_name, peer_ip,
                                status=status, error=reason)


def _sha256_file(path: Path, display: str, progress_cb: Optional[ProgressFn],
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
                    progress_cb(display, done, size, "hashing")
                except Exception:  # noqa: BLE001
                    pass
    return h.hexdigest()


def _send_one(tls: ssl.SSLSocket, path: Path, wire_name: str, display: str,
             peer_name: str, show_progress: bool,
             log: LogFn, progress_cb: Optional[ProgressFn],
             cancel_event: Optional[threading.Event]) -> Dict[str, Any]:
    size = path.stat().st_size
    digest = _sha256_file(path, display, progress_cb, cancel_event)

    send_msg(tls, {"type": "offer", "name": wire_name, "size": size, "sha256": digest})
    decision = recv_msg(tls)
    if decision.get("type") != "decision":
        raise SendError("unexpected reply to offer")
    if not decision.get("accept"):
        reason = decision.get("reason", "declined")
        log(f"  '{display}' was not accepted: {reason}")
        return {"file": str(path), "name": display, "sent": False, "reason": reason}

    stored_as = sanitize_display_text(decision.get("stored_as", display), limit=120)
    log(f"  Sending '{display}' -> '{stored_as}' ...")

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
                    f"'{display}' shrank while it was being sent "
                    f"({sent} of {size} bytes available); transfer aborted"
                )
            tls.sendall(chunk)
            sent += len(chunk)
            if show_progress and size:
                _console_progress(sent, size, start)
            if progress_cb:
                try:
                    progress_cb(display, sent, size, "sending")
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
    return {"file": str(path), "name": display, "sent": True,
            "stored_as": stored_as, "sha256": digest}


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
