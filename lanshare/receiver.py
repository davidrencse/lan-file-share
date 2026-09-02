"""Receiver side: a TLS server that authenticates, asks for approval, and
writes incoming files safely into the download directory."""

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
from typing import Any, Callable, Dict, List, Optional

from . import PROTOCOL_VERSION
from . import config as cfg_mod
from . import history
from . import identity
from .auth import AuthError, server_authenticate
from .discovery import DiscoveryResponder
from .netutil import (
    ProtocolError,
    describe_local_networks,
    is_lan_address,
    local_ipv4_addresses,
    recv_msg,
    send_msg,
    set_exclusive_bind,
)
from .safety import (
    UnsafeFileError,
    check_free_space,
    human_size,
    partial_path,
    release_destination,
    reserve_destination,
    sanitize_display_text,
    sanitize_filename,
    validate_size,
)
from .tlsctx import server_context

# A stalled TLS handshake must not tie up a slot for long.
_HANDSHAKE_TIMEOUT = 15.0
# No single control exchange should take longer than this.
_CONTROL_TIMEOUT = 120.0
# Abort a stalled data transfer if no bytes arrive for this long.
_DATA_TIMEOUT = 120.0
_CHUNK = 1024 * 1024
# Connections served at once. Bounded so a flood cannot exhaust memory/threads.
_MAX_CONCURRENT = 8


# An approval callback returns True to accept a transfer. Default is interactive.
ApprovalFn = Callable[[Dict[str, Any]], bool]
# Progress callback: (file_name, bytes_received, total_bytes).
ProgressFn = Callable[[str, int, int], None]
# Log callback: a human-readable status line (also always printed to console).
LogFn = Callable[[str], None]
# Completion callback: fired once per file, only after the checksum is verified
# and the file is in place, so the UI can show a truthful final state.
CompleteFn = Callable[[Dict[str, Any]], None]


def _interactive_approval(info: Dict[str, Any]) -> bool:
    print()
    print("  Incoming file transfer request")
    print(f"    From        : {info['peer_name']}  ({info['peer_ip']})")
    print(f"    File        : {info['safe_name']}")
    if info["safe_name"] != info["raw_name"]:
        print(f"    (original)  : {info['raw_name']}")
    print(f"    Size        : {human_size(info['size'])}")
    print(f"    Will save to: {info['download_dir']}")
    print()
    try:
        answer = input("  Accept this file? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


class _AuthThrottle:
    """Rate-limits failed authentication attempts, per source address.

    The shared secret is the only thing standing between a LAN peer and the
    approval prompt, so unlimited online guessing should not be free. Repeated
    failures from one address earn a cooldown.
    """

    MAX_FAILURES = 5
    WINDOW = 300.0     # forget failures older than this
    LOCKOUT = 60.0     # refuse the address for this long once tripped
    MAX_TRACKED = 1024

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: Dict[str, List[float]] = {}
        self._blocked_until: Dict[str, float] = {}

    def retry_after(self, ip: str) -> float:
        """Seconds remaining before *ip* may try again (0 if allowed now)."""
        now = time.monotonic()
        with self._lock:
            until = self._blocked_until.get(ip, 0.0)
            return max(0.0, until - now)

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._failures) > self.MAX_TRACKED:
                self._failures.clear()
                self._blocked_until.clear()
            times = [t for t in self._failures.get(ip, []) if now - t < self.WINDOW]
            times.append(now)
            self._failures[ip] = times
            if len(times) >= self.MAX_FAILURES:
                self._blocked_until[ip] = now + self.LOCKOUT
                self._failures[ip] = []

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
            self._blocked_until.pop(ip, None)


class Receiver:
    def __init__(self, config: Dict[str, Any], *, approval: Optional[ApprovalFn] = None,
                 bind_host: str = "0.0.0.0", progress_cb: Optional[ProgressFn] = None,
                 log_cb: Optional[LogFn] = None,
                 complete_cb: Optional[CompleteFn] = None):
        self.config = config
        self.approval = approval or _interactive_approval
        self.bind_host = bind_host
        self.progress_cb = progress_cb
        self.log_cb = log_cb
        self.complete_cb = complete_cb
        # Set when the discovery responder could not bind, so the GUI can say
        # so instead of leaving the user wondering why nobody sees them.
        self.discovery_error: Optional[str] = None
        self.refused_addresses: Dict[str, int] = {}
        self.download_dir = cfg_mod.get_download_dir(config)
        self.max_bytes = int(config.get("max_file_bytes"))
        self.secret = cfg_mod.load_secret()
        self.device_name = config["device_name"]
        self._responder: Optional[DiscoveryResponder] = None
        self.actual_port: Optional[int] = None
        self._stop_flag = threading.Event()
        self._log_lock = threading.Lock()
        self._approval_lock = threading.Lock()
        self._slots = threading.Semaphore(_MAX_CONCURRENT)
        self._workers: List[threading.Thread] = []
        self._throttle = _AuthThrottle()

    # -- lifecycle ----------------------------------------------------------

    def stop(self) -> None:
        """Ask a running serve_forever() loop to shut down (from any thread)."""
        self._stop_flag.set()

    def _log(self, msg: str, *, err: bool = False) -> None:
        with self._log_lock:
            print(msg, file=sys.stderr if err else sys.stdout)
        if self.log_cb:
            try:
                self.log_cb(msg)
            except Exception:  # noqa: BLE001 -- a broken UI callback must not kill the server
                pass

    def serve_forever(self) -> None:
        if not self.secret:
            raise RuntimeError(
                "No shared secret set. Run 'lanshare set-secret' first "
                "(and use the same secret on both devices)."
            )
        self._stop_flag.clear()
        key_path, cert_path = identity.ensure_identity(self.device_name)
        server_fpr = identity.own_fingerprint() or ""
        ctx = server_context(cert_path, key_path)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_exclusive_bind(listener)
        listener.bind((self.bind_host, int(self.config["port"])))
        listener.listen(16)
        listener.settimeout(0.5)  # periodic wake-up to check the stop flag
        self.actual_port = listener.getsockname()[1]

        if self.config.get("discovery_enabled", True):
            self._responder = DiscoveryResponder(
                self.device_name, self.actual_port,
                int(self.config["discovery_port"]), server_fpr, self.secret,
            )
            try:
                self._responder.start()
            except OSError as exc:
                self.discovery_error = str(exc)
                self._log(f"  WARNING: discovery is off ({exc}) -- other devices "
                          f"will not find this one automatically; they can still "
                          f"connect by IP.", err=True)
                self._responder = None

        self._print_banner(server_fpr)

        try:
            while not self._stop_flag.is_set():
                try:
                    raw_sock, addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._dispatch(ctx, raw_sock, addr, server_fpr)
        finally:
            if self._responder:
                self._responder.stop()
            listener.close()
            self._join_workers()

    def _dispatch(self, ctx: ssl.SSLContext, raw_sock: socket.socket,
                  addr: Any, server_fpr: str) -> None:
        """Hand one accepted connection to a worker thread.

        Handling connections inline would let a single peer that opens a socket
        and then goes quiet block every other transfer for the whole timeout.
        """
        if not self._slots.acquire(blocking=False):
            self._log(f"  Too many concurrent connections; refused {addr[0]}", err=True)
            try:
                raw_sock.close()
            except OSError:
                pass
            return

        def run() -> None:
            try:
                self._handle_one(ctx, raw_sock, addr, server_fpr)
            except Exception as exc:  # noqa: BLE001 -- never let one peer kill the server
                self._log(f"  Connection from {addr[0]} failed: {exc}", err=True)
            finally:
                self._slots.release()

        worker = threading.Thread(target=run, name=f"xfer-{addr[0]}", daemon=True)
        self._workers = [t for t in self._workers if t.is_alive()]
        self._workers.append(worker)
        worker.start()

    def _join_workers(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        for worker in list(self._workers):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            worker.join(remaining)

    def _print_banner(self, server_fpr: str) -> None:
        self._log(f"LANShare receiver '{self.device_name}' is ready.")
        addrs = local_ipv4_addresses()
        if addrs:
            self._log(f"  Listening on : {', '.join(addrs)} port {self.actual_port}")
        else:
            self._log(f"  Listening on port {self.actual_port}")
        self._log(f"  Saving files to: {self.download_dir}")
        self._log(f"  This device's fingerprint: {identity.fingerprint_pretty(server_fpr)}")
        self._log("  Waiting for transfers... (Ctrl+C to stop)")

    # -- per-connection handling -------------------------------------------

    def _handle_one(self, ctx: ssl.SSLContext, raw_sock: socket.socket,
                    addr: Any, server_fpr: str) -> None:
        peer_ip = addr[0]
        if not is_lan_address(peer_ip):
            # Counted so the Troubleshoot panel can say "we refused N
            # connections from 172.1.x.x because it is not recognised as a
            # local network" -- previously this only went to stderr, which the
            # GUI never displayed, so it looked like nothing happened at all.
            with self._log_lock:
                self.refused_addresses[peer_ip] = \
                    self.refused_addresses.get(peer_ip, 0) + 1
            self._log(f"  Rejected connection from {peer_ip}: not on a network "
                      f"this device recognises as local "
                      f"({describe_local_networks()})", err=True)
            raw_sock.close()
            return

        cooldown = self._throttle.retry_after(peer_ip)
        if cooldown > 0:
            self._log(f"  {peer_ip} is rate-limited after repeated auth failures "
                      f"({cooldown:.0f}s remaining)", err=True)
            raw_sock.close()
            return

        tls: Optional[ssl.SSLSocket] = None
        try:
            raw_sock.settimeout(_HANDSHAKE_TIMEOUT)
            tls = ctx.wrap_socket(raw_sock, server_side=True)
            tls.settimeout(_CONTROL_TIMEOUT)
            assert self.secret is not None
            try:
                server_authenticate(tls, self.secret, server_fpr)
            except AuthError:
                self._throttle.record_failure(peer_ip)
                raise
            self._throttle.record_success(peer_ip)

            hello = recv_msg(tls)
            if hello.get("type") != "hello":
                raise ProtocolError("expected hello")
            peer_name = sanitize_display_text(hello.get("device_name", "unknown"))
            send_msg(tls, {
                "type": "hello",
                "device_name": self.device_name,
                "protocol": PROTOCOL_VERSION,
            })

            self._session(tls, peer_ip, peer_name)

        except AuthError as exc:
            self._log(f"  Auth failed from {peer_ip}: {exc}", err=True)
            _safe_send(tls, {"type": "error", "error": "authentication failed"})
        except (ProtocolError, ssl.SSLError, OSError, UnsafeFileError) as exc:
            self._log(f"  Connection from {peer_ip} ended: {exc}", err=True)
        finally:
            _close(tls, raw_sock)

    def _session(self, tls: ssl.SSLSocket, peer_ip: str, peer_name: str) -> None:
        """Handle one or more file offers on an authenticated connection."""
        while not self._stop_flag.is_set():
            msg = recv_msg(tls)
            mtype = msg.get("type")
            if mtype == "bye":
                return
            if mtype != "offer":
                raise ProtocolError(f"unexpected message: {mtype!r}")
            self._handle_offer(tls, peer_ip, peer_name, msg)

    def _handle_offer(self, tls: ssl.SSLSocket, peer_ip: str, peer_name: str,
                      msg: Dict[str, Any]) -> None:
        raw_name = str(msg.get("name", ""))
        size = msg.get("size")
        declared_sha = msg.get("sha256")

        # Validate everything before we even show the prompt.
        try:
            safe_name = sanitize_filename(raw_name)
            validate_size(size if isinstance(size, int) else -1, self.max_bytes)
            check_free_space(self.download_dir, int(size))
        except UnsafeFileError as exc:
            self._log(f"  Rejected offer from {peer_name}: {exc}", err=True)
            send_msg(tls, {"type": "decision", "accept": False, "reason": str(exc)})
            return
        except OSError as exc:
            self._log(f"  Cannot accept offer from {peer_name}: {exc}", err=True)
            send_msg(tls, {"type": "decision", "accept": False,
                           "reason": "receiver cannot store the file right now"})
            return

        info = {
            "peer_name": peer_name,
            "peer_ip": peer_ip,
            "raw_name": sanitize_display_text(raw_name, limit=120),
            "safe_name": safe_name,
            "size": int(size),
            "download_dir": str(self.download_dir),
        }
        # Only one prompt at a time, even with several connections in flight.
        with self._approval_lock:
            try:
                accepted = self.approval(info)
            except KeyboardInterrupt:
                accepted = False

        if not accepted:
            self._log(f"  Declined '{safe_name}' from {peer_name}")
            history.record_received(safe_name, int(size), peer_name, peer_ip,
                                    path=None, status=history.DECLINED)
            send_msg(tls, {"type": "decision", "accept": False, "reason": "declined by user"})
            return

        # Claim the destination name atomically so two concurrent transfers (or
        # anything else on the machine) cannot pick the same path.
        try:
            dest = reserve_destination(self.download_dir, safe_name)
        except UnsafeFileError as exc:
            self._log(f"  Cannot store '{safe_name}': {exc}", err=True)
            send_msg(tls, {"type": "decision", "accept": False,
                           "reason": "receiver could not allocate a destination"})
            return

        try:
            send_msg(tls, {"type": "decision", "accept": True, "stored_as": dest.name})
            self._receive_file(tls, dest, int(size), declared_sha, peer_name, peer_ip)
        except BaseException:
            release_destination(dest)
            raise

    def _receive_file(self, tls: ssl.SSLSocket, dest: Path, size: int,
                      declared_sha: Any, peer_name: str, peer_ip: str = "") -> None:
        tmp = partial_path(dest)
        hasher = hashlib.sha256()
        received = 0
        tls.settimeout(_DATA_TIMEOUT)
        try:
            with open(tmp, "wb") as fh:
                while received < size:
                    if self._stop_flag.is_set():
                        raise ProtocolError("receiver is shutting down")
                    chunk = tls.recv(min(_CHUNK, size - received))
                    if not chunk:
                        raise ProtocolError("stream ended before file was complete")
                    fh.write(chunk)
                    hasher.update(chunk)
                    received += len(chunk)
                    if self.progress_cb:
                        try:
                            self.progress_cb(dest.name, received, size)
                        except Exception:  # noqa: BLE001
                            pass
            actual_sha = hasher.hexdigest()

            if isinstance(declared_sha, str) and declared_sha:
                if not _hex_equal(actual_sha, declared_sha):
                    raise ProtocolError("sha256 mismatch -- file corrupted in transit")

            os.replace(tmp, dest)  # atomically replaces our own reservation
            # Recorded only here: past the checksum check and past the rename,
            # so a record of "ok" always means the file really is on disk and
            # verified.
            history.record_received(dest.name, size, peer_name, peer_ip,
                                    path=str(dest), status=history.OK)
            if self.complete_cb:
                try:
                    self.complete_cb({"name": dest.name, "size": size,
                                      "path": str(dest), "peer_name": peer_name,
                                      "status": history.OK})
                except Exception:  # noqa: BLE001
                    pass
            self._log(f"  Saved '{dest.name}' ({human_size(size)}) from {peer_name}")
            send_msg(tls, {
                "type": "result", "ok": True,
                "stored_as": dest.name, "sha256": actual_sha,
            })
        except Exception as exc:  # noqa: BLE001 -- always clean up the temp file
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            history.record_received(dest.name, size, peer_name, peer_ip,
                                    path=None, status=history.FAILED,
                                    error=str(exc))
            if self.complete_cb:
                try:
                    self.complete_cb({"name": dest.name, "size": size,
                                      "path": None, "peer_name": peer_name,
                                      "status": history.FAILED, "error": str(exc)})
                except Exception:  # noqa: BLE001
                    pass
            # Detail stays local; the peer gets a generic reason so local paths
            # and disk layout are not disclosed over the wire.
            self._log(f"  Transfer of '{dest.name}' failed: {exc}", err=True)
            _safe_send(tls, {"type": "result", "ok": False,
                             "error": "receiver could not store the file"})
            raise
        finally:
            tls.settimeout(_CONTROL_TIMEOUT)


def _hex_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower(), b.lower().strip())


def _safe_send(tls: Optional[ssl.SSLSocket], obj: Dict[str, Any]) -> None:
    if tls is None:
        return
    try:
        send_msg(tls, obj)
    except (OSError, ssl.SSLError, ProtocolError):
        pass


def _close(tls: Optional[ssl.SSLSocket], raw_sock: socket.socket) -> None:
    if tls is not None:
        try:
            tls.close()
            return
        except OSError:
            pass
    try:
        raw_sock.close()
    except OSError:
        pass
