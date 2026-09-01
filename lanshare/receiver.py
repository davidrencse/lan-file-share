"""Receiver side: a TLS server that authenticates, asks for approval, and
writes incoming files safely into the download directory."""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from . import PROTOCOL_VERSION
from . import config as cfg_mod
from . import identity
from .auth import AuthError, server_authenticate
from .discovery import DiscoveryResponder
from .netutil import (
    ProtocolError,
    is_lan_address,
    local_ipv4_addresses,
    recv_exact,
    recv_msg,
    send_msg,
)
from .safety import (
    UnsafeFileError,
    check_free_space,
    human_size,
    partial_path,
    resolve_safe_destination,
    sanitize_filename,
    validate_size,
)
from .tlsctx import server_context

# No single control exchange should take longer than this.
_CONTROL_TIMEOUT = 120.0
# Abort a stalled data transfer if no bytes arrive for this long.
_DATA_TIMEOUT = 120.0
_CHUNK = 1024 * 1024


# An approval callback returns True to accept a transfer. Default is interactive.
ApprovalFn = Callable[[Dict[str, Any]], bool]
# Progress callback: (file_name, bytes_received, total_bytes).
ProgressFn = Callable[[str, int, int], None]
# Log callback: a human-readable status line (also always printed to console).
LogFn = Callable[[str], None]


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


class Receiver:
    def __init__(self, config: Dict[str, Any], *, approval: Optional[ApprovalFn] = None,
                 bind_host: str = "0.0.0.0", progress_cb: Optional[ProgressFn] = None,
                 log_cb: Optional[LogFn] = None):
        self.config = config
        self.approval = approval or _interactive_approval
        self.bind_host = bind_host
        self.progress_cb = progress_cb
        self.log_cb = log_cb
        self.download_dir = cfg_mod.get_download_dir(config)
        self.max_bytes = int(config.get("max_file_bytes"))
        self.secret = cfg_mod.load_secret()
        self.device_name = config["device_name"]
        self._responder: Optional[DiscoveryResponder] = None
        self.actual_port: Optional[int] = None
        self._stop_flag = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    def stop(self) -> None:
        """Ask a running serve_forever() loop to shut down (from any thread)."""
        self._stop_flag.set()

    def _log(self, msg: str, *, err: bool = False) -> None:
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
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, int(self.config["port"])))
        listener.listen(8)
        listener.settimeout(0.5)  # periodic wake-up to check the stop flag
        self.actual_port = listener.getsockname()[1]

        if self.config.get("discovery_enabled", True):
            self._responder = DiscoveryResponder(
                self.device_name, self.actual_port,
                int(self.config["discovery_port"]), server_fpr,
            )
            try:
                self._responder.start()
            except OSError as exc:
                self._log(f"  (discovery disabled: {exc})", err=True)
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
                self._handle_one(ctx, raw_sock, addr, server_fpr)
        finally:
            if self._responder:
                self._responder.stop()
            listener.close()

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
            self._log(f"  Rejected non-LAN connection from {peer_ip}", err=True)
            raw_sock.close()
            return

        tls: Optional[ssl.SSLSocket] = None
        try:
            raw_sock.settimeout(_CONTROL_TIMEOUT)
            tls = ctx.wrap_socket(raw_sock, server_side=True)
            assert self.secret is not None
            server_authenticate(tls, self.secret, server_fpr)

            hello = recv_msg(tls)
            if hello.get("type") != "hello":
                raise ProtocolError("expected hello")
            peer_name = str(hello.get("device_name", "unknown"))[:64]
            send_msg(tls, {
                "type": "hello",
                "device_name": self.device_name,
                "protocol": PROTOCOL_VERSION,
            })

            self._session(tls, peer_ip, peer_name)

        except AuthError as exc:
            self._log(f"  Auth failed from {peer_ip}: {exc}", err=True)
            _safe_send(tls, {"type": "error", "error": "authentication failed"})
        except (ProtocolError, ssl.SSLError, OSError) as exc:
            self._log(f"  Connection from {peer_ip} ended: {exc}", err=True)
        finally:
            _close(tls, raw_sock)

    def _session(self, tls: ssl.SSLSocket, peer_ip: str, peer_name: str) -> None:
        """Handle one or more file offers on an authenticated connection."""
        while True:
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

        info = {
            "peer_name": peer_name,
            "peer_ip": peer_ip,
            "raw_name": raw_name,
            "safe_name": safe_name,
            "size": int(size),
            "download_dir": str(self.download_dir),
        }
        try:
            accepted = self.approval(info)
        except KeyboardInterrupt:
            accepted = False

        if not accepted:
            self._log(f"  Declined '{safe_name}' from {peer_name}")
            send_msg(tls, {"type": "decision", "accept": False, "reason": "declined by user"})
            return

        dest = resolve_safe_destination(self.download_dir, safe_name)
        send_msg(tls, {"type": "decision", "accept": True, "stored_as": dest.name})
        self._receive_file(tls, dest, int(size), declared_sha, peer_name)

    def _receive_file(self, tls: ssl.SSLSocket, dest: Path, size: int,
                      declared_sha: Any, peer_name: str) -> None:
        tmp = partial_path(dest)
        hasher = hashlib.sha256()
        received = 0
        tls.settimeout(_DATA_TIMEOUT)
        try:
            with open(tmp, "wb") as fh:
                while received < size:
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
                if actual_sha.lower() != declared_sha.lower():
                    raise ProtocolError("sha256 mismatch -- file corrupted in transit")

            os.replace(tmp, dest)
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
            _safe_send(tls, {"type": "result", "ok": False, "error": str(exc)})
            raise
        finally:
            tls.settimeout(_CONTROL_TIMEOUT)


def _safe_send(tls: Optional[ssl.SSLSocket], obj: Dict[str, Any]) -> None:
    if tls is None:
        return
    try:
        send_msg(tls, obj)
    except OSError:
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
