"""A loopback self-test: start a receiver on 127.0.0.1 and send a file to it.

This exercises the full stack -- TLS, authentication, approval, safe writing
and integrity verification -- without needing a second machine. It uses a
temporary, throwaway config directory so it never touches real settings.
"""

from __future__ import annotations

import os
import secrets
import socket
import tempfile
import threading
from pathlib import Path


def _serve_one_connection(receiver, ready_evt, errbox) -> None:
    """Bind an ephemeral port, accept exactly one connection, handle it."""
    from . import identity
    from .tlsctx import server_context

    try:
        key_path, cert_path = identity.ensure_identity(receiver.device_name)
        server_fpr = identity.own_fingerprint() or ""
        ctx = server_context(cert_path, key_path)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        receiver.actual_port = listener.getsockname()[1]
        ready_evt.set()

        listener.settimeout(20.0)
        raw, addr = listener.accept()
        receiver._handle_one(ctx, raw, addr, server_fpr)  # noqa: SLF001
        listener.close()
    except Exception as exc:  # noqa: BLE001
        errbox["error"] = exc
        ready_evt.set()


def run_selftest() -> int:
    """Run a throwaway loopback transfer. Returns 0 on success.

    The temporary config directory is applied by swapping ``LANSHARE_HOME`` and
    is always restored before returning -- leaking it would silently repoint the
    whole process (notably a long-lived GUI) at the throwaway directory.
    """
    previous_home = os.environ.get("LANSHARE_HOME")
    try:
        return _run_selftest_inner()
    finally:
        if previous_home is None:
            os.environ.pop("LANSHARE_HOME", None)
        else:
            os.environ["LANSHARE_HOME"] = previous_home


def _run_selftest_inner() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="lanshare-selftest-"))
    os.environ["LANSHARE_HOME"] = str(tmp / "cfg")
    download_dir = tmp / "downloads"
    download_dir.mkdir(parents=True)

    # Import *after* LANSHARE_HOME is set so config paths pick it up.
    from . import config as cfg_mod
    from . import identity
    from .receiver import Receiver
    from .sender import send_files

    # Random, never a fixed constant: a hardcoded value published in the source
    # would be an authentication bypass for anyone who read it, should this
    # config directory ever be used for real.
    secret = secrets.token_urlsafe(24)
    cfg_mod.save_secret(secret)
    cfg = cfg_mod.load_config()
    cfg["device_name"] = "selftest-receiver"
    cfg["download_dir"] = str(download_dir)
    cfg["discovery_enabled"] = False
    cfg_mod.save_config(cfg)
    identity.ensure_identity(cfg["device_name"])

    payload = os.urandom(3 * 1024 * 1024 + 12345)
    src = tmp / "hello world.bin"
    src.write_bytes(payload)

    receiver = Receiver(cfg, approval=lambda info: True, bind_host="127.0.0.1")

    ready = threading.Event()
    errbox: dict = {}
    t = threading.Thread(
        target=_serve_one_connection, args=(receiver, ready, errbox), daemon=True
    )
    t.start()
    if not ready.wait(timeout=10):
        print("SELFTEST FAILED: receiver did not start")
        return 1
    if "error" in errbox:
        print(f"SELFTEST FAILED: receiver error: {errbox['error']}")
        return 1

    port = int(receiver.actual_port)
    print(f"  Receiver up on 127.0.0.1:{port}; sending test file...")
    try:
        results = send_files(
            "127.0.0.1", port, [str(src)],
            secret=secret.encode(), device_name="selftest-sender",
            interactive=False, show_progress=False,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"SELFTEST FAILED: send raised: {exc}")
        return 1

    t.join(timeout=10)

    if not results or not results[0].get("sent"):
        print(f"SELFTEST FAILED: file not sent: {results}")
        return 1
    stored = download_dir / results[0]["stored_as"]
    if not stored.exists():
        print(f"SELFTEST FAILED: stored file missing: {stored}")
        return 1
    if stored.read_bytes() != payload:
        print("SELFTEST FAILED: received bytes differ from source")
        return 1

    print(f"  Verified {stored.name}: {stored.stat().st_size} bytes, contents match.")
    print("SELFTEST PASSED")
    return 0
