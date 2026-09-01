"""Tests for LANShare. Runs under pytest, or standalone: python tests/test_lanshare.py

The tests use a temporary LANSHARE_HOME so they never touch real config.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

# Make the package importable when run standalone.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolate config before importing anything that resolves config paths.
_TMP_HOME = tempfile.mkdtemp(prefix="lanshare-test-home-")
os.environ.setdefault("LANSHARE_HOME", _TMP_HOME)

from lanshare import auth, netutil, safety  # noqa: E402
from lanshare.safety import UnsafeFileError  # noqa: E402


# --- filename sanitization -------------------------------------------------

def test_sanitize_strips_paths_and_traversal():
    assert safety.sanitize_filename("report.pdf") == "report.pdf"
    assert safety.sanitize_filename("/etc/passwd") == "passwd"
    assert safety.sanitize_filename(r"C:\Windows\system32\evil.dll") == "evil.dll"
    assert safety.sanitize_filename("../../secret.txt") == "secret.txt"
    assert safety.sanitize_filename("a/b/c/deep.txt") == "deep.txt"


def test_sanitize_rejects_pure_traversal():
    for bad in ["..", ".", "", "   ", "...", "/", "\\"]:
        try:
            safety.sanitize_filename(bad)
            assert False, f"expected rejection for {bad!r}"
        except UnsafeFileError:
            pass


def test_sanitize_control_chars_and_illegal():
    assert "\x00" not in safety.sanitize_filename("foo\x00bar.txt")
    out = safety.sanitize_filename('na<>me:"?.txt')
    for ch in '<>:"?':
        assert ch not in out


def test_sanitize_windows_reserved():
    assert safety.sanitize_filename("CON").startswith("_")
    assert safety.sanitize_filename("con.txt").startswith("_")
    assert safety.sanitize_filename("LPT1.dat").startswith("_")


def test_sanitize_length_cap():
    name = "a" * 5000 + ".txt"
    out = safety.sanitize_filename(name)
    assert len(out) <= safety.MAX_NAME_LEN
    assert out.endswith(".txt")


# --- destination safety ----------------------------------------------------

def test_resolve_destination_contained_and_collision(tmp_path=None):
    d = Path(tempfile.mkdtemp(prefix="lanshare-dl-"))
    p1 = safety.resolve_safe_destination(d, "file.txt")
    assert p1.parent == d.resolve()
    p1.write_bytes(b"x")
    p2 = safety.resolve_safe_destination(d, "file.txt")
    assert p2 != p1
    assert p2.name == "file (1).txt"


def test_validate_size():
    safety.validate_size(0, 100)
    safety.validate_size(100, 100)
    for bad in [-1, 101]:
        try:
            safety.validate_size(bad, 100)
            assert False
        except UnsafeFileError:
            pass
    try:
        safety.validate_size(True, 100)  # bool is not a valid size
        assert False
    except UnsafeFileError:
        pass


# --- LAN restriction -------------------------------------------------------

def test_is_lan_address():
    for good in ["127.0.0.1", "192.168.1.5", "10.0.0.3", "172.16.4.4",
                 "169.254.1.1", "::1", "fc00::1"]:
        assert netutil.is_lan_address(good), good
    for bad in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2607:f8b0::1", "notanip"]:
        assert not netutil.is_lan_address(bad), bad


# --- authentication handshake ---------------------------------------------

def _run_auth(server_secret: bytes, client_secret: bytes, fpr: str = "abc123"):
    a, b = socket.socketpair()
    server_err = {}
    client_err = {}

    def server():
        try:
            auth.server_authenticate(a, server_secret, fpr)
        except Exception as exc:  # noqa: BLE001
            server_err["e"] = exc
        finally:
            a.close()

    def client():
        try:
            auth.client_authenticate(b, client_secret, fpr)
        except Exception as exc:  # noqa: BLE001
            client_err["e"] = exc
        finally:
            b.close()

    ts = threading.Thread(target=server)
    tc = threading.Thread(target=client)
    ts.start(); tc.start(); ts.join(5); tc.join(5)
    return server_err.get("e"), client_err.get("e")


def test_auth_success_with_matching_secret():
    se, ce = _run_auth(b"same-secret", b"same-secret")
    assert se is None, se
    assert ce is None, ce


def test_auth_fails_with_wrong_secret():
    se, ce = _run_auth(b"server-secret", b"different-secret")
    # Server must reject the client's bad MAC.
    assert isinstance(se, auth.AuthError)


def test_auth_channel_binding_detects_fpr_mismatch():
    # Same secret but the two ends believe in different certificate fingerprints,
    # which is exactly what a MITM would cause. Auth must fail.
    a, b = socket.socketpair()
    server_err = {}

    def server():
        try:
            auth.server_authenticate(a, b"secret", "server-real-fpr")
        except Exception as exc:  # noqa: BLE001
            server_err["e"] = exc
        finally:
            a.close()

    def client():
        try:
            auth.client_authenticate(b, b"secret", "attacker-fpr")
        except Exception:  # noqa: BLE001
            pass
        finally:
            b.close()

    ts = threading.Thread(target=server); tc = threading.Thread(target=client)
    ts.start(); tc.start(); ts.join(5); tc.join(5)
    assert isinstance(server_err.get("e"), auth.AuthError)


# --- full round trip -------------------------------------------------------

def _run_receiver_once(receiver, ready, errbox):
    from lanshare import identity
    from lanshare.tlsctx import server_context

    try:
        key_path, cert_path = identity.ensure_identity(receiver.device_name)
        server_fpr = identity.own_fingerprint() or ""
        ctx = server_context(cert_path, key_path)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        receiver.actual_port = listener.getsockname()[1]
        ready.set()
        listener.settimeout(20.0)
        raw, addr = listener.accept()
        receiver._handle_one(ctx, raw, addr, server_fpr)
        listener.close()
    except Exception as exc:  # noqa: BLE001
        errbox["e"] = exc
        ready.set()


def _do_transfer(approval, files, secret_recv="round-trip-secret",
                 secret_send="round-trip-secret"):
    from lanshare import config as cfg_mod
    from lanshare import identity
    from lanshare.receiver import Receiver
    from lanshare.sender import send_files

    workdir = Path(tempfile.mkdtemp(prefix="lanshare-rt-"))
    dl = workdir / "dl"; dl.mkdir()
    cfg_mod.save_secret(secret_recv)
    cfg = cfg_mod.load_config()
    cfg["device_name"] = "rt-receiver"
    cfg["download_dir"] = str(dl)
    cfg["discovery_enabled"] = False
    cfg["max_file_bytes"] = 10 * 1024 * 1024
    cfg_mod.save_config(cfg)
    identity.ensure_identity(cfg["device_name"])

    receiver = Receiver(cfg, approval=approval, bind_host="127.0.0.1")
    ready = threading.Event(); errbox = {}
    t = threading.Thread(target=_run_receiver_once, args=(receiver, ready, errbox),
                         daemon=True)
    t.start()
    assert ready.wait(10)
    results = None
    err = None
    try:
        results = send_files("127.0.0.1", int(receiver.actual_port), files,
                             secret=secret_send.encode(), device_name="rt-sender",
                             interactive=False, show_progress=False)
    except Exception as exc:  # noqa: BLE001
        err = exc
    t.join(10)
    return dl, results, err, errbox.get("e")


def test_round_trip_accept():
    workdir = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    src = workdir / "photo.bin"
    payload = os.urandom(1024 * 512 + 7)
    src.write_bytes(payload)
    dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)])
    assert err is None, err
    assert results and results[0]["sent"]
    stored = dl / results[0]["stored_as"]
    assert stored.read_bytes() == payload


def test_round_trip_decline():
    workdir = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    src = workdir / "photo.bin"
    src.write_bytes(b"data")
    dl, results, err, rerr = _do_transfer(lambda info: False, [str(src)])
    assert err is None
    assert results and results[0]["sent"] is False
    assert not any(dl.iterdir())  # nothing written


def test_round_trip_wrong_secret_fails():
    workdir = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    src = workdir / "photo.bin"
    src.write_bytes(b"data")
    dl, results, err, rerr = _do_transfer(
        lambda info: True, [str(src)],
        secret_recv="correct-secret", secret_send="wrong-secret")
    assert err is not None  # sender should see an auth failure
    assert not any(dl.iterdir())


def _main():
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            import traceback
            print(f"FAIL {fn.__name__}: {exc}")
            traceback.print_exc()
    print(f"\n{len(funcs) - failures}/{len(funcs)} tests passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_main())
