"""Tests for LANShare. Runs under pytest, or standalone: python tests/test_lanshare.py

The tests use a temporary LANSHARE_HOME so they never touch real config.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading
import time
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
    assert safety.sanitize_filename("../../secret.txt") == "secret.txt"
    assert safety.sanitize_filename("a/b/c/deep.txt") == "deep.txt"
    # A backslash is escaped rather than split on, so a Windows-looking path is
    # flattened instead of reduced to its last component. Either way no
    # separator survives -- and the behaviour is identical on both platforms.
    out = safety.sanitize_filename(r"C:\Windows\system32\evil.dll")
    assert "/" not in out and "\\" not in out
    assert out.endswith("evil.dll"), out


def test_sanitize_rejects_pure_traversal():
    for bad in ["..", ".", "", "   ", "...", "/"]:
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

def test_reserve_destination_contained_and_collision(tmp_path=None):
    d = Path(tempfile.mkdtemp(prefix="lanshare-dl-"))
    p1 = safety.reserve_destination(d, "file.txt")
    assert p1.parent == d.resolve()
    assert p1.exists(), "reservation must actually claim the name on disk"
    p1.write_bytes(b"x")
    p2 = safety.reserve_destination(d, "file.txt")
    assert p2 != p1
    assert p2.name == "file (1).txt"


def test_reserve_destination_is_atomic_under_concurrency():
    """Two racing receivers must never be handed the same path."""
    d = Path(tempfile.mkdtemp(prefix="lanshare-race-"))
    handed_out = []
    lock = threading.Lock()

    def claim():
        p = safety.reserve_destination(d, "same.bin")
        with lock:
            handed_out.append(p)

    threads = [threading.Thread(target=claim) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(handed_out) == 12
    assert len(set(handed_out)) == 12, "duplicate destination handed to two callers"


def test_sanitize_strips_bidi_and_invisible_characters():
    """U+202E makes 'gnp.exe' render as 'exe.png' - a spoofed approval prompt."""
    out = safety.sanitize_filename("‮gnp.exe")
    assert "‮" not in out
    assert out == "gnp.exe"
    for sneaky in ("​", "‎", "⁦", "﻿", "؜"):
        assert sneaky not in safety.sanitize_filename(f"a{sneaky}b.txt")


def test_sanitize_preserves_dotfiles_and_backslash_names():
    # A leading dot is legal and meaningful; it must survive.
    assert safety.sanitize_filename(".bashrc") == ".bashrc"
    assert safety.sanitize_filename(".gitignore") == ".gitignore"
    # A backslash is an ordinary character on POSIX, so the name must not be
    # truncated at it -- and it must not act as a separator on Windows either.
    # Same result on both platforms.
    assert safety.sanitize_filename("back\\slash.txt") == "back_slash.txt"
    # Traversal-looking names are still neutralised.
    escaped = safety.sanitize_filename("..\\..\\evil.txt")
    assert "\\" not in escaped and "/" not in escaped and escaped.endswith("evil.txt")
    for bad in ("..", ".", "...", ""):
        try:
            safety.sanitize_filename(bad)
            assert False, f"expected rejection for {bad!r}"
        except UnsafeFileError:
            pass


def test_sanitize_display_text_neutralises_markup_and_controls():
    out = safety.sanitize_display_text("<b>trusted</b>‮foo\x00")
    assert "‮" not in out and "\x00" not in out
    # Markup is *kept as literal text* - the GUI renders plain text - but it
    # must never contain characters that reorder or hide what follows.
    assert "<b>" in out


def test_parse_size_rejects_negative_and_junk():
    assert safety.parse_size("10GiB") == 10 * 1024 ** 3
    for bad in ("-5G", "abc", ""):
        try:
            safety.parse_size(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass


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

def test_interface_probe_finds_real_prefixes():
    """The OS probe must work on this platform and report real prefix lengths.

    Regression: the Windows path passed GAA_FLAG_SKIP_UNICAST by mistake, so it
    silently returned nothing and fell back to assuming /24 for every address --
    which wrongly refuses peers on a /16 or /20 network.
    """
    from lanshare import localnet

    probe = localnet._windows_networks if os.name == "nt" else localnet._posix_networks
    nets = probe()
    assert nets, f"{probe.__name__} returned nothing; the fallback would hide real prefixes"
    assert any(n.prefixlen != 24 for n in nets), \
        "every prefix is /24, which suggests the /24 fallback rather than a real probe"


def test_local_networks_contain_our_own_address():
    from lanshare import localnet
    from lanshare.netutil import local_ipv4_addresses

    nets = localnet.local_ipv4_networks(force=True)
    assert nets
    mine = [ipaddress.ip_address(a) for a in local_ipv4_addresses()]
    assert any(a in n for a in mine for n in nets), \
        "none of our own addresses fall inside the detected local networks"


def test_lan_check_accepts_our_network_even_outside_rfc1918():
    """A real home Wi-Fi handed out 172.1.140.16/16 -- public space. Refusing it
    made the whole app unusable on that network."""
    from lanshare import localnet, netutil

    real = localnet.local_ipv4_networks
    localnet.local_ipv4_networks = lambda force=False: [
        ipaddress.ip_network("172.1.0.0/16")
    ]
    try:
        assert not ipaddress.ip_address("172.1.140.16").is_private  # public space
        assert netutil.is_lan_address("172.1.140.16")   # ...but it is our network
        assert netutil.is_lan_address("172.1.55.9")     # elsewhere on the same /16
        # Still rejects the genuinely remote internet.
        assert not netutil.is_lan_address("8.8.8.8")
        assert not netutil.is_lan_address("93.184.216.34")
        assert not netutil.is_lan_address("172.2.0.1")  # adjacent /16 we're not on
    finally:
        localnet.local_ipv4_networks = real


def test_extra_local_networks_escape_hatch():
    from lanshare import config as cfg_mod
    from lanshare import localnet, netutil

    real = localnet.local_ipv4_networks
    localnet.local_ipv4_networks = lambda force=False: []
    cfg = cfg_mod.load_config()
    try:
        assert not netutil.is_lan_address("100.64.5.5")
        cfg_mod.save_config({**cfg, "extra_local_networks": ["100.64.0.0/10"]})
        assert netutil.is_lan_address("100.64.5.5")
        assert not netutil.is_lan_address("8.8.8.8")
    finally:
        localnet.local_ipv4_networks = real
        cfg_mod.save_config(cfg)


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
                 secret_send="round-trip-secret",
                 max_file_bytes=10 * 1024 * 1024):
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
    cfg["max_file_bytes"] = max_file_bytes
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


def _expect_unsafe(fn, *args):
    try:
        fn(*args)
        assert False, f"expected rejection for {args!r}"
    except UnsafeFileError:
        pass


def test_sanitize_relpath_accepts_a_tree_and_refuses_traversal():
    assert safety.sanitize_relpath("photos/2024/beach.jpg") == "photos/2024/beach.jpg"
    # Redundant separators and "." components collapse away.
    assert safety.sanitize_relpath("a//./b.txt") == "a/b.txt"
    # A leading slash is not an absolute path once the empty component is gone.
    assert safety.sanitize_relpath("/a/b.txt") == "a/b.txt"
    # Every component still goes through the single-name rules.
    assert safety.sanitize_relpath('a/na<>me:"?.txt') == "a/na__me___.txt"
    for bad in ["..", "../x", "a/../../b", "a/..", "photos/../../etc/passwd",
                "/", "", "."]:
        _expect_unsafe(safety.sanitize_relpath, bad)
    _expect_unsafe(safety.sanitize_relpath,
                   "/".join(["a"] * (safety.MAX_RELPATH_DEPTH + 1)))
    _expect_unsafe(safety.sanitize_relpath, "x" * (safety.MAX_RELPATH_LEN + 1))


def test_reserve_batch_root_deduplicates_the_folder_name():
    d = Path(tempfile.mkdtemp())
    first = safety.reserve_batch_root(d, "photos")
    second = safety.reserve_batch_root(d, "photos")
    assert first.name == "photos" and second.name == "photos (1)"
    assert first.is_dir() and second.is_dir()


def test_reserve_destination_at_creates_the_tree_and_avoids_collisions():
    d = Path(tempfile.mkdtemp())
    root = safety.reserve_batch_root(d, "photos")
    first = safety.reserve_destination_at(root, "2024/beach.jpg")
    assert first.relative_to(root) == Path("2024/beach.jpg")
    assert first.exists()
    second = safety.reserve_destination_at(root, "2024/beach.jpg")
    assert second.name == "beach (1).jpg"


def test_reserve_destination_at_refuses_a_symlinked_subdirectory():
    """A subdirectory that is really a link out must not be written through."""
    d = Path(tempfile.mkdtemp())
    outside = Path(tempfile.mkdtemp())
    root = safety.reserve_batch_root(d, "photos")
    try:
        os.symlink(outside, root / "escape", target_is_directory=True)
    except (OSError, AttributeError, NotImplementedError) as exc:
        # Windows refuses this without the right privilege; nothing to test.
        print(f"  (skipped: cannot create a symlink here: {exc})")
        return
    _expect_unsafe(safety.reserve_destination_at, root, "escape/evil.txt")
    assert not (outside / "evil.txt").exists()

    # Second layer: a planted symlink named like the incoming file itself is
    # caught when the final destination is resolved, not written through.
    os.symlink(outside / "target.txt", root / "leaf.txt")
    _expect_unsafe(safety.reserve_destination_at, root, "leaf.txt")
    assert list(outside.iterdir()) == []


def _make_tree(root: Path):
    """A small nested tree, returned as {relative path: bytes}."""
    files = {
        "top.txt": b"top-level",
        "2024/beach.jpg": os.urandom(2048),
        "2024/raw/IMG_1.dng": os.urandom(4096),
        "notes/.hidden": b"dotfile survives",
    }
    for rel, payload in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return files


def _folder_to_send():
    parent = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    folder = parent / "photos"
    folder.mkdir()
    return folder, _make_tree(folder)


def test_round_trip_folder_is_one_approval_and_keeps_its_tree():
    folder, files = _folder_to_send()
    prompts = []

    def approval(info):
        prompts.append(info)
        return True

    dl, results, err, rerr = _do_transfer(approval, [str(folder)])
    assert err is None, err
    assert rerr is None, rerr

    # One prompt for the whole folder, not one per file.
    assert len(prompts) == 1
    assert prompts[0]["kind"] == "folder"
    assert prompts[0]["safe_name"] == "photos"
    assert prompts[0]["count"] == len(files)
    assert prompts[0]["size"] == sum(len(v) for v in files.values())

    assert results and all(r["sent"] for r in results)
    # Every file landed at its original relative path, with its content intact.
    stored_root = dl / "photos"
    for rel, payload in files.items():
        assert (stored_root / rel).read_bytes() == payload
    # ...and nothing was scattered into the download root itself.
    assert [p.name for p in dl.iterdir()] == ["photos"]
    # Results (and so history) name files by their path inside the folder.
    assert {r["name"] for r in results} == {f"photos/{rel}" for rel in files}


def test_folder_transfer_records_every_file_in_history():
    """Buffered history writes must all be flushed, with folder-relative names."""
    from lanshare import history

    folder, files = _folder_to_send()
    history.clear()
    dl, results, err, rerr = _do_transfer(lambda info: True, [str(folder)])
    assert err is None, err

    records = history.load(limit=10_000)
    received = {r.name for r in records if r.direction == history.RECEIVED}
    sent = {r.name for r in records if r.direction == history.SENT}
    expected = {f"photos/{rel}" for rel in files}
    assert received == expected, received
    assert sent == expected, sent
    # A received record points at the file that actually landed.
    for rec in records:
        if rec.direction == history.RECEIVED:
            assert rec.status == history.OK
            assert rec.path and Path(rec.path).exists()
    history.clear()


def test_round_trip_folder_declined_writes_nothing():
    folder, files = _folder_to_send()
    prompts = []

    def approval(info):
        prompts.append(info)
        return False

    dl, results, err, rerr = _do_transfer(approval, [str(folder)])
    assert err is None, err
    # Declined once for the folder; the files inside are never asked about.
    assert len(prompts) == 1
    assert results and not any(r["sent"] for r in results)
    assert len(results) == len(files)
    assert not any(dl.iterdir())


def test_folder_send_refused_against_an_older_receiver():
    """A protocol-1 receiver can only take flat files, so say so up front."""
    import lanshare.receiver as receiver_mod
    import lanshare.sender as sender_mod

    folder, _files = _folder_to_send()
    original = receiver_mod.PROTOCOL_VERSION
    try:
        receiver_mod.PROTOCOL_VERSION = 1
        dl, results, err, rerr = _do_transfer(lambda info: True, [str(folder)])
    finally:
        receiver_mod.PROTOCOL_VERSION = original

    assert isinstance(err, sender_mod.SendError), err
    assert "older version" in str(err)
    assert not any(dl.iterdir())


def test_nested_offer_outside_a_batch_is_still_flattened():
    """Without an approved folder, a path in an offer is collapsed as before.

    This is what keeps the receiver's batch state -- not the sender's say-so --
    in charge of whether directories get created at all.
    """
    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "photo.bin"
    src.write_bytes(b"payload")

    import lanshare.sender as sender_mod

    real_send_msg = sender_mod.send_msg

    def sneaky_send_msg(tls, obj):
        if obj.get("type") == "offer":
            obj = dict(obj, name="../../../evil/pwned.bin")
        return real_send_msg(tls, obj)

    prompts = []

    def approval(info):
        prompts.append(info)
        return True

    try:
        sender_mod.send_msg = sneaky_send_msg
        dl, results, err, rerr = _do_transfer(approval, [str(src)])
    finally:
        sender_mod.send_msg = real_send_msg

    assert err is None, err
    # Prompted as a plain file with the traversal stripped, and written flat.
    assert len(prompts) == 1 and prompts[0]["kind"] == "file"
    assert prompts[0]["safe_name"] == "pwned.bin"
    assert [p.name for p in dl.iterdir()] == ["pwned.bin"]
    assert (dl / "pwned.bin").read_bytes() == b"payload"


def test_round_trip_large_file_uses_the_streaming_path():
    """Files above the inline threshold are hashed and sent by streaming.

    Small files are read once into memory; larger ones take a separate code
    path that reads in chunks, so both need to be exercised byte for byte.
    """
    from lanshare import sender as sender_mod

    workdir = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    src = workdir / "big.bin"
    size = sender_mod._INLINE_MAX + 3 * 1024 * 1024 + 517
    payload = os.urandom(size)
    src.write_bytes(payload)
    assert src.stat().st_size > sender_mod._INLINE_MAX  # really the other path

    dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)],
                                          max_file_bytes=64 * 1024 * 1024)
    assert err is None, err
    assert results and results[0]["sent"], results
    stored = dl / results[0]["stored_as"]
    assert stored.stat().st_size == size
    assert stored.read_bytes() == payload


def test_rejection_reason_does_not_leak_the_size_limit():
    """A peer learns that its file was too big, not what this device's cap is."""
    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "big.bin"
    src.write_bytes(b"x" * 4096)

    dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)],
                                          max_file_bytes=1024)
    assert err is None, err
    assert results and results[0]["sent"] is False
    reason = results[0]["reason"]
    # No byte counts of any kind: the configured ceiling is this device's
    # business, and the sender only needs to know the file was refused.
    assert not any(ch.isdigit() for ch in reason), reason
    assert "1024" not in reason
    assert str(dl) not in reason
    assert not any(dl.iterdir())


def test_rejection_reason_does_not_leak_free_disk_space():
    """The free-space check must not report this device's disk to the peer.

    Any paired peer could otherwise read the exact number of free bytes off
    this machine by offering an impossibly large file -- and that is refused
    before the prompt, so the user would never even see it happen.
    """
    import lanshare.receiver as receiver_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "a.bin"
    src.write_bytes(b"x" * 512)

    real_check = receiver_mod.check_free_space
    secret_number = "24479604736"

    def fake_check(download_dir, size):
        raise receiver_mod.UnsafeFileError(
            f"not enough free space: need {size} bytes, "
            f"{secret_number} available")

    try:
        receiver_mod.check_free_space = fake_check
        dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)])
    finally:
        receiver_mod.check_free_space = real_check

    assert err is None, err
    assert results and results[0]["sent"] is False
    reason = results[0]["reason"]
    assert secret_number not in reason, reason
    assert not any(ch.isdigit() for ch in reason), reason
    assert not any(dl.iterdir())


def test_history_file_is_owner_only_on_posix():
    """History names your peers, their addresses and where files landed."""
    import stat as stat_mod

    from lanshare import history

    history.clear()
    history.record_sent("secret-plans.pdf", 10, "Peer", "192.168.1.9")
    path = history.history_path()
    assert path.exists()
    if os.name != "nt":   # Windows inherits the per-user profile ACL instead
        mode = stat_mod.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, oct(mode)
    history.clear()


def test_nothing_on_the_wire_carries_a_local_path():
    """Only names relative to what was selected are sent, never local paths.

    The peer is told "photos/2024/beach.jpg", never
    "C:/Users/someone/private/photos/2024/beach.jpg" -- so the transfer does
    not disclose the sender's directory layout, user name or home directory.
    """
    import lanshare.sender as sender_mod

    parent = Path(tempfile.mkdtemp(prefix="lanshare-private-dir-"))
    folder = parent / "photos"
    folder.mkdir()
    files = _make_tree(folder)

    seen = []
    real_send_msg = sender_mod.send_msg

    def recording_send_msg(tls, obj):
        seen.append(obj)
        return real_send_msg(tls, obj)

    try:
        sender_mod.send_msg = recording_send_msg
        dl, results, err, rerr = _do_transfer(lambda info: True, [str(folder)])
    finally:
        sender_mod.send_msg = real_send_msg

    assert err is None, err
    assert seen, "no control messages were captured"
    blob = json.dumps(seen)
    assert str(parent) not in blob
    assert str(folder) not in blob
    assert str(Path.home()) not in blob
    # The names that *are* sent are relative to the selected folder.
    offered = {m["name"] for m in seen if m.get("type") == "offer"}
    assert offered == set(files), offered
    for name in offered:
        assert not Path(name).is_absolute()


def test_offer_without_a_checksum_is_refused():
    """A file is reported as received only once its checksum is verified.

    Accepting an offer that carries no sha256 would store it and log it as
    "ok" having been verified against nothing at all.
    """
    import lanshare.sender as sender_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "payload.bin"
    src.write_bytes(b"REAL-CONTENT" * 100)

    real_send_msg = sender_mod.send_msg

    def strip_sha(tls, obj):
        if obj.get("type") == "offer":
            obj = {k: v for k, v in obj.items() if k != "sha256"}
        return real_send_msg(tls, obj)

    try:
        sender_mod.send_msg = strip_sha
        dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)])
    finally:
        sender_mod.send_msg = real_send_msg

    assert results and results[0]["sent"] is False, results
    assert "checksum" in results[0]["reason"], results[0]["reason"]
    assert not any(dl.iterdir())


def test_offer_with_a_malformed_checksum_is_refused():
    import lanshare.sender as sender_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "payload.bin"
    src.write_bytes(b"data" * 100)

    real_send_msg = sender_mod.send_msg

    for bogus in ("not-a-hash", "", "AA" * 31, None, 12345):
        def bad_sha(tls, obj, bogus=bogus):
            if obj.get("type") == "offer":
                obj = dict(obj, sha256=bogus)
            return real_send_msg(tls, obj)

        try:
            sender_mod.send_msg = bad_sha
            dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)])
        finally:
            sender_mod.send_msg = real_send_msg
        assert results and results[0]["sent"] is False, (bogus, results)
        assert not any(dl.iterdir()), bogus


def test_a_long_hash_does_not_look_like_a_stalled_sender():
    """Hashing happens before the offer, while the receiver waits on recv_msg.

    A big file on a slow disk can take longer than the receiver's control
    timeout, which used to drop the connection mid-transfer. The sender says
    it is still working instead.
    """
    import lanshare.receiver as receiver_mod
    import lanshare.sender as sender_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "big-video.bin"
    src.write_bytes(b"z" * 4096)

    real_timeout = receiver_mod._CONTROL_TIMEOUT
    real_sha = sender_mod._sha256_file
    real_inline = sender_mod._INLINE_MAX

    def slow_sha(path, display, progress_cb, cancel_event, keepalive=None):
        waited = 0.0
        while waited < 3.0:            # longer than the receiver will wait
            time.sleep(0.25)
            waited += 0.25
            if keepalive is not None:
                keepalive()
        return real_sha(path, display, progress_cb, cancel_event)

    try:
        receiver_mod._CONTROL_TIMEOUT = 1.5
        sender_mod._sha256_file = slow_sha
        sender_mod._INLINE_MAX = 0      # force the streaming (hash-first) path
        dl, results, err, rerr = _do_transfer(lambda info: True, [str(src)])
    finally:
        receiver_mod._CONTROL_TIMEOUT = real_timeout
        sender_mod._sha256_file = real_sha
        sender_mod._INLINE_MAX = real_inline

    assert err is None, err
    assert results and results[0]["sent"], results
    assert (dl / "big-video.bin").read_bytes() == b"z" * 4096


def test_the_real_hash_loop_emits_keepalives():
    """The scaled-down test above stubs the hash; this checks the real loop."""
    import lanshare.sender as sender_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "big.bin"
    src.write_bytes(os.urandom(4 * 1024 * 1024))

    pings = []
    real_interval = sender_mod._KEEPALIVE_SECONDS
    real_chunk = sender_mod._CHUNK
    try:
        sender_mod._KEEPALIVE_SECONDS = 0.0    # ping at every opportunity
        sender_mod._CHUNK = 64 * 1024          # so there are several
        digest = sender_mod._sha256_file(src, "big.bin", None, None,
                                         lambda: pings.append(1))
    finally:
        sender_mod._KEEPALIVE_SECONDS = real_interval
        sender_mod._CHUNK = real_chunk

    assert pings, "the hash loop never signalled that it was still working"
    assert digest == hashlib.sha256(src.read_bytes()).hexdigest()


def test_sender_reports_a_silent_receiver_clearly():
    """No answer to an offer is a plain message, not a raw socket error."""
    import lanshare.sender as sender_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "a.bin"
    src.write_bytes(b"x" * 64)

    def never_answer(info):
        time.sleep(2.0)               # longer than the shortened wait below
        return False

    real_decision_timeout = sender_mod._DECISION_TIMEOUT
    try:
        sender_mod._DECISION_TIMEOUT = 0.5
        dl, results, err, rerr = _do_transfer(never_answer, [str(src)])
    finally:
        sender_mod._DECISION_TIMEOUT = real_decision_timeout

    assert isinstance(err, sender_mod.SendError), err
    assert "did not answer in time" in str(err), err


def test_a_hostile_reason_cannot_smuggle_control_characters():
    """Whatever the far end says is display text, and is treated as such."""
    import lanshare.receiver as receiver_mod

    src = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "a.bin"
    src.write_bytes(b"x" * 64)

    nasty = "\u202eDECLINED\x00" + "A" * 500
    real_send_msg = receiver_mod.send_msg

    def rude_decision(tls, obj):
        if obj.get("type") == "decision":
            obj = dict(obj, accept=False, reason=nasty)
        return real_send_msg(tls, obj)

    try:
        receiver_mod.send_msg = rude_decision
        dl, results, err, rerr = _do_transfer(lambda info: False, [str(src)])
    finally:
        receiver_mod.send_msg = real_send_msg

    reason = results[0]["reason"]
    assert "\u202e" not in reason and "\x00" not in reason, repr(reason)
    assert len(reason) <= 121, len(reason)


def test_an_empty_folder_does_not_abandon_everything_else():
    parent = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    (parent / "empty").mkdir()
    good = parent / "photos"
    good.mkdir()
    files = _make_tree(good)

    dl, results, err, rerr = _do_transfer(
        lambda info: True, [str(parent / "empty"), str(good)])
    assert err is None, err
    assert len(results) == len(files)
    assert all(r["sent"] for r in results)
    assert (dl / "photos").is_dir()


def test_an_empty_folder_on_its_own_says_so():
    from lanshare.sender import SendError, send_files

    empty = Path(tempfile.mkdtemp(prefix="lanshare-src-")) / "empty"
    empty.mkdir()
    try:
        send_files("127.0.0.1", 1, [str(empty)], secret=b"x" * 16,
                   device_name="t", interactive=False, show_progress=False,
                   log_cb=lambda m: None)
        assert False, "expected a SendError"
    except SendError as exc:
        assert "empty" in str(exc), exc


def test_a_folder_chosen_by_hand_is_sent_even_if_it_is_a_symlink():
    """Links inside a tree are skipped; one the user picked is what they meant."""
    parent = Path(tempfile.mkdtemp(prefix="lanshare-src-"))
    real = parent / "real-photos"
    real.mkdir()
    files = _make_tree(real)
    link = parent / "linked-photos"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, AttributeError, NotImplementedError) as exc:
        print(f"  (skipped: cannot create a symlink here: {exc})")
        return

    dl, results, err, rerr = _do_transfer(lambda info: True, [str(link)])
    assert err is None, err
    assert results and all(r["sent"] for r in results), results
    for rel in files:
        assert (dl / "linked-photos" / rel).exists()


def test_tofu_warns_when_a_known_key_claims_another_device_name():
    """A device you already trust must not silently take another one's name."""
    from lanshare import config as cfg_mod
    from lanshare import sender as sender_mod

    fpr_laptop = "aa" * 32
    fpr_printer = "bb" * 32
    cfg_mod.save_known_peers({fpr_laptop: "laptop", fpr_printer: "printer"})

    warnings = []
    prompted = []

    def confirm(peer_name, known_fpr, new_fpr):
        prompted.append((peer_name, known_fpr, new_fpr))
        return False        # user refuses

    try:
        sender_mod._check_tofu("laptop", fpr_printer, interactive=False,
                               log=warnings.append, tofu_confirm_cb=confirm)
        assert False, "expected the send to be aborted"
    except sender_mod.SendError as exc:
        assert "fingerprint change" in str(exc), exc

    assert prompted, "the user was never warned"
    assert any("NEW identity" in w for w in warnings), warnings
    cfg_mod.save_known_peers({})


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


# --- discovery must be authenticated ---------------------------------------

def test_discovery_ignores_unauthenticated_queries():
    """A device without the shared secret must learn nothing - not even that
    we exist. No reply at all (also removes the reflection amplifier)."""
    from lanshare.discovery import DiscoveryResponder

    responder = DiscoveryResponder("SecretiveBox", 51888, 0,
                                   "ab" * 32, b"the-real-secret")
    # Hand-rolled query with no MAC, and one with a wrong MAC.
    import base64
    import json as _json
    no_mac = _json.dumps({"magic": "lanshare-discovery-v2", "kind": "query",
                          "nonce": base64.b64encode(b"x" * 16).decode()}).encode()
    bad_mac = _json.dumps({"magic": "lanshare-discovery-v2", "kind": "query",
                           "nonce": base64.b64encode(b"x" * 16).decode(),
                           "mac": base64.b64encode(b"y" * 32).decode()}).encode()
    assert responder._build_reply(no_mac) is None
    assert responder._build_reply(bad_mac) is None
    assert responder._build_reply(b"not even json") is None
    # And with the right secret it does answer.
    from lanshare.discovery import _b64, _mac
    nonce = b"z" * 16
    good = _json.dumps({"magic": "lanshare-discovery-v2", "kind": "query",
                        "nonce": _b64(nonce),
                        "mac": _b64(_mac(b"the-real-secret", "query", nonce))}).encode()
    reply = responder._build_reply(good)
    assert reply is not None and b"SecretiveBox" in reply


def test_discovery_rejects_forged_replies():
    """A forged/replayed reply must not appear as a peer (lure prevention)."""
    from lanshare.discovery import _b64, _mac, _parse_reply
    import json as _json

    secret = b"shared-secret-value"
    nonce = b"n" * 16
    # Reply MAC'd with the wrong secret -> rejected.
    forged = _json.dumps({
        "magic": "lanshare-discovery-v2", "kind": "reply", "name": "Impostor",
        "port": 51888, "fpr": "cd" * 32,
        "mac": _b64(_mac(b"attacker-secret", "reply", nonce, "Impostor", 51888, "cd" * 32)),
    }).encode()
    assert _parse_reply(forged, ("192.168.1.9", 51889), secret, nonce) is None
    # Correctly MAC'd but bound to a *different* nonce -> rejected (replay).
    other = b"m" * 16
    replayed = _json.dumps({
        "magic": "lanshare-discovery-v2", "kind": "reply", "name": "Real",
        "port": 51888, "fpr": "ab" * 32,
        "mac": _b64(_mac(secret, "reply", other, "Real", 51888, "ab" * 32)),
    }).encode()
    assert _parse_reply(replayed, ("192.168.1.9", 51889), secret, nonce) is None
    # Genuine reply for our nonce -> accepted.
    good = _json.dumps({
        "magic": "lanshare-discovery-v2", "kind": "reply", "name": "Real",
        "port": 51888, "fpr": "ab" * 32,
        "mac": _b64(_mac(secret, "reply", nonce, "Real", 51888, "ab" * 32)),
    }).encode()
    peer = _parse_reply(good, ("192.168.1.9", 51889), secret, nonce)
    assert peer is not None and peer.name == "Real" and peer.port == 51888


# --- the self-test must not leak its throwaway config dir -------------------

def test_selftest_restores_lanshare_home():
    from lanshare import config as cfg_mod
    from lanshare.selftest import run_selftest

    before = os.environ.get("LANSHARE_HOME")
    cfg_mod.save_secret("a-real-user-secret-value")
    import contextlib
    import io as _io
    with contextlib.redirect_stdout(_io.StringIO()):
        rc = run_selftest()
    assert rc == 0
    assert os.environ.get("LANSHARE_HOME") == before, "self-test leaked its temp home"
    assert cfg_mod.load_secret() == b"a-real-user-secret-value", \
        "self-test clobbered the real secret"


def test_selftest_secret_is_not_a_fixed_constant():
    """A hardcoded secret in shipped source would be an auth bypass."""
    import inspect

    from lanshare import selftest as st
    src = inspect.getsource(st)
    assert "selftest-shared-secret" not in src
    assert "token_urlsafe" in src or "token_hex" in src


# --- one rude peer must not starve the receiver -----------------------------

def test_idle_connection_does_not_block_other_transfers():
    """An unauthenticated peer that connects and goes silent used to hold the
    single-threaded accept loop hostage for the full control timeout."""
    from lanshare import config as cfg_mod
    from lanshare import identity
    from lanshare.receiver import Receiver
    from lanshare.sender import send_files
    from lanshare.tlsctx import server_context

    secret = "starvation-test-secret"
    workdir = Path(tempfile.mkdtemp(prefix="lanshare-starve-"))
    dl = workdir / "dl"
    dl.mkdir()
    cfg_mod.save_secret(secret)
    cfg = cfg_mod.load_config()
    cfg["device_name"] = "starve-receiver"
    cfg["download_dir"] = str(dl)
    cfg["discovery_enabled"] = False
    cfg_mod.save_config(cfg)
    identity.ensure_identity(cfg["device_name"])

    receiver = Receiver(cfg, approval=lambda info: True, bind_host="127.0.0.1")
    ready = threading.Event()
    port_box = {}

    def serve():
        kp, cp = identity.ensure_identity(receiver.device_name)
        fpr = identity.own_fingerprint() or ""
        ctx = server_context(cp, kp)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.5)
        port_box["port"] = listener.getsockname()[1]
        ready.set()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and not receiver._stop_flag.is_set():
            try:
                s, a = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            receiver._dispatch(ctx, s, a, fpr)
        listener.close()

    threading.Thread(target=serve, daemon=True).start()
    assert ready.wait(10)
    port = port_box["port"]

    # A rude peer: TCP connected, never completes the TLS handshake.
    rude = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        src = workdir / "payload.txt"
        src.write_bytes(b"legitimate traffic")
        started = time.monotonic()
        results = send_files("127.0.0.1", port, [str(src)], secret=secret.encode(),
                             device_name="legit", interactive=False,
                             show_progress=False)
        elapsed = time.monotonic() - started
        assert results and results[0]["sent"], "legitimate transfer was blocked"
        assert elapsed < 15, f"transfer took {elapsed:.1f}s - looks serialized"
    finally:
        rude.close()
        receiver.stop()


# --- transfer history -------------------------------------------------------

def test_history_records_and_orders():
    from lanshare import history

    history.clear()
    history.record_received("a.txt", 10, "Peer", "192.168.1.5", path="/tmp/a.txt")
    history.record_sent("b.bin", 20, "Peer", "192.168.1.5")
    records = history.load()
    assert len(records) == 2
    assert records[0].name == "b.bin", "most recent must come first"
    assert records[0].direction == history.SENT
    assert records[1].direction == history.RECEIVED
    assert records[1].path == "/tmp/a.txt"
    history.clear()
    assert history.load() == []


def test_history_survives_a_corrupt_line():
    from lanshare import history

    history.clear()
    history.record_received("good.txt", 1, "P", "192.168.1.5", path=None)
    with open(history.history_path(), "a", encoding="utf-8") as fh:
        fh.write("{not json at all\n")          # e.g. a truncated write
        fh.write('{"direction":"sent"}\n')      # valid JSON, missing fields
    records = history.load()
    assert [r.name for r in records] == ["good.txt"]
    history.clear()


def test_history_is_thread_safe():
    """The receiver appends from up to 8 concurrent transfer threads."""
    from lanshare import history

    history.clear()

    def writer(n):
        for i in range(20):
            history.record_received(f"f{n}-{i}.bin", i, "P", "192.168.1.5", path=None)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    records = history.load(limit=1000)
    assert len(records) == 120, f"lost records under concurrency: {len(records)}"
    history.clear()


def test_history_stays_bounded_and_newest_first():
    """The file is trimmed on a high-water mark, not rewritten every append.

    Rewriting per append made an N-file transfer cost O(N^2). What has to hold
    is that the file cannot grow without bound and that a default load() still
    returns the newest MAX_RECORDS -- not that the file is cut on every write.
    """
    from lanshare import history

    history.clear()
    total = 5000
    for i in range(total):
        history.record_sent(f"f{i}.bin", 1000, "P", "192.168.1.5")

    records = history.load()
    assert len(records) == history.MAX_RECORDS
    assert records[0].name == f"f{total - 1}.bin"          # newest first
    assert records[-1].name == f"f{total - history.MAX_RECORDS}.bin"

    # Bounded on disk: the trim keeps it near the high-water mark, nowhere near
    # the ~800 KB that 5000 untrimmed records would occupy.
    size = history.history_path().stat().st_size
    assert size <= history.TRIM_AT_BYTES * 2, size
    history.clear()


def test_history_is_written_byte_exact():
    """One JSON object per LF-terminated line, on every platform.

    The append path opens the file with os.open(), which is a text-mode
    descriptor on Windows unless O_BINARY is passed -- and would then rewrite
    every newline, mixing line endings with the trim path, which writes bytes.
    """
    from lanshare import history

    history.clear()
    for i in range(3):
        history.record_sent(f"f{i}.bin", 1, "P", "192.168.1.5")
    raw = history.history_path().read_bytes()
    assert b"\r" not in raw, raw[:120]
    assert raw.count(b"\n") == 3
    assert len(history.load()) == 3
    history.clear()


def test_history_append_many_is_equivalent_to_repeated_appends():
    from lanshare import history

    history.clear()
    history.append_many([
        history.sent_record(f"b{i}.bin", 10, "P", "192.168.1.5")
        for i in range(3)
    ])
    names = [r.name for r in history.load()]
    assert names == ["b2.bin", "b1.bin", "b0.bin"]
    history.append_many([])  # must be a no-op, not an empty line
    assert len(history.load()) == 3
    history.clear()


# --- secret ID ---------------------------------------------------------------

def test_secret_fingerprint_is_stable_and_distinct():
    from lanshare import config as cfg_mod

    a = cfg_mod.secret_fingerprint(b"one-shared-secret-value")
    b = cfg_mod.secret_fingerprint(b"one-shared-secret-value")
    c = cfg_mod.secret_fingerprint(b"a-different-secret-value")
    assert a == b and a != c
    assert len(a) == 6 and a.isalnum()
    assert cfg_mod.secret_fingerprint(b"") is None


def test_secret_fingerprint_never_goes_on_the_wire():
    """It is a display aid. Broadcasting it would let an eavesdropper test
    guessed secrets offline."""
    from lanshare import config as cfg_mod
    from lanshare.discovery import DiscoveryResponder, _b64, _mac

    secret = b"a-shared-secret-for-the-wire-test"
    fingerprint = cfg_mod.secret_fingerprint(secret)
    assert fingerprint

    nonce = b"q" * 16
    import json as _json
    query = _json.dumps({"magic": "lanshare-discovery-v2", "kind": "query",
                         "nonce": _b64(nonce),
                         "mac": _b64(_mac(secret, "query", nonce))}).encode()
    responder = DiscoveryResponder("Box", 51888, 51889, "ab" * 32, secret)
    reply = responder._build_reply(query)
    assert reply is not None
    assert fingerprint.encode() not in reply
    assert fingerprint.lower().encode() not in reply.lower()
    assert secret not in reply


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
