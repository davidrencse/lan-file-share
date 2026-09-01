"""Command-line interface for LANShare."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import List, Optional

from . import DEFAULT_DISCOVERY_PORT, DEFAULT_PORT, __version__
from . import config as cfg_mod
from . import identity


def _cmd_init(args: argparse.Namespace) -> int:
    cfg = cfg_mod.load_config()
    if args.name:
        cfg["device_name"] = args.name
        cfg_mod.save_config(cfg)
    identity.ensure_identity(cfg["device_name"])
    fpr = identity.own_fingerprint() or ""

    secret = cfg_mod.load_secret()
    created = False
    if not secret:
        new_secret = cfg_mod.generate_secret()
        cfg_mod.save_secret(new_secret)
        secret = new_secret.encode()
        created = True

    print(f"LANShare initialised for device '{cfg['device_name']}'.")
    print(f"  Config dir : {cfg_mod.config_dir()}")
    print(f"  Identity   : {identity.fingerprint_pretty(fpr)}")
    if created:
        print()
        print("  A new shared secret was generated for this device:")
        print(f"      {secret.decode('utf-8', 'replace')}")
        print("  Run this on every OTHER device you want to pair with:")
        print(f"      lanshare set-secret {secret.decode('utf-8', 'replace')}")
    else:
        print("  A shared secret is already configured (use 'show-secret' to view).")
    return 0


def _cmd_set_secret(args: argparse.Namespace) -> int:
    secret = args.secret
    if not secret:
        secret = getpass.getpass("Enter shared secret (same on all devices): ").strip()
        confirm = getpass.getpass("Confirm shared secret: ").strip()
        if secret != confirm:
            print("Secrets did not match.", file=sys.stderr)
            return 1
    if not secret:
        print("Empty secret rejected.", file=sys.stderr)
        return 1
    if len(secret) < 8:
        print("Refusing a secret shorter than 8 characters.", file=sys.stderr)
        return 1
    cfg_mod.save_secret(secret)
    print("Shared secret saved.")
    return 0


def _cmd_show_secret(args: argparse.Namespace) -> int:
    secret = cfg_mod.load_secret()
    if not secret:
        print("No shared secret set. Run 'lanshare init' or 'lanshare set-secret'.",
              file=sys.stderr)
        return 1
    fpr = identity.own_fingerprint()
    print("Shared secret (copy to other devices with 'lanshare set-secret <value>'):")
    print(f"    {secret.decode('utf-8', 'replace')}")
    if fpr:
        print(f"This device's fingerprint: {identity.fingerprint_pretty(fpr)}")
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    from .netutil import local_ipv4_addresses

    cfg = cfg_mod.load_config()
    fpr = identity.own_fingerprint()
    print(f"LANShare {__version__}")
    print(f"  Device name  : {cfg['device_name']}")
    print(f"  Config dir   : {cfg_mod.config_dir()}")
    print(f"  Download dir : {cfg_mod.get_download_dir(cfg)}")
    print(f"  TCP port     : {cfg['port']}")
    print(f"  Discovery    : {'on' if cfg.get('discovery_enabled', True) else 'off'}"
          f" (udp {cfg['discovery_port']})")
    print(f"  Secret set   : {'yes' if cfg_mod.load_secret() else 'NO'}")
    print(f"  Fingerprint  : {identity.fingerprint_pretty(fpr) if fpr else '(none yet)'}")
    addrs = local_ipv4_addresses()
    if addrs:
        print(f"  Local IPv4   : {', '.join(addrs)}")
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    cfg = cfg_mod.load_config()
    changed = False
    if args.name is not None:
        cfg["device_name"] = args.name
        changed = True
    if args.dir is not None:
        cfg["download_dir"] = args.dir
        changed = True
    if args.port is not None:
        cfg["port"] = args.port
        changed = True
    if args.max_size is not None:
        cfg["max_file_bytes"] = _parse_size(args.max_size)
        changed = True
    if args.discovery is not None:
        cfg["discovery_enabled"] = (args.discovery == "on")
        changed = True
    if changed:
        cfg_mod.save_config(cfg)
        print("Configuration updated.")
    return _cmd_info(args)


def _cmd_receive(args: argparse.Namespace) -> int:
    from .receiver import Receiver

    cfg = cfg_mod.load_config()
    if args.name:
        cfg["device_name"] = args.name
    if args.dir:
        cfg["download_dir"] = args.dir
    if args.port:
        cfg["port"] = args.port
    if args.no_discovery:
        cfg["discovery_enabled"] = False

    approval = None
    if args.yes:
        print("WARNING: --yes auto-accepts every transfer. Use only on a trusted "
              "network for testing.", file=sys.stderr)

        def approval(_info):  # type: ignore[misc]
            print(f"  Auto-accepting '{_info['safe_name']}' from {_info['peer_name']}")
            return True

    try:
        Receiver(cfg, approval=approval).serve_forever()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nReceiver stopped.")
    return 0


def _resolve_target(target: str, discovery_port: int):
    """Resolve a discovered device name to its (ip, port) via LAN discovery."""
    from .discovery import discover

    print(f"  Looking for device '{target}' on the network...")
    peers = discover(discovery_port, timeout=3.0)
    matches = [p for p in peers if p.name.lower() == target.lower()]
    if not matches:
        names = ", ".join(sorted(p.name for p in peers)) or "(none found)"
        raise SystemExit(f"No device named '{target}' found. Discovered: {names}")
    if len(matches) > 1:
        detail = "; ".join(f"{p.name}@{p.ip}:{p.port}" for p in matches)
        raise SystemExit(f"Multiple devices named '{target}': {detail}. Use an IP.")
    peer = matches[0]
    print(f"  Found '{peer.name}' at {peer.ip}:{peer.port}")
    return peer.ip, peer.port


def _cmd_send(args: argparse.Namespace) -> int:
    from .sender import SendError, send_files

    cfg = cfg_mod.load_config()
    host = args.target
    port = args.port or int(cfg["port"])
    if args.find:
        host, found_port = _resolve_target(args.target, int(cfg["discovery_port"]))
        # Prefer the port the peer actually advertised unless overridden.
        if args.port is None:
            port = found_port
    try:
        results = send_files(host, port, args.files,
                             device_name=cfg["device_name"], interactive=True)
    except SendError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    sent = sum(1 for r in results if r.get("sent"))
    print(f"\n{sent}/{len(results)} file(s) delivered.")
    return 0 if sent == len(results) else 2


def _cmd_discover(args: argparse.Namespace) -> int:
    from .discovery import discover

    cfg = cfg_mod.load_config()
    port = args.discovery_port or int(cfg["discovery_port"])
    print(f"Searching for LANShare devices (udp {port}, {args.timeout:.0f}s)...")
    peers = discover(port, timeout=args.timeout)
    if not peers:
        print("  No devices found. Make sure a receiver is running on the LAN.")
        return 0
    print(f"  Found {len(peers)} device(s):")
    for p in sorted(peers, key=lambda x: x.name):
        fpr = identity.fingerprint_pretty(p.fingerprint) if p.fingerprint else "?"
        print(f"    {p.name:<24} {p.ip}:{p.port}")
        print(f"        fingerprint: {fpr}")
    return 0


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .selftest import run_selftest

    return run_selftest()


def _cmd_gui(args: argparse.Namespace) -> int:
    from .gui.app import main as gui_main

    return gui_main()


def _parse_size(text: str) -> int:
    from .safety import parse_size

    return parse_size(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lanshare",
        description="Reasonably secure LAN file sharing (Windows <-> Linux).",
    )
    p.add_argument("--version", action="version", version=f"lanshare {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="generate identity + shared secret")
    pi.add_argument("--name", help="set this device's display name")
    pi.set_defaults(func=_cmd_init)

    ps = sub.add_parser("set-secret", help="set the shared pairing secret")
    ps.add_argument("secret", nargs="?", help="secret value (prompted if omitted)")
    ps.set_defaults(func=_cmd_set_secret)

    psh = sub.add_parser("show-secret", help="print the shared secret for pairing")
    psh.set_defaults(func=_cmd_show_secret)

    pinf = sub.add_parser("info", help="show configuration and identity")
    pinf.set_defaults(func=_cmd_info)

    pc = sub.add_parser("config", help="view or change persistent settings")
    pc.add_argument("--name", help="device display name")
    pc.add_argument("--dir", help="download directory for received files")
    pc.add_argument("--port", type=int, help=f"TCP port (default {DEFAULT_PORT})")
    pc.add_argument("--max-size", help="max accepted file size (e.g. 500M, 20G)")
    pc.add_argument("--discovery", choices=["on", "off"], help="enable LAN discovery")
    pc.set_defaults(func=_cmd_config)

    pr = sub.add_parser("receive", aliases=["recv", "serve"],
                        help="run the receiver and wait for transfers")
    pr.add_argument("--name", help="override device display name for this run")
    pr.add_argument("--dir", help="override download directory for this run")
    pr.add_argument("--port", type=int, help="override TCP port for this run")
    pr.add_argument("--no-discovery", action="store_true",
                    help="do not answer LAN discovery queries")
    pr.add_argument("--yes", action="store_true",
                    help="auto-accept all transfers (INSECURE; testing only)")
    pr.set_defaults(func=_cmd_receive)

    psn = sub.add_parser("send", help="send file(s) to a receiver")
    psn.add_argument("target", help="receiver IP/hostname, or device name with --find")
    psn.add_argument("files", nargs="+", help="one or more files to send")
    psn.add_argument("--port", type=int, help="receiver TCP port")
    psn.add_argument("--find", action="store_true",
                     help="treat target as a device name and locate it via discovery")
    psn.set_defaults(func=_cmd_send)

    pd = sub.add_parser("discover", help="list LANShare receivers on the network")
    pd.add_argument("--timeout", type=float, default=3.0, help="seconds to listen")
    pd.add_argument("--discovery-port", type=int,
                    help=f"UDP discovery port (default {DEFAULT_DISCOVERY_PORT})")
    pd.set_defaults(func=_cmd_discover)

    pt = sub.add_parser("selftest", help="run a local loopback transfer self-test")
    pt.set_defaults(func=_cmd_selftest)

    pg = sub.add_parser("gui", help="launch the desktop GUI")
    pg.set_defaults(func=_cmd_gui)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    # Line-buffer output so status lines and prompts appear promptly even when
    # stdout is redirected to a file or pipe (e.g. a background receiver log).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
