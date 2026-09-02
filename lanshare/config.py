"""Configuration, on-disk state and paths for LANShare.

All persistent state lives in a per-user config directory:

  * ``config.json``      -- settings (device name, port, download dir, ...)
  * ``secret``           -- the shared pairing secret (used for HMAC auth)
  * ``identity.key`` / ``identity.crt`` -- this device's TLS identity
  * ``known_peers.json`` -- remembered peer fingerprints (trust-on-first-use)

The directory and the secret file are created with owner-only permissions on
POSIX systems. On Windows the files inherit the (already per-user) profile ACL.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import stat
from pathlib import Path
from typing import Any, Dict

from . import DEFAULT_DISCOVERY_PORT, DEFAULT_PORT


def config_dir() -> Path:
    """Return the per-user LANShare config directory (created if missing)."""
    override = os.environ.get("LANSHARE_HOME")
    if override:
        base = Path(override)
    elif os.name == "nt":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        base = Path(appdata) / "LANShare"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = (Path(xdg) if xdg else Path.home() / ".config") / "lanshare"
    base.mkdir(parents=True, exist_ok=True)
    _harden_dir(base)
    return base


def _harden_dir(path: Path) -> None:
    """Best-effort: make a directory owner-accessible only (POSIX)."""
    if os.name != "nt":
        try:
            os.chmod(path, stat.S_IRWXU)  # 0700
        except OSError:
            pass


def _harden_file(path: Path) -> None:
    """Best-effort: make a file owner read/write only (POSIX)."""
    if os.name != "nt":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass


def write_private_bytes(path: Path, data: bytes) -> None:
    """Write *data* to *path* so it is owner-only from the very first byte.

    ``Path.write_bytes`` would create the file using the process umask (often
    world-readable) and only be tightened afterwards, leaving a window where
    secret material is readable by other local users. Passing the mode to
    ``os.open`` closes that window.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW  # never write through a planted symlink
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    _harden_file(path)  # no-op on POSIX, keeps intent explicit elsewhere


MIN_SECRET_LEN = 12


def check_secret_strength(secret: str) -> str | None:
    """Return a human-readable problem with *secret*, or None if acceptable."""
    if len(secret) < MIN_SECRET_LEN:
        return (f"too short -- use at least {MIN_SECRET_LEN} characters "
                f"(the generated secret is strongest)")
    if len(set(secret)) < 5:
        return "too repetitive to be guess-resistant"
    lowered = secret.lower()
    if lowered in {"password1234", "lanshare1234", "changemenow"}:
        return "this is a well-known value; pick something unguessable"
    return None


def default_download_dir() -> Path:
    return Path.home() / "LANShare received"


DEFAULTS: Dict[str, Any] = {
    "device_name": socket.gethostname() or "lanshare-device",
    "port": DEFAULT_PORT,
    "discovery_port": DEFAULT_DISCOVERY_PORT,
    "download_dir": None,          # None -> default_download_dir()
    "max_file_bytes": 100 * 1024 * 1024 * 1024,  # 100 GiB safety ceiling
    "discovery_enabled": True,
    # Extra CIDRs to treat as local, for networks the OS probe cannot see (a
    # VPN, or a segment reached through a router). Normally empty: the local
    # interface subnets are detected automatically.
    "extra_local_networks": [],
    "wizard_done": False,
}


def config_path() -> Path:
    return config_dir() / "config.json"


def _coerce(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Force known keys to sane types so a hand-edited or corrupt config file
    fails soft here instead of raising deep inside the transfer path."""
    def as_port(value: Any, fallback: int) -> int:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return fallback
        return port if 0 <= port <= 65535 else fallback

    cfg["port"] = as_port(cfg.get("port"), DEFAULTS["port"])
    cfg["discovery_port"] = as_port(
        cfg.get("discovery_port"), DEFAULTS["discovery_port"])
    try:
        max_bytes = int(cfg.get("max_file_bytes"))
        cfg["max_file_bytes"] = max_bytes if max_bytes >= 0 else DEFAULTS["max_file_bytes"]
    except (TypeError, ValueError):
        cfg["max_file_bytes"] = DEFAULTS["max_file_bytes"]
    cfg["discovery_enabled"] = bool(cfg.get("discovery_enabled", True))
    cfg["wizard_done"] = bool(cfg.get("wizard_done", False))
    raw_nets = cfg.get("extra_local_networks")
    cfg["extra_local_networks"] = (
        [str(n) for n in raw_nets] if isinstance(raw_nets, list) else []
    )
    if not isinstance(cfg.get("device_name"), str) or not cfg["device_name"].strip():
        cfg["device_name"] = DEFAULTS["device_name"]
    cfg["device_name"] = cfg["device_name"].strip()[:64]
    raw_dir = cfg.get("download_dir")
    cfg["download_dir"] = raw_dir if isinstance(raw_dir, str) and raw_dir else None
    return cfg


def load_config() -> Dict[str, Any]:
    """Load settings, filling in defaults for anything missing."""
    cfg = dict(DEFAULTS)
    path = config_path()
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            # Corrupt config should not brick the tool; fall back to defaults.
            pass
    return _coerce(cfg)


def save_config(cfg: Dict[str, Any]) -> None:
    path = config_path()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    _harden_file(path)


def get_download_dir(cfg: Dict[str, Any]) -> Path:
    raw = cfg.get("download_dir")
    path = Path(raw).expanduser() if raw else default_download_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


# --- shared pairing secret -------------------------------------------------

def secret_path() -> Path:
    return config_dir() / "secret"


def load_secret() -> bytes | None:
    """Return the shared pairing secret bytes, or None if not set."""
    path = secret_path()
    if not path.exists():
        return None
    data = path.read_bytes().strip()
    return data or None


def save_secret(secret: str | bytes) -> None:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    path = secret_path()
    tmp = path.with_suffix(".tmp")
    write_private_bytes(tmp, secret)
    os.replace(tmp, path)
    _harden_file(path)


def secret_fingerprint(secret: bytes | None = None) -> str | None:
    """A short, safe-to-display ID for the shared secret ("Secret ID").

    Two devices showing the same ID are paired with the same secret. That is
    the one question the UI previously could not answer: with authenticated
    discovery, a mismatched secret produces silence that looks exactly like
    "nothing is out there".

    Display only. This must never be broadcast or sent over the wire -- doing
    so would hand an eavesdropper an offline check against guessed secrets.
    """
    if secret is None:
        secret = load_secret()
    if not secret:
        return None
    digest = hashlib.sha256(b"lanshare-secret-id|" + secret).hexdigest()
    return digest[:6].upper()


def generate_secret() -> str:
    """Generate a fresh human-transferable pairing secret."""
    # ~124 bits of entropy, URL-safe and easy to copy/type between machines.
    return secrets.token_urlsafe(16)


# --- known peers (trust on first use) --------------------------------------

def known_peers_path() -> Path:
    return config_dir() / "known_peers.json"


def load_known_peers() -> Dict[str, str]:
    path = known_peers_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_known_peers(peers: Dict[str, str]) -> None:
    path = known_peers_path()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(peers, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    _harden_file(path)
