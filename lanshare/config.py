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


def default_download_dir() -> Path:
    return Path.home() / "LANShare received"


DEFAULTS: Dict[str, Any] = {
    "device_name": socket.gethostname() or "lanshare-device",
    "port": DEFAULT_PORT,
    "discovery_port": DEFAULT_DISCOVERY_PORT,
    "download_dir": None,          # None -> default_download_dir()
    "max_file_bytes": 100 * 1024 * 1024 * 1024,  # 100 GiB safety ceiling
    "discovery_enabled": True,
}


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> Dict[str, Any]:
    """Load settings, filling in defaults for anything missing."""
    cfg = dict(DEFAULTS)
    path = config_path()
    if path.exists():
        try:
            cfg.update(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            # Corrupt config should not brick the tool; fall back to defaults.
            pass
    if not cfg.get("device_name"):
        cfg["device_name"] = DEFAULTS["device_name"]
    return cfg


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
    tmp.write_bytes(secret)
    os.replace(tmp, path)
    _harden_file(path)


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
