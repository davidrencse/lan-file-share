"""Defensive handling of untrusted file names, sizes and destination paths.

Everything a remote peer sends about a file is treated as hostile input:

  * File names are reduced to a bare, sanitized base name -- no directory
    components, no traversal, no reserved device names, no control characters.
  * The destination is always inside the configured download directory, verified
    by resolving the real path and confirming containment.
  * Sizes are validated against a configured ceiling and against free disk
    space before a byte is written, and enforced again while streaming.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Tuple

# Windows reserved device names (case-insensitive, with or without extension).
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Characters illegal in Windows file names (also a safe superset elsewhere).
_ILLEGAL = re.compile(r'[<>:"/\\|?*]')

MAX_NAME_LEN = 200


class UnsafeFileError(Exception):
    """Raised when a proposed name or size cannot be made safe."""


def sanitize_filename(raw: str) -> str:
    """Return a safe base file name derived from an untrusted string.

    Raises :class:`UnsafeFileError` if nothing usable remains.
    """
    if not isinstance(raw, str) or not raw:
        raise UnsafeFileError("empty file name")

    # Collapse any path structure: take the last component regardless of the
    # separator style the sender used.
    name = raw.replace("\\", "/").split("/")[-1]

    # Strip control chars and NULs, then illegal characters.
    name = _CONTROL_CHARS.sub("", name)
    name = _ILLEGAL.sub("_", name)

    # No leading dots-only names, no traversal remnants.
    name = name.strip()
    name = name.strip(". ")  # Windows also dislikes trailing dots/spaces.

    if not name or name in {".", ".."}:
        raise UnsafeFileError(f"file name reduces to nothing safe: {raw!r}")

    # Reserved device names (check the stem before the first dot).
    stem = name.split(".")[0].lower()
    if stem in _WINDOWS_RESERVED:
        name = "_" + name

    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        ext = ext[: MAX_NAME_LEN // 2]
        root = root[: MAX_NAME_LEN - len(ext)]
        name = root + ext

    # Final guard: the result must be a single, non-traversing component.
    if os.path.basename(name) != name or name in {".", ".."}:
        raise UnsafeFileError(f"file name still unsafe after sanitizing: {raw!r}")

    return name


def validate_size(size: int, max_bytes: int) -> None:
    """Validate a declared file size against the configured ceiling."""
    if not isinstance(size, int) or isinstance(size, bool):
        raise UnsafeFileError("file size is not an integer")
    if size < 0:
        raise UnsafeFileError("negative file size")
    if size > max_bytes:
        raise UnsafeFileError(
            f"file size {size} exceeds limit {max_bytes} bytes"
        )


def check_free_space(download_dir: Path, size: int) -> None:
    """Ensure the target volume has room (with a small margin)."""
    try:
        usage = os.statvfs(download_dir)  # POSIX
        free = usage.f_bavail * usage.f_frsize
    except AttributeError:
        import shutil

        free = shutil.disk_usage(download_dir).free
    # Keep a 16 MiB cushion so we never fill the disk to zero.
    if size + (16 * 1024 * 1024) > free:
        raise UnsafeFileError(
            f"not enough free space: need {size} bytes, {free} available"
        )


def resolve_safe_destination(download_dir: Path, safe_name: str) -> Path:
    """Return a collision-free path guaranteed to sit inside *download_dir*.

    The name must already be sanitized. The final path's real location is
    verified to be contained within the download directory.
    """
    download_dir = download_dir.resolve()
    candidate = (download_dir / safe_name)

    # Containment check: the parent of the destination must be the download dir.
    parent = candidate.resolve().parent
    if parent != download_dir:
        raise UnsafeFileError("destination escapes the download directory")

    # Avoid overwriting existing files: "name.ext" -> "name (1).ext", ...
    if not candidate.exists():
        return candidate
    root, ext = os.path.splitext(safe_name)
    for i in range(1, 10000):
        alt = download_dir / f"{root} ({i}){ext}"
        if not alt.exists():
            return alt
    raise UnsafeFileError("too many name collisions in download directory")


def partial_path(final: Path) -> Path:
    """A temp path (same directory) used while a transfer is in flight."""
    return final.with_name(f".{final.name}.part-{os.getpid()}")


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def split_root_ext(name: str) -> Tuple[str, str]:
    return os.path.splitext(name)


_SIZE_UNITS = {
    "B": 1, "K": 1024, "KB": 1024, "KIB": 1024,
    "M": 1024**2, "MB": 1024**2, "MIB": 1024**2,
    "G": 1024**3, "GB": 1024**3, "GIB": 1024**3,
    "T": 1024**4, "TB": 1024**4, "TIB": 1024**4,
}


def parse_size(text: str) -> int:
    """Parse a human size string like '500M' or '20 GiB' into bytes."""
    text = text.strip().upper()
    for suffix in sorted(_SIZE_UNITS, key=len, reverse=True):
        if text.endswith(suffix) and text[: -len(suffix)].strip():
            return int(float(text[: -len(suffix)].strip()) * _SIZE_UNITS[suffix])
    return int(text)
