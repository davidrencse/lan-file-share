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
import unicodedata
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
# Backslash is handled separately so a legitimate POSIX name containing one is
# not truncated.
_ILLEGAL = re.compile(r'[<>:"/|?*]')

MAX_NAME_LEN = 200


class UnsafeFileError(Exception):
    """Raised when a proposed name or size cannot be made safe."""


def _strip_invisibles(text: str) -> str:
    """Remove Unicode characters that render as nothing or reorder what follows.

    Bidirectional overrides (U+202E RIGHT-TO-LEFT OVERRIDE and friends) let a
    hostile sender make ``<RLO>gnp.exe`` *display* as ``exe.png``, which would
    defeat the whole point of showing the user a name to approve. Zero-width
    and other invisible format characters allow similar homograph tricks. Every
    Unicode "format" (Cf) and "control" (Cc) character is dropped, which covers
    the whole family without needing an explicit blocklist.
    """
    return "".join(
        ch for ch in text if unicodedata.category(ch) not in ("Cf", "Cc", "Cs")
    )


def sanitize_display_text(raw: object, limit: int = 64) -> str:
    """Make a peer-supplied string safe to show in a UI.

    Strips control/format characters (so it cannot reorder or hide the text
    around it) and clamps the length. This is belt-and-braces alongside forcing
    plain-text rendering in the GUI.
    """
    text = raw if isinstance(raw, str) else str(raw)
    text = unicodedata.normalize("NFC", text)
    text = _strip_invisibles(_CONTROL_CHARS.sub("", text)).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text or "unknown"


def sanitize_filename(raw: str) -> str:
    """Return a safe base file name derived from an untrusted string.

    Raises :class:`UnsafeFileError` if nothing usable remains.
    """
    if not isinstance(raw, str) or not raw:
        raise UnsafeFileError("empty file name")

    # Normalise first so look-alike encodings collapse to one form.
    name = unicodedata.normalize("NFC", raw)

    # Collapse any path structure: '/' is a separator on every platform, so
    # take the last component. A backslash is deliberately *not* treated as a
    # separator, because on POSIX it is an ordinary filename character and
    # splitting on it would silently discard half of a genuine name like
    # "back\slash.txt". Escaping it instead is equally safe (the result can
    # contain no separator on either platform) and, unlike splitting, behaves
    # identically on Windows and Linux.
    name = name.split("/")[-1]

    # Drop control characters, then anything invisible or direction-altering.
    name = _CONTROL_CHARS.sub("", name)
    name = _strip_invisibles(name)
    name = name.replace("\\", "_")
    name = _ILLEGAL.sub("_", name)

    # Trailing dots/spaces are illegal on Windows. A *leading* dot is kept so
    # dotfiles survive intact; names made only of dots are rejected below.
    name = name.strip().rstrip(". ")

    if not name or set(name) <= {"."}:
        raise UnsafeFileError(f"file name reduces to nothing safe: {raw!r}")

    # Reserved device names (check the stem before the first dot).
    stem = name.split(".")[0].lower()
    if stem in _WINDOWS_RESERVED:
        name = "_" + name

    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        ext = ext[: MAX_NAME_LEN // 2]
        root = root[: MAX_NAME_LEN - len(ext)]
        name = (root + ext).rstrip(". ")

    # Final guard: the result must be a single, non-traversing component on
    # *either* platform's rules, whichever we happen to be running on.
    if "/" in name or "\\" in name or os.path.basename(name) != name:
        raise UnsafeFileError(f"file name still unsafe after sanitizing: {raw!r}")
    if not name or set(name) <= {"."}:
        raise UnsafeFileError(f"file name reduces to nothing safe: {raw!r}")

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


def _contained_candidate(download_dir: Path, name: str) -> Path:
    """Return download_dir/name, proving it really resolves inside the dir."""
    candidate = download_dir / name
    # .resolve() follows symlinks, so a planted symlink pointing elsewhere is
    # caught here rather than being written through.
    if candidate.resolve().parent != download_dir:
        raise UnsafeFileError("destination escapes the download directory")
    return candidate


def reserve_destination(download_dir: Path, safe_name: str) -> Path:
    """Atomically claim a free path inside *download_dir* and return it.

    A zero-byte placeholder is created with ``O_EXCL``, so two concurrent
    transfers -- or any other program -- cannot select the same path and
    clobber each other. The caller must either ``os.replace()`` the finished
    file over the placeholder or remove it (see :func:`release_destination`).

    The name must already have been through :func:`sanitize_filename`.
    """
    download_dir = download_dir.resolve()
    root, ext = os.path.splitext(safe_name)
    for i in range(0, 10000):
        name = safe_name if i == 0 else f"{root} ({i}){ext}"
        candidate = _contained_candidate(download_dir, name)
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise UnsafeFileError(f"cannot create destination: {exc}") from exc
        os.close(fd)
        return candidate
    raise UnsafeFileError("too many name collisions in download directory")


def release_destination(dest: Path) -> None:
    """Drop a reservation made by :func:`reserve_destination` (best effort)."""
    try:
        if dest.exists() and dest.stat().st_size == 0:
            dest.unlink()
    except OSError:
        pass


def partial_path(final: Path) -> Path:
    """A temp path (same directory) used while a transfer is in flight."""
    return final.with_name(f".{final.name}.part-{os.getpid()}-{os.urandom(4).hex()}")


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
    """Parse a human size string like '500M' or '20 GiB' into bytes.

    Raises ValueError on junk or on a negative size (a negative ceiling would
    silently reject every incoming file).
    """
    text = text.strip().upper()
    value = None
    for suffix in sorted(_SIZE_UNITS, key=len, reverse=True):
        if text.endswith(suffix) and text[: -len(suffix)].strip():
            value = int(float(text[: -len(suffix)].strip()) * _SIZE_UNITS[suffix])
            break
    if value is None:
        value = int(float(text))
    if value < 0:
        raise ValueError("size cannot be negative")
    return value
