"""A durable record of what was sent and received.

The app previously kept nothing: progress rows were trimmed to the last few and
the send results list was wiped on every new send, so there was no way to
answer "what did they send me, and where did it go?".

Records live in one JSON-per-line file in the config directory. Append-only,
trimmed to a cap, tolerant of a truncated or hand-edited file, and safe to call
from the receiver's worker threads.

Trimming is amortized. Rewriting the file on every append made a transfer of N
files cost O(N^2) -- measured at 10 ms per record once the file had a few
hundred entries, which was 92% of the time spent sending a folder of small
files. Instead the file is allowed to grow past the cap up to a high-water
mark and is then rewritten once, so the cost per record is a single append.
:func:`load` returns the newest ``limit`` records regardless, so the overshoot
is invisible to callers.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import config as cfg_mod

MAX_RECORDS = 500
# Rewrite only once the file passes this size (roughly a few thousand records),
# then cut it back to MAX_RECORDS. Amortizes the rewrite over many appends.
TRIM_AT_BYTES = 256 * 1024
_lock = threading.Lock()

SENT = "sent"
RECEIVED = "received"

OK = "ok"
DECLINED = "declined"
FAILED = "failed"


@dataclass
class Record:
    direction: str                 # SENT | RECEIVED
    name: str
    size: int
    peer_name: str
    peer_ip: str
    status: str                    # OK | DECLINED | FAILED
    at: float = field(default_factory=time.time)   # unix seconds, UTC
    path: Optional[str] = None     # where it landed (received, ok only)
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Optional["Record"]:
        try:
            return Record(
                direction=str(data["direction"]),
                name=str(data["name"]),
                size=int(data.get("size") or 0),
                peer_name=str(data.get("peer_name") or "unknown"),
                peer_ip=str(data.get("peer_ip") or ""),
                status=str(data.get("status") or OK),
                at=float(data.get("at") or 0.0),
                path=data.get("path") or None,
                error=data.get("error") or None,
            )
        except (KeyError, TypeError, ValueError):
            return None


def history_path() -> Path:
    return cfg_mod.config_dir() / "history.jsonl"


def append(record: Record) -> None:
    """Add one record. Never raises -- history must not break a transfer."""
    append_many((record,))


def append_many(records: Iterable[Record]) -> None:
    """Add several records in one open/write/close.

    The sender records an outcome per file at the end of a transfer; for a
    folder of a few thousand files that is a few thousand separate opens if
    done one at a time.
    """
    if not records:
        return
    blob = "".join(r.to_json() + "\n" for r in records).encode("utf-8")
    if not blob:
        return
    try:
        with _lock:
            path = history_path()
            # History names the people you exchanged files with, their
            # addresses and where files landed, so it is created owner-only
            # from its first byte rather than with the process umask and
            # tightened afterwards. Opened per call rather than chmod'ed per
            # record, which used to cost more than the write itself.
            # O_BINARY matters on Windows: without it os.open() hands back
            # a text-mode descriptor and os.write() rewrites every newline
            # in this JSON as a carriage-return pair, mixing line endings
            # with the trim path, which writes bytes.
            flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
                     | getattr(os, "O_BINARY", 0))
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, blob)
                size = os.lseek(fd, 0, os.SEEK_CUR)
            finally:
                os.close(fd)
            if size > TRIM_AT_BYTES:
                _trim_locked(path)
    except OSError:
        pass


def _trim_locked(path: Path) -> None:
    """Cut the file back to MAX_RECORDS. Called with the lock held, rarely."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= MAX_RECORDS:
            return
        keep = lines[-MAX_RECORDS:]
        tmp = path.with_suffix(".jsonl.tmp")
        # Written owner-only before it is moved into place: a plain write would
        # create it with the process umask and hand those permissions to the
        # history file when it replaces it.
        cfg_mod.write_private_bytes(tmp, ("\n".join(keep) + "\n").encode("utf-8"))
        os.replace(tmp, path)
    except OSError:
        pass


def load(limit: int = MAX_RECORDS) -> List[Record]:
    """Most recent first. A missing or damaged file reads as empty."""
    path = history_path()
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    records: List[Record] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue  # a truncated final line, or someone edited the file
        if isinstance(data, dict):
            rec = Record.from_dict(data)
            if rec is not None:
                records.append(rec)
    records.reverse()
    return records[:limit]


def clear() -> None:
    try:
        with _lock:
            history_path().unlink(missing_ok=True)
    except OSError:
        pass


def record_received(name: str, size: int, peer_name: str, peer_ip: str,
                    path: Optional[str], status: str = OK,
                    error: Optional[str] = None) -> None:
    append(received_record(name, size, peer_name, peer_ip, path, status, error))


def received_record(name: str, size: int, peer_name: str, peer_ip: str,
                    path: Optional[str], status: str = OK,
                    error: Optional[str] = None) -> Record:
    """Build a RECEIVED record without writing it, for batching."""
    return Record(direction=RECEIVED, name=name, size=size, peer_name=peer_name,
                  peer_ip=peer_ip, status=status, path=path, error=error)


def record_sent(name: str, size: int, peer_name: str, peer_ip: str,
                status: str = OK, error: Optional[str] = None) -> None:
    append(Record(direction=SENT, name=name, size=size, peer_name=peer_name,
                  peer_ip=peer_ip, status=status, error=error))


def sent_record(name: str, size: int, peer_name: str, peer_ip: str,
                status: str = OK, error: Optional[str] = None) -> Record:
    """Build a SENT record without writing it, for batching via append_many."""
    return Record(direction=SENT, name=name, size=size, peer_name=peer_name,
                  peer_ip=peer_ip, status=status, error=error)


def relative_time(when: float) -> str:
    """'just now' / '4 min ago' / '3 days ago' -- for list rows."""
    delta = max(0.0, time.time() - when)
    if delta < 45:
        return "just now"
    if delta < 3600:
        n = int(delta // 60)
        return f"{n} min ago"
    if delta < 86400:
        n = int(delta // 3600)
        return f"{n} hour{'s' if n != 1 else ''} ago"
    n = int(delta // 86400)
    if n < 30:
        return f"{n} day{'s' if n != 1 else ''} ago"
    return time.strftime("%d %b %Y", time.localtime(when))
