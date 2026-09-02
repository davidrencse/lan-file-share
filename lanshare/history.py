"""A durable record of what was sent and received.

The app previously kept nothing: progress rows were trimmed to the last few and
the send results list was wiped on every new send, so there was no way to
answer "what did they send me, and where did it go?".

Records live in one JSON-per-line file in the config directory. Append-only,
trimmed to a cap, tolerant of a truncated or hand-edited file, and safe to call
from the receiver's worker threads.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config as cfg_mod

MAX_RECORDS = 500
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
    try:
        with _lock:
            path = history_path()
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(record.to_json() + "\n")
            cfg_mod._harden_file(path)  # noqa: SLF001 -- same config-dir policy
            _trim_locked(path)
    except OSError:
        pass


# A record is at least this many bytes on disk, so a file smaller than
# MAX_RECORDS * this cannot possibly be over the cap and needn't be read.
# Deliberately conservative: guessing high here silently stops the cap from
# being enforced at all for short records.
_MIN_RECORD_BYTES = 60


def _trim_locked(path: Path) -> None:
    """Keep the file bounded. Called with the lock held."""
    try:
        if path.stat().st_size < MAX_RECORDS * _MIN_RECORD_BYTES:
            return  # cheap guard: cannot be over the cap yet
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= MAX_RECORDS:
            return
        keep = lines[-MAX_RECORDS:]
        tmp = path.with_suffix(".jsonl.tmp")
        tmp.write_text("\n".join(keep) + "\n", encoding="utf-8")
        os.replace(tmp, path)
        cfg_mod._harden_file(path)  # noqa: SLF001
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
    append(Record(direction=RECEIVED, name=name, size=size, peer_name=peer_name,
                  peer_ip=peer_ip, status=status, path=path, error=error))


def record_sent(name: str, size: int, peer_name: str, peer_ip: str,
                status: str = OK, error: Optional[str] = None) -> None:
    append(Record(direction=SENT, name=name, size=size, peer_name=peer_name,
                  peer_ip=peer_ip, status=status, error=error))


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
