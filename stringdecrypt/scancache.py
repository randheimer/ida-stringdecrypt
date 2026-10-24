"""Small, bounded in-process cache for file scans.

AI clients typically call ``analyze_binary``, ``map_strings`` and then
``get_string_context`` for the same file.  Repeated full scans are wasteful, so
this module keeps a few recent result payloads and a small file-digest cache.

The cache is intentionally process-local: no files are written, nothing is
shared between users, and a file change (mtime/size or digest) produces a new
entry.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict


def sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class ScanCache:
    def __init__(self, max_entries: int = 6, max_age: float = 900.0) -> None:
        self.max_entries = max(0, int(max_entries))
        self.max_age = max(0.0, float(max_age))
        self._entries: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._digests: OrderedDict[tuple[str, int, int], tuple[float, str]] = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.digest_hits = 0

    # ------------------------------------------------------------------
    # Result payloads
    # ------------------------------------------------------------------
    def get(self, key: str, *, refresh: bool = False) -> tuple[dict, float] | None:
        if self.max_entries <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            if refresh:
                self._entries.pop(key, None)
                return None
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            created, payload = entry
            age = now - created
            if age > self.max_age:
                self._entries.pop(key, None)
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return payload, age

    def put(self, key: str, payload: dict) -> None:
        if self.max_entries <= 0:
            return
        with self._lock:
            self._entries[key] = (time.monotonic(), payload)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.evictions += 1

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._digests.clear()

    # ------------------------------------------------------------------
    # File digests
    # ------------------------------------------------------------------
    def digest(self, path: str) -> tuple[str, os.stat_result]:
        """Return (sha256, stat) and cache digests by path/mtime/size."""
        stat = os.stat(path)
        key = (os.path.abspath(path), int(stat.st_mtime_ns), int(stat.st_size))
        with self._lock:
            cached = self._digests.get(key)
            if cached is not None:
                self._digests.move_to_end(key)
                self.digest_hits += 1
                return cached[1], stat
        digest = sha256_file(path)
        with self._lock:
            self._digests[key] = (time.monotonic(), digest)
            self._digests.move_to_end(key)
            while len(self._digests) > max(16, self.max_entries * 4):
                self._digests.popitem(last=False)
        return digest, stat

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            now = time.monotonic()
            ages = [now - created for created, _ in self._entries.values()]
            return {
                "entries": len(self._entries),
                "max_entries": self.max_entries,
                "max_age_seconds": self.max_age,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "digest_hits": self.digest_hits,
                "oldest_entry_seconds": round(max(ages), 1) if ages else 0.0,
            }


def cache_from_env() -> ScanCache:
    disabled = os.environ.get("STRINGDECRYPT_CACHE", "1").strip().lower() in (
        "0",
        "false",
        "off",
        "no",
    )
    try:
        entries = int(os.environ.get("STRINGDECRYPT_CACHE_ENTRIES", "6"))
    except ValueError:
        entries = 6
    try:
        age = float(os.environ.get("STRINGDECRYPT_CACHE_TTL", "900"))
    except ValueError:
        age = 900.0
    return ScanCache(0 if disabled else entries, age)
