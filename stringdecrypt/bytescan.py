"""Shared byte/string scanning helpers.

These functions are deliberately IDA-independent so the CLI and the IDA
plugin use exactly the same candidate extraction logic.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator


ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")
UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}")

# bytes.translate() lets the hot printable-ratio check run in C instead of
# looping in Python.  It is called for every transform the engine evaluates.
_PRINTABLE_TABLE = bytes(
    1 if (0x20 <= value <= 0x7E or value in (9, 10, 13)) else 0 for value in range(256)
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.translate(_PRINTABLE_TABLE).count(1) / len(data)


def is_probably_plaintext(data: bytes, threshold: float = 0.7) -> bool:
    return printable_ratio(data) >= threshold


def iter_ascii_strings(data: bytes, base_ea: int = 0, min_length: int = 4) -> Iterator[tuple[int, bytes, str]]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_length))
    for match in pattern.finditer(data):
        yield base_ea + match.start(), match.group(), match.group().decode("ascii", "replace")


def iter_utf16le_strings(data: bytes, base_ea: int = 0, min_length: int = 4) -> Iterator[tuple[int, bytes, str]]:
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, min_length))
    for match in pattern.finditer(data):
        raw = match.group()
        try:
            text = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        yield base_ea + match.start(), raw, text


def iter_utf16be_strings(data: bytes, base_ea: int = 0, min_length: int = 4) -> Iterator[tuple[int, bytes, str]]:
    pattern = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % max(1, min_length))
    for match in pattern.finditer(data):
        raw = match.group()
        try:
            text = raw.decode("utf-16-be")
        except UnicodeDecodeError:
            continue
        yield base_ea + match.start(), raw, text


@dataclass
class StringHit:
    ea: int
    raw: bytes
    text: str
    encoding: str
    kind: str = "string"


def extract_strings(
    data: bytes,
    base_ea: int = 0,
    min_length: int = 4,
    include_utf16: bool = True,
) -> list[StringHit]:
    hits: list[StringHit] = []
    for ea, raw, text in iter_ascii_strings(data, base_ea, min_length):
        hits.append(StringHit(ea, raw, text, "ascii"))
    if include_utf16:
        for ea, raw, text in iter_utf16le_strings(data, base_ea, min_length):
            hits.append(StringHit(ea, raw, text, "utf-16le"))
        for ea, raw, text in iter_utf16be_strings(data, base_ea, min_length):
            hits.append(StringHit(ea, raw, text, "utf-16be"))
    # Overlapping ASCII hits inside UTF-16 are usually duplicate noise.
    unique: dict[tuple[int, str], StringHit] = {}
    for hit in hits:
        unique.setdefault((hit.ea, hit.text), hit)
    return list(unique.values())


def entropy_blobs(
    data: bytes,
    base_ea: int = 0,
    min_length: int = 8,
    max_length: int = 512,
    threshold: float = 4.35,
    step: int = 16,
    max_blobs: int = 4096,
) -> list[StringHit]:
    """Find high-entropy runs that may be raw ciphertext.

    This is intentionally conservative: it prefers isolated blobs and skips
    text-like regions that the normal string scanner already handles.
    """
    hits: list[StringHit] = []
    if len(data) < min_length:
        return hits

    offset = 0
    while offset < len(data) and len(hits) < max_blobs:
        chunk = data[offset:offset + max_length]
        if len(chunk) < min_length:
            break
        entropy = shannon_entropy(chunk)
        printable = printable_ratio(chunk)
        if entropy >= threshold and printable < 0.82 and chunk.count(0) < len(chunk) * 0.8:
            hits.append(StringHit(base_ea + offset, chunk, "", "raw", "entropy"))
            offset += max_length // 2
        else:
            offset += step
    return hits


def data_ref_blob(data: bytes, ea: int, requested: int = 256, min_length: int = 4) -> tuple[int, bytes] | None:
    """Trim a referenced data blob at a sensible boundary.

    IDA often leaves encrypted blobs as undefined bytes.  Reading a fixed
    window catches those while cutting trailing BSS/zero padding.
    """
    if not data:
        return None
    # Prefer the first NUL-terminated run if that is still long enough.
    first_nul = data.find(b"\x00")
    if first_nul >= min_length:
        return ea, data[:first_nul]
    trimmed = data.rstrip(b"\x00")
    if len(trimmed) < min_length:
        return None
    return ea, trimmed[:requested]
