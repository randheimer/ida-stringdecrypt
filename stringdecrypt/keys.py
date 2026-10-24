"""Key/IV candidate handling.

No attempt is made to brute-force AES/DES key space.  The engine tries keys
provided by the analyst and plausible keys found in the binary.
"""

from __future__ import annotations

import re
import string
from typing import Iterable

from .bytescan import printable_ratio


MAX_MATERIAL = 4096
MAX_KEY_LENGTH = 64

# Translation tables for the fast statistical XOR-key recovery.  Each table
# maps a ciphertext byte to 1 when (byte ^ candidate) is printable.  Doing this
# in bytes.translate() keeps the hot loop in C instead of Python.
_XOR_PRINTABLE = tuple(
    bytes(
        1 if (0x20 <= (value ^ candidate) <= 0x7E or (value ^ candidate) in (9, 10, 13)) else 0
        for value in range(256)
    )
    for candidate in range(256)
)


DEFAULT_CRIBS = [
    b"http://",
    b"https://",
    b"www.",
    b"MZ",
    b"PK\x03\x04",
    b"{\"",
    b"<?xml",
    b"SELECT ",
    b"INSERT ",
    b"HKEY_",
    b"C:\\",
    b"\\\\",
    b"System.",
    b"Microsoft",
    b"kernel32",
    b"VirtualAlloc",
    b"LoadLibrary",
    b"GetProcAddress",
    b"\\x00",
]


def _decode_escaped(value: str) -> bytes:
    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("x"):
            return chr(int(token[1:], 16))
        return {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "0": "\0",
            "\\": "\\",
            "\"": "\"",
            "'": "'",
        }.get(token, token)

    text = re.sub(r"\\(x[0-9a-fA-F]{2}|[nrt0\\\"'])", replace, value)
    return text.encode("latin-1", "ignore")


def parse_key_text(text: str) -> list[bytes]:
    """Parse a newline/comma separated key list.

    Accepted forms:
      0x41424344
      41424344
      hex:41 42 43 44
      ascii:secret
      secret
      \\x41\\x42\\x43
    """
    keys: list[bytes] = []
    seen: set[bytes] = set()

    for raw_line in re.split(r"[\r\n,]+", text or ""):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        candidates: list[bytes] = []
        lower = line.lower()
        if lower.startswith("ascii:"):
            candidates.append(line[6:].encode("latin-1", "ignore"))
        elif lower.startswith("hex:"):
            value = re.sub(r"[\s_:-]", "", line[4:])
            if len(value) % 2:
                value = "0" + value
            try:
                candidates.append(bytes.fromhex(value))
            except ValueError:
                pass
        elif lower.startswith("0x"):
            value = re.sub(r"[\s_:-]", "", line[2:])
            if len(value) % 2:
                value = "0" + value
            try:
                candidates.append(bytes.fromhex(value))
            except ValueError:
                pass
        elif "\\x" in line:
            candidates.append(_decode_escaped(line))
        else:
            compact = re.sub(r"[\s_:-]", "", line)
            if compact and len(compact) % 2 == 0 and all(ch in string.hexdigits for ch in compact):
                try:
                    candidates.append(bytes.fromhex(compact))
                except ValueError:
                    pass
            candidates.append(line.encode("latin-1", "ignore"))

        for key in candidates:
            if not key or len(key) > 256:
                continue
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def merge_material(*sources: Iterable[bytes], limit: int = MAX_MATERIAL) -> list[bytes]:
    material: list[bytes] = []
    seen: set[bytes] = set()
    for source in sources:
        for value in source:
            if not value or len(value) > 256 or value in seen:
                continue
            seen.add(value)
            material.append(value)
            if len(material) >= limit:
                return material
    return material


def material_rank(value: bytes) -> float:
    """Rank likely cryptographic keys above generic strings.

    The binary usually contains far more strings than keys, so the cipher
    limits must not simply take the first N values in file order.
    """
    length = len(value)
    if not 4 <= length <= 64:
        return -100.0
    printable = printable_ratio(value)
    score = printable * 12.0
    if 6 <= length <= 32:
        score += 6.0
    elif length <= 48:
        score += 2.0
    else:
        score -= 6.0
    if printable >= 0.9:
        try:
            text = value.decode("latin-1")
        except UnicodeDecodeError:
            text = ""
        if " " in text or "\t" in text or "\r" in text or "\n" in text:
            score -= 8.0
        if text.lower().startswith(("http://", "https://", "hkey_", "c:\\", "\\\\")):
            score -= 12.0
        if text.startswith(("?", "!")) or text.endswith((".", ":")):
            score -= 3.0
        has_alpha = any(ch.isalpha() for ch in text)
        has_digit = any(ch.isdigit() for ch in text)
        if has_alpha and has_digit:
            score += 4.0
        if text.isidentifier():
            score += 3.0
        if text.isupper() or text.islower():
            score += 1.0
    else:
        # Binary keys are legitimate, but prefer compact blobs.
        if length in (8, 16, 24, 32):
            score += 2.0
        if len(set(value)) < max(3, length // 3):
            score -= 4.0
    return score


def rank_material(material: Iterable[bytes], limit: int = MAX_MATERIAL) -> list[bytes]:
    values = merge_material(material, limit=limit)
    values.sort(key=material_rank, reverse=True)
    return values


def _dedupe_pairs(pairs: Iterable[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for label, value in pairs:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append((label, value))
    return result


def aes_keys(user_keys: Iterable[bytes], material: Iterable[bytes]) -> list[tuple[str, bytes]]:
    pairs: list[tuple[str, bytes]] = []
    for key in user_keys:
        if not key:
            continue
        length = len(key)
        if length == 16:
            pairs.append(("16", key))
        elif length == 24:
            pairs.append(("24", key))
        elif length == 32:
            pairs.append(("32", key))
        elif length < 16:
            pairs.append(("16", key.ljust(16, b"\x00")))
        elif length < 24:
            pairs.append(("24", key.ljust(24, b"\x00")))
            pairs.append(("16", key[:16]))
        elif length < 32:
            pairs.append(("32", key.ljust(32, b"\x00")))
            pairs.append(("24", key[:24]))
        else:
            pairs.append(("32", key[:32]))
            pairs.append(("24", key[:24]))
            pairs.append(("16", key[:16]))

    for key in material:
        if len(key) in (16, 24, 32):
            pairs.append((str(len(key)), key))
    return _dedupe_pairs(pairs)


def des_keys(user_keys: Iterable[bytes], material: Iterable[bytes]) -> list[tuple[str, bytes]]:
    pairs: list[tuple[str, bytes]] = []
    for key in user_keys:
        if key:
            pairs.append(("8", key.ljust(8, b"\x00")[:8]))
    for key in material:
        if len(key) == 8:
            pairs.append(("8", key))
    return _dedupe_pairs(pairs)


def rc4_keys(user_keys: Iterable[bytes], material: Iterable[bytes], limit: int = 512) -> list[bytes]:
    keys: list[bytes] = []
    seen: set[bytes] = set()
    for key in list(user_keys) + list(material):
        if not key or len(key) > 64 or key in seen:
            continue
        seen.add(key)
        keys.append(key)
        if len(keys) >= limit:
            break
    return keys


def iv_candidates(user_ivs: Iterable[bytes], material: Iterable[bytes], size: int) -> list[tuple[str, bytes]]:
    pairs: list[tuple[str, bytes]] = []
    zero = b"\x00" * size
    pairs.append(("zero", zero))
    for iv in user_ivs:
        if not iv:
            continue
        if len(iv) == size:
            pairs.append(("exact", iv))
        else:
            pairs.append(("pad", iv.ljust(size, b"\x00")[:size]))
    for value in material:
        if len(value) == size:
            pairs.append(("material", value))
    return _dedupe_pairs(pairs)


def repeating_xor_static(
    material: Iterable[bytes],
    *,
    limit: int = 192,
) -> list[bytes]:
    """Rank once-per-scan repeating-XOR key material.

    The engine calls :func:`repeating_xor_keys` for every candidate.  Ranking
    and sorting thousands of material values on every call dominated scan time,
    so the static part is prepared once and reused.
    """
    values = [
        value
        for value in merge_material(material, limit=MAX_MATERIAL)
        if 1 < len(value) <= MAX_KEY_LENGTH
    ]
    values.sort(key=lambda value: (-material_rank(value), len(value), value))
    return values[:max(1, int(limit))]


def repeating_xor_keys(
    data: bytes,
    material: Iterable[bytes],
    cribs: Iterable[bytes] | None = None,
    max_keys: int = 96,
    statistical: bool = True,
    static_keys: Iterable[bytes] | None = None,
) -> list[bytes]:
    keys: list[bytes] = []
    seen: set[bytes] = set()

    def add(key: bytes) -> None:
        if not key or len(key) > MAX_KEY_LENGTH or key in seen:
            return
        seen.add(key)
        keys.append(key)

    for key in (static_keys if static_keys is not None else material):
        if 1 < len(key) <= MAX_KEY_LENGTH:
            add(key)

    for crib in (cribs if cribs is not None else DEFAULT_CRIBS):
        if not crib or len(crib) > MAX_KEY_LENGTH:
            continue
        # A crib-derived key whose length is close to the data length would
        # merely translate the input into the crib; that is not evidence of a
        # real repeated-XOR string.  Require at least three repetitions.
        if len(data) < len(crib) + 8 or len(data) < 3 * len(crib):
            continue
        if len(data) >= len(crib):
            add(bytes(a ^ b for a, b in zip(data[:len(crib)], crib)))

    # Recover a key statistically for ASCII plaintext.  This is cheap and works
    # well for the common "XOR every byte with a compile-time key" pattern.
    if statistical and len(data) >= 12:
        max_len = min(6, len(data) // 3)
        for key_len in range(2, max_len + 1):
            key = bytearray()
            for column_index in range(key_len):
                column = data[column_index::key_len]
                total = len(column)
                if not total:
                    key.append(0)
                    continue
                best_key = 0
                best_value = -1.0
                for candidate in range(256):
                    good = column.translate(_XOR_PRINTABLE[candidate]).count(1)
                    score = good / total
                    # Prefer printable key bytes when plaintext score ties.
                    if 0x20 <= candidate <= 0x7E:
                        score += 0.002
                    if score > best_value:
                        best_value = score
                        best_key = candidate
                key.append(best_key)
            add(bytes(key))

    keys.sort(key=lambda item: (len(item), item))
    return keys[:max_keys]
