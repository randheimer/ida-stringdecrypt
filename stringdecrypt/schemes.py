"""Byte transforms, encodings, and cipher wrappers."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Iterable

from .purecrypto import aes, des, rc4
from .scoring import looks_like_base64_text


def xor_single(data: bytes, key: int) -> bytes:
    key &= 0xFF
    return bytes(value ^ key for value in data)


def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes(value ^ key[index % key_len] for index, value in enumerate(data))


def add_bytes(data: bytes, key: int) -> bytes:
    key &= 0xFF
    return bytes((value + key) & 0xFF for value in data)


def sub_bytes(data: bytes, key: int) -> bytes:
    key &= 0xFF
    return bytes((value - key) & 0xFF for value in data)


def rsub_bytes(data: bytes, key: int) -> bytes:
    key &= 0xFF
    return bytes((key - value) & 0xFF for value in data)


def rotl8(value: int, shift: int) -> int:
    shift %= 8
    if shift == 0:
        return value & 0xFF
    value &= 0xFF
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def rotr8(value: int, shift: int) -> int:
    shift %= 8
    if shift == 0:
        return value & 0xFF
    value &= 0xFF
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def rol_bytes(data: bytes, shift: int) -> bytes:
    return bytes(rotl8(value, shift) for value in data)


def ror_bytes(data: bytes, shift: int) -> bytes:
    return bytes(rotr8(value, shift) for value in data)


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    return rc4.crypt(data, key)


def aes_decrypt(data: bytes, key: bytes, mode: str, iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        return aes.decrypt_ecb(data, key)
    if mode == "CBC":
        if iv is None:
            iv = b"\x00" * 16
        return aes.decrypt_cbc(data, key, iv)
    raise ValueError(f"unknown AES mode: {mode}")


def des_decrypt(data: bytes, key: bytes, mode: str, iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        return des.decrypt_ecb(data, key)
    if mode == "CBC":
        if iv is None:
            iv = b"\x00" * 8
        return des.decrypt_cbc(data, key, iv)
    raise ValueError(f"unknown DES mode: {mode}")


def block_variants(data: bytes, block_size: int) -> list[tuple[str, bytes]]:
    if not data:
        return []
    remainder = len(data) % block_size
    if remainder == 0:
        return [("aligned", data)]

    variants: list[tuple[str, bytes]] = [
        ("zero-pad", data + b"\x00" * (block_size - remainder)),
    ]
    trimmed = data[:len(data) - remainder]
    if len(trimmed) >= block_size:
        variants.append(("trim", trimmed))
    return variants


def _printable_prefix_length(data: bytes) -> int:
    length = 0
    for value in data:
        if 0x20 <= value <= 0x7E or value in (9, 10, 13):
            length += 1
        else:
            break
    return length


def text_variants(data: bytes) -> list[tuple[str, bytes]]:
    """Plaintext variants that cut trailing binary data.

    A decrypted blob is often followed by unrelated bytes in the same data
    window.  Scoring the whole window would hide a valid plaintext prefix.
    """
    if not data:
        return []
    variants: list[tuple[str, bytes]] = [("raw", data)]
    prefix = _printable_prefix_length(data)
    if 4 <= prefix < len(data):
        variants.append(("text-prefix", data[:prefix]))

    # UTF-16LE plaintext followed by binary data.
    if len(data) >= 8 and data[1::2].count(0) >= len(data[1::2]) * 0.8:
        end = 0
        while end + 1 < len(data):
            low, high = data[end], data[end + 1]
            if high == 0 and (0x20 <= low <= 0x7E or low in (9, 10, 13)):
                end += 2
            else:
                break
        if end >= 8 and end < len(data):
            variants.append(("utf16le-prefix", data[:end]))

    seen: set[bytes] = set()
    unique: list[tuple[str, bytes]] = []
    for label, value in variants:
        if value in seen:
            continue
        seen.add(value)
        unique.append((label, value))
    return unique


def unpad_variants(data: bytes, block_size: int = 16) -> list[tuple[str, bytes]]:
    if not data:
        return []
    variants: list[tuple[str, bytes]] = [("raw", data)]

    # A referenced blob may contain the real ciphertext followed by unrelated
    # bytes.  Try short block-aligned prefixes; string plaintexts are normally
    # short, so the first few blocks cover the useful cases without exploding
    # the number of scored candidates.
    block_count = len(data) // block_size
    for blocks in range(1, min(block_count, 4) + 1):
        prefix = data[:blocks * block_size]
        if len(prefix) < len(data):
            variants.append((f"prefix{blocks}b", prefix))

    prefix = _printable_prefix_length(data)
    if 4 <= prefix < len(data):
        variants.append(("text-prefix", data[:prefix]))

    if data and 1 <= data[-1] <= block_size:
        pad = data[-1]
        if len(data) >= pad and data[-pad:] == bytes([pad]) * pad:
            variants.append(("pkcs7", data[:-pad]))

    trimmed = data.rstrip(b"\x00")
    if trimmed != data and len(trimmed) >= 2:
        variants.append(("zero-trim", trimmed))

    # Some binaries pad with a repeated printable byte ('.', ' ', '#', ...).
    if len(data) >= 6 and data[-1] not in (0x00, 0x0A, 0x0D, 0x09):
        char_trimmed = data.rstrip(bytes([data[-1]]))
        if char_trimmed != data and len(char_trimmed) >= 4:
            variants.append(("char-trim", char_trimmed))

    first_nul = data.find(b"\x00")
    if 2 <= first_nul < len(data) - 1:
        variants.append(("cstr", data[:first_nul]))

    seen: set[bytes] = set()
    unique: list[tuple[str, bytes]] = []
    for label, value in variants:
        if value in seen:
            continue
        seen.add(value)
        unique.append((label, value))
    return unique


def base64_variants(data: bytes) -> list[tuple[str, bytes]]:
    """Decode Base64, including truncated/unpadded inputs."""
    cleaned = re.sub(rb"\s+", b"", data)
    if not cleaned:
        return []
    cleaned = cleaned.replace(b"-", b"+").replace(b"_", b"/")

    candidates: list[bytes] = []
    if len(cleaned) % 4 == 1:
        candidates.append(cleaned[:-1])
    candidates.append(cleaned)

    decoded: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for candidate in candidates:
        if not candidate:
            continue
        padded = candidate + b"=" * ((-len(candidate)) % 4)
        for label, value in (("normal", candidate), ("padded", padded)):
            try:
                result = base64.b64decode(value, validate=False)
            except (binascii.Error, ValueError):
                continue
            if not result or result in seen:
                continue
            seen.add(result)
            decoded.append((label if len(candidates) == 1 else label + "-trunc", result))
    return decoded


def is_base64_candidate(data: bytes) -> bool:
    try:
        return looks_like_base64_text(data.decode("ascii"))
    except UnicodeDecodeError:
        return False


def dedupe_bytes(values: Iterable[bytes]) -> list[bytes]:
    result: list[bytes] = []
    seen: set[bytes] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
