"""Pure-Python AES (ECB/CBC) used by the string decryptor.

This module intentionally has no third-party dependencies.  It implements the
standard AES block cipher for 128/192/256-bit keys and only the decryption
paths needed by the plugin (encryption is included so the implementation can be
verified against known-answer vectors).
"""

from __future__ import annotations

from functools import lru_cache


# ---------------------------------------------------------------------------
# AES constants / S-box construction
# ---------------------------------------------------------------------------

RCON = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
    0x6C000000,
    0xD8000000,
    0xAB000000,
    0x4D000000,
]


def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv = [0] * 256

    p = 1
    q = 1
    while True:
        # p walks the multiplicative group, q is its inverse, both in GF(2^8).
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09

        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break

    sbox[0] = 0x63
    for i, value in enumerate(sbox):
        inv[value] = i
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


MUL2 = [_gmul(i, 2) for i in range(256)]
MUL3 = [_gmul(i, 3) for i in range(256)]
MUL9 = [_gmul(i, 9) for i in range(256)]
MUL11 = [_gmul(i, 11) for i in range(256)]
MUL13 = [_gmul(i, 13) for i in range(256)]
MUL14 = [_gmul(i, 14) for i in range(256)]


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------

@lru_cache(maxsize=256)
def _expand_key(key: bytes) -> tuple[list[int], int]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]

    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= (RCON[i // nk] >> 24) & 0xFF
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

    round_keys: list[int] = []
    for word in words:
        round_keys.extend(word)
    return round_keys, nr


# ---------------------------------------------------------------------------
# Round primitives
# ---------------------------------------------------------------------------

def _add_round_key(state: list[int], round_keys: list[int], offset: int) -> None:
    for i in range(16):
        state[i] ^= round_keys[offset + i]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state: list[int]) -> list[int]:
    s = state
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]


def _inv_shift_rows(state: list[int]) -> list[int]:
    s = state
    return [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]


def _mix_columns(state: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]
        state[i + 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        state[i + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        state[i + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        state[i + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]


def _inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]
        state[i + 0] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3]
        state[i + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3]
        state[i + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3]
        state[i + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3]


# ---------------------------------------------------------------------------
# Public block API
# ---------------------------------------------------------------------------

def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys, nr = _expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys, 0)
    for rnd in range(1, nr):
        _sub_bytes(state)
        state = _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys, rnd * 16)
    _sub_bytes(state)
    state = _shift_rows(state)
    _add_round_key(state, round_keys, nr * 16)
    return bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys, nr = _expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys, nr * 16)
    for rnd in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys, rnd * 16)
        _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys, 0)
    return bytes(state)


def _check_data(data: bytes) -> None:
    if len(data) % 16:
        raise ValueError("AES data length must be a multiple of 16")


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    _check_data(data)
    return b"".join(decrypt_block(data[i:i + 16], key) for i in range(0, len(data), 16))


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    _check_data(data)
    return b"".join(encrypt_block(data[i:i + 16], key) for i in range(0, len(data), 16))


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    _check_data(data)
    if len(iv) != 16:
        raise ValueError("AES CBC IV must be 16 bytes")
    out = bytearray()
    previous = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = decrypt_block(block, key)
        out.extend(a ^ b for a, b in zip(plain, previous))
        previous = block
    return bytes(out)


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    _check_data(data)
    if len(iv) != 16:
        raise ValueError("AES CBC IV must be 16 bytes")
    out = bytearray()
    previous = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], previous))
        encrypted = encrypt_block(block, key)
        out.extend(encrypted)
        previous = encrypted
    return bytes(out)
