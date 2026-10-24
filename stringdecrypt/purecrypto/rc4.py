"""Pure-Python RC4."""

from __future__ import annotations


def crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")

    state = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + state[i] + key[i % key_len]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for index, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[index] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)
