"""Disabled ROT13 example decoder.

Rename this file to ``rot13.py`` (without the leading underscore) to activate
it.  ROT13 is included only as a template; real malware rarely uses it.
"""

from __future__ import annotations

NAME = "rot13"
DESCRIPTION = "ROT13 for ASCII letters (example custom decoder)"


def decode(data: bytes) -> bytes:
    output = bytearray(data)
    for index, value in enumerate(output):
        if 0x41 <= value <= 0x5A:
            output[index] = (value - 0x41 + 13) % 26 + 0x41
        elif 0x61 <= value <= 0x7A:
            output[index] = (value - 0x61 + 13) % 26 + 0x61
    return bytes(output)
