"""Generate a tiny native PE64 with known encrypted strings.

Only used by the IDA integration test; the file has no imports and its entry
point merely references the embedded blobs so that IDA creates cross
references for them.
"""

from __future__ import annotations

import base64
import json
import os
import struct

from stringdecrypt.purecrypto import aes, des, rc4

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "ida_test_pe.exe")
EXPECTED = os.path.join(HERE, "ida_test_pe_expected.json")

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
TEXT_RAW = 0x200
RDATA_RAW = 0x400
RDATA_SIZE = 0x400

PLAIN = b"Hello from the string decryptor!"
XOR_PLAIN = b"https://example.com/api/v1"
XOR_KEY = 0x5A
B64_PLAIN = b"http://example.com/api"
RC4_PLAIN = b"SecretConfigValue"
AES_PLAIN = b"This is an AES encrypted message"
DES_PLAIN = b"des test payload"
PATH_PLAIN = b"C:\\Windows\\System32\\kernel32.dll"


def _xor(data: bytes, key: int) -> bytes:
    return bytes(value ^ key for value in data)


def _rc4_without_nul(plain: bytes) -> tuple[bytes, bytes]:
    for suffix in range(1000):
        key = f"SecretKey{suffix:03d}".encode("ascii")
        data = rc4.crypt(plain, key)
        if b"\x00" not in data:
            return data, key
    raise RuntimeError("no RC4 key produced NUL-free ciphertext")


def _aes_without_nul(plain: bytes) -> tuple[bytes, bytes]:
    for suffix in range(1000):
        key = f"AESKEY{suffix:010d}".encode("ascii")
        data = aes.encrypt_ecb(plain, key)
        if b"\x00" not in data:
            return data, key
    raise RuntimeError("no AES key produced NUL-free ciphertext")


def _des_without_nul(plain: bytes) -> tuple[bytes, bytes]:
    for suffix in range(1000):
        key = f"DESK{suffix:04d}".encode("ascii")
        data = des.encrypt_ecb(plain, key)
        if b"\x00" not in data:
            return data, key
    raise RuntimeError("no DES key produced NUL-free ciphertext")


def _place(buffer: bytearray, offset: int, data: bytes) -> int:
    ea = IMAGE_BASE + RDATA_RVA + offset
    buffer[offset:offset + len(data)] = data
    return ea


def build() -> dict:
    rdata = bytearray(RDATA_SIZE)
    rdata[0:len(PLAIN) + 1] = PLAIN + b"\x00"

    b64 = base64.b64encode(B64_PLAIN) + b"\x00"
    rdata[0x40:0x40 + len(b64)] = b64

    xor_data = _xor(XOR_PLAIN, XOR_KEY)
    rc4_data, rc4_key = _rc4_without_nul(RC4_PLAIN)
    aes_data, aes_key = _aes_without_nul(AES_PLAIN)
    des_data, des_key = _des_without_nul(DES_PLAIN)

    blobs = [
        (0x80, xor_data),
        (0xA0, rc4_data),
        (0xC0, aes_data),
        (0xE0, des_data),
    ]
    for offset, data in blobs:
        assert len(data) <= 0x20, (offset, len(data))
        rdata[offset:offset + len(data)] = data

    keys = [
        (0x100, rc4_key + b"\x00"),
        (0x120, aes_key + b"\x00"),
        (0x140, des_key + b"\x00"),
        (0x160, XOR_PLAIN + b"\x00"),
    ]
    for offset, data in keys:
        rdata[offset:offset + len(data)] = data

    path_offset = 0x180
    rdata[path_offset:path_offset + len(PATH_PLAIN) + 1] = PATH_PLAIN + b"\x00"

    names = {
        "plain": IMAGE_BASE + RDATA_RVA,
        "base64": IMAGE_BASE + RDATA_RVA + 0x40,
        "xor": IMAGE_BASE + RDATA_RVA + 0x80,
        "rc4": IMAGE_BASE + RDATA_RVA + 0xA0,
        "aes": IMAGE_BASE + RDATA_RVA + 0xC0,
        "des": IMAGE_BASE + RDATA_RVA + 0xE0,
        "rc4_key": IMAGE_BASE + RDATA_RVA + 0x100,
        "aes_key": IMAGE_BASE + RDATA_RVA + 0x120,
        "des_key": IMAGE_BASE + RDATA_RVA + 0x140,
        "path": IMAGE_BASE + RDATA_RVA + path_offset,
    }

    # Build code: a lea for every blob, one 8-byte immediate, then ret.
    code = bytearray()
    targets = [
        names["plain"],
        names["base64"],
        names["xor"],
        names["rc4"],
        names["aes"],
        names["des"],
    ]
    for target in targets:
        next_rva = TEXT_RVA + len(code) + 7
        displacement = target - (IMAGE_BASE + next_rva)
        code += b"\x48\x8D\x05" + struct.pack("<i", displacement)
    # mov r9, 0x4142434445464748 ("ABCDEFGH" little endian in memory)
    code += b"\x49\xB9" + struct.pack("<Q", 0x4142434445464748)
    code += b"\x48\x31\xC0\xC3"

    text = bytearray(0x200)
    text[0:len(code)] = code

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # machine
        2,  # sections
        0,  # timestamp
        0,  # symbol table
        0,  # symbols
        0xF0,  # optional header size
        0x0022,  # executable image | large address aware
    )

    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0x00, 0x20B)  # PE32+
    struct.pack_into("<B", optional, 0x02, 1)  # linker major
    struct.pack_into("<I", optional, 0x04, 0x200)  # size of code
    struct.pack_into("<I", optional, 0x08, 0x400)  # size of initialized data
    struct.pack_into("<I", optional, 0x0C, 0)  # size of uninitialized data
    struct.pack_into("<I", optional, 0x10, TEXT_RVA)  # entry point
    struct.pack_into("<I", optional, 0x14, TEXT_RVA)  # base of code
    struct.pack_into("<Q", optional, 0x18, IMAGE_BASE)
    struct.pack_into("<I", optional, 0x20, 0x1000)  # section alignment
    struct.pack_into("<I", optional, 0x24, 0x200)  # file alignment
    struct.pack_into("<H", optional, 0x28, 6)  # OS major
    struct.pack_into("<H", optional, 0x2A, 0)  # OS minor
    struct.pack_into("<H", optional, 0x2C, 0)  # image major
    struct.pack_into("<H", optional, 0x2E, 0)  # image minor
    struct.pack_into("<H", optional, 0x30, 6)  # subsystem major
    struct.pack_into("<H", optional, 0x32, 0)  # subsystem minor
    struct.pack_into("<I", optional, 0x34, 0)  # win32 version
    struct.pack_into("<I", optional, 0x38, 0x3000)  # size of image
    struct.pack_into("<I", optional, 0x3C, 0x200)  # size of headers
    struct.pack_into("<H", optional, 0x44, 3)  # console subsystem
    struct.pack_into("<Q", optional, 0x48, 0x100000)  # stack reserve
    struct.pack_into("<Q", optional, 0x50, 0x1000)  # stack commit
    struct.pack_into("<Q", optional, 0x58, 0x100000)  # heap reserve
    struct.pack_into("<Q", optional, 0x60, 0x1000)  # heap commit
    struct.pack_into("<I", optional, 0x68, 0)  # loader flags
    struct.pack_into("<I", optional, 0x6C, 16)  # number of directories

    sections = bytearray()
    sections += struct.pack(
        "<8sIIIIIIHHI",
        b".text", 0x200, TEXT_RVA, 0x200, TEXT_RAW, 0, 0, 0, 0, 0x60000020
    )
    sections += struct.pack(
        "<8sIIIIIIHHI",
        b".rdata", RDATA_SIZE, RDATA_RVA, RDATA_SIZE, RDATA_RAW, 0, 0, 0, 0, 0x40000040
    )

    pe = bytearray(0x800)
    pe[0:0x80] = dos
    pe[0x80:0x84] = b"PE\x00\x00"
    pe[0x84:0x84 + len(coff)] = coff
    pe[0x98:0x98 + len(optional)] = optional
    pe[0x188:0x188 + len(sections)] = sections
    pe[TEXT_RAW:TEXT_RAW + len(text)] = text
    pe[RDATA_RAW:RDATA_RAW + len(rdata)] = rdata

    with open(OUTPUT, "wb") as handle:
        handle.write(pe)

    expected = {
        "path": OUTPUT,
        "image_base": IMAGE_BASE,
        "addresses": names,
        "plaintexts": {
            "plain": PLAIN.decode(),
            "base64": B64_PLAIN.decode(),
            "xor": XOR_PLAIN.decode(),
            "rc4": RC4_PLAIN.decode(),
            "aes": AES_PLAIN.decode(),
            "des": DES_PLAIN.decode(),
            "path": PATH_PLAIN.decode(),
        },
        "keys": {
            "xor": f"{XOR_KEY:02x}",
            "rc4": rc4_key.decode(),
            "aes": aes_key.decode(),
            "des": des_key.decode(),
        },
        "cipher_lengths": {
            "xor": len(xor_data),
            "rc4": len(rc4_data),
            "aes": len(aes_data),
            "des": len(des_data),
        },
    }
    with open(EXPECTED, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(expected, handle, indent=2)
        handle.write("\n")
    return expected


if __name__ == "__main__":
    info = build()
    print(json.dumps(info, indent=2))
