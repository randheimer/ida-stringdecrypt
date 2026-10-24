from __future__ import annotations

import base64
import sys

from stringdecrypt import schemes, scoring
from stringdecrypt.purecrypto import aes, rc4

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


SAMPLES = [
    "Hello from the string decryptor!",
    "https://example.com/api/v1",
    "SecretConfigValue",
    r"C:\Windows\System32\kernel32.dll",
    r"Software\Microsoft\Windows\CurrentVersion",
    "Content-Type: application/json",
    '{"name": "test", "value": 42}',
    "SELECT * FROM users WHERE id = 1",
    "https://O|8ht\x7fi.Tcqr{:-8Ccalhu;|",
    "LoadLibrarypbh(P=vi`xy`onzZ9po|>",
    "cqm{vR$*|sdt\ni|%fvf[x{l6}4",
    "kernel32tg{ah&k=nby?k4{.u ",
    "\x01\x02\x03\x04\x05\x06\x07\x08",
    "0123456789abcdef0123456789abcdef",
    "m_difeebDZhl",
    "AVeg7kVTT",
    "SecretConfigValue",
    "VirtualAllocEx",
    "GetProcAddress",
    "jHYiAJnY_Adi",
    "ZIhLt_yK",
    "api-ms-win-core-process-threadsl1-1-0.dll",
    "dsl0pv0zlq0fruh0surfhvvwkuhdgv0o404031goo",
]

for sample in SAMPLES:
    print(f"{scoring.score_text(sample):6.2f} {sample!r}")

print("--- true transforms ---")
pt = b"https://example.com/api/v1"
data = schemes.xor_repeating(pt, b"KEY")
print("xorstr true", scoring.score_bytes(schemes.xor_repeating(data, b"KEY")))
xorct = schemes.xor_single(b"Hello from the string decryptor!", 0x5A)
print("xor true", scoring.score_bytes(schemes.xor_single(xorct, 0x5A)))
print("b64 true", scoring.score_bytes(base64.b64decode(base64.b64encode(b"http://example.com/api"))))
print("rc4 true", scoring.score_bytes(rc4.crypt(rc4.crypt(b"SecretConfigValue", b"Key123"), b"Key123")))
aespt = b"This is a secret!!"[:16]
aesct = aes.encrypt_ecb(aespt.ljust(16, b"."), b"0123456789abcdef")
print("aes true", scoring.score_bytes(aes.decrypt_ecb(aesct, b"0123456789abcdef")))
