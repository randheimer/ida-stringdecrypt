from __future__ import annotations

import base64
import sys
import time

from stringdecrypt import schemes
from stringdecrypt.engine import Candidate, ScanConfig, StringDecryptEngine
from stringdecrypt.purecrypto import aes, des, rc4

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


def run(name: str, data: bytes, material: list[bytes] | None = None, kind: str = "data") -> None:
    config = ScanConfig(
        key_material=list(material or []),
        max_heavy_candidates=10,
        max_cipher_keys=24,
        min_score=55.0,
    )
    engine = StringDecryptEngine(config)
    candidate = Candidate(ea=0x1000, raw=data, kind=kind, text="")
    started = time.time()
    results = engine.scan_candidate(candidate)
    elapsed = time.time() - started
    print(f"--- {name}: {elapsed:.3f}s, {len(results)} results")
    for result in results[:6]:
        print(
            "   ",
            f"{result.scheme:8s}",
            f"{result.score:6.2f}",
            repr(result.plaintext[:80]),
            result.key_display(),
            result.pipeline,
        )


aes_plain = b"This is an AES encrypted message."
aes_key = b"0123456789abcdef"
aes_plain = aes_plain + b"." * ((-len(aes_plain)) % 16)
run("aes-ecb", aes.encrypt_ecb(aes_plain, aes_key), [aes_key])

des_plain = b"Secret!!"
des_key = b"12345678"
run("des-ecb", des.encrypt_ecb(des_plain, des_key), [des_key])

rc4_key = b"Key123"
rc4_plain = b"SecretConfigValue"
run("rc4", rc4.crypt(rc4_plain, rc4_key), [rc4_key])

xor_plain = b"Hello from the string decryptor!"
run("xor", schemes.xor_single(xor_plain, 0x5A))

xorstr_plain = b"https://example.com/api/v1"
run("xorstr", schemes.xor_repeating(xorstr_plain, b"KEY"), [b"KEY"])

b64_plain = b"http://example.com/api"
run("base64", base64.b64encode(b64_plain))

run("false-printable", b"cqm{vR$*|sdt\ni|%fvf[x{l6}4", [], kind="string")
run("false-random", bytes(range(1, 40)), [], kind="entropy")
