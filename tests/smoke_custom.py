from __future__ import annotations

import os
import shutil
import sys
import tempfile

from stringdecrypt.engine import Candidate, ScanConfig, StringDecryptEngine

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))
DECODER_DIR = os.path.join(HERE, "custom_decoders")
os.makedirs(DECODER_DIR, exist_ok=True)
DECODER_PATH = os.path.join(DECODER_DIR, "rot13.py")
with open(DECODER_PATH, "w", encoding="utf-8") as handle:
    handle.write(
        'from __future__ import annotations\n'
        'NAME = "rot13"\n'
        'DESCRIPTION = "test decoder"\n'
        "def decode(data: bytes) -> bytes:\n"
        "    out = bytearray(data)\n"
        "    for i, value in enumerate(out):\n"
        "        if 0x41 <= value <= 0x5A:\n"
        "            out[i] = (value - 0x41 + 13) % 26 + 0x41\n"
        "        elif 0x61 <= value <= 0x7A:\n"
        "            out[i] = (value - 0x61 + 13) % 26 + 0x61\n"
        "    return bytes(out)\n"
    )


def rot13(data: bytes) -> bytes:
    out = bytearray(data)
    for i, value in enumerate(out):
        if 0x41 <= value <= 0x5A:
            out[i] = (value - 0x41 + 13) % 26 + 0x41
        elif 0x61 <= value <= 0x7A:
            out[i] = (value - 0x61 + 13) % 26 + 0x61
    return bytes(out)


plain = b"Hello from the custom decoder!"
cipher = rot13(plain)

config = ScanConfig(
    min_score=55.0,
    custom_dirs=[DECODER_DIR],
    max_heavy_candidates=4,
    max_cipher_keys=8,
)
engine = StringDecryptEngine(config)
results = engine.scan_candidate(
    Candidate(ea=0x401000, raw=cipher, kind="string", text=cipher.decode("latin-1"))
)
for result in results:
    print(f"{result.scheme:12s} {result.score:6.2f} {result.plaintext!r} {result.pipeline}")

ok = any(result.scheme == "custom:rot13" and result.plaintext == plain.decode() for result in results)
print("PASS" if ok else "FAIL")

shutil.rmtree(DECODER_DIR, ignore_errors=True)
raise SystemExit(0 if ok else 1)
