from __future__ import annotations

import sys
import time

from stringdecrypt.peelf import image_candidates, load_binary

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

for path in sys.argv[1:]:
    started = time.time()
    image = load_binary(path)
    print(f"=== {path}")
    print(
        f"format={image.format} bits={image.bits} machine={image.machine} "
        f"type={image.file_type} base=0x{image.image_base:x} entry=0x{image.entry:x} "
        f"sections={len(image.sections)} imports={len(image.imports)}"
    )
    for section in image.sections[:12]:
        print(
            f"  {section.name:10s} va=0x{section.va:08x} vsize={section.vsize:8d} "
            f"off=0x{section.file_offset:08x} fsize={section.file_size:8d} "
            f"{'X' if section.executable else '-'}{'W' if section.writable else '-'}"
        )
    candidates = image_candidates(image, max_entropy_blobs=200)
    print(f"candidates={len(candidates)} elapsed={time.time() - started:.2f}s")
    for candidate in candidates[:8]:
        print(
            f"  {candidate.kind:7s} ea=0x{candidate.ea:x} seg={candidate.segment} "
            f"{candidate.preview(60)!r}"
        )
    print(f"imports: {image.imports[:5]}")
