"""Command-line interface for the native string decryptor.

Designed to be consumed by both humans and automation:

    python -m stringdecrypt.cli scan sample.exe --format json

The JSON schema is stable and includes file metadata, sections, scan stats and
one object per decrypted candidate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import Sequence

from . import __version__, intel, keys, peelf
from .engine import ScanConfig, StringDecryptEngine


def _split_list(values: Sequence[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def _read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _apply_schemes(config: ScanConfig, schemes: list[str]) -> None:
    if not schemes:
        return
    requested = {value.lower() for value in schemes}
    if "all" in requested:
        return
    config.enable_base64 = "base64" in requested or "b64" in requested
    config.enable_xor = "xor" in requested
    config.enable_xorstr = "xor" in requested or "xorstr" in requested
    config.enable_add = "add" in requested
    config.enable_sub = "sub" in requested
    config.enable_rol = "rol" in requested
    config.enable_rc4 = "rc4" in requested
    config.enable_aes = "aes" in requested
    config.enable_des = "des" in requested
    config.enable_custom = "custom" in requested or "all" in requested
    heavy = any(name in requested for name in ("rc4", "aes", "des"))
    if not heavy and not config.force_heavy:
        config.max_cipher_keys = 0
    if not heavy:
        config.enable_heavy = False


def _confidence(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    if score >= 55:
        return "low"
    return "very_low"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stringdecrypt",
        description="Native PE/ELF string and ciphertext scanner (IDA-independent CLI).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a native PE or ELF file")
    scan.add_argument("file", help="path to a native PE/ELF binary")
    scan.add_argument("--format", choices=("json", "text", "jsonl"), default="json")
    scan.add_argument("--output", "-o", help="write output to this file")
    scan.add_argument("--min-score", type=float, default=60.0)
    scan.add_argument("--min-length", type=int, default=5)
    scan.add_argument("--max-results", type=int, default=2000)
    scan.add_argument("--max-candidates", type=int, default=30000)
    scan.add_argument("--max-input", type=int, default=8192)
    scan.add_argument("--schemes", action="append", help="comma list: base64,xor,xorstr,add,sub,rol,rc4,aes,des,custom")
    scan.add_argument("--no-base64", action="store_true")
    scan.add_argument("--no-xor", action="store_true")
    scan.add_argument("--no-xorstr", action="store_true")
    scan.add_argument("--no-add", action="store_true")
    scan.add_argument("--no-sub", action="store_true")
    scan.add_argument("--no-rol", action="store_true")
    scan.add_argument("--no-rc4", action="store_true")
    scan.add_argument("--no-aes", action="store_true")
    scan.add_argument("--no-des", action="store_true")
    scan.add_argument("--no-heavy", action="store_true", help="skip RC4/AES/DES")
    scan.add_argument("--no-entropy", action="store_true", help="do not scan high-entropy blobs")
    scan.add_argument("--no-intel", action="store_true", help="skip IOC/behavior tags in the output")
    scan.add_argument("--include-code", action="store_true", help="also extract strings from executable sections")
    scan.add_argument("--force-heavy", action="store_true", help="run keyed ciphers on every candidate")
    scan.add_argument("--keys", action="append", help="key(s), comma separated; prefixes ascii:, hex:, 0x")
    scan.add_argument("--key-file", help="file with one key per line")
    scan.add_argument("--ivs", action="append", help="IV(s), comma separated")
    scan.add_argument("--iv-file", help="file with one IV per line")
    scan.add_argument("--cribs", action="append", help="known-plaintext crib(s), comma separated")
    scan.add_argument("--crib-file", help="file with one crib per line")
    scan.add_argument("--custom-dir", action="append", help="extra directory with custom decoder modules")
    scan.add_argument("--no-custom", action="store_true")
    scan.add_argument("--max-entropy-blobs", type=int, default=2048)
    scan.add_argument(
        "--timeout",
        dest="timeout_seconds",
        type=float,
        default=0,
        metavar="SECONDS",
        help="stop the scan with partial results after this many seconds (0 = no limit)",
    )
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--pretty", action="store_true", default=True)
    return parser


def _build_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig(
        min_length=max(2, args.min_length),
        min_score=args.min_score,
        max_input_length=args.max_input,
        max_total_results=args.max_results,
        max_entropy_blobs=getattr(args, "max_entropy_blobs", 2048),
        force_heavy=args.force_heavy,
    )
    config.enable_base64 = not args.no_base64
    config.enable_xor = not args.no_xor
    config.enable_xorstr = not args.no_xorstr
    config.enable_add = not args.no_add
    config.enable_sub = not args.no_sub
    config.enable_rol = not args.no_rol
    config.enable_rc4 = not args.no_rc4
    config.enable_aes = not args.no_aes
    config.enable_des = not args.no_des
    config.enable_heavy = not args.no_heavy
    config.enable_custom = not args.no_custom

    scheme_list = _split_list(args.schemes)
    _apply_schemes(config, scheme_list)

    key_text = "\n".join(args.keys or [])
    if args.key_file:
        key_text += "\n" + _read_text_file(args.key_file)
    iv_text = "\n".join(args.ivs or [])
    if args.iv_file:
        iv_text += "\n" + _read_text_file(args.iv_file)
    crib_text = "\n".join(args.cribs or [])
    if args.crib_file:
        crib_text += "\n" + _read_text_file(args.crib_file)
    config.key_text = key_text
    config.iv_text = iv_text
    config.crib_text = crib_text
    config.custom_dirs = list(args.custom_dir or [])
    config.prepare()
    return config


def _scan_file(path: str, args: argparse.Namespace) -> dict:
    started = time.time()
    timeout_seconds = float(getattr(args, "timeout_seconds", 0) or 0)
    # ScanConfig.deadline is monotonic; wall-clock time cannot be compared to
    # time.monotonic().
    deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
    enrich = not bool(getattr(args, "no_intel", False))

    image = peelf.load_binary(path)
    candidates = peelf.image_candidates(
        image,
        min_length=max(2, args.min_length),
        include_entropy=not args.no_entropy,
        include_code_strings=args.include_code,
        max_entropy_blobs=args.max_entropy_blobs,
    )
    if len(candidates) > args.max_candidates:
        candidates = candidates[:args.max_candidates]
    config = _build_config(args)
    config.deadline = deadline

    # Imports and section names are excellent key material; candidate strings
    # are appended as generators so a huge string table does not create a
    # second material list before merge_material() hits its limit.
    material_imports: list[bytes] = []
    for imported in image.imports:
        material_imports.append(imported.encode("latin-1", "ignore"))
        for part in imported.replace("!", ".").split("."):
            if part:
                material_imports.append(part.encode("latin-1", "ignore"))
    material_sections = [
        section.name.encode("latin-1", "ignore")
        for section in image.sections
        if section.name
    ]
    config.key_material = keys.merge_material(
        config.key_material,
        material_imports,
        material_sections,
        (candidate.raw for candidate in candidates if 1 <= len(candidate.raw) <= 64),
        (candidate.text.encode("latin-1", "ignore") for candidate in candidates if candidate.text),
        limit=4096,
    )

    engine = StringDecryptEngine(config)
    results = engine.scan_candidates(candidates)
    elapsed = time.time() - started

    intel_tags: Counter[str] = Counter()
    intel_entities: Counter[str] = Counter()
    intel_risks: Counter[str] = Counter()
    intel_tagged = 0
    output_results = []
    for result in results:
        data = result.to_dict()
        data["id"] = intel.string_id(result.candidate.ea, result.plaintext)
        data["confidence"] = _confidence(result.score)
        data["section"] = result.candidate.segment
        data["source"] = result.candidate.source
        if enrich:
            intelligence = intel.analyze_text(result.plaintext)
            data["tags"] = list(intelligence.tags)
            data["entities"] = intelligence.entities_dict()
            data["risk"] = intelligence.risk
            if intelligence.tags:
                intel_tagged += 1
            intel_tags.update(intelligence.tags)
            intel_entities.update(intelligence.entities.keys())
            intel_risks[intelligence.risk] += 1
        output_results.append(data)

    scheme_counts = Counter(result.scheme for result in results)
    total_elapsed = time.time() - started
    payload = {
        "tool": "ida-stringdecrypt",
        "version": __version__,
        "ok": True,
        "file": image.path,
        "sha256": image.sha256,
        "image": image.to_dict(),
        "config": {
            "min_score": config.min_score,
            "min_length": config.min_length,
            "max_input_length": config.max_input_length,
            "max_results": config.max_total_results,
            "schemes": {
                "base64": config.enable_base64,
                "xor": config.enable_xor,
                "xorstr": config.enable_xorstr,
                "add": config.enable_add,
                "sub": config.enable_sub,
                "rol": config.enable_rol,
                "rc4": config.enable_rc4,
                "aes": config.enable_aes,
                "des": config.enable_des,
                "custom": config.enable_custom,
            },
            "force_heavy": config.force_heavy,
            "enrich": enrich,
            "timeout_seconds": timeout_seconds or None,
        },
        "stats": {
            "candidates": len(candidates),
            "strings": sum(1 for candidate in candidates if candidate.kind == "string"),
            "entropy_blobs": sum(1 for candidate in candidates if candidate.kind == "entropy"),
            "results": len(results),
            "schemes": dict(sorted(scheme_counts.items())),
            "elapsed_seconds": round(elapsed, 3),
            "total_elapsed_seconds": round(total_elapsed, 3),
            "timed_out": bool(getattr(engine, "expired", False)),
        },
        "results": output_results,
    }
    if enrich:
        payload["intel"] = {
            "tagged_strings": intel_tagged,
            "tags": dict(intel_tags.most_common(50)),
            "entity_types": dict(
                sorted(intel_entities.items(), key=lambda item: (-item[1], item[0]))
            ),
            "risks": dict(sorted(intel_risks.items())),
        }
    return payload


def scan_path(
    path: str,
    *,
    min_score: float = 60.0,
    min_length: int = 5,
    max_results: int = 2000,
    max_candidates: int = 30000,
    max_input: int = 8192,
    max_entropy_blobs: int = 2048,
    schemes: Sequence[str] | None = None,
    keys: Sequence[str] | None = None,
    ivs: Sequence[str] | None = None,
    cribs: Sequence[str] | None = None,
    custom_dirs: Sequence[str] | None = None,
    include_entropy: bool = True,
    include_code: bool = False,
    force_heavy: bool = False,
    heavy: bool = True,
    custom: bool = True,
    timeout_seconds: float | None = None,
    enrich: bool = True,
) -> dict:
    """Programmatic equivalent of ``stringdecrypt scan --format json``.

    Used by the MCP server and other integrations.  Raises ``OSError`` or
    ``peelf.BinaryParseError`` for unusable inputs.
    """
    args = argparse.Namespace(
        min_length=max(2, int(min_length)),
        min_score=float(min_score),
        max_results=max(1, int(max_results)),
        max_candidates=max(1, int(max_candidates)),
        max_input=max(16, int(max_input)),
        max_entropy_blobs=max(0, int(max_entropy_blobs)),
        no_entropy=not include_entropy,
        include_code=bool(include_code),
        no_base64=False,
        no_xor=False,
        no_xorstr=False,
        no_add=False,
        no_sub=False,
        no_rol=False,
        no_rc4=False,
        no_aes=False,
        no_des=False,
        no_heavy=not heavy,
        no_custom=not custom,
        no_intel=not enrich,
        force_heavy=bool(force_heavy),
        timeout_seconds=timeout_seconds or 0,
        schemes=[",".join(schemes)] if schemes else None,
        keys=list(keys or []),
        key_file=None,
        ivs=list(ivs or []),
        iv_file=None,
        cribs=list(cribs or []),
        crib_file=None,
        custom_dir=list(custom_dirs or []),
        quiet=True,
        pretty=True,
        format="json",
    )
    return _scan_file(path, args)


def _print_text(payload: dict) -> None:
    if not payload.get("ok"):
        print(f"error: {payload.get('error')}", file=sys.stderr)
        return
    image = payload["image"]
    print(f"{payload['file']} ({image['format']} {image['machine']} {image['bits']}-bit)")
    print(f"{len(image['sections'])} sections, {image['imports'] and len(image['imports']) or 0} imports")
    stats = payload["stats"]
    print(
        f"{stats['candidates']} candidates -> {stats['results']} results "
        f"in {stats['elapsed_seconds']}s"
    )
    print()
    for result in payload["results"]:
        key = f" key={result['key']}" if result.get("key") else ""
        tags = f" [{'|'.join(result.get('tags', []))}]" if result.get("tags") else ""
        print(
            f"{result['address']:>12s} {result['scheme']:9s} {result['score']:6.2f} "
            f"{result['confidence']:8s} {result['plaintext']!r}{tags}{key}"
        )
    if not payload["results"]:
        print("(no results)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Windows consoles often default to cp1252, which cannot encode arbitrary
    # recovered plaintext.  JSON output must stay valid UTF-8.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass
    if args.command != "scan":
        parser.error("unknown command")

    try:
        payload = _scan_file(args.file, args)
    except (OSError, peelf.BinaryParseError) as error:
        payload = {
            "tool": "ida-stringdecrypt",
            "version": __version__,
            "ok": False,
            "file": os.path.abspath(args.file),
            "error": str(error),
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    elif args.format == "jsonl":
        lines = [json.dumps({key: value for key, value in payload.items() if key != "results"}, ensure_ascii=False)]
        lines.extend(json.dumps(result, ensure_ascii=False) for result in payload["results"])
        text = "\n".join(lines)
    else:
        _print_text(payload)
        text = ""

    if args.output and text:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.write("\n")
        if not args.quiet:
            print(f"wrote {args.output}", file=sys.stderr)
    elif text:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
