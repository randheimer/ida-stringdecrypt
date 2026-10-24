"""Real-binary scan profile for the default UI settings.

Run through ``idat.exe -A -S"tests/ida_real_scan.py" notepad.exe``.  It does
not modify the database; it only reports timings, candidate statistics and
result quality.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
INSTALL_DIR = os.path.join(
    os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "plugins", "ida_stringdecrypt"
)
for path in (INSTALL_DIR, PROJECT):
    if path and path not in sys.path:
        sys.path.insert(0, path)

REPORT_PATH = os.path.join(HERE, "ida_real_report.json")
report = {"ok": False, "steps": []}


def step(name, function):
    try:
        detail = function()
        report["steps"].append({"name": name, "ok": True, "detail": str(detail)[:2000]})
        print(f"[PASS] {name}: {detail}")
        return detail
    except Exception:  # noqa: BLE001
        detail = traceback.format_exc()
        report["steps"].append({"name": name, "ok": False, "detail": detail})
        print(f"[FAIL] {name}\n{detail}")
        return None


import ida_auto  # noqa: E402
import ida_bytes  # noqa: E402
import ida_nalt  # noqa: E402
import idc  # noqa: E402
import cProfile  # noqa: E402
import pstats  # noqa: E402


def probe_utf16() -> str:
    import idautils
    import ida_nalt

    samples = []
    for item in idautils.Strings():
        try:
            bpu = ida_nalt.get_strtype_bpu(item.strtype)
            if bpu != 2:
                continue
            raw = ida_bytes.get_bytes(item.ea, min(max(item.length, 16), 64))
            samples.append(
                {
                    "ea": f"0x{item.ea:x}",
                    "length": item.length,
                    "text_chars": len(str(item)),
                    "raw_head": raw[:24].hex(),
                    "text": str(item)[:40],
                }
            )
            if len(samples) >= 5:
                break
        except Exception:
            continue
    report["utf16_samples"] = samples
    return f"{len(samples)} UTF-16 samples"


def collect() -> str:
    from ida_stringdecrypt_pkg import ida_scan

    options = ida_scan.IdaScanOptions(
        min_length=5,
        max_entropy_blobs=512,
        max_candidates=8000,
    )
    started = time.time()
    candidates, stats = ida_scan.collect_candidates(options)
    elapsed = time.time() - started
    report["collection_seconds"] = round(elapsed, 2)
    report["candidate_count"] = len(candidates)
    report["collection_stats"] = stats.as_text()
    report["kind_counts"] = {}
    for candidate in candidates:
        report["kind_counts"][candidate.kind] = (
            report["kind_counts"].get(candidate.kind, 0) + 1
        )
    return f"{len(candidates)} candidates in {elapsed:.1f}s ({stats.as_text()})"


def scan() -> str:
    from ida_stringdecrypt_pkg import ida_scan
    from ida_stringdecrypt_pkg.engine import ScanConfig, StringDecryptEngine

    started = time.time()
    candidates, _stats = ida_scan.collect_candidates(
        ida_scan.IdaScanOptions(min_length=5, max_entropy_blobs=512, max_candidates=8000)
    )
    material = ida_scan.collect_key_material(candidates)
    key_seconds = time.time() - started

    config = ScanConfig(
        min_length=5,
        min_score=60.0,
        max_total_results=5000,
        max_heavy_candidates=400,
        max_entropy_blobs=512,
        enable_heavy=True,
        enable_custom=True,
        force_heavy=False,
        key_material=material,
    )
    engine = StringDecryptEngine(config)
    started = time.time()
    profiler = cProfile.Profile()
    profiler.enable()
    results = engine.scan_candidates(
        candidates,
        progress=lambda done, total: print(f"  scan {done}/{total}", flush=True)
        if done % 500 == 0
        else None,
    )
    profiler.disable()
    elapsed = time.time() - started
    stats_path = os.path.join(HERE, "ida_real_profile.txt")
    with open(stats_path, "w", encoding="utf-8", newline="\n") as handle:
        pstats.Stats(profiler, stream=handle).sort_stats("cumulative").print_stats(30)
    report["profile"] = stats_path
    report["cipher_ops"] = engine._cipher_ops
    report["heavy_candidates"] = engine._heavy_candidates
    counts = {}
    for result in results:
        counts[result.scheme] = counts.get(result.scheme, 0) + 1
    report["key_material"] = len(material)
    report["key_seconds"] = round(key_seconds, 2)
    report["scan_seconds"] = round(elapsed, 2)
    report["result_count"] = len(results)
    report["scheme_counts"] = counts
    report["results"] = [
        {
            "ea": f"0x{result.candidate.ea:x}",
            "kind": result.candidate.kind,
            "scheme": result.scheme,
            "score": round(result.score, 2),
            "plaintext": result.plaintext[:300],
            "pipeline": result.pipeline,
        }
        for result in results[:80]
    ]
    report["high_confidence"] = sum(1 for result in results if result.score >= 75)
    report["score_bands"] = {
        str(band): sum(1 for result in results if result.score >= band)
        for band in (60, 65, 70, 75, 80, 85, 90)
    }
    return (
        f"{len(results)} results in {elapsed:.1f}s, keys={len(material)} "
        f"({key_seconds:.1f}s), high={report['high_confidence']}, counts={counts}"
    )


def main() -> None:
    ida_auto.auto_wait()
    path = ida_nalt.get_input_file_path()
    report["input"] = path
    step("utf16 length probe", probe_utf16)
    step("default collection", collect)
    step("default scan", scan)
    report["ok"] = all(item["ok"] for item in report["steps"])
    with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"[{'OK' if report['ok'] else 'FAILED'}] {REPORT_PATH}")
    idc.qexit(0 if report["ok"] else 1)


try:
    main()
except BaseException:  # noqa: BLE001
    report["fatal"] = traceback.format_exc()
    try:
        with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except Exception:
        pass
    print(report["fatal"])
    idc.qexit(1)
