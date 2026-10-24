"""Headless IDA 9.5 integration test for the String Decryptor plugin.

Run through ``idat.exe -A -S"tests/ida_headless_test.py" tests/ida_test_pe.exe``.
The script writes ``tests/ida_headless_report.json`` and exits IDA with a status
code derived from the individual checks.
"""

from __future__ import annotations

import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
INSTALL_DIR = os.path.join(
    os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "plugins", "ida_stringdecrypt"
)
for path in (INSTALL_DIR, PROJECT):
    if path and path not in sys.path:
        sys.path.insert(0, path)

REPORT_PATH = os.path.join(HERE, "ida_headless_report.json")
EXPECTED_PATH = os.path.join(HERE, "ida_test_pe_expected.json")

report = {
    "ok": False,
    "python": sys.version,
    "install_dir": INSTALL_DIR,
    "plugin_import": "",
    "steps": [],
}
CANDIDATES = []


def run_step(name, function):
    try:
        detail = function()
        report["steps"].append({"name": name, "ok": True, "detail": str(detail)[:8000]})
        print(f"[PASS] {name}: {detail}")
        return detail
    except Exception:  # noqa: BLE001 - the report must contain failures
        detail = traceback.format_exc()
        report["steps"].append({"name": name, "ok": False, "detail": detail})
        print(f"[FAIL] {name}\n{detail}")
        return None


import ida_auto  # noqa: E402
import ida_bytes  # noqa: E402
import ida_kernwin  # noqa: E402
import ida_loader  # noqa: E402
import ida_nalt  # noqa: E402
import ida_idaapi  # noqa: E402
import idc  # noqa: E402


def expected_data() -> dict:
    with open(EXPECTED_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def check_input_file() -> str:
    path = ida_nalt.get_input_file_path()
    assert path, "IDA did not report an input file"
    assert os.path.basename(path).lower() == "ida_test_pe.exe", path
    return path


def check_plugin_discovery_and_init() -> str:
    expected = expected_data()
    assert expected["addresses"]["aes"] > 0

    discovered = []
    for name in (
        "ida-stringdecrypt",
        "ida_stringdecrypt",
        "ida_stringdecrypt_plugin",
        os.path.join(INSTALL_DIR, "ida_stringdecrypt_plugin.py"),
    ):
        try:
            plugin = ida_loader.find_plugin(name, False)
        except Exception as error:  # noqa: BLE001
            discovered.append(f"{name}=error:{error}")
            continue
        discovered.append(f"{name}={'found' if plugin else 'missing'}")

    import ida_stringdecrypt_plugin

    plugin = ida_stringdecrypt_plugin.PLUGIN_ENTRY()
    flags = plugin.init()
    assert flags == ida_idaapi.PLUGIN_KEEP, flags
    assert plugin.wanted_name == "String Decryptor"
    assert plugin.wanted_hotkey.lower() == "ctrl-shift-d"
    plugin.term()

    # The plugin must also be loadable by IDA itself.
    loaded = None
    for name in (
        "ida-stringdecrypt",
        os.path.join(INSTALL_DIR, "ida_stringdecrypt_plugin.py"),
    ):
        try:
            loaded = ida_loader.load_plugin(name)
        except Exception:
            loaded = None
        if loaded:
            break
    assert loaded is not None, "ida_loader.load_plugin() could not load the installed plugin"

    return f"loader={loaded!r}; " + ", ".join(discovered)


def check_ui_import() -> str:
    sys.path.insert(0, INSTALL_DIR)
    try:
        from ida_stringdecrypt_pkg import ui
    except ImportError as error:
        if not ida_kernwin.is_idaq() and "GUI version of IDA" in str(error):
            report["ui_skipped"] = str(error)
            return "skipped: PySide6 requires the GUI version of IDA"

    assert hasattr(ui, "StringDecryptForm")
    assert hasattr(ui, "ResultsModel")
    assert hasattr(ui, "ScanWorker")
    return f"ui module {ui.__file__}"


def check_candidates() -> str:
    global CANDIDATES
    ida_auto.auto_wait()
    from ida_stringdecrypt_pkg import ida_scan

    options = ida_scan.IdaScanOptions(
        min_length=5,
        include_entropy=False,
        max_candidates=2000,
        max_instructions=100000,
    )
    candidates, stats = ida_scan.collect_candidates(options)
    assert candidates, "no candidates collected"
    CANDIDATES = candidates

    expected = expected_data()
    by_ea = {candidate.ea: candidate for candidate in candidates}
    addresses = expected["addresses"]
    lengths = expected["cipher_lengths"]

    details = []
    for name in ("plain", "base64", "xor", "rc4", "aes", "des", "path"):
        ea = addresses[name]
        candidate = by_ea.get(ea)
        assert candidate is not None, f"missing {name} candidate at 0x{ea:x}"
        details.append(f"{name}=0x{ea:x}/{candidate.kind}/{len(candidate.raw)}b")

    assert by_ea[addresses["plain"]].raw.startswith(expected["plaintexts"]["plain"].encode())
    assert by_ea[addresses["base64"]].raw.startswith(b"aHR0cDovL2V4YW1wbGUuY29tL2FwaQ==")
    assert by_ea[addresses["xor"]].raw == bytes(
        ord(char) ^ 0x5A for char in expected["plaintexts"]["xor"]
    )
    assert len(by_ea[addresses["rc4"]].raw) == lengths["rc4"]
    assert len(by_ea[addresses["des"]].raw) == lengths["des"]
    aes_len = len(by_ea[addresses["aes"]].raw)
    assert aes_len >= lengths["aes"], aes_len

    immediate = next(
        (c for c in candidates if c.kind == "immediate" and c.raw == b"HGFEDCBA"), None
    )
    assert immediate is not None, "immediate constant was not collected"

    report["collector_stats"] = stats.as_text()
    report["candidate_count"] = len(candidates)
    report["candidates"] = [
        {
            "ea": f"0x{candidate.ea:x}",
            "kind": candidate.kind,
            "length": len(candidate.raw),
            "preview": candidate.preview(80),
        }
        for candidate in candidates
    ]
    return f"{len(candidates)} candidates ({stats.as_text()}); " + ", ".join(details)


def check_key_material(candidates) -> str:
    from ida_stringdecrypt_pkg import ida_scan

    material = ida_scan.collect_key_material(candidates)
    expected = expected_data()
    blob = b"\n".join(material)
    for name in ("rc4", "aes", "des"):
        key = expected["keys"][name].encode()
        assert key in material or key in blob, f"missing {name} key material {key!r}"
    report["key_material_count"] = len(material)
    return f"{len(material)} key candidates, expected keys present"


def check_targeted_decryption(candidates) -> str:
    from ida_stringdecrypt_pkg.engine import ScanConfig, StringDecryptEngine

    expected = expected_data()
    addresses = expected["addresses"]
    by_ea = {candidate.ea: candidate for candidate in candidates}
    user_keys = [expected["keys"][name].encode() for name in ("rc4", "aes", "des")]
    config = ScanConfig(
        min_score=55.0,
        user_keys=user_keys,
        max_cipher_keys=8,
        max_cipher_ops=50000,
        force_heavy=True,
        enable_custom=False,
    )
    results = []
    for name in ("xor", "rc4", "aes", "des"):
        engine = StringDecryptEngine(config)
        candidate = by_ea[addresses[name]]
        found = engine.scan_candidate(candidate)
        wanted = expected["plaintexts"][name]
        matches = [item for item in found if item.plaintext == wanted]
        assert matches, f"{name}: no exact plaintext, got {[(r.scheme, r.plaintext, r.score) for r in found]}"
        best = max(matches, key=lambda item: item.score)
        results.append(
            {
                "name": name,
                "scheme": best.scheme,
                "score": best.score,
                "pipeline": best.pipeline,
                "ea": f"0x{best.candidate.ea:x}",
            }
        )
    report["targeted_results"] = results
    return "; ".join(
        f"{item['name']}={item['scheme']}/{item['score']:.2f}" for item in results
    )


def check_auto_decryption(candidates) -> str:
    from ida_stringdecrypt_pkg import ida_scan
    from ida_stringdecrypt_pkg.engine import ScanConfig, StringDecryptEngine

    expected = expected_data()
    material = ida_scan.collect_key_material(candidates)
    config = ScanConfig(
        min_score=55.0,
        max_total_results=1000,
        max_cipher_keys=64,
        max_cipher_ops=40000,
        force_heavy=False,
        enable_custom=False,
        key_material=material,
    )
    engine = StringDecryptEngine(config)
    found = engine.scan_candidates(candidates)
    wanted = expected["plaintexts"]
    summary = {}
    for name in ("xor", "rc4", "aes", "des", "base64"):
        matches = [item for item in found if item.plaintext == wanted[name]]
        assert matches, f"{name}: automatic scan missed {wanted[name]!r}"
        best = max(matches, key=lambda item: item.score)
        summary[name] = {
            "scheme": best.scheme,
            "score": best.score,
            "ea": f"0x{best.candidate.ea:x}",
            "pipeline": best.pipeline,
        }
    report["auto_results"] = summary
    report["auto_result_count"] = len(found)
    return "; ".join(
        f"{name}={data['scheme']}/{data['score']:.2f}" for name, data in summary.items()
    )


def check_comments() -> str:
    from ida_stringdecrypt_pkg import ida_scan
    from ida_stringdecrypt_pkg.engine import ScanConfig, ScanResult

    expected = expected_data()
    ea = expected["addresses"]["xor"]
    existing = "existing analyst note"
    assert ida_bytes.set_cmt(ea, existing, False), "could not create the test comment"

    import ida_stringdecrypt_pkg.engine as engine_module

    candidate = engine_module.Candidate(
        ea=ea,
        raw=b"irrelevant",
        kind="string",
        text="irrelevant",
        source="test",
    )
    result = ScanResult(
        candidate=candidate,
        scheme="xor",
        plaintext="https://example.com/api/v1",
        score=100.0,
        key=b"\x5a",
        pipeline="xor(0x5a)",
        encoding="latin-1",
    )
    added, skipped = ida_scan.apply_comments([result], 0.0)
    assert added == 1, (added, skipped)
    comment = ida_bytes.get_cmt(ea, False) or ""
    assert existing in comment, comment
    assert ida_scan.COMMENT_PREFIX in comment, comment

    added_again, skipped_again = ida_scan.apply_comments([result], 0.0)
    assert added_again == 0 and skipped_again == 1, (added_again, skipped_again)
    comment_again = ida_bytes.get_cmt(ea, False) or ""
    assert comment_again == comment, "second pass modified the comment"

    ida_bytes.set_cmt(ea, "", False)
    report["comment"] = comment
    return f"preserved existing comment and deduplicated on the second pass: {comment!r}"


def main() -> None:
    auto_ok = run_step("input file", check_input_file)
    plugin_ok = run_step("plugin discovery/init", check_plugin_discovery_and_init)
    ui_ok = run_step("ui import", check_ui_import)
    run_step("candidate collection", check_candidates)
    candidates = CANDIDATES
    if candidates:
        run_step("key material", lambda: check_key_material(candidates))
        run_step("targeted decryption", lambda: check_targeted_decryption(candidates))
        run_step("automatic decryption", lambda: check_auto_decryption(candidates))
        run_step("comments", check_comments)
    else:
        report["steps"].append(
            {"name": "dependent checks", "ok": False, "detail": "no candidates"}
        )

    report["ok"] = bool(auto_ok and plugin_ok and ui_ok and candidates) and all(
        step["ok"] for step in report["steps"]
    )
    with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"[{'OK' if report['ok'] else 'FAILED'}] report written to {REPORT_PATH}")
    idc.qexit(0 if report["ok"] else 1)


try:
    main()
except BaseException:  # noqa: BLE001 - never leave idat.exe hanging
    report["fatal"] = traceback.format_exc()
    report["ok"] = False
    try:
        with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except Exception:
        pass
    print(report["fatal"])
    idc.qexit(1)
