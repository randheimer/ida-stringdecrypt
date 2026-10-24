"""GUI integration test for the String Decryptor plugin.

Run through ``ida.exe -A -S"tests/ida_gui_test.py" tests/ida_test_pe.exe``.
It opens the plugin form, runs a real threaded scan, validates the model, and
closes the form again.  A watchdog exits IDA if a modal dialog blocks us.
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

REPORT_PATH = os.path.join(HERE, "ida_gui_report.json")
EXPECTED_PATH = os.path.join(HERE, "ida_test_pe_expected.json")
SCAN_TIMEOUT = 180.0

report = {
    "ok": False,
    "python": sys.version,
    "install_dir": INSTALL_DIR,
    "steps": [],
}


def run_step(name, function):
    try:
        detail = function()
        report["steps"].append({"name": name, "ok": True, "detail": str(detail)[:8000]})
        print(f"[PASS] {name}: {detail}")
        return True
    except Exception:  # noqa: BLE001 - report every failure
        detail = traceback.format_exc()
        report["steps"].append({"name": name, "ok": False, "detail": detail})
        print(f"[FAIL] {name}\n{detail}")
        return False


import ida_auto  # noqa: E402
import ida_idaapi  # noqa: E402
import ida_kernwin  # noqa: E402
import ida_nalt  # noqa: E402
import idc  # noqa: E402
from PySide6 import QtCore, QtWidgets  # noqa: E402


def watchdog() -> None:
    report["ok"] = False
    report["fatal"] = "watchdog timeout"
    try:
        with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except Exception:
        pass
    print("[FAILED] watchdog timeout")
    idc.qexit(2)


QtCore.QTimer.singleShot(int(SCAN_TIMEOUT * 1000), watchdog)


def expected_data() -> dict:
    with open(EXPECTED_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def check_gui_available() -> str:
    assert ida_kernwin.is_idaq(), "not running in the GUI client"
    widget = QtWidgets.QApplication.instance()
    assert widget is not None, "no QApplication instance"
    path = ida_nalt.get_input_file_path()
    assert path and os.path.basename(path).lower() == "ida_test_pe.exe", path
    return f"GUI client ready for {path}"


def open_plugin_form() -> str:
    from ida_stringdecrypt_pkg.plugin import StringDecryptPlugin

    plugin = StringDecryptPlugin()
    flags = plugin.init()
    assert flags == ida_idaapi.PLUGIN_KEEP, flags
    report["plugin"] = plugin
    plugin.run(0)
    QtWidgets.QApplication.processEvents()

    form = plugin.form
    assert form is not None, "plugin did not create a form"
    assert form.GetWidget() is not None, "form widget was not created"
    assert form.view.model() is not None, "table model is missing"
    assert form.view.columnWidth(4) > 100, "plaintext column was not configured"
    report["form"] = form
    return f"form={form!r}, columns={form.view.model().columnCount()}"


def run_scan() -> str:
    form = report["form"]
    form.scope_combo.setCurrentIndex(0)
    form.min_score_spin.setValue(55.0)
    form.comment_score_spin.setValue(75.0)
    form.max_candidates_spin.setValue(100)
    form.max_entropy_spin.setValue(32)
    form.code_check.setChecked(False)
    form.force_heavy_check.setChecked(False)
    form._start_scan()

    deadline = time.time() + SCAN_TIMEOUT - 10
    while form._scanning and time.time() < deadline:
        QtWidgets.QApplication.processEvents()
        time.sleep(0.02)
    QtWidgets.QApplication.processEvents()
    assert not form._scanning, "scan did not finish before the timeout"
    assert form._model.rowCount() > 0, "scan produced no visible rows"
    assert form.comment_button.isEnabled(), "comment button was not enabled"
    assert form.export_button.isEnabled(), "export button was not enabled"

    expected = expected_data()["plaintexts"]
    plaintexts = [result.plaintext for result in form._results]
    for name in ("xor", "rc4", "aes", "des", "base64"):
        assert expected[name] in plaintexts, f"missing {name} result: {expected[name]!r}"

    index = form._model.index(0, 4)
    assert form._model.data(index), "model returned no plaintext for the first row"
    report["rows"] = form._model.rowCount()
    report["results"] = [
        {
            "ea": f"0x{result.candidate.ea:x}",
            "scheme": result.scheme,
            "score": result.score,
            "plaintext": result.plaintext,
            "pipeline": result.pipeline,
        }
        for result in form._results
    ]
    return f"{form._model.rowCount()} model rows, all expected plaintexts present"


def close_plugin_form() -> str:
    form = report["form"]
    plugin = report["plugin"]
    form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    QtWidgets.QApplication.processEvents()
    plugin.term()
    QtWidgets.QApplication.processEvents()
    return "form closed and plugin terminated"


def main() -> None:
    ida_auto.auto_wait()
    run_step("gui availability", check_gui_available)
    run_step("open plugin form", open_plugin_form)
    run_step("threaded ui scan", run_scan)
    run_step("close plugin form", close_plugin_form)

    report["ok"] = all(step["ok"] for step in report["steps"])
    report.pop("plugin", None)
    report.pop("form", None)
    with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"[{'OK' if report['ok'] else 'FAILED'}] report written to {REPORT_PATH}")
    idc.qexit(0 if report["ok"] else 1)


try:
    main()
except BaseException:  # noqa: BLE001 - never leave the GUI hanging
    report["fatal"] = traceback.format_exc()
    report["ok"] = False
    report.pop("plugin", None)
    report.pop("form", None)
    try:
        with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except Exception:
        pass
    print(report["fatal"])
    idc.qexit(1)
