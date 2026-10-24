"""PySide6 user interface for the IDA string decryptor."""

from __future__ import annotations

import json
import os
import traceback

from PySide6 import QtCore, QtGui, QtWidgets

import ida_kernwin

from . import __version__, ida_scan
from .engine import ScanConfig, ScanResult, StringDecryptEngine


_ACTIVE_WORKERS: set["ScanWorker"] = set()


class ScanWorker(QtCore.QThread):
    scan_progress = QtCore.Signal(int, int)
    scan_done = QtCore.Signal(object)
    scan_failed = QtCore.Signal(str)

    def __init__(self, engine: StringDecryptEngine, candidates: list):
        super().__init__()
        self.engine = engine
        self.candidates = candidates
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:  # noqa: D401 - Qt entry point
        try:
            results = self.engine.scan_candidates(
                self.candidates,
                progress=lambda done, total: self.scan_progress.emit(done, total),
                cancel=lambda: self._cancel,
            )
        except Exception:  # noqa: BLE001
            self.scan_failed.emit(traceback.format_exc())
            return
        self.scan_done.emit(results)


class ResultsModel(QtCore.QAbstractTableModel):
    HEADERS = ("EA", "Scheme", "Score", "Key", "Plaintext", "Pipeline", "Kind")
    SCORE_COLUMN = 2

    def __init__(self, parent=None):
        super().__init__(parent)
        self._results: list[ScanResult] = []

    # Qt interface -----------------------------------------------------
    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._results)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if role != QtCore.Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == QtCore.Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def data(self, index, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._results)):
            return None
        result = self._results[index.row()]
        column = index.column()

        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return f"0x{result.candidate.ea:x}"
            if column == 1:
                return result.scheme
            if column == 2:
                return f"{result.score:.1f}"
            if column == 3:
                return result.key_display()
            if column == 4:
                text = result.plaintext.replace("\r", "\\r").replace("\n", "\\n")
                return text[:400]
            if column == 5:
                return result.pipeline
            if column == 6:
                return result.candidate.kind
        elif role == QtCore.Qt.ItemDataRole.TextAlignmentRole:
            if column == 2:
                return int(QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignVCenter)
        elif role == QtCore.Qt.ItemDataRole.ForegroundRole:
            if column == 2:
                if result.score >= 85:
                    return QtGui.QColor("#7bd88f")
                if result.score >= 75:
                    return QtGui.QColor("#ffd166")
                return QtGui.QColor("#c7c7c7")
        elif role == QtCore.Qt.ItemDataRole.ToolTipRole:
            return (
                f"EA: 0x{result.candidate.ea:x}\n"
                f"Scheme: {result.scheme}\n"
                f"Score: {result.score:.2f}\n"
                f"Key: {result.key_display() or '-'}\n"
                f"IV: {result.iv.hex() or '-'}\n"
                f"Pipeline: {result.pipeline}\n"
                f"Original: {result.candidate.preview(240)}\n"
                f"Plaintext: {result.plaintext}"
            )
        return None

    # Sorting ----------------------------------------------------------
    def sort(self, column: int, order=QtCore.Qt.SortOrder.AscendingOrder) -> None:
        reverse = order == QtCore.Qt.SortOrder.DescendingOrder
        key_functions = {
            0: lambda item: item.candidate.ea,
            1: lambda item: item.scheme.lower(),
            2: lambda item: item.score,
            3: lambda item: item.key,
            4: lambda item: item.plaintext.lower(),
            5: lambda item: item.pipeline.lower(),
            6: lambda item: item.candidate.kind.lower(),
        }
        key = key_functions.get(column, lambda item: item.score)
        self.layoutAboutToBeChanged.emit()
        self._results.sort(key=key, reverse=reverse)
        self.layoutChanged.emit()

    # Helpers ----------------------------------------------------------
    def set_results(self, results: list[ScanResult]) -> None:
        self.beginResetModel()
        self._results = list(results)
        self.endResetModel()

    def clear(self) -> None:
        self.set_results([])

    def result_at(self, row: int) -> ScanResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def results(self) -> list[ScanResult]:
        return list(self._results)


class StringDecryptForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None
        self._worker = None
        self._results: list[ScanResult] = []
        self._last_stats = None
        self._last_candidates = 0
        self._model = ResultsModel()
        self._scanning = False

    # ------------------------------------------------------------------
    # Form lifecycle
    # ------------------------------------------------------------------
    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self._build_ui(self.parent)
        self._apply_ida_palette()

    def OnClose(self, form):
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        return None

    def _apply_ida_palette(self) -> None:
        try:
            if self.parent is not None:
                self.parent.setStyleSheet(
                    "QGroupBox { font-weight: bold; margin-top: 6px; }"
                    "QGroupBox::title { subcontrol-origin: margin; left: 9px; padding: 0 4px; }"
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self, root) -> None:
        layout = QtWidgets.QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        header = QtWidgets.QHBoxLayout()
        self.file_label = QtWidgets.QLabel(self._input_path())
        self.file_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        font = self.file_label.font()
        font.setBold(True)
        self.file_label.setFont(font)
        header.addWidget(self.file_label, 1)
        header.addWidget(QtWidgets.QLabel("Scope:"))
        self.scope_combo = QtWidgets.QComboBox()
        self.scope_combo.addItems(["Whole database", "Current function", "Selected range"])
        header.addWidget(self.scope_combo)
        self.scan_button = QtWidgets.QPushButton("Scan")
        self.scan_button.setDefault(True)
        self.scan_button.clicked.connect(self._start_scan)
        header.addWidget(self.scan_button)
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_scan)
        header.addWidget(self.cancel_button)
        layout.addLayout(header)

        options = QtWidgets.QGroupBox("Scan options")
        grid = QtWidgets.QGridLayout(options)
        grid.setContentsMargins(8, 12, 8, 8)

        self.min_score_spin = QtWidgets.QDoubleSpinBox()
        self.min_score_spin.setRange(0.0, 100.0)
        self.min_score_spin.setDecimals(1)
        self.min_score_spin.setSingleStep(2.5)
        self.min_score_spin.setValue(70.0)
        self.min_score_spin.setToolTip("Discard results below this confidence score.")
        grid.addWidget(QtWidgets.QLabel("Min score:"), 0, 0)
        grid.addWidget(self.min_score_spin, 0, 1)

        self.comment_score_spin = QtWidgets.QDoubleSpinBox()
        self.comment_score_spin.setRange(0.0, 100.0)
        self.comment_score_spin.setDecimals(1)
        self.comment_score_spin.setSingleStep(2.5)
        self.comment_score_spin.setValue(75.0)
        self.comment_score_spin.setToolTip(
            "Only results at or above this score are added as comments."
        )
        grid.addWidget(QtWidgets.QLabel("Comment score:"), 0, 2)
        grid.addWidget(self.comment_score_spin, 0, 3)

        self.min_length_spin = QtWidgets.QSpinBox()
        self.min_length_spin.setRange(2, 64)
        self.min_length_spin.setValue(5)
        grid.addWidget(QtWidgets.QLabel("Min length:"), 0, 4)
        grid.addWidget(self.min_length_spin, 0, 5)

        self.max_candidates_spin = QtWidgets.QSpinBox()
        self.max_candidates_spin.setRange(100, 100000)
        self.max_candidates_spin.setSingleStep(500)
        self.max_candidates_spin.setValue(8000)
        self.max_candidates_spin.setToolTip(
            "Upper bound on candidates sent to the engine. Lower this for huge databases."
        )
        grid.addWidget(QtWidgets.QLabel("Max candidates:"), 0, 6)
        grid.addWidget(self.max_candidates_spin, 0, 7)

        self.max_entropy_spin = QtWidgets.QSpinBox()
        self.max_entropy_spin.setRange(0, 20000)
        self.max_entropy_spin.setSingleStep(128)
        self.max_entropy_spin.setValue(512)
        grid.addWidget(QtWidgets.QLabel("Entropy blobs:"), 0, 8)
        grid.addWidget(self.max_entropy_spin, 0, 9)

        self.heavy_check = QtWidgets.QCheckBox("Keyed ciphers (RC4/AES/DES)")
        self.heavy_check.setChecked(True)
        self.heavy_check.setToolTip(
            "Try plausible keys from imports, names and string material. "
            "Keyed ciphers are only attempted on likely candidates."
        )
        grid.addWidget(self.heavy_check, 1, 0, 1, 2)

        self.custom_check = QtWidgets.QCheckBox("Custom decoders")
        self.custom_check.setChecked(True)
        self.custom_check.setToolTip("Run enabled modules from custom_decoders/.")
        grid.addWidget(self.custom_check, 1, 2, 1, 2)

        self.entropy_check = QtWidgets.QCheckBox("Entropy blobs")
        self.entropy_check.setChecked(True)
        self.entropy_check.setToolTip("Scan high-entropy data regions as raw ciphertext.")
        grid.addWidget(self.entropy_check, 1, 4, 1, 2)

        self.code_check = QtWidgets.QCheckBox("Strings in code sections")
        self.code_check.setChecked(False)
        self.code_check.setToolTip(
            "Also treat printable runs inside executable segments as strings."
        )
        grid.addWidget(self.code_check, 1, 6, 1, 2)

        self.force_heavy_check = QtWidgets.QCheckBox("Force keyed ciphers")
        self.force_heavy_check.setChecked(False)
        self.force_heavy_check.setToolTip(
            "Run RC4/AES/DES against every candidate instead of only plausible ones. Slow."
        )
        grid.addWidget(self.force_heavy_check, 1, 8, 1, 2)

        grid.addWidget(QtWidgets.QLabel("Keys:"), 2, 0)
        self.key_edit = QtWidgets.QLineEdit()
        self.key_edit.setPlaceholderText(
            "optional — leave empty to auto-guess keys from imports, names and strings"
        )
        self.key_edit.setToolTip(
            "Leave this empty for automatic key discovery. Add keys only if the "
            "binary hides the key at runtime or the automatic scan misses a known cipher."
        )
        grid.addWidget(self.key_edit, 2, 1, 1, 9)

        grid.addWidget(QtWidgets.QLabel("IVs:"), 3, 0)
        self.iv_edit = QtWidgets.QLineEdit()
        self.iv_edit.setPlaceholderText("optional: ascii:0123456789abcdef")
        grid.addWidget(self.iv_edit, 3, 1, 1, 9)

        grid.addWidget(QtWidgets.QLabel("Cribs:"), 4, 0)
        self.crib_edit = QtWidgets.QLineEdit()
        self.crib_edit.setPlaceholderText("optional known plaintext prefixes (defaults are built in)")
        grid.addWidget(self.crib_edit, 4, 1, 1, 9)

        for column in range(10):
            grid.setColumnStretch(column, 1)
        layout.addWidget(options)

        self.view = QtWidgets.QTableView()
        self.view.setModel(self._model)
        self.view.setSortingEnabled(True)
        self.view.sortByColumn(2, QtCore.Qt.SortOrder.DescendingOrder)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setAlternatingRowColors(True)
        self.view.setWordWrap(False)
        self.view.verticalHeader().setVisible(False)
        self.view.horizontalHeader().setStretchLastSection(False)
        self.view.setColumnWidth(0, 105)
        self.view.setColumnWidth(1, 90)
        self.view.setColumnWidth(2, 55)
        self.view.setColumnWidth(3, 180)
        self.view.setColumnWidth(4, 520)
        self.view.setColumnWidth(5, 190)
        self.view.setColumnWidth(6, 80)
        self.view.doubleClicked.connect(self._jump_to_index)
        self.view.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.view, 1)

        bottom = QtWidgets.QHBoxLayout()
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumWidth(220)
        bottom.addWidget(self.progress)
        self.status_label = QtWidgets.QLabel("Ready.")
        bottom.addWidget(self.status_label, 1)
        self.comment_button = QtWidgets.QPushButton("Add comments")
        self.comment_button.setToolTip("Append comments for results at or above the comment score.")
        self.comment_button.clicked.connect(lambda: self._add_comments(False))
        self.comment_button.setEnabled(False)
        bottom.addWidget(self.comment_button)
        self.comment_selected_button = QtWidgets.QPushButton("Comment selected")
        self.comment_selected_button.clicked.connect(lambda: self._add_comments(True))
        self.comment_selected_button.setEnabled(False)
        bottom.addWidget(self.comment_selected_button)
        self.export_button = QtWidgets.QPushButton("Export JSON")
        self.export_button.clicked.connect(self._export_json)
        self.export_button.setEnabled(False)
        bottom.addWidget(self.export_button)
        layout.addLayout(bottom)

    def _input_path(self) -> str:
        try:
            import ida_nalt

            path = ida_nalt.get_input_file_path()
            if path:
                return os.path.basename(path) + f"  [{path}]"
        except Exception:
            pass
        return "No input file"

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _collect_progress(self, stage: str, current: int, total: int) -> None:
        if total:
            self.status_label.setText(f"Collecting {stage}: {current}/{total}")
        else:
            self.status_label.setText(f"Collecting {stage}...")
        QtWidgets.QApplication.processEvents()

    def _current_range(self) -> tuple[int, int] | None:
        scope = self.scope_combo.currentIndex()
        if scope == 1:
            selected = ida_scan.current_function_range()
            if selected is None:
                QtWidgets.QMessageBox.warning(
                    self.parent, "String Decryptor", "The cursor is not inside a function."
                )
            return selected
        if scope == 2:
            selected = ida_scan.selected_range()
            if selected is None:
                QtWidgets.QMessageBox.warning(
                    self.parent,
                    "String Decryptor",
                    "Select an address range in the disassembly view first.",
                )
            return selected
        return None

    def _start_scan(self) -> None:
        if self._scanning:
            return
        try:
            import ida_auto

            if not ida_auto.auto_is_ok():
                ida_auto.auto_wait()
        except Exception:
            pass

        address_range = self._current_range()
        if self.scope_combo.currentIndex() in (1, 2) and address_range is None:
            return

        options = ida_scan.IdaScanOptions(
            min_length=max(2, self.min_length_spin.value()),
            include_entropy=self.entropy_check.isChecked(),
            include_code_strings=self.code_check.isChecked(),
            max_entropy_blobs=self.max_entropy_spin.value(),
            max_candidates=self.max_candidates_spin.value(),
        )
        if address_range is not None:
            options.start_ea, options.end_ea = address_range

        self._set_scanning(True)
        self.status_label.setText("Collecting candidates...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        QtWidgets.QApplication.processEvents()
        try:
            candidates, stats = ida_scan.collect_candidates(options, progress=self._collect_progress)
        except Exception:
            self._set_scanning(False)
            self._show_error("Candidate collection failed", traceback.format_exc())
            return
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

        self._last_stats = stats
        self._last_candidates = len(candidates)
        if not candidates:
            self._set_scanning(False)
            self.status_label.setText("No candidates found.")
            QtWidgets.QMessageBox.information(
                self.parent, "String Decryptor", "No candidate strings or blobs were found."
            )
            return

        config = ScanConfig(
            min_length=max(2, self.min_length_spin.value()),
            min_score=self.min_score_spin.value(),
            max_total_results=5000,
            max_heavy_candidates=400,
            max_entropy_blobs=self.max_entropy_spin.value(),
            force_heavy=self.force_heavy_check.isChecked(),
            enable_heavy=self.heavy_check.isChecked(),
            enable_custom=self.custom_check.isChecked(),
        )
        config.key_text = self.key_edit.text()
        config.iv_text = self.iv_edit.text()
        config.crib_text = self.crib_edit.text()
        try:
            config.prepare()
            config.key_material = ida_scan.collect_key_material(candidates)
        except Exception:
            self._set_scanning(False)
            self._show_error("Key material collection failed", traceback.format_exc())
            return

        self.progress.setRange(0, len(candidates))
        self.progress.setValue(0)
        self.status_label.setText(
            f"{stats.as_text()} -> scanning {len(candidates)} candidates..."
        )

        engine = StringDecryptEngine(config)
        worker = ScanWorker(engine, candidates)
        worker.scan_progress.connect(self._on_scan_progress)
        worker.scan_done.connect(self._on_scan_done)
        worker.scan_failed.connect(self._on_scan_failed)
        worker.finished.connect(lambda: _ACTIVE_WORKERS.discard(worker))
        _ACTIVE_WORKERS.add(worker)
        self._worker = worker
        worker.start()

    def _cancel_scan(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self.status_label.setText("Cancelling after the current candidate...")
            self.cancel_button.setEnabled(False)

    def _on_scan_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(max(1, total))
        self.progress.setValue(done)
        self.status_label.setText(f"Scanning {done}/{total} candidates...")

    def _on_scan_done(self, results) -> None:
        self._results = list(results)
        self._model.set_results(self._results)
        self._set_scanning(False)
        self.progress.setValue(self.progress.maximum())
        counts: dict[str, int] = {}
        for result in self._results:
            counts[result.scheme] = counts.get(result.scheme, 0) + 1
        summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
        stats = self._last_stats
        stats_text = stats.as_text() if stats else ""
        self.status_label.setText(
            f"{len(self._results)} results from {self._last_candidates} candidates"
            + (f" ({summary})" if summary else "")
            + (f" | {stats_text}" if stats_text else "")
        )
        self.comment_button.setEnabled(bool(self._results))
        self.comment_selected_button.setEnabled(bool(self._results))
        self.export_button.setEnabled(bool(self._results))
        if not self._results:
            QtWidgets.QMessageBox.information(
                self.parent,
                "String Decryptor",
                "The scan finished without results above the minimum score.\n"
                "Try lowering the minimum score, enabling more schemes, or adding keys.",
            )

    def _on_scan_failed(self, message: str) -> None:
        self._set_scanning(False)
        self.status_label.setText("Scan failed.")
        self._show_error("Scan failed", message)

    def _set_scanning(self, scanning: bool) -> None:
        self._scanning = scanning
        self.scan_button.setEnabled(not scanning)
        self.cancel_button.setEnabled(scanning)
        self.scope_combo.setEnabled(not scanning)
        self.min_score_spin.setEnabled(not scanning)
        self.comment_score_spin.setEnabled(not scanning)
        self.min_length_spin.setEnabled(not scanning)
        self.max_candidates_spin.setEnabled(not scanning)
        self.max_entropy_spin.setEnabled(not scanning)
        self.heavy_check.setEnabled(not scanning)
        self.custom_check.setEnabled(not scanning)
        self.entropy_check.setEnabled(not scanning)
        self.code_check.setEnabled(not scanning)
        self.force_heavy_check.setEnabled(not scanning)
        self.key_edit.setEnabled(not scanning)
        self.iv_edit.setEnabled(not scanning)
        self.crib_edit.setEnabled(not scanning)
        if scanning:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 100)

    def _show_error(self, title: str, details: str) -> None:
        box = QtWidgets.QMessageBox(self.parent)
        box.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        box.setWindowTitle("String Decryptor")
        box.setText(title)
        box.setDetailedText(details)
        box.exec()

    # ------------------------------------------------------------------
    # Results actions
    # ------------------------------------------------------------------
    def _selected_result(self) -> ScanResult | None:
        index = self.view.currentIndex()
        if not index.isValid():
            return None
        return self._model.result_at(index.row())

    def _jump_to_index(self, index) -> None:
        result = self._model.result_at(index.row())
        if result is not None:
            self._jump_to(result.candidate.ea)

    def _jump_to(self, ea: int) -> None:
        try:
            ida_kernwin.jumpto(ea)
        except Exception:
            QtWidgets.QMessageBox.warning(
                self.parent, "String Decryptor", f"Cannot jump to 0x{ea:x}."
            )

    def _context_menu(self, position) -> None:
        index = self.view.indexAt(position)
        if not index.isValid():
            return
        self.view.setCurrentIndex(index)
        result = self._model.result_at(index.row())
        if result is None:
            return
        menu = QtWidgets.QMenu(self.parent)
        jump = menu.addAction("Jump to address")
        copy_plain = menu.addAction("Copy plaintext")
        copy_key = menu.addAction("Copy key")
        copy_row = menu.addAction("Copy result as JSON")
        menu.addSeparator()
        comment = menu.addAction("Add comment for this result")
        chosen = menu.exec(self.view.viewport().mapToGlobal(position))
        if chosen is jump:
            self._jump_to(result.candidate.ea)
        elif chosen is copy_plain:
            QtWidgets.QApplication.clipboard().setText(result.plaintext)
        elif chosen is copy_key:
            QtWidgets.QApplication.clipboard().setText(result.key_display())
        elif chosen is copy_row:
            QtWidgets.QApplication.clipboard().setText(json.dumps(result.to_dict(), indent=2))
        elif chosen is comment:
            added, skipped = ida_scan.apply_comments([result], 0.0, selected_eas={result.candidate.ea})
            self._after_comments(added, skipped)

    def _add_comments(self, selected_only: bool) -> None:
        if selected_only:
            result = self._selected_result()
            if result is None:
                QtWidgets.QMessageBox.information(
                    self.parent, "String Decryptor", "Select a result row first."
                )
                return
            added, skipped = ida_scan.apply_comments(
                [result], 0.0, selected_eas={result.candidate.ea}
            )
            self._after_comments(added, skipped)
            return

        threshold = self.comment_score_spin.value()
        addresses = {result.candidate.ea for result in self._results if result.score >= threshold}
        if not addresses:
            QtWidgets.QMessageBox.information(
                self.parent,
                "String Decryptor",
                f"No results reach the comment score ({threshold:.1f}).",
            )
            return
        answer = QtWidgets.QMessageBox.question(
            self.parent,
            "String Decryptor",
            f"Add non-destructive comments for {len(addresses)} address(es) "
            f"at score >= {threshold:.1f}?\n\nExisting comments are preserved.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        added, skipped = ida_scan.apply_comments(self._results, threshold)
        self._after_comments(added, skipped)

    def _after_comments(self, added: int, skipped: int) -> None:
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
        self.status_label.setText(f"Comments added: {added}, skipped: {skipped}.")
        QtWidgets.QMessageBox.information(
            self.parent,
            "String Decryptor",
            f"Comments added: {added}\nSkipped (already present): {skipped}",
        )

    def _export_json(self) -> None:
        if not self._results:
            return
        try:
            import ida_nalt

            base = ida_nalt.get_input_file_path() or "strings"
        except Exception:
            base = "strings"
        suggested = os.path.splitext(base)[0] + ".stringdecrypt.json"
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self.parent, "Export scan results", suggested, "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        payload = {
            "tool": "ida-stringdecrypt",
            "version": __version__,
            "file": base,
            "stats": {
                "candidates": self._last_candidates,
                "results": len(self._results),
                "collector": self._last_stats.as_text() if self._last_stats else "",
            },
            "results": [result.to_dict() for result in self._results],
        }
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
        except OSError as error:
            QtWidgets.QMessageBox.warning(
                self.parent, "String Decryptor", f"Could not write {path}:\n{error}"
            )
            return
        self.status_label.setText(f"Exported {len(self._results)} results to {path}.")
