"""IDA plugin registration."""

from __future__ import annotations

import traceback

import ida_idaapi
import ida_kernwin

from . import __version__


class StringDecryptPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Automatic native string/ciphertext decryptor"
    help = (
        "Scans strings, referenced data blobs, immediate/stack constants and "
        "high-entropy regions, then tries XOR/XorStr/Add/Sub/Rol, Base64, "
        "RC4, AES and DES. Comments are optional and non-destructive."
    )
    wanted_name = "String Decryptor"
    wanted_hotkey = "Ctrl-Shift-D"

    def __init__(self):
        super().__init__()
        self.form = None
        self._last_error = ""

    def init(self) -> int:
        try:
            # The engine works headlessly, but the PySide6 form only makes
            # sense in the GUI client.
            if ida_kernwin.is_idaq():
                from .ui import StringDecryptForm  # noqa: F401
        except Exception:
            self._last_error = traceback.format_exc()
            ida_kernwin.msg(
                f"[String Decryptor] failed to load UI ({__version__}):\n{self._last_error}\n"
            )
            return ida_idaapi.PLUGIN_SKIP
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int = 0) -> None:
        if not ida_kernwin.is_idaq():
            ida_kernwin.msg("[String Decryptor] the GUI form requires IDA's Qt client.\n")
            return
        try:
            if self.form is None:
                from .ui import StringDecryptForm

                self.form = StringDecryptForm()
            self.form.Show(
                f"String Decryptor {__version__}",
                ida_kernwin.PluginForm.WOPN_DP_TAB
                | ida_kernwin.PluginForm.WOPN_RESTORE
                | ida_kernwin.PluginForm.WOPN_ONTOP,
            )
        except Exception:
            ida_kernwin.msg(f"[String Decryptor] failed to open:\n{traceback.format_exc()}\n")

    def term(self) -> None:
        if self.form is not None:
            try:
                self.form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            except Exception:
                pass
            self.form = None
