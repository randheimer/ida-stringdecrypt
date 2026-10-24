"""IDA plugin entry point.

IDA loads this file because ``ida-plugin.json`` names it as the entry point.
The actual package is installed next to this file as ``ida_stringdecrypt_pkg``
so its module name cannot collide with other plugins.
"""

from __future__ import annotations

import os
import sys
import traceback

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

try:
    from ida_stringdecrypt_pkg.plugin import StringDecryptPlugin
except Exception:
    # Allow running directly from the source checkout (package name
    # "stringdecrypt") for development and tests.
    try:
        from stringdecrypt.plugin import StringDecryptPlugin
    except Exception:
        import ida_kernwin

        ida_kernwin.msg(
            "[String Decryptor] import failed; check the installation layout:\n"
            f"{traceback.format_exc()}\n"
        )
        raise


def PLUGIN_ENTRY():
    return StringDecryptPlugin()
