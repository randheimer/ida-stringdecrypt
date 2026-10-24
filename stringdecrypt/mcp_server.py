"""MCP (Model Context Protocol) stdio server for the string decryptor.

The server is intentionally dependency-free: it speaks the small, stable
JSON-RPC subset used by MCP tool clients and can be launched directly:

    python mcp_server.py

It uses the same PE/ELF parser and decryption engine as the CLI, so an AI agent
can scan a file or decrypt a single blob without opening IDA.  When used next
to the official Hex-Rays IDA MCP server, the agent can take an address returned
here and inspect it in IDA with the official tools.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import traceback

from . import __version__, cli
from . import keys as key_material
from .engine import Candidate, ScanConfig, StringDecryptEngine

SERVER_NAME = "ida-stringdecrypt"
SERVER_TITLE = "IDA String Decryptor"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = PROTOCOL_VERSIONS[0]

SCHEME_NAMES = ("base64", "xor", "xorstr", "add", "sub", "rol", "rc4", "aes", "des", "custom")

_SCHEME_INFO = [
    {"name": "base64", "needs_key": False, "description": "Base64, including truncated/unpadded input."},
    {"name": "xor", "needs_key": False, "description": "Single-byte XOR; all 256 keys are tried."},
    {"name": "xorstr", "needs_key": False, "description": "Repeating-key XOR/XorStr; key material and short statistical keys."},
    {"name": "add", "needs_key": False, "description": "Byte-wise addition; all 256 keys are tried."},
    {"name": "sub", "needs_key": False, "description": "Byte-wise subtraction; all 256 keys are tried."},
    {"name": "rol", "needs_key": False, "description": "Bit rotations ROL/ROR."},
    {"name": "rc4", "needs_key": True, "description": "RC4; keys come from the binary, cribs or the caller."},
    {"name": "aes", "needs_key": True, "description": "AES-128/192/256 ECB and CBC; 16/24/32-byte keys."},
    {"name": "des", "needs_key": True, "description": "DES ECB and CBC; 8-byte keys."},
    {"name": "custom", "needs_key": False, "description": "User decoders from custom_directories."},
]

_READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def _json_schema(
    properties: dict,
    *,
    required: list[str] | None = None,
    description: str = "",
) -> dict:
    schema: dict = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    if description:
        schema["description"] = description
    return schema


_LIST_OF_STRINGS = {"type": "array", "items": {"type": "string"}}


def _tool_definitions() -> list[dict]:
    scan_props = {
        "path": {
            "type": "string",
            "description": "Absolute or working-directory-relative path to a native PE or ELF file.",
        },
        "min_score": {
            "type": "number",
            "default": 60,
            "minimum": 0,
            "maximum": 100,
            "description": "Only return candidates at or above this confidence score.",
        },
        "min_length": {"type": "integer", "default": 5, "minimum": 2},
        "schemes": {
            "type": "array",
            "items": {"type": "string", "enum": list(SCHEME_NAMES)},
            "description": "Schemes to try. Omit for all enabled schemes.",
        },
        "keys": {**_LIST_OF_STRINGS, "description": "Optional user keys (ascii:..., hex:..., 0x...)."},
        "ivs": {**_LIST_OF_STRINGS, "description": "Optional IVs for CBC modes."},
        "cribs": {**_LIST_OF_STRINGS, "description": "Optional known-plaintext cribs."},
        "custom_directories": {
            **_LIST_OF_STRINGS,
            "description": "Additional directories containing custom decoder modules.",
        },
        "include_entropy": {"type": "boolean", "default": True},
        "include_code": {"type": "boolean", "default": False},
        "force_heavy": {"type": "boolean", "default": False},
        "heavy": {"type": "boolean", "default": True, "description": "Enable RC4/AES/DES."},
        "custom": {"type": "boolean", "default": True},
        "max_candidates": {"type": "integer", "default": 5000, "minimum": 1},
        "max_results": {"type": "integer", "default": 200, "minimum": 1, "maximum": 5000},
        "max_input": {"type": "integer", "default": 8192, "minimum": 16},
        "max_entropy_blobs": {"type": "integer", "default": 512, "minimum": 0},
        "max_plaintext_chars": {
            "type": "integer",
            "default": 2000,
            "minimum": 0,
            "description": "Truncate each returned plaintext to this many characters (0 = no limit).",
        },
    }
    blob_props = {
        "data": {
            "type": "string",
            "description": "Ciphertext as hex, Base64, plain text, or latin-1 text.",
        },
        "data_encoding": {
            "type": "string",
            "enum": ["hex", "base64", "text", "latin-1"],
            "default": "hex",
        },
        "min_score": {"type": "number", "default": 60, "minimum": 0, "maximum": 100},
        "min_length": {"type": "integer", "default": 4, "minimum": 2},
        "schemes": {
            "type": "array",
            "items": {"type": "string", "enum": list(SCHEME_NAMES)},
            "description": "Schemes to try. Omit for all enabled schemes.",
        },
        "keys": _LIST_OF_STRINGS,
        "ivs": _LIST_OF_STRINGS,
        "cribs": _LIST_OF_STRINGS,
        "force_heavy": {"type": "boolean", "default": False},
        "heavy": {"type": "boolean", "default": True},
        "max_plaintext_chars": {"type": "integer", "default": 2000, "minimum": 0},
    }
    return [
        {
            "name": "scan_binary",
            "title": "Scan native binary",
            "description": (
                "Scan a native PE/ELF file for XOR/XorStr/Add/Sub/Rol, Base64, "
                "RC4, AES and DES strings. Keys are guessed from imports, names, "
                "strings and blobs, so `keys` may be omitted. Returns the same "
                "stable JSON payload as the CLI, including addresses and scores."
            ),
            "inputSchema": _json_schema(scan_props, required=["path"]),
            "annotations": {"title": "Scan native binary", **_READ_ONLY},
        },
        {
            "name": "decrypt_blob",
            "title": "Decrypt one ciphertext blob",
            "description": (
                "Try automatic decryption on one hex/Base64/text ciphertext blob. "
                "Useful for a string discovered by another IDA MCP tool."
            ),
            "inputSchema": _json_schema(blob_props, required=["data"]),
            "annotations": {"title": "Decrypt one ciphertext blob", **_READ_ONLY},
        },
        {
            "name": "list_schemes",
            "title": "List supported schemes",
            "description": "List supported schemes, data encodings and MCP server metadata.",
            "inputSchema": _json_schema({}),
            "annotations": {"title": "List supported schemes", **_READ_ONLY},
        },
    ]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    raise ValueError("expected a string or an array of strings")


def _requested_schemes(arguments: dict) -> list[str] | None:
    raw = arguments.get("schemes")
    if raw is None:
        return None
    schemes = [part.lower() for part in _as_list(raw)]
    if not schemes or "all" in schemes:
        return None
    aliases = {"b64": "base64", "rc4": "rc4"}
    normalized: list[str] = []
    for name in schemes:
        name = aliases.get(name, name)
        if name not in SCHEME_NAMES:
            raise ValueError(f"unknown scheme {name!r}; expected one of {', '.join(SCHEME_NAMES)}")
        if name not in normalized:
            normalized.append(name)
    return normalized


def _confidence(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    if score >= 55:
        return "low"
    return "very_low"


def _trim_plaintexts(results: list[dict], limit: int) -> None:
    if limit <= 0:
        return
    for result in results:
        text = result.get("plaintext", "")
        if len(text) > limit:
            result["plaintext"] = text[:limit]
            result["plaintext_truncated"] = True


def _scan_binary(arguments: dict) -> dict:
    path = os.path.abspath(os.path.expanduser(str(arguments.get("path", "")).strip()))
    if not path:
        raise ValueError("path is required")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"file not found: {path}")

    schemes = _requested_schemes(arguments)
    payload = cli.scan_path(
        path,
        min_score=float(arguments.get("min_score", 60.0)),
        min_length=int(arguments.get("min_length", 5)),
        max_results=int(arguments.get("max_results", 200)),
        max_candidates=int(arguments.get("max_candidates", 5000)),
        max_input=int(arguments.get("max_input", 8192)),
        max_entropy_blobs=int(arguments.get("max_entropy_blobs", 512)),
        schemes=schemes,
        keys=_as_list(arguments.get("keys")),
        ivs=_as_list(arguments.get("ivs")),
        cribs=_as_list(arguments.get("cribs")),
        custom_dirs=_as_list(arguments.get("custom_directories")),
        include_entropy=bool(arguments.get("include_entropy", True)),
        include_code=bool(arguments.get("include_code", False)),
        force_heavy=bool(arguments.get("force_heavy", False)),
        heavy=bool(arguments.get("heavy", True)),
        custom=bool(arguments.get("custom", True)),
    )
    payload["mcp"] = {"server": SERVER_NAME, "tool": "scan_binary"}
    _trim_plaintexts(payload.get("results", []), int(arguments.get("max_plaintext_chars", 2000)))
    return payload


def _decode_blob(arguments: dict) -> tuple[bytes, str]:
    value = arguments.get("data")
    if not isinstance(value, str) or not value:
        raise ValueError("data is required")
    encoding = str(arguments.get("data_encoding", "hex")).lower().replace("_", "-")
    if encoding == "hex":
        cleaned = value.strip().lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace("\\x", "").replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
        try:
            return bytes.fromhex(cleaned), "raw"
        except ValueError as error:
            raise ValueError(f"invalid hex data: {error}") from error
    if encoding in ("base64", "b64"):
        cleaned = "".join(value.split())
        try:
            return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True), "raw"
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"invalid Base64 data: {error}") from error
    if encoding in ("latin-1", "latin1"):
        return value.encode("latin-1", "replace"), "raw"
    if encoding in ("text", "utf-8", "utf8"):
        return value.encode("utf-8"), "text"
    raise ValueError("data_encoding must be hex, base64, text or latin-1")


def _decrypt_blob(arguments: dict) -> dict:
    raw, encoding = _decode_blob(arguments)
    if not raw:
        raise ValueError("decoded data is empty")
    if len(raw) > 65536:
        raise ValueError("blob is too large (maximum 65536 bytes)")

    config = ScanConfig(
        min_length=max(2, int(arguments.get("min_length", 4))),
        min_score=float(arguments.get("min_score", 60.0)),
        max_input_length=max(16, len(raw)),
        max_results_per_candidate=16,
        max_cipher_keys=64,
        max_cipher_ops=30000,
        force_heavy=bool(arguments.get("force_heavy", False)),
        enable_heavy=bool(arguments.get("heavy", True)),
    )
    schemes = _requested_schemes(arguments)
    if schemes is not None:
        enabled = set(schemes)
        config.enable_base64 = "base64" in enabled
        config.enable_xor = "xor" in enabled
        config.enable_xorstr = "xorstr" in enabled or "xor" in enabled
        config.enable_add = "add" in enabled
        config.enable_sub = "sub" in enabled
        config.enable_rol = "rol" in enabled
        config.enable_rc4 = "rc4" in enabled
        config.enable_aes = "aes" in enabled
        config.enable_des = "des" in enabled
        config.enable_custom = "custom" in enabled
        if not any(name in enabled for name in ("rc4", "aes", "des")):
            config.enable_heavy = False
    config.key_text = "\n".join(_as_list(arguments.get("keys")))
    config.iv_text = "\n".join(_as_list(arguments.get("ivs")))
    config.crib_text = "\n".join(_as_list(arguments.get("cribs")))
    config.prepare()
    config.key_material = list(config.user_keys)

    text = raw.decode("latin-1", "replace")
    candidate = Candidate(
        ea=0,
        raw=raw,
        kind="raw",
        encoding="raw",
        text=text if encoding == "text" else text,
        source="mcp",
    )
    engine = StringDecryptEngine(config)
    results = engine.scan_candidate(candidate)
    output = []
    for result in results:
        item = result.to_dict()
        item["confidence"] = _confidence(result.score)
        output.append(item)
    _trim_plaintexts(output, int(arguments.get("max_plaintext_chars", 2000)))
    return {
        "ok": True,
        "mcp": {"server": SERVER_NAME, "tool": "decrypt_blob"},
        "input_bytes": len(raw),
        "input_hex": raw[:256].hex(),
        "data_encoding": arguments.get("data_encoding", "hex"),
        "results": output,
    }


def _list_schemes(_arguments: dict) -> dict:
    return {
        "ok": True,
        "mcp": {"server": SERVER_NAME, "tool": "list_schemes"},
        "server": {
            "name": SERVER_NAME,
            "title": SERVER_TITLE,
            "version": __version__,
        },
        "protocol_versions": list(PROTOCOL_VERSIONS),
        "schemes": _SCHEME_INFO,
        "data_encodings": ["hex", "base64", "text", "latin-1"],
        "notes": (
            "scan_binary accepts a file path and needs no keys. decrypt_blob "
            "works on a single blob. For IDA database context, run this MCP "
            "server next to the official Hex-Rays IDA MCP server and use the "
            "addresses returned here with its disassembly/xref tools."
        ),
    }


_TOOLS = _tool_definitions()
_HANDLERS = {
    "scan_binary": _scan_binary,
    "decrypt_blob": _decrypt_blob,
    "list_schemes": _list_schemes,
}


class McpServer:
    def __init__(self, *, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.protocol = DEFAULT_PROTOCOL
        self._initialized = False

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------
    def send(self, message: dict) -> None:
        self.stream.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.stream.flush()

    def error(self, request_id, code: int, message: str) -> None:
        self.send({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        })

    def tool_result(self, payload: dict, *, is_error: bool = False) -> dict:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }
        # structuredContent is part of the 2025-06-18 schema.  Older clients
        # still get the JSON in content, so avoid sending an unknown field.
        if self.protocol >= "2025-06-18":
            result["structuredContent"] = payload
        return result

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------
    def handle(self, message: dict) -> None:
        if not isinstance(message, dict):
            self.error(None, -32600, "invalid request")
            return
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message

        if method == "initialize":
            params = message.get("params") or {}
            requested = str(params.get("protocolVersion", DEFAULT_PROTOCOL))
            self.protocol = requested if requested in PROTOCOL_VERSIONS else DEFAULT_PROTOCOL
            self._initialized = True
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": self.protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "title": SERVER_TITLE,
                        "version": __version__,
                    },
                    "instructions": (
                        "String decryptor for native PE/ELF files. Call scan_binary "
                        "with a path; keys are optional. Use decrypt_blob for one "
                        "ciphertext. Addresses can be passed to IDA MCP tools."
                    ),
                },
            })
            return

        if is_notification:
            # notifications/initialized, notifications/cancelled, ...
            return

        if not self._initialized and method != "ping":
            self.error(request_id, -32002, "server is not initialized")
            return

        if method == "ping":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {}})
            return
        if method == "tools/list":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": _TOOLS}})
            return
        if method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            handler = _HANDLERS.get(name)
            if handler is None:
                self.error(request_id, -32602, f"unknown tool: {name}")
                return
            if not isinstance(arguments, dict):
                self.error(request_id, -32602, "tool arguments must be an object")
                return
            try:
                payload = handler(arguments)
            except Exception as error:  # noqa: BLE001 - convert tool errors to results
                print(f"[{SERVER_NAME}] tool {name} failed: {error}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                self.send({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": self.tool_result(
                        {"ok": False, "error": str(error), "tool": name},
                        is_error=True,
                    ),
                })
                return
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": self.tool_result(payload),
            })
            return
        if method == "resources/list":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {"resources": []}})
            return
        if method == "prompts/list":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {"prompts": []}})
            return
        if method == "logging/setLevel":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {}})
            return

        self.error(request_id, -32601, f"method not found: {method}")

    def serve(self, input_stream=None) -> int:
        input_stream = input_stream or sys.stdin
        for line in input_stream:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as error:
                self.error(None, -32700, f"parse error: {error}")
                continue
            try:
                self.handle(message)
            except Exception as error:  # noqa: BLE001 - never kill the server
                print(f"[{SERVER_NAME}] request failed: {error}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                request_id = message.get("id") if isinstance(message, dict) else None
                if request_id is not None:
                    self.error(request_id, -32603, "internal error")
        return 0


def _config_payload(style: str) -> dict:
    """Build a copy-paste MCP client configuration for this installation."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    launcher = os.path.join(root, "mcp_server.py")
    if os.path.isfile(launcher):
        command = [sys.executable, launcher]
    else:
        # Running from an installed package without the root launcher.
        command = [sys.executable, "-m", "stringdecrypt.mcp_server"]
    if style == "vscode":
        return {
            "servers": {
                "stringdecrypt": {
                    "type": "stdio",
                    "command": command[0],
                    "args": command[1:],
                }
            }
        }
    if style == "opencode":
        return {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "stringdecrypt": {
                    "type": "local",
                    "command": command,
                    "enabled": True,
                }
            },
        }
    return {
        "mcpServers": {
            "stringdecrypt": {
                "command": command[0],
                "args": command[1:],
            }
        }
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-stringdecrypt-mcp",
        description="MCP stdio server for the native string decryptor.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="print a ready-to-paste MCP client configuration and exit",
    )
    parser.add_argument(
        "--config-style",
        choices=("mcpServers", "vscode", "opencode"),
        default="mcpServers",
        help="configuration dialect used by --print-config (default: mcpServers)",
    )
    args = parser.parse_args(argv)
    if args.print_config:
        print(json.dumps(_config_payload(args.config_style), indent=2))
        return 0

    # MCP uses newline-delimited UTF-8 JSON.  Windows consoles may default to
    # cp1252, which would corrupt non-ASCII plaintext.
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    return McpServer().serve()


if __name__ == "__main__":
    raise SystemExit(main())
