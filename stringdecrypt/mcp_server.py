"""MCP (Model Context Protocol) stdio server for the string decryptor.

The server is intentionally dependency-free: it speaks the small, stable
JSON-RPC subset used by MCP tool clients and can be launched directly:

    python mcp_server.py

It uses the same PE/ELF parser and decryption engine as the CLI, so an AI agent
can scan a file, map recovered strings back to addresses/sections, inspect
IOC/behavior context and decrypt a single blob without opening IDA.  When used
next to the official Hex-Rays IDA MCP server, the agent can take an address
returned here and inspect it in IDA with the official tools.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import traceback

from . import __version__, intel, stringmap
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

_RESOURCE_DEFS = [
    {
        "uri": "stringdecrypt://schemes",
        "name": "Supported schemes and limits",
        "title": "Supported schemes and limits",
        "description": "Scheme list, data encodings, tag vocabulary, entity types and server limits.",
        "mimeType": "application/json",
    },
    {
        "uri": "stringdecrypt://tags",
        "name": "String intelligence vocabulary",
        "title": "String intelligence vocabulary",
        "description": "Behavior tag definitions and entity types used by map_strings and extract_iocs.",
        "mimeType": "application/json",
    },
    {
        "uri": "stringdecrypt://usage",
        "name": "AI triage workflow",
        "title": "AI triage workflow",
        "description": "Recommended analyze -> map -> context workflow for this server.",
        "mimeType": "text/plain",
    },
]

_PROMPTS = [
    {
        "name": "triage_binary",
        "title": "Triage a native binary with string decryption",
        "description": "Analyze recovered strings, IOCs and behavior hints, then inspect the most interesting string in context.",
        "arguments": [
            {"name": "path", "description": "Path to the PE/ELF file to triage.", "required": True},
            {"name": "focus", "description": "Optional focus, for example network, persistence or credentials.", "required": False},
        ],
    },
]


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
_PATH_PROP = {
    "type": "string",
    "description": "Absolute or working-directory-relative path to a native PE or ELF file.",
}
_SCHEMES_PROP = {
    "type": "array",
    "items": {"type": "string", "enum": list(SCHEME_NAMES)},
    "description": "Schemes to try. Omit for all enabled schemes.",
}
_REFRESH_PROP = {
    "type": "boolean",
    "default": False,
    "description": "Ignore the scan cache and rescan the file.",
}
_LIMIT_PROP = {
    "type": "integer",
    "default": 50,
    "minimum": 1,
    "maximum": stringmap.MAX_PAGE_SIZE,
    "description": "Maximum strings in this page.",
}
_OFFSET_PROP = {
    "type": "integer",
    "default": 0,
    "minimum": 0,
    "description": "Pagination offset into the filtered string set.",
}
_TAGS_PROP = {
    **_LIST_OF_STRINGS,
    "description": "Behavior/content tags such as network, http, persistence, injection, url or registry.",
}
_ENTITY_TYPES_PROP = {
    "type": "array",
    "items": {"type": "string", "enum": list(intel.ENTITY_TYPES)},
    "description": "Only match strings containing one of these entity types.",
}


def _tool_definitions() -> list[dict]:
    scan_props = {
        "path": _PATH_PROP,
        "min_score": {
            "type": "number",
            "default": 60,
            "minimum": 0,
            "maximum": 100,
            "description": "Only return candidates at or above this confidence score.",
        },
        "min_length": {"type": "integer", "default": 5, "minimum": 2},
        "schemes": _SCHEMES_PROP,
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
        "timeout_seconds": {
            "type": "number",
            "default": 120,
            "minimum": 1,
            "maximum": 600,
            "description": "Stop the scan and return partial results after this many seconds.",
        },
        "refresh": _REFRESH_PROP,
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
        "schemes": _SCHEMES_PROP,
        "keys": _LIST_OF_STRINGS,
        "ivs": _LIST_OF_STRINGS,
        "cribs": _LIST_OF_STRINGS,
        "force_heavy": {"type": "boolean", "default": False},
        "heavy": {"type": "boolean", "default": True},
        "max_plaintext_chars": {"type": "integer", "default": 2000, "minimum": 0},
    }
    analyze_props = {
        "path": _PATH_PROP,
        "min_score": {
            "type": "number",
            "default": 60,
            "minimum": 0,
            "maximum": 100,
            "description": "Include recovered strings at or above this score.",
        },
        "notable_limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
        "max_iocs": {"type": "integer", "default": 30, "minimum": 0, "maximum": 200},
        "max_plaintext_chars": {"type": "integer", "default": 300, "minimum": 40, "maximum": 4000},
        "refresh": _REFRESH_PROP,
    }
    map_props = {
        "path": _PATH_PROP,
        "min_score": {"type": "number", "default": 30, "minimum": 0, "maximum": 100},
        "tags": _TAGS_PROP,
        "tag_mode": {
            "type": "string",
            "enum": ["any", "all"],
            "default": "any",
            "description": "Match strings with any or all requested tags.",
        },
        "entity_types": _ENTITY_TYPES_PROP,
        "schemes": _SCHEMES_PROP,
        "min_risk": {
            "type": "string",
            "enum": list(intel.RISK_LEVELS),
            "description": "Only return strings at or above this risk level.",
        },
        "query": {"type": "string", "description": "Case-insensitive substring filter on the recovered plaintext."},
        "regex": {"type": "boolean", "default": False, "description": "Treat query as a regular expression."},
        "sort": {"type": "string", "enum": ["address", "score", "risk"], "default": "address"},
        "offset": _OFFSET_PROP,
        "limit": _LIMIT_PROP,
        "include_entities": {"type": "boolean", "default": True},
        "include_original": {"type": "boolean", "default": False},
        "include_pipeline": {"type": "boolean", "default": False},
        "max_plaintext_chars": {"type": "integer", "default": 400, "minimum": 40, "maximum": 4000},
        "refresh": _REFRESH_PROP,
    }
    context_props = {
        "path": _PATH_PROP,
        "id": {"type": "string", "description": "Stable string ID returned by scan_binary, analyze_binary or map_strings."},
        "address": {"type": "string", "description": "Address or file offset as decimal or 0x-prefixed hex."},
        "text": {"type": "string", "description": "Exact or partial plaintext to locate."},
        "before": {"type": "integer", "default": 3, "minimum": 0, "maximum": 50},
        "after": {"type": "integer", "default": 3, "minimum": 0, "maximum": 50},
        "max_plaintext_chars": {"type": "integer", "default": 600, "minimum": 40, "maximum": 4000},
        "refresh": _REFRESH_PROP,
    }
    find_props = {
        "path": _PATH_PROP,
        "query": {"type": "string", "description": "Text or regular expression to search for in recovered strings."},
        "regex": {"type": "boolean", "default": False},
        "min_score": {"type": "number", "default": 30, "minimum": 0, "maximum": 100},
        "tags": _TAGS_PROP,
        "tag_mode": {"type": "string", "enum": ["any", "all"], "default": "any"},
        "entity_types": _ENTITY_TYPES_PROP,
        "schemes": _SCHEMES_PROP,
        "offset": _OFFSET_PROP,
        "limit": {**_LIMIT_PROP, "default": 30},
        "max_plaintext_chars": {"type": "integer", "default": 400, "minimum": 40, "maximum": 4000},
        "refresh": _REFRESH_PROP,
    }
    iocs_props = {
        "path": _PATH_PROP,
        "types": {
            "type": "array",
            "items": {"type": "string", "enum": list(intel.ENTITY_TYPES)},
            "description": "Restrict extraction to these entity types. Omit for all.",
        },
        "min_score": {"type": "number", "default": 55, "minimum": 0, "maximum": 100},
        "limit_per_type": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
        "defang": {"type": "boolean", "default": False, "description": "Add a defanged copy of each network indicator."},
        "refresh": _REFRESH_PROP,
    }
    return [
        {
            "name": "scan_binary",
            "title": "Scan native binary",
            "description": (
                "Scan a native PE/ELF file for XOR/XorStr/Add/Sub/Rol, Base64, "
                "RC4, AES and DES strings. Keys are guessed from imports, names, "
                "strings and blobs, so `keys` may be omitted. Returns addresses, "
                "sections, file offsets, stable string IDs, IOC/behavior tags and "
                "scores. The scan is cached by SHA-256."
            ),
            "inputSchema": _json_schema(scan_props, required=["path"]),
            "annotations": {"title": "Scan native binary", **_READ_ONLY},
        },
        {
            "name": "analyze_binary",
            "title": "Triage recovered strings",
            "description": (
                "Return a concise triage summary: file metadata, scheme/risk/tag "
                "counts, notable strings, network IOCs, suspicious imports and "
                "suggested next tool calls. Use this first on an unknown file."
            ),
            "inputSchema": _json_schema(analyze_props, required=["path"]),
            "annotations": {"title": "Triage recovered strings", **_READ_ONLY},
        },
        {
            "name": "map_strings",
            "title": "Map recovered strings to addresses",
            "description": (
                "Return a compact, paginated string map. Filter by tag, entity "
                "type, scheme, risk, score or plaintext. Each item includes a "
                "stable ID, address, file offset, section, tags, entities and "
                "plaintext; use get_string_context for code/context details."
            ),
            "inputSchema": _json_schema(map_props, required=["path"]),
            "annotations": {"title": "Map recovered strings", **_READ_ONLY},
        },
        {
            "name": "get_string_context",
            "title": "Get string context",
            "description": (
                "Resolve one string by stable ID, address or text and return its "
                "neighbors, possible pointer references, related imports, raw "
                "file window, tags and an IDA hand-off address."
            ),
            "inputSchema": _json_schema(context_props, required=["path"]),
            "annotations": {"title": "Get string context", **_READ_ONLY},
        },
        {
            "name": "find_strings",
            "title": "Search recovered strings",
            "description": (
                "Search recovered plaintext by substring or regular expression, "
                "with optional tag/entity/scheme filters. Results are paginated."
            ),
            "inputSchema": _json_schema(find_props, required=["path", "query"]),
            "annotations": {"title": "Search recovered strings", **_READ_ONLY},
        },
        {
            "name": "extract_iocs",
            "title": "Extract indicators of compromise",
            "description": (
                "Aggregate URLs, domains, IPs, emails, paths, registry keys, "
                "wallets, hashes and filenames from recovered strings. Each IOC "
                "keeps the stable string IDs and addresses that produced it."
            ),
            "inputSchema": _json_schema(iocs_props, required=["path"]),
            "annotations": {"title": "Extract indicators of compromise", **_READ_ONLY},
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
            "title": "List supported schemes and vocabulary",
            "description": "List supported schemes, encodings, tag definitions, entity types and server metadata.",
            "inputSchema": _json_schema({}),
            "annotations": {"title": "List supported schemes and vocabulary", **_READ_ONLY},
        },
    ]


# ----------------------------------------------------------------------
# Argument helpers
# ----------------------------------------------------------------------
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
    aliases = {"b64": "base64"}
    normalized: list[str] = []
    for name in schemes:
        name = aliases.get(name, name)
        if name not in SCHEME_NAMES:
            raise ValueError(f"unknown scheme {name!r}; expected one of {', '.join(SCHEME_NAMES)}")
        if name not in normalized:
            normalized.append(name)
    return normalized


def _integer(arguments: dict, name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        value = int(arguments.get(name, default))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _number(arguments: dict, name: str, default: float, *, minimum: float | None = None, maximum: float | None = None) -> float:
    try:
        value = float(arguments.get(name, default))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a number") from error
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _parse_address(value) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
        return int(text, 16)
    except ValueError as error:
        raise ValueError("address must be a decimal or hexadecimal value") from error


def _confidence(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    if score >= 55:
        return "low"
    return "very_low"


def _mark_mcp(payload: dict, tool: str) -> dict:
    payload["mcp"] = {"server": SERVER_NAME, "tool": tool}
    return payload


# ----------------------------------------------------------------------
# Tool implementations
# ----------------------------------------------------------------------
def _scan_binary(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    options = {
        "min_score": _number(arguments, "min_score", 60.0, minimum=0.0, maximum=100.0),
        "min_length": _integer(arguments, "min_length", 5, minimum=2, maximum=4096),
        "max_results": _integer(arguments, "max_results", 200, minimum=1, maximum=5000),
        "max_candidates": _integer(arguments, "max_candidates", 5000, minimum=1, maximum=200000),
        "max_input": _integer(arguments, "max_input", 8192, minimum=16, maximum=1_000_000),
        "max_entropy_blobs": _integer(arguments, "max_entropy_blobs", 512, minimum=0, maximum=100000),
        "schemes": _requested_schemes(arguments),
        "keys": _as_list(arguments.get("keys")),
        "ivs": _as_list(arguments.get("ivs")),
        "cribs": _as_list(arguments.get("cribs")),
        "custom_dirs": _as_list(arguments.get("custom_directories")),
        "include_entropy": bool(arguments.get("include_entropy", True)),
        "include_code": bool(arguments.get("include_code", False)),
        "force_heavy": bool(arguments.get("force_heavy", False)),
        "heavy": bool(arguments.get("heavy", True)),
        "custom": bool(arguments.get("custom", True)),
        "timeout_seconds": _number(arguments, "timeout_seconds", 120.0, minimum=1.0, maximum=600.0),
        "enrich": True,
    }
    payload, meta = stringmap.scan_file(path, options=options, refresh=bool(arguments.get("refresh", False)))
    output = stringmap.present_scan(
        payload,
        meta,
        plaintext_limit=_integer(arguments, "max_plaintext_chars", 2000, minimum=0, maximum=200000),
    )
    return _mark_mcp(output, "scan_binary")


def _analyze_binary(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    return stringmap.analyze_binary(
        path,
        min_score=_number(arguments, "min_score", 60.0, minimum=0.0, maximum=100.0),
        notable_limit=_integer(arguments, "notable_limit", 20, minimum=1, maximum=100),
        max_iocs=_integer(arguments, "max_iocs", 30, minimum=0, maximum=200),
        plaintext_limit=_integer(arguments, "max_plaintext_chars", 300, minimum=40, maximum=4000),
        refresh=bool(arguments.get("refresh", False)),
    )


def _map_strings(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    return stringmap.map_strings(
        path,
        min_score=_number(arguments, "min_score", 30.0, minimum=0.0, maximum=100.0),
        tags=_as_list(arguments.get("tags")),
        tag_mode=str(arguments.get("tag_mode", "any")),
        entity_types=_as_list(arguments.get("entity_types")),
        schemes=_requested_schemes(arguments),
        min_risk=arguments.get("min_risk"),
        query=arguments.get("query"),
        regex=bool(arguments.get("regex", False)),
        sort=str(arguments.get("sort", "address")),
        offset=_integer(arguments, "offset", 0, minimum=0),
        limit=_integer(arguments, "limit", 50, minimum=1, maximum=stringmap.MAX_PAGE_SIZE),
        include_entities=bool(arguments.get("include_entities", True)),
        include_original=bool(arguments.get("include_original", False)),
        include_pipeline=bool(arguments.get("include_pipeline", False)),
        plaintext_limit=_integer(arguments, "max_plaintext_chars", 400, minimum=40, maximum=4000),
        refresh=bool(arguments.get("refresh", False)),
    )


def _get_string_context(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    return stringmap.get_string_context(
        path,
        string_id=str(arguments.get("id", "") or "") or None,
        address=_parse_address(arguments.get("address")),
        text=str(arguments.get("text", "") or "") or None,
        before=_integer(arguments, "before", 3, minimum=0, maximum=50),
        after=_integer(arguments, "after", 3, minimum=0, maximum=50),
        plaintext_limit=_integer(arguments, "max_plaintext_chars", 600, minimum=40, maximum=4000),
        refresh=bool(arguments.get("refresh", False)),
    )


def _find_strings(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    return stringmap.find_strings(
        path,
        str(arguments.get("query", "")),
        regex=bool(arguments.get("regex", False)),
        min_score=_number(arguments, "min_score", 30.0, minimum=0.0, maximum=100.0),
        tags=_as_list(arguments.get("tags")),
        tag_mode=str(arguments.get("tag_mode", "any")),
        entity_types=_as_list(arguments.get("entity_types")),
        schemes=_requested_schemes(arguments),
        offset=_integer(arguments, "offset", 0, minimum=0),
        limit=_integer(arguments, "limit", 30, minimum=1, maximum=stringmap.MAX_PAGE_SIZE),
        plaintext_limit=_integer(arguments, "max_plaintext_chars", 400, minimum=40, maximum=4000),
        refresh=bool(arguments.get("refresh", False)),
    )


def _extract_iocs(arguments: dict) -> dict:
    path = stringmap.validate_path(str(arguments.get("path", "")))
    return stringmap.extract_iocs(
        path,
        types=_as_list(arguments.get("types")),
        min_score=_number(arguments, "min_score", 55.0, minimum=0.0, maximum=100.0),
        limit_per_type=_integer(arguments, "limit_per_type", 100, minimum=1, maximum=1000),
        defang=bool(arguments.get("defang", False)),
        refresh=bool(arguments.get("refresh", False)),
    )


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
        min_length=max(2, _integer(arguments, "min_length", 4, minimum=2, maximum=65536)),
        min_score=_number(arguments, "min_score", 60.0, minimum=0.0, maximum=100.0),
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
    limit = _integer(arguments, "max_plaintext_chars", 2000, minimum=0, maximum=200000)
    output = []
    for result in results:
        item = result.to_dict()
        item["id"] = intel.string_id(0, result.plaintext)
        item["confidence"] = _confidence(result.score)
        intelligence = intel.analyze_text(result.plaintext)
        item["tags"] = list(intelligence.tags)
        item["entities"] = intelligence.entities_dict()
        item["risk"] = intelligence.risk
        if limit and len(item["plaintext"]) > limit:
            item["plaintext"] = item["plaintext"][:limit]
            item["plaintext_truncated"] = True
        output.append(item)
    return {
        "ok": True,
        "mcp": {"server": SERVER_NAME, "tool": "decrypt_blob"},
        "input_bytes": len(raw),
        "input_hex": raw[:256].hex(),
        "data_encoding": arguments.get("data_encoding", "hex"),
        "results": output,
    }


def _schemes_payload() -> dict:
    return {
        "server": {"name": SERVER_NAME, "title": SERVER_TITLE, "version": __version__},
        "protocol_versions": list(PROTOCOL_VERSIONS),
        "schemes": _SCHEME_INFO,
        "data_encodings": ["hex", "base64", "text", "latin-1"],
        "entity_types": list(intel.ENTITY_TYPES),
        "tags": intel.TAG_DEFINITIONS,
        "limits": stringmap.limits(),
        "cache": stringmap.cache_stats(),
        "notes": (
            "scan_binary accepts a file path and needs no keys. analyze_binary, "
            "map_strings, get_string_context, find_strings and extract_iocs share "
            "a SHA-256-keyed scan cache inside this process. Addresses can be "
            "passed to the official IDA MCP server."
        ),
    }


def _list_schemes(_arguments: dict) -> dict:
    output = _schemes_payload()
    output.update({
        "ok": True,
        "mcp": {"server": SERVER_NAME, "tool": "list_schemes"},
        "tools": [tool["name"] for tool in _TOOLS],
    })
    return output


_TOOLS = _tool_definitions()
_HANDLERS = {
    "scan_binary": _scan_binary,
    "analyze_binary": _analyze_binary,
    "map_strings": _map_strings,
    "get_string_context": _get_string_context,
    "find_strings": _find_strings,
    "extract_iocs": _extract_iocs,
    "decrypt_blob": _decrypt_blob,
    "list_schemes": _list_schemes,
}


# ----------------------------------------------------------------------
# MCP resources and prompts
# ----------------------------------------------------------------------
def _resource_text(uri: str) -> tuple[str, str]:
    if uri == "stringdecrypt://schemes":
        return "application/json", json.dumps(_schemes_payload(), indent=2, ensure_ascii=False)
    if uri == "stringdecrypt://tags":
        payload = {
            "tags": intel.TAG_DEFINITIONS,
            "entity_types": list(intel.ENTITY_TYPES),
            "risk_levels": list(intel.RISK_LEVELS),
            "id_format": "s_<12 hex chars of sha1(ea + NUL + plaintext)>",
        }
        return "application/json", json.dumps(payload, indent=2, ensure_ascii=False)
    if uri == "stringdecrypt://usage":
        return "text/plain", (
            "String decryptor triage workflow:\n"
            "1. analyze_binary(path) for a compact summary, tags, IOCs and imports.\n"
            "2. map_strings(path, tags=[...], limit=50) to inspect filtered strings.\n"
            "3. get_string_context(path, id=...) for neighbors, pointer references and an IDA hand-off address.\n"
            "4. extract_iocs(path) for aggregated indicators.\n"
            "5. Use the official IDA MCP server with the returned address for xrefs/decompilation.\n"
        )
    raise ValueError(f"unknown resource: {uri}")


def _prompt_messages(arguments: dict) -> list[dict]:
    path = str(arguments.get("path", "") or "").strip() or "<path>"
    focus = str(arguments.get("focus", "") or "").strip()
    focus_text = f" Focus especially on: {focus}." if focus else ""
    text = (
        f"Triage the native binary at {path} with the string-decryptor tools. "
        "Start with analyze_binary, then inspect notable strings with map_strings "
        "and get_string_context, and aggregate indicators with extract_iocs. "
        "Treat tags as hints, cite stable string IDs and addresses, and do not "
        "invent indicators that are not in the tool output."
        f"{focus_text}"
    )
    return [{"role": "user", "content": {"type": "text", "text": text}}]


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
                "servers": {
                    "stringdecrypt": {
                        "type": "local",
                        "command": command,
                    }
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
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "title": SERVER_TITLE,
                        "version": __version__,
                    },
                    "instructions": (
                        "String decryptor for native PE/ELF files. Call "
                        "analyze_binary first, then map_strings or find_strings "
                        "and get_string_context for specific hits. extract_iocs "
                        "aggregates indicators. Keys are optional and scans are "
                        "cached by SHA-256. Addresses can be passed to IDA MCP tools."
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
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"resources": _RESOURCE_DEFS},
            })
            return
        if method == "resources/templates/list":
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"resourceTemplates": []},
            })
            return
        if method == "resources/read":
            params = message.get("params") or {}
            uri = str(params.get("uri", ""))
            try:
                mime, text = _resource_text(uri)
            except ValueError as error:
                self.error(request_id, -32602, str(error))
                return
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [{"uri": uri, "mimeType": mime, "text": text}]
                },
            })
            return
        if method == "prompts/list":
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"prompts": _PROMPTS},
            })
            return
        if method == "prompts/get":
            params = message.get("params") or {}
            name = params.get("name")
            if name != "triage_binary":
                self.error(request_id, -32602, f"unknown prompt: {name}")
                return
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                self.error(request_id, -32602, "prompt arguments must be an object")
                return
            self.send({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "description": "Triage a native binary with string decryption.",
                    "messages": _prompt_messages(arguments),
                },
            })
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
