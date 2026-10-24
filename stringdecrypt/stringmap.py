"""String mapping and triage helpers used by the MCP server.

This module turns the raw scan payload into compact, paginated, AI-friendly
views: a string map, per-string context (including possible pointer references),
IOC aggregation and a binary triage summary.  It also owns the process-local
scan cache.
"""

from __future__ import annotations

import json
import os
import re
import struct
import time
from collections import Counter
from typing import Iterable, Sequence

from . import __version__, cli, intel, peelf, scancache

MAX_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 90.0
MAX_PAGE_SIZE = 500

DEFAULT_SCAN_OPTIONS: dict = {
    "min_score": 30.0,
    "min_length": 5,
    "max_results": 3000,
    "max_candidates": 20000,
    "max_input": 8192,
    "max_entropy_blobs": 768,
    "schemes": None,
    "keys": None,
    "ivs": None,
    "cribs": None,
    "custom_dirs": None,
    "include_entropy": True,
    "include_code": False,
    "force_heavy": False,
    "heavy": True,
    "custom": True,
    "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    "enrich": True,
}

_CACHE = scancache.cache_from_env()

# x86-64 instructions with a RIP-relative memory operand: optional REX prefix,
# LEA (0x8d) or MOV (0x8b) opcode.  The ModRM byte is validated below.
_RIP_INSTRUCTION_RE = re.compile(rb"[\x40-\x4f]?[\x8d\x8b]")

_RELATED_IMPORT_ALIASES = {
    "http": "network",
    "dns": "network",
    "download": "network",
    "exfiltration": "network",
    "command": "execution",
    "process": "process",
    "injection": "injection",
    "registry": "persistence",
    "credential_theft": "credential",
}


def cache_stats() -> dict:
    return _CACHE.stats()


def limits() -> dict:
    return {
        "max_file_bytes": MAX_FILE_BYTES,
        "max_page_size": MAX_PAGE_SIZE,
        "default_scan_results": DEFAULT_SCAN_OPTIONS["max_results"],
        "default_scan_candidates": DEFAULT_SCAN_OPTIONS["max_candidates"],
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "context_scan_min_score": DEFAULT_SCAN_OPTIONS["min_score"],
    }


def validate_path(path: str) -> str:
    value = os.path.abspath(os.path.expanduser(str(path or "").strip()))
    if not value:
        raise ValueError("path is required")
    if not os.path.isfile(value):
        raise FileNotFoundError(f"file not found: {value}")
    size = os.path.getsize(value)
    if size > MAX_FILE_BYTES:
        raise ValueError(
            f"file is too large ({size} bytes; maximum {MAX_FILE_BYTES} bytes)"
        )
    return value


def _normalize_options(options: dict | None) -> dict:
    merged = dict(DEFAULT_SCAN_OPTIONS)
    for key, value in (options or {}).items():
        if key in merged and value is not None:
            merged[key] = value
    for key in ("schemes", "keys", "ivs", "cribs", "custom_dirs"):
        value = merged.get(key)
        if value is not None and not isinstance(value, str):
            merged[key] = tuple(str(item) for item in value)
    return merged


def _cache_key(path: str, digest: str, options: dict) -> str:
    payload = json.dumps(options, sort_keys=True, default=str, separators=(",", ":"))
    return f"{__version__}|{path}|{digest}|{payload}"


def scan_file(
    path: str,
    *,
    options: dict | None = None,
    refresh: bool = False,
) -> tuple[dict, dict]:
    """Return a cached scan payload and its cache metadata."""
    path = validate_path(path)
    digest, stat = _CACHE.digest(path)
    settings = _normalize_options(options)
    key = _cache_key(path, digest, settings)
    cached = _CACHE.get(key, refresh=refresh)
    if cached is not None:
        payload, age = cached
        hit = True
    else:
        payload = cli.scan_path(path, **settings)
        _CACHE.put(key, payload)
        age = 0.0
        hit = False
    meta = {
        "hit": hit,
        "age_seconds": round(age, 2),
        "sha256": digest,
        "size": stat.st_size,
        "entries": _CACHE.stats()["entries"],
    }
    return payload, meta


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    if limit and len(text) > limit:
        return text[:limit], True
    return text, False


def _copy_result(result: dict, plaintext_limit: int = 2000) -> dict:
    item = dict(result)
    text, truncated = _truncate(str(item.get("plaintext", "")), plaintext_limit)
    item["plaintext"] = text
    if truncated:
        item["plaintext_truncated"] = True
    return item


def present_scan(payload: dict, meta: dict, *, plaintext_limit: int = 2000) -> dict:
    """Copy a cached payload before adding MCP-specific fields."""
    output = dict(payload)
    output["stats"] = dict(payload.get("stats", {}))
    output["stats"]["cached"] = bool(meta.get("hit"))
    output["stats"]["timed_out"] = bool(output["stats"].get("timed_out", False))
    output["cache"] = {
        "hit": bool(meta.get("hit")),
        "age_seconds": meta.get("age_seconds", 0.0),
        "sha256": meta.get("sha256"),
        "entries": meta.get("entries", 0),
    }
    output["results"] = [
        _copy_result(result, plaintext_limit) for result in payload.get("results", [])
    ]
    if meta.get("sha256"):
        output["sha256"] = meta["sha256"]
    return output


def file_summary(payload: dict) -> dict:
    image = payload.get("image", {})
    return {
        "path": payload.get("file"),
        "sha256": payload.get("sha256") or image.get("sha256"),
        "size": image.get("size"),
        "format": image.get("format"),
        "bits": image.get("bits"),
        "machine": image.get("machine"),
        "file_type": image.get("file_type"),
        "image_base": image.get("image_base"),
        "entry": image.get("entry"),
        "sections": len(image.get("sections", [])),
        "imports": len(image.get("imports", [])),
        "warnings": image.get("warnings", []),
    }


def scan_summary(payload: dict) -> dict:
    stats = payload.get("stats", {})
    config = payload.get("config", {})
    return {
        "min_score": config.get("min_score"),
        "schemes": config.get("schemes"),
        "elapsed_seconds": stats.get("elapsed_seconds"),
        "timed_out": bool(stats.get("timed_out", False)),
    }


def _address(result: dict) -> int:
    try:
        return int(result.get("ea", 0))
    except (TypeError, ValueError):
        return 0


def result_item(
    result: dict,
    *,
    include_entities: bool = True,
    include_original: bool = False,
    include_pipeline: bool = False,
    plaintext_limit: int = 400,
) -> dict:
    plaintext, truncated = _truncate(str(result.get("plaintext", "")), plaintext_limit)
    item = {
        "id": result.get("id") or intel.string_id(_address(result), plaintext),
        "address": result.get("address") or f"0x{_address(result):x}",
        "ea": _address(result),
        "file_offset": result.get("file_offset"),
        "section": result.get("section") or result.get("segment") or "",
        "scheme": result.get("scheme", ""),
        "score": result.get("score"),
        "confidence": result.get("confidence", ""),
        "risk": result.get("risk", "info"),
        "tags": list(result.get("tags", []) or []),
        "plaintext": plaintext,
    }
    if truncated:
        item["plaintext_truncated"] = True
    if result.get("key"):
        item["key"] = result["key"]
    if include_pipeline and result.get("pipeline"):
        item["pipeline"] = result["pipeline"]
    if include_original and result.get("original"):
        item["original"] = result["original"]
    if result.get("xrefs"):
        item["xrefs"] = list(result["xrefs"])
    if include_entities:
        item["entities"] = {
            name: list(values)
            for name, values in (result.get("entities", {}) or {}).items()
            if values
        }
    return item


def _normalize_list(value: Sequence[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(part).strip() for part in value if str(part).strip()]


def filter_results(
    results: Iterable[dict],
    *,
    min_score: float = 0.0,
    tags: Sequence[str] | None = None,
    tag_mode: str = "any",
    entity_types: Sequence[str] | None = None,
    schemes: Sequence[str] | None = None,
    min_risk: str | None = None,
    query: str | None = None,
    regex: bool = False,
) -> list[dict]:
    requested_tags = {tag.lower() for tag in _normalize_list(tags)}
    unknown_tags = requested_tags - set(intel.TAG_DEFINITIONS)
    if unknown_tags:
        raise ValueError(
            "unknown tag(s): "
            + ", ".join(sorted(unknown_tags))
            + "; use list_schemes to see the tag vocabulary"
        )
    requested_entities = {name.lower() for name in _normalize_list(entity_types)}
    unknown_entities = requested_entities - set(intel.ENTITY_TYPES)
    if unknown_entities:
        raise ValueError(
            "unknown entity type(s): "
            + ", ".join(sorted(unknown_entities))
            + "; expected one of "
            + ", ".join(intel.ENTITY_TYPES)
        )
    requested_schemes = {name.lower() for name in _normalize_list(schemes)}
    mode = str(tag_mode or "any").lower()
    if mode not in ("any", "all"):
        raise ValueError("tag_mode must be 'any' or 'all'")
    risk_floor = intel.risk_weight(min_risk) if min_risk else 0
    if min_risk and str(min_risk).lower() not in intel.RISK_LEVELS:
        raise ValueError("min_risk must be info, low, medium or high")

    pattern = None
    if query:
        if regex:
            try:
                pattern = re.compile(query, re.I)
            except re.error as error:
                raise ValueError(f"invalid regular expression: {error}") from error
        query_lower = query.lower()

    selected: list[dict] = []
    for result in results:
        try:
            score = float(result.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        if score < float(min_score):
            continue
        if requested_schemes and str(result.get("scheme", "")).lower() not in requested_schemes:
            continue
        result_tags = {str(tag).lower() for tag in result.get("tags", []) or []}
        if requested_tags:
            if mode == "all" and not requested_tags <= result_tags:
                continue
            if mode == "any" and not requested_tags & result_tags:
                continue
        if requested_entities:
            result_entities = {
                str(name).lower()
                for name, values in (result.get("entities", {}) or {}).items()
                if values
            }
            if not requested_entities & result_entities:
                continue
        if risk_floor and intel.risk_weight(result.get("risk", "info")) < risk_floor:
            continue
        if query:
            haystack = str(result.get("plaintext", ""))
            if pattern is not None:
                if not pattern.search(haystack):
                    continue
            elif query_lower not in haystack.lower():
                continue
        selected.append(result)

    return selected


def sort_results(results: list[dict], sort: str = "address") -> list[dict]:
    key = str(sort or "address").lower()
    if key == "score":
        return sorted(results, key=lambda item: (-float(item.get("score", 0.0)), _address(item)))
    if key == "risk":
        return sorted(
            results,
            key=lambda item: (
                -intel.risk_weight(item.get("risk", "info")),
                -float(item.get("score", 0.0)),
                _address(item),
            ),
        )
    if key != "address":
        raise ValueError("sort must be address, score or risk")
    return sorted(
        results,
        key=lambda item: (
            _address(item),
            item.get("file_offset") if item.get("file_offset") is not None else -1,
            -float(item.get("score", 0.0)),
            str(item.get("scheme", "")),
        ),
    )


def facets(results: Iterable[dict]) -> dict:
    tag_counts: Counter[str] = Counter()
    scheme_counts: Counter[str] = Counter()
    risk_counts: Counter[str] = Counter()
    entity_counts: Counter[str] = Counter()
    tagged = 0
    for result in results:
        tags = list(result.get("tags", []) or [])
        if tags:
            tagged += 1
        tag_counts.update(tags)
        scheme_counts.update([str(result.get("scheme", ""))])
        risk_counts.update([str(result.get("risk", "info"))])
        for name, values in (result.get("entities", {}) or {}).items():
            if values:
                entity_counts[name] += 1
    return {
        "strings": sum(1 for _ in results),
        "tagged_strings": tagged,
        "tags": dict(tag_counts.most_common(40)),
        "schemes": dict(sorted(scheme_counts.items())),
        "risks": dict(sorted(risk_counts.items())),
        "entity_types": dict(sorted(entity_counts.items(), key=lambda item: (-item[1], item[0]))),
    }


def _collection_payload(
    *,
    tool: str,
    path: str,
    payload: dict,
    meta: dict,
    filtered: list[dict],
    offset: int,
    limit: int,
    plaintext_limit: int,
    include_entities: bool,
    include_original: bool,
    include_pipeline: bool,
    extra: dict | None = None,
) -> dict:
    total = len(filtered)
    offset = max(0, min(int(offset), total))
    limit = max(1, min(int(limit), MAX_PAGE_SIZE))
    page = filtered[offset:offset + limit]
    next_offset = offset + len(page) if offset + len(page) < total else None
    output = {
        "ok": True,
        "mcp": {"server": "ida-stringdecrypt", "tool": tool},
        "file": file_summary(payload),
        "scan": scan_summary(payload),
        "cache": {
            "hit": bool(meta.get("hit")),
            "age_seconds": meta.get("age_seconds", 0.0),
        },
        "stats": {
            "total_results": len(payload.get("results", [])),
            "matched": total,
            "returned": len(page),
            "offset": offset,
            "next_offset": next_offset,
            "truncated": next_offset is not None,
            "timed_out": bool(payload.get("stats", {}).get("timed_out", False)),
            "elapsed_seconds": payload.get("stats", {}).get("elapsed_seconds"),
        },
        "facets": facets(filtered),
        "strings": [
            result_item(
                result,
                include_entities=include_entities,
                include_original=include_original,
                include_pipeline=include_pipeline,
                plaintext_limit=plaintext_limit,
            )
            for result in page
        ],
    }
    if extra:
        output.update(extra)
    return output


def map_strings(
    path: str,
    *,
    min_score: float = 30.0,
    tags: Sequence[str] | None = None,
    tag_mode: str = "any",
    entity_types: Sequence[str] | None = None,
    schemes: Sequence[str] | None = None,
    min_risk: str | None = None,
    query: str | None = None,
    regex: bool = False,
    sort: str = "address",
    offset: int = 0,
    limit: int = 50,
    include_entities: bool = True,
    include_original: bool = False,
    include_pipeline: bool = False,
    plaintext_limit: int = 400,
    refresh: bool = False,
) -> dict:
    scan_min = min(float(DEFAULT_SCAN_OPTIONS["min_score"]), float(min_score))
    payload, meta = scan_file(
        path,
        options={"min_score": scan_min},
        refresh=refresh,
    )
    filtered = filter_results(
        payload.get("results", []),
        min_score=min_score,
        tags=tags,
        tag_mode=tag_mode,
        entity_types=entity_types,
        schemes=schemes,
        min_risk=min_risk,
        query=query,
        regex=regex,
    )
    filtered = sort_results(filtered, sort)
    return _collection_payload(
        tool="map_strings",
        path=path,
        payload=payload,
        meta=meta,
        filtered=filtered,
        offset=offset,
        limit=limit,
        plaintext_limit=plaintext_limit,
        include_entities=include_entities,
        include_original=include_original,
        include_pipeline=include_pipeline,
        extra={"filters": {
            "min_score": min_score,
            "tags": list(tags or []),
            "tag_mode": tag_mode,
            "entity_types": list(entity_types or []),
            "schemes": list(schemes or []),
            "min_risk": min_risk,
            "query": query,
            "regex": bool(regex),
            "sort": sort,
        }},
    )


def find_strings(
    path: str,
    query: str,
    *,
    regex: bool = False,
    min_score: float = 30.0,
    tags: Sequence[str] | None = None,
    tag_mode: str = "any",
    entity_types: Sequence[str] | None = None,
    schemes: Sequence[str] | None = None,
    offset: int = 0,
    limit: int = 30,
    plaintext_limit: int = 400,
    refresh: bool = False,
) -> dict:
    if not str(query or "").strip():
        raise ValueError("query is required")
    payload, meta = scan_file(
        path,
        options={"min_score": min(float(DEFAULT_SCAN_OPTIONS["min_score"]), float(min_score))},
        refresh=refresh,
    )
    filtered = filter_results(
        payload.get("results", []),
        min_score=min_score,
        tags=tags,
        tag_mode=tag_mode,
        entity_types=entity_types,
        schemes=schemes,
        query=query,
        regex=regex,
    )
    filtered = sort_results(filtered, "score")
    return _collection_payload(
        tool="find_strings",
        path=path,
        payload=payload,
        meta=meta,
        filtered=filtered,
        offset=offset,
        limit=limit,
        plaintext_limit=plaintext_limit,
        include_entities=True,
        include_original=False,
        include_pipeline=False,
        extra={
            "query": query,
            "regex": bool(regex),
            "filters": {"min_score": min_score, "tags": list(tags or []), "tag_mode": tag_mode},
        },
    )


def aggregate_entities(
    results: Iterable[dict],
    *,
    types: Sequence[str] | None = None,
    min_score: float = 0.0,
) -> dict[str, list[dict]]:
    requested = {str(name).lower() for name in _normalize_list(types)}
    if requested:
        unknown = requested - set(intel.ENTITY_TYPES)
        if unknown:
            raise ValueError(
                "unknown entity type(s): "
                + ", ".join(sorted(unknown))
                + "; expected one of "
                + ", ".join(intel.ENTITY_TYPES)
            )
    allowed = requested or set(intel.ENTITY_TYPES)
    buckets: dict[str, dict[str, dict]] = {}
    case_insensitive = {"url", "domain", "ip", "email", "hash", "filename", "registry"}
    for result in results:
        try:
            if float(result.get("score", 0.0)) < float(min_score):
                continue
        except (TypeError, ValueError):
            continue
        address = result.get("address") or f"0x{_address(result):x}"
        string_id = result.get("id") or intel.string_id(_address(result), result.get("plaintext", ""))
        try:
            result_score = float(result.get("score", 0.0))
        except (TypeError, ValueError):
            result_score = 0.0
        for name, values in (result.get("entities", {}) or {}).items():
            if name not in allowed:
                continue
            for value in values or []:
                key = value.lower() if name in case_insensitive else value
                bucket = buckets.setdefault(name, {})
                record = bucket.get(key)
                if record is None:
                    record = {
                        "value": value,
                        "count": 0,
                        "max_score": 0.0,
                        "string_ids": [],
                        "addresses": [],
                    }
                    bucket[key] = record
                record["count"] += 1
                record["max_score"] = round(max(record["max_score"], result_score), 2)
                if len(record["string_ids"]) < 20 and string_id not in record["string_ids"]:
                    record["string_ids"].append(string_id)
                if len(record["addresses"]) < 20 and address not in record["addresses"]:
                    record["addresses"].append(address)
    output: dict[str, list[dict]] = {}
    for name, bucket in buckets.items():
        output[name] = sorted(
            bucket.values(),
            key=lambda item: (-item["count"], str(item["value"]).lower()),
        )
    return output


def extract_iocs(
    path: str,
    *,
    types: Sequence[str] | None = None,
    min_score: float = 55.0,
    limit_per_type: int = 100,
    defang: bool = False,
    refresh: bool = False,
) -> dict:
    requested = _normalize_list(types)
    payload, meta = scan_file(
        path,
        options={"min_score": min(float(DEFAULT_SCAN_OPTIONS["min_score"]), float(min_score))},
        refresh=refresh,
    )
    selected = filter_results(payload.get("results", []), min_score=min_score)
    entities = aggregate_entities(selected, types=requested, min_score=min_score)
    limit = max(1, min(int(limit_per_type), 1000))
    output: dict[str, list[dict]] = {}
    totals: dict[str, int] = {}
    truncated: dict[str, int] = {}
    for name, records in entities.items():
        totals[name] = len(records)
        page = records[:limit]
        if len(records) > limit:
            truncated[name] = len(records) - limit
        items = []
        for record in page:
            item = dict(record)
            if defang:
                item["defanged"] = intel.defang_entity(name, record["value"])
            items.append(item)
        output[name] = items
    ioc_strings = sum(
        1
        for result in selected
        if any((result.get("entities", {}) or {}).get(name) for name in entities)
    )
    return {
        "ok": True,
        "mcp": {"server": "ida-stringdecrypt", "tool": "extract_iocs"},
        "file": file_summary(payload),
        "cache": {"hit": bool(meta.get("hit")), "age_seconds": meta.get("age_seconds", 0.0)},
        "stats": {
            "strings_with_iocs": ioc_strings,
            "unique_indicators": sum(totals.values()),
            "types": len(output),
            "timed_out": bool(payload.get("stats", {}).get("timed_out", False)),
        },
        "counts": dict(sorted(totals.items(), key=lambda item: (-item[1], item[0]))),
        "truncated": truncated,
        "min_score": min_score,
        "iocs": dict(sorted(output.items())),
    }


def analyze_binary(
    path: str,
    *,
    min_score: float = 60.0,
    notable_limit: int = 20,
    max_iocs: int = 30,
    plaintext_limit: int = 300,
    refresh: bool = False,
) -> dict:
    payload, meta = scan_file(
        path,
        options={"min_score": min(float(DEFAULT_SCAN_OPTIONS["min_score"]), float(min_score))},
        refresh=refresh,
    )
    results = filter_results(payload.get("results", []), min_score=min_score)
    ranked = sorted(
        results,
        key=lambda item: (
            -intel.risk_weight(item.get("risk", "info")),
            -float(item.get("score", 0.0)),
            -len(item.get("tags", []) or []),
            _address(item),
        ),
    )
    notable_limit = max(1, min(int(notable_limit), 100))
    notable = [
        result_item(result, plaintext_limit=plaintext_limit)
        for result in ranked[:notable_limit]
    ]
    tag_counts = Counter(
        tag for result in results for tag in (result.get("tags", []) or [])
    )
    risk_counts = Counter(str(result.get("risk", "info")) for result in results)
    entity_counts = intel.entity_type_counts(results)
    entities = aggregate_entities(
        results,
        types=("url", "domain", "ip", "email", "wallet", "registry", "path"),
        min_score=min_score,
    )
    network_iocs: list[dict] = []
    for name in ("url", "domain", "ip", "email"):
        for record in entities.get(name, []):
            network_iocs.append({"type": name, **record})
    network_iocs.sort(key=lambda item: (-item["count"], item["type"], item["value"].lower()))
    max_iocs = max(0, min(int(max_iocs), 200))
    network_iocs = network_iocs[:max_iocs]

    image = payload.get("image", {})
    imports = intel.suspicious_imports(image.get("imports", []), limit=50)
    import_categories = Counter(
        category for item in imports for category in item["categories"]
    )
    stats = payload.get("stats", {})
    tagged = sum(1 for result in results if result.get("tags"))
    recommendations = []
    if tag_counts:
        top_tag = tag_counts.most_common(1)[0][0]
        recommendations.append({
            "tool": "map_strings",
            "arguments": {"path": path, "tags": [top_tag], "tag_mode": "any", "limit": 50},
        })
    recommendations.append({
        "tool": "extract_iocs",
        "arguments": {"path": path, "limit_per_type": 100},
    })
    if notable:
        recommendations.append({
            "tool": "get_string_context",
            "arguments": {"path": path, "id": notable[0]["id"]},
        })
    return {
        "ok": True,
        "mcp": {"server": "ida-stringdecrypt", "tool": "analyze_binary"},
        "file": file_summary(payload),
        "cache": {
            "hit": bool(meta.get("hit")),
            "age_seconds": meta.get("age_seconds", 0.0),
        },
        "stats": {
            "candidates": stats.get("candidates", 0),
            "strings": stats.get("strings", 0),
            "entropy_blobs": stats.get("entropy_blobs", 0),
            "results": stats.get("results", 0),
            "matched": len(results),
            "tagged": tagged,
            "schemes": stats.get("schemes", {}),
            "elapsed_seconds": stats.get("elapsed_seconds"),
            "timed_out": bool(stats.get("timed_out", False)),
        },
        "findings": {
            "tag_counts": dict(tag_counts.most_common(40)),
            "risk_counts": dict(sorted(risk_counts.items())),
            "entity_counts": entity_counts,
        },
        "notable_strings": notable,
        "network_iocs": network_iocs,
        "imports": {
            "categories": dict(import_categories.most_common()),
            "highlights": imports[:30],
        },
        "recommendations": recommendations,
        "warnings": image.get("warnings", []),
    }


def _section_for_offset(image: peelf.BinaryImage, file_offset: int):
    for section in image.sections:
        if section.file_offset <= file_offset < section.file_offset + section.file_size:
            return section
    return None


def _pointer_references(
    image: peelf.BinaryImage,
    target: int,
    *,
    limit: int = 24,
) -> dict:
    widths: list[tuple[int, int, str]] = []
    if image.bits == 64:
        widths.append((8, target, "va"))
        rva = target - image.image_base
        if 0 <= rva < (1 << 32):
            widths.append((4, rva, "rva"))
    else:
        widths.append((4, target, "va"))
        if image.image_base:
            rva = target - image.image_base
            if 0 <= rva < (1 << 32):
                widths.append((4, rva, "rva"))

    references: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for width, value, kind in widths:
        if value < 0 or value >= (1 << (width * 8)):
            continue
        needle = struct.pack("<I" if width == 4 else "<Q", value)
        start = 0
        while len(references) < limit:
            offset = image.data.find(needle, start)
            if offset < 0:
                break
            start = offset + 1
            section = _section_for_offset(image, offset)
            if section is None:
                continue
            key = (offset, kind)
            if key in seen:
                continue
            seen.add(key)
            references.append({
                "file_offset": offset,
                "address": f"0x{section.va + offset - section.file_offset:x}",
                "section": section.name,
                "kind": f"{kind}_pointer",
                "pointer_size": width,
                "target_value": f"0x{value:x}",
                "confidence": "low" if width == 4 else "medium",
            })
    return {
        "count": len(references),
        "truncated": len(references) >= limit,
        "items": references,
    }


def _rip_relative_references(
    image: peelf.BinaryImage,
    target: int,
    *,
    limit: int = 24,
) -> dict:
    """Find x86-64 LEA/MOV instructions that resolve to ``target``.

    Absolute-pointer scanning misses normal compiler output because references
    are encoded as ``[rip + disp32]``.  Only executable sections are searched
    and the computed target must match exactly, which keeps false positives
    low.  The fixture uses this form, and real PE/ELF code almost always does
    too.
    """
    empty = {
        "count": 0,
        "truncated": False,
        "items": [],
        "kind": "rip_relative",
    }
    if image.bits != 64 or image.machine != "x86_64":
        return empty
    references: list[dict] = []
    seen: set[int] = set()
    for section in image.sections:
        if not section.executable or section.file_size <= 0:
            continue
        start_offset = section.file_offset
        end_offset = min(len(image.data), section.file_offset + section.file_size)
        if end_offset - start_offset < 6:
            continue
        buffer = image.data[start_offset:end_offset]
        for match in _RIP_INSTRUCTION_RE.finditer(buffer):
            start = match.start()
            has_rex = 0x40 <= buffer[start] <= 0x4F
            opcode_index = start + (1 if has_rex else 0)
            # Opcode + ModRM + disp32.
            if opcode_index + 6 > len(buffer):
                continue
            opcode = buffer[opcode_index]
            modrm = buffer[opcode_index + 1]
            if (modrm & 0xC7) != 0x05:  # mod=00, rm=101 => RIP-relative
                continue
            displacement = struct.unpack_from("<i", buffer, opcode_index + 2)[0]
            instruction_length = opcode_index + 6 - start
            instruction_va = section.va + start
            resolved = instruction_va + instruction_length + displacement
            if resolved != target:
                continue
            file_offset = start_offset + start
            if file_offset in seen:
                continue
            seen.add(file_offset)
            mnemonic = "lea" if opcode == 0x8D else "mov"
            references.append({
                "file_offset": file_offset,
                "address": f"0x{instruction_va:x}",
                "section": section.name,
                "kind": f"rip_relative_{mnemonic}",
                "instruction": mnemonic,
                "target_value": f"0x{resolved:x}",
                "confidence": "high" if mnemonic == "lea" else "medium",
            })
            if len(references) >= limit:
                return {
                    "count": len(references),
                    "truncated": True,
                    "items": references,
                    "kind": "rip_relative",
                }
    return {
        "count": len(references),
        "truncated": False,
        "items": references,
        "kind": "rip_relative",
    }


def _related_imports(tags: Iterable[str], imports: Iterable[str], *, limit: int = 25) -> list[str]:
    categories: set[str] = set()
    for tag in tags:
        category = _RELATED_IMPORT_ALIASES.get(str(tag), str(tag))
        if category in intel.IMPORT_TERMS:
            categories.add(category)
    if not categories:
        return []
    terms = [term for category in categories for term in intel.IMPORT_TERMS[category]]
    output: list[str] = []
    for imported in imports:
        lowered = str(imported).lower()
        if any(term in lowered for term in terms) and imported not in output:
            output.append(str(imported))
            if len(output) >= limit:
                break
    return output


def _hex_window(image: peelf.BinaryImage | None, file_offset: int | None, plaintext: str) -> dict | None:
    if image is None or file_offset is None or not (0 <= file_offset < len(image.data)):
        return None
    start = max(0, file_offset - 32)
    end = min(len(image.data), file_offset + max(64, min(len(plaintext), 128)))
    raw = image.data[start:end]
    ascii_preview = "".join(chr(value) if 0x20 <= value <= 0x7E else "." for value in raw)
    section = _section_for_offset(image, start)
    return {
        "start_file_offset": start,
        "start_address": f"0x{section.va + start - section.file_offset:x}" if section else None,
        "bytes_hex": raw.hex(),
        "ascii": ascii_preview,
    }


def get_string_context(
    path: str,
    *,
    string_id: str | None = None,
    address: int | None = None,
    text: str | None = None,
    before: int = 3,
    after: int = 3,
    plaintext_limit: int = 600,
    refresh: bool = False,
) -> dict:
    if not any((string_id, address is not None, text)):
        raise ValueError("provide one of id, address or text")
    payload, meta = scan_file(path, refresh=refresh)
    results = payload.get("results", [])
    selected: dict | None = None
    matched_by = ""
    candidates = 0
    if string_id:
        matches = [item for item in results if item.get("id") == string_id]
        candidates = len(matches)
        if matches:
            selected = max(matches, key=lambda item: float(item.get("score", 0.0)))
            matched_by = "id"
    if selected is None and address is not None:
        matches = [
            item
            for item in results
            if _address(item) == int(address) or item.get("file_offset") == int(address)
        ]
        candidates = len(matches)
        if matches:
            selected = max(matches, key=lambda item: float(item.get("score", 0.0)))
            matched_by = "address"
    if selected is None and text:
        exact = [item for item in results if item.get("plaintext") == text]
        matches = exact or [
            item for item in results
            if str(text).lower() in str(item.get("plaintext", "")).lower()
        ]
        candidates = len(matches)
        if matches:
            selected = max(matches, key=lambda item: float(item.get("score", 0.0)))
            matched_by = "text"
    if selected is None:
        raise ValueError(
            "string not found in the current scan; run map_strings or find_strings first"
        )

    before = max(0, min(int(before), 50))
    after = max(0, min(int(after), 50))
    ordered = sorted(
        results,
        key=lambda item: (
            _address(item),
            item.get("file_offset") if item.get("file_offset") is not None else -1,
            -float(item.get("score", 0.0)),
        ),
    )
    position = ordered.index(selected)
    previous = ordered[max(0, position - before):position][::-1]
    following = ordered[position + 1:position + 1 + after]
    neighbors = []
    for direction, items in (("before", previous), ("after", following)):
        for item in items:
            entry = result_item(item, plaintext_limit=180)
            entry["direction"] = direction
            entry["distance_bytes"] = abs(_address(item) - _address(selected))
            neighbors.append(entry)

    image = None
    context_warning = None
    try:
        image = peelf.load_binary(path)
    except (OSError, peelf.BinaryParseError) as error:
        context_warning = f"could not reload image for pointer context: {error}"

    references = {
        "count": 0,
        "truncated": False,
        "items": [],
        "absolute_pointer_count": 0,
        "rip_relative_count": 0,
    }
    related: list[str] = []
    window = None
    if image is not None:
        absolute = _pointer_references(image, _address(selected))
        relative = _rip_relative_references(image, _address(selected))
        items = absolute["items"] + relative["items"]
        references = {
            "count": len(items),
            "truncated": bool(absolute["truncated"] or relative["truncated"]),
            "absolute_pointer_count": absolute["count"],
            "rip_relative_count": relative["count"],
            "items": items,
        }
        related = _related_imports(selected.get("tags", []), image.imports)
        window = _hex_window(image, selected.get("file_offset"), selected.get("plaintext", ""))

    selected_item = result_item(
        selected,
        include_original=True,
        include_pipeline=True,
        plaintext_limit=plaintext_limit,
    )
    output = {
        "ok": True,
        "mcp": {"server": "ida-stringdecrypt", "tool": "get_string_context"},
        "file": file_summary(payload),
        "cache": {"hit": bool(meta.get("hit")), "age_seconds": meta.get("age_seconds", 0.0)},
        "match": {"method": matched_by, "candidates": candidates},
        "string": selected_item,
        "context": {
            "section": selected_item.get("section"),
            "file_offset": selected_item.get("file_offset"),
            "address": selected_item.get("address"),
            "nearby_strings": neighbors,
            "possible_references": references,
            "related_imports": related,
            "hex_window": window,
            "warning": context_warning,
        },
        "ida": {
            "address": selected_item.get("address"),
            "file_offset": selected_item.get("file_offset"),
            "note": (
                "Pass the address to the official IDA MCP server for xrefs and "
                "decompilation. If IDA loaded the image at a different base, add "
                "the rebase delta first."
            ),
        },
    }
    return output
