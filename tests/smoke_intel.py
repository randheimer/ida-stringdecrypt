"""Smoke test for string intelligence, mapping and caching.

Run from the project root:

    python tests/smoke_intel.py
"""

from __future__ import annotations

import os
import sys

from stringdecrypt import cli, intel, stringmap

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "ida_test_pe.exe")
URL_ADDRESS = 0x140002080

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


def check_intelligence() -> None:
    info = intel.analyze_text("https://example.com/api/v1")
    assert "url" in info.tags, info
    assert "network" in info.tags, info
    assert "http" in info.tags, info
    assert "domain" in info.tags, info
    assert info.entities_dict()["url"] == ["https://example.com/api/v1"], info
    assert info.entities_dict()["domain"] == ["example.com"], info
    assert info.risk == "low", info

    path_info = intel.analyze_text(r"C:\Windows\System32\kernel32.dll")
    assert "path" in path_info.tags, path_info
    assert "filename" in path_info.tags, path_info
    assert path_info.entities_dict()["filename"] == ["kernel32.dll"], path_info

    persistence = intel.analyze_text(
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )
    assert "persistence" in persistence.tags, persistence
    assert persistence.risk == "medium", persistence

    injection = intel.analyze_text(
        "VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    )
    assert "injection" in injection.tags, injection
    assert injection.risk == "high", injection

    command = intel.analyze_text("powershell -enc SQBFAFgA")
    assert "command" in command.tags, command

    network = intel.analyze_text("10.1.2.3:8080")
    assert "ip" in network.tags, network
    assert network.entities_dict()["ip"] == ["10.1.2.3:8080"], network

    empty = intel.analyze_text("")
    assert empty.tags == () and empty.entities == {} and empty.risk == "info"

    first_id = intel.string_id(0x1000, "hello")
    assert first_id == intel.string_id(0x1000, "hello")
    assert first_id != intel.string_id(0x1001, "hello")
    assert first_id.startswith("s_") and len(first_id) == 14

    assert intel.defang("https://user@example.com/a") == (
        "hxxps://user[@]example[.]com/a"
    )

    counts = intel.entity_type_counts(
        [
            {"entities": {"url": ["a"], "domain": ["b"]}},
            {"entities": {"url": ["c"]}},
        ]
    )
    assert counts == {"url": 2, "domain": 1}, counts

    imports = intel.suspicious_imports(
        ["VirtualAllocEx", "InternetOpenA", "CreateFileW", "Sleep"]
    )
    categories = {category for item in imports for category in item["categories"]}
    assert "injection" in categories, imports
    assert "network" in categories, imports
    assert all(item["import"] != "Sleep" for item in imports), imports


def check_mapping() -> None:
    analysis = stringmap.analyze_binary(FIXTURE)
    assert analysis["ok"] is True
    assert analysis["stats"]["matched"] >= 2, analysis["stats"]
    assert analysis["stats"]["tagged"] >= 2, analysis["stats"]
    assert "url" in analysis["findings"]["tag_counts"], analysis["findings"]
    assert len(analysis["notable_strings"]) <= 20
    assert analysis["recommendations"], analysis
    assert analysis["file"]["sha256"], analysis["file"]

    first_page = stringmap.map_strings(
        FIXTURE,
        tags=["network"],
        tag_mode="all",
        sort="score",
        limit=1,
    )
    assert first_page["ok"] is True
    assert first_page["stats"]["matched"] == 2, first_page["stats"]
    assert first_page["stats"]["returned"] == 1, first_page["stats"]
    assert first_page["stats"]["next_offset"] == 1, first_page["stats"]
    assert first_page["stats"]["truncated"] is True
    assert "network" in first_page["facets"]["tags"], first_page["facets"]
    assert first_page["strings"][0]["id"].startswith("s_"), first_page["strings"][0]

    second_page = stringmap.map_strings(
        FIXTURE,
        tags=["network"],
        sort="score",
        limit=1,
        offset=1,
    )
    assert second_page["cache"]["hit"] is True, second_page["cache"]
    assert second_page["stats"]["returned"] == 1, second_page["stats"]
    assert second_page["stats"]["next_offset"] is None, second_page["stats"]
    assert second_page["stats"]["truncated"] is False
    assert second_page["strings"][0]["id"] != first_page["strings"][0]["id"]

    try:
        stringmap.map_strings(FIXTURE, tags=["not-a-real-tag"])
    except ValueError as error:
        assert "unknown tag" in str(error), error
    else:
        raise AssertionError("unknown tag was accepted")

    context = stringmap.get_string_context(FIXTURE, address=URL_ADDRESS)
    assert context["ok"] is True
    assert context["match"]["method"] == "address", context["match"]
    assert context["string"]["address"] == "0x140002080", context["string"]
    assert context["string"]["tags"], context["string"]
    references = context["context"]["possible_references"]
    assert references["rip_relative_count"] >= 1, references
    assert references["count"] >= 1, references
    assert any(
        item["kind"] == "rip_relative_lea" and item["target_value"] == "0x140002080"
        for item in references["items"]
    ), references
    assert context["context"]["hex_window"]["bytes_hex"], context["context"]
    assert context["context"]["warning"] is None, context["context"]

    found = stringmap.find_strings(FIXTURE, "example.com")
    assert found["ok"] is True
    assert found["stats"]["matched"] == 2, found["stats"]
    assert all("example.com" in item["plaintext"] for item in found["strings"])

    iocs = stringmap.extract_iocs(FIXTURE)
    assert iocs["ok"] is True
    assert iocs["counts"]["url"] == 2, iocs["counts"]
    assert iocs["counts"]["domain"] == 1, iocs["counts"]
    assert iocs["iocs"]["domain"][0]["value"] == "example.com", iocs["iocs"]
    assert iocs["iocs"]["domain"][0]["count"] == 2, iocs["iocs"]

    defanged = stringmap.extract_iocs(FIXTURE, types=["url"], defang=True)
    values = {item["value"] for item in defanged["iocs"]["url"]}
    assert "https://example.com/api/v1" in values, values
    defanged_values = {item["defanged"] for item in defanged["iocs"]["url"]}
    assert "hxxps://example[.]com/api/v1" in defanged_values, defanged_values

    cache = stringmap.cache_stats()
    assert cache["entries"] >= 1, cache
    assert cache["hits"] >= 1, cache

    refreshed = stringmap.analyze_binary(FIXTURE, refresh=True)
    assert refreshed["cache"]["hit"] is False, refreshed["cache"]


def check_cli_contract() -> None:
    plain = cli.scan_path(FIXTURE, heavy=False, enrich=False)
    assert "intel" not in plain, plain.keys()
    assert plain["config"]["enrich"] is False, plain["config"]
    assert all("tags" not in item for item in plain["results"]), plain["results"]

    timed_out = cli.scan_path(
        FIXTURE,
        heavy=False,
        enrich=False,
        timeout_seconds=1e-7,
    )
    assert timed_out["stats"]["timed_out"] is True, timed_out["stats"]
    assert timed_out["stats"]["results"] == 0, timed_out["stats"]


def main() -> int:
    check_intelligence()
    check_mapping()
    check_cli_contract()
    print("Intel/mapping smoke test PASS")
    print(f"  tags: {', '.join(intel.TAG_DEFINITIONS)}")
    print(f"  entity types: {', '.join(intel.ENTITY_TYPES)}")
    print(f"  cache: {stringmap.cache_stats()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
