"""Smoke test for the dependency-free MCP stdio server.

Run from the project root:

    python tests/smoke_mcp.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
SERVER = os.path.join(PROJECT, "mcp_server.py")
FIXTURE = os.path.join(HERE, "ida_test_pe.exe")


class Client:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, SERVER],
            cwd=PROJECT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.next_id = 0

    def send(self, method: str, params: dict | None = None) -> int:
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self.next_id

    def notify(self, method: str, params: dict | None = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def receive(self, expected_id: int, timeout: float = 120.0) -> dict:
        assert self.process.stdout is not None
        started = time.time()
        while time.time() - started < timeout:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("MCP server closed stdout")
            message = json.loads(line)
            if message.get("id") == expected_id:
                return message
        raise TimeoutError(f"no response for request {expected_id}")

    def request(self, method: str, params: dict | None = None, timeout: float = 120.0) -> dict:
        request_id = self.send(method, params)
        response = self.receive(request_id, timeout)
        if "error" in response:
            raise AssertionError(response["error"])
        return response["result"]

    def call(self, name: str, arguments: dict, timeout: float = 120.0) -> dict:
        result = self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout
        )
        assert result.get("isError") is False, result
        return json.loads(result["content"][0]["text"])

    def call_error(self, name: str, arguments: dict, timeout: float = 120.0) -> dict:
        result = self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout
        )
        assert result.get("isError") is True, result
        return json.loads(result["content"][0]["text"])

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        if self.process.returncode not in (0, None):
            assert self.process.stderr is not None
            print(self.process.stderr.read(), file=sys.stderr)
        assert self.process.returncode in (0, None), self.process.returncode


def main() -> int:
    client = Client()
    try:
        init_id = client.send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        )
        init = client.receive(init_id)
        assert init["result"]["serverInfo"]["name"] == "ida-stringdecrypt"
        client.notify("notifications/initialized")

        tools = client.request("tools/list")["tools"]
        names = {tool["name"] for tool in tools}
        assert names == {
            "scan_binary",
            "analyze_binary",
            "map_strings",
            "get_string_context",
            "find_strings",
            "extract_iocs",
            "decrypt_blob",
            "list_schemes",
        }, names
        schemas = {tool["name"]: tool["inputSchema"] for tool in tools}
        assert schemas["analyze_binary"]["properties"]["min_score"]["default"] == 60
        assert schemas["extract_iocs"]["properties"]["min_score"]["default"] == 55
        assert schemas["map_strings"]["properties"]["min_score"]["default"] == 30

        resources = client.request("resources/list")["resources"]
        resource_uris = {item["uri"] for item in resources}
        assert {
            "stringdecrypt://schemes",
            "stringdecrypt://tags",
            "stringdecrypt://usage",
        } <= resource_uris, resource_uris
        tags_resource = client.request(
            "resources/read", {"uri": "stringdecrypt://tags"}
        )["contents"][0]
        tags_payload = json.loads(tags_resource["text"])
        assert "injection" in tags_payload["tags"], tags_payload
        assert "url" in tags_payload["entity_types"], tags_payload

        prompts = client.request("prompts/list")["prompts"]
        assert {item["name"] for item in prompts} == {"triage_binary"}, prompts
        prompt = client.request(
            "prompts/get",
            {
                "name": "triage_binary",
                "arguments": {"path": FIXTURE, "focus": "network"},
            },
        )
        prompt_text = prompt["messages"][0]["content"]["text"]
        assert FIXTURE in prompt_text, prompt_text
        assert "network" in prompt_text, prompt_text

        scheme_result = client.request(
            "tools/call", {"name": "list_schemes", "arguments": {}}
        )
        assert "structuredContent" in scheme_result, scheme_result
        metadata = json.loads(scheme_result["content"][0]["text"])
        assert metadata["ok"] is True
        assert {item["name"] for item in metadata["schemes"]} >= {"xor", "aes", "des"}

        scan = client.call(
            "scan_binary",
            {
                "path": FIXTURE,
                "min_score": 60,
                "heavy": False,
                "max_candidates": 100,
                "schemes": ["xor", "base64"],
                "max_plaintext_chars": 500,
            },
        )
        assert scan["ok"] is True, scan
        plaintexts = {item["plaintext"] for item in scan["results"]}
        assert "https://example.com/api/v1" in plaintexts, plaintexts
        assert "http://example.com/api" in plaintexts, plaintexts
        assert any("url" in item["tags"] for item in scan["results"]), scan["results"]

        analysis = client.call("analyze_binary", {"path": FIXTURE})
        assert analysis["ok"] is True, analysis
        assert analysis["stats"]["matched"] >= 2, analysis["stats"]
        assert analysis["findings"]["tag_counts"].get("url", 0) >= 2, analysis
        assert analysis["notable_strings"], analysis
        notable_id = analysis["notable_strings"][0]["id"]

        page_one = client.call(
            "map_strings",
            {"path": FIXTURE, "tags": ["network"], "limit": 1},
        )
        assert page_one["ok"] is True, page_one
        assert page_one["stats"]["matched"] == 2, page_one["stats"]
        assert page_one["stats"]["returned"] == 1, page_one["stats"]
        assert page_one["stats"]["next_offset"] == 1, page_one["stats"]
        assert page_one["cache"]["hit"] is True, page_one["cache"]

        page_two = client.call(
            "map_strings",
            {"path": FIXTURE, "tags": ["network"], "limit": 1, "offset": 1},
        )
        assert page_two["stats"]["returned"] == 1, page_two["stats"]
        assert page_two["stats"]["next_offset"] is None, page_two["stats"]
        assert page_two["strings"][0]["id"] != page_one["strings"][0]["id"]

        context = client.call(
            "get_string_context", {"path": FIXTURE, "id": notable_id}
        )
        assert context["ok"] is True, context
        assert context["match"]["method"] == "id", context["match"]
        references = context["context"]["possible_references"]
        assert references["rip_relative_count"] >= 1, references
        assert any(
            item["instruction"] == "lea" for item in references["items"]
        ), references
        assert context["context"]["nearby_strings"], context["context"]

        found = client.call(
            "find_strings", {"path": FIXTURE, "query": "example.com"}
        )
        assert found["ok"] is True, found
        assert found["stats"]["matched"] == 2, found["stats"]

        iocs = client.call("extract_iocs", {"path": FIXTURE})
        assert iocs["ok"] is True, iocs
        assert iocs["counts"]["url"] == 2, iocs["counts"]
        assert iocs["counts"]["domain"] == 1, iocs["counts"]

        defanged = client.call(
            "extract_iocs", {"path": FIXTURE, "types": ["url"], "defang": True}
        )
        assert any(
            item.get("defanged") == "hxxps://example[.]com/api/v1"
            for item in defanged["iocs"]["url"]
        ), defanged["iocs"]

        error = client.call_error(
            "map_strings", {"path": FIXTURE, "tags": ["not-a-real-tag"]}
        )
        assert error["ok"] is False, error
        assert "unknown tag" in error["error"], error

        plain = b"https://example.com/api/v1"
        cipher = bytes(value ^ 0x5A for value in plain)
        blob = client.call(
            "decrypt_blob",
            {
                "data": cipher.hex(),
                "data_encoding": "hex",
                "min_score": 60,
                "schemes": ["xor"],
            },
        )
        assert blob["ok"] is True, blob
        blob_plaintexts = {item["plaintext"] for item in blob["results"]}
        assert plain.decode() in blob_plaintexts, blob_plaintexts

        old_client = Client()
        try:
            old_init = old_client.request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke-test-old", "version": "1.0"},
                },
            )
            assert old_init["protocolVersion"] == "2024-11-05", old_init
            old_client.notify("notifications/initialized")
            old_result = old_client.request(
                "tools/call", {"name": "list_schemes", "arguments": {}}
            )
            assert "structuredContent" not in old_result, old_result
            assert json.loads(old_result["content"][0]["text"])["ok"] is True
        finally:
            old_client.close()

        config = subprocess.run(
            [sys.executable, SERVER, "--print-config", "--config-style", "opencode"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        config_payload = json.loads(config.stdout)
        server_config = config_payload["mcp"]["servers"]["stringdecrypt"]
        assert server_config["type"] == "local"
        assert server_config["command"][0] == sys.executable
        assert os.path.isfile(server_config["command"][1]), server_config["command"]

        print("MCP smoke test PASS")
        print(f"  tools: {', '.join(sorted(names))}")
        print(f"  scan results: {scan['stats']['results']}")
        print(f"  analysis matches: {analysis['stats']['matched']}")
        print(f"  map page: {page_one['stats']}")
        print(f"  context refs: {references['count']}")
        print(f"  IOC counts: {iocs['counts']}")
        print(f"  blob results: {len(blob['results'])}")
        print(f"  config launcher: {server_config['command'][1]}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
