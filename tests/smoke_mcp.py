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

    def call(self, name: str, arguments: dict, timeout: float = 120.0) -> dict:
        request_id = self.send("tools/call", {"name": name, "arguments": arguments})
        response = self.receive(request_id, timeout)
        if "error" in response:
            raise AssertionError(response["error"])
        result = response["result"]
        assert result.get("isError") is False, result
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

        tools_id = client.send("tools/list")
        tools = client.receive(tools_id)["result"]["tools"]
        names = {tool["name"] for tool in tools}
        assert {"scan_binary", "decrypt_blob", "list_schemes"} <= names, names

        metadata = client.call("list_schemes", {})
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
        print(f"  blob results: {len(blob['results'])}")
        print(f"  config launcher: {server_config['command'][1]}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
