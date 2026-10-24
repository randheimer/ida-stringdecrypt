"""Smoke test for install_mcp.py using an isolated fake home directory.

Run from the project root:

    python tests/smoke_install_mcp.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT))

import install_mcp  # noqa: E402

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="stringdecrypt-mcp-") as temporary:
        root = Path(temporary)
        home = root / "home"
        appdata = root / "appdata"
        localappdata = root / "local"
        home.mkdir()

        opencode = home / ".config" / "opencode" / "opencode.json"
        write_json(
            opencode,
            {
                "mcp": {
                    "servers": {
                        "ida": {
                            "type": "local",
                            "command": ["uvx", "ida-mcp", "stdio"],
                        }
                    }
                }
            },
        )
        antigravity = home / ".gemini" / "config" / "mcp_config.json"
        write_json(antigravity, {"mcpServers": {"ida": {"command": "uvx", "args": ["ida-mcp"]}}})
        claude = home / ".claude.json"
        write_json(claude, {"machineID": "test", "mcpServers": {"other": {"command": "other"}}})
        codex = home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(
            'model = "test"\n\n[mcp_servers.other]\ncommand = "other"\n',
            encoding="utf-8",
        )
        vscode = appdata / "Code - Insiders" / "User" / "mcp.json"
        write_json(vscode, {"servers": {"other": {"type": "stdio", "command": "other"}}})
        cursor = home / ".cursor" / "mcp.json"
        write_json(cursor, {"mcpServers": {"other": {"command": "other"}}})

        clients = install_mcp.build_clients(home=home, appdata=appdata, localappdata=localappdata)
        by_key = {client.key: client for client in clients}
        command = [sys.executable, str(PROJECT / "mcp_server.py")]

        detected = {client.key for client in clients if client.detected()}
        assert {"opencode", "antigravity", "claude-code", "codex", "vscode-insiders", "cursor"} <= detected, detected

        for key in ("opencode", "antigravity", "claude-code", "codex", "vscode-insiders", "cursor"):
            result = install_mcp.apply_client(
                by_key[key],
                "stringdecrypt",
                command,
                force=False,
            )
            assert result["status"] in ("installed", "updated"), (key, result)
            assert result["backup"], (key, result)

        opencode_data = read_json(opencode)
        assert "ida" in opencode_data["mcp"]["servers"]
        entry = opencode_data["mcp"]["servers"]["stringdecrypt"]
        assert entry == {"type": "local", "command": command}, entry

        antigravity_data = read_json(antigravity)
        assert "ida" in antigravity_data["mcpServers"]
        assert antigravity_data["mcpServers"]["stringdecrypt"] == {
            "command": command[0],
            "args": [command[1]],
        }

        claude_data = read_json(claude)
        assert claude_data["machineID"] == "test"
        assert "other" in claude_data["mcpServers"]
        assert claude_data["mcpServers"]["stringdecrypt"]["command"] == command[0]

        vscode_data = read_json(vscode)
        assert "other" in vscode_data["servers"]
        assert vscode_data["servers"]["stringdecrypt"] == {
            "type": "stdio",
            "command": command[0],
            "args": [command[1]],
        }

        cursor_data = read_json(cursor)
        assert "other" in cursor_data["mcpServers"]
        assert cursor_data["mcpServers"]["stringdecrypt"]["args"] == [command[1]]

        if tomllib is not None:
            codex_text = codex.read_text(encoding="utf-8")
            codex_data = tomllib.loads(codex_text)
            assert codex_data["model"] == "test"
            assert codex_data["mcp_servers"]["other"]["command"] == "other"
            assert codex_data["mcp_servers"]["stringdecrypt"]["command"] == command[0]
            assert codex_data["mcp_servers"]["stringdecrypt"]["args"] == [command[1]]
            assert install_mcp.MARKER in codex_text

        # A second run must be idempotent and must not create another backup.
        for key in ("opencode", "antigravity", "claude-code", "codex", "vscode-insiders", "cursor"):
            result = install_mcp.apply_client(by_key[key], "stringdecrypt", command)
            assert result["status"] == "unchanged", (key, result)
            assert result["backup"] == "", (key, result)

        # Uninstall only our entry and leave every other server intact.
        for key in ("opencode", "antigravity", "claude-code", "codex", "vscode-insiders", "cursor"):
            result = install_mcp.apply_client(
                by_key[key],
                "stringdecrypt",
                command,
                uninstall=True,
            )
            assert result["status"] == "removed", (key, result)

        assert "ida" in read_json(opencode)["mcp"]["servers"]
        assert "ida" in read_json(antigravity)["mcpServers"]
        assert "other" in read_json(claude)["mcpServers"]
        assert "other" in read_json(vscode)["servers"]
        assert "other" in read_json(cursor)["mcpServers"]
        if tomllib is not None:
            codex_data = tomllib.loads(codex.read_text(encoding="utf-8"))
            assert codex_data["model"] == "test"
            assert "stringdecrypt" not in codex_data.get("mcp_servers", {})
            assert "other" in codex_data["mcp_servers"]

        # An explicit client that is not installed must not be written without --force.
        result = install_mcp.apply_client(by_key["windsurf"], "stringdecrypt", command)
        assert result["status"] == "not installed", result
        assert not by_key["windsurf"].config.exists()

        print("install_mcp smoke test PASS")
        print(f"  detected: {', '.join(sorted(detected))}")
        print("  JSON merge, TOML merge, idempotence and uninstall verified")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
