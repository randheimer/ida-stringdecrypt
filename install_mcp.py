#!/usr/bin/env python3
"""Register the String Decryptor MCP server with installed AI clients.

MCP clients do not discover local servers by scanning the disk.  Each client
reads its own configuration file, so this script detects the clients installed
on this machine and merges a single ``stringdecrypt`` entry into their config.
Every other server entry is preserved and a timestamped backup is written
before a file is changed.

Examples:

    python install_mcp.py                     # detect and show status
    python install_mcp.py --auto              # configure every detected client
    python install_mcp.py --auto --dry-run    # show what --auto would change
    python install_mcp.py --client antigravity --client claude-code
    python install_mcp.py --auto --uninstall
    python install_mcp.py --auto --json

Supported clients: OpenCode, Antigravity, Claude Code, Claude Desktop, Codex,
VS Code, VS Code Insiders, Cursor, Windsurf, Cline, Roo Code, Gemini CLI and
GitHub Copilot CLI.  A client is only touched when it is installed or when it
is named explicitly with ``--client``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - Python 3.9/3.10 fallback
    tomllib = None


DEFAULT_NAME = "stringdecrypt"
MARKER = "# ida-stringdecrypt MCP server (managed by install_mcp.py)"
BACKUP_SUFFIX = ".bak-"


class ConfigError(Exception):
    """A client configuration could not be read or updated safely."""


@dataclass(frozen=True)
class Client:
    key: str
    name: str
    format: str  # opencode, stdio, vscode, toml
    config: Path
    root: str = "mcpServers"
    detect: tuple[Path, ...] = ()

    def detected(self) -> bool:
        return self.config.exists() or any(path.exists() for path in self.detect)


def _env_path(env: Mapping[str, str], key: str, fallback: Path) -> Path:
    value = env.get(key)
    return Path(value).expanduser() if value else fallback


def build_clients(
    *,
    home: Path | None = None,
    appdata: Path | None = None,
    localappdata: Path | None = None,
) -> list[Client]:
    """Build the known client list for a home directory and Windows profiles."""
    home = Path(home).expanduser() if home else Path.home()
    appdata = Path(appdata).expanduser() if appdata else _env_path(
        os.environ, "APPDATA", home / "AppData" / "Roaming"
    )
    localappdata = Path(localappdata).expanduser() if localappdata else _env_path(
        os.environ, "LOCALAPPDATA", home / "AppData" / "Local"
    )
    programs = localappdata / "Programs"
    vscode_storage = appdata / "Code" / "User" / "globalStorage"
    insiders_storage = appdata / "Code - Insiders" / "User" / "globalStorage"

    def first_existing(paths: Sequence[Path], fallback: Path) -> Path:
        for path in paths:
            if path.exists():
                return path
        return fallback

    cline_config = first_existing(
        (
            insiders_storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            vscode_storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        ),
        vscode_storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
    )
    roo_config = first_existing(
        (
            insiders_storage / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
            vscode_storage / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
        ),
        vscode_storage / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
    )

    return [
        Client(
            key="opencode",
            name="OpenCode",
            format="opencode",
            config=home / ".config" / "opencode" / "opencode.json",
            detect=(
                home / ".config" / "opencode",
                appdata / "ai.opencode.desktop",
                programs / "@opencodedesktop",
            ),
        ),
        Client(
            key="antigravity",
            name="Antigravity",
            format="stdio",
            config=home / ".gemini" / "config" / "mcp_config.json",
            detect=(
                home / ".gemini" / "config",
                appdata / "Antigravity",
                programs / "Antigravity",
                programs / "Antigravity IDE",
            ),
        ),
        Client(
            key="claude-code",
            name="Claude Code",
            format="stdio",
            config=home / ".claude.json",
            detect=(
                home / ".claude.json",
                home / ".claude",
                home / ".local" / "bin" / "claude.exe",
                home / ".local" / "bin" / "claude",
            ),
        ),
        Client(
            key="claude-desktop",
            name="Claude Desktop",
            format="stdio",
            config=appdata / "Claude" / "claude_desktop_config.json",
            detect=(appdata / "Claude", localappdata / "AnthropicClaude"),
        ),
        Client(
            key="codex",
            name="Codex / ChatGPT desktop",
            format="toml",
            config=home / ".codex" / "config.toml",
            detect=(home / ".codex", appdata / "npm" / "codex.cmd"),
        ),
        Client(
            key="vscode",
            name="VS Code",
            format="vscode",
            config=appdata / "Code" / "User" / "mcp.json",
            root="servers",
            detect=(
                appdata / "Code" / "User",
                programs / "Microsoft VS Code" / "Code.exe",
            ),
        ),
        Client(
            key="vscode-insiders",
            name="VS Code Insiders",
            format="vscode",
            config=appdata / "Code - Insiders" / "User" / "mcp.json",
            root="servers",
            detect=(
                appdata / "Code - Insiders" / "User",
                programs / "Microsoft VS Code Insiders" / "Code - Insiders.exe",
            ),
        ),
        Client(
            key="cursor",
            name="Cursor",
            format="stdio",
            config=home / ".cursor" / "mcp.json",
            detect=(home / ".cursor", programs / "cursor" / "Cursor.exe"),
        ),
        Client(
            key="windsurf",
            name="Windsurf",
            format="stdio",
            config=home / ".codeium" / "windsurf" / "mcp_config.json",
            detect=(
                home / ".codeium" / "windsurf",
                appdata / "Windsurf",
                programs / "Windsurf" / "Windsurf.exe",
            ),
        ),
        Client(
            key="cline",
            name="Cline",
            format="stdio",
            config=cline_config,
            detect=(
                insiders_storage / "saoudrizwan.claude-dev",
                vscode_storage / "saoudrizwan.claude-dev",
            ),
        ),
        Client(
            key="roo",
            name="Roo Code",
            format="stdio",
            config=roo_config,
            detect=(
                insiders_storage / "rooveterinaryinc.roo-cline",
                vscode_storage / "rooveterinaryinc.roo-cline",
            ),
        ),
        Client(
            key="gemini-cli",
            name="Gemini CLI",
            format="stdio",
            config=home / ".gemini" / "settings.json",
            detect=(home / ".gemini" / "settings.json",),
        ),
        Client(
            key="copilot-cli",
            name="GitHub Copilot CLI",
            format="stdio",
            config=home / ".copilot" / "mcp-config.json",
            detect=(home / ".copilot",),
        ),
    ]


def _server_map(data: dict, client: Client) -> dict:
    if client.format == "opencode":
        mcp = data.get("mcp")
        if not isinstance(mcp, dict):
            return {}
        servers = mcp.get("servers")
    else:
        servers = data.get(client.root)
    return servers if isinstance(servers, dict) else {}


def _ensure_server_map(data: dict, client: Client) -> dict:
    if client.format == "opencode":
        mcp = data.setdefault("mcp", {})
        if not isinstance(mcp, dict):
            raise ConfigError('"mcp" must be an object')
        servers = mcp.setdefault("servers", {})
    else:
        servers = data.setdefault(client.root, {})
    if not isinstance(servers, dict):
        raise ConfigError(f'"{client.root}" must be an object')
    return servers


def _entry(client: Client, command: Sequence[str]) -> dict:
    if client.format == "opencode":
        return {"type": "local", "command": list(command)}
    if client.format == "vscode":
        return {"type": "stdio", "command": command[0], "args": list(command[1:])}
    return {"command": command[0], "args": list(command[1:])}


def _has_jsonc_comments(text: str) -> bool:
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] in "/*":
            return True
        index += 1
    return False


def _strip_jsonc_comments(text: str) -> str:
    """Replace comments with spaces while preserving line breaks and strings."""
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            while index < len(text) and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            output.append(" ")
            output.append(" ")
            index += 2
            while index < len(text) and not (
                text[index] == "*" and index + 1 < len(text) and text[index + 1] == "/"
            ):
                output.append("\n" if text[index] in "\r\n" else " ")
                index += 1
            if index < len(text):
                output.append(" ")
                output.append(" ")
                index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _read_json(path: Path, *, allow_jsonc: bool) -> dict:
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        return {}
    if _has_jsonc_comments(raw):
        if not allow_jsonc:
            raise ConfigError(
                "contains JSONC comments; rerun with --allow-jsonc (comments will "
                "not be preserved) or edit the file manually"
            )
        raw = _strip_jsonc_comments(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigError(f"invalid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError("the top-level JSON value is not an object")
    return data


def _backup(path: Path) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = path.with_name(f"{path.name}{BACKUP_SUFFIX}{stamp}")
    suffix = 2
    while target.exists():
        target = path.with_name(f"{path.name}{BACKUP_SUFFIX}{stamp}-{suffix}")
        suffix += 1
    shutil.copy2(path, target)
    return target


def _chmod_like(path: Path, temporary: Path) -> None:
    if not path.exists():
        return
    try:
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
    except OSError:
        pass


def _write_json(path: Path, data: dict, *, dry_run: bool, backup: bool) -> Path | None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text(encoding="utf-8-sig") == text:
        return None
    backup_path = None
    if dry_run:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and backup:
        backup_path = _backup(path)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    _chmod_like(path, temporary)
    os.replace(temporary, path)
    return backup_path


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_block(name: str, command: Sequence[str]) -> str:
    args = ", ".join(_toml_string(item) for item in command[1:])
    return (
        f"{MARKER}\n"
        f"[mcp_servers.{name}]\n"
        f"command = {_toml_string(command[0])}\n"
        f"args = [{args}]\n"
    )


def _toml_pattern(name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?ms)(?:^{re.escape(MARKER)}\r?\n)?"
        rf"^\[mcp_servers\.{re.escape(name)}\][ \t]*\r?\n"
        rf".*?(?=^\[|\Z)"
    )


def _toml_entry(text: str, name: str) -> dict | None:
    if tomllib is None:
        return None
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001 - invalid TOML is handled by the caller
        return None
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        return None
    entry = servers.get(name)
    return entry if isinstance(entry, dict) else None


def _read_toml(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig") if path.exists() else ""


def _write_toml(path: Path, text: str, *, dry_run: bool, backup: bool) -> Path | None:
    if path.exists() and path.read_text(encoding="utf-8-sig") == text:
        return None
    backup_path = None
    if dry_run:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and backup:
        backup_path = _backup(path)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    _chmod_like(path, temporary)
    os.replace(temporary, path)
    return backup_path


def _resolve_config(client: Client) -> Path:
    if client.format == "opencode" and not client.config.exists():
        jsonc = client.config.with_suffix(".jsonc")
        if jsonc.exists():
            return jsonc
    return client.config


def _inspect_json(client: Client, path: Path, name: str, expected: dict) -> str:
    try:
        data = _read_json(path, allow_jsonc=True)
    except ConfigError as error:
        return f"error: {error}"
    servers = _server_map(data, client)
    if name not in servers:
        return "not configured"
    return "configured" if servers[name] == expected else "configured (stale paths)"


def _inspect(client: Client, name: str, command: Sequence[str]) -> tuple[str, Path]:
    path = _resolve_config(client)
    if not client.detected():
        return "not installed", path
    if not path.exists():
        return "not configured", path
    if client.format == "toml":
        text = _read_toml(path)
        entry = _toml_entry(text, name)
        if entry is None and name not in text:
            return "not configured", path
        if entry is not None:
            expected = {"command": command[0], "args": list(command[1:])}
            return ("configured" if entry == expected else "configured (stale paths)"), path
        return "configured" if _toml_block(name, command).strip() in text else "configured (stale paths)", path
    return _inspect_json(client, path, name, _entry(client, command)), path


def _install_json(
    client: Client,
    path: Path,
    name: str,
    command: Sequence[str],
    *,
    uninstall: bool,
    dry_run: bool,
    backup: bool,
    allow_jsonc: bool,
) -> tuple[str, Path | None]:
    data = _read_json(path, allow_jsonc=allow_jsonc)
    servers = _ensure_server_map(data, client)
    expected = _entry(client, command)
    if uninstall:
        if name not in servers:
            return "unchanged", None
        del servers[name]
        action = "removed"
    else:
        if servers.get(name) == expected:
            return "unchanged", None
        was_present = name in servers
        servers[name] = expected
        action = "updated" if was_present else "installed"
    backup_path = _write_json(path, data, dry_run=dry_run, backup=backup)
    return action, backup_path


def _install_toml(
    client: Client,
    path: Path,
    name: str,
    command: Sequence[str],
    *,
    uninstall: bool,
    dry_run: bool,
    backup: bool,
) -> tuple[str, Path | None]:
    text = _read_toml(path)
    pattern = _toml_pattern(name)
    match = pattern.search(text)
    if uninstall:
        if match is None:
            return "unchanged", None
        new_text = text[: match.start()] + text[match.end() :]
        action = "removed"
    else:
        block = _toml_block(name, command)
        if match is not None:
            if match.group(0) == block:
                return "unchanged", None
            new_text = text[: match.start()] + block + text[match.end() :]
            action = "updated"
        else:
            base = text.rstrip()
            new_text = (base + "\n\n" if base else "") + block
            action = "installed"
    backup_path = _write_toml(path, new_text, dry_run=dry_run, backup=backup)
    return action, backup_path


def apply_client(
    client: Client,
    name: str,
    command: Sequence[str],
    *,
    uninstall: bool = False,
    dry_run: bool = False,
    backup: bool = True,
    allow_jsonc: bool = False,
    force: bool = False,
) -> dict:
    path = _resolve_config(client)
    result = {
        "key": client.key,
        "name": client.name,
        "config": str(path),
        "detected": client.detected(),
        "status": "",
        "action": "none",
        "backup": "",
    }
    if not client.detected() and not force:
        result["status"] = "not installed"
        return result
    try:
        if client.format == "toml":
            action, backup_path = _install_toml(
                client,
                path,
                name,
                command,
                uninstall=uninstall,
                dry_run=dry_run,
                backup=backup,
            )
        else:
            action, backup_path = _install_json(
                client,
                path,
                name,
                command,
                uninstall=uninstall,
                dry_run=dry_run,
                backup=backup,
                allow_jsonc=allow_jsonc,
            )
    except (ConfigError, OSError) as error:
        result["status"] = f"error: {error}"
        return result
    result["action"] = action
    result["backup"] = str(backup_path) if backup_path else ""
    result["status"] = "would change" if dry_run and action != "unchanged" else action
    return result


def _client_by_key(clients: Sequence[Client], key: str) -> Client:
    for client in clients:
        if client.key == key:
            return client
    raise KeyError(key)


def _print_table(results: Sequence[dict]) -> None:
    if not results:
        print("No clients selected.")
        return
    width = max(len(item["name"]) for item in results) + 2
    for item in results:
        state = item["status"]
        marker = {
            "configured": "[ok]",
            "unchanged": "[ok]",
            "not installed": "[--]",
            "not configured": "[  ]",
        }.get(state, "[!!]" if "error" in state else "[..]")
        print(f"  {marker} {item['name']:<{width}} {state:<26} {item['config']}")
        if item.get("backup"):
            print(f"       backup: {item['backup']}")


def _status_results(clients: Sequence[Client], name: str, command: Sequence[str]) -> list[dict]:
    results = []
    for client in clients:
        status, path = _inspect(client, name, command)
        results.append(
            {
                "key": client.key,
                "name": client.name,
                "config": str(path),
                "detected": client.detected(),
                "status": status,
                "action": "none",
                "backup": "",
            }
        )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="install_mcp",
        description=(
            "Register the String Decryptor MCP server with installed AI clients. "
            "MCP clients do not discover servers automatically, so this script "
            "merges the entry into each client's configuration."
        ),
    )
    parser.add_argument("--auto", action="store_true", help="configure every detected client")
    parser.add_argument(
        "--client",
        action="append",
        metavar="KEY",
        help="configure a specific client (repeatable); implies --force",
    )
    parser.add_argument("--uninstall", action="store_true", help="remove the server entry")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    parser.add_argument("--name", default=DEFAULT_NAME, help=f"server name (default: {DEFAULT_NAME})")
    parser.add_argument("--python", default=sys.executable, help="Python executable used to launch the server")
    parser.add_argument(
        "--launcher",
        default=str(Path(__file__).resolve().with_name("mcp_server.py")),
        help="path to mcp_server.py",
    )
    parser.add_argument("--no-backup", action="store_true", help="do not keep .bak files")
    parser.add_argument(
        "--allow-jsonc",
        action="store_true",
        help="rewrite JSONC configs even though their comments are not preserved",
    )
    args = parser.parse_args(argv)

    if args.auto and args.client:
        parser.error("use either --auto or --client, not both")
    if args.uninstall and not (args.auto or args.client):
        parser.error("--uninstall requires --auto or --client")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.name):
        parser.error("--name may only contain letters, digits, '_' and '-'")

    clients = build_clients()
    if args.client:
        try:
            selected = [_client_by_key(clients, key.lower()) for key in args.client]
        except KeyError as error:
            parser.error(f"unknown client {error.args[0]!r}; choose from: {', '.join(c.key for c in clients)}")
    elif args.auto:
        selected = [client for client in clients if client.detected()]
    else:
        selected = clients

    python_path = Path(args.python).expanduser()
    launcher_path = Path(args.launcher).expanduser()
    if not python_path.is_file():
        parser.error(f"Python executable not found: {python_path}")
    if not launcher_path.is_file():
        parser.error(f"MCP launcher not found: {launcher_path}")
    command = [str(python_path.resolve()), str(launcher_path.resolve())]

    if not args.auto and not args.client:
        results = _status_results(selected, args.name, command)
        if args.as_json:
            print(json.dumps({"ok": True, "python": command[0], "launcher": command[1], "clients": results}, indent=2))
            return 0
        print("String Decryptor MCP setup")
        print(f"  Python:   {command[0]}")
        print(f"  Launcher: {command[1]}")
        print()
        _print_table(results)
        detected = sum(1 for item in results if item["detected"])
        print()
        print(f"Detected {detected} client(s).")
        print("Run `python install_mcp.py --auto` to configure every detected client.")
        print("Use `--client <key>` for one client; `--uninstall` removes the entry.")
        return 0

    if not selected:
        if args.as_json:
            print(json.dumps({"ok": True, "clients": [], "message": "no supported clients detected"}, indent=2))
        else:
            print("No supported clients detected. Use --client <key> --force to configure one anyway.")
        return 0

    results = [
        apply_client(
            client,
            args.name,
            command,
            uninstall=args.uninstall,
            dry_run=args.dry_run,
            backup=not args.no_backup,
            allow_jsonc=args.allow_jsonc,
            force=bool(args.client),
        )
        for client in selected
    ]

    if args.as_json:
        print(
            json.dumps(
                {
                    "ok": not any(item["status"].startswith("error:") for item in results),
                    "dry_run": args.dry_run,
                    "uninstall": args.uninstall,
                    "python": command[0],
                    "launcher": command[1],
                    "clients": results,
                },
                indent=2,
            )
        )
    else:
        action = "Removing" if args.uninstall else "Installing"
        print(f"{action} the {args.name!r} MCP server")
        print(f"  Python:   {command[0]}")
        print(f"  Launcher: {command[1]}")
        print()
        _print_table(results)
        print()
        changed = sum(1 for item in results if item["action"] not in ("none", "unchanged"))
        errors = sum(1 for item in results if item["status"].startswith("error:"))
        if args.dry_run:
            print(f"Dry run: {changed} client(s) would change.")
        else:
            print(f"{changed} client(s) changed; {errors} error(s).")
        print("Restart or reload a client if it does not pick up MCP changes automatically.")

    return 1 if any(item["status"].startswith("error:") for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
