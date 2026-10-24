"""Install the String Decryptor plugin and register its MCP server.

Run without arguments for an interactive wizard:

    python install.py

The wizard asks whether to install the IDA plugin, the MCP server for AI
clients, or both.  It detects IDA user plugin directories and IDA
installations, and asks for a path when nothing is found.

Non-interactive examples:

    python install.py --all --yes
    python install.py --ida-only --target "C:\\path\\to\\plugins" --yes
    python install.py --mcp-only --yes
    python install.py --mcp-only --mcp-client antigravity --yes
    python install.py --all --uninstall --yes
    python install.py --dry-run

The installer never touches other plugins.  It replaces only its own package
folder and keeps user-provided files in ``custom_decoders`` intact.  MCP
registration merges a single ``stringdecrypt`` entry and preserves every other
server.
"""

from __future__ import annotations

import argparse
import compileall
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

PLUGIN_DIR_NAME = "ida_stringdecrypt"
PACKAGE_NAME = "ida_stringdecrypt_pkg"
ENTRY_POINT = "ida_stringdecrypt_plugin.py"
MANIFEST = "ida-plugin.json"
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".mypy_cache", ".pytest_cache")

_IDA_INSTALL_NAME = re.compile(r"^ida(?:\s|[ _-]?\d|$)", re.IGNORECASE)
_IDA_EXECUTABLES = (
    "ida.exe",
    "ida64.exe",
    "idat.exe",
    "idat64.exe",
    "ida",
    "ida64",
    "idat",
    "idat64",
)


class InstallerError(RuntimeError):
    """The installer cannot continue without more information."""


class Cancelled(Exception):
    """The user cancelled the wizard."""


@dataclass(frozen=True)
class IdaLocation:
    """A potential IDA plugin directory and where the installer found it."""

    plugins: Path
    source: str
    exists: bool
    needs_admin: bool = False

    @property
    def state(self) -> str:
        return "exists" if self.exists else "will be created"


# ---------------------------------------------------------------------------
# IDA detection


def _expand_path(value: str) -> Path:
    value = value.strip().strip('"').strip("'")
    return Path(os.path.expandvars(value)).expanduser()


def _is_ida_install(path: Path) -> bool:
    return any((path / name).is_file() for name in _IDA_EXECUTABLES)


def normalize_plugin_dir(value: str | Path) -> Path:
    """Turn an IDA install dir, plugin dir or pasted path into a plugin dir."""
    path = _expand_path(str(value))
    if path.name.lower() == PLUGIN_DIR_NAME:
        path = path.parent
    if path.is_file() and path.name.lower() in _IDA_EXECUTABLES:
        path = path.parent
    if _is_ida_install(path) or _IDA_INSTALL_NAME.match(path.name or ""):
        return path / "plugins"
    if (path / "plugins").is_dir():
        return path / "plugins"
    return path


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _requires_admin(path: Path, env: Mapping[str, str] | None = None) -> bool:
    if not sys.platform.startswith("win"):
        return False
    env = os.environ if env is None else env
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = env.get(key)
        if value and _is_under(path, Path(value)):
            return True
    return False


def _registry_string(key, name: str) -> str | None:
    try:
        import winreg

        value, _ = winreg.QueryValueEx(key, name)
    except (ImportError, OSError):
        return None
    return value if isinstance(value, str) and value.strip() else None


def _registry_ida_install_dirs() -> list[tuple[str, Path]]:
    """Find IDA installations through the Windows registry."""
    if not sys.platform.startswith("win"):
        return []
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows always has winreg
        return []

    found: list[tuple[str, Path]] = []
    uninstall_roots = (
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    )
    for hive, subkey in uninstall_roots:
        try:
            root = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    entry = winreg.OpenKey(root, name)
                except OSError:
                    continue
                with entry:
                    display = _registry_string(entry, "DisplayName") or ""
                    publisher = _registry_string(entry, "Publisher") or ""
                    location = _registry_string(entry, "InstallLocation")
                if location and (
                    "hex-rays" in publisher.lower() or display.lower().startswith("ida")
                ):
                    found.append(
                        (f"registry uninstall entry {display or name}", _expand_path(location))
                    )

    for hive, subkey in (
        (winreg.HKEY_CURRENT_USER, r"Software\Hex-Rays\IDA"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Hex-Rays\IDA"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Hex-Rays\IDA"),
    ):
        try:
            key = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        with key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if (
                    isinstance(value, str)
                    and re.search(r"install|plugin|path|dir", name, re.IGNORECASE)
                    and value.strip()
                ):
                    found.append((f"registry value {name}", _expand_path(value)))

    return found


def _default_program_roots(
    env: Mapping[str, str] | None = None,
) -> list[Path]:
    env = os.environ if env is None else env
    roots: list[Path] = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = env.get(key)
        if value:
            roots.append(_expand_path(value))
    local = env.get("LOCALAPPDATA")
    if local:
        roots.append(_expand_path(local) / "Programs")
    if sys.platform.startswith("win"):
        drive = Path(env.get("SystemDrive", "C:") + "\\")
        if drive.is_dir():
            roots.append(drive)
    else:
        roots.extend((Path("/opt"), Path("/usr/local")))
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def detect_ida_locations(
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    registry: Iterable[tuple[str, Path]] | None = None,
    program_roots: Iterable[Path] | None = None,
) -> list[IdaLocation]:
    """Return IDA plugin directories known to this machine, best first."""
    env = os.environ if env is None else env
    home = Path(home).expanduser() if home else Path.home()
    locations: list[IdaLocation] = []
    seen: set[str] = set()

    def add(plugins: Path, source: str, *, needs_admin: bool = False) -> None:
        key = str(plugins).lower()
        if key in seen:
            return
        seen.add(key)
        locations.append(
            IdaLocation(
                plugins=plugins,
                source=source,
                exists=plugins.is_dir(),
                needs_admin=needs_admin or _requires_admin(plugins, env),
            )
        )

    idausr = env.get("IDAUSR")
    if idausr:
        add(_expand_path(idausr) / "plugins", "IDAUSR environment variable")

    if registry is None:
        registry = _registry_ida_install_dirs()
    installs: list[tuple[str, Path]] = list(registry)
    roots = list(program_roots) if program_roots is not None else _default_program_roots(env)
    for root in roots:
        try:
            children = sorted(root.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and child.name.lower().startswith("ida") and _is_ida_install(child):
                installs.append((f"installation in {root}", child))

    installs = [(source, path) for source, path in installs if _is_ida_install(path)]

    appdata = env.get("APPDATA")
    if appdata:
        ida_user_dir = _expand_path(appdata) / "Hex-Rays" / "IDA Pro"
        if ida_user_dir.is_dir() or installs:
            add(ida_user_dir / "plugins", "%APPDATA%\\Hex-Rays\\IDA Pro")

    idapro = home / ".idapro"
    if idapro.is_dir():
        add(idapro / "plugins", "~/.idapro")

    for source, install_dir in installs:
        add(install_dir / "plugins", source, needs_admin=_requires_admin(install_dir, env))

    return locations


# ---------------------------------------------------------------------------
# Interactive helpers


def _stdin_is_tty() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, OSError):
        return False


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError as error:
        raise Cancelled from error
    if answer.lower() in {"q", "quit", "exit"}:
        raise Cancelled
    return answer or default


def _ask_yes_no(question: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = _ask(f"{question} {hint}").lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("  Please answer yes or no.")


def _print_locations(locations: Sequence[IdaLocation]) -> None:
    print("\nDetected IDA locations:")
    for index, location in enumerate(locations, 1):
        note = "  (may require administrator rights)" if location.needs_admin else ""
        print(f"  {index}. {location.plugins}{note}")
        print(f"     from {location.source}; {location.state}")


def choose_ida_target(
    target: str | None,
    *,
    interactive: bool,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the plugin directory, prompting when necessary."""
    if target:
        plugin_dir = normalize_plugin_dir(target).resolve()
        print(f"IDA plugin directory: {plugin_dir}")
        return plugin_dir

    locations = detect_ida_locations(env=env)
    if not interactive:
        existing = [location for location in locations if location.exists]
        if existing:
            return existing[0].plugins.resolve()
        if locations:
            return locations[0].plugins.resolve()
        raise InstallerError(
            "could not detect IDA; pass --target with your IDA plugins directory"
        )

    if locations:
        _print_locations(locations)
        default_index = next(
            (index for index, location in enumerate(locations, 1) if location.exists),
            1,
        )
        while True:
            answer = _ask(
                "Select a directory number or enter a path",
                str(default_index),
            )
            if answer.isdigit():
                index = int(answer)
                if 1 <= index <= len(locations):
                    selected = locations[index - 1].plugins.resolve()
                    break
                print(f"  Enter a number between 1 and {len(locations)}.")
                continue
            selected = normalize_plugin_dir(answer).resolve()
            if selected.is_dir() or _ask_yes_no(
                f"{selected} does not exist. Create it during installation?", True
            ):
                break
        return selected

    print("\nNo IDA installation or IDA user plugin directory was found.")
    print("You can enter the IDA plugins directory, or the IDA installation")
    print('directory (for example "C:\\Program Files\\IDA Professional 9.5").')
    while True:
        try:
            answer = input("IDA path (leave empty to cancel): ").strip()
        except EOFError as error:
            raise Cancelled from error
        if not answer:
            raise Cancelled
        selected = normalize_plugin_dir(answer).resolve()
        if selected.is_dir() or _ask_yes_no(
            f"{selected} does not exist. Create it during installation?", True
        ):
            return selected
        print("  Enter an existing directory or confirm that it should be created.")


def _print_client_list(clients: Sequence[object]) -> None:
    for index, client in enumerate(clients, 1):
        state = "detected" if client.detected() else "not installed"
        print(f"  {index:>2}. {client.name:<24} {state:<14} {client.config}")


def _choose_clients(clients: Sequence[object]) -> list[object]:
    print("\nSupported AI clients:")
    _print_client_list(clients)
    while True:
        answer = _ask("Client numbers (comma-separated, 'all', empty to cancel)")
        if not answer:
            return []
        if answer.lower() == "all":
            return list(clients)
        selected = []
        valid = True
        for token in answer.replace(" ", "").split(","):
            if not token:
                continue
            if not token.isdigit() or not (1 <= int(token) <= len(clients)):
                print(f"  Invalid number: {token}")
                valid = False
                break
            client = clients[int(token) - 1]
            if client not in selected:
                selected.append(client)
        if valid:
            return selected


def choose_mcp_clients(
    requested: Sequence[str],
    *,
    interactive: bool,
    source_root: Path | None = None,
    uninstall: bool = False,
) -> tuple[list[object], bool]:
    """Return (clients, force).  Empty means MCP installation is skipped."""
    try:
        import install_mcp
    except ImportError as error:  # pragma: no cover - broken checkout
        raise InstallerError(f"cannot load install_mcp.py: {error}") from error

    clients = install_mcp.build_clients()
    by_key = {client.key: client for client in clients}

    if requested:
        selected = []
        for key in requested:
            client = by_key.get(key.lower())
            if client is None:
                keys = ", ".join(client.key for client in clients)
                raise InstallerError(f"unknown MCP client {key!r}; choose from: {keys}")
            if client not in selected:
                selected.append(client)
        return selected, True

    detected = [client for client in clients if client.detected()]
    if not interactive:
        return detected, False

    command = [
        sys.executable,
        str(((source_root or Path(__file__).resolve().parent) / "mcp_server.py").resolve()),
    ]
    if detected:
        print("\nDetected AI clients:")
        install_mcp.print_results(
            install_mcp.status_results(detected, install_mcp.DEFAULT_NAME, command)
        )
        verb = "Remove the entry from" if uninstall else "Configure"
        if _ask_yes_no(f"{verb} all {len(detected)} detected client(s)?", True):
            return detected, False
        return _choose_clients(clients), True

    print("\nNo supported AI clients were detected on this machine.")
    print("Install one later and rerun `python install_mcp.py --auto`.")
    if _ask_yes_no("Choose from all supported clients anyway?", False):
        return _choose_clients(clients), True
    return [], False


# ---------------------------------------------------------------------------
# Installation


def _copy_file(source: Path, destination: Path, dry_run: bool) -> None:
    print(f"  file  {destination}")
    if not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _copy_tree(source: Path, destination: Path, dry_run: bool, *, clean: bool) -> None:
    print(f"  tree  {destination}")
    if dry_run:
        return
    if clean and destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=IGNORE, dirs_exist_ok=True)


def _merge_custom_decoders(source: Path, destination: Path, dry_run: bool) -> None:
    if not source.is_dir():
        return
    print(f"  merge {destination} (existing user decoders are kept)")
    if dry_run:
        return
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        if not item.is_file():
            continue
        target = destination / item.name
        if target.exists():
            continue
        shutil.copy2(item, target)


def validate_source(source_root: Path) -> None:
    missing = [
        path
        for path in (
            source_root / "stringdecrypt",
            source_root / ENTRY_POINT,
            source_root / MANIFEST,
            source_root / "mcp_server.py",
        )
        if not path.exists()
    ]
    if missing:
        raise InstallerError(
            "missing installer input: " + ", ".join(str(path) for path in missing)
        )


def install_plugin(
    source_root: Path,
    target_plugins: Path,
    *,
    dry_run: bool = False,
    compile_: bool = True,
) -> Path:
    source_root = source_root.resolve()
    install_dir = (target_plugins / PLUGIN_DIR_NAME).resolve()

    package_source = source_root / "stringdecrypt"
    entry_source = source_root / ENTRY_POINT
    manifest_source = source_root / MANIFEST
    decoders_source = source_root / "custom_decoders"

    missing = [
        path for path in (package_source, entry_source, manifest_source) if not path.exists()
    ]
    if missing:
        raise InstallerError(
            "missing installer input: " + ", ".join(str(path) for path in missing)
        )

    print("\nInstalling IDA plugin")
    print(f"  Source: {source_root}")
    print(f"  Target: {install_dir}")
    if dry_run:
        print("  Mode:   dry run (nothing is written)")

    _copy_tree(package_source, install_dir / PACKAGE_NAME, dry_run, clean=True)
    _copy_file(entry_source, install_dir / ENTRY_POINT, dry_run)
    _copy_file(manifest_source, install_dir / MANIFEST, dry_run)
    _merge_custom_decoders(decoders_source, install_dir / "custom_decoders", dry_run)

    readme = source_root / "README.md"
    if readme.exists():
        _copy_file(readme, install_dir / "README.md", dry_run)

    if compile_ and not dry_run:
        if not compileall.compile_dir(
            install_dir / PACKAGE_NAME,
            quiet=1,
            force=True,
            legacy=False,
        ):
            raise InstallerError("byte-compilation failed; the installed plugin may be broken")
        print("  byte-compiled package")

    return install_dir


def uninstall_plugin(target_plugins: Path, *, dry_run: bool = False) -> bool:
    install_dir = target_plugins / PLUGIN_DIR_NAME
    print("\nRemoving IDA plugin")
    print(f"  Target: {install_dir}")
    if not install_dir.exists():
        print("  not installed; nothing to remove")
        return False
    if dry_run:
        print("  would remove (dry run)")
        return True
    shutil.rmtree(install_dir)
    print("  removed")
    return True


def configure_mcp(
    clients: Sequence[object],
    *,
    source_root: Path,
    uninstall: bool,
    dry_run: bool,
    force: bool,
    allow_jsonc: bool,
    backup: bool,
) -> tuple[list[dict], int]:
    """Install or remove the MCP entry, returning results and error count."""
    if not clients:
        print("\nMCP server")
        print("  skipped: no AI clients selected")
        return [], 0

    import install_mcp

    command = [sys.executable, str((source_root / "mcp_server.py").resolve())]
    action = "Removing" if uninstall else "Installing"
    print(f"\n{action} the MCP server")
    print(f"  Python:   {command[0]}")
    print(f"  Launcher: {command[1]}")

    results = [
        install_mcp.apply_client(
            client,
            install_mcp.DEFAULT_NAME,
            command,
            uninstall=uninstall,
            dry_run=dry_run,
            backup=backup,
            allow_jsonc=allow_jsonc,
            force=force,
        )
        for client in clients
    ]
    install_mcp.print_results(results)
    errors = sum(1 for item in results if item["status"].startswith("error:"))
    return results, errors


# ---------------------------------------------------------------------------
# Wizard flow


def _component_menu(uninstall: bool) -> tuple[bool, bool]:
    title = "What do you want to remove?" if uninstall else "What do you want to install?"
    print(f"\n{title}")
    print("  1) IDA plugin only")
    print("  2) MCP server for AI clients only")
    print("  3) Both")
    print("  0) Back")
    default = "3" if not uninstall else "1"
    while True:
        answer = _ask("Choose", default)
        if answer == "0":
            raise Cancelled
        if answer == "1":
            return True, False
        if answer == "2":
            return False, True
        if answer == "3":
            return True, True
        print("  Enter 0, 1, 2 or 3.")


def _main_menu() -> tuple[bool, bool, bool]:
    print("\nString Decryptor installer")
    print("==========================")
    print("  1) IDA plugin only")
    print("  2) MCP server for AI clients only")
    print("  3) Both")
    print("  4) Uninstall")
    print("  5) Exit")
    while True:
        answer = _ask("Choose", "3")
        if answer in {"5", "0"}:
            raise Cancelled
        if answer == "1":
            return False, True, False
        if answer == "2":
            return False, False, True
        if answer == "3":
            return False, True, True
        if answer == "4":
            print("\nUninstall")
            print("  1) IDA plugin")
            print("  2) MCP server entries")
            print("  3) Both")
            print("  0) Cancel")
            while True:
                choice = _ask("Choose", "1")
                if choice == "0":
                    raise Cancelled
                if choice == "1":
                    return True, True, False
                if choice == "2":
                    return True, False, True
                if choice == "3":
                    return True, True, True
                print("  Enter 0, 1, 2 or 3.")
        print("  Enter 1, 2, 3, 4 or 5.")


def _show_plan(
    *,
    target: Path | None,
    install_plugin_component: bool,
    mcp_clients: Sequence[object],
    mcp_component: bool,
    uninstall: bool,
    dry_run: bool,
) -> None:
    print("\nPlan")
    print("----")
    verb = "remove" if uninstall else "install"
    if install_plugin_component and target is not None:
        print(f"  IDA plugin : {verb} {target / PLUGIN_DIR_NAME}")
        if _requires_admin(target):
            print("               note: this location may require administrator rights")
    if mcp_component:
        if mcp_clients:
            names = ", ".join(client.name for client in mcp_clients)
            print(f"  MCP server : {verb} entry for {names}")
        elif uninstall:
            print("  MCP server : nothing to remove")
        else:
            print("  MCP server : skipped (no clients selected)")
    if dry_run:
        print("  Mode       : dry run (nothing is written)")


def _next_steps(
    *,
    plugin_changed: bool,
    mcp_changed: bool,
    mcp_clients: Sequence[object],
    uninstall: bool,
    dry_run: bool,
) -> None:
    if dry_run:
        print("\nDry run complete; no files were changed.")
        return
    print("\nDone.")
    if plugin_changed:
        if uninstall:
            print("  IDA plugin removed. Restart IDA to unload it.")
        else:
            print("  Restart IDA, then open Edit > Plugins > String Decryptor")
            print("  or press Ctrl-Shift-D.")
    if mcp_clients and mcp_changed:
        if uninstall:
            print("  MCP entries removed. Restart any open AI client.")
        else:
            print("  Reload or restart your AI clients to pick up the MCP server.")
            print("  OpenCode reloads its configuration automatically.")


def run(args: argparse.Namespace) -> int:
    if args.interactive and args.yes:
        raise InstallerError("use either --interactive or --yes, not both")
    if args.mcp_client and args.ida_only:
        raise InstallerError("--mcp-client cannot be combined with --ida-only")

    source_root = _expand_path(args.source).resolve()
    validate_source(source_root)

    mode_given = bool(args.ida_only or args.mcp_only or args.all)
    legacy_flags = bool(
        args.target or args.dry_run or args.no_compile or args.uninstall or args.mcp_client
    )
    can_prompt = bool(args.interactive or _stdin_is_tty())
    wizard = bool(
        (args.interactive and not mode_given)
        or (not mode_given and not legacy_flags and not args.yes and can_prompt)
    )
    ask_user = bool(can_prompt and not args.yes)
    confirm = bool(can_prompt and not args.yes)

    uninstall = bool(args.uninstall)
    plugin_component = False
    mcp_component = False

    if wizard:
        if args.uninstall:
            plugin_component, mcp_component = _component_menu(True)
        else:
            uninstall, plugin_component, mcp_component = _main_menu()
        ask_user = True
    else:
        if args.ida_only:
            plugin_component, mcp_component = True, False
        elif args.mcp_only:
            plugin_component, mcp_component = False, True
        elif args.all:
            plugin_component, mcp_component = True, True
        elif args.mcp_client:
            plugin_component = bool(args.target)
            mcp_component = True
        elif args.yes:
            plugin_component, mcp_component = True, True
        else:
            # Preserve the original plugin-only behaviour for existing scripts.
            plugin_component, mcp_component = True, False

    target: Path | None = None
    if plugin_component:
        target = choose_ida_target(args.target, interactive=ask_user, env=os.environ)

    clients: list[object] = []
    mcp_force = False
    if mcp_component:
        clients, mcp_force = choose_mcp_clients(
            args.mcp_client,
            interactive=ask_user,
            source_root=source_root,
            uninstall=uninstall,
        )
        if not uninstall and not clients and not plugin_component:
            raise InstallerError(
                "no AI clients were selected, so the MCP server was not configured; "
                "install a supported client or use --mcp-client <key> to force one"
            )

    _show_plan(
        target=target,
        install_plugin_component=plugin_component,
        mcp_clients=clients,
        mcp_component=mcp_component,
        uninstall=uninstall,
        dry_run=args.dry_run,
    )

    if confirm:
        if not _ask_yes_no("Proceed?", True):
            print("Cancelled; nothing was changed.")
            return 0

    plugin_changed = False
    mcp_changed = False
    mcp_errors = 0

    if plugin_component and target is not None:
        if uninstall:
            plugin_changed = uninstall_plugin(target, dry_run=args.dry_run)
        else:
            install_plugin(
                source_root,
                target,
                dry_run=args.dry_run,
                compile_=not args.no_compile,
            )
            plugin_changed = True

    if mcp_component:
        results, mcp_errors = configure_mcp(
            clients,
            source_root=source_root,
            uninstall=uninstall,
            dry_run=args.dry_run,
            force=mcp_force,
            allow_jsonc=args.allow_jsonc,
            backup=not args.no_backup,
        )
        mcp_changed = any(item["action"] not in ("none", "unchanged") for item in results)

    _next_steps(
        plugin_changed=plugin_changed,
        mcp_changed=mcp_changed,
        mcp_clients=clients,
        uninstall=uninstall,
        dry_run=args.dry_run,
    )

    if mcp_errors:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install",
        description=(
            "Install the IDA String Decryptor plugin and/or register its MCP "
            "server. Run without arguments for an interactive wizard."
        ),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--ida-only", action="store_true", help="install/remove only the IDA plugin")
    modes.add_argument("--mcp-only", action="store_true", help="install/remove only MCP entries")
    modes.add_argument("--all", action="store_true", help="install/remove both components")
    parser.add_argument(
        "--target",
        help="IDA plugins directory or IDA installation directory",
    )
    parser.add_argument(
        "--mcp-client",
        action="append",
        metavar="KEY",
        help="MCP client to configure (repeatable); see install_mcp.py",
    )
    parser.add_argument("--source", default=str(Path(__file__).resolve().parent), help="source checkout")
    parser.add_argument("--dry-run", action="store_true", help="show actions without writing")
    parser.add_argument("--no-compile", action="store_true", help="skip byte-compilation")
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="remove the installed plugin and/or MCP entries",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="do not ask for confirmation (with no mode or legacy flag, installs both)",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="force the interactive wizard even when stdin is not a TTY",
    )
    parser.add_argument(
        "--allow-jsonc",
        action="store_true",
        help="rewrite MCP JSONC configs even though comments are not preserved",
    )
    parser.add_argument("--no-backup", action="store_true", help="do not keep MCP config backups")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except Cancelled:
        print("\nCancelled; nothing was changed.")
        return 0
    except (InstallerError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
