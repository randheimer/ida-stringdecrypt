"""Install the String Decryptor plugin into IDA's user plugin directory.

Typical use:

    python install.py
    python install.py --target "C:\\path\\to\\plugins" --force
    python install.py --dry-run

The installer never touches other plugins.  It replaces only its own package
folder and keeps user-provided files in ``custom_decoders`` intact.
"""

from __future__ import annotations

import argparse
import compileall
import os
import shutil
import sys
from pathlib import Path

PLUGIN_DIR_NAME = "ida_stringdecrypt"
PACKAGE_NAME = "ida_stringdecrypt_pkg"
ENTRY_POINT = "ida_stringdecrypt_plugin.py"
MANIFEST = "ida-plugin.json"
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".mypy_cache", ".pytest_cache")


def default_target() -> Path:
    idausr = os.environ.get("IDAUSR")
    if idausr:
        return Path(idausr).expanduser() / "plugins"
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / ".idapro" / "plugins"


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


def install(source_root: Path, target_plugins: Path, *, dry_run: bool = False, compile_: bool = True) -> Path:
    source_root = source_root.resolve()
    install_dir = (target_plugins / PLUGIN_DIR_NAME).resolve()

    package_source = source_root / "stringdecrypt"
    entry_source = source_root / ENTRY_POINT
    manifest_source = source_root / MANIFEST
    decoders_source = source_root / "custom_decoders"

    missing = [
        path
        for path in (package_source, entry_source, manifest_source)
        if not path.exists()
    ]
    if missing:
        raise FileNotFoundError("missing installer input: " + ", ".join(str(path) for path in missing))

    print(f"Source:  {source_root}")
    print(f"Target:  {install_dir}")
    if dry_run:
        print("Mode:    dry run (nothing is written)")

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
            raise RuntimeError("byte-compilation failed; the installed plugin may be broken")
        print("  byte-compiled package")

    print("\nInstalled. Restart IDA and open Edit > Plugins > String Decryptor")
    print("or press Ctrl-Shift-D.")
    return install_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install the IDA String Decryptor plugin.")
    parser.add_argument(
        "--target",
        help="IDA user plugin directory (defaults to %%APPDATA%%/Hex-Rays/IDA Pro/plugins)",
    )
    parser.add_argument("--source", default=str(Path(__file__).resolve().parent), help="source checkout")
    parser.add_argument("--dry-run", action="store_true", help="show actions without writing")
    parser.add_argument("--no-compile", action="store_true", help="skip byte-compilation")
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="remove the installed plugin directory instead of installing",
    )
    args = parser.parse_args(argv)

    target = Path(args.target).expanduser() if args.target else default_target()
    source = Path(args.source).expanduser()
    install_dir = target / PLUGIN_DIR_NAME

    if args.uninstall:
        print(f"Removing {install_dir}")
        if not args.dry_run and install_dir.exists():
            shutil.rmtree(install_dir)
        return 0

    try:
        install(source, target, dry_run=args.dry_run, compile_=not args.no_compile)
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
