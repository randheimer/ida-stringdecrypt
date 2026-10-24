"""Smoke test for the interactive and non-interactive installer.

Run from the project root:

    python tests/smoke_install.py

The test never writes to the real IDA plugin directory or to a real AI client
configuration.  Plugin installs go to a temporary directory and MCP client
detection runs with a temporary HOME/APPDATA profile.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT))

import install  # noqa: E402


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_installer(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONPATH"] = str(PROJECT)
    merged.pop("IDAUSR", None)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(PROJECT / "install.py"), *args],
        cwd=str(PROJECT),
        input=stdin,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        env=merged,
        timeout=240,
    )


def test_path_normalization(root: Path) -> None:
    plugins = root / "plugins"
    assert install.normalize_plugin_dir(plugins) == plugins
    assert install.normalize_plugin_dir(root / "IDA Professional 9.5") == (
        root / "IDA Professional 9.5" / "plugins"
    )
    installed = plugins / install.PLUGIN_DIR_NAME
    installed.mkdir(parents=True)
    assert install.normalize_plugin_dir(installed) == plugins
    assert install.normalize_plugin_dir(root / "IDA Pro" / "plugins") == (
        root / "IDA Pro" / "plugins"
    )


def test_detection(root: Path) -> None:
    home = root / "home"
    appdata = root / "appdata"
    home.mkdir(parents=True)
    plugin_dir = appdata / "Hex-Rays" / "IDA Pro" / "plugins"
    plugin_dir.mkdir(parents=True)

    locations = install.detect_ida_locations(
        env={"APPDATA": str(appdata)},
        home=home,
        registry=[],
        program_roots=[],
    )
    assert locations, locations
    assert locations[0].plugins == plugin_dir
    assert locations[0].exists

    idausr = root / "idausr"
    locations = install.detect_ida_locations(
        env={"APPDATA": str(appdata), "IDAUSR": str(idausr)},
        home=home,
        registry=[],
        program_roots=[],
    )
    assert locations[0].plugins == idausr / "plugins"
    assert not locations[0].exists

    program_files = root / "Program Files"
    ida_install = program_files / "IDA Professional 9.5"
    ida_install.mkdir(parents=True)
    (ida_install / "ida64.exe").write_bytes(b"stub")
    locations = install.detect_ida_locations(
        env={},
        home=root / "empty-home",
        registry=[("test registry", ida_install)],
        program_roots=[program_files],
    )
    assert len(locations) == 1, locations
    assert locations[0].plugins == ida_install / "plugins"
    assert not locations[0].exists
    assert "registry" in locations[0].source

    # With IDA installed but no user folder yet, offer the standard APPDATA path.
    new_appdata = root / "new-appdata"
    locations = install.detect_ida_locations(
        env={"APPDATA": str(new_appdata)},
        home=root / "empty-home",
        registry=[("test registry", ida_install)],
        program_roots=[],
    )
    assert locations[0].plugins == new_appdata / "Hex-Rays" / "IDA Pro" / "plugins"
    assert locations[1].plugins == ida_install / "plugins"


def test_target_prompt(root: Path) -> None:
    original_detect = install.detect_ida_locations
    original_input = builtins.input
    try:
        install.detect_ida_locations = lambda **kwargs: []
        answers = iter([str(root / "custom plugins"), "y"])
        prompts: list[str] = []

        def fake_input(prompt: str = "") -> str:
            prompts.append(prompt)
            return next(answers)

        builtins.input = fake_input
        with contextlib.redirect_stdout(io.StringIO()):
            chosen = install.choose_ida_target(None, interactive=True)
            assert chosen == (root / "custom plugins").resolve(), chosen
            assert any("IDA path" in prompt for prompt in prompts), prompts

            try:
                install.choose_ida_target(None, interactive=False)
            except install.InstallerError:
                pass
            else:
                raise AssertionError("missing IDA path must fail without --target")
    finally:
        install.detect_ida_locations = original_detect
        builtins.input = original_input


def test_plugin_install(root: Path) -> None:
    target = root / "plugin-target"
    result = run_installer(
        [
            "--ida-only",
            "--target",
            str(target),
            "--no-compile",
            "--yes",
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr

    installed = target / install.PLUGIN_DIR_NAME
    assert (installed / install.ENTRY_POINT).is_file()
    assert (installed / install.MANIFEST).is_file()
    assert (installed / install.PACKAGE_NAME / "__init__.py").is_file()
    assert (installed / "README.md").is_file()

    custom = installed / "custom_decoders" / "mine.py"
    custom.write_text("# user decoder\n", encoding="utf-8")
    result = run_installer(
        ["--ida-only", "--target", str(target), "--no-compile", "--yes"]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert custom.read_text(encoding="utf-8") == "# user decoder\n"

    dry_target = root / "dry-target"
    result = run_installer(
        [
            "--ida-only",
            "--target",
            str(dry_target),
            "--dry-run",
            "--no-compile",
            "--yes",
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dry run complete" in result.stdout
    assert not dry_target.exists()

    result = run_installer(
        ["--ida-only", "--target", str(target), "--uninstall", "--yes"]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not installed.exists()

    result = run_installer(
        ["--ida-only", "--target", str(target), "--uninstall", "--yes"]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not installed" in result.stdout


def fake_mcp_env(root: Path) -> tuple[dict[str, str], Path, Path]:
    home = root / "mcp-home"
    appdata = root / "mcp-appdata"
    localappdata = root / "mcp-local"
    home.mkdir(parents=True)
    appdata.mkdir(parents=True, exist_ok=True)
    localappdata.mkdir(parents=True, exist_ok=True)
    opencode = home / ".config" / "opencode" / "opencode.json"
    write_json(
        opencode,
        {
            "mcp": {
                "servers": {
                    "ida": {"type": "local", "command": ["uvx", "ida-mcp", "stdio"]}
                }
            }
        },
    )
    env = {
        "USERPROFILE": str(home),
        "HOME": str(home),
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(localappdata),
    }
    return env, home, opencode


def test_mcp_install(root: Path) -> None:
    env, home, opencode = fake_mcp_env(root)
    expected_command = [sys.executable, str((PROJECT / "mcp_server.py").resolve())]

    result = run_installer(["--mcp-only", "--yes", "--no-backup"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    data = read_json(opencode)
    assert "ida" in data["mcp"]["servers"]
    entry = data["mcp"]["servers"][install_mcp_name()]
    assert entry == {"type": "local", "command": expected_command}, entry

    result = run_installer(["--mcp-only", "--yes", "--no-backup"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "unchanged" in result.stdout, result.stdout

    result = run_installer(
        ["--mcp-only", "--uninstall", "--yes", "--no-backup"], env=env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = read_json(opencode)
    assert "ida" in data["mcp"]["servers"]
    assert install_mcp_name() not in data["mcp"]["servers"]

    # Explicit --mcp-client writes a client that detection did not find.
    result = run_installer(
        ["--mcp-only", "--mcp-client", "windsurf", "--yes", "--no-backup"],
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    windsurf = home / ".codeium" / "windsurf" / "mcp_config.json"
    assert windsurf.is_file()
    entry = read_json(windsurf)["mcpServers"][install_mcp_name()]
    assert entry["command"] == expected_command[0]
    assert entry["args"] == [expected_command[1]]

    result = run_installer(
        [
            "--mcp-only",
            "--mcp-client",
            "windsurf",
            "--uninstall",
            "--yes",
            "--no-backup",
        ],
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert install_mcp_name() not in read_json(windsurf)["mcpServers"]

    result = run_installer(
        ["--mcp-only", "--mcp-client", "does-not-exist", "--yes"], env=env
    )
    assert result.returncode == 1
    assert "unknown MCP client" in result.stderr

    empty = root / "mcp-empty"
    empty_home = empty / "home"
    empty_home.mkdir(parents=True)
    result = run_installer(
        ["--mcp-only", "--yes"],
        env={
            "USERPROFILE": str(empty_home),
            "HOME": str(empty_home),
            "APPDATA": str(empty / "appdata"),
            "LOCALAPPDATA": str(empty / "local"),
        },
    )
    assert result.returncode == 1
    assert "no AI clients" in result.stderr


def install_mcp_name() -> str:
    import install_mcp

    return install_mcp.DEFAULT_NAME


def test_both(root: Path) -> None:
    env, _, opencode = fake_mcp_env(root / "both")
    target = root / "both" / "plugins"
    result = run_installer(
        ["--all", "--target", str(target), "--no-compile", "--yes", "--no-backup"],
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (target / install.PLUGIN_DIR_NAME / install.ENTRY_POINT).is_file()
    assert install_mcp_name() in read_json(opencode)["mcp"]["servers"]

    result = run_installer(
        [
            "--all",
            "--target",
            str(target),
            "--uninstall",
            "--yes",
            "--no-backup",
        ],
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (target / install.PLUGIN_DIR_NAME).exists()
    assert install_mcp_name() not in read_json(opencode)["mcp"]["servers"]
    assert "ida" in read_json(opencode)["mcp"]["servers"]


def test_interactive_menus(root: Path) -> None:
    result = run_installer(["--interactive"], stdin="5\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "String Decryptor installer" in result.stdout
    assert "Cancelled" in result.stdout

    result = run_installer(["--interactive", "--uninstall"], stdin="0\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Cancelled" in result.stdout

    env, _, opencode = fake_mcp_env(root / "wizard")
    target = root / "wizard" / "plugins"
    before = opencode.read_text(encoding="utf-8")
    answers = "\n".join(["3", str(target), "y", "y", "y"]) + "\n"
    result = run_installer(
        ["--interactive", "--dry-run", "--no-compile"], env=env, stdin=answers
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Detected IDA locations:" in result.stdout, result.stdout
    assert "Detected AI clients:" in result.stdout, result.stdout
    assert "Plan" in result.stdout
    assert "Dry run complete" in result.stdout
    assert not target.exists()
    assert opencode.read_text(encoding="utf-8") == before


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="stringdecrypt-install-") as temporary:
        root = Path(temporary)
        test_path_normalization(root / "paths")
        test_detection(root / "detect")
        test_target_prompt(root / "prompt")
        test_plugin_install(root / "plugin")
        test_mcp_install(root / "mcp")
        test_both(root / "both")
        test_interactive_menus(root / "interactive")

    print("install smoke test PASS")
    print("  IDA detection, path normalization and missing-path prompt verified")
    print("  plugin install, dry-run, custom decoder preservation and uninstall verified")
    print("  MCP auto-detection, explicit client, idempotence and uninstall verified")
    print("  combined --all install/uninstall and interactive menus verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
