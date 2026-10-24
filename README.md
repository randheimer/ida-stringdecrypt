# String Decryptor for IDA Pro

Automatic, best-effort string and ciphertext recovery for **native PE/ELF**
binaries. The plugin collects IDA strings, data-reference blobs, immediate and
stack-string runs, key material and high-entropy regions, tries common
obfuscation schemes, scores the recovered plaintext, and optionally writes
non-destructive comments at the source address.

The decryption engine is pure Python and has no PyCryptodome/OpenSSL runtime
dependency. AES, DES and RC4 are implemented in `stringdecrypt/purecrypto/`.

## Features

- XOR (single byte), repeating-key XOR / XorStr, Add, Sub, ROL/ROR
- RC4, AES-128/192/256 ECB and CBC, DES ECB and CBC
- Base64 (including truncated/unpadded input), with nested pipelines
- Key/IV material discovered from the binary, user keys/IVs and known-plaintext
  cribs
- Confidence scoring with `[StringDecrypt]` comments at a configurable threshold
- Complete CLI with stable JSON/JSONL output for automation and AI agents
- String map: stable IDs, address/section/file-offset mapping, nearby strings,
  absolute-pointer and x86-64 RIP-relative code references
- IOC and behavior intelligence: URLs, domains, IPs, paths, registry keys,
  wallets, hashes and behavior tags with an aggregated risk level
- Dependency-free MCP stdio server (`mcp_server.py`) for AI agents, usable next
  to the official IDA 9.5 MCP server
- SHA-256-keyed scan cache and per-scan timeouts so AI clients can explore a
  file without rescanning it for every question
- One-command MCP registration for installed AI clients (`install_mcp.py`)
- Interactive installer that detects IDA and AI clients, with a guided
  uninstall and non-interactive flags (`install.py`)
- Pluggable custom decoders (`custom_decoders/*.py`)
- IDA 9.5 plugin UI (PySide6), press **Ctrl-Shift-D**

.NET assemblies are intentionally not supported; only native binaries are
scanned.

## Installation

Requirements: IDA Professional 9.5 (IDA 9.0+ metadata is declared) and the
Python environment shipped with IDA for the UI. The CLI works with a normal
Python 3.9+ installation.

From this directory, run the interactive wizard:

```powershell
python install.py
```

The wizard asks what to do:

```text
  1) IDA plugin only
  2) MCP server for AI clients only
  3) Both
  4) Uninstall
  5) Exit
```

It then:

1. detects IDA user plugin directories and IDA installations
   (`IDAUSR`, `%APPDATA%\Hex-Rays\IDA Pro`, `~/.idapro`, the Windows registry
   uninstall entries and `Program Files\IDA*`);
2. asks for an IDA plugin or installation path when no location is found;
3. lists the AI clients installed on this machine and asks whether to
   configure all of them (or selected ones);
4. shows the final plan and asks for confirmation.

On Windows the default target is:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_stringdecrypt\
```

The installer keeps existing user files in the installed `custom_decoders`
directory.

### Non-interactive installation

```powershell
python install.py --all --yes             # IDA plugin + detected AI clients
python install.py --ida-only --yes
python install.py --mcp-only --yes
python install.py --mcp-only --mcp-client antigravity --mcp-client claude-code --yes
python install.py --all --uninstall --yes
```

Other options:

```powershell
python install.py --ida-only --target "D:\ida\plugins"
python install.py --ida-only --target "C:\Program Files\IDA Professional 9.5"
python install.py --dry-run              # preview the IDA plugin copy
python install.py --interactive --dry-run
python install.py --no-compile
python install.py --allow-jsonc          # MCP JSONC files (comments are lost)
python install.py --no-backup            # no MCP .bak-* files
```

`--target` accepts either the plugins directory itself or an IDA installation
directory; the installer appends `plugins` when needed. When no mode flag is
given, legacy behaviour is preserved: `--target`, `--dry-run`, `--no-compile`
and `--uninstall` act on the IDA plugin only. Use `--all`, `--mcp-only` or
`--interactive` to include the MCP component. `--yes` without a mode or legacy
flag installs both components. Use `--interactive` to force the wizard when
stdin is not a TTY (for example in a CI shell).

The MCP part uses `install_mcp.py` under the hood and preserves every existing
server entry. Restart IDA after installation. Open **Edit > Plugins > String
Decryptor** or press **Ctrl-Shift-D**.

## IDA usage

1. Open a native PE or ELF database and let auto-analysis finish.
2. Press **Ctrl-Shift-D**.
3. Choose the scan scope and options, then click **Scan**.
4. Review results in the table. Select rows and use **Add comments** to write
   comments, or **Export JSON** to save them.

Defaults in the form:

| Option | Default |
| --- | --- |
| Minimum score | 70 |
| Auto-comment score | 75 |
| Minimum length | 5 |
| Max candidates | 8000 |
| Max heavy candidates | 400 |
| Entropy blobs | 512 |

Keyed ciphers and custom decoders are enabled. Scanning strings from executable
sections and forcing heavy ciphers on every candidate are off by default.

**Keys and IVs are optional.** Leave the **Keys**, **IVs** and **Cribs** fields
empty to use automatic discovery. The plugin tries single-byte XOR/Add/Sub/Rol
and Base64 exhaustively, and derives RC4/AES/DES keys from imports, function
and section names, candidate strings/blobs and built-in cribs (AES material
keys of 16/24/32 bytes, DES keys of 8 bytes, any short RC4 material). Short
user keys are zero-padded and long user keys are truncated to valid cipher
sizes. If a strong
cipher uses a random runtime-only key, no scanner can brute-force it — supply
that key with `--keys` (CLI) or the **Keys** field (UI), or use a known-plaintext
crib.

Comments are **non-destructive**: existing comments are preserved and a new
`[StringDecrypt] ...` line is appended. Addresses that already contain a
`[StringDecrypt]` comment are skipped. The plugin does not patch bytes by
default.

## CLI

The CLI parses PE and ELF files directly and does not require IDA:

```powershell
python -m stringdecrypt.cli scan sample.exe --format json
python -m stringdecrypt.cli scan sample.exe --format text
python -m stringdecrypt.cli scan sample.exe --format jsonl --output results.jsonl
```

Useful filters:

```powershell
python -m stringdecrypt.cli scan sample.exe --min-score 70
python -m stringdecrypt.cli scan sample.exe --schemes xor,base64,rc4
python -m stringdecrypt.cli scan sample.exe --no-heavy
python -m stringdecrypt.cli scan sample.exe --keys "MyKey,hex:00112233"
python -m stringdecrypt.cli scan sample.exe --ivs "0000000000000000"
python -m stringdecrypt.cli scan sample.exe --cribs "https://"
python -m stringdecrypt.cli scan sample.exe --custom-dir .\my_decoders
python -m stringdecrypt.cli scan sample.exe --timeout 90
python -m stringdecrypt.cli scan sample.exe --no-intel
```

CLI defaults: minimum score 60, minimum length 5, 2000 results, 30000
candidates, 2048 entropy blobs. Use `--include-code` to extract strings from
executable sections, `--force-heavy` to run RC4/AES/DES on every candidate,
`--no-custom` to disable custom decoders, and `--no-intel` to skip IOC/behavior
enrichment. `--timeout SECONDS` stops the scan with partial results; the JSON
sets `stats.timed_out` to `true`.

Each result carries a stable `id`, `tags`, `entities` and a `risk` level. The
top level contains the image `sha256` and an `intel` summary with tag, entity
and risk counts. Stable IDs are derived from the address and plaintext, so they
remain valid for later `map_strings`/`get_string_context` calls.

### JSON schema

`--format json` prints one object:

```json
{
  "tool": "ida-stringdecrypt",
  "version": "1.1.0",
  "ok": true,
  "file": "C:\\samples\\sample.exe",
  "sha256": "9f2c...e1",
  "image": {
    "format": "PE",
    "machine": "AMD64",
    "bits": 64,
    "sections": [{"name": ".text", "address": "0x140001000", "...": "..."}],
    "imports": ["KERNEL32.dll!VirtualAlloc"]
  },
  "config": {
    "min_score": 60.0,
    "min_length": 5,
    "max_input_length": 8192,
    "max_results": 2000,
    "schemes": {"base64": true, "xor": true, "xorstr": true, "aes": true},
    "force_heavy": false,
    "enrich": true,
    "timeout_seconds": null
  },
  "stats": {
    "candidates": 1025,
    "strings": 742,
    "entropy_blobs": 138,
    "results": 105,
    "schemes": {"xor": 23, "xorstr": 71, "aes": 1},
    "elapsed_seconds": 88.8,
    "total_elapsed_seconds": 89.1,
    "timed_out": false
  },
  "intel": {
    "tagged_strings": 41,
    "tags": {"url": 12, "network": 12, "http": 10, "domain": 12},
    "entity_types": {"url": 12, "domain": 12},
    "risks": {"info": 64, "low": 41}
  },
  "results": [
    {
      "id": "s_7d08db90826b",
      "address": "0x140002080",
      "ea": 5368713344,
      "file_offset": 2176,
      "kind": "string",
      "encoding": "raw",
      "segment": ".rdata",
      "xrefs": ["0x140001234"],
      "original": "irrelevant input preview",
      "scheme": "xor",
      "key": "5a (Z)",
      "key_hex": "5a",
      "iv_hex": "",
      "pipeline": "xor(0x5a)",
      "plaintext": "https://example.com/api/v1",
      "score": 100.0,
      "text_encoding": "latin-1",
      "details": "input=26b output=26b",
      "confidence": "high",
      "tags": ["url", "network", "http", "domain", "dns"],
      "entities": {
        "url": ["https://example.com/api/v1"],
        "domain": ["example.com"]
      },
      "risk": "low",
      "section": ".rdata",
      "source": "ida"
    }
  ]
}
```

On a parse error the command prints `{"ok": false, "error": "..."}` for JSON
output and exits with code 2. `jsonl` emits one metadata line followed by one
line per result; the result lines are the same objects as above without the
top-level fields. JSON/JSONL output is UTF-8; the CLI reconfigures stdout on
Windows so recovered non-ASCII plaintext cannot break the JSON stream.

Confidence labels: `high` >= 85, `medium` >= 70, `low` >= 55, otherwise
`very_low`.

## MCP server (AI agents)

`mcp_server.py` is a dependency-free MCP (Model Context Protocol) stdio server
that exposes the same PE/ELF engine to any MCP-capable agent: OpenCode, Claude
Desktop, Cline, VS Code, custom tooling, and so on. It does **not** need IDA,
PySide6 or the `mcp` Python package, and it never writes to the binary.

Tools:

| Tool | Purpose |
| --- | --- |
| `scan_binary` | Scan a PE/ELF path; keys are guessed automatically. Returns addresses, sections, file offsets, stable IDs, schemes, keys, scores, tags and plaintext. |
| `analyze_binary` | Triage summary for an unknown file: file metadata, tag/risk/entity counts, notable strings, network IOCs, suspicious imports and suggested next calls. |
| `map_strings` | Paginated, filterable string map. Filter by tag, entity type, scheme, risk, score or plaintext; sort by address, score or risk. |
| `get_string_context` | Resolve one string by ID, address or text. Returns nearby strings, absolute-pointer and RIP-relative code references, related imports, a raw hex window and an IDA hand-off address. |
| `find_strings` | Search recovered plaintext by substring or regular expression, with the same tag/entity/scheme filters. |
| `extract_iocs` | Aggregate URLs, domains, IPs, emails, paths, registry keys, wallets, hashes and filenames, keeping the string IDs and addresses that produced each one. |
| `decrypt_blob` | Try automatic decryption on one hex/Base64/text ciphertext blob. |
| `list_schemes` | Return supported schemes, encodings, tag/entity vocabulary, limits, protocol versions and server metadata. |

Three MCP resources are available:

| URI | Content |
| --- | --- |
| `stringdecrypt://schemes` | Schemes, encodings, tag definitions, entity types, limits and cache stats. |
| `stringdecrypt://tags` | Tag definitions, risk levels, entity types and the stable-ID format. |
| `stringdecrypt://usage` | Recommended analyze → map → context workflow. |

A `triage_binary` prompt accepts `path` and an optional `focus` (for example
`network`, `persistence` or `credentials`) and produces a triage request for the
agent.

The server speaks MCP protocol versions `2025-06-18`, `2025-03-26` and
`2024-11-05`, and honors read-only tool annotations. `structuredContent` is
emitted for `2025-06-18`; older clients receive the same payload as JSON text.

### Automatic setup for AI clients

There is no universal MCP auto-discovery. Every AI client reads its own
configuration file; an agent cannot see the server until that file names it.
`install_mcp.py` detects the clients installed on this machine and merges a
single `stringdecrypt` entry into each config. Existing servers are preserved,
and a timestamped backup is written before every change.

```powershell
python install_mcp.py                      # detect clients and show status
python install_mcp.py --auto --dry-run     # preview all changes
python install_mcp.py --auto               # configure every detected client
python install_mcp.py --client antigravity --client claude-code
python install_mcp.py --auto --uninstall   # remove the entry again
python install_mcp.py --auto --json        # machine-readable result
```

`--auto` touches only clients detected through their config directory,
extension folder or executable. An explicit `--client <key>` writes that
client even when detection missed it. Supported keys:

| Key | Client | Configuration |
| --- | --- | --- |
| `opencode` | OpenCode | `~/.config/opencode/opencode.json` (`mcp.servers`) |
| `antigravity` | Antigravity | `~/.gemini/config/mcp_config.json` (`mcpServers`) |
| `claude-code` | Claude Code | `~/.claude.json` (`mcpServers`, user scope) |
| `claude-desktop` | Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` |
| `codex` | Codex / ChatGPT desktop | `~/.codex/config.toml` (`[mcp_servers.stringdecrypt]`) |
| `vscode` | VS Code | `%APPDATA%\Code\User\mcp.json` (`servers`) |
| `vscode-insiders` | VS Code Insiders | `%APPDATA%\Code - Insiders\User\mcp.json` |
| `cursor` | Cursor | `~/.cursor/mcp.json` (`mcpServers`) |
| `windsurf` | Windsurf | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |
| `cline` | Cline | VS Code globalStorage `cline_mcp_settings.json` |
| `roo` | Roo Code | VS Code globalStorage `mcp_settings.json` |
| `gemini-cli` | Gemini CLI | `~/.gemini/settings.json` (`mcpServers`) |
| `copilot-cli` | GitHub Copilot CLI | `~/.copilot/mcp-config.json` (`mcpServers`) |

The generated entries point at absolute paths, so rerun the installer if the
repository is moved or a different Python interpreter should be used. JSONC
files with comments are skipped unless `--allow-jsonc` is passed; that option
rewrites the file and does not preserve comments. Use `--no-backup` to suppress
the `.bak-*` files.

After installation, most clients need a reload or a new session: reload the VS
Code window, refresh Antigravity's MCP servers, or start a new Claude/Codex
session. OpenCode V2 reloads its configuration automatically.

### Register the server manually

Print a configuration with the correct absolute Python and script paths:

```powershell
cd "C:\Users\Administrator\Documents\Standardprojekt\ida_stringdecrypt"
python mcp_server.py --print-config
python mcp_server.py --print-config --config-style opencode
python mcp_server.py --print-config --config-style vscode
```

Use the Python interpreter that should run the scanner, for example the system
Python or IDA's Python. The server only needs the standard library plus this
repository.

Generic `mcpServers` format (Claude Desktop, Cline, many clients):

```json
{
  "mcpServers": {
    "stringdecrypt": {
      "command": "C:\\Python314\\python.exe",
      "args": ["C:\\Users\\you\\ida_stringdecrypt\\mcp_server.py"]
    }
  }
}
```

OpenCode (`opencode.json` / global config):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "stringdecrypt": {
        "type": "local",
        "command": [
          "C:\\Python314\\python.exe",
          "C:\\Users\\you\\ida_stringdecrypt\\mcp_server.py"
        ]
      }
    }
  }
}
```

The CLI writes the same entry without disturbing other servers:

```powershell
opencode mcp add stringdecrypt --global -- "C:\Python314\python.exe" "C:\Users\you\ida_stringdecrypt\mcp_server.py"
opencode mcp list
```

VS Code `.vscode/mcp.json`:

```json
{
  "servers": {
    "stringdecrypt": {
      "type": "stdio",
      "command": "C:\\Python314\\python.exe",
      "args": ["C:\\Users\\you\\ida_stringdecrypt\\mcp_server.py"]
    }
  }
}
```

Restart or reload the MCP client after editing its configuration. OpenCode V2
watches its configuration and reloads MCP servers automatically. The client
should list all eight tools described above.

### Recommended triage workflow

The canonical scan is cached, so these calls are cheap after the first one:

```text
analyze_binary({"path": "C:\\samples\\sample.exe"})
map_strings({"path": "C:\\samples\\sample.exe",
             "tags": ["network", "http"], "tag_mode": "all",
             "sort": "risk", "limit": 50})
get_string_context({"path": "C:\\samples\\sample.exe", "id": "s_7d08db90826b"})
extract_iocs({"path": "C:\\samples\\sample.exe", "defang": true})
find_strings({"path": "C:\\samples\\sample.exe",
              "query": "password|token", "regex": true})
```

`analyze_binary` is the best first call: it defaults to score 60, returns only
the most notable strings, and suggests the next tool calls. Use a lower
`min_score` (for example 30) when you need recall over precision.

`map_strings` and `find_strings` default to score 30 and are paginated. Each
string item contains `id`, `address`, `ea`, `file_offset`, `section`, `scheme`,
`score`, `confidence`, `risk`, `tags`, `entities` and truncated `plaintext`.
When `stats.next_offset` is not null, call the same tool again with that value
as `offset`.

Filters for `map_strings`/`find_strings`:

| Argument | Default | Meaning |
| --- | --- | --- |
| `tags` | empty | Match behavior/content tags such as `network`, `http`, `persistence`, `injection`, `url` or `registry`. |
| `tag_mode` | `any` | `any` or `all` of the requested tags. |
| `entity_types` | empty | Require a URL, domain, IP, email, path, registry key, wallet, hash, filename, user agent, JWT, environment reference or named pipe. |
| `schemes` | all | Filter by `base64,xor,xorstr,add,sub,rol,rc4,aes,des,custom`. |
| `min_risk` | none | `info`, `low`, `medium` or `high`. |
| `query`, `regex` | empty, false | Substring or regular-expression search on the plaintext. |
| `sort` | `address` | `address`, `score` or `risk`. |
| `offset`, `limit` | 0, 50 | Pagination; maximum page size is 500 (`find_strings` defaults to 30). |
| `max_plaintext_chars` | 400 | Per-string plaintext truncation. |

`analyze_binary` also accepts `notable_limit` (20), `max_iocs` (30) and
`max_plaintext_chars` (300). `extract_iocs` accepts `types`, `min_score` (55),
`limit_per_type` (100) and `defang` (false). `get_string_context` accepts one of
`id`, `address` or `text`, plus `before`/`after` neighbor counts (3 each).

`scan_binary` returns the same JSON payload as `--format json`, including
`sha256`, stable IDs, tags, entities and risk. Its scan options:

| Argument | Default | Meaning |
| --- | --- | --- |
| `path` | required | Native PE or ELF file. |
| `min_score` | 60 | Confidence threshold. Use 70+ for triage, 55 for recall. |
| `schemes` | all | `base64,xor,xorstr,add,sub,rol,rc4,aes,des,custom`. |
| `keys`, `ivs`, `cribs` | empty | Optional; automatic discovery is the default. |
| `heavy` | true | Set false to skip RC4/AES/DES for fast triage. |
| `max_candidates` | 5000 | Lower for speed, raise for large binaries. |
| `max_results` | 200 | Cap on returned hits (maximum 5000). |
| `timeout_seconds` | 120 | Stop with partial results after this many seconds. |
| `refresh` | false | Ignore the scan cache and rescan the file. |

`decrypt_blob` accepts `data`, `data_encoding` (`hex`, `base64`, `text`,
`latin-1`) plus the same scheme/key options, which is handy for a blob
extracted by another tool. It defaults to score 60 and caps input at 64 KiB.

### Tags, entities and risk

Tags are conservative hints, not verdicts. Content tags describe what a string
is (`url`, `domain`, `ip`, `email`, `path`, `registry`, `wallet`, `hash`,
`filename`, `user_agent`, `jwt`, `environment`, `named_pipe`). Behavior tags
describe what it may be used for (`network`, `http`, `dns`, `download`,
`execution`, `command`, `persistence`, `credential`, `credential_theft`,
`crypto`, `anti_debug`, `evasion`, `injection`, `process`, `privilege`,
`lateral`, `wmi`, `exfiltration`, `ransomware`, `uac_bypass`, `sql`,
`encoded`).

Every string gets a risk level (`info`, `low`, `medium`, `high`) equal to the
highest severity of its tags. `analyze_binary` aggregates these into tag, risk
and entity counts. The complete machine-readable vocabulary is available from
`list_schemes` and the `stringdecrypt://tags` resource.

### Caching, limits and timeouts

`scan_binary`, `analyze_binary`, `map_strings`, `find_strings`,
`get_string_context` and `extract_iocs` share a process-local cache. The
mapping/triage tools reuse one canonical scan at score 30 and filter afterwards,
so `analyze_binary` followed by several `map_strings`/`get_string_context` calls
does not rescan the file. Cache keys include the image SHA-256 and scan options;
a changed file or `refresh: true` produces a fresh scan.

- Maximum file size: 256 MiB.
- Maximum page size: 500 strings.
- Canonical mapping scan timeout: 90 seconds. `scan_binary` defaults to 120
  seconds (range 1–600). A timed-out scan returns partial results and sets
  `stats.timed_out`/`cache` information in the response.
- `STRINGDECRYPT_CACHE=0` disables the cache. `STRINGDECRYPT_CACHE_ENTRIES`
  (default 6) and `STRINGDECRYPT_CACHE_TTL` (default 900 seconds) bound memory
  and entry age.
- The cache is in memory only; the server never writes scan results to disk and
  never patches the binary.

### Using it with the official IDA MCP

IDA 9.5 ships the official Hex-Rays IDA MCP server, which multiplexes an open
IDA database for disassembly, decompilation and xrefs. This server is a
companion, not a replacement: register both under distinct names, for example
`ida` and `stringdecrypt`.

Typical combined workflow:

1. Call `analyze_binary` on the target file for recovered strings, tags, IOCs
   and import hints.
2. Use `map_strings` or `find_strings` to narrow the list to a behavior or
   indicator, then `get_string_context` for neighbors and code references.
3. Feed the returned address to the official IDA MCP tools to view the
   surrounding code, xrefs or decompilation. Use `extract_iocs` when you need a
   deduplicated indicator list.

The official IDA MCP documentation recommends disabling *competing IDA MCP
servers* to avoid confusing the agent. This server does not connect to IDA or
claim the same tools, so it can run alongside the official one; keeping the
server names distinct keeps the agent's tool selection unambiguous.

Addresses returned by `scan_binary` are PE virtual addresses using the image
base in the file. If IDA loaded the image at a different base, add the rebase
delta before using an address there.

### Verify the server

```powershell
$env:PYTHONPATH = (Get-Location).Path
python tests\smoke_mcp.py
python tests\smoke_intel.py
```

The MCP smoke test initializes sessions with both new and old protocol
versions, lists tools/resources/prompts, scans the PE64 fixture, checks map
pagination and cache hits, resolves a RIP-relative code reference, extracts
IOCs and decrypts a single XOR blob. The server also works with the official
MCP Python SDK as a client.

## Detection and scoring

The engine tries cheap transforms first and only runs keyed ciphers for
plausible candidates:

- Candidate sources: IDA strings, data references (including RIP-relative
  operands), immediate/stack string runs, high-entropy blobs and key material.
- Key sources: user keys, imports, section names, candidate strings/blobs,
  cribs and material ranked as plausible key lengths. Keys and IVs are
  truncated or zero-padded to valid AES/DES sizes; Base64 input may be
  truncated or missing padding.
- Scoring rewards printable text, letters, vowels, spaces, common words,
  paths/URLs/registry keys/JSON/SQL, and penalizes control characters,
  punctuation soup, repeated tokens, random case, high entropy and
  Base64/hex-like plaintext.
- To suppress Caesar-shift noise, transforms of already-printable data are
  accepted only when the result has a strong marker (`://`, paths, `.dll`,
  registry keys, XML, SQL, etc.) and a high score.

Auto-commenting is deliberately stricter than scanning: the default comment
threshold is 75.

## Custom decoders

Add a Python file to `custom_decoders/` with a callable named `decode`. The
installed plugin also reads `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_stringdecrypt\custom_decoders`.
Names starting with `_` are ignored, so `_example_rot13.py` is a disabled
template. See `custom_decoders/README.md` for the API.

## Limitations

- These are heuristic transformations, not a decompiler or an emulator. A
  custom algorithm, unusual key schedule or runtime-generated key will be
  missed.
- Keyed-cipher key guessing is bounded by design. If a binary uses a long random
  key, supply it with `--keys`/`--key-file` or the UI key field.
- Scores are confidence estimates, not proof. Short or low-entropy strings can
  score moderately without being real decryptions. Review results before
  acting on them.
- Tags and risk levels are heuristics derived from plaintext and imports. They
  can miss context that only exists in code and can produce false positives on
  ordinary library strings.
- Printable data is analyzed conservatively to avoid reporting shifts of
  ordinary strings; some real decryptions of printable sources can be hidden.
- No .NET/IL support; no automatic patching; no network access.
- Large inputs are capped (8192 bytes per candidate by default). Nested
  pipelines are limited to depth 2. The MCP mapping tools refuse files larger
  than 256 MiB.
- Code-reference mapping covers absolute pointer values and x86-64 RIP-relative
  `LEA`/`MOV` operands. Other architectures and computed references are not
  mapped; use the official IDA MCP server for full xrefs.
- Scan time grows with the number of candidates and keyed-cipher operations.
  A typical 1,000-candidate native binary takes roughly 1–2 minutes with the
  default UI settings; reduce the candidate/heavy caps or disable schemes for
  faster triage. MCP scans can be bounded with `timeout_seconds`.

## Development and tests

The repository includes offline unit/smoke tests, a generated PE64 fixture and
IDA integration tests:

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m compileall -q stringdecrypt
python tests\smoke_scoring.py
python tests\smoke_engine.py
python tests\smoke_custom.py
python tests\smoke_peelf.py
python tests\smoke_mcp.py
python tests\smoke_intel.py
python tests\smoke_install_mcp.py
python tests\smoke_install.py
```

IDA integration tests (use fresh database copies):

```powershell
python tests\make_test_pe.py
& "C:\Program Files\IDA Professional 9.5\idat.exe" -A -c -S"tests\ida_headless_test.py" tests\ida_test_pe.exe
& "C:\Program Files\IDA Professional 9.5\ida.exe" -A -c -S"tests\ida_gui_test.py" tests\ida_test_pe.exe
```

The headless test checks discovery, plugin init, candidate collection, key
material, targeted/automatic decryption and comment preservation. The GUI test
opens the PySide6 form, runs the threaded scan and validates the results. The
real-binary profiler is `tests/ida_real_scan.py`.
