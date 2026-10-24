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
- Pluggable custom decoders (`custom_decoders/*.py`)
- IDA 9.5 plugin UI (PySide6), press **Ctrl-Shift-D**

.NET assemblies are intentionally not supported; only native binaries are
scanned.

## Installation

Requirements: IDA Professional 9.5 (IDA 9.0+ metadata is declared) and the
Python environment shipped with IDA for the UI. The CLI works with a normal
Python 3.9+ installation.

From this directory:

```powershell
python install.py
```

The installer copies the plugin to:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_stringdecrypt\
```

Other options:

```powershell
python install.py --dry-run              # show what would be copied
python install.py --target "D:\ida\plugins"
python install.py --no-compile
python install.py --uninstall
```

Restart IDA after installation. Open **Edit > Plugins > String Decryptor** or
press **Ctrl-Shift-D**. The installer keeps existing user files in the
installed `custom_decoders` directory.

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
```

CLI defaults: minimum score 60, minimum length 5, 2000 results, 30000
candidates, 2048 entropy blobs. Use `--include-code` to extract strings from
executable sections, `--force-heavy` to run RC4/AES/DES on every candidate, and
`--no-custom` to disable custom decoders.

### JSON schema

`--format json` prints one object:

```json
{
  "tool": "ida-stringdecrypt",
  "version": "1.0.0",
  "ok": true,
  "file": "C:\\samples\\sample.exe",
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
    "force_heavy": false
  },
  "stats": {
    "candidates": 1025,
    "strings": 742,
    "entropy_blobs": 138,
    "results": 105,
    "schemes": {"xor": 23, "xorstr": 71, "aes": 1},
    "elapsed_seconds": 88.8
  },
  "results": [
    {
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
      "section": ".rdata",
      "source": "ida"
    }
  ]
}
```

On a parse error the command prints `{"ok": false, "error": "..."}` for JSON
output and exits with code 2. `jsonl` emits one metadata line followed by one
line per result; the result lines are the same objects as above without the
top-level fields.

Confidence labels: `high` >= 85, `medium` >= 70, `low` >= 55, otherwise
`very_low`.

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
- Printable data is analyzed conservatively to avoid reporting shifts of
  ordinary strings; some real decryptions of printable sources can be hidden.
- No .NET/IL support; no automatic patching; no network access.
- Large inputs are capped (8192 bytes per candidate by default). Nested
  pipelines are limited to depth 2.
- Scan time grows with the number of candidates and keyed-cipher operations.
  A typical 1,000-candidate native binary takes roughly 1–2 minutes with the
  default UI settings; reduce the candidate/heavy caps or disable schemes for
  faster triage.

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
