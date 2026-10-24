# Custom decoders

Drop a Python file in this directory to teach the scanner an extra transform.
Files whose names start with `_` are ignored, so `_example_rot13.py` is a
disabled template: rename it (for example `rot13.py`) to activate it.

A decoder module must expose a callable named `decode`:

```python
NAME = "rot13"
DESCRIPTION = "ROT13 (ASCII letters only)"

def decode(data: bytes):
    # Return bytes, a list/tuple of bytes, or None.
    return bytes(
        (value - 65 + 13) % 26 + 65 if 65 <= value <= 90 else
        (value - 97 + 13) % 26 + 97 if 97 <= value <= 122 else value
        for value in data
    )
```

Optional extras:

* `NAME` - short name shown in results and in the UI.
* `DESCRIPTION` - free-form text.
* A second parameter is allowed: `def decode(data, context)` where `context`
  is currently `None` (reserved for future use).

Notes:

* Decoders are best-effort. Exceptions are collected and never abort a scan.
* Results still go through the normal confidence scorer, so a bad transform
  will not be auto-commented.
* The scanner also searches for custom decoder files in
  `<plugin dir>/custom_decoders` when running inside IDA.
* Never import modules that require network access or block for a long time;
  custom decoders run for every candidate.
