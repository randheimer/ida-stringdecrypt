"""IDA-side candidate extraction, key collection and comment helpers.

The crypto engine is intentionally IDA-independent.  This module is the thin
bridge: it pulls strings, referenced blobs, immediate/stack constants and
high-entropy regions out of the current database, and it can append comments
without modifying bytes or overwriting existing comments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import keys
from .bytescan import data_ref_blob, entropy_blobs, printable_ratio, shannon_entropy
from .engine import Candidate, ScanResult

try:  # pragma: no cover - only importable inside IDA
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_strlist
    import ida_ua
    import idautils

    IDA_AVAILABLE = True
    IDA_IMPORT_ERROR = ""
except Exception as error:  # noqa: BLE001 - allow CLI imports on plain Python
    IDA_AVAILABLE = False
    IDA_IMPORT_ERROR = f"{type(error).__name__}: {error}"


COMMENT_PREFIX = "[StringDecrypt]"
MAX_STRING_BYTES = 8192
MAX_BLOB_BYTES = 256
MAX_XREFS = 16


@dataclass
class IdaScanOptions:
    min_length: int = 5
    include_strings: bool = True
    include_data_refs: bool = True
    include_immediates: bool = True
    include_entropy: bool = True
    include_code_strings: bool = False
    max_entropy_blobs: int = 512
    max_candidates: int = 20000
    max_instructions: int = 400000
    max_immediates: int = 12000
    start_ea: int | None = None
    end_ea: int | None = None


@dataclass
class CollectStats:
    strings: int = 0
    data_refs: int = 0
    immediates: int = 0
    entropy: int = 0
    instructions: int = 0
    truncated: bool = False

    def as_text(self) -> str:
        return (
            f"strings={self.strings}, data refs={self.data_refs}, "
            f"immediates={self.immediates}, entropy={self.entropy}, "
            f"instructions={self.instructions}"
        )


# ----------------------------------------------------------------------
# Small IDA helpers
# ----------------------------------------------------------------------
def _require_ida() -> None:
    if not IDA_AVAILABLE:
        raise RuntimeError(f"IDA modules are not available: {IDA_IMPORT_ERROR}")


def _is_be() -> bool:
    try:
        return bool(ida_ida.inf_is_be())
    except Exception:
        return False


def _segment_info(ea: int) -> tuple[int, int, str, bool] | None:
    """Return (start, end, name, executable) using the IDA 9.5 API."""
    try:
        info = ida_segment.segment_info_t()
        if ida_segment.get_segment_info(info, ea, ida_segment.GSI_NAME):
            return (
                int(info.start_ea),
                int(info.end_ea),
                info.get_name() or "",
                bool(info.get_perm() & ida_segment.SEGPERM_EXEC),
            )
    except Exception:
        pass
    try:  # IDA 9.0/9.1 fallback
        seg = ida_segment.getseg(ea)
        if seg:
            return (
                int(seg.start_ea),
                int(seg.end_ea),
                ida_segment.get_segm_name(seg) or "",
                bool(seg.perm & ida_segment.SEGPERM_EXEC),
            )
    except Exception:
        pass
    return None


def _segment_name(ea: int) -> str:
    info = _segment_info(ea)
    return info[2] if info else ""


def _is_executable(ea: int) -> bool:
    info = _segment_info(ea)
    return bool(info and info[3])


def _in_range(ea: int, options: IdaScanOptions) -> bool:
    if options.start_ea is not None and ea < options.start_ea:
        return False
    if options.end_ea is not None and ea >= options.end_ea:
        return False
    return True


def _segments() -> list[tuple[int, int, str, bool]]:
    result: list[tuple[int, int, str, bool]] = []
    try:
        current = int(ida_segment.get_first_segment_ea())
        while current != ida_idaapi.BADADDR:
            info = _segment_info(current)
            if info:
                result.append(info)
            next_ea = int(ida_segment.get_next_segment_ea(current))
            if next_ea == ida_idaapi.BADADDR or next_ea == current:
                break
            current = next_ea
        return result
    except Exception:
        result.clear()
    try:  # IDA 9.0/9.1 fallback
        seg = ida_segment.get_first_seg()
        while seg:
            start = int(seg.start_ea)
            result.append(
                (
                    start,
                    int(seg.end_ea),
                    ida_segment.get_segm_name(seg) or "",
                    bool(seg.perm & ida_segment.SEGPERM_EXEC),
                )
            )
            seg = ida_segment.get_next_seg(start)
    except Exception:
        pass
    return result


def _read_bytes(ea: int, size: int) -> bytes:
    try:
        data = ida_bytes.get_bytes(ea, max(0, size))
        return bytes(data) if data else b""
    except Exception:
        return b""


def _clean_blob(raw: bytes) -> bytes:
    """Trim terminators and obvious padding without cutting the payload."""
    if not raw:
        return b""
    raw = raw[:MAX_STRING_BYTES]
    if len(raw) > 4:
        # A NUL terminator is expected for C strings; anything after it is a
        # separate item and only adds noise.
        nul = raw.find(b"\x00")
        if 0 < nul <= len(raw) - 1 and nul >= 4:
            raw = raw[:nul]
    return raw


def _dtype_size(dtype: int) -> int:
    try:
        size = int(ida_ua.get_dtype_size(dtype))
        if 1 <= size <= 8:
            return size
    except Exception:
        pass
    return 0


def _immediate_bytes(value: int, dtype: int) -> bytes:
    size = _dtype_size(dtype)
    if not size:
        return b""
    value &= (1 << (size * 8)) - 1
    return int(value).to_bytes(size, "big" if _is_be() else "little", signed=False)


def _interesting_immediate(raw: bytes) -> bool:
    if not raw or len(raw) < 3:
        return False
    if raw.count(0) == len(raw) or raw.count(0xFF) == len(raw):
        return False
    if len(set(raw)) == 1:
        return False
    printable = printable_ratio(raw)
    if printable >= 0.6:
        return True
    if printable <= 0.15:
        return False
    return shannon_entropy(raw) >= 2.0


def _xrefs_to(ea: int) -> list[int]:
    result: list[int] = []
    try:
        for xref in idautils.XrefsTo(ea, 0):
            result.append(int(xref.frm))
            if len(result) >= MAX_XREFS:
                break
    except Exception:
        pass
    return result


def _address_like(value: int, options: IdaScanOptions) -> bool:
    try:
        if options.start_ea is not None and value < options.start_ea:
            return False
        if options.end_ea is not None and value >= options.end_ea:
            return False
        return ida_bytes.is_loaded(value) and _segment_info(value) is not None
    except Exception:
        return False


# ----------------------------------------------------------------------
# Candidate collection
# ----------------------------------------------------------------------
class _Collector:
    def __init__(self, options: IdaScanOptions):
        self.options = options
        self.candidates: list[Candidate] = []
        self._by_key: dict[tuple[int, bytes], Candidate] = {}
        self.stats = CollectStats()

    @property
    def full(self) -> bool:
        return len(self.candidates) >= self.options.max_candidates

    def add(
        self,
        ea: int,
        raw: bytes,
        *,
        kind: str,
        text: str = "",
        encoding: str = "raw",
        xrefs: Iterable[int] | None = None,
    ) -> Candidate | None:
        ea = int(ea)
        raw = _clean_blob(raw)
        if self.full or not raw or len(raw) < self.options.min_length:
            return None
        if not _in_range(ea, self.options):
            return None
        key = (ea, raw)
        existing = self._by_key.get(key)
        if existing is not None:
            if xrefs:
                for ref in xrefs:
                    if ref not in existing.xrefs and len(existing.xrefs) < MAX_XREFS:
                        existing.xrefs.append(ref)
            return existing
        candidate = Candidate(
            ea=ea,
            raw=raw,
            kind=kind,
            encoding=encoding,
            text=text,
            xrefs=list(xrefs or [])[:MAX_XREFS],
            segment=_segment_name(ea),
            source="ida",
        )
        self._by_key[key] = candidate
        self.candidates.append(candidate)
        return candidate

    def add_stat(self, kind: str) -> None:
        if kind == "string":
            self.stats.strings += 1
        elif kind == "data-ref":
            self.stats.data_refs += 1
        elif kind in ("immediate", "stack"):
            self.stats.immediates += 1
        elif kind == "entropy":
            self.stats.entropy += 1


def _collect_strings(collector: _Collector, progress: Callable[[str, int, int], None] | None) -> None:
    options = collector.options
    try:
        strings = idautils.Strings()
        strings.setup(
            strtypes=[
                ida_nalt.STRTYPE_C,
                ida_nalt.STRTYPE_C_16,
                ida_nalt.STRTYPE_C_32,
                ida_nalt.STRTYPE_PASCAL,
                ida_nalt.STRTYPE_PASCAL_16,
                ida_nalt.STRTYPE_PASCAL_32,
                ida_nalt.STRTYPE_LEN2,
                ida_nalt.STRTYPE_LEN2_16,
                ida_nalt.STRTYPE_LEN2_32,
                ida_nalt.STRTYPE_LEN4,
                ida_nalt.STRTYPE_LEN4_16,
                ida_nalt.STRTYPE_LEN4_32,
            ],
            minlen=max(2, options.min_length),
            only_7bit=False,
            ignore_instructions=not options.include_code_strings,
            display_only_existing_strings=False,
        )
    except Exception:
        strings = None

    if strings is not None:
        total = strings.size
        for index, item in enumerate(strings):
            if collector.full:
                collector.stats.truncated = True
                break
            if item is None:
                continue
            try:
                if item.is_synthetic_string():
                    # The text does not exist in the bytes; nothing to decrypt.
                    continue
                ea = int(item.ea)
                if not _in_range(ea, options):
                    continue
                if _is_executable(ea) and not options.include_code_strings:
                    continue
                bpu = int(ida_nalt.get_strtype_bpu(item.strtype))
                byte_length = max(1, int(item.length))
                raw = _read_bytes(ea, min(byte_length, MAX_STRING_BYTES))
                text = str(item)
            except Exception:
                continue
            if bpu == 2:
                encoding = "utf-16be" if _is_be() else "utf-16le"
            elif bpu == 4:
                encoding = "utf-32be" if _is_be() else "utf-32le"
            else:
                encoding = "ascii"
            before = len(collector.candidates)
            collector.add(
                ea,
                raw,
                kind="string",
                text=text,
                encoding=encoding,
                xrefs=_xrefs_to(ea),
            )
            if len(collector.candidates) > before:
                collector.add_stat("string")
            if progress and index and index % 250 == 0:
                progress("strings", index, total)


def _collect_data_refs(collector: _Collector) -> None:
    """Follow immediate/direct-memory operands to data blobs.

    This catches encrypted blobs that IDA has not typed as strings and that do
    not look like strings to its own scanner.
    """
    options = collector.options
    if not options.include_data_refs:
        return
    seen_targets: set[int] = set()
    for start, end, _name, executable in _segments():
        if not executable or collector.full:
            continue
        current = start
        while current < end:
            if collector.stats.instructions >= options.max_instructions:
                collector.stats.truncated = True
                return
            try:
                flags = ida_bytes.get_flags(current)
                if not ida_bytes.is_code(flags):
                    current = ida_bytes.next_head(current, end)
                    if current == ida_idaapi.BADADDR:
                        break
                    continue
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, current):
                    current = ida_bytes.next_head(current, end)
                    if current == ida_idaapi.BADADDR:
                        break
                    continue
                collector.stats.instructions += 1
                for operand in insn.ops:
                    try:
                        optype = operand.type
                    except Exception:
                        continue
                    target = 0
                    if optype == ida_ua.o_mem:
                        target = int(operand.addr)
                    elif optype == ida_ua.o_displ:
                        # RIP-relative operands (the normal x64 data reference)
                        # store the computed target address in 'addr'.
                        target = int(operand.addr)
                    elif optype == ida_ua.o_imm:
                        target = int(operand.value)
                    else:
                        continue
                    if not _address_like(target, options) or target in seen_targets:
                        continue
                    seen_targets.add(target)
                    if ida_bytes.is_strlit_ea(target) or ida_bytes.is_code_ea(target):
                        continue
                    raw = _read_bytes(target, MAX_BLOB_BYTES)
                    if not raw:
                        continue
                    # Keep this cheap: referenced names/structures are noise.
                    printable = printable_ratio(raw)
                    entropy = shannon_entropy(raw)
                    if printable >= 0.98 and len(set(raw)) < 12:
                        continue
                    if printable < 0.35 and entropy < 3.0:
                        continue
                    trimmed = data_ref_blob(raw, target, MAX_BLOB_BYTES, options.min_length)
                    if trimmed is None:
                        continue
                    ea, blob = trimmed
                    before = len(collector.candidates)
                    collector.add(
                        ea,
                        blob,
                        kind="data-ref",
                        encoding="raw",
                        xrefs=[current],
                    )
                    if len(collector.candidates) > before:
                        collector.add_stat("data-ref")
            except Exception:
                pass
            current = ida_bytes.next_head(current, end)
            if current == ida_idaapi.BADADDR:
                break


def _collect_immediates(collector: _Collector) -> None:
    """Extract immediate values and short runs (stack-string heuristic)."""
    options = collector.options
    if not options.include_immediates:
        return
    seen: set[bytes] = set()
    run: list[tuple[int, bytes]] = []
    run_function = -1
    run_last_ea = -1
    immediate_count = 0

    def flush() -> None:
        nonlocal run
        if len(run) >= 2:
            joined = b"".join(raw for _ea, raw in run)[:128]
            if len(joined) >= 4:
                if joined not in seen:
                    seen.add(joined)
                    before = len(collector.candidates)
                    collector.add(run[0][0], joined, kind="stack", encoding="raw")
                    if len(collector.candidates) > before:
                        collector.add_stat("stack")
                reversed_blob = b"".join(raw for _ea, raw in reversed(run))[:128]
                if reversed_blob not in seen:
                    seen.add(reversed_blob)
                    before = len(collector.candidates)
                    collector.add(run[0][0], reversed_blob, kind="stack", encoding="raw")
                    if len(collector.candidates) > before:
                        collector.add_stat("stack")
        run = []

    for start, end, _name, executable in _segments():
        if not executable or collector.full:
            continue
        current = start
        while current < end:
            if (
                collector.stats.instructions >= options.max_instructions
                or immediate_count >= options.max_immediates
            ):
                collector.stats.truncated = True
                flush()
                return
            try:
                flags = ida_bytes.get_flags(current)
                if not ida_bytes.is_code(flags):
                    current = ida_bytes.next_head(current, end)
                    if current == ida_idaapi.BADADDR:
                        break
                    continue
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, current):
                    current = ida_bytes.next_head(current, end)
                    if current == ida_idaapi.BADADDR:
                        break
                    continue
                collector.stats.instructions += 1
                function_ea = -1
                try:
                    start_ea = int(ida_funcs.get_func_start(current))
                    if start_ea != ida_idaapi.BADADDR:
                        function_ea = start_ea
                except Exception:
                    pass
                immediates: list[bytes] = []
                for operand in insn.ops:
                    try:
                        if operand.type != ida_ua.o_imm:
                            continue
                    except Exception:
                        continue
                    value = int(operand.value)
                    if _address_like(value, options):
                        # Address-valued operands are handled as data refs.
                        continue
                    raw = _immediate_bytes(value, int(operand.dtype))
                    if _interesting_immediate(raw):
                        immediates.append(raw)
                        immediate_count += 1
                if immediates:
                    if (
                        function_ea == run_function
                        and run_last_ea >= 0
                        and current - run_last_ea <= 32
                        and len(run) < 12
                    ):
                        run.extend((current, raw) for raw in immediates)
                    else:
                        flush()
                        run = [(current, raw) for raw in immediates]
                    run_function = function_ea
                    run_last_ea = current
                    for raw in immediates:
                        if raw in seen:
                            continue
                        seen.add(raw)
                        before = len(collector.candidates)
                        collector.add(current, raw, kind="immediate", encoding="raw")
                        if len(collector.candidates) > before:
                            collector.add_stat("immediate")
                else:
                    if run and current - run_last_ea > 32:
                        flush()
            except Exception:
                pass
            current = ida_bytes.next_head(current, end)
            if current == ida_idaapi.BADADDR:
                break
    flush()


def _collect_entropy(collector: _Collector) -> None:
    options = collector.options
    if not options.include_entropy:
        return
    remaining = max(0, options.max_entropy_blobs)
    if not remaining:
        return
    for start, end, _name, executable in _segments():
        if executable or remaining <= 0 or collector.full:
            continue
        if options.start_ea is not None:
            start = max(start, options.start_ea)
        if options.end_ea is not None:
            end = min(end, options.end_ea)
        if start >= end:
            continue
        current = start
        while current < end and remaining > 0 and not collector.full:
            chunk_size = min(0x10000, end - current)
            chunk = _read_bytes(current, chunk_size)
            if not chunk:
                current += chunk_size
                continue
            hits = entropy_blobs(
                chunk,
                base_ea=current,
                min_length=max(8, options.min_length),
                max_length=256,
                threshold=4.35,
                step=64,
                max_blobs=remaining,
            )
            for hit in hits:
                before = len(collector.candidates)
                collector.add(
                    hit.ea,
                    hit.raw,
                    kind="entropy",
                    encoding="raw",
                )
                if len(collector.candidates) > before:
                    collector.add_stat("entropy")
                    remaining -= 1
            current += chunk_size


def collect_candidates(
    options: IdaScanOptions | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> tuple[list[Candidate], CollectStats]:
    """Collect decryptable candidates from the current IDA database."""
    _require_ida()
    options = options or IdaScanOptions()
    collector = _Collector(options)

    if options.include_strings:
        if progress:
            progress("strings", 0, 0)
        _collect_strings(collector, progress)
    if progress:
        progress("references", 0, 0)
    _collect_data_refs(collector)
    if progress:
        progress("immediates", 0, 0)
    _collect_immediates(collector)
    if progress:
        progress("entropy", 0, 0)
    _collect_entropy(collector)

    if collector.full:
        collector.stats.truncated = True
    return collector.candidates, collector.stats


# ----------------------------------------------------------------------
# Key material
# ----------------------------------------------------------------------
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def _add_material(target: list[bytes], seen: set[bytes], value: bytes, limit: int) -> None:
    if not value or len(value) > 256 or value in seen:
        return
    seen.add(value)
    target.append(value)
    text = value.decode("latin-1", "ignore")
    for part in _SPLIT_RE.split(text):
        if len(part) >= 2:
            for candidate in (part.encode("latin-1", "ignore"), part.encode("utf-8", "ignore")):
                if candidate and candidate not in seen and len(candidate) <= 256:
                    seen.add(candidate)
                    target.append(candidate)
                    if len(target) >= limit:
                        return
    # CamelCase split: GetProcAddress -> Get, Proc, Address.
    for part in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", text):
        if len(part) >= 3:
            candidate = part.encode("latin-1", "ignore")
            if candidate and candidate not in seen:
                seen.add(candidate)
                target.append(candidate)
                if len(target) >= limit:
                    return


def collect_key_material(
    candidates: Iterable[Candidate],
    *,
    include_names: bool = True,
    limit: int = 4096,
) -> list[bytes]:
    """Build plausible key/IV material from the database and candidates."""
    _require_ida()
    material: list[bytes] = []
    seen: set[bytes] = set()

    # Data referenced by the code is a much better key source than the flood of
    # function/import names, so collect it before the generic names.
    candidates = list(candidates)
    for candidate in candidates:
        if 1 <= len(candidate.raw) <= 64:
            _add_material(material, seen, candidate.raw, limit)
        if candidate.text:
            try:
                text_bytes = candidate.text.encode("latin-1", "ignore")
            except Exception:
                text_bytes = b""
            if 1 <= len(text_bytes) <= 64:
                _add_material(material, seen, text_bytes, limit)
        if len(material) >= limit:
            break

    if include_names:
        try:
            module_count = int(ida_nalt.get_import_module_qty())
            for index in range(min(module_count, 1024)):
                module = ida_nalt.get_import_module_name(index) or ""
                _add_material(material, seen, module.encode("latin-1", "ignore"), limit)

                def callback(ea, name, ordinal, _module=module):
                    if name:
                        _add_material(
                            material,
                            seen,
                            name.encode("latin-1", "ignore"),
                            limit,
                        )
                        _add_material(
                            material,
                            seen,
                            f"{_module}!{name}".encode("latin-1", "ignore"),
                            limit,
                        )
                    return True

                try:
                    ida_nalt.enum_import_names(index, callback)
                except Exception:
                    pass
                if len(material) >= limit:
                    break
        except Exception:
            pass

        if len(material) < limit:
            try:
                for function_ea in idautils.Functions():
                    name = ida_funcs.get_func_name(function_ea) or ""
                    _add_material(material, seen, name.encode("latin-1", "ignore"), limit)
                    if len(material) >= limit:
                        break
            except Exception:
                pass

        if len(material) < limit:
            try:
                for ea, name in idautils.Names():
                    if not name:
                        continue
                    _add_material(material, seen, name.encode("latin-1", "ignore"), limit)
                    if len(material) >= limit:
                        break
            except Exception:
                pass

        if len(material) < limit:
            for _start, _end, name, _executable in _segments():
                _add_material(material, seen, name.encode("latin-1", "ignore"), limit)

    return keys.merge_material(material, limit=limit)


# ----------------------------------------------------------------------
# Address ranges
# ----------------------------------------------------------------------
def current_function_range() -> tuple[int, int] | None:
    _require_ida()
    try:
        ea = int(ida_kernwin.get_screen_ea())
        info = ida_funcs.func_entry_info_t()
        if ida_funcs.get_func_entry_info(info, ea):
            return int(info.start_ea), int(info.end_ea)
    except Exception:
        pass
    try:  # IDA 9.0/9.1 fallback
        ea = int(ida_kernwin.get_screen_ea())
        function = ida_funcs.get_func(ea)
        if function:
            return int(function.start_ea), int(function.end_ea)
    except Exception:
        pass
    return None


def selected_range() -> tuple[int, int] | None:
    _require_ida()
    try:
        selection = ida_kernwin.read_range_selection(None)
        if not selection:
            return None
        if isinstance(selection, tuple) and len(selection) >= 2:
            start, end = int(selection[0]), int(selection[1])
        else:  # pragma: no cover - some IDA builds return a custom object
            start, end = int(selection[0]), int(selection[1])
        if start > end:
            start, end = end, start
        return start, end + 1
    except Exception:
        return None


# ----------------------------------------------------------------------
# Comments (non-destructive)
# ----------------------------------------------------------------------
def _format_comment(result: ScanResult, max_length: int = 220) -> str:
    plaintext = (
        result.plaintext.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    if len(plaintext) > max_length:
        plaintext = plaintext[: max_length - 3] + "..."
    key = result.key_display()
    key_part = f" key={key}" if key else ""
    return (
        f"{COMMENT_PREFIX} {result.scheme} "
        f"score={result.score:.1f}{key_part}: {plaintext}"
    )


def apply_comments(
    results: Iterable[ScanResult],
    threshold: float,
    *,
    selected_eas: set[int] | None = None,
) -> tuple[int, int]:
    """Append comments for the best result per address.

    Returns (added, skipped).  Existing comments are preserved and a marker is
    used to avoid adding the same plugin comment twice.
    """
    _require_ida()
    best: dict[int, ScanResult] = {}
    for result in results:
        if selected_eas is not None and result.candidate.ea not in selected_eas:
            continue
        if result.score < threshold:
            continue
        current = best.get(result.candidate.ea)
        if current is None or result.score > current.score:
            best[result.candidate.ea] = result

    added = 0
    skipped = 0
    for ea, result in sorted(best.items()):
        try:
            current = ida_bytes.get_cmt(ea, False) or ""
            if COMMENT_PREFIX in current:
                skipped += 1
                continue
            line = _format_comment(result)
            combined = f"{current}\n{line}" if current else line
            if ida_bytes.set_cmt(ea, combined, False):
                added += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return added, skipped
