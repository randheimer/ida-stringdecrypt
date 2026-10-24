"""Minimal pure-Python PE/ELF image parser.

The CLI uses this module to find strings and high-entropy blobs without IDA.
Only the parts needed for static string recovery are implemented: headers,
sections/segments, image base, entry point and (for PE) imports.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Iterator

from . import bytescan
from .engine import Candidate


class BinaryParseError(Exception):
    pass


PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0x01C2: "arm_thumb",
    0x01C4: "arm",
    0xAA64: "aarch64",
    0x0200: "ia64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

ELF_MACHINES = {
    0: "none",
    2: "sparc",
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    42: "superh",
    50: "ia64",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    258: "loongarch",
}

PE_SCN_MEM_EXECUTE = 0x20000000
PE_SCN_MEM_READ = 0x40000000
PE_SCN_MEM_WRITE = 0x80000000
PE_SCN_CNT_CODE = 0x00000020
PE_SCN_CNT_INITIALIZED_DATA = 0x00000040
PE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_NOBITS = 8
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11


def _u16(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _cstring(data: bytes, offset: int, limit: int = 1024) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("latin-1", "replace")


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    file_offset: int
    file_size: int
    executable: bool = False
    writable: bool = False
    readable: bool = True
    alloc: bool = True
    section_type: int = 0

    @property
    def end(self) -> int:
        return self.va + self.vsize

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": f"0x{self.va:x}",
            "va": self.va,
            "vsize": self.vsize,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "executable": self.executable,
            "writable": self.writable,
            "alloc": self.alloc,
        }


@dataclass
class BinaryImage:
    path: str
    data: bytes
    format: str
    bits: int
    machine: str
    file_type: str
    image_base: int
    entry: int
    sections: list[Section]
    imports: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    size_of_headers: int = 0
    sha256: str = ""

    # ------------------------------------------------------------------
    # Address translation
    # ------------------------------------------------------------------
    def section_for_va(self, va: int) -> Section | None:
        for section in self.sections:
            if section.contains(va):
                return section
        return None

    def va_to_file_offset(self, va: int) -> int | None:
        section = self.section_for_va(va)
        if section is None:
            return None
        delta = va - section.va
        if delta < 0 or delta >= section.file_size:
            return None
        return section.file_offset + delta

    def pe_rva_to_offset(self, rva: int) -> int | None:
        if rva < self.size_of_headers:
            return rva
        for section in self.sections:
            section_rva = section.va - self.image_base
            if section_rva <= rva < section_rva + max(section.vsize, section.file_size):
                delta = rva - section_rva
                if delta < section.file_size:
                    return section.file_offset + delta
                return None
        return None

    def read_va(self, va: int, size: int) -> bytes:
        section = self.section_for_va(va)
        if section is None and 0 < va < self.image_base:
            shifted = self.image_base + va
            section = self.section_for_va(shifted)
            if section is not None:
                va = shifted
        if section is None or size <= 0:
            return b""
        delta = va - section.va
        available = min(size, max(0, section.file_size - delta))
        start = section.file_offset + delta
        out = bytearray(self.data[start:start + available])
        if len(out) < size and section.vsize > delta + len(out):
            out.extend(b"\x00" * min(size - len(out), section.vsize - delta - len(out)))
        return bytes(out)

    def section_data(self, section: Section) -> bytes:
        if section.file_size <= 0:
            return b""
        start = section.file_offset
        return self.data[start:start + section.file_size]

    def to_dict(self) -> dict:
        return {
            "file": self.path,
            "format": self.format,
            "bits": self.bits,
            "machine": self.machine,
            "file_type": self.file_type,
            "image_base": f"0x{self.image_base:x}",
            "entry": f"0x{self.entry:x}",
            "size": len(self.data),
            "sha256": self.sha256,
            "sections": [section.to_dict() for section in self.sections],
            "imports": self.imports,
            "warnings": self.warnings,
        }


# ----------------------------------------------------------------------
# PE
# ----------------------------------------------------------------------
def _parse_pe(path: str, data: bytes) -> BinaryImage:
    if len(data) < 0x40:
        raise BinaryParseError("file is too small to be a PE image")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise BinaryParseError("invalid PE signature")
    coff = pe_offset + 4
    machine_id = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    symbol_offset = _u32(data, coff + 8)
    symbol_count = _u32(data, coff + 12)
    optional_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    if section_count == 0 or section_count > 256:
        raise BinaryParseError(f"unreasonable PE section count: {section_count}")

    optional = coff + 20
    if optional + optional_size > len(data) or optional_size < 64:
        raise BinaryParseError("truncated PE optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        bits = 32
        image_base = _u32(data, optional + 28)
        size_of_headers = _u32(data, optional + 60)
        entry = _u32(data, optional + 16)
        dir_count = _u32(data, optional + 92)
        dir_offset = optional + 96
        thunk_size = 4
    elif magic == 0x20B:
        bits = 64
        image_base = _u64(data, optional + 24)
        size_of_headers = _u32(data, optional + 60)
        entry = _u32(data, optional + 16)
        dir_count = _u32(data, optional + 108)
        dir_offset = optional + 112
        thunk_size = 8
    else:
        raise BinaryParseError(f"unsupported PE optional header magic 0x{magic:x}")

    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise BinaryParseError("truncated PE section table")

    sections: list[Section] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = data[offset:offset + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("latin-1", "replace") or f"section{index}"
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_offset = _u32(data, offset + 20)
        flags = _u32(data, offset + 36)
        if raw_offset > len(data):
            raw_size = 0
        else:
            raw_size = min(raw_size, len(data) - raw_offset)
        sections.append(Section(
            name=name,
            va=image_base + virtual_address,
            vsize=max(virtual_size, raw_size),
            file_offset=raw_offset,
            file_size=raw_size,
            executable=bool(flags & PE_SCN_MEM_EXECUTE) or bool(flags & PE_SCN_CNT_CODE),
            writable=bool(flags & PE_SCN_MEM_WRITE),
            readable=bool(flags & PE_SCN_MEM_READ),
            alloc=True,
            section_type=flags,
        ))

    file_type = "dll" if characteristics & 0x2000 else "exe"
    if characteristics & 0x0001:
        file_type = "obj"
    image = BinaryImage(
        path=path,
        data=data,
        format="pe",
        bits=bits,
        machine=PE_MACHINES.get(machine_id, f"machine_0x{machine_id:x}"),
        file_type=file_type,
        image_base=image_base,
        entry=image_base + entry,
        sections=sections,
        size_of_headers=size_of_headers,
    )

    if symbol_offset and symbol_count and symbol_offset < len(data):
        image.warnings.append(f"COFF symbols present ({symbol_count})")
    if dir_count > 0 and dir_offset + 8 <= optional + optional_size:
        import_rva = _u32(data, dir_offset + 8)
        import_size = _u32(data, dir_offset + 12)
        if import_rva and import_size:
            image.imports = _parse_pe_imports(image, import_rva, import_size, thunk_size)
    return image


def _parse_pe_imports(image: BinaryImage, rva: int, size: int, thunk_size: int) -> list[str]:
    data = image.data
    descriptor_offset = image.pe_rva_to_offset(rva)
    if descriptor_offset is None:
        image.warnings.append("PE import directory is not file-backed")
        return []

    imports: list[str] = []
    max_descriptors = min(max(size // 20, 1), 4096)
    for index in range(max_descriptors):
        offset = descriptor_offset + index * 20
        if offset + 20 > len(data):
            break
        original_thunk, timestamp, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", data, offset)
        if not (original_thunk or timestamp or forwarder or name_rva or first_thunk):
            break
        dll = _cstring(data, image.pe_rva_to_offset(name_rva) or 0)
        thunk_rva = original_thunk or first_thunk
        thunk_offset = image.pe_rva_to_offset(thunk_rva)
        if thunk_offset is None:
            continue
        for thunk_index in range(4096):
            entry_offset = thunk_offset + thunk_index * thunk_size
            if entry_offset + thunk_size > len(data):
                break
            if thunk_size == 8:
                value = _u64(data, entry_offset)
                ordinal_mask = 1 << 63
            else:
                value = _u32(data, entry_offset)
                ordinal_mask = 1 << 31
            if value == 0:
                break
            if value & ordinal_mask:
                imports.append(f"{dll}!#{value & 0xFFFF}")
            else:
                name_offset = image.pe_rva_to_offset(value & 0x7FFFFFFF)
                if name_offset is None:
                    continue
                symbol = _cstring(data, name_offset + 2)
                imports.append(f"{dll}!{symbol}" if dll else symbol)
            if len(imports) >= 5000:
                return imports
    return imports


# ----------------------------------------------------------------------
# ELF
# ----------------------------------------------------------------------
def _parse_elf(path: str, data: bytes) -> BinaryImage:
    if len(data) < 52:
        raise BinaryParseError("file is too small to be an ELF image")
    elf_class = data[4]
    elf_data = data[5]
    if elf_class not in (1, 2):
        raise BinaryParseError(f"unsupported ELF class {elf_class}")
    if elf_data not in (1, 2):
        raise BinaryParseError(f"unsupported ELF data encoding {elf_data}")
    bits = 32 if elf_class == 1 else 64
    endian = "<" if elf_data == 1 else ">"
    is64 = bits == 64

    if is64:
        if len(data) < 64:
            raise BinaryParseError("truncated ELF64 header")
        entry = _u64(data, 24, endian)
        phoff = _u64(data, 32, endian)
        shoff = _u64(data, 40, endian)
        phentsize = _u16(data, 54, endian)
        phnum = _u16(data, 56, endian)
        shentsize = _u16(data, 58, endian)
        shnum = _u16(data, 60, endian)
        shstrndx = _u16(data, 62, endian)
    else:
        entry = _u32(data, 24, endian)
        phoff = _u32(data, 28, endian)
        shoff = _u32(data, 32, endian)
        phentsize = _u16(data, 42, endian)
        phnum = _u16(data, 44, endian)
        shentsize = _u16(data, 46, endian)
        shnum = _u16(data, 48, endian)
        shstrndx = _u16(data, 50, endian)

    e_type = _u16(data, 16, endian)
    machine_id = _u16(data, 18, endian)
    file_type = {
        1: "elf-rel",
        2: "elf-exec",
        3: "elf-shared",
        4: "elf-core",
    }.get(e_type, f"elf-type-{e_type}")

    raw_sections: list[tuple[int, int, int, int, int, int, int]] = []
    if shoff and shnum and shentsize:
        min_entsize = 64 if is64 else 40
        if shentsize < min_entsize:
            raise BinaryParseError("invalid ELF section header size")
        if shnum > 8192:
            raise BinaryParseError(f"unreasonable ELF section count: {shnum}")
        for index in range(shnum):
            offset = shoff + index * shentsize
            if offset + min_entsize > len(data):
                break
            name_off = _u32(data, offset, endian)
            sh_type = _u32(data, offset + 4, endian)
            if is64:
                flags = _u64(data, offset + 8, endian)
                addr = _u64(data, offset + 16, endian)
                file_offset = _u64(data, offset + 24, endian)
                size = _u64(data, offset + 32, endian)
            else:
                flags = _u32(data, offset + 8, endian)
                addr = _u32(data, offset + 12, endian)
                file_offset = _u32(data, offset + 16, endian)
                size = _u32(data, offset + 20, endian)
            raw_sections.append((name_off, sh_type, flags, addr, file_offset, size, index))

    shstrtab = b""
    if raw_sections and shstrndx < len(raw_sections):
        _, sh_type, _, _, file_offset, size, _ = raw_sections[shstrndx]
        if sh_type != SHT_NOBITS and file_offset < len(data):
            shstrtab = data[file_offset:min(file_offset + size, len(data))]

    def section_name(name_off: int) -> str:
        if not shstrtab or name_off >= len(shstrtab):
            return ""
        end = shstrtab.find(b"\x00", name_off)
        if end < 0:
            end = len(shstrtab)
        return shstrtab[name_off:end].decode("latin-1", "replace")

    sections: list[Section] = []
    for name_off, sh_type, flags, addr, file_offset, size, index in raw_sections:
        name = section_name(name_off) or f"section{index}"
        if sh_type == SHT_NOBITS:
            file_size = 0
        elif file_offset >= len(data):
            file_size = 0
        else:
            file_size = min(size, len(data) - file_offset)
        alloc = bool(flags & SHF_ALLOC)
        sections.append(Section(
            name=name,
            va=addr if alloc and addr else file_offset,
            vsize=max(size, file_size),
            file_offset=file_offset,
            file_size=file_size,
            executable=bool(flags & SHF_EXECINSTR),
            writable=bool(flags & SHF_WRITE),
            readable=True,
            alloc=alloc,
            section_type=sh_type,
        ))

    warnings: list[str] = []
    # Section headers may be stripped from packed/extracted images.  Fall back
    # to PT_LOAD segments so the CLI can still find strings.
    if not sections and phoff and phnum:
        if phentsize < (56 if is64 else 32):
            raise BinaryParseError("invalid ELF program header size")
        for index in range(min(phnum, 1024)):
            offset = phoff + index * phentsize
            if offset + (56 if is64 else 32) > len(data):
                break
            p_type = _u32(data, offset, endian)
            if is64:
                p_flags = _u32(data, offset + 4, endian)
                p_offset = _u64(data, offset + 8, endian)
                p_vaddr = _u64(data, offset + 16, endian)
                p_filesz = _u64(data, offset + 32, endian)
                p_memsz = _u64(data, offset + 40, endian)
            else:
                p_offset = _u32(data, offset + 4, endian)
                p_vaddr = _u32(data, offset + 8, endian)
                p_filesz = _u32(data, offset + 16, endian)
                p_memsz = _u32(data, offset + 20, endian)
                p_flags = _u32(data, offset + 24, endian)
            if p_type != 1:  # PT_LOAD
                continue
            if p_offset >= len(data):
                p_filesz = 0
            else:
                p_filesz = min(p_filesz, len(data) - p_offset)
            sections.append(Section(
                name=f"LOAD{index}",
                va=p_vaddr,
                vsize=max(p_memsz, p_filesz),
                file_offset=p_offset,
                file_size=p_filesz,
                executable=bool(p_flags & 1),
                writable=bool(p_flags & 2),
                readable=bool(p_flags & 4),
                alloc=True,
                section_type=1,
            ))
        if sections:
            warnings.append("section headers missing; using PT_LOAD segments")

    return BinaryImage(
        path=path,
        data=data,
        format="elf",
        bits=bits,
        machine=ELF_MACHINES.get(machine_id, f"machine_{machine_id}"),
        file_type=file_type,
        image_base=0,
        entry=entry,
        sections=sections,
        warnings=warnings,
    )


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def load_binary(path: str) -> BinaryImage:
    path = os.path.abspath(path)
    with open(path, "rb") as handle:
        data = handle.read()
    if not data:
        raise BinaryParseError("file is empty")
    digest = hashlib.sha256(data).hexdigest()
    if data.startswith(b"MZ"):
        image = _parse_pe(path, data)
    elif data.startswith(b"\x7fELF"):
        image = _parse_elf(path, data)
    else:
        raise BinaryParseError("not a native PE or ELF image")
    image.sha256 = digest
    return image


def _overlay_sections(image: BinaryImage) -> list[Section]:
    if not image.sections:
        return []
    end = max((section.file_offset + section.file_size for section in image.sections), default=0)
    if end >= len(image.data) or len(image.data) - end < 32:
        return []
    virtual_end = max((section.va + section.vsize for section in image.sections), default=image.image_base)
    return [Section(
        name="overlay",
        va=virtual_end,
        vsize=len(image.data) - end,
        file_offset=end,
        file_size=len(image.data) - end,
        executable=False,
        writable=True,
        readable=True,
        alloc=False,
        section_type=0,
    )]


def image_candidates(
    image: BinaryImage,
    *,
    min_length: int = 5,
    include_strings: bool = True,
    include_entropy: bool = True,
    include_code_strings: bool = False,
    max_entropy_blobs: int = 2048,
    entropy_threshold: float = 4.35,
) -> list[Candidate]:
    """Extract native strings and ciphertext-like blobs from an image."""
    sections = list(image.sections) + _overlay_sections(image)
    candidates: list[Candidate] = []
    seen: set[tuple[int, bytes]] = set()
    skip_names = {
        ".reloc", ".pdata", ".symtab", ".strtab", ".dynsym", ".dynstr",
        ".shstrtab", ".comment", ".gnu_debuglink", ".gnu_debugdata",
    }

    def add(candidate: Candidate) -> None:
        key = (candidate.ea, candidate.raw)
        if key in seen:
            return
        seen.add(key)
        candidate.file_offset = image.va_to_file_offset(candidate.ea)
        candidates.append(candidate)

    for section in sections:
        if section.file_size <= 0:
            continue
        lowered = section.name.lower()
        if lowered in skip_names or lowered.startswith((".debug", ".zdebug", ".gnu_debug", ".note")):
            continue
        raw = image.section_data(section)
        if not raw:
            continue
        if include_strings and (include_code_strings or not section.executable):
            for hit in bytescan.extract_strings(raw, base_ea=section.va, min_length=min_length):
                add(Candidate(
                    ea=hit.ea,
                    raw=hit.raw,
                    kind="string",
                    encoding=hit.encoding,
                    text=hit.text,
                    segment=section.name,
                    source="file",
                ))
        if include_entropy and not section.executable:
            blobs = bytescan.entropy_blobs(
                raw,
                base_ea=section.va,
                min_length=max(8, min_length),
                max_length=256,
                threshold=entropy_threshold,
                step=64,
                max_blobs=max_entropy_blobs,
            )
            for hit in blobs:
                add(Candidate(
                    ea=hit.ea,
                    raw=hit.raw,
                    kind="entropy",
                    encoding="raw",
                    text="",
                    segment=section.name,
                    source="file",
                ))
    return candidates


def summary_dict(image: BinaryImage) -> dict:
    return image.to_dict()
