#!/usr/bin/env python3
"""Resolve IL2CPP runtime string-literal references from AArch64 disassembly.

Unity 2022 / IL2CPP metadata v31 stores runtime metadata usages behind relocated
pointer slots.  This helper combines ``global-metadata.dat``, the matching ELF,
and a text disassembly (for example from ``llvm-objdump -d``) to turn the
``ADRP + LDR`` pointer loads back into managed string literals.

It is intentionally narrow: the current implementation targets the final CGSS
11.6.3 arm64 specimen and other Unity 2022 metadata-v31 binaries with the same
metadata-usage encoding.  It does not dump code or proprietary resources.
"""
from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path
from typing import Iterable

MAGIC = 0xFAB11BAF
METADATA_VERSION = 31
R_AARCH64_RELATIVE = 1027
SHT_RELA = 4
PT_LOAD = 1
STRING_LITERAL_USAGE_KIND = 5

HEADER_PAIRS = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]

ADRP_RE = re.compile(r"^\s*([0-9a-fA-F]+):.*\badrp\s+x(\d+),\s*0x([0-9a-fA-F]+)")
LDR_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):.*\bldr\s+x(\d+),\s*\[x(\d+),\s*#(0x[0-9a-fA-F]+|\d+)\]"
)


def decode_metadata_usage(encoded: int, literals: list[str]) -> str | None:
    """Decode a Unity metadata-usage pointer object into a string literal."""
    kind = encoded >> 29
    index = (encoded & 0x1FFFFFFF) >> 1
    if kind != STRING_LITERAL_USAGE_KIND or not (0 <= index < len(literals)):
        return None
    return literals[index]


def parse_string_literals(metadata: bytes) -> list[str]:
    if len(metadata) < 256:
        raise ValueError("metadata file is too small")
    values = struct.unpack_from("<64I", metadata, 0)
    if values[0] != MAGIC:
        raise ValueError(f"bad metadata magic: 0x{values[0]:08x}")
    if values[1] != METADATA_VERSION:
        raise ValueError(f"unsupported metadata version {values[1]}; expected 31")

    header = {
        name: (values[2 + index * 2], values[3 + index * 2])
        for index, name in enumerate(HEADER_PAIRS)
    }
    literal_offset, literal_size = header["stringLiteral"]
    data_offset, data_size = header["stringLiteralData"]
    literals: list[str] = []
    for index in range(literal_size // 8):
        length, relative = struct.unpack_from("<II", metadata, literal_offset + index * 8)
        if relative + length > data_size:
            raise ValueError("string literal points outside stringLiteralData")
        raw = metadata[data_offset + relative : data_offset + relative + length]
        literals.append(raw.decode("utf-8", "replace"))
    return literals


class Elf64Image:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("expected a little-endian ELF64 image")

        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]
        self.load_segments: list[tuple[int, int, int]] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            p_type = struct.unpack_from("<I", data, offset)[0]
            if p_type != PT_LOAD:
                continue
            p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", data, offset + 8)
            self.load_segments.append((p_vaddr, p_vaddr + p_filesz, p_offset))

        self.relative_relocations: dict[int, int] = {}
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shentsize = struct.unpack_from("<H", data, 58)[0]
        shnum = struct.unpack_from("<H", data, 60)[0]
        for index in range(shnum):
            offset = shoff + index * shentsize
            sh_type = struct.unpack_from("<I", data, offset + 4)[0]
            if sh_type != SHT_RELA:
                continue
            sh_offset, sh_size = struct.unpack_from("<QQ", data, offset + 24)
            sh_entsize = struct.unpack_from("<Q", data, offset + 56)[0]
            if sh_entsize < 24:
                continue
            for pos in range(sh_offset, sh_offset + sh_size, sh_entsize):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, pos)
                if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
                    self.relative_relocations[r_offset] = r_addend

    def virtual_to_file_offset(self, address: int) -> int | None:
        for start, end, file_offset in self.load_segments:
            if start <= address < end:
                return file_offset + address - start
        return None

    def relocated_u64(self, slot_address: int) -> int | None:
        target = self.relative_relocations.get(slot_address)
        if target is None:
            return None
        offset = self.virtual_to_file_offset(target)
        if offset is None or offset + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, offset)[0]


def collect_pointer_slots(lines: Iterable[str]) -> list[tuple[int, int]]:
    """Collect ``(instruction_address, pointer_slot_address)`` pairs."""
    pages: dict[int, int] = {}
    results: list[tuple[int, int]] = []
    for line in lines:
        match = ADRP_RE.search(line)
        if match:
            pages[int(match.group(2))] = int(match.group(3), 16)
            continue
        match = LDR_RE.search(line)
        if not match:
            continue
        instruction = int(match.group(1), 16)
        destination = int(match.group(2))
        base = int(match.group(3))
        immediate = int(match.group(4), 0)
        page = pages.get(base)
        if page is not None:
            results.append((instruction, page + immediate))
        # LDR overwrites its destination after the address calculation.
        pages.pop(destination, None)
    return results


def extract_refs(metadata_path: Path, elf_path: Path, disassembly_path: Path) -> list[dict[str, object]]:
    literals = parse_string_literals(metadata_path.read_bytes())
    image = Elf64Image(elf_path.read_bytes())
    refs: list[dict[str, object]] = []
    lines = disassembly_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for instruction, slot in collect_pointer_slots(lines):
        encoded = image.relocated_u64(slot)
        if encoded is None:
            continue
        literal = decode_metadata_usage(encoded, literals)
        if literal is None:
            continue
        refs.append({"instruction": instruction, "slot": slot, "literal": literal})
    return refs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("elf", type=Path)
    parser.add_argument("disassembly", type=Path)
    parser.add_argument("--unique", action="store_true", help="print each literal once, preserving first-use order")
    args = parser.parse_args()

    refs = extract_refs(args.metadata, args.elf, args.disassembly)
    seen: set[str] = set()
    for ref in refs:
        literal = str(ref["literal"])
        if args.unique and literal in seen:
            continue
        seen.add(literal)
        print(f"0x{int(ref['instruction']):x}\t0x{int(ref['slot']):x}\t{literal}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
