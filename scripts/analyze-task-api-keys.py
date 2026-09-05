#!/usr/bin/env python3
"""Infer final-client NetworkTask -> ApiType key bindings from constructor code.

The pass uses exact enum/task-name matches only as *anchors* to discover recurring
native patterns (for example a common this-field store or base-constructor argument).
It then applies only conflict-free, multi-anchor patterns to the remaining task
constructors.  Output remains derived metadata: task names, constructor RVAs,
small integer keys, offsets/call targets and evidence counts.

No naming-only result is promoted to proven-static by this script.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_MOV,
    ARM64_INS_MOVK,
    ARM64_INS_MOVN,
    ARM64_INS_MOVZ,
    ARM64_INS_RET,
    ARM64_INS_STR,
    ARM64_INS_STUR,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_CTOR_SIZE = 0x1000
MAX_KEY = 515
MIN_STRONG_SUPPORT = 8
MAX_FEATURE_CONFLICTS = 0

_SUFFIXES = ("NetworkTask", "Task", "Api", "Request", "Response")


@dataclass(frozen=True)
class Method:
    address: int
    name: str

    @property
    def owner(self) -> str:
        return self.name.split("$$", 1)[0] if "$$" in self.name else ""

    @property
    def member(self) -> str:
        return self.name.split("$$", 1)[1] if "$$" in self.name else self.name


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            self.segments.append(
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_memsz"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                )
            )

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.segments:
            if vaddr <= address < vaddr + memsz:
                relative = address - vaddr
                if relative >= filesz:
                    return b""
                count = min(size, filesz - relative)
                self.stream.seek(offset + relative)
                return self.stream.read(count)
        return b""


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def normalize(value: str) -> str:
    value = value.rsplit(".", 1)[-1]
    changed = True
    while changed:
        changed = False
        for suffix in _SUFFIXES:
            if value.endswith(suffix):
                value = value[: -len(suffix)]
                changed = True
                break
    return re.sub(r"[^a-z0-9]", "", value.lower())


def canon_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] in {"w", "x"} and name[1:].isdigit():
        return "x" + name[1:]
    return name


def load_methods(path: Path) -> tuple[list[Method], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    starts: set[int] = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        name = str(item.get("Name", ""))
        methods.append(Method(address=address, name=name))
        starts.add(address)
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts)


def constructor_index(methods: list[Method]) -> dict[str, list[Method]]:
    result: dict[str, list[Method]] = defaultdict(list)
    for method in methods:
        if method.member not in {".ctor", "ctor"}:
            continue
        if method.owner:
            result[method.owner].append(method)
    for values in result.values():
        values.sort(key=lambda item: item.address)
    return result


def function_end(starts: list[int], address: int) -> int:
    index = bisect.bisect_right(starts, address)
    end = starts[index] if index < len(starts) else address + MAX_CTOR_SIZE
    return min(end, address + MAX_CTOR_SIZE)


def reg_name(md: Cs, operand: Any) -> str:
    return canon_reg(md.reg_name(int(operand.reg)))


def key_value(value: int | None) -> int | None:
    if value is None:
        return None
    return value if 0 <= value <= MAX_KEY else None


def scan_constructor(view: BinaryView, starts: list[int], method: Method) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, method.address)
    instructions = list(md.disasm(view.read(method.address, end - method.address), method.address))

    constants: dict[str, int] = {}
    this_aliases: set[str] = {"x0"}
    events: list[dict[str, Any]] = []

    def invalidate(reg: str) -> None:
        constants.pop(reg, None)
        if reg != "x0":
            this_aliases.discard(reg)

    for ins in instructions:
        ops = ins.operands
        mnem = ins.mnemonic.lower()
        if ins.id == ARM64_INS_RET:
            break

        # mov Xd, Xn / mov Wd, #imm
        if ins.id == ARM64_INS_MOV and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            dst = reg_name(md, ops[0])
            if ops[1].type == ARM64_OP_IMM:
                constants[dst] = int(ops[1].imm) & 0xFFFFFFFFFFFFFFFF
                this_aliases.discard(dst)
                continue
            if ops[1].type == ARM64_OP_REG:
                src = reg_name(md, ops[1])
                if src in constants:
                    constants[dst] = constants[src]
                else:
                    constants.pop(dst, None)
                if src in this_aliases:
                    this_aliases.add(dst)
                else:
                    this_aliases.discard(dst)
                continue
            invalidate(dst)
            continue

        if ins.id in {ARM64_INS_MOVZ, ARM64_INS_MOVN, ARM64_INS_MOVK} and len(ops) >= 2:
            if ops[0].type != ARM64_OP_REG or ops[1].type != ARM64_OP_IMM:
                continue
            dst = reg_name(md, ops[0])
            imm = int(ops[1].imm)
            shift = int(getattr(ops[1], "shift", None).value) if getattr(ops[1], "shift", None) else 0
            if ins.id == ARM64_INS_MOVZ:
                constants[dst] = imm << shift
            elif ins.id == ARM64_INS_MOVN:
                constants[dst] = (~(imm << shift)) & 0xFFFFFFFFFFFFFFFF
            else:
                old = constants.get(dst, 0)
                mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
                constants[dst] = (old & mask) | ((imm & 0xFFFF) << shift)
            this_aliases.discard(dst)
            continue

        # add Xd, Xn, #0 preserves aliases; other immediate adds preserve only
        # constants where useful.
        if ins.id == ARM64_INS_ADD and len(ops) >= 3 and ops[0].type == ARM64_OP_REG:
            dst = reg_name(md, ops[0])
            if ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                src = reg_name(md, ops[1])
                imm = int(ops[2].imm)
                if src in constants:
                    constants[dst] = constants[src] + imm
                else:
                    constants.pop(dst, None)
                if src in this_aliases and imm == 0:
                    this_aliases.add(dst)
                else:
                    this_aliases.discard(dst)
                continue
            invalidate(dst)
            continue

        if ins.id in {ARM64_INS_STR, ARM64_INS_STUR} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
                src = reg_name(md, ops[0])
                base = canon_reg(md.reg_name(int(ops[1].mem.base)))
                value = key_value(constants.get(src))
                if base in this_aliases and value is not None:
                    events.append(
                        {
                            "kind": "store_this",
                            "feature": f"store_this:+0x{int(ops[1].mem.disp):x}",
                            "value": value,
                            "rva": int(ins.address),
                            "source_reg": src,
                        }
                    )
            continue

        if ins.id == ARM64_INS_BL and ops and ops[0].type == ARM64_OP_IMM:
            target = int(ops[0].imm)
            for arg_index in range(1, 8):
                reg = f"x{arg_index}"
                value = key_value(constants.get(reg))
                if value is None:
                    continue
                events.append(
                    {
                        "kind": "call_arg",
                        "feature": f"call:0x{target:x}:x{arg_index}",
                        "value": value,
                        "rva": int(ins.address),
                        "target": target,
                        "arg_reg": reg,
                    }
                )
            # A normal BL clobbers caller-saved registers. Keep x18+ state,
            # including typical this aliases such as x19/x20.
            for index in range(0, 18):
                reg = f"x{index}"
                constants.pop(reg, None)
                if index != 0:
                    this_aliases.discard(reg)
            continue

        if ins.id == ARM64_INS_BLR:
            for index in range(0, 18):
                reg = f"x{index}"
                constants.pop(reg, None)
                if index != 0:
                    this_aliases.discard(reg)
            continue

        # Conservative invalidation for common register-writing instructions.
        if ops and ops[0].type == ARM64_OP_REG and mnem not in {
            "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"
        } and not mnem.startswith("b."):
            invalidate(reg_name(md, ops[0]))

    # Deduplicate exact observations while retaining the earliest site.
    unique: dict[tuple[str, int], dict[str, Any]] = {}
    for event in events:
        key = (event["feature"], event["value"])
        unique.setdefault(key, event)
    return sorted(unique.values(), key=lambda item: (item["feature"], item["value"], item["rva"]))


def enum_entries(report: dict[str, Any], group: str) -> list[dict[str, Any]]:
    key = "a_candidates" if group == "A" else "b_candidates"
    candidates = report.get(key, [])
    if len(candidates) != 1:
        raise RuntimeError(f"expected one {group} enum candidate")
    result = []
    for name, value in candidates[0]["entries"]:
        result.append({"name": str(name), "key": int(value), "group": group})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--api-type-enums", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    enum_report = json.loads(args.api_type_enums.read_text(encoding="utf-8"))
    methods, starts = load_methods(args.script_json)
    ctors = constructor_index(methods)
    tasks = [str(item["type"]) for item in inventory.get("tasks", [])]
    if not tasks:
        raise RuntimeError("empty NetworkTask inventory")

    a_entries = enum_entries(enum_report, "A")
    enum_by_norm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in a_entries:
        enum_by_norm[normalize(entry["name"])].append(entry)

    view = BinaryView(args.lib)
    try:
        task_records: list[dict[str, Any]] = []
        for task in tasks:
            task_ctors = ctors.get(task, [])
            if not task_ctors:
                # Some ScriptMethod owner names can be unqualified. Only fall
                # back when the short owner is unique among constructors.
                short = task.rsplit(".", 1)[-1]
                candidates = ctors.get(short, [])
                if candidates:
                    task_ctors = candidates
            ctor_records = [
                {
                    "rva": ctor.address,
                    "name": ctor.name,
                    "events": scan_constructor(view, starts, ctor),
                }
                for ctor in task_ctors
            ]
            anchors = enum_by_norm.get(normalize(task), [])
            anchor = anchors[0] if len(anchors) == 1 else None
            task_records.append(
                {
                    "task": task,
                    "anchor": anchor,
                    "constructors": ctor_records,
                }
            )
    finally:
        view.close()

    # Measure each structural feature against exact-name A-group anchors.
    feature_stats: dict[str, dict[str, Any]] = {}
    for record in task_records:
        anchor = record["anchor"]
        if anchor is None:
            continue
        expected = int(anchor["key"])
        seen_features: dict[str, set[int]] = defaultdict(set)
        for ctor in record["constructors"]:
            for event in ctor["events"]:
                seen_features[event["feature"]].add(int(event["value"]))
        for feature, values in seen_features.items():
            stat = feature_stats.setdefault(
                feature,
                {"feature": feature, "matches": 0, "conflicts": 0, "anchor_observations": 0, "examples": []},
            )
            stat["anchor_observations"] += 1
            if expected in values and len(values) == 1:
                stat["matches"] += 1
                if len(stat["examples"]) < 8:
                    stat["examples"].append({"task": record["task"], "key": expected})
            else:
                stat["conflicts"] += 1

    strong = {
        feature
        for feature, stat in feature_stats.items()
        if stat["matches"] >= MIN_STRONG_SUPPORT and stat["conflicts"] <= MAX_FEATURE_CONFLICTS
    }

    inferred_count = 0
    conflict_count = 0
    for record in task_records:
        inferred_values: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for ctor in record["constructors"]:
            for event in ctor["events"]:
                if event["feature"] in strong:
                    inferred_values[int(event["value"])].append(event)
        if len(inferred_values) == 1:
            value = next(iter(inferred_values))
            record["inferred"] = {
                "status": "proven-static-pattern",
                "group": "A",
                "key": value,
                "evidence": inferred_values[value],
            }
            inferred_count += 1
        elif len(inferred_values) > 1:
            record["inferred"] = {
                "status": "conflict",
                "values": sorted(inferred_values),
            }
            conflict_count += 1
        else:
            record["inferred"] = {"status": "unresolved"}

    stats_sorted = sorted(
        feature_stats.values(),
        key=lambda item: (-item["matches"], item["conflicts"], item["feature"]),
    )
    report = {
        "schema": SCHEMA,
        "scope": "A-group NetworkTask constructor ApiType-key structural inference",
        "anchor_count": sum(record["anchor"] is not None for record in task_records),
        "task_count": len(task_records),
        "strong_features": [item for item in stats_sorted if item["feature"] in strong],
        "feature_stats": stats_sorted[:128],
        "proven_static_pattern_count": inferred_count,
        "conflict_count": conflict_count,
        "unresolved_count": len(task_records) - inferred_count - conflict_count,
        "tasks": task_records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
