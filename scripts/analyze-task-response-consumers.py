#!/usr/bin/env python3
"""C18b: trace C17 parser values into task fields and direct consumers.

This is a structural final-client pass. It deliberately distinguishes two
cardinalities that must not be collapsed:

* route-field relations: one C17 response-field relation per endpoint/route;
* native parser-field origins: a shared parser can back multiple routes.

For each unique native origin the pass follows exact C3 JsonData access results
through optional conversions, records direct stores into known task instance
fields from Il2CppDumper ``dump.cs``, finds task-owned methods that directly read
those offsets, then finds exact ARM64 BL/B-tail callers of those readers.

Nested JsonData accesses are handled conservatively: a conversion call preserves
the provenance currently carried in x0 instead of unioning every C3 row that
happens to share the same conversion RVA. This prevents a parent ``data`` access
from being mislabelled as the scalar value of a nested child access.

No response value, empty-container safety, or untouched-client acceptance is
inferred by this pass.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_MOV, ARM64_INS_ORR, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SCHEMA = 2
MAX_FUNCTION_SIZE = 0x20000
DUMPER_NAMESPACE_RE = re.compile(r"^//\s*Namespace:\s*(.*?)\s*$")
TYPE_RE = re.compile(
    r"^(?:(?:public|private|protected|internal|abstract|sealed|static|partial|new)\s+)*"
    r"(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*(?:`\d+)?)"
)
FIELD_RE = re.compile(
    r"^(?:(?:public|private|protected|internal|readonly|volatile|static|const|new)\s+)+"
    r"(.+?)\s+([^\s;]+)\s*;\s*//\s*0x([0-9A-Fa-f]+)\s*$"
)

Origin = tuple[str, str, str]


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


@dataclass(frozen=True)
class FieldLayout:
    owner: str
    name: str
    type_name: str
    offset: int


class ConsumerAnalysisError(ValueError):
    pass


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads: list[tuple[int, int, int, int]] = []
        self.execs: list[tuple[int, int, int]] = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            row = (
                int(seg["p_vaddr"]), int(seg["p_memsz"]),
                int(seg["p_offset"]), int(seg["p_filesz"]),
            )
            self.loads.append(row)
            if int(seg["p_flags"]) & 1 and row[3]:
                self.execs.append((row[0], row[2], row[3]))

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                self.stream.seek(offset + rel)
                return self.stream.read(min(size, filesz - rel))
        return b""

    def direct_branches_to(self, targets: set[int]) -> list[tuple[int, int, str]]:
        if not targets:
            return []
        out: list[tuple[int, int, str]] = []
        for vaddr, offset, filesz in self.execs:
            self.stream.seek(offset)
            data = self.stream.read(filesz)
            limit = len(data) - len(data) % 4
            for pos in range(0, limit, 4):
                word = struct.unpack_from("<I", data, pos)[0]
                top = word & 0xFC000000
                if top not in {0x94000000, 0x14000000}:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                pc = vaddr + pos
                target = pc + (imm26 << 2)
                if target in targets:
                    out.append((pc, target, "BL" if top == 0x94000000 else "B-tail"))
        return out


def norm_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def _strip_type_comment(line: str) -> str:
    return line.split("//", 1)[0].strip() if "//" in line else line.strip()


def parse_dump_fields(path: Path, wanted_types: set[str]) -> dict[str, dict[int, FieldLayout]]:
    namespace = ""
    current_type: str | None = None
    in_fields = False
    result: dict[str, dict[int, FieldLayout]] = defaultdict(dict)
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        line = raw.strip()
        ns = DUMPER_NAMESPACE_RE.match(line)
        if ns:
            namespace = ns.group(1).strip()
            current_type = None
            in_fields = False
            continue
        decl = _strip_type_comment(line).rstrip("{").strip()
        match = TYPE_RE.match(decl)
        if match:
            short = match.group(1)
            current_type = f"{namespace}.{short}" if namespace else short
            in_fields = False
            continue
        if line == "// Fields":
            in_fields = current_type in wanted_types
            continue
        if line.startswith("// ") and line != "// Fields":
            in_fields = False
        if not in_fields or current_type is None:
            continue
        match = FIELD_RE.match(line)
        if not match:
            continue
        type_name, field_name, raw_offset = match.groups()
        if " static " in f" {line.lower()} ":
            continue
        offset = int(raw_offset, 16)
        if offset < 0x10:
            continue
        result[current_type][offset] = FieldLayout(
            owner=current_type,
            name=field_name,
            type_name=type_name.strip(),
            offset=offset,
        )
    return dict(result)


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ConsumerAnalysisError(f"invalid RVA: {value!r}")


def load_script(path: Path) -> tuple[dict[int, list[Method]], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts: set[int] = set()
    for row in raw.get("ScriptMethod", []):
        rva = _as_int(row.get("Address", 0))
        if rva <= 0:
            continue
        sig = row.get("Signature")
        by_rva[rva].append(Method(rva, str(row.get("Name") or ""), str(sig) if sig else None))
        starts.add(rva)
    for value in raw.get("Addresses", []):
        rva = _as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in by_rva.values():
        rows.sort(key=lambda row: row.name)
    return dict(by_rva), sorted(starts)


def function_end(starts: list[int], rva: int) -> int:
    index = bisect.bisect_right(starts, rva)
    end = starts[index] if index < len(starts) else rva + MAX_FUNCTION_SIZE
    return min(end, rva + MAX_FUNCTION_SIZE)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConsumerAnalysisError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ConsumerAnalysisError(f"{label} must contain schema=1")
    return value


def _target_fields(c17: dict[str, Any]) -> dict[Origin, list[dict[str, Any]]]:
    result: dict[Origin, list[dict[str, Any]]] = defaultdict(list)
    for route in c17.get("routes", []):
        if not isinstance(route, dict):
            continue
        for field in route.get("fields", []):
            if not isinstance(field, dict):
                continue
            task, method, name = field.get("task"), field.get("method"), field.get("field")
            if not all(isinstance(value, str) for value in (task, method, name)):
                continue
            result[(task, method, name)].append({
                "route": route.get("route"),
                "endpoint_id": route.get("endpoint_id"),
                "route_class": route.get("route_class"),
                "refined_shape": field.get("refined_shape"),
                "requiredness": field.get("requiredness"),
            })
    for rows in result.values():
        rows.sort(key=lambda row: (str(row.get("route")), int(row.get("endpoint_id") or -1)))
    return dict(result)


def _c3_targets(c3: dict[str, Any], wanted: set[Origin]) -> dict[int, list[dict[str, Any]]]:
    by_method: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in c3.get("accesses", []):
        if not isinstance(row, dict):
            continue
        key = (row.get("task"), row.get("method"), row.get("field"))
        if key not in wanted:
            continue
        method_rva, access_rva = row.get("method_rva"), row.get("access_rva")
        if isinstance(method_rva, int) and isinstance(access_rva, int):
            by_method[method_rva].append(row)
    return dict(by_method)


def _propagate_alias(ins: Any, md: Cs, regs: set[str]) -> set[str]:
    out = set(regs)
    if ins.id in {ARM64_INS_MOV, ARM64_INS_ORR} and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            src = norm_reg(md.reg_name(ins.operands[1].reg))
            if src in out:
                out.add(dst)
            else:
                out.discard(dst)
            return out
    if ins.mnemonic.lower() == "add" and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            src = norm_reg(md.reg_name(ins.operands[1].reg))
            if src in out:
                out.add(dst)
            else:
                out.discard(dst)
            return out
    try:
        _reads, writes = ins.regs_access()
    except Exception:
        writes = []
    for reg_id in writes:
        reg = norm_reg(md.reg_name(reg_id))
        if reg:
            out.discard(reg)
    return out


def trace_parser_stores(
    view: BinaryView,
    by_rva: dict[int, list[Method]],
    starts: list[int],
    c3_by_method: dict[int, list[dict[str, Any]]],
    layouts: dict[str, dict[int, FieldLayout]],
) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    stores: list[dict[str, Any]] = []
    caller_saved = {f"x{i}" for i in range(18)}

    for method_rva, rows in sorted(c3_by_method.items()):
        identities = by_rva.get(method_rva, [])
        owner = identities[0].name.split("$$", 1)[0] if identities and "$$" in identities[0].name else None
        if owner is None or owner not in layouts:
            continue
        end = function_end(starts, method_rva)
        insns = list(md.disasm(view.read(method_rva, end - method_rva), method_rva))
        access_events: dict[int, set[Origin]] = defaultdict(set)
        conversion_rvas: set[int] = set()
        for row in rows:
            origin = (str(row["task"]), str(row["method"]), str(row["field"]))
            access_events[int(row["access_rva"])].add(origin)
            if isinstance(row.get("conversion_rva"), int):
                conversion_rvas.add(int(row["conversion_rva"]))

        this_regs = {"x0"}
        value_regs: dict[str, set[Origin]] = {}
        for ins in insns:
            address = int(ins.address)
            if ins.id == ARM64_INS_BL:
                if address in access_events:
                    origins = set(access_events[address])
                    this_regs -= caller_saved
                    value_regs = {reg: origins0 for reg, origins0 in value_regs.items() if reg not in caller_saved}
                    value_regs["x0"] = origins
                elif address in conversion_rvas:
                    origins = set(value_regs.get("x0", set()))
                    this_regs -= caller_saved
                    value_regs = {reg: origins0 for reg, origins0 in value_regs.items() if reg not in caller_saved}
                    if origins:
                        value_regs["x0"] = origins
                    else:
                        value_regs.pop("x0", None)
                else:
                    this_regs -= caller_saved
                    value_regs = {reg: origins0 for reg, origins0 in value_regs.items() if reg not in caller_saved}
                continue

            if ins.mnemonic.lower().startswith(("str", "stur")) and len(ins.operands) >= 2:
                if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_MEM:
                    src = norm_reg(md.reg_name(ins.operands[0].reg))
                    base = norm_reg(md.reg_name(ins.operands[1].mem.base))
                    offset = int(ins.operands[1].mem.disp)
                    if base in this_regs and src in value_regs and offset in layouts[owner]:
                        layout = layouts[owner][offset]
                        for origin in sorted(value_regs[src]):
                            stores.append({
                                "task": origin[0],
                                "parser_method": origin[1],
                                "response_field": origin[2],
                                "parser_rva": method_rva,
                                "store_rva": address,
                                "task_field": layout.name,
                                "task_field_type": layout.type_name,
                                "task_field_offset": offset,
                            })

            before_this = set(this_regs)
            this_regs = _propagate_alias(ins, md, this_regs)
            if ins.id in {ARM64_INS_MOV, ARM64_INS_ORR} and len(ins.operands) >= 2:
                if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
                    dst = norm_reg(md.reg_name(ins.operands[0].reg))
                    src = norm_reg(md.reg_name(ins.operands[1].reg))
                    if src in value_regs:
                        value_regs[dst] = set(value_regs[src])
                    else:
                        value_regs.pop(dst, None)
                    continue
            if ins.mnemonic.lower() == "add" and len(ins.operands) >= 2:
                if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
                    dst = norm_reg(md.reg_name(ins.operands[0].reg))
                    src = norm_reg(md.reg_name(ins.operands[1].reg))
                    if src in value_regs:
                        value_regs[dst] = set(value_regs[src])
                    else:
                        value_regs.pop(dst, None)
                    continue
            try:
                _reads, writes = ins.regs_access()
            except Exception:
                writes = []
            for reg_id in writes:
                reg = norm_reg(md.reg_name(reg_id))
                if reg and reg not in before_this:
                    value_regs.pop(reg, None)

    unique = {
        (row["task"], row["parser_method"], row["response_field"], row["store_rva"], row["task_field_offset"]): row
        for row in stores
    }
    return sorted(unique.values(), key=lambda row: (row["task"], row["response_field"], row["store_rva"]))


def find_task_readers(
    view: BinaryView,
    by_rva: dict[int, list[Method]],
    starts: list[int],
    stores: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    wanted: dict[str, set[int]] = defaultdict(set)
    for row in stores:
        wanted[str(row["task"])].add(int(row["task_field_offset"]))
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    readers: list[dict[str, Any]] = []
    for rva, identities in sorted(by_rva.items()):
        names = [row.name for row in identities if "$$" in row.name]
        owners = {name.split("$$", 1)[0] for name in names}
        candidate_owners = owners & set(wanted)
        if not candidate_owners:
            continue
        end = function_end(starts, rva)
        insns = list(md.disasm(view.read(rva, end - rva), rva))
        this_regs = {"x0"}
        for ins in insns:
            if ins.id == ARM64_INS_BL:
                this_regs -= {f"x{i}" for i in range(18)}
                continue
            if ins.mnemonic.lower().startswith(("ldr", "ldur")) and len(ins.operands) >= 2:
                if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_MEM:
                    base = norm_reg(md.reg_name(ins.operands[1].mem.base))
                    offset = int(ins.operands[1].mem.disp)
                    if base in this_regs:
                        for owner in sorted(candidate_owners):
                            if offset in wanted[owner]:
                                readers.append({
                                    "task": owner,
                                    "task_field_offset": offset,
                                    "reader_rva": rva,
                                    "reader_methods": sorted(name for name in names if name.startswith(owner + "$$")),
                                    "load_rva": int(ins.address),
                                })
            this_regs = _propagate_alias(ins, md, this_regs)
    unique = {
        (row["task"], row["task_field_offset"], row["reader_rva"], row["load_rva"]): row
        for row in readers
    }
    return sorted(unique.values(), key=lambda row: (row["task"], row["task_field_offset"], row["reader_rva"]))


def map_reader_callers(
    view: BinaryView,
    by_rva: dict[int, list[Method]],
    starts: list[int],
    readers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    target_to_readers: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in readers:
        target_to_readers[int(row["reader_rva"])].append(row)
    out = []
    for site, target, kind in view.direct_branches_to(set(target_to_readers)):
        index = bisect.bisect_right(starts, site) - 1
        if index < 0:
            continue
        caller_rva = starts[index]
        caller_methods = by_rva.get(caller_rva, [])
        if not caller_methods:
            continue
        for reader in target_to_readers[target]:
            out.append({
                "task": reader["task"],
                "task_field_offset": reader["task_field_offset"],
                "reader_rva": target,
                "reader_methods": reader["reader_methods"],
                "call_kind": kind,
                "callsite_rva": site,
                "caller_rva": caller_rva,
                "caller_methods": sorted(method.name for method in caller_methods if method.name),
            })
    unique = {
        (row["task"], row["task_field_offset"], row["reader_rva"], row["callsite_rva"], row["caller_rva"]): row
        for row in out
    }
    return sorted(unique.values(), key=lambda row: (row["task"], row["task_field_offset"], row["caller_rva"], row["callsite_rva"]))


def build_report(
    c17: dict[str, Any],
    stores: list[dict[str, Any]],
    readers: list[dict[str, Any]],
    callers: list[dict[str, Any]],
) -> dict[str, Any]:
    targets = _target_fields(c17)
    store_by_origin: dict[Origin, list[dict[str, Any]]] = defaultdict(list)
    for row in stores:
        store_by_origin[(row["task"], row["parser_method"], row["response_field"])].append(row)
    reader_by_offset: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in readers:
        reader_by_offset[(row["task"], row["task_field_offset"])].append(row)
    caller_by_reader: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in callers:
        caller_by_reader[(row["task"], row["task_field_offset"], row["reader_rva"])].append(row)

    fields = []
    relation_counts = Counter()
    for origin, metas in sorted(targets.items()):
        origin_stores = store_by_origin.get(origin, [])
        field_readers: list[dict[str, Any]] = []
        direct_callers: list[dict[str, Any]] = []
        for store in origin_stores:
            for reader in reader_by_offset.get((store["task"], store["task_field_offset"]), []):
                field_readers.append(reader)
                direct_callers.extend(
                    caller_by_reader.get((reader["task"], reader["task_field_offset"], reader["reader_rva"]), [])
                )
        if not origin_stores:
            relation = "no-direct-task-field-store"
        elif not field_readers:
            relation = "stored-no-task-owned-reader"
        elif not direct_callers:
            relation = "stored-reader-no-direct-caller"
        else:
            relation = "stored-reader-direct-caller"
        for meta in metas:
            relation_counts[relation] += 1
            fields.append({
                "route": meta["route"],
                "endpoint_id": meta["endpoint_id"],
                "route_class": meta["route_class"],
                "task": origin[0],
                "parser_method": origin[1],
                "response_field": origin[2],
                "refined_shape": meta["refined_shape"],
                "requiredness": meta["requiredness"],
                "relation_class": relation,
                "task_field_stores": origin_stores,
                "task_owned_readers": field_readers,
                "direct_reader_callers": direct_callers,
                "empty_value_promotion": "not-proven-by-c18b",
            })

    return {
        "schema": SCHEMA,
        "scope": (
            "C18b exact final-client parser-result task-field stores, task-owned readers and direct BL/B callers; "
            "route-field relations remain distinct from shared native parser-field origins; no response values inferred"
        ),
        "source_c17_shape_only_route_count": c17.get("shape_only_route_count"),
        "target_route_field_relation_count": len(fields),
        "unique_native_parser_field_origin_count": len(targets),
        "direct_task_field_store_count": len(stores),
        "task_owned_reader_count": len(readers),
        "direct_reader_caller_count": len(callers),
        "relation_class_counts": dict(sorted(relation_counts.items())),
        "fields": sorted(fields, key=lambda row: (str(row["route"]), str(row["response_field"]), str(row["task"]))),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c17", type=Path, required=True)
    parser.add_argument("--c3", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        c17 = _load_json(args.c17, "C17 report")
        c3 = _load_json(args.c3, "C3 report")
        targets = _target_fields(c17)
        layouts = parse_dump_fields(args.dump_cs, {key[0] for key in targets})
        by_rva, starts = load_script(args.script_json)
        c3_by_method = _c3_targets(c3, set(targets))
        view = BinaryView(args.lib)
        try:
            stores = trace_parser_stores(view, by_rva, starts, c3_by_method, layouts)
            readers = find_task_readers(view, by_rva, starts, stores)
            callers = map_reader_callers(view, by_rva, starts, readers)
        finally:
            view.close()
        report = build_report(c17, stores, readers, callers)
    except (OSError, json.JSONDecodeError, ConsumerAnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_field_relation_count": report["target_route_field_relation_count"],
        "unique_native_parser_field_origin_count": report["unique_native_parser_field_origin_count"],
        "direct_task_field_store_count": report["direct_task_field_store_count"],
        "task_owned_reader_count": report["task_owned_reader_count"],
        "direct_reader_caller_count": report["direct_reader_caller_count"],
        "relation_class_counts": report["relation_class_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
