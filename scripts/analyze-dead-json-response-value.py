#!/usr/bin/env python3
"""C27: prove whether one parsed JsonData response value is semantically dead.

The remaining C25 opaque route ``/stream/telescope_view/send_action`` has an exact
C3 ``JsonData.get_Item(\"data\")`` access but C20 found no direct or indirect call
consumer.  Absence of call consumers alone is not enough: the returned JsonData
object could still be compared, dereferenced, stored, returned, or used through a
branch predicate.

This pass performs a conservative ARM64 instruction-CFG taint analysis starting
immediately after the exact top-level ``data`` access.  The returned object is
tracked through register copies and stack spills/reloads.  Any non-transparent
read, non-stack store, call argument, return value, indirect branch escape, or
unknown control-flow escape is a semantic sink.  A ``dead-value`` conclusion is
emitted only when all reachable post-access paths terminate at known exits and no
sink is observed.

Output contains only sanitized derived metadata; no disassembly/native bytes or
response values are emitted.  Even a parser-local dead-value proof is still not
untouched-client/device acceptance.
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_MOV,
    ARM64_INS_ORR,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x20000
TARGET_ROUTE = "/stream/telescope_view/send_action"
TARGET_ENDPOINT_ID = 414
TARGET_TASK = "Stage.TeleScopeSendActionTask"
TARGET_METHOD = "Stage.TeleScopeSendActionTask$$Parse"


@dataclass(frozen=True)
class State:
    regs: frozenset[str]
    stack: frozenset[int]

    def union(self, other: "State") -> "State":
        return State(self.regs | other.regs, self.stack | other.stack)


class AnalysisError(ValueError):
    pass


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads: list[tuple[int, int, int, int]] = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.loads.append((
                    int(seg["p_vaddr"]), int(seg["p_memsz"]),
                    int(seg["p_offset"]), int(seg["p_filesz"]),
                ))

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


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise AnalysisError(f"invalid RVA {value!r}")


def norm_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def load_method_starts(path: Path) -> tuple[list[int], set[int]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    managed: set[int] = set()
    for row in doc.get("ScriptMethod", []):
        rva = as_int(row.get("Address", 0))
        if rva > 0:
            starts.add(rva)
            managed.add(rva)
    for value in doc.get("Addresses", []):
        rva = as_int(value)
        if rva > 0:
            starts.add(rva)
    return sorted(starts), managed


def function_end(starts: list[int], start: int) -> int:
    i = bisect.bisect_right(starts, start)
    end = starts[i] if i < len(starts) else start + MAX_FUNCTION_SIZE
    return min(end, start + MAX_FUNCTION_SIZE)


def branch_target(ins: Any) -> int | None:
    if not ins.operands or ins.operands[-1].type != ARM64_OP_IMM:
        return None
    return int(ins.operands[-1].imm)


def is_conditional_branch(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}


def is_ret(mnemonic: str) -> bool:
    return mnemonic.lower() in {"ret", "retaa", "retab", "eret"}


def load_target(c20_path: Path) -> dict[str, Any]:
    doc = json.loads(c20_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("target_route_count") != 15:
        raise AnalysisError("unexpected C20 report")
    rows = [row for row in doc.get("routes", []) if isinstance(row, dict) and row.get("route") == TARGET_ROUTE]
    if len(rows) != 1:
        raise AnalysisError(f"expected one C20 target route, got {len(rows)}")
    row = rows[0]
    if row.get("endpoint_id") != TARGET_ENDPOINT_ID:
        raise AnalysisError("target endpoint id mismatch")
    if row.get("task") != TARGET_TASK or row.get("method") != TARGET_METHOD:
        raise AnalysisError("target parser identity mismatch")
    if row.get("consumer_resolution") != "no-consumer-recovered":
        raise AnalysisError("C20 target no longer has no-consumer-recovered status")
    if not isinstance(row.get("method_rva"), int) or not isinstance(row.get("data_access_rva"), int):
        raise AnalysisError("target parser/access RVA missing")
    return row


def _reg_operands(ins: Any, md: Cs) -> list[str]:
    out: list[str] = []
    for op in ins.operands:
        if op.type == ARM64_OP_REG:
            out.append(norm_reg(md.reg_name(op.reg)))
        elif op.type == ARM64_OP_MEM:
            if op.mem.base:
                out.append(norm_reg(md.reg_name(op.mem.base)))
            if op.mem.index:
                out.append(norm_reg(md.reg_name(op.mem.index)))
    return [reg for reg in out if reg]


def _written_regs(ins: Any, md: Cs) -> set[str]:
    try:
        _reads, writes = ins.regs_access()
    except Exception:
        return set()
    return {norm_reg(md.reg_name(reg)) for reg in writes if md.reg_name(reg)}


def _read_regs(ins: Any, md: Cs) -> set[str]:
    try:
        reads, _writes = ins.regs_access()
    except Exception:
        return set(_reg_operands(ins, md))
    return {norm_reg(md.reg_name(reg)) for reg in reads if md.reg_name(reg)}


def _is_stack_base(reg: str) -> bool:
    return reg in {"sp", "x29"}


def transfer(ins: Any, md: Cs, state: State, managed_starts: set[int]) -> tuple[State, list[dict[str, Any]], str | None]:
    regs = set(state.regs)
    stack = set(state.stack)
    sinks: list[dict[str, Any]] = []
    terminal: str | None = None
    mnemonic = ins.mnemonic.lower()
    addr = int(ins.address)

    # Direct/indirect calls: only architectural argument registers are semantic input.
    if ins.id in {ARM64_INS_BL, ARM64_INS_BLR}:
        args = sorted(int(reg[1:]) for reg in regs if reg.startswith("x") and reg[1:].isdigit() and int(reg[1:]) <= 7)
        if args:
            sinks.append({
                "kind": "call-argument",
                "rva": addr,
                "call_kind": "direct" if ins.id == ARM64_INS_BL else "indirect",
                "argument_positions": args,
                "target_rva": branch_target(ins) if ins.id == ARM64_INS_BL else None,
            })
        for i in range(18):
            regs.discard(f"x{i}")
        return State(frozenset(regs), frozenset(stack)), sinks, terminal

    # RET only escapes the JsonData value when it remains in x0.
    if is_ret(mnemonic):
        if "x0" in regs:
            sinks.append({"kind": "return-value", "rva": addr})
        terminal = "return"
        return State(frozenset(regs), frozenset(stack)), sinks, terminal

    # Direct unconditional external B is a tail-call exit; argument taint escapes.
    if ins.id == ARM64_INS_B:
        target = branch_target(ins)
        args = sorted(int(reg[1:]) for reg in regs if reg.startswith("x") and reg[1:].isdigit() and int(reg[1:]) <= 7)
        if target is not None and target in managed_starts:
            if args:
                sinks.append({
                    "kind": "tail-call-argument",
                    "rva": addr,
                    "argument_positions": args,
                    "target_rva": target,
                })
            terminal = "managed-tail-exit"
        return State(frozenset(regs), frozenset(stack)), sinks, terminal

    # Transparent register aliases.
    if ins.id in {ARM64_INS_MOV, ARM64_INS_ORR} and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            src = norm_reg(md.reg_name(ins.operands[1].reg))
            regs.discard(dst)
            if src in state.regs:
                regs.add(dst)
            return State(frozenset(regs), frozenset(stack)), sinks, terminal

    # Stack spills/reloads are transparent.  Non-stack stores are observable escapes.
    if mnemonic.startswith(("str", "stur")) and len(ins.operands) >= 2:
        src_op, mem_op = ins.operands[0], ins.operands[1]
        if src_op.type == ARM64_OP_REG and mem_op.type == ARM64_OP_MEM:
            src = norm_reg(md.reg_name(src_op.reg))
            base = norm_reg(md.reg_name(mem_op.mem.base))
            disp = int(mem_op.mem.disp)
            if src in regs:
                if _is_stack_base(base):
                    stack.add(disp)
                else:
                    sinks.append({
                        "kind": "nonstack-store",
                        "rva": addr,
                        "base_register": base,
                        "offset": disp,
                    })
            return State(frozenset(regs), frozenset(stack)), sinks, terminal

    if mnemonic.startswith(("ldr", "ldur")) and len(ins.operands) >= 2:
        dst_op, mem_op = ins.operands[0], ins.operands[1]
        if dst_op.type == ARM64_OP_REG and mem_op.type == ARM64_OP_MEM:
            dst = norm_reg(md.reg_name(dst_op.reg))
            base = norm_reg(md.reg_name(mem_op.mem.base))
            disp = int(mem_op.mem.disp)
            regs.discard(dst)
            if _is_stack_base(base) and disp in stack:
                regs.add(dst)
            elif base in state.regs:
                sinks.append({
                    "kind": "dereference",
                    "rva": addr,
                    "base_register": base,
                    "offset": disp,
                })
            return State(frozenset(regs), frozenset(stack)), sinks, terminal

    reads = _read_regs(ins, md)
    tainted_reads = sorted(reads & set(state.regs))
    if tainted_reads:
        sinks.append({
            "kind": "nontransparent-register-use",
            "rva": addr,
            "mnemonic": mnemonic,
            "tainted_registers": tainted_reads,
        })

    # Ordinary register writes kill previous taint in the destination.
    for reg in _written_regs(ins, md):
        regs.discard(reg)
    return State(frozenset(regs), frozenset(stack)), sinks, terminal


def instruction_successors(insns: list[Any], start: int, end: int, managed_starts: set[int]) -> tuple[dict[int, list[int]], list[dict[str, Any]]]:
    by = {int(ins.address): ins for ins in insns}
    addrs = sorted(by)
    next_addr = {addr: addrs[i + 1] if i + 1 < len(addrs) else None for i, addr in enumerate(addrs)}
    succ: dict[int, list[int]] = {}
    unresolved: list[dict[str, Any]] = []
    for addr in addrs:
        ins = by[addr]
        m = ins.mnemonic.lower()
        nxt = next_addr[addr]
        targets: list[int] = []
        if is_ret(m):
            targets = []
        elif ins.id == ARM64_INS_B:
            target = branch_target(ins)
            if target is not None and start <= target < end and target in by:
                targets = [target]
            elif target is not None and target in managed_starts:
                targets = []
            else:
                unresolved.append({"rva": addr, "kind": "unverified-external-branch", "target_rva": target})
                targets = []
        elif is_conditional_branch(m):
            target = branch_target(ins)
            if target is None or not (start <= target < end) or target not in by:
                unresolved.append({"rva": addr, "kind": "conditional-target-unresolved", "target_rva": target})
            else:
                targets.append(target)
            if nxt is not None:
                targets.append(nxt)
        elif m in {"br", "braa", "brab"}:
            unresolved.append({"rva": addr, "kind": "indirect-branch", "target_rva": None})
            targets = []
        else:
            targets = [nxt] if nxt is not None else []
        succ[addr] = sorted(set(x for x in targets if x is not None))
    return succ, unresolved


def analyze(view: BinaryView, script_json: Path, c20_path: Path) -> dict[str, Any]:
    target = load_target(c20_path)
    starts, managed_starts = load_method_starts(script_json)
    start = int(target["method_rva"])
    access = int(target["data_access_rva"])
    end = function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    if access not in by or by[access].id != ARM64_INS_BL:
        raise AnalysisError("C20 data access is not a direct BL in final binary")
    addrs = sorted(by)
    access_index = addrs.index(access)
    if access_index + 1 >= len(addrs):
        raise AnalysisError("data access has no following instruction")
    entry = addrs[access_index + 1]
    succ, unresolved_edges = instruction_successors(insns, start, end, managed_starts)

    state_at: dict[int, State] = {entry: State(frozenset({"x0"}), frozenset())}
    queue: deque[int] = deque([entry])
    sinks: dict[tuple[Any, ...], dict[str, Any]] = {}
    reached_returns: set[int] = set()
    reached_tail_exits: set[int] = set()
    reached_unresolved_edges: list[dict[str, Any]] = []
    iterations = 0

    while queue:
        addr = queue.popleft()
        iterations += 1
        if iterations > 200000:
            raise AnalysisError("dataflow iteration cap exceeded")
        ins = by[addr]
        state = state_at[addr]
        out_state, new_sinks, terminal = transfer(ins, md, state, managed_starts)
        for sink in new_sinks:
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
            sinks[key] = sink
        if terminal == "return":
            reached_returns.add(addr)
        elif terminal == "managed-tail-exit":
            reached_tail_exits.add(addr)

        for edge in unresolved_edges:
            if edge["rva"] == addr:
                reached_unresolved_edges.append(edge)
                # Any live taint at unknown control-flow escape blocks a dead-value proof.
                if state.regs or state.stack:
                    sink = {
                        "kind": "unknown-control-flow-with-live-taint",
                        "rva": addr,
                        "edge_kind": edge["kind"],
                    }
                    key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
                    sinks[key] = sink

        for dst in succ.get(addr, []):
            previous = state_at.get(dst)
            merged = out_state if previous is None else previous.union(out_state)
            if previous != merged:
                state_at[dst] = merged
                queue.append(dst)

    known_exit_count = len(reached_returns) + len(reached_tail_exits)
    dead = not sinks and not reached_unresolved_edges and known_exit_count > 0
    return {
        "schema": SCHEMA,
        "scope": (
            "C27 conservative final-client instruction-CFG taint liveness for the exact top-level data "
            "JsonData value of /stream/telescope_view/send_action; no response value generated"
        ),
        "route": TARGET_ROUTE,
        "endpoint_id": TARGET_ENDPOINT_ID,
        "task": TARGET_TASK,
        "method": TARGET_METHOD,
        "method_rva": start,
        "data_access_rva": access,
        "post_access_entry_rva": entry,
        "reachable_instruction_count": len(state_at),
        "reachable_normal_return_count": len(reached_returns),
        "reachable_managed_tail_exit_count": len(reached_tail_exits),
        "reachable_unresolved_control_flow": reached_unresolved_edges,
        "semantic_sink_count": len(sinks),
        "semantic_sinks": sorted(sinks.values(), key=lambda row: (int(row["rva"]), str(row["kind"]))),
        "parser_data_value_class": "dead-value" if dead else "observable-or-unresolved",
        "parser_local_arbitrary_json_value_safe": dead,
        "empty_object_promotion": "parser-local-safe-if-field-present" if dead else "not-proven-by-c27",
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--c20", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        view = BinaryView(args.lib)
        try:
            report = analyze(view, args.script_json, args.c20)
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route": report["route"],
        "parser_data_value_class": report["parser_data_value_class"],
        "parser_local_arbitrary_json_value_safe": report["parser_local_arbitrary_json_value_safe"],
        "semantic_sink_count": report["semantic_sink_count"],
        "reachable_normal_return_count": report["reachable_normal_return_count"],
        "reachable_managed_tail_exit_count": report["reachable_managed_tail_exit_count"],
        "reachable_unresolved_control_flow_count": len(report["reachable_unresolved_control_flow"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
