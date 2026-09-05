#!/usr/bin/env python3
"""C19b: prove parser-local zero-iteration exits for C17 object-shaped data.

C19 showed that merely observing ``JsonData.get_Keys`` is not enough: most
parsers subsequently index JsonData.  This refinement taints the exact
``get_Keys`` return through ARM64 registers and simple stack spills, recognizes
managed ``Count/GetEnumerator/MoveNext`` operations when their receiver is
keys-derived, and associates zero/false conditional branches with the parser CFG.

A route is labelled ``parser-empty-object-zero-path`` only when all of the
following are statically true in the final 11.6.3 parser:

1. C19 CFG is complete and the get_Keys site is reachable;
2. a keys-derived Count==0 or MoveNext==false guard is recovered;
3. the zero/false successor reaches a known parser exit;
4. that path can avoid every post-get_Keys LitJson JsonData.get_Item callsite.

This proves parser-local structural acceptance of an empty object.  It does NOT
prove task callback/UI acceptance and therefore is still below untouched-client
evidence level.
"""
from __future__ import annotations

import argparse
import bisect
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x20000
CALLER_SAVED = {f"x{i}" for i in range(18)}


@dataclass
class Block:
    start: int
    insns: list[int]
    successors: set[int]
    terminal: str = "fallthrough"
    terminal_target: int | None = None


class ZeroIterationError(ValueError):
    pass


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads = []
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


def norm_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ZeroIterationError(f"invalid RVA {value!r}")


def load_methods(path: Path) -> tuple[list[int], dict[int, list[str]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    methods: dict[int, list[str]] = defaultdict(list)
    for row in raw.get("ScriptMethod", []):
        rva = as_int(row.get("Address", 0))
        if rva <= 0:
            continue
        starts.add(rva)
        name = str(row.get("Name") or "")
        if name:
            methods[rva].append(name)
    for value in raw.get("Addresses", []):
        rva = as_int(value)
        if rva > 0:
            starts.add(rva)
    for names in methods.values():
        names.sort()
    return sorted(starts), dict(methods), set(methods)


def function_end(starts: list[int], start: int) -> int:
    i = bisect.bisect_right(starts, start)
    end = starts[i] if i < len(starts) else start + MAX_FUNCTION_SIZE
    return min(end, start + MAX_FUNCTION_SIZE)


def branch_target(ins: Any) -> int | None:
    if not ins.operands or ins.operands[-1].type != ARM64_OP_IMM:
        return None
    return int(ins.operands[-1].imm)


def is_cond(m: str) -> bool:
    m = m.lower()
    return m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}


def build_cfg(view: BinaryView, start: int, end: int, managed_starts: set[int]) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    if not insns or int(insns[0].address) != start:
        return {"complete": False, "blocks": {}, "addr_block": {}, "reachable": set(), "known_exits": set()}
    addrs = sorted(by)
    nxt = {a: addrs[i + 1] if i + 1 < len(addrs) else None for i, a in enumerate(addrs)}
    leaders = {start}
    complete = True
    for ins in insns:
        a = int(ins.address)
        m = ins.mnemonic.lower()
        if is_cond(m) or m == "b":
            target = branch_target(ins)
            if target is not None and start <= target < end and target in by:
                leaders.add(target)
            elif is_cond(m):
                complete = False
            if nxt[a] is not None:
                leaders.add(nxt[a])
        elif m in {"br", "braa", "brab", "ret", "retaa", "retab", "eret"}:
            if nxt[a] is not None:
                leaders.add(nxt[a])
            if m in {"br", "braa", "brab"}:
                complete = False
    leaders = sorted(x for x in leaders if x in by)
    blocks: dict[int, Block] = {}
    addr_block: dict[int, int] = {}
    for i, leader in enumerate(leaders):
        limit = leaders[i + 1] if i + 1 < len(leaders) else end
        members = [a for a in addrs if leader <= a < limit]
        if not members:
            continue
        blocks[leader] = Block(leader, members, set())
        for a in members:
            addr_block[a] = leader

    for block in blocks.values():
        a = block.insns[-1]
        ins = by[a]
        m = ins.mnemonic.lower()
        if m in {"ret", "retaa", "retab", "eret"}:
            block.terminal = "return"
        elif m == "b":
            target = branch_target(ins)
            block.terminal_target = target
            if target is not None and start <= target < end and target in addr_block:
                block.terminal = "branch"
                block.successors.add(addr_block[target])
            elif target is not None and target in managed_starts:
                block.terminal = "managed-tail-exit"
            else:
                block.terminal = "external-branch"
                complete = False
        elif is_cond(m):
            target = branch_target(ins)
            block.terminal = "conditional"
            block.terminal_target = target
            if target is not None and target in addr_block:
                block.successors.add(addr_block[target])
            else:
                complete = False
            if nxt[a] is not None and nxt[a] in addr_block:
                block.successors.add(addr_block[nxt[a]])
        elif m in {"br", "braa", "brab"}:
            block.terminal = "indirect-branch"
        elif nxt[a] is not None and nxt[a] in addr_block:
            block.successors.add(addr_block[nxt[a]])

    reachable: set[int] = set()
    q = deque([start]) if start in blocks else deque()
    while q:
        cur = q.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        q.extend(blocks[cur].successors - reachable)
    exits = {
        b for b in reachable
        if blocks[b].terminal in {"return", "managed-tail-exit"}
    }
    if not exits:
        complete = False
    return {
        "complete": complete,
        "blocks": blocks,
        "addr_block": addr_block,
        "reachable": reachable,
        "known_exits": exits,
        "next": nxt,
        "by": by,
    }


def stack_key(ins: Any, md: Cs) -> tuple[str, int] | None:
    if len(ins.operands) < 2 or ins.operands[1].type != ARM64_OP_MEM:
        return None
    base = norm_reg(md.reg_name(ins.operands[1].mem.base))
    if base not in {"sp", "x29"}:
        return None
    return base, int(ins.operands[1].mem.disp)


def call_semantic(names: list[str]) -> str:
    low = " ".join(names).lower()
    if "getenumerator" in low:
        return "get-enumerator"
    if "movenext" in low:
        return "move-next"
    if "get_count" in low or "get_length" in low:
        return "count"
    if "get_current" in low:
        return "current"
    return "other"


def propagate_simple(ins: Any, md: Cs, regs: dict[str, set[str]], stack: dict[tuple[str, int], set[str]]) -> None:
    m = ins.mnemonic.lower()
    # register copies
    if m in {"mov", "orr"} and len(ins.operands) >= 2 and all(op.type == ARM64_OP_REG for op in ins.operands[:2]):
        dst = norm_reg(md.reg_name(ins.operands[0].reg))
        src = norm_reg(md.reg_name(ins.operands[1].reg))
        if src in regs:
            regs[dst] = set(regs[src])
        else:
            regs.pop(dst, None)
        return
    # simple stack spill/reload
    if m.startswith(("str", "stur")) and ins.operands and ins.operands[0].type == ARM64_OP_REG:
        key = stack_key(ins, md)
        if key is not None:
            src = norm_reg(md.reg_name(ins.operands[0].reg))
            if src in regs:
                stack[key] = set(regs[src])
            else:
                stack.pop(key, None)
            return
    if m.startswith(("ldr", "ldur")) and ins.operands and ins.operands[0].type == ARM64_OP_REG:
        key = stack_key(ins, md)
        if key is not None:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            if key in stack:
                regs[dst] = set(stack[key])
            else:
                regs.pop(dst, None)
            return
    try:
        _reads, writes = ins.regs_access()
    except Exception:
        writes = []
    for reg_id in writes:
        name = norm_reg(md.reg_name(reg_id))
        if name:
            regs.pop(name, None)


def zero_successor_for_guard(ins: Any, cfg: dict[str, Any], tag: str, compared_reg: str | None) -> tuple[int | None, str | None]:
    m = ins.mnemonic.lower()
    a = int(ins.address)
    target = branch_target(ins)
    fallthrough = cfg["next"].get(a)
    if m in {"cbz", "cbnz"} and ins.operands and ins.operands[0].type == ARM64_OP_REG:
        reg = norm_reg(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).reg_name(ins.operands[0].reg))
        if reg != compared_reg:
            return None, None
        return (target if m == "cbz" else fallthrough), ("zero" if tag == "count" else "false")
    if m.startswith("b.") and compared_reg is not None:
        cond = m[2:]
        if cond in {"eq", "z"}:
            return target, ("zero" if tag == "count" else "false")
        if cond in {"ne", "nz"}:
            return fallthrough, ("zero" if tag == "count" else "false")
    return None, None


def path_to_exit_avoiding(cfg: dict[str, Any], successor: int, forbidden_sites: set[int]) -> dict[str, Any] | None:
    start_block = cfg["addr_block"].get(successor)
    if start_block is None or start_block not in cfg["reachable"]:
        return None
    forbidden_blocks = {
        cfg["addr_block"][site] for site in forbidden_sites if site in cfg["addr_block"]
    }
    q: deque[tuple[int, list[int]]] = deque([(start_block, [start_block])])
    seen: set[int] = set()
    while q:
        block, path = q.popleft()
        if block in seen or block in forbidden_blocks:
            continue
        seen.add(block)
        if block in cfg["known_exits"]:
            return {"exit_block": block, "path_blocks": path}
        for nxt in sorted(cfg["blocks"][block].successors):
            if nxt not in seen:
                q.append((nxt, path + [nxt]))
    return None


def analyze_route(route: dict[str, Any], view: BinaryView, starts: list[int], methods: dict[int, list[str]], managed_starts: set[int]) -> dict[str, Any]:
    start = int(route["method_rva"])
    end = function_end(starts, start)
    cfg = build_cfg(view, start, end, managed_starts)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    keys_site = int(route["get_keys_rva"])
    forbidden = {
        int(call["callsite_rva"])
        for call in route.get("post_keys_managed_calls", [])
        if call.get("kind") == "json-index"
    }
    regs: dict[str, set[str]] = {}
    stack: dict[tuple[str, int], set[str]] = {}
    seen_keys = False
    guards: list[dict[str, Any]] = []
    last_cmp: tuple[str, str] | None = None  # (tag, reg)
    indirect_keys_calls = 0
    managed_keys_calls = Counter()

    for ins in insns:
        a = int(ins.address)
        if a < keys_site:
            continue
        if ins.id == ARM64_INS_BL:
            target = branch_target(ins)
            names = methods.get(target or -1, [])
            if a == keys_site:
                regs = {"x0": {"keys"}}
                seen_keys = True
                last_cmp = None
                continue
            if not seen_keys:
                continue
            receiver_tags = set(regs.get("x0", set()))
            semantic = call_semantic(names)
            if receiver_tags:
                managed_keys_calls[semantic] += 1
            for reg in list(regs):
                if reg in CALLER_SAVED:
                    regs.pop(reg, None)
            if "keys" in receiver_tags and semantic == "count":
                regs["x0"] = {"count"}
            elif "keys" in receiver_tags and semantic == "get-enumerator":
                regs["x0"] = {"iterator"}
            elif "iterator" in receiver_tags and semantic == "move-next":
                regs["x0"] = {"move-next"}
            elif "iterator" in receiver_tags and semantic == "current":
                regs["x0"] = {"current"}
            last_cmp = None
            continue
        if not seen_keys:
            continue
        m = ins.mnemonic.lower()
        if m in {"blr", "blraa", "blrab"}:
            if regs.get("x0"):
                indirect_keys_calls += 1
            for reg in list(regs):
                if reg in CALLER_SAVED:
                    regs.pop(reg, None)
            last_cmp = None
            continue

        # Direct zero/false register branches.
        if m in {"cbz", "cbnz"} and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            reg = norm_reg(md.reg_name(ins.operands[0].reg))
            tags = regs.get(reg, set())
            tag = "count" if "count" in tags else ("move-next" if "move-next" in tags else None)
            if tag:
                successor, zero_sem = zero_successor_for_guard(ins, cfg, tag, reg)
                if successor is not None:
                    proof = path_to_exit_avoiding(cfg, successor, forbidden)
                    guards.append({
                        "guard_rva": a,
                        "guard_kind": f"{tag}-{zero_sem}",
                        "zero_false_successor_rva": successor,
                        "zero_false_path_avoids_json_index": proof is not None,
                        "zero_false_exit_block": proof["exit_block"] if proof else None,
                        "zero_false_path_block_count": len(proof["path_blocks"]) if proof else 0,
                    })
            last_cmp = None
            continue

        # cmp <derived>, #0 followed by b.eq/b.ne
        if m == "cmp" and len(ins.operands) >= 2 and ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_IMM:
            reg = norm_reg(md.reg_name(ins.operands[0].reg))
            if int(ins.operands[1].imm) == 0:
                tags = regs.get(reg, set())
                if "count" in tags:
                    last_cmp = ("count", reg)
                elif "move-next" in tags:
                    last_cmp = ("move-next", reg)
                else:
                    last_cmp = None
            else:
                last_cmp = None
            propagate_simple(ins, md, regs, stack)
            continue
        if m.startswith("b.") and last_cmp is not None:
            tag, reg = last_cmp
            successor, zero_sem = zero_successor_for_guard(ins, cfg, tag, reg)
            if successor is not None:
                proof = path_to_exit_avoiding(cfg, successor, forbidden)
                guards.append({
                    "guard_rva": a,
                    "guard_kind": f"{tag}-{zero_sem}",
                    "zero_false_successor_rva": successor,
                    "zero_false_path_avoids_json_index": proof is not None,
                    "zero_false_exit_block": proof["exit_block"] if proof else None,
                    "zero_false_path_block_count": len(proof["path_blocks"]) if proof else 0,
                })
            last_cmp = None
            continue
        if is_cond(m):
            last_cmp = None

        propagate_simple(ins, md, regs, stack)

    proven_guards = [guard for guard in guards if guard["zero_false_path_avoids_json_index"]]
    out = {
        "route": route["route"],
        "endpoint_id": route["endpoint_id"],
        "task": route["task"],
        "method": route["method"],
        "method_rva": start,
        "get_keys_rva": keys_site,
        "cfg_complete": bool(cfg["complete"]),
        "post_keys_json_index_call_count": len(forbidden),
        "keys_derived_managed_call_counts": dict(sorted(managed_keys_calls.items())),
        "keys_derived_indirect_call_count": indirect_keys_calls,
        "zero_iteration_guards": guards,
        "proven_zero_iteration_guard_count": len(proven_guards),
        "parser_empty_object_class": (
            "parser-empty-object-zero-path" if cfg["complete"] and proven_guards else "not-proven"
        ),
        "untouched_client_acceptance": False,
    }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c19", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        c19 = json.loads(args.c19.read_text(encoding="utf-8"))
        if c19.get("schema") != 1 or c19.get("target_route_count") != 36:
            raise ZeroIterationError("unexpected C19 input")
        starts, methods, managed_starts = load_methods(args.script_json)
        view = BinaryView(args.lib)
        try:
            routes = [
                analyze_route(row, view, starts, methods, managed_starts)
                for row in c19.get("routes", [])
            ]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, ZeroIterationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    proven = [row for row in routes if row["parser_empty_object_class"] == "parser-empty-object-zero-path"]
    report = {
        "schema": SCHEMA,
        "scope": (
            "C19b exact final-client get_Keys-derived Count/MoveNext zero-path proof; "
            "parser-local only, no callback or untouched-client acceptance claim"
        ),
        "target_route_count": len(routes),
        "parser_empty_object_zero_path_route_count": len(proven),
        "routes": sorted(routes, key=lambda row: str(row["route"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "parser_empty_object_zero_path_route_count": report["parser_empty_object_zero_path_route_count"],
        "proven_routes": [row["route"] for row in proven],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
