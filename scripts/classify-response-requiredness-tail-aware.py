#!/usr/bin/env python3
"""C5 refinement: conservative response requiredness with validated managed tail exits.

This is intentionally stricter than treating every external ARM64 ``B`` as an
exit. An unconditional direct branch outside the current bounded function is a
legal tail-call exit only when its statically decoded target is an exact managed
method start from Il2CppDumper ``ScriptMethod``. Unknown external targets,
conditional external branches and indirect BR/BRAA/BRAB remain incomplete.

For a complete CFG, a direct JsonData.get_Item access is ``required-path`` only
when its block dominates every reachable known exit: normal RET plus validated
managed tail-call exits. Optional TryGet*/Get*OrDefault semantics are unchanged.
Output is sanitized derived metadata only.
"""
from __future__ import annotations

import argparse
import bisect
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x20000


@dataclass
class Block:
    start: int
    insns: list[int]
    successors: set[int]
    predecessors: set[int]
    terminal: str = "fallthrough"
    terminal_target: int | None = None


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.loads.append((int(seg["p_vaddr"]), int(seg["p_memsz"]),
                                   int(seg["p_offset"]), int(seg["p_filesz"])))

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
    raise TypeError(value)


def load_method_map(path: Path) -> tuple[list[int], dict[int, list[str]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    all_starts: set[int] = set()
    managed: dict[int, list[str]] = defaultdict(list)
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        if address <= 0:
            continue
        all_starts.add(address)
        name = str(row.get("Name") or "")
        if name:
            managed[address].append(name)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            all_starts.add(address)
    for names in managed.values():
        names.sort()
    return sorted(all_starts), dict(managed), set(managed)


def function_end(starts: list[int], start: int) -> int:
    i = bisect.bisect_right(starts, start)
    end = starts[i] if i < len(starts) else start + MAX_FUNCTION_SIZE
    return min(end, start + MAX_FUNCTION_SIZE)


def target(ins: Any) -> int | None:
    if not ins.operands or ins.operands[-1].type != ARM64_OP_IMM:
        return None
    return int(ins.operands[-1].imm)


def cond(m: str) -> bool:
    m = m.lower()
    return m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}


def uncond(m: str) -> bool:
    return m.lower() == "b"


def indirect(m: str) -> bool:
    return m.lower() in {"br", "braa", "brab"}


def ret(m: str) -> bool:
    return m.lower() in {"ret", "retaa", "retab", "eret"}


def build_cfg(view: BinaryView, start: int, end: int,
              managed_starts: set[int], managed_names: dict[int, list[str]]) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, max(0, end - start)), start))
    if not insns or int(insns[0].address) != start:
        return {"complete": False, "reason": "entry-not-disassembled", "blocks": {},
                "reachable": set(), "returns": set(), "tail_exits": set(), "known_exits": set(),
                "dom": {}, "addr_block": {}, "validated_tail_edges": []}

    by = {int(i.address): i for i in insns}
    addrs = sorted(by)
    nxt = {a: (addrs[i + 1] if i + 1 < len(addrs) else None) for i, a in enumerate(addrs)}
    leaders = {start}
    complete = True
    reasons: set[str] = set()

    for ins in insns:
        m = ins.mnemonic.lower()
        a = int(ins.address)
        if cond(m) or uncond(m):
            t = target(ins)
            if t is None:
                complete = False
                reasons.add("branch-without-target")
            elif start <= t < end:
                if t in by:
                    leaders.add(t)
                else:
                    complete = False
                    reasons.add("internal-target-not-disassembled")
            elif cond(m):
                complete = False
                reasons.add("conditional-external-target")
            # An unconditional branch has no architectural fallthrough, but a
            # separate following block may still be a branch target from elsewhere.
            if nxt[a] is not None:
                leaders.add(nxt[a])
        elif indirect(m) or ret(m):
            if nxt[a] is not None:
                leaders.add(nxt[a])
            if indirect(m):
                complete = False
                reasons.add("indirect-branch")

    leaders = sorted(x for x in leaders if x in by)
    blocks: dict[int, Block] = {}
    addr_block: dict[int, int] = {}
    for i, leader in enumerate(leaders):
        limit = leaders[i + 1] if i + 1 < len(leaders) else end
        members = [a for a in addrs if leader <= a < limit]
        if not members:
            continue
        blocks[leader] = Block(leader, members, set(), set())
        for a in members:
            addr_block[a] = leader

    def edge(block: Block, dst: int | None) -> None:
        nonlocal complete
        if dst is None:
            return
        bdst = addr_block.get(dst)
        if bdst is None:
            if start <= dst < end:
                complete = False
                reasons.add("successor-not-in-cfg")
            return
        block.successors.add(bdst)

    for block in blocks.values():
        a = block.insns[-1]
        ins = by[a]
        m = ins.mnemonic.lower()
        if ret(m):
            block.terminal = "return"
        elif indirect(m):
            block.terminal = "indirect-branch"
        elif uncond(m):
            t = target(ins)
            block.terminal_target = t
            if t is not None and start <= t < end:
                block.terminal = "branch"
                edge(block, t)
            elif t is not None and t in managed_starts:
                block.terminal = "managed-tail-call-exit"
            else:
                block.terminal = "unverified-external-branch"
                complete = False
                reasons.add("unverified-external-tail-branch")
        elif cond(m):
            block.terminal = "conditional"
            t = target(ins)
            block.terminal_target = t
            if t is not None and start <= t < end:
                edge(block, t)
            else:
                complete = False
                reasons.add("conditional-external-target")
            edge(block, nxt[a])
        else:
            edge(block, nxt[a])

    for src, block in blocks.items():
        for dst in block.successors:
            blocks[dst].predecessors.add(src)

    reachable: set[int] = set()
    if start in blocks:
        q: deque[int] = deque([start])
        while q:
            cur = q.popleft()
            if cur in reachable:
                continue
            reachable.add(cur)
            q.extend(blocks[cur].successors - reachable)

    returns = {b for b in reachable if blocks[b].terminal == "return"}
    tail_exits = {b for b in reachable if blocks[b].terminal == "managed-tail-call-exit"}
    known_exits = returns | tail_exits
    if not known_exits:
        complete = False
        reasons.add("no-reachable-known-exit")

    dom: dict[int, set[int]] = {}
    for b in reachable:
        dom[b] = {start} if b == start else set(reachable)
    changed = True
    while changed:
        changed = False
        for b in sorted(reachable):
            if b == start:
                continue
            preds = blocks[b].predecessors & reachable
            if not preds:
                new = {b}
            else:
                inter: set[int] | None = None
                for pred in preds:
                    inter = set(dom[pred]) if inter is None else inter & dom[pred]
                new = {b} | (inter or set())
            if new != dom[b]:
                dom[b] = new
                changed = True

    validated_tail_edges = []
    for block_start in sorted(tail_exits):
        block = blocks[block_start]
        t = block.terminal_target
        validated_tail_edges.append({
            "block_start": block_start,
            "branch_rva": block.insns[-1],
            "target_rva": t,
            "target_methods": managed_names.get(int(t), []) if t is not None else [],
            "evidence": "direct unconditional ARM64 B targets exact Il2CppDumper ScriptMethod start",
        })

    return {
        "complete": complete,
        "reason": ",".join(sorted(reasons)) or None,
        "blocks": blocks,
        "reachable": reachable,
        "returns": returns,
        "tail_exits": tail_exits,
        "known_exits": known_exits,
        "dom": dom,
        "addr_block": addr_block,
        "validated_tail_edges": validated_tail_edges,
    }


def endpoint_map(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in raw.get("endpoints", []):
        route = str(ep.get("route") or "")
        if not route:
            continue
        route = route if route.startswith("/") else "/" + route
        for binding in ep.get("task_bindings", []):
            task = str(binding.get("task") or "")
            if task:
                out[task].append({
                    "route": route,
                    "enum": ep.get("enum"),
                    "status": ep.get("status"),
                    "binding_evidence": binding.get("evidence"),
                })
    for task in out:
        out[task].sort(key=lambda x: (x["route"], str(x.get("enum"))))
    return dict(out)


def aggregate_requiredness(rows: list[dict[str, Any]]) -> str:
    kinds = {str(x["requiredness"]) for x in rows}
    for choice in ("required-path", "conditional-direct", "unknown-cfg",
                   "optional-defaulted", "optional-conditional"):
        if choice in kinds:
            return choice
    return "unknown"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--c3", type=Path, required=True)
    p.add_argument("--endpoint-contracts", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    args = p.parse_args()

    c3 = json.loads(args.c3.read_text(encoding="utf-8"))
    if c3.get("schema") != 1:
        raise RuntimeError(f"unsupported C3 schema {c3.get('schema')}")
    starts, managed_names, managed_starts = load_method_map(args.script_json)
    epmap = endpoint_map(args.endpoint_contracts)
    method_rvas = sorted({int(x["method_rva"]) for x in c3.get("accesses", [])})

    view = BinaryView(args.lib)
    try:
        cfgs = {
            rva: build_cfg(view, rva, function_end(starts, rva), managed_starts, managed_names)
            for rva in method_rvas
        }
    finally:
        view.close()

    accesses = []
    for src in c3.get("accesses", []):
        row = dict(src)
        cfg = cfgs[int(row["method_rva"])]
        block = cfg["addr_block"].get(int(row["access_rva"]))
        reachable = block in cfg["reachable"] if block is not None else False
        dominates = bool(
            block is not None and reachable and cfg["known_exits"] and
            all(block in cfg["dom"].get(exit_block, set()) for exit_block in cfg["known_exits"])
        )
        style = str(row.get("access_style") or "")
        if style == "try-get":
            requiredness, confidence = "optional-conditional", "high"
        elif style == "defaulted":
            requiredness, confidence = "optional-defaulted", "high"
        elif style == "direct-index":
            if block is None or not reachable or not cfg["complete"]:
                requiredness, confidence = "unknown-cfg", "low"
            elif dominates:
                requiredness, confidence = "required-path", "high"
            else:
                requiredness, confidence = "conditional-direct", "high"
        else:
            requiredness, confidence = "unknown", "low"
        row.update({
            "requiredness": requiredness,
            "requiredness_confidence": confidence,
            "cfg_block_start": block,
            "cfg_reachable": reachable,
            "cfg_complete": bool(cfg["complete"]),
            "cfg_incomplete_reason": cfg["reason"],
            "cfg_reachable_normal_return_count": len(cfg["returns"]),
            "cfg_reachable_managed_tail_exit_count": len(cfg["tail_exits"]),
            "cfg_reachable_known_exit_count": len(cfg["known_exits"]),
            "cfg_dominates_all_normal_returns": bool(
                block is not None and reachable and cfg["returns"] and
                all(block in cfg["dom"].get(r, set()) for r in cfg["returns"])
            ),
            "cfg_dominates_all_known_exits": dominates,
            "cfg_validated_managed_tail_edges": cfg["validated_tail_edges"],
            "endpoint_candidates": epmap.get(str(row.get("task")), []),
        })
        accesses.append(row)

    grouped: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in accesses:
        grouped[(str(row["task"]), str(row["method"]), int(row["method_rva"]), str(row["field"]))].append(row)
    contracts = []
    for (task, method, method_rva, field), rows in sorted(grouped.items()):
        contracts.append({
            "task": task,
            "method": method,
            "method_rva": method_rva,
            "field": field,
            "endpoint_candidates": epmap.get(task, []),
            "value_types": sorted({str(x.get("value_type") or "unknown") for x in rows}),
            "access_styles": sorted({str(x.get("access_style") or "unknown") for x in rows}),
            "requiredness": aggregate_requiredness(rows),
            "access_count": len(rows),
            "evidence": [{
                "access_rva": int(x["access_rva"]),
                "literal_load_rva": int(x["literal_load_rva"]),
                "helper": x.get("helper"),
                "conversion_helper": x.get("conversion_helper"),
                "cfg_block_start": x.get("cfg_block_start"),
                "cfg_complete": x.get("cfg_complete"),
                "cfg_incomplete_reason": x.get("cfg_incomplete_reason"),
                "cfg_reachable_normal_return_count": x.get("cfg_reachable_normal_return_count"),
                "cfg_reachable_managed_tail_exit_count": x.get("cfg_reachable_managed_tail_exit_count"),
                "cfg_dominates_all_known_exits": x.get("cfg_dominates_all_known_exits"),
                "requiredness": x.get("requiredness"),
            } for x in rows],
        })

    complete = sum(bool(x["complete"]) for x in cfgs.values())
    methods_with_tail = sum(bool(x["validated_tail_edges"]) for x in cfgs.values())
    tail_edge_count = sum(len(x["validated_tail_edges"]) for x in cfgs.values())
    incomplete_reason_counts = Counter(x["reason"] or "none" for x in cfgs.values() if not x["complete"])
    report = {
        "schema": SCHEMA,
        "scope": "C5 refined conservative CFG/dominator requiredness; exact managed direct-B tail calls count as known exits; indirect dispatch remains unknown",
        "refinement": "managed-direct-tail-exit-v1",
        "source_c3_schema": c3.get("schema"),
        "source_c3_access_count": len(c3.get("accesses", [])),
        "method_count": len(cfgs),
        "cfg_complete_method_count": complete,
        "cfg_incomplete_method_count": len(cfgs) - complete,
        "cfg_method_with_validated_managed_tail_exit_count": methods_with_tail,
        "cfg_validated_managed_tail_edge_count": tail_edge_count,
        "cfg_incomplete_reason_counts": dict(sorted(incomplete_reason_counts.items())),
        "requiredness_counts": dict(sorted(Counter(x["requiredness"] for x in accesses).items())),
        "contract_requiredness_counts": dict(sorted(Counter(x["requiredness"] for x in contracts).items())),
        "access_count": len(accesses),
        "contract_count": len(contracts),
        "validated_managed_tail_methods": [
            {
                "method_rva": rva,
                "tail_edges": cfg["validated_tail_edges"],
                "cfg_complete": cfg["complete"],
                "cfg_incomplete_reason": cfg["reason"],
            }
            for rva, cfg in sorted(cfgs.items()) if cfg["validated_tail_edges"]
        ],
        "contracts": contracts,
        "accesses": accesses,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C5 response requiredness — managed-tail refinement", "",
            "Only direct external `B` targets that exactly match an Il2CppDumper `ScriptMethod` start are accepted as tail-call exits. Indirect branches remain unknown.", "",
            f"- C3 accesses: **{report['source_c3_access_count']}**",
            f"- parser methods: **{report['method_count']}**",
            f"- complete CFGs: **{report['cfg_complete_method_count']}**",
            f"- incomplete CFGs: **{report['cfg_incomplete_method_count']}**",
            f"- methods with validated managed tail exits: **{methods_with_tail}**",
            f"- validated managed tail edges: **{tail_edge_count}**",
            f"- field contracts: **{report['contract_count']}**", "",
            "## Access requiredness", "",
        ]
        lines += [f"- `{k}`: **{v}**" for k, v in report["requiredness_counts"].items()]
        lines += ["", "## Contract requiredness", ""]
        lines += [f"- `{k}`: **{v}**" for k, v in report["contract_requiredness_counts"].items()]
        lines += ["", "## Remaining incomplete CFG reasons", ""]
        lines += [f"- `{k}`: **{v}** methods" for k, v in report["cfg_incomplete_reason_counts"].items()]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "method_count", "cfg_complete_method_count", "cfg_incomplete_method_count",
        "cfg_method_with_validated_managed_tail_exit_count", "cfg_validated_managed_tail_edge_count",
        "cfg_incomplete_reason_counts", "requiredness_counts", "contract_requiredness_counts",
        "contract_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
