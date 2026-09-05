#!/usr/bin/env python3
"""C5: conservatively classify response-field requiredness with ARM64 CFG dominators.

Consumes the sanitized C3 field-access report plus the exact final libil2cpp.so and
Il2CppDumper script.json.  TryGet*/Get*OrDefault stay optional.  A direct
JsonData.get_Item is called ``required-path`` only when its basic block dominates
every reachable normal RET in a complete bounded intraprocedural CFG.

Output contains only derived RVAs/contracts/evidence; no native bytes or bulk
disassembly are emitted.
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


def load_starts(path: Path) -> list[int]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    starts = {as_int(x["Address"]) for x in raw.get("ScriptMethod", []) if as_int(x.get("Address", 0)) > 0}
    starts.update(as_int(x) for x in raw.get("Addresses", []) if as_int(x) > 0)
    return sorted(starts)


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


def build_cfg(view: BinaryView, start: int, end: int) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, max(0, end - start)), start))
    if not insns or int(insns[0].address) != start:
        return {"complete": False, "reason": "entry-not-disassembled", "blocks": {},
                "reachable": set(), "returns": set(), "dom": {}, "addr_block": {}}

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
                complete = False; reasons.add("branch-without-target")
            elif start <= t < end:
                if t in by: leaders.add(t)
                else: complete = False; reasons.add("internal-target-not-disassembled")
            elif cond(m):
                complete = False; reasons.add("conditional-external-target")
            if nxt[a] is not None: leaders.add(nxt[a])
        elif indirect(m) or ret(m):
            if nxt[a] is not None: leaders.add(nxt[a])
            if indirect(m): complete = False; reasons.add("indirect-branch")

    leaders = sorted(x for x in leaders if x in by)
    blocks: dict[int, Block] = {}
    addr_block: dict[int, int] = {}
    for i, leader in enumerate(leaders):
        limit = leaders[i + 1] if i + 1 < len(leaders) else end
        members = [a for a in addrs if leader <= a < limit]
        if not members: continue
        blocks[leader] = Block(leader, members, set(), set())
        for a in members: addr_block[a] = leader

    def edge(block: Block, dst: int | None) -> None:
        nonlocal complete
        if dst is None: return
        bdst = addr_block.get(dst)
        if bdst is None:
            if start <= dst < end:
                complete = False; reasons.add("successor-not-in-cfg")
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
            if t is not None and start <= t < end:
                block.terminal = "branch"; edge(block, t)
            else:
                block.terminal = "external-branch"; complete = False; reasons.add("external-tail-branch")
        elif cond(m):
            block.terminal = "conditional"
            t = target(ins)
            if t is not None and start <= t < end: edge(block, t)
            else: complete = False; reasons.add("conditional-external-target")
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
            if cur in reachable: continue
            reachable.add(cur)
            q.extend(blocks[cur].successors - reachable)
    returns = {b for b in reachable if blocks[b].terminal == "return"}
    if not returns:
        complete = False; reasons.add("no-reachable-normal-return")

    dom: dict[int, set[int]] = {}
    for b in reachable:
        dom[b] = {start} if b == start else set(reachable)
    changed = True
    while changed:
        changed = False
        for b in sorted(reachable):
            if b == start: continue
            preds = blocks[b].predecessors & reachable
            if not preds:
                new = {b}
            else:
                inter: set[int] | None = None
                for p in preds:
                    inter = set(dom[p]) if inter is None else inter & dom[p]
                new = {b} | (inter or set())
            if new != dom[b]: dom[b] = new; changed = True

    return {"complete": complete, "reason": ",".join(sorted(reasons)) or None,
            "blocks": blocks, "reachable": reachable, "returns": returns,
            "dom": dom, "addr_block": addr_block}


def endpoint_map(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None: return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in raw.get("endpoints", []):
        route = str(ep.get("route") or "")
        if not route: continue
        route = route if route.startswith("/") else "/" + route
        for binding in ep.get("task_bindings", []):
            task = str(binding.get("task") or "")
            if task:
                out[task].append({"route": route, "enum": ep.get("enum"),
                                  "status": ep.get("status"),
                                  "binding_evidence": binding.get("evidence")})
    for task in out:
        out[task].sort(key=lambda x: (x["route"], str(x.get("enum"))))
    return dict(out)


def aggregate_requiredness(rows: list[dict[str, Any]]) -> str:
    kinds = {str(x["requiredness"]) for x in rows}
    for choice in ("required-path", "conditional-direct", "unknown-cfg",
                   "optional-defaulted", "optional-conditional"):
        if choice in kinds: return choice
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
    starts = load_starts(args.script_json)
    epmap = endpoint_map(args.endpoint_contracts)
    method_rvas = sorted({int(x["method_rva"]) for x in c3.get("accesses", [])})

    view = BinaryView(args.lib)
    try:
        cfgs = {rva: build_cfg(view, rva, function_end(starts, rva)) for rva in method_rvas}
    finally:
        view.close()

    accesses = []
    for src in c3.get("accesses", []):
        row = dict(src)
        cfg = cfgs[int(row["method_rva"])]
        block = cfg["addr_block"].get(int(row["access_rva"]))
        reachable = block in cfg["reachable"] if block is not None else False
        dominates = bool(block is not None and reachable and cfg["returns"] and
                         all(block in cfg["dom"].get(r, set()) for r in cfg["returns"]))
        style = str(row.get("access_style") or "")
        if style == "try-get": requiredness, confidence = "optional-conditional", "high"
        elif style == "defaulted": requiredness, confidence = "optional-defaulted", "high"
        elif style == "direct-index":
            if block is None or not reachable or not cfg["complete"]:
                requiredness, confidence = "unknown-cfg", "low"
            elif dominates:
                requiredness, confidence = "required-path", "high"
            else:
                requiredness, confidence = "conditional-direct", "high"
        else: requiredness, confidence = "unknown", "low"
        row.update({
            "requiredness": requiredness,
            "requiredness_confidence": confidence,
            "cfg_block_start": block,
            "cfg_reachable": reachable,
            "cfg_complete": bool(cfg["complete"]),
            "cfg_incomplete_reason": cfg["reason"],
            "cfg_reachable_normal_return_count": len(cfg["returns"]),
            "cfg_dominates_all_normal_returns": dominates,
            "endpoint_candidates": epmap.get(str(row.get("task")), []),
        })
        accesses.append(row)

    grouped: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in accesses:
        grouped[(str(row["task"]), str(row["method"]), int(row["method_rva"]), str(row["field"]))].append(row)
    contracts = []
    for (task, method, method_rva, field), rows in sorted(grouped.items()):
        contracts.append({
            "task": task, "method": method, "method_rva": method_rva, "field": field,
            "endpoint_candidates": epmap.get(task, []),
            "value_types": sorted({str(x.get("value_type") or "unknown") for x in rows}),
            "access_styles": sorted({str(x.get("access_style") or "unknown") for x in rows}),
            "requiredness": aggregate_requiredness(rows), "access_count": len(rows),
            "evidence": [{
                "access_rva": int(x["access_rva"]), "literal_load_rva": int(x["literal_load_rva"]),
                "helper": x.get("helper"), "conversion_helper": x.get("conversion_helper"),
                "cfg_block_start": x.get("cfg_block_start"), "cfg_complete": x.get("cfg_complete"),
                "cfg_dominates_all_normal_returns": x.get("cfg_dominates_all_normal_returns"),
                "requiredness": x.get("requiredness"),
            } for x in rows],
        })

    complete = sum(bool(x["complete"]) for x in cfgs.values())
    report = {
        "schema": SCHEMA,
        "scope": "C5 conservative intraprocedural CFG/dominator response requiredness over C3 exact helper accesses",
        "source_c3_schema": c3.get("schema"), "source_c3_access_count": len(c3.get("accesses", [])),
        "method_count": len(cfgs), "cfg_complete_method_count": complete,
        "cfg_incomplete_method_count": len(cfgs) - complete,
        "requiredness_counts": dict(sorted(Counter(x["requiredness"] for x in accesses).items())),
        "contract_requiredness_counts": dict(sorted(Counter(x["requiredness"] for x in contracts).items())),
        "access_count": len(accesses), "contract_count": len(contracts),
        "contracts": contracts, "accesses": accesses,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        lines = ["# C5 response requiredness", "",
                 "Conservative intraprocedural ARM64 CFG/dominator evidence over C3 exact parser-helper accesses.", "",
                 f"- C3 accesses: **{report['source_c3_access_count']}**",
                 f"- parser methods: **{report['method_count']}**",
                 f"- complete CFGs: **{report['cfg_complete_method_count']}**",
                 f"- incomplete CFGs: **{report['cfg_incomplete_method_count']}**",
                 f"- field contracts: **{report['contract_count']}**", "", "## Access requiredness", ""]
        lines += [f"- `{k}`: **{v}**" for k, v in report["requiredness_counts"].items()]
        lines += ["", "## Contract requiredness", ""]
        lines += [f"- `{k}`: **{v}**" for k, v in report["contract_requiredness_counts"].items()]
        lines += ["", "`required-path` means the access block dominates every reachable normal RET in a complete bounded parser CFG; it is not a production-backend business-semantics claim.", ""]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("source_c3_access_count", "method_count", "cfg_complete_method_count", "cfg_incomplete_method_count", "requiredness_counts", "contract_count")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
