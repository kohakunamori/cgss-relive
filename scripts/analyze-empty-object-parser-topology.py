#!/usr/bin/env python3
"""C19: inventory final-client parser topology after ``data.get_Keys``.

C17 identified 36 low-complexity routes whose only concrete business response
field is top-level ``data`` and whose native conversion evidence is
``LitJson.JsonData.get_Keys``.  This pass does not assume that ``data={}`` is
accepted.  It disassembles each exact final parser and exports a sanitized
post-get_Keys topology:

* managed direct call sequence and target names;
* conditional/unconditional/indirect branch counts;
* whether another LitJson JsonData index/conversion call appears;
* reachable RET / validated managed tail-exit counts via a conservative CFG;
* whether the get_Keys block dominates all known exits.

No native bytes, operands, response values or automatic empty-object promotion
are exported.
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
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x20000
MAX_POST_KEYS_CALLS = 64


@dataclass
class Block:
    start: int
    insns: list[int]
    successors: set[int]
    predecessors: set[int]
    terminal: str = "fallthrough"
    terminal_target: int | None = None


class TopologyError(ValueError):
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


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TopologyError(f"invalid RVA {value!r}")


def load_methods(path: Path) -> tuple[list[int], dict[int, list[dict[str, str | None]]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    managed: dict[int, list[dict[str, str | None]]] = defaultdict(list)
    for row in raw.get("ScriptMethod", []):
        rva = _as_int(row.get("Address", 0))
        if rva <= 0:
            continue
        starts.add(rva)
        name = str(row.get("Name") or "")
        sig = row.get("Signature")
        if name:
            managed[rva].append({"name": name, "signature": str(sig) if sig else None})
    for value in raw.get("Addresses", []):
        rva = _as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in managed.values():
        rows.sort(key=lambda row: str(row["name"]))
    return sorted(starts), dict(managed), set(managed)


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    end = starts[index] if index < len(starts) else start + MAX_FUNCTION_SIZE
    return min(end, start + MAX_FUNCTION_SIZE)


def _target(ins: Any) -> int | None:
    if not ins.operands or ins.operands[-1].type != ARM64_OP_IMM:
        return None
    return int(ins.operands[-1].imm)


def _is_conditional(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}


def build_cfg(
    view: BinaryView,
    start: int,
    end: int,
    managed_starts: set[int],
) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, max(0, end - start)), start))
    if not insns or int(insns[0].address) != start:
        return {
            "complete": False, "reason": "entry-not-disassembled", "blocks": {},
            "addr_block": {}, "reachable": set(), "known_exits": set(),
            "returns": set(), "tail_exits": set(), "dom": {},
        }
    by = {int(ins.address): ins for ins in insns}
    addrs = sorted(by)
    nxt = {a: addrs[i + 1] if i + 1 < len(addrs) else None for i, a in enumerate(addrs)}
    leaders = {start}
    complete = True
    reasons: set[str] = set()
    for ins in insns:
        a = int(ins.address)
        m = ins.mnemonic.lower()
        if _is_conditional(m) or m == "b":
            target = _target(ins)
            if target is None:
                complete = False
                reasons.add("branch-without-target")
            elif start <= target < end:
                if target in by:
                    leaders.add(target)
                else:
                    complete = False
                    reasons.add("internal-target-not-disassembled")
            elif _is_conditional(m):
                complete = False
                reasons.add("conditional-external-target")
            if nxt[a] is not None:
                leaders.add(nxt[a])
        elif m in {"br", "braa", "brab", "ret", "retaa", "retab", "eret"}:
            if nxt[a] is not None:
                leaders.add(nxt[a])
            if m in {"br", "braa", "brab"}:
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
        block_dst = addr_block.get(dst)
        if block_dst is None:
            if start <= dst < end:
                complete = False
                reasons.add("successor-not-in-cfg")
            return
        block.successors.add(block_dst)

    for block in blocks.values():
        a = block.insns[-1]
        ins = by[a]
        m = ins.mnemonic.lower()
        if m in {"ret", "retaa", "retab", "eret"}:
            block.terminal = "return"
        elif m in {"br", "braa", "brab"}:
            block.terminal = "indirect-branch"
        elif m == "b":
            target = _target(ins)
            block.terminal_target = target
            if target is not None and start <= target < end:
                block.terminal = "branch"
                edge(block, target)
            elif target is not None and target in managed_starts:
                block.terminal = "managed-tail-call-exit"
            else:
                block.terminal = "unverified-external-branch"
                complete = False
                reasons.add("unverified-external-tail-branch")
        elif _is_conditional(m):
            block.terminal = "conditional"
            target = _target(ins)
            block.terminal_target = target
            if target is not None and start <= target < end:
                edge(block, target)
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
    queue: deque[int] = deque([start]) if start in blocks else deque()
    while queue:
        current = queue.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        queue.extend(blocks[current].successors - reachable)
    returns = {b for b in reachable if blocks[b].terminal == "return"}
    tails = {b for b in reachable if blocks[b].terminal == "managed-tail-call-exit"}
    exits = returns | tails
    if not exits:
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
    return {
        "complete": complete,
        "reason": ",".join(sorted(reasons)) or None,
        "blocks": blocks,
        "addr_block": addr_block,
        "reachable": reachable,
        "known_exits": exits,
        "returns": returns,
        "tail_exits": tails,
        "dom": dom,
    }


def load_targets(c17_path: Path, c3_path: Path) -> list[dict[str, Any]]:
    c17 = json.loads(c17_path.read_text(encoding="utf-8"))
    c3 = json.loads(c3_path.read_text(encoding="utf-8"))
    if c17.get("schema") != 1 or c3.get("schema") != 1:
        raise TopologyError("C17/C3 schema mismatch")
    c3_by_origin: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in c3.get("accesses", []):
        if isinstance(row, dict):
            c3_by_origin[(str(row.get("task")), str(row.get("method")), str(row.get("field")))].append(row)
    targets = []
    for route in c17.get("routes", []):
        if not isinstance(route, dict) or route.get("route_class") != "data-only:proven-object":
            continue
        fields = route.get("fields")
        if not isinstance(fields, list) or len(fields) != 1:
            raise TopologyError(f"unexpected proven-object field shape for {route.get('route')}")
        field = fields[0]
        origin = (str(field.get("task")), str(field.get("method")), str(field.get("field")))
        rows = c3_by_origin.get(origin, [])
        keys_rows = [row for row in rows if "get_Keys" in str(row.get("conversion_helper") or "")]
        if not keys_rows:
            raise TopologyError(f"missing get_Keys C3 evidence for {route.get('route')}")
        conversion_rvas = sorted({int(row["conversion_rva"]) for row in keys_rows if isinstance(row.get("conversion_rva"), int)})
        method_rvas = sorted({int(row["method_rva"]) for row in keys_rows if isinstance(row.get("method_rva"), int)})
        if len(conversion_rvas) != 1 or len(method_rvas) != 1:
            raise TopologyError(f"non-unique get_Keys site for {route.get('route')}")
        targets.append({
            "route": route.get("route"),
            "endpoint_id": route.get("endpoint_id"),
            "task": origin[0],
            "method": origin[1],
            "field": origin[2],
            "requiredness": field.get("requiredness"),
            "method_rva": method_rvas[0],
            "get_keys_rva": conversion_rvas[0],
        })
    return targets


def classify_call(name: str) -> str:
    low = name.lower()
    if "litjson.jsondata$$get_item" in low:
        return "json-index"
    if "litjson.jsondata$$get_keys" in low:
        return "json-keys"
    if "litjson.jsondata$$get_count" in low:
        return "json-count"
    if "getenumerator" in low:
        return "enumerator"
    if "movenext" in low:
        return "move-next"
    if "get_count" in low or "get_length" in low:
        return "collection-count"
    if "get_item" in low:
        return "collection-index"
    if "add" in low:
        return "collection-add"
    return "other"


def analyze_target(
    target: dict[str, Any],
    view: BinaryView,
    starts: list[int],
    managed: dict[int, list[dict[str, str | None]]],
    managed_starts: set[int],
) -> dict[str, Any]:
    start = int(target["method_rva"])
    end = function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by_address = {int(ins.address): ins for ins in insns}
    if int(target["get_keys_rva"]) not in by_address:
        raise TopologyError(f"get_Keys site not in parser for {target['route']}")
    calls = []
    branch_counts = Counter()
    indirect_call_count = 0
    seen_keys = False
    for ins in insns:
        address = int(ins.address)
        if address == int(target["get_keys_rva"]):
            seen_keys = True
        if not seen_keys:
            continue
        m = ins.mnemonic.lower()
        if _is_conditional(m):
            branch_counts["conditional"] += 1
        elif m == "b":
            branch_counts["unconditional"] += 1
        elif m in {"br", "braa", "brab"}:
            branch_counts["indirect-branch"] += 1
        elif m in {"blr", "blraa", "blrab"}:
            indirect_call_count += 1
        if m == "bl":
            call_target = _target(ins)
            if call_target is None:
                continue
            methods = managed.get(call_target, [])
            if not methods:
                continue
            for method in methods:
                calls.append({
                    "callsite_rva": address,
                    "target_rva": call_target,
                    "target_method": method["name"],
                    "kind": classify_call(str(method["name"])),
                })
                if len(calls) >= MAX_POST_KEYS_CALLS:
                    break
            if len(calls) >= MAX_POST_KEYS_CALLS:
                break

    cfg = build_cfg(view, start, end, managed_starts)
    keys_block = cfg["addr_block"].get(int(target["get_keys_rva"]))
    keys_reachable = keys_block in cfg["reachable"] if keys_block is not None else False
    dominates = bool(
        keys_block is not None and keys_reachable and cfg["known_exits"] and
        all(keys_block in cfg["dom"].get(exit_block, set()) for exit_block in cfg["known_exits"])
    )
    kinds = Counter(row["kind"] for row in calls)
    result = dict(target)
    result.update({
        "cfg_complete": bool(cfg["complete"]),
        "cfg_incomplete_reason": cfg["reason"],
        "get_keys_cfg_block": keys_block,
        "get_keys_reachable": keys_reachable,
        "get_keys_dominates_all_known_exits": dominates,
        "reachable_return_count": len(cfg["returns"]),
        "reachable_managed_tail_exit_count": len(cfg["tail_exits"]),
        "post_keys_branch_counts": dict(sorted(branch_counts.items())),
        "post_keys_indirect_call_count": indirect_call_count,
        "post_keys_managed_call_count": len(calls),
        "post_keys_managed_call_kind_counts": dict(sorted(kinds.items())),
        "post_keys_managed_calls": calls,
        "post_keys_json_index_call_count": kinds.get("json-index", 0),
        "empty_object_promotion": "not-proven-by-c19-topology",
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c17", type=Path, required=True)
    parser.add_argument("--c3", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        targets = load_targets(args.c17, args.c3)
        starts, managed, managed_starts = load_methods(args.script_json)
        view = BinaryView(args.lib)
        try:
            routes = [analyze_target(row, view, starts, managed, managed_starts) for row in targets]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, TopologyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    signature_counts = Counter()
    complete_count = 0
    no_post_json_index = 0
    for row in routes:
        if row["cfg_complete"]:
            complete_count += 1
        if row["post_keys_json_index_call_count"] == 0:
            no_post_json_index += 1
        signature = (
            row["cfg_complete"],
            tuple(sorted(row["post_keys_managed_call_kind_counts"].items())),
            row["post_keys_indirect_call_count"],
        )
        signature_counts[str(signature)] += 1
    report = {
        "schema": SCHEMA,
        "scope": (
            "C19 final-client post-get_Keys parser topology for C17 data-only proven-object routes; "
            "sanitized call/control-flow inventory only, no empty-object acceptance inference"
        ),
        "target_route_count": len(routes),
        "cfg_complete_route_count": complete_count,
        "route_without_post_keys_json_index_count": no_post_json_index,
        "topology_signature_counts": dict(sorted(signature_counts.items())),
        "routes": sorted(routes, key=lambda row: str(row["route"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "cfg_complete_route_count": report["cfg_complete_route_count"],
        "route_without_post_keys_json_index_count": report["route_without_post_keys_json_index_count"],
        "topology_signature_count": len(report["topology_signature_counts"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
