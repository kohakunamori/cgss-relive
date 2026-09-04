#!/usr/bin/env python3
"""Hardened entry point for C27 dead JsonData value analysis.

Capstone represents AArch64 conditional ``b.<cond>`` forms with the same broad
instruction family as ``b`` on some builds.  The base C27 implementation is kept
as the dataflow engine, while this runner patches branch transfer/successor logic
to classify conditional branches *before* unconditional B.  This prevents a
missing fallthrough edge from ever producing a false dead-value proof.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from capstone.arm64 import ARM64_INS_B

ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "scripts" / "analyze-dead-json-response-value.py"
SPEC = importlib.util.spec_from_file_location("c27_dead_value_base", BASE_PATH)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

_ORIGINAL_TRANSFER = BASE.transfer


def hardened_transfer(ins: Any, md: Any, state: Any, managed_starts: set[int]):
    mnemonic = ins.mnemonic.lower()
    if BASE.is_conditional_branch(mnemonic):
        regs = set(state.regs)
        stack = set(state.stack)
        reads = BASE._read_regs(ins, md)
        tainted_reads = sorted(reads & regs)
        sinks = []
        if tainted_reads:
            sinks.append({
                "kind": "conditional-branch-register-use",
                "rva": int(ins.address),
                "mnemonic": mnemonic,
                "tainted_registers": tainted_reads,
            })
        # Conditional branches do not define general-purpose data registers.
        return BASE.State(frozenset(regs), frozenset(stack)), sinks, None
    return _ORIGINAL_TRANSFER(ins, md, state, managed_starts)


def hardened_instruction_successors(insns: list[Any], start: int, end: int, managed_starts: set[int]):
    by = {int(ins.address): ins for ins in insns}
    addrs = sorted(by)
    next_addr = {
        addr: addrs[i + 1] if i + 1 < len(addrs) else None
        for i, addr in enumerate(addrs)
    }
    succ: dict[int, list[int]] = {}
    unresolved: list[dict[str, Any]] = []
    for addr in addrs:
        ins = by[addr]
        mnemonic = ins.mnemonic.lower()
        nxt = next_addr[addr]
        targets: list[int] = []
        if BASE.is_ret(mnemonic):
            targets = []
        elif BASE.is_conditional_branch(mnemonic):
            target = BASE.branch_target(ins)
            if target is None or not (start <= target < end) or target not in by:
                unresolved.append({
                    "rva": addr,
                    "kind": "conditional-target-unresolved",
                    "target_rva": target,
                })
            else:
                targets.append(target)
            if nxt is not None:
                targets.append(nxt)
        elif ins.id == ARM64_INS_B:
            target = BASE.branch_target(ins)
            if target is not None and start <= target < end and target in by:
                targets = [target]
            elif target is not None and target in managed_starts:
                targets = []
            else:
                unresolved.append({
                    "rva": addr,
                    "kind": "unverified-external-branch",
                    "target_rva": target,
                })
                targets = []
        elif mnemonic in {"br", "braa", "brab"}:
            unresolved.append({
                "rva": addr,
                "kind": "indirect-branch",
                "target_rva": None,
            })
            targets = []
        else:
            targets = [nxt] if nxt is not None else []
        succ[addr] = sorted(set(value for value in targets if value is not None))
    return succ, unresolved


BASE.transfer = hardened_transfer
BASE.instruction_successors = hardened_instruction_successors


def main() -> int:
    return BASE.main()


if __name__ == "__main__":
    raise SystemExit(main())
