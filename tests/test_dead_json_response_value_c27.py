import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from capstone.arm64 import ARM64_INS_B, ARM64_OP_IMM

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-dead-json-response-value-c27.py"
SPEC = importlib.util.spec_from_file_location("c27_hardened_runner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class FakeInsn:
    def __init__(self, address, mnemonic, ins_id=0, target=None):
        self.address = address
        self.mnemonic = mnemonic
        self.id = ins_id
        self.operands = [] if target is None else [SimpleNamespace(type=ARM64_OP_IMM, imm=target)]


class DeadJsonResponseValueC27Tests(unittest.TestCase):
    def test_conditional_b_keeps_target_and_fallthrough_even_with_b_id(self):
        insns = [
            FakeInsn(0x1000, "b.eq", ARM64_INS_B, 0x1008),
            FakeInsn(0x1004, "nop"),
            FakeInsn(0x1008, "ret"),
        ]
        succ, unresolved = MOD.hardened_instruction_successors(
            insns, 0x1000, 0x100C, set()
        )
        self.assertEqual(succ[0x1000], [0x1004, 0x1008])
        self.assertEqual(unresolved, [])

    def test_external_conditional_target_is_not_treated_as_tail_exit(self):
        insns = [
            FakeInsn(0x1000, "b.ne", ARM64_INS_B, 0x9000),
            FakeInsn(0x1004, "ret"),
        ]
        succ, unresolved = MOD.hardened_instruction_successors(
            insns, 0x1000, 0x1008, {0x9000}
        )
        self.assertEqual(succ[0x1000], [0x1004])
        self.assertEqual(unresolved[0]["kind"], "conditional-target-unresolved")


if __name__ == "__main__":
    unittest.main()
