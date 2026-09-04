from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-inherited-base-contracts.py"
SPEC = importlib.util.spec_from_file_location("analyze_inherited_base_contracts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class InheritedBaseContractParserTests(unittest.TestCase):
    def test_il2cppdumper_namespace_and_typedef_comments(self) -> None:
        text = """
// Namespace: Stage
public class NetworkTask : object // TypeDefIndex: 100
{
}
// Namespace: Stage
public class RankingTaskBase : NetworkTask // TypeDefIndex: 101
{
}
// Namespace: Stage
public class AtaponRankingTask : RankingTaskBase // TypeDefIndex: 102
{
}
// Namespace: Stage
public class DerivedWithInterfaces : AtaponRankingTask, IDisposable // TypeDefIndex: 103
{
}
// Namespace:
public class GlobalType : object // TypeDefIndex: 104
{
}
""".lstrip()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dump.cs"
            path.write_text(text, encoding="utf-8")
            inheritance = module.parse_inheritance(path)

        self.assertEqual(inheritance["Stage.NetworkTask"], "Stage.object")
        self.assertEqual(inheritance["Stage.RankingTaskBase"], "Stage.NetworkTask")
        self.assertEqual(inheritance["Stage.AtaponRankingTask"], "Stage.RankingTaskBase")
        self.assertEqual(inheritance["Stage.DerivedWithInterfaces"], "Stage.AtaponRankingTask")
        self.assertEqual(inheritance["GlobalType"], "object")
        self.assertTrue(
            module.derives_from(
                "Stage.DerivedWithInterfaces",
                "Stage.RankingTaskBase",
                inheritance,
            )
        )
        self.assertFalse(
            module.derives_from(
                "Stage.RankingTaskBase",
                "Stage.AtaponRankingTask",
                inheritance,
            )
        )

    def test_normal_namespace_syntax_remains_supported(self) -> None:
        text = """
namespace Stage
{
public class BaseTask : object
{
}
public class ConcreteTask : BaseTask
{
}
""".lstrip()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dummy.cs"
            path.write_text(text, encoding="utf-8")
            inheritance = module.parse_inheritance(path)
        self.assertEqual(inheritance["Stage.ConcreteTask"], "Stage.BaseTask")
        self.assertTrue(module.derives_from("Stage.ConcreteTask", "Stage.BaseTask", inheritance))


if __name__ == "__main__":
    unittest.main()
