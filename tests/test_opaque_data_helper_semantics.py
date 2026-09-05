import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-opaque-data-helper-semantics.py"
SPEC = importlib.util.spec_from_file_location("c21_helper_semantics", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class OpaqueDataHelperSemanticsTests(unittest.TestCase):
    def test_item_index_kind_uses_managed_signature(self):
        self.assertEqual(MOD.item_index_kind("JsonData* get_Item(JsonData* self, System_String_o* prop_name, MethodInfo* m);"), "string-key")
        self.assertEqual(MOD.item_index_kind("JsonData* get_Item(JsonData* self, int32_t index, MethodInfo* m);"), "integer-index")

    def test_json_operation_and_shape_refinement(self):
        op = MOD.json_operation([{
            "name": "LitJson.JsonData$$get_Item",
            "signature": "LitJson_JsonData_o* get_Item(LitJson_JsonData_o* self, System_String_o* key, MethodInfo* m);",
        }])
        self.assertEqual(op, "json-index-string")
        self.assertEqual(MOD.shape_from_operations(["json-index-string"]), "helper-proven-object")
        self.assertEqual(MOD.shape_from_operations(["json-index-int"]), "helper-proven-array")
        self.assertEqual(MOD.shape_from_operations(["json-count"]), "helper-countable-ambiguous")
        self.assertEqual(MOD.shape_from_operations(["json-to-json"]), "helper-opaque-json")
        self.assertEqual(MOD.shape_from_operations([]), "helper-unresolved")


if __name__ == "__main__":
    unittest.main()
