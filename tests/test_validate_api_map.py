from __future__ import annotations

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "validate-api-map.py"
SPEC = importlib.util.spec_from_file_location("validate_api_map", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def make_map() -> dict[str, list[list[object]]]:
    group_a = [[f"A{key}", key, f"test/a/{key}", key + 1000] for key in range(516)]
    by_key = {entry[1]: entry for entry in group_a}
    by_key[0][:] = ["VersionCheck", 0, "load/check", 28434]
    by_key[1][:] = ["SetCacheClearFlg", 1, "load/set_cache_clear_flg", 28437]
    by_key[10][:] = ["Title", 10, "load/title", 28438]
    by_key[11][:] = ["Load", 11, "load/index", 28436]
    by_key[12][:] = ["LoadGetExternalSiteUrl", 12, "load/get_external_site_url", 28435]
    by_key[13][:] = ["LoadUpdateAgreementStatus", 13, "load/update_agreement_status", 28439]
    by_key[81][2] = "room/levelup"
    by_key[82][2] = "room/levelup"
    by_key[234][:] = ["HomeCustomizeUpdate", 234, "home/update", 26713]

    b_keys = [0, 1, 2, *range(8, 27)]
    group_b = [[f"B{key}", key, f"vr/test/{key}", key + 2000] for key in b_keys]
    return {"A": group_a, "B": group_b}


class ValidateApiMapTests(unittest.TestCase):
    def test_valid_complete_map(self) -> None:
        report = MODULE.validate_map(make_map())
        self.assertEqual(report["groups"], {"A": 516, "B": 22})
        self.assertEqual(
            [entry["path"] for entry in report["load_entries"]],
            [
                "load/check",
                "load/set_cache_clear_flg",
                "load/title",
                "load/index",
                "load/get_external_site_url",
                "load/update_agreement_status",
            ],
        )
        self.assertEqual(report["home_entries"][0]["path"], "home/update")
        self.assertIn("room/levelup", report["alias_paths"])

    def test_missing_a_key_is_rejected(self) -> None:
        raw = make_map()
        raw["A"].pop()
        with self.assertRaisesRegex(ValueError, "group A key coverage mismatch"):
            MODULE.validate_map(raw)

    def test_duplicate_b_key_is_rejected(self) -> None:
        raw = make_map()
        raw["B"].append(list(raw["B"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate keys"):
            MODULE.validate_map(raw)

    def test_absolute_path_is_rejected(self) -> None:
        raw = make_map()
        raw["A"][0][2] = "/load/check"
        with self.assertRaisesRegex(ValueError, "relative path"):
            MODULE.validate_map(raw)


if __name__ == "__main__":
    unittest.main()
