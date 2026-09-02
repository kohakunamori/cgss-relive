from __future__ import annotations

import unittest

from server import api_registry


def make_complete_map() -> dict[str, list[list[object]]]:
    a = [[f"A{key}", key, f"test/a/{key}", key + 1000] for key in range(516)]
    a[0] = ["VersionCheck", 0, "load/check", 28434]
    a[10] = ["Title", 10, "load/title", 28438]
    a[11] = ["Load", 11, "load/index", 28436]
    a[81][2] = "room/levelup"
    a[82][2] = "room/levelup"
    a[234] = ["HomeCustomizeUpdate", 234, "home/update", 26713]
    b_keys = [0, 1, 2, *range(8, 27)]
    b = [[f"B{key}", key, f"vr/test/{key}", key + 2000] for key in b_keys]
    return {"A": a, "B": b}


class ApiRegistryTests(unittest.TestCase):
    def test_final_load_surface(self) -> None:
        self.assertEqual(
            [(entry.key, entry.name, entry.path) for entry in api_registry.A_LOAD_ENDPOINTS],
            [
                (0, "VersionCheck", "load/check"),
                (1, "SetCacheClearFlg", "load/set_cache_clear_flg"),
                (10, "Title", "load/title"),
                (11, "Load", "load/index"),
                (12, "LoadGetExternalSiteUrl", "load/get_external_site_url"),
                (13, "LoadUpdateAgreementStatus", "load/update_agreement_status"),
            ],
        )

    def test_bootstrap_routes_are_registry_backed(self) -> None:
        self.assertEqual(
            api_registry.BOOTSTRAP_HTTP_ROUTES,
            frozenset(
                {
                    "/load/check",
                    "/load/set_cache_clear_flg",
                    "/load/title",
                    "/load/index",
                    "/load/update_agreement_status",
                }
            ),
        )
        self.assertEqual(
            api_registry.EMPTY_SUCCESS_HTTP_ROUTES,
            frozenset({"/load/set_cache_clear_flg", "/load/update_agreement_status"}),
        )

    def test_home_is_update_only_in_verified_runtime_subset(self) -> None:
        self.assertEqual(api_registry.HOME_CUSTOMIZE_UPDATE.key, 234)
        self.assertEqual(api_registry.HOME_CUSTOMIZE_UPDATE.path, "home/update")

    def test_vr_group_stays_separate(self) -> None:
        self.assertEqual(api_registry.VR_LOGIN_CHECK.path, "vr/login/check")
        self.assertEqual(api_registry.VR_LOAD.path, "vr/login/load")

    def test_complete_runtime_map_parser_preserves_aliases(self) -> None:
        endpoints = api_registry.parse_delivered_map(make_complete_map())
        self.assertEqual(len(endpoints), 538)
        index = api_registry.by_http_path(endpoints)
        self.assertEqual([endpoint.key for endpoint in index["/room/levelup"]], [81, 82])
        self.assertEqual(index["/home/update"][0].name, "HomeCustomizeUpdate")

    def test_complete_runtime_map_parser_rejects_holes(self) -> None:
        raw = make_complete_map()
        raw["A"].pop(100)
        with self.assertRaisesRegex(ValueError, "group A key coverage mismatch"):
            api_registry.parse_delivered_map(raw)


if __name__ == "__main__":
    unittest.main()
