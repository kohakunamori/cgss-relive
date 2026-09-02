from __future__ import annotations

import unittest

from server import api_registry


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
            frozenset({"/load/check", "/load/title", "/load/index"}),
        )

    def test_home_is_update_only_in_verified_runtime_subset(self) -> None:
        self.assertEqual(api_registry.HOME_CUSTOMIZE_UPDATE.key, 234)
        self.assertEqual(api_registry.HOME_CUSTOMIZE_UPDATE.path, "home/update")

    def test_vr_group_stays_separate(self) -> None:
        self.assertEqual(api_registry.VR_LOGIN_CHECK.path, "vr/login/check")
        self.assertEqual(api_registry.VR_LOAD.path, "vr/login/load")


if __name__ == "__main__":
    unittest.main()
