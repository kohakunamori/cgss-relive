from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from server.application import DomainLoadIndexConfig, DomainLoadIndexController
from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.domain import (
    BootstrapPolicy,
    FixedClock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
    Unit,
    UnitMember,
)
from server.minimal_profile import STARTER_WORK_CARD_SECTION


class DomainLoadIndexControllerTests(unittest.TestCase):
    def _build_stack(self, tmp: str):
        clock = FixedClock(datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc))
        domain = SQLiteDomainStore.open(Path(tmp) / "domain.sqlite3", master_revision="10133800")
        identities = SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3")
        service = PreservationProfileService(
            domain,
            clock=clock,
            ids=SequentialIdGenerator(),
        )
        return clock, domain, identities, service

    def test_controller_bootstraps_explicit_policy_and_projects_current_state(self) -> None:
        with TemporaryDirectory() as tmp:
            clock, domain, identities, service = self._build_stack(tmp)
            try:
                config = DomainLoadIndexConfig(
                    player_id="archival-player",
                    viewer_id=77,
                    bootstrap_policy=BootstrapPolicy(
                        name="Relive Producer",
                        initial_resources={"stamina": 100, "gold": 50},
                        starter_cards=(StarterCardGrant(100001, skill_level=1),),
                    ),
                )
                controller = DomainLoadIndexController(
                    service,
                    identities,
                    clock=clock,
                    config=config,
                )

                first = controller.build_data()
                cards = first[STARTER_WORK_CARD_SECTION]
                self.assertIsInstance(cards, list)
                self.assertEqual(cards[0]["serial_id"], 1)
                self.assertEqual(cards[0]["card_id"], 100001)
                self.assertEqual(first["user_info"]["stamina"], 100)
                self.assertEqual(first["user_info"]["gold"], 50)

                snapshot = service.get_home_snapshot("archival-player")
                owned = snapshot.cards[0]
                domain.save_unit(
                    Unit(
                        unit_id="unit:home",
                        player_id="archival-player",
                        slot=0,
                        name="Relive Unit",
                        members=(UnitMember(0, owned.user_card_id),),
                    )
                )

                second = controller.build_data()
                self.assertEqual(second[STARTER_WORK_CARD_SECTION][0]["serial_id"], 1)
                self.assertEqual(second["user_unit_list"][0]["unit_id"], 1)
                self.assertEqual(second["user_unit_list"][0]["unit_slot"], 1)
                self.assertEqual(second["user_unit_list"][0]["serial_id_0"], 1)
                self.assertEqual(second["user_unit_list"][0]["serial_id_1"], 0)
            finally:
                identities.close()
                domain.close()

    def test_controller_does_not_create_missing_profile_without_policy(self) -> None:
        with TemporaryDirectory() as tmp:
            clock, domain, identities, service = self._build_stack(tmp)
            try:
                controller = DomainLoadIndexController(
                    service,
                    identities,
                    clock=clock,
                    config=DomainLoadIndexConfig(player_id="missing", viewer_id=1),
                )
                with self.assertRaises(KeyError):
                    controller.build_data()
                self.assertIsNone(domain.get_profile("missing"))
            finally:
                identities.close()
                domain.close()


if __name__ == "__main__":
    unittest.main()
