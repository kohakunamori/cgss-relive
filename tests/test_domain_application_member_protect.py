from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.application import MemberProtectConfig, MemberProtectController
from server.domain import (
    BootstrapPolicy,
    FixedClock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
)


class MemberProtectApplicationTests(unittest.TestCase):
    def test_controller_toggles_domain_state_and_returns_authoritative_membership(self) -> None:
        with TemporaryDirectory() as tmp:
            now = datetime(2026, 9, 5, 5, 30, tzinfo=timezone.utc)
            domain = SQLiteDomainStore.open(Path(tmp) / "domain.sqlite3")
            identities = SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3")
            try:
                profiles = PreservationProfileService(
                    domain,
                    clock=FixedClock(now),
                    ids=SequentialIdGenerator(),
                )
                profiles.bootstrap_profile(
                    BootstrapPolicy(
                        name="Archive",
                        starter_cards=(
                            StarterCardGrant(100001, is_protected=False),
                            StarterCardGrant(100002, is_protected=True),
                        ),
                    ),
                    player_id="player:archive",
                )
                self.assertEqual(identities.ensure_card_serial("player:archive", "card:1"), 1)
                self.assertEqual(identities.ensure_card_serial("player:archive", "card:2"), 2)

                controller = MemberProtectController(
                    profiles,
                    identities,
                    config=MemberProtectConfig("player:archive"),
                )

                first = controller.handle({"serial_ids": [1, 2]})
                self.assertEqual(first, {"protect_card_list": [1]})
                self.assertEqual(
                    [card.is_protected for card in profiles.get_home_snapshot("player:archive").cards],
                    [True, False],
                )

                second = controller.handle({"serial_ids": [1, 2]})
                self.assertEqual(second, {"protect_card_list": [2]})
                self.assertEqual(
                    [card.is_protected for card in profiles.get_home_snapshot("player:archive").cards],
                    [False, True],
                )
            finally:
                identities.close()
                domain.close()

    def test_controller_rejects_unknown_or_duplicate_serial_before_mutation(self) -> None:
        with TemporaryDirectory() as tmp:
            now = datetime(2026, 9, 5, 5, 30, tzinfo=timezone.utc)
            domain = SQLiteDomainStore.open(Path(tmp) / "domain.sqlite3")
            identities = SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3")
            try:
                profiles = PreservationProfileService(
                    domain,
                    clock=FixedClock(now),
                    ids=SequentialIdGenerator(),
                )
                profiles.bootstrap_profile(
                    BootstrapPolicy(
                        name="Archive",
                        starter_cards=(StarterCardGrant(100001),),
                    ),
                    player_id="player:archive",
                )
                identities.ensure_card_serial("player:archive", "card:1")
                controller = MemberProtectController(
                    profiles,
                    identities,
                    config=MemberProtectConfig("player:archive"),
                )

                for request in ({"serial_ids": [999]}, {"serial_ids": [1, 1]}):
                    with self.subTest(request=request):
                        with self.assertRaises(ValueError):
                            controller.handle(request)
                        self.assertFalse(
                            profiles.get_home_snapshot("player:archive").cards[0].is_protected
                        )
            finally:
                identities.close()
                domain.close()


if __name__ == "__main__":
    unittest.main()
