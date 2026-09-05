from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from server.domain.card_services import PreservationCardService
from server.domain import (
    BootstrapPolicy,
    FixedClock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
)


class PreservationCardServiceTests(unittest.TestCase):
    def test_set_favorites_is_explicit_atomic_and_preserves_other_card_state(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "domain.sqlite3"
            clock = FixedClock(datetime(2026, 9, 5, 6, 0, tzinfo=timezone.utc))
            with SQLiteDomainStore.open(path) as domain:
                profiles = PreservationProfileService(
                    domain,
                    clock=clock,
                    ids=SequentialIdGenerator(),
                )
                profiles.bootstrap_profile(
                    BootstrapPolicy(
                        name="Archive Producer",
                        starter_cards=(
                            StarterCardGrant(100001, skill_level=3, is_protected=True),
                            StarterCardGrant(100002, favorite=True),
                        ),
                    ),
                    player_id="player",
                )
                service = PreservationCardService(domain)

                changes = service.set_favorites(
                    "player",
                    (("card:1", True), ("card:2", False)),
                )
                self.assertEqual(len(changes.entities), 2)
                self.assertEqual(changes.metadata["command_semantics"], "member-favorite-explicit-set")

                cards = {card.user_card_id: card for card in domain.list_cards("player")}
                self.assertTrue(cards["card:1"].favorite)
                self.assertTrue(cards["card:1"].is_protected)
                self.assertEqual(cards["card:1"].skill_level, 3)
                self.assertFalse(cards["card:2"].favorite)

                no_op = service.set_favorites("player", (("card:1", True),))
                self.assertFalse(no_op.entities)

    def test_set_favorites_validates_entire_batch_before_writing(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "domain.sqlite3"
            clock = FixedClock(datetime(2026, 9, 5, 6, 0, tzinfo=timezone.utc))
            with SQLiteDomainStore.open(path) as domain:
                profiles = PreservationProfileService(
                    domain,
                    clock=clock,
                    ids=SequentialIdGenerator(),
                )
                profiles.bootstrap_profile(
                    BootstrapPolicy(
                        name="Archive Producer",
                        starter_cards=(StarterCardGrant(100001),),
                    ),
                    player_id="player",
                )
                service = PreservationCardService(domain)

                with self.assertRaises(KeyError):
                    service.set_favorites(
                        "player",
                        (("card:1", True), ("card:missing", True)),
                    )
                self.assertFalse(domain.list_cards("player")[0].favorite)

                with self.assertRaises(ValueError):
                    service.set_favorites(
                        "player",
                        (("card:1", True), ("card:1", False)),
                    )
                self.assertFalse(domain.list_cards("player")[0].favorite)


if __name__ == "__main__":
    unittest.main()
