from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from server.domain import SQLiteDomainStore
from server.domain_server import provision_archival_profile


class DomainServerProvisioningTests(unittest.TestCase):
    def test_provisioning_creates_stable_starter_card_and_unit_idempotently(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "domain.sqlite3"
            first = provision_archival_profile(
                path,
                player_id="archival-player",
                producer_name="Relive Producer",
                starter_card_id=100001,
                initial_stamina=100,
                master_revision="10133800",
                resource_revision="10133800",
            )
            second = provision_archival_profile(
                path,
                player_id="archival-player",
                producer_name="Ignored after first bootstrap",
                starter_card_id=100002,
                initial_stamina=999,
                master_revision="10133800",
                resource_revision="10133800",
            )
            self.assertEqual(first, "card:1")
            self.assertEqual(second, "card:1")

            with SQLiteDomainStore.open(
                path,
                master_revision="10133800",
                resource_revision="10133800",
            ) as domain:
                snapshot = domain.get_home_snapshot("archival-player")
                self.assertIsNotNone(snapshot)
                assert snapshot is not None
                self.assertEqual(snapshot.profile.name, "Relive Producer")
                self.assertEqual(len(snapshot.cards), 1)
                self.assertEqual(snapshot.cards[0].master_card_id, 100001)
                self.assertEqual(snapshot.resources[0].resource_kind, "stamina")
                self.assertEqual(snapshot.resources[0].amount, 100)
                self.assertEqual(len(snapshot.units), 1)
                self.assertEqual(snapshot.units[0].slot, 0)
                self.assertEqual(snapshot.units[0].members[0].user_card_id, "card:1")

    def test_provisioning_rejects_invalid_policy_values(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "domain.sqlite3"
            with self.assertRaises(ValueError):
                provision_archival_profile(
                    path,
                    player_id="",
                    producer_name="Relive",
                    starter_card_id=100001,
                    initial_stamina=100,
                    master_revision="10133800",
                    resource_revision="10133800",
                )
            with self.assertRaises(ValueError):
                provision_archival_profile(
                    path,
                    player_id="p",
                    producer_name="Relive",
                    starter_card_id=0,
                    initial_stamina=100,
                    master_revision="10133800",
                    resource_revision="10133800",
                )


if __name__ == "__main__":
    unittest.main()
