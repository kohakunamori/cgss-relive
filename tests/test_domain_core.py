from __future__ import annotations

from datetime import datetime, timezone
import unittest

from server.domain import (
    ChangeOperation,
    ChangeSet,
    EntityChange,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    FixedClock,
    ResourceChange,
    Reward,
    SeededRandomSource,
    SequentialIdGenerator,
)


class DomainCoreTests(unittest.TestCase):
    def test_reward_requires_positive_quantity_and_freezes_metadata(self) -> None:
        reward = Reward("item", 2, master_ref_id=123, metadata={"source": "test"})
        self.assertEqual(reward.quantity, 2)
        self.assertEqual(reward.metadata["source"], "test")
        with self.assertRaises(TypeError):
            reward.metadata["source"] = "mutated"  # type: ignore[index]
        with self.assertRaises(ValueError):
            Reward("item", 0)

    def test_changeset_is_wire_independent_and_detects_empty(self) -> None:
        self.assertTrue(ChangeSet().is_empty)

        evidence = Evidence(
            EvidenceStatus.PROVEN_STATIC,
            EvidenceKind.EXACT,
            source="client-semantic-db",
        )
        change = EntityChange(
            category="card",
            entity_id="card:1",
            operation=ChangeOperation.UPDATE,
            values={"favorite": True},
            evidence=evidence,
        )
        changeset = ChangeSet(
            resources=(ResourceChange("stamina", -5, resulting_amount=95),),
            entities=(change,),
        )
        self.assertFalse(changeset.is_empty)
        self.assertEqual(changeset.entities[0].category, "card")
        self.assertEqual(changeset.entities[0].evidence.status, EvidenceStatus.PROVEN_STATIC)

    def test_fixed_clock_requires_offset_aware_time(self) -> None:
        instant = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(FixedClock(instant).now(), instant)
        with self.assertRaises(ValueError):
            FixedClock(datetime(2026, 9, 4, 12, 0))

    def test_seeded_random_source_is_reproducible(self) -> None:
        left = SeededRandomSource(12345)
        right = SeededRandomSource(12345)
        self.assertEqual(
            [left.randbelow(1000) for _ in range(8)],
            [right.randbelow(1000) for _ in range(8)],
        )
        with self.assertRaises(ValueError):
            left.randbelow(0)

    def test_sequential_ids_are_namespaced_and_deterministic(self) -> None:
        ids = SequentialIdGenerator()
        self.assertEqual(ids.new_id("live"), "live:1")
        self.assertEqual(ids.new_id("card"), "card:1")
        self.assertEqual(ids.new_id("live"), "live:2")
        with self.assertRaises(ValueError):
            ids.new_id("")


if __name__ == "__main__":
    unittest.main()
