"""Route-independent preservation-domain commands for unit membership state."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .core import ChangeOperation, ChangeSet, EntityChange, Evidence, EvidenceKind, EvidenceStatus
from .models import UnitMember
from .repositories import PlayerStateRepository


_UNIT_MEMBERSHIP_EVIDENCE = Evidence(
    EvidenceStatus.PROVEN_STATIC,
    EvidenceKind.EXACT,
    source="final-11.6.3 WorkUnitData/user_unit_list",
    note=(
        "final client persists ordered unit member positions as owned-card serial references; "
        "endpoint-specific UnitEdit request/response semantics are tracked separately"
    ),
)


@dataclass(frozen=True)
class UnitMembershipUpdate:
    """Replacement ordered membership for one semantic unit identity."""

    unit_id: str
    members: tuple[UnitMember, ...]

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("unit_id must be non-empty")
        members = tuple(self.members)
        if len({member.position for member in members}) != len(members):
            raise ValueError("unit member positions must be unique")
        object.__setattr__(self, "members", members)


class PreservationUnitService:
    """Unit mutations independent of CGSS numeric IDs and endpoint DTOs."""

    def __init__(self, repository: PlayerStateRepository) -> None:
        self._repository = repository

    def replace_members(
        self,
        player_id: str,
        updates: tuple[UnitMembershipUpdate, ...],
    ) -> ChangeSet:
        """Atomically replace membership for one or more existing player units.

        All units and all referenced cards are resolved before the first write so a
        malformed client-facing request cannot leave a partially updated profile.
        Slot/name/costume semantics are deliberately outside this command until an
        endpoint-specific contract proves they belong to the same mutation.
        """

        if not player_id:
            raise ValueError("player_id must be non-empty")
        requested = tuple(updates)
        if not requested:
            return ChangeSet()
        unit_ids = [update.unit_id for update in requested]
        if len(set(unit_ids)) != len(unit_ids):
            raise ValueError("duplicate unit updates are not allowed")

        units = {unit.unit_id: unit for unit in self._repository.list_units(player_id)}
        missing_units = [unit_id for unit_id in unit_ids if unit_id not in units]
        if missing_units:
            raise KeyError(
                f"unknown units for archival player {player_id!r}: {missing_units!r}"
            )

        owned_cards = {
            card.user_card_id for card in self._repository.list_cards(player_id)
        }
        missing_cards = sorted(
            {
                member.user_card_id
                for update in requested
                for member in update.members
                if member.user_card_id not in owned_cards
            }
        )
        if missing_cards:
            raise KeyError(
                f"unknown owned cards for archival player {player_id!r}: {missing_cards!r}"
            )

        replacements = [
            replace(units[update.unit_id], members=update.members)
            for update in requested
        ]
        changed = [
            unit
            for unit, update in zip(replacements, requested, strict=True)
            if units[update.unit_id].members != unit.members
        ]
        if not changed:
            return ChangeSet()

        with self._repository.transaction():
            for unit in changed:
                self._repository.save_unit(unit)

        return ChangeSet(
            entities=tuple(
                EntityChange(
                    category="unit",
                    entity_id=unit.unit_id,
                    operation=ChangeOperation.UPDATE,
                    values={
                        "members": tuple(
                            (member.position, member.user_card_id)
                            for member in unit.members
                        )
                    },
                    evidence=_UNIT_MEMBERSHIP_EVIDENCE,
                )
                for unit in changed
            )
        )
