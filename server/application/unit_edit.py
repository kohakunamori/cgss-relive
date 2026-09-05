"""Application/controller for final-11.6.3 A:19 ``unit/edit`` mutations.

This layer owns conversion from client-facing numeric unit/card identities into
preservation-domain identities.

Exact final-client native evidence closes the endpoint response boundary:
``MemberUnitEditTask.Parse`` is an 8-byte two-instruction tail call to
``BaseTask.Parse`` and consumes no endpoint-specific response data.  Therefore
``handle()`` returns an empty data mapping for the common CGSS success envelope.

The three dress/costume arrays are validated as parallel five-slot compatibility
state but are not persisted into the semantic domain yet. ``main_unit_id`` is
likewise preserved by the request adapter but not assigned domain meaning here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.adapters.unit_edit import MemberUnitEditRequest, parse_member_unit_edit_request
from server.domain import (
    ChangeSet,
    PreservationUnitService,
    SQLiteDomainStore,
    UnitMember,
    UnitMembershipUpdate,
)
from server.minimal_profile import FINAL_UNIT_SLOT_COUNT


@dataclass(frozen=True)
class MemberUnitEditConfig:
    player_id: str

    def __post_init__(self) -> None:
        if not self.player_id:
            raise ValueError("player_id must be non-empty")


class MemberUnitEditController:
    """Translate exact A:19 request DTOs into semantic unit membership changes."""

    def __init__(
        self,
        units: PreservationUnitService,
        identities: SQLiteCompatibilityIdentityStore,
        *,
        config: MemberUnitEditConfig,
    ) -> None:
        self._units = units
        self._identities = identities
        self._config = config

    @staticmethod
    def _validate_parallel_slots(request: MemberUnitEditRequest) -> None:
        for info in request.unit_info_list:
            lengths = {
                len(info.serial_ids),
                len(info.dress_types),
                len(info.dress_2d_types),
                len(info.dress_storage_ids),
            }
            if lengths != {FINAL_UNIT_SLOT_COUNT}:
                raise ValueError(
                    "unit/edit standard unit arrays must all contain exactly "
                    f"{FINAL_UNIT_SLOT_COUNT} member slots"
                )

    def apply(self, decoded_request: object) -> ChangeSet:
        """Apply the membership portion of an exact UnitEdit request atomically.

        The final client constructs each request from five parallel member slots.
        A zero card serial represents an unoccupied client slot; positive serials
        are resolved through the compatibility identity store. All requested
        units/cards are resolved before ``PreservationUnitService`` writes anything.

        ``main_unit_id`` and dress/costume arrays remain compatibility concerns and
        are deliberately not persisted by this semantic membership command yet.
        """

        request = parse_member_unit_edit_request(decoded_request)
        self._validate_parallel_slots(request)
        player_id = self._config.player_id

        client_unit_ids = [info.unit_id for info in request.unit_info_list]
        if len(set(client_unit_ids)) != len(client_unit_ids):
            raise ValueError("unit/edit request contains duplicate unit_id entries")

        updates: list[UnitMembershipUpdate] = []
        for info in request.unit_info_list:
            domain_unit_id = self._identities.get_domain_unit_id(player_id, info.unit_id)
            if domain_unit_id is None:
                raise ValueError(f"unit/edit unknown client unit_id {info.unit_id}")

            members: list[UnitMember] = []
            for position, serial_id in enumerate(info.serial_ids):
                if serial_id == 0:
                    continue
                user_card_id = self._identities.get_user_card_id(player_id, serial_id)
                if user_card_id is None:
                    raise ValueError(f"unit/edit unknown card serial_id {serial_id}")
                members.append(UnitMember(position, user_card_id))

            updates.append(UnitMembershipUpdate(domain_unit_id, tuple(members)))

        return self._units.replace_members(player_id, tuple(updates))

    def handle(self, decoded_request: object) -> dict[str, object]:
        """Apply A:19 and return its exact endpoint-specific response data.

        Final 11.6.3 ``MemberUnitEditTask.Parse`` executes only::

            mov x1, xzr
            b Stage.BaseTask$$Parse

        so no endpoint-specific response members are consumed.
        """

        self.apply(decoded_request)
        return {}


class SQLiteMemberUnitEditHandler:
    """Thread-safe A:19 handler backed by short-lived SQLite connections."""

    def __init__(
        self,
        domain_path: str | Path,
        identity_path: str | Path,
        *,
        config: MemberUnitEditConfig,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> None:
        self._domain_path = Path(domain_path)
        self._identity_path = Path(identity_path)
        self._config = config
        self._master_revision = master_revision
        self._resource_revision = resource_revision

    def __call__(self, decoded_request: object) -> dict[str, object]:
        with SQLiteDomainStore.open(
            self._domain_path,
            master_revision=self._master_revision,
            resource_revision=self._resource_revision,
        ) as domain:
            with SQLiteCompatibilityIdentityStore.open(self._identity_path) as identities:
                controller = MemberUnitEditController(
                    PreservationUnitService(domain),
                    identities,
                    config=self._config,
                )
                return controller.handle(decoded_request)
