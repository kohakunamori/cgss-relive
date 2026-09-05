"""Application/controller for final-11.6.3 A:19 ``unit/edit`` mutations.

This layer owns conversion from client-facing numeric unit/card identities into
preservation-domain identities. Semantic unit membership is written through the
domain service; final-client costume arrays and main-unit selection remain in the
separate compatibility store.

Exact final-client evidence closes both important response/selection boundaries:

* ``MemberUnitEditTask.Parse`` tail-calls ``BaseTask.Parse`` and consumes no
  endpoint-specific response data, so ``handle()`` returns ``{}``;
* the caller obtains ``WorkUnitData.GetMainUnit().UnitData._unitId`` at offset
  ``0x10``, converts its ``ObscuredInt`` with ``op_Implicit``, and passes that int
  to ``SetParameter(mainUnit, ...)``, which becomes request ``main_unit_id``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from server.adapters.identity_store import (
    SQLiteCompatibilityIdentityStore,
    UnitCompatibilitySlot,
)
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


@dataclass(frozen=True)
class _ResolvedUnitEdit:
    domain_unit_id: str
    membership: UnitMembershipUpdate
    cosmetics: tuple[UnitCompatibilitySlot, ...]


class MemberUnitEditController:
    """Translate exact A:19 request DTOs into durable preservation state."""

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

    def _resolve(self, request: MemberUnitEditRequest) -> tuple[tuple[_ResolvedUnitEdit, ...], str | None]:
        """Resolve every client identity before any persistent mutation occurs."""

        player_id = self._config.player_id
        client_unit_ids = [info.unit_id for info in request.unit_info_list]
        if len(set(client_unit_ids)) != len(client_unit_ids):
            raise ValueError("unit/edit request contains duplicate unit_id entries")

        resolved: list[_ResolvedUnitEdit] = []
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

            cosmetics = tuple(
                UnitCompatibilitySlot(
                    position=position,
                    dress_type=info.dress_types[position],
                    dress_2d_type=info.dress_2d_types[position],
                    dress_storage_id=info.dress_storage_ids[position],
                )
                for position in range(FINAL_UNIT_SLOT_COUNT)
            )
            resolved.append(
                _ResolvedUnitEdit(
                    domain_unit_id=domain_unit_id,
                    membership=UnitMembershipUpdate(domain_unit_id, tuple(members)),
                    cosmetics=cosmetics,
                )
            )

        if request.main_unit_id == 0:
            # The exact final UI caller supplies a real GetMainUnit()._unitId. Zero
            # is retained only as an adapter-safe absent sentinel because managed
            # metadata alone permits int zero and no final caller path using it has
            # been observed.
            main_domain_unit_id = None
        else:
            main_domain_unit_id = self._identities.get_domain_unit_id(
                player_id, request.main_unit_id
            )
            if main_domain_unit_id is None:
                raise ValueError(f"unit/edit unknown main_unit_id {request.main_unit_id}")

        return tuple(resolved), main_domain_unit_id

    def apply(self, decoded_request: object) -> ChangeSet:
        """Apply semantic membership and compatibility-only A:19 state.

        All request identities and five-slot arrays are validated before either DB
        is mutated. Domain membership is then committed atomically in the domain DB;
        costume/main-unit state is committed atomically inside the compatibility DB.
        Because these are deliberately separate SQLite files, the composite write is
        not a distributed transaction; a compatibility-DB I/O failure after the
        domain commit is an explicit residual limitation rather than hidden as full
        atomicity.
        """

        request = parse_member_unit_edit_request(decoded_request)
        self._validate_parallel_slots(request)
        resolved, main_domain_unit_id = self._resolve(request)
        player_id = self._config.player_id

        changes = self._units.replace_members(
            player_id,
            tuple(item.membership for item in resolved),
        )

        with self._identities.transaction():
            for item in resolved:
                self._identities.replace_unit_compatibility_slots(
                    player_id,
                    item.domain_unit_id,
                    item.cosmetics,
                )
            self._identities.set_main_unit(player_id, main_domain_unit_id)

        return changes

    def handle(self, decoded_request: object) -> dict[str, object]:
        """Apply A:19 and return its exact endpoint-specific response data."""

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
