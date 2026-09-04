"""Application/controller for domain-backed final-client ``/load/index`` data.

This layer composes three independent concerns:

* preservation-domain profile/Home state;
* persistent client-facing numeric identity bindings;
* the final 11.6.3 response projection.

It intentionally does not perform HTTP/body encryption. ``server.http_server`` can
consume one of the Mapping facades below as ordinary ``load_index_data``.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping as MappingABC
from dataclasses import dataclass, field
from pathlib import Path
from threading import local
from types import MappingProxyType
from typing import Mapping

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.adapters.load_index import (
    CardLoadIndexBinding,
    LoadIndexProjectionPolicy,
    UnitLoadIndexBinding,
    project_home_snapshot_to_load_index_data,
)
from server.domain import (
    BootstrapPolicy,
    Clock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
)


_DEFAULT_RESOURCE_KIND_MAP = {
    "friend_pt": "friend_pt",
    "jewel": "jewel",
    "free_jewel": "free_jewel",
    "gold": "gold",
    "stamina": "stamina",
}


@dataclass(frozen=True)
class DomainLoadIndexConfig:
    """Explicit compatibility policy for one archival player.

    Fields that are not yet proven domain semantics remain here at the application /
    adapter boundary. They can later migrate into the domain only when evidence
    shows they represent durable game meaning.
    """

    player_id: str
    viewer_id: int
    bootstrap_policy: BootstrapPolicy | None = None
    leader_user_card_id: str | None = None
    resource_kind_map: Mapping[str, str] = field(default_factory=lambda: dict(_DEFAULT_RESOURCE_KIND_MAP))
    comment: str = ""
    max_card_num: int = 300
    max_room_storage_num: int = 500
    fan: int = 0
    producer_rank: int = 1
    birth: int = 0
    sum_of_money: int = 0
    last_payment_date: int = 0

    def __post_init__(self) -> None:
        if not self.player_id:
            raise ValueError("player_id must be non-empty")
        if self.viewer_id <= 0:
            raise ValueError("viewer_id must be positive")
        resource_map = dict(self.resource_kind_map)
        if set(resource_map) != set(_DEFAULT_RESOURCE_KIND_MAP):
            raise ValueError("resource_kind_map must map the five load/index user_info resource fields")
        if any(not value for value in resource_map.values()):
            raise ValueError("resource_kind_map values must be non-empty")
        object.__setattr__(self, "resource_kind_map", MappingProxyType(resource_map))


class DomainLoadIndexController:
    """Build current ``/load/index`` data from one repository/service instance."""

    def __init__(
        self,
        profile_service: PreservationProfileService,
        identities: SQLiteCompatibilityIdentityStore,
        *,
        clock: Clock,
        config: DomainLoadIndexConfig,
    ) -> None:
        self._profiles = profile_service
        self._identities = identities
        self._clock = clock
        self._config = config

    def _snapshot(self):
        try:
            return self._profiles.get_home_snapshot(self._config.player_id)
        except KeyError:
            policy = self._config.bootstrap_policy
            if policy is None:
                raise
            return self._profiles.bootstrap_profile(
                policy,
                player_id=self._config.player_id,
            ).snapshot

    def build_data(self) -> dict[str, object]:
        snapshot = self._snapshot()
        player_id = snapshot.profile.player_id

        card_bindings = {
            card.user_card_id: CardLoadIndexBinding(
                serial_id=self._identities.ensure_card_serial(player_id, card.user_card_id)
            )
            for card in snapshot.cards
        }
        unit_bindings = {
            unit.unit_id: UnitLoadIndexBinding(
                unit_id=self._identities.ensure_unit_id(player_id, unit.unit_id)
            )
            for unit in snapshot.units
        }

        projection = LoadIndexProjectionPolicy(
            viewer_id=self._config.viewer_id,
            now=int(self._clock.now().timestamp()),
            card_bindings=card_bindings,
            unit_bindings=unit_bindings,
            leader_user_card_id=self._config.leader_user_card_id,
            resource_kind_map=self._config.resource_kind_map,
            comment=self._config.comment,
            max_card_num=self._config.max_card_num,
            max_room_storage_num=self._config.max_room_storage_num,
            fan=self._config.fan,
            producer_rank=self._config.producer_rank,
            birth=self._config.birth,
            sum_of_money=self._config.sum_of_money,
            last_payment_date=self._config.last_payment_date,
        )
        return project_home_snapshot_to_load_index_data(snapshot, projection)


class _RefreshingMapping(MappingABC[str, object]):
    """Refresh one coherent thread-local projection for each ``dict(mapping)``."""

    def __init__(self) -> None:
        self._local = local()

    def _build_data(self) -> dict[str, object]:
        raise NotImplementedError

    def _refresh(self) -> dict[str, object]:
        current = self._build_data()
        self._local.current = current
        return current

    def _current(self) -> dict[str, object]:
        current = getattr(self._local, "current", None)
        return self._refresh() if current is None else current

    def keys(self):
        return tuple(self._refresh().keys())

    def __getitem__(self, key: str) -> object:
        return self._current()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(tuple(self._refresh().keys()))

    def __len__(self) -> int:
        return len(self._current())


class DynamicLoadIndexData(_RefreshingMapping):
    """Dynamic facade for a controller whose repositories are thread-safe.

    This is useful in tests or single-threaded hosts. Do not pass a controller that
    owns default thread-bound SQLite connections to ``ThreadingHTTPServer``; use
    ``SQLiteDomainLoadIndexData`` below instead.
    """

    def __init__(self, controller: DomainLoadIndexController) -> None:
        super().__init__()
        self._controller = controller

    def _build_data(self) -> dict[str, object]:
        return self._controller.build_data()


class SQLiteDomainLoadIndexData(_RefreshingMapping):
    """Thread-safe mapping backed by short-lived SQLite repository connections.

    Each response projection opens its own mutable-state and compatibility-identity
    connections in the worker thread, builds the current snapshot, then closes both.
    This preserves SQLite's default thread-safety contract instead of disabling
    ``check_same_thread`` on long-lived shared connections.
    """

    def __init__(
        self,
        domain_path: str | Path,
        identity_path: str | Path,
        *,
        clock: Clock,
        config: DomainLoadIndexConfig,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> None:
        super().__init__()
        self._domain_path = Path(domain_path)
        self._identity_path = Path(identity_path)
        self._clock = clock
        self._config = config
        self._master_revision = master_revision
        self._resource_revision = resource_revision

    def _build_data(self) -> dict[str, object]:
        with SQLiteDomainStore.open(
            self._domain_path,
            master_revision=self._master_revision,
            resource_revision=self._resource_revision,
        ) as domain:
            with SQLiteCompatibilityIdentityStore.open(self._identity_path) as identities:
                profiles = PreservationProfileService(
                    domain,
                    clock=self._clock,
                    ids=SequentialIdGenerator(),
                )
                controller = DomainLoadIndexController(
                    profiles,
                    identities,
                    clock=self._clock,
                    config=self._config,
                )
                return controller.build_data()
