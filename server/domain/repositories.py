"""Repository interfaces for preservation-domain state and frozen master data."""

from __future__ import annotations

from typing import Any, ContextManager, Mapping, Protocol, runtime_checkable

from .models import (
    CardOwnership,
    FeatureUnlock,
    HomeStateSnapshot,
    PlayerProfile,
    PlayerResource,
    Unit,
)


@runtime_checkable
class MasterDataRepository(Protocol):
    """Read-only access to frozen master data.

    The interface is intentionally generic while CGSS master-table semantics are
    still being normalized. Domain services may ask whether a referenced master
    entity exists and retrieve a read-only record by semantic kind + stable ID.
    """

    @property
    def master_revision(self) -> str:
        ...

    def contains(self, kind: str, master_id: int) -> bool:
        ...

    def get(self, kind: str, master_id: int) -> Mapping[str, Any] | None:
        ...


@runtime_checkable
class PlayerStateRepository(Protocol):
    """Mutable archival profile state independent of HTTP/API DTOs."""

    def transaction(self) -> ContextManager[None]:
        ...

    def get_profile(self, player_id: str) -> PlayerProfile | None:
        ...

    def save_profile(self, profile: PlayerProfile) -> None:
        ...

    def list_resources(self, player_id: str) -> tuple[PlayerResource, ...]:
        ...

    def set_resource(self, resource: PlayerResource) -> None:
        ...

    def get_card(self, player_id: str, user_card_id: str) -> CardOwnership | None:
        ...

    def list_cards(self, player_id: str) -> tuple[CardOwnership, ...]:
        ...

    def save_card(self, card: CardOwnership) -> None:
        ...

    def list_units(self, player_id: str) -> tuple[Unit, ...]:
        ...

    def save_unit(self, unit: Unit) -> None:
        ...

    def list_feature_unlocks(self, player_id: str) -> tuple[FeatureUnlock, ...]:
        ...

    def save_feature_unlock(self, unlock: FeatureUnlock) -> None:
        ...

    def get_home_snapshot(self, player_id: str) -> HomeStateSnapshot | None:
        ...
