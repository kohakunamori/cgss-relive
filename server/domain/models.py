"""Initial D1 preservation-domain entities.

These classes model mutable archival state without copying CGSS wire DTO names.
Fields are intentionally limited to semantics needed by the first Home-oriented
implementation slice. More fields should be added only with client/master evidence
or an explicit preservation policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


def _require_non_empty(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must be non-empty")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True)
class PlayerProfile:
    player_id: str
    name: str
    producer_level: int
    experience: int
    created_at: datetime
    last_login_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.player_id, "player_id")
        _require_non_empty(self.name, "name")
        if self.producer_level < 1:
            raise ValueError("producer_level must be at least 1")
        if self.experience < 0:
            raise ValueError("experience must be non-negative")
        _require_aware(self.created_at, "created_at")
        if self.last_login_at is not None:
            _require_aware(self.last_login_at, "last_login_at")


@dataclass(frozen=True)
class PlayerResource:
    player_id: str
    resource_kind: str
    amount: int

    def __post_init__(self) -> None:
        _require_non_empty(self.player_id, "player_id")
        _require_non_empty(self.resource_kind, "resource_kind")
        if self.amount < 0:
            raise ValueError("resource amount must be non-negative")


@dataclass(frozen=True)
class CardOwnership:
    """One user-owned card instance referencing immutable master card data.

    ``star_lesson_step``, ``love`` and ``is_protected`` are final-11.6.3
    proven-static semantics:

    * the final CardData ``_step`` field is directly read by
      ``get_starLessonStep`` and star-rank UI/gameplay consumers;
    * ``_love`` is paired with ``GetLoveMax`` and LIVE/gift/heart consumers;
    * ``_isProtect`` is an independent bool written by ``SetResponseProtect``.

    ``favorite`` remains separate because the final client has independent
    ``isFavorite`` state/accessors.
    """

    user_card_id: str
    player_id: str
    master_card_id: int
    level: int
    experience: int
    skill_level: int
    star_lesson_step: int
    love: int
    is_protected: bool
    favorite: bool
    acquired_at: datetime

    def __post_init__(self) -> None:
        _require_non_empty(self.user_card_id, "user_card_id")
        _require_non_empty(self.player_id, "player_id")
        if self.master_card_id <= 0:
            raise ValueError("master_card_id must be positive")
        if self.level < 1:
            raise ValueError("card level must be at least 1")
        if self.experience < 0:
            raise ValueError("card experience must be non-negative")
        if self.skill_level < 0:
            raise ValueError("skill_level must be non-negative")
        if self.star_lesson_step < 0:
            raise ValueError("star_lesson_step must be non-negative")
        if self.love < 0:
            raise ValueError("love must be non-negative")
        _require_aware(self.acquired_at, "acquired_at")


@dataclass(frozen=True)
class UnitMember:
    position: int
    user_card_id: str

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("unit member position must be non-negative")
        _require_non_empty(self.user_card_id, "user_card_id")


@dataclass(frozen=True)
class Unit:
    unit_id: str
    player_id: str
    slot: int
    name: str | None = None
    members: tuple[UnitMember, ...] = ()

    def __post_init__(self) -> None:
        _require_non_empty(self.unit_id, "unit_id")
        _require_non_empty(self.player_id, "player_id")
        if self.slot < 0:
            raise ValueError("unit slot must be non-negative")
        members = tuple(self.members)
        if len({member.position for member in members}) != len(members):
            raise ValueError("unit member positions must be unique")
        object.__setattr__(self, "members", members)


@dataclass(frozen=True)
class FeatureUnlock:
    player_id: str
    unlock_kind: str
    master_ref_id: int
    unlocked_at: datetime
    source: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.player_id, "player_id")
        _require_non_empty(self.unlock_kind, "unlock_kind")
        if self.master_ref_id <= 0:
            raise ValueError("master_ref_id must be positive")
        _require_aware(self.unlocked_at, "unlocked_at")


@dataclass(frozen=True)
class HomeStateSnapshot:
    """Wire-independent state needed to build bootstrap/Home projections."""

    profile: PlayerProfile
    resources: tuple[PlayerResource, ...] = ()
    cards: tuple[CardOwnership, ...] = ()
    units: tuple[Unit, ...] = ()
    unlocks: tuple[FeatureUnlock, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "resources", tuple(self.resources))
        object.__setattr__(self, "cards", tuple(self.cards))
        object.__setattr__(self, "units", tuple(self.units))
        object.__setattr__(self, "unlocks", tuple(self.unlocks))

        player_id = self.profile.player_id
        for collection_name, rows in (
            ("resources", self.resources),
            ("cards", self.cards),
            ("units", self.units),
            ("unlocks", self.unlocks),
        ):
            if any(row.player_id != player_id for row in rows):
                raise ValueError(f"{collection_name} contains state for another player")
