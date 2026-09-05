"""CGSS 11.6.3 ``/load/index`` projection from preservation-domain state.

This module is intentionally outside ``server.domain``. It owns client-specific
field names, numeric compatibility identifiers and parser-safe synthetic defaults.
The projection is based on the reduced final-client parser documented in
``docs/load-index-11.6.3.md``.

Important boundary:

* domain IDs such as ``user_card_id='card:1'`` are not assumed to be CGSS numeric
  serial IDs;
* adapter bindings explicitly map domain entities to client-facing numeric IDs;
* final-11.6.3 proven card semantics (star lesson step, love, protect) come directly
  from ``CardOwnership``;
* unit costume arrays remain client compatibility state and are projected only when
  a saved compatibility record exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from server.domain import HomeStateSnapshot
from server.minimal_profile import (
    FINAL_UNIT_SLOT_COUNT,
    STARTER_WORK_CARD_SECTION,
    build_home_candidate_load_index_data,
    validate_home_candidate_profile,
)


_RESOURCE_USER_INFO_FIELDS = (
    "friend_pt",
    "jewel",
    "free_jewel",
    "gold",
    "stamina",
)


def _default_resource_kind_map() -> dict[str, str]:
    return {field: field for field in _RESOURCE_USER_INFO_FIELDS}


@dataclass(frozen=True)
class CardLoadIndexBinding:
    """Stable numeric CGSS serial identity for one domain-owned card."""

    serial_id: int

    def __post_init__(self) -> None:
        if self.serial_id <= 0:
            raise ValueError("card serial_id must be positive")


@dataclass(frozen=True)
class UnitLoadIndexBinding:
    """Numeric CGSS unit identity corresponding to one domain Unit."""

    unit_id: int

    def __post_init__(self) -> None:
        if self.unit_id <= 0:
            raise ValueError("CGSS unit_id must be positive")


@dataclass(frozen=True)
class UnitCosmeticLoadIndexSlot:
    """One saved final-client unit slot's optional compatibility-only costume state."""

    position: int
    dress_type: int
    dress_2d_type: int
    dress_storage_id: int

    def __post_init__(self) -> None:
        if not 0 <= self.position < FINAL_UNIT_SLOT_COUNT:
            raise ValueError("unit cosmetic position is outside final-client slot count")
        for name, value in (
            ("dress_type", self.dress_type),
            ("dress_2d_type", self.dress_2d_type),
            ("dress_storage_id", self.dress_storage_id),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class LoadIndexProjectionPolicy:
    """Wire/compatibility policy for one ``/load/index`` projection."""

    viewer_id: int
    now: int
    card_bindings: Mapping[str, CardLoadIndexBinding] = field(default_factory=dict)
    unit_bindings: Mapping[str, UnitLoadIndexBinding] = field(default_factory=dict)
    unit_cosmetics: Mapping[str, tuple[UnitCosmeticLoadIndexSlot, ...]] = field(default_factory=dict)
    leader_user_card_id: str | None = None
    resource_kind_map: Mapping[str, str] = field(default_factory=_default_resource_kind_map)
    comment: str = ""
    max_card_num: int = 300
    max_room_storage_num: int = 500
    fan: int = 0
    producer_rank: int = 1
    birth: int = 0
    sum_of_money: int = 0
    last_payment_date: int = 0

    def __post_init__(self) -> None:
        if self.viewer_id <= 0:
            raise ValueError("viewer_id must be positive")
        if self.now < 0:
            raise ValueError("projection timestamp must be non-negative")
        if self.max_card_num < 0 or self.max_room_storage_num < 0:
            raise ValueError("storage caps must be non-negative")
        if self.fan < 0 or self.producer_rank < 0:
            raise ValueError("fan/producer_rank must be non-negative")
        if self.birth < 0 or self.sum_of_money < 0 or self.last_payment_date < 0:
            raise ValueError("compatibility scalar defaults must be non-negative")

        cards = dict(self.card_bindings)
        units = dict(self.unit_bindings)
        cosmetics = {key: tuple(value) for key, value in self.unit_cosmetics.items()}
        resource_map = dict(self.resource_kind_map)
        if any(not key for key in cards):
            raise ValueError("card binding domain IDs must be non-empty")
        if any(not key for key in units):
            raise ValueError("unit binding domain IDs must be non-empty")
        if any(not key for key in cosmetics):
            raise ValueError("unit cosmetic domain IDs must be non-empty")
        for domain_unit_id, slots in cosmetics.items():
            positions = [slot.position for slot in slots]
            if len(set(positions)) != len(positions):
                raise ValueError(f"duplicate cosmetic slot for unit {domain_unit_id!r}")
        if set(resource_map) != set(_RESOURCE_USER_INFO_FIELDS):
            raise ValueError(
                "resource_kind_map must map exactly: " + ", ".join(_RESOURCE_USER_INFO_FIELDS)
            )
        if any(not value for value in resource_map.values()):
            raise ValueError("domain resource kinds must be non-empty")

        object.__setattr__(self, "card_bindings", MappingProxyType(cards))
        object.__setattr__(self, "unit_bindings", MappingProxyType(units))
        object.__setattr__(self, "unit_cosmetics", MappingProxyType(cosmetics))
        object.__setattr__(self, "resource_kind_map", MappingProxyType(resource_map))


def _resource_amounts(snapshot: HomeStateSnapshot) -> dict[str, int]:
    amounts: dict[str, int] = {}
    for resource in snapshot.resources:
        if resource.resource_kind in amounts:
            raise ValueError(f"duplicate domain resource kind {resource.resource_kind!r}")
        amounts[resource.resource_kind] = resource.amount
    return amounts


def project_home_snapshot_to_load_index_data(
    snapshot: HomeStateSnapshot,
    policy: LoadIndexProjectionPolicy,
) -> dict[str, object]:
    """Project one wire-independent Home snapshot into final-client load data."""

    data = build_home_candidate_load_index_data(
        viewer_id=policy.viewer_id,
        producer_name=snapshot.profile.name,
        now=policy.now,
    )
    baseline_errors = validate_home_candidate_profile(data)
    if baseline_errors:
        raise RuntimeError(f"internal Home candidate scaffold invalid: {baseline_errors!r}")

    user_info = data["user_info"]
    assert isinstance(user_info, dict)
    user_info.update(
        {
            "name": snapshot.profile.name,
            "comment": policy.comment,
            "max_card_num": policy.max_card_num,
            "max_room_storage_num": policy.max_room_storage_num,
            "level": snapshot.profile.producer_level,
            "exp": snapshot.profile.experience,
            "fan": policy.fan,
            "producer_rank": policy.producer_rank,
            "birth": policy.birth,
            "sum_of_money": policy.sum_of_money,
            "last_payment_date": policy.last_payment_date,
            "stamina_heal_time": policy.now,
        }
    )

    resources = _resource_amounts(snapshot)
    for wire_field, domain_kind in policy.resource_kind_map.items():
        user_info[wire_field] = resources.get(domain_kind, 0)

    card_by_id = {card.user_card_id: card for card in snapshot.cards}
    if len(card_by_id) != len(snapshot.cards):
        raise ValueError("duplicate user_card_id in Home snapshot")

    used_serials: set[int] = set()
    projected_cards: list[dict[str, int]] = []
    for card in sorted(snapshot.cards, key=lambda item: item.user_card_id):
        binding = policy.card_bindings.get(card.user_card_id)
        if binding is None:
            raise ValueError(f"missing load-index card binding for {card.user_card_id!r}")
        if binding.serial_id in used_serials:
            raise ValueError(f"duplicate CGSS card serial_id {binding.serial_id}")
        used_serials.add(binding.serial_id)
        projected_cards.append(
            {
                "serial_id": binding.serial_id,
                "card_id": card.master_card_id,
                "exp": card.experience,
                "step": card.star_lesson_step,
                "love": card.love,
                "skill_level": card.skill_level,
                "protect": int(card.is_protected),
            }
        )

    if projected_cards:
        data[STARTER_WORK_CARD_SECTION] = projected_cards

    projected_units: list[dict[str, object]] = []
    used_unit_ids: set[int] = set()
    for unit in sorted(snapshot.units, key=lambda item: (item.slot, item.unit_id)):
        binding = policy.unit_bindings.get(unit.unit_id)
        if binding is None:
            raise ValueError(f"missing load-index unit binding for {unit.unit_id!r}")
        if binding.unit_id in used_unit_ids:
            raise ValueError(f"duplicate CGSS unit_id {binding.unit_id}")
        used_unit_ids.add(binding.unit_id)

        serial_slots = [0] * FINAL_UNIT_SLOT_COUNT
        for member in unit.members:
            if member.position >= FINAL_UNIT_SLOT_COUNT:
                raise ValueError(
                    f"unit member position {member.position} exceeds final-client slot count "
                    f"{FINAL_UNIT_SLOT_COUNT}"
                )
            if member.user_card_id not in card_by_id:
                raise ValueError(
                    f"unit {unit.unit_id!r} references card absent from Home snapshot: "
                    f"{member.user_card_id!r}"
                )
            card_binding = policy.card_bindings.get(member.user_card_id)
            if card_binding is None:
                raise ValueError(
                    f"unit member lacks load-index card binding: {member.user_card_id!r}"
                )
            serial_slots[member.position] = card_binding.serial_id

        projected: dict[str, object] = {
            "unit_slot": unit.slot + 1,
            "unit_id": binding.unit_id,
            "name": unit.name or "",
        }
        projected.update(
            {f"serial_id_{index}": serial_slots[index] for index in range(FINAL_UNIT_SLOT_COUNT)}
        )

        # Final LoadTask helpers guard each formatted cosmetic key before reading it.
        # Omit these keys until UnitEdit (or another exact source) has persisted them.
        for slot in policy.unit_cosmetics.get(unit.unit_id, ()):
            projected[f"dress_type_{slot.position}"] = slot.dress_type
            projected[f"dress_2d_type_{slot.position}"] = slot.dress_2d_type
            projected[f"dress_storage_id_{slot.position}"] = slot.dress_storage_id

        projected_units.append(projected)

    data["user_unit_list"] = projected_units

    if policy.leader_user_card_id is not None:
        if policy.leader_user_card_id not in card_by_id:
            raise ValueError("leader_user_card_id is absent from Home snapshot")
        leader_binding = policy.card_bindings.get(policy.leader_user_card_id)
        if leader_binding is None:
            raise ValueError("leader_user_card_id has no load-index card binding")
        user_info["leader_serial_id"] = leader_binding.serial_id

    data["user_chara_list"] = []
    data["user_card_list"] = []
    return data
