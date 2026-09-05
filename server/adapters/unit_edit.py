"""Final-CGSS 11.6.3 adapter for A:19 ``unit/edit`` request data.

Exact final managed metadata proves:

``MemberUnitEditTaskParam``
    ``unit_info_list : UnitInfo[]``
    ``main_unit_id : int``

``MemberUnitEditTaskParam.UnitInfo``
    ``unit_id : int``
    ``serial_ids : int[]``
    ``dress_types : int[]``
    ``dress_2d_types : int[]``
    ``dress_storage_ids : int[]``

This module preserves all five arrays but does not assign domain semantics to the
three dress/costume families. Zero serial meaning, fixed slot count, main-unit
selection semantics, and response behavior are intentionally left to the bounded
native/application evidence layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class MemberUnitEditUnitInfo:
    unit_id: int
    serial_ids: tuple[int, ...]
    dress_types: tuple[int, ...]
    dress_2d_types: tuple[int, ...]
    dress_storage_ids: tuple[int, ...]


@dataclass(frozen=True)
class MemberUnitEditRequest:
    unit_info_list: tuple[MemberUnitEditUnitInfo, ...]
    main_unit_id: int


def _integer(value: Any, *, field: str, positive: bool = False) -> int:
    if type(value) is not int:
        raise ValueError(f"unit/edit {field} must be an integer")
    if positive and value <= 0:
        raise ValueError(f"unit/edit {field} must be positive")
    if not positive and value < 0:
        raise ValueError(f"unit/edit {field} must be non-negative")
    return value


def _integer_array(value: Any, *, field: str) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"unit/edit {field} must be an array")
    return tuple(
        _integer(item, field=f"{field}[]", positive=False)
        for item in value
    )


def parse_member_unit_edit_request(request: Any) -> MemberUnitEditRequest:
    """Parse only fields proven by the final 11.6.3 managed request contract."""

    if not isinstance(request, Mapping):
        raise ValueError("unit/edit request must be an object")
    if "unit_info_list" not in request:
        raise ValueError("unit/edit request is missing unit_info_list")
    if "main_unit_id" not in request:
        raise ValueError("unit/edit request is missing main_unit_id")

    raw_units = request["unit_info_list"]
    if not isinstance(raw_units, (list, tuple)):
        raise ValueError("unit/edit unit_info_list must be an array")

    units: list[MemberUnitEditUnitInfo] = []
    for index, raw in enumerate(raw_units):
        if not isinstance(raw, Mapping):
            raise ValueError(f"unit/edit unit_info_list[{index}] must be an object")
        required = (
            "unit_id",
            "serial_ids",
            "dress_types",
            "dress_2d_types",
            "dress_storage_ids",
        )
        missing = [field for field in required if field not in raw]
        if missing:
            raise ValueError(
                f"unit/edit unit_info_list[{index}] is missing {', '.join(missing)}"
            )
        units.append(
            MemberUnitEditUnitInfo(
                unit_id=_integer(raw["unit_id"], field=f"unit_info_list[{index}].unit_id", positive=True),
                serial_ids=_integer_array(raw["serial_ids"], field=f"unit_info_list[{index}].serial_ids"),
                dress_types=_integer_array(raw["dress_types"], field=f"unit_info_list[{index}].dress_types"),
                dress_2d_types=_integer_array(raw["dress_2d_types"], field=f"unit_info_list[{index}].dress_2d_types"),
                dress_storage_ids=_integer_array(
                    raw["dress_storage_ids"],
                    field=f"unit_info_list[{index}].dress_storage_ids",
                ),
            )
        )

    return MemberUnitEditRequest(
        unit_info_list=tuple(units),
        # Managed metadata proves an int but does not yet close whether zero is a
        # valid "no current main unit" sentinel. Preserve non-negative values.
        main_unit_id=_integer(request["main_unit_id"], field="main_unit_id", positive=False),
    )
