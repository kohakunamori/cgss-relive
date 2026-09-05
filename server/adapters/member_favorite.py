"""Final-CGSS 11.6.3 request adapter for A:22 ``favorite/edit``.

Exact final API/managed metadata establishes:

* ApiType A:22 ``MemberFavoriteEdit`` -> ``favorite/edit``;
* ``MemberFavoriteEditTaskParam.serial_ids : int[]``;
* ``MemberFavoriteEditTaskParam.change_flags : int[]``.

This module intentionally does not assign business meaning to individual
``change_flags`` values until the bounded native SetParameter/Parse pass closes
that mapping. It therefore parses and preserves the exact parallel arrays only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class MemberFavoriteEditRequest:
    serial_ids: tuple[int, ...]
    change_flags: tuple[int, ...]


def parse_member_favorite_edit_request(request: Any) -> MemberFavoriteEditRequest:
    """Validate and preserve the exact final A:22 request-side DTO shape."""

    if not isinstance(request, Mapping):
        raise ValueError("favorite/edit request must be an object")
    for field in ("serial_ids", "change_flags"):
        if field not in request:
            raise ValueError(f"favorite/edit request is missing {field}")
        if not isinstance(request[field], (list, tuple)):
            raise ValueError(f"favorite/edit {field} must be an array")

    serials: list[int] = []
    for value in request["serial_ids"]:
        if type(value) is not int or value <= 0:
            raise ValueError("favorite/edit serial_ids must contain positive integers")
        serials.append(value)

    flags: list[int] = []
    for value in request["change_flags"]:
        if type(value) is not int:
            raise ValueError("favorite/edit change_flags must contain integers")
        flags.append(value)

    if len(serials) != len(flags):
        raise ValueError("favorite/edit serial_ids and change_flags must be parallel arrays")

    # Preserve order, duplicates and raw flag values. Managed metadata proves only
    # the two int[] fields; normalization and flag semantics belong to later exact
    # native/application evidence.
    return MemberFavoriteEditRequest(tuple(serials), tuple(flags))
