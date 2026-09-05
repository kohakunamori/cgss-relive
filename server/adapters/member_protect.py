"""Final-CGSS 11.6.3 adapter for ``member/protect_card`` request data.

Exact final metadata proves ``MemberProtectCardTaskParam.serial_ids : int[]`` and no
wire boolean flag.  This module therefore parses only that proven request shape. It
does not infer the resulting protection state; toggle/set semantics belong to the
application command only after ``MemberProtectCardTask.Parse`` is closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class MemberProtectRequest:
    serial_ids: tuple[int, ...]


def parse_member_protect_request(request: Any) -> MemberProtectRequest:
    """Validate the exact request-side contract without inventing a protect flag."""

    if not isinstance(request, Mapping):
        raise ValueError("member/protect_card request must be an object")
    if "serial_ids" not in request:
        raise ValueError("member/protect_card request is missing serial_ids")

    raw = request["serial_ids"]
    if not isinstance(raw, (list, tuple)):
        raise ValueError("member/protect_card serial_ids must be an array")

    serials: list[int] = []
    for value in raw:
        # bool is an int subclass in Python but is not an acceptable card serial.
        if type(value) is not int or value <= 0:
            raise ValueError("member/protect_card serial_ids must contain positive integers")
        serials.append(value)

    # Preserve order and duplicates: exact metadata proves an int[] but does not
    # prove that the client/server contract normalizes or rejects duplicates.
    return MemberProtectRequest(tuple(serials))
