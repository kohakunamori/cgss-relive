"""Final-CGSS 11.6.3 adapter for ``member/protect_card``.

Exact final metadata proves ``MemberProtectCardTaskParam.serial_ids : int[]`` and no
wire boolean flag. Exact final Parse analysis also proves response
``data.protect_card_list``. For each requested serial the client clears protection,
then sets it true iff that serial appears in ``protect_card_list``.

This module owns only those proven wire shapes. The server mutation algorithm
(toggle vs another rule) remains an application/domain concern with its own evidence
label.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


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


def project_member_protect_response_data(
    request: MemberProtectRequest,
    protected_serial_ids: Iterable[int],
) -> dict[str, object]:
    """Build the minimal exact ``data`` object consumed by final 11.6.3 Parse.

    The parser only tests requested serials for membership. To avoid manufacturing a
    claim that production returned the player's global protected-card set, the
    preservation response returns the protected subset of the requested serials in
    request order.
    """

    protected = set(protected_serial_ids)
    if any(type(serial_id) is not int or serial_id <= 0 for serial_id in protected):
        raise ValueError("protected serial IDs must be positive integers")
    requested_set = set(request.serial_ids)
    unexpected = protected - requested_set
    if unexpected:
        raise ValueError(
            f"member/protect response cannot include unrequested serial IDs: {sorted(unexpected)!r}"
        )

    return {
        "protect_card_list": [
            serial_id for serial_id in request.serial_ids if serial_id in protected
        ]
    }
