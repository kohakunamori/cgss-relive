"""CGSS 11.6.3 BNID migration-status response.

Runtime evidence from the untouched final client identifies
``Stage.MigrationCheckTask.Parse`` at libil2cpp RVA 0x0489E680. The parser reads
``data.transition`` as an integer. Values 1, 2, and 9 are mapped to three
non-zero migration states; every other integer maps to the normal state 0.
Official successful captures proceed from this task to the ordinary
``/tool/signup`` flow, so the preservation backend reports transition 0.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body

RESULT_SUCCESS = 1
NORMAL_TRANSITION = 0


@dataclass(frozen=True)
class MigrationCheckResponse:
    payload: dict[str, Any]
    body: bytes


def build_migration_check_payload(
    *,
    sid: str | None = None,
    servertime: int | None = None,
    transition: int = NORMAL_TRANSITION,
) -> dict[str, Any]:
    if isinstance(transition, bool) or not isinstance(transition, int):
        raise TypeError("transition must be an integer")
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {
        "data_headers": headers,
        "data": {"transition": transition},
    }


def encode_migration_check_response(
    udid: str,
    *,
    sid: str | None = None,
    servertime: int | None = None,
    transition: int = NORMAL_TRANSITION,
    dynamic_key: bytes | None = None,
) -> MigrationCheckResponse:
    payload = build_migration_check_payload(
        sid=sid,
        servertime=servertime,
        transition=transition,
    )
    return MigrationCheckResponse(
        payload=payload,
        body=encode_body(payload, udid, dynamic_key=dynamic_key),
    )
