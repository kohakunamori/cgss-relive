"""Common success response for final-client tasks that only use NetworkTask.Parse.

Use this only where final 11.6.3 native analysis proves the task has no
additional response-field requirements beyond the common NetworkTask envelope.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body

RESULT_SUCCESS = 1


@dataclass(frozen=True)
class EmptySuccessResponse:
    payload: dict[str, Any]
    body: bytes


def build_empty_success_payload(*, sid: str | None = None, servertime: int | None = None) -> dict[str, Any]:
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {"data_headers": headers, "data": {}}


def encode_empty_success_response(
    udid: str,
    *,
    sid: str | None = None,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> EmptySuccessResponse:
    payload = build_empty_success_payload(sid=sid, servertime=servertime)
    return EmptySuccessResponse(
        payload=payload,
        body=encode_body(payload, udid, dynamic_key=dynamic_key),
    )
