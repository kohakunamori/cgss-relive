"""Wire encoder for explicitly supplied reconstructed endpoint templates."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from .cgss_codec import encode_body

RESULT_SUCCESS = 1


@dataclass(frozen=True)
class TemplateResponse:
    payload: dict[str, Any]
    body: bytes


def build_template_success_payload(
    data: Mapping[str, Any],
    *,
    sid: str | None = None,
    servertime: int | None = None,
) -> dict[str, Any]:
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {"data_headers": headers, "data": dict(data)}


def encode_template_success_response(
    udid: str,
    data: Mapping[str, Any],
    *,
    sid: str | None = None,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> TemplateResponse:
    payload = build_template_success_payload(data, sid=sid, servertime=servertime)
    return TemplateResponse(
        payload=payload,
        body=encode_body(payload, udid, dynamic_key=dynamic_key),
    )
