"""Minimal CGSS 11.6.3 ``/load/title`` response builder.

Final-client native analysis of ``Stage.TitleTask.Parse`` shows that the task
first delegates to ``NetworkTask.Parse`` and therefore requires a successful
``data_headers.result_code``.  On success it reads the top-level ``data`` map
and conditionally consumes the title-refund field; an empty data map is a valid
minimal preservation response for the current parser path.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body


RESULT_SUCCESS = 1


@dataclass(frozen=True)
class LoadTitleResponse:
    payload: dict[str, Any]
    body: bytes


def build_load_title_payload(*, sid: str | None = None, servertime: int | None = None) -> dict[str, Any]:
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {
        "data_headers": headers,
        "data": {},
    }


def encode_load_title_response(
    udid: str,
    *,
    sid: str | None = None,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> LoadTitleResponse:
    payload = build_load_title_payload(sid=sid, servertime=servertime)
    body = encode_body(payload, udid, dynamic_key=dynamic_key)
    return LoadTitleResponse(payload=payload, body=body)
