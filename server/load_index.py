"""CGSS 11.6.3 ``/load/index`` response wrapper.

Unlike ``load/check`` and ``load/title``, the final client's ``Stage.LoadTask.Parse``
consumes a large initialization profile.  This module intentionally keeps that
profile as injected data rather than pretending an empty map is client-valid.
The transport/envelope is already reconstructed; profile minimization is tracked
separately by final-client parser analysis.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from .cgss_codec import encode_body


RESULT_SUCCESS = 1


@dataclass(frozen=True)
class LoadIndexResponse:
    payload: dict[str, Any]
    body: bytes


def build_load_index_payload(
    data: Mapping[str, Any],
    *,
    sid: str | None = None,
    servertime: int | None = None,
    viewer_id: int | None = None,
    user_id: int | None = None,
) -> dict[str, Any]:
    """Wrap an archival profile in the final-client common response shape."""
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    if viewer_id is not None:
        headers["viewer_id"] = int(viewer_id)
    if user_id is not None:
        headers["user_id"] = int(user_id)
    return {
        "data_headers": headers,
        "data": dict(data),
    }


def encode_load_index_response(
    udid: str,
    data: Mapping[str, Any],
    *,
    sid: str | None = None,
    servertime: int | None = None,
    viewer_id: int | None = None,
    user_id: int | None = None,
    dynamic_key: bytes | None = None,
) -> LoadIndexResponse:
    """Build and encrypt a profile-backed ``/load/index`` response."""
    payload = build_load_index_payload(
        data,
        sid=sid,
        servertime=servertime,
        viewer_id=viewer_id,
        user_id=user_id,
    )
    body = encode_body(payload, udid, dynamic_key=dynamic_key)
    return LoadIndexResponse(payload=payload, body=body)
