"""Minimal CGSS 11.6.3 ``/load/check`` response builder.

The result-code and data_headers behavior in this module is reconstructed from
CGSS Android 11.6.3 IL2CPP metadata/native code.  It deliberately models only
the control-plane fields required for version negotiation and early bootstrap;
it does not emulate an account service.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body


RESULT_SUCCESS = 1
RESULT_SESSION_ERROR = 201
RESULT_APP_VERSION_ERROR = 204
RESULT_RES_VERSION_ERROR = 214

FINAL_RESOURCE_VERSION = "10133800"


@dataclass(frozen=True)
class LoadCheckResponse:
    """Both decoded and wire representations of a synthetic load/check reply."""

    payload: dict[str, Any]
    body: bytes


def build_load_check_payload(
    current_res_ver: str,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    sid: str | None = None,
    servertime: int | None = None,
    include_empty_data: bool = True,
) -> dict[str, Any]:
    """Build the smallest preservation-oriented response shape.

    The final client reads ``data_headers.result_code`` unconditionally. ``sid``
    is optional but, when present, is copied into Certification.SessionId.
    ``required_res_ver`` is consumed by common result handling and persisted to
    local ``RES_VER``.  A mismatch therefore returns the current client's
    resource-version error code (214); once the caller reports the frozen final
    version, the response switches to success (1).
    """

    mismatch = str(current_res_ver) != str(final_res_ver)
    headers: dict[str, Any] = {
        "result_code": RESULT_RES_VERSION_ERROR if mismatch else RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    if mismatch:
        headers["required_res_ver"] = str(final_res_ver)

    payload: dict[str, Any] = {"data_headers": headers}
    if include_empty_data:
        # VersionCheckTask.Parse tolerates an absent data object, but keeping an
        # empty map is convenient and production-like for synthetic fixtures.
        payload["data"] = {}
    return payload


def encode_load_check_response(
    udid: str,
    current_res_ver: str,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    sid: str | None = None,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> LoadCheckResponse:
    """Build and encrypt a load/check response with the final-client envelope."""

    payload = build_load_check_payload(
        current_res_ver,
        final_res_ver=final_res_ver,
        sid=sid,
        servertime=servertime,
    )
    body = encode_body(payload, udid, dynamic_key=dynamic_key)
    return LoadCheckResponse(payload=payload, body=body)
