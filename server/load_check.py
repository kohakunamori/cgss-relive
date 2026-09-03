"""Minimal CGSS 11.6.3 ``/load/check`` response builder.

The result-code and data_headers behavior in this module is reconstructed from
CGSS Android 11.6.3 IL2CPP metadata/native code. It models only the control-plane
fields required for version negotiation and early bootstrap; it does not emulate
an account service.
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
    is_s3: bool | None = None,
    accept_old_resource_version: bool = False,
) -> dict[str, Any]:
    """Build the preservation-oriented response shape.

    The final client reads ``data_headers.result_code`` unconditionally.
    ``required_res_ver`` is persisted into Savedata ``RES_VER`` by common result
    handling. Static analysis also proves that result code 214 does *not* itself
    resend ``/load/check``; any later request belongs to a higher-level resource
    or boot state machine.

    By default a version mismatch therefore returns the native resource-version
    code 214. ``accept_old_resource_version`` is an explicit diagnostic mode: it
    returns result code 1 while still supplying ``required_res_ver`` so the local
    RES_VER can advance. This is useful for separating the 214/resource-update
    path from later BootMain blockers; it is not the default protocol model.

    ``data.isS3`` controls the final client's resource-host/URL-family selector.
    Pass ``False`` for the reconstructed ``storages.game.starlight-stage.jp``
    family. ``None`` preserves the older minimal fixture shape with an empty data
    object.
    """
    mismatch = str(current_res_ver) != str(final_res_ver)
    result_code = RESULT_SUCCESS
    if mismatch and not accept_old_resource_version:
        result_code = RESULT_RES_VERSION_ERROR

    headers: dict[str, Any] = {
        "result_code": result_code,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    if mismatch:
        # Common result handling persists this even when diagnostic direct
        # success is selected, advancing subsequent RES-VER request headers.
        headers["required_res_ver"] = str(final_res_ver)

    payload: dict[str, Any] = {"data_headers": headers}
    if include_empty_data:
        data: dict[str, Any] = {}
        if is_s3 is not None:
            data["isS3"] = bool(is_s3)
        payload["data"] = data
    return payload


def encode_load_check_response(
    udid: str,
    current_res_ver: str,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    sid: str | None = None,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
    is_s3: bool | None = None,
    accept_old_resource_version: bool = False,
) -> LoadCheckResponse:
    """Build and encrypt a load/check response with the final-client envelope."""
    payload = build_load_check_payload(
        current_res_ver,
        final_res_ver=final_res_ver,
        sid=sid,
        servertime=servertime,
        is_s3=is_s3,
        accept_old_resource_version=accept_old_resource_version,
    )
    body = encode_body(payload, udid, dynamic_key=dynamic_key)
    return LoadCheckResponse(payload=payload, body=body)
