"""Minimal CGSS 11.6.3 login/signup response shared by signup routes.

Official final-client captures show ``Cute.LoginTask`` handling ``/tool/signup``
with ``result_code=1`` and a response data object containing only
``change_domain_enabled``. The current preserved device can enter
``/tool/signup_migration`` with the same ``Cute.LoginTask`` parser, so both
routes intentionally share this narrow response contract.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body

RESULT_SUCCESS = 1


@dataclass(frozen=True)
class LoginSignupResponse:
    payload: dict[str, Any]
    body: bytes


def build_login_signup_payload(
    *,
    sid: str | None = None,
    servertime: int | None = None,
    change_domain_enabled: bool = False,
    viewer_id: int | None = None,
    user_id: int | None = None,
    udid: str | None = None,
) -> dict[str, Any]:
    if not isinstance(change_domain_enabled, bool):
        raise TypeError("change_domain_enabled must be a bool")
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
    if udid is not None:
        headers["udid"] = udid
    return {
        "data_headers": headers,
        "data": {"change_domain_enabled": change_domain_enabled},
    }


def encode_login_signup_response(
    udid: str,
    *,
    sid: str | None = None,
    servertime: int | None = None,
    change_domain_enabled: bool = False,
    viewer_id: int | None = None,
    user_id: int | None = None,
    dynamic_key: bytes | None = None,
) -> LoginSignupResponse:
    payload = build_login_signup_payload(
        sid=sid,
        servertime=servertime,
        change_domain_enabled=change_domain_enabled,
        viewer_id=viewer_id,
        user_id=user_id,
        udid=udid,
    )
    return LoginSignupResponse(
        payload=payload,
        body=encode_body(payload, udid, dynamic_key=dynamic_key),
    )
