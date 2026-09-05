"""Minimal CGSS 11.6.3 Bandai Namco consent-state response.

Runtime evidence from the untouched final client proves
``Stage.BnContentGetStateTask.Parse`` requires ``data.consent_state`` and reads
it through the integer conversion path. Keep this contract narrow until the
same parser proves additional fields are required.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body

RESULT_SUCCESS = 1
NORMAL_CONSENT_STATE = 0


@dataclass(frozen=True)
class BnConsentStateResponse:
    payload: dict[str, Any]
    body: bytes


def build_bn_consent_state_payload(
    *,
    sid: str | None = None,
    servertime: int | None = None,
    consent_state: int = NORMAL_CONSENT_STATE,
) -> dict[str, Any]:
    if isinstance(consent_state, bool) or not isinstance(consent_state, int):
        raise TypeError("consent_state must be an integer")
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {
        "data_headers": headers,
        "data": {"consent_state": consent_state},
    }


def encode_bn_consent_state_response(
    udid: str,
    *,
    sid: str | None = None,
    servertime: int | None = None,
    consent_state: int = NORMAL_CONSENT_STATE,
    dynamic_key: bytes | None = None,
) -> BnConsentStateResponse:
    payload = build_bn_consent_state_payload(
        sid=sid,
        servertime=servertime,
        consent_state=consent_state,
    )
    return BnConsentStateResponse(
        payload=payload,
        body=encode_body(payload, udid, dynamic_key=dynamic_key),
    )
