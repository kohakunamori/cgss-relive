"""Wire encoder for explicitly supplied reconstructed endpoint templates."""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any

from .cgss_codec import encode_body

RESULT_SUCCESS = 1


@dataclass(frozen=True)
class TemplateResponse:
    payload: dict[str, Any]
    body: bytes


def build_template_success_payload(
    data: Any,
    *,
    sid: str | None = None,
    servertime: int | None = None,
) -> dict[str, Any]:
    """Build the common CGSS success envelope around an exact JSON-like data shape.

    Endpoint parsers in final 11.6.3 do not universally consume ``data`` as an
    object; some expect arrays/collections or other JSON-like shapes.  Explicit
    templates therefore preserve the supplied shape instead of coercing it to a
    mapping.  Values originate from JSON template documents or audited built-ins.
    """
    headers: dict[str, Any] = {
        "result_code": RESULT_SUCCESS,
        "servertime": int(time.time() if servertime is None else servertime),
    }
    if sid is not None:
        headers["sid"] = sid
    return {"data_headers": headers, "data": copy.deepcopy(data)}


def encode_template_success_response(
    udid: str,
    data: Any,
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
