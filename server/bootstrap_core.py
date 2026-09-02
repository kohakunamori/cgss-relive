"""Transport-independent bootstrap logic for the first CGSS relive server.

This module accepts HTTP-like headers plus raw encrypted bodies and returns
wire-compatible early-bootstrap responses. Socket/TLS/DNS concerns are kept out
of this layer so reconstructed CGSS contracts can be tested deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from . import cgss_codec
from .header_codec import decode_header_value
from .load_check import FINAL_RESOURCE_VERSION, encode_load_check_response
from .load_title import encode_load_title_response


@dataclass(frozen=True)
class BootstrapExchange:
    udid: str
    request: Any
    response: dict[str, Any]
    response_body: bytes


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def decode_client_request(headers: Mapping[str, str], body: bytes | str, *, route: str) -> tuple[str, Any]:
    """Recover the raw UDID and decode a final-client encrypted request body."""
    encoded_udid = _get_header(headers, "UDID")
    if not encoded_udid:
        raise ValueError(f"{route} request is missing UDID header")
    udid = decode_header_value(encoded_udid)
    return udid, cgss_codec.decode_body(body, udid)


def process_load_check_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Decode a final-client load/check request and build its encrypted reply."""
    udid, request = decode_client_request(headers, body, route="load/check")
    current_res_ver = _get_header(headers, "RES-VER") or ""
    sid = _get_header(headers, "SID")

    response = encode_load_check_response(
        udid,
        current_res_ver,
        final_res_ver=final_res_ver,
        sid=sid,
        servertime=servertime,
        dynamic_key=dynamic_key,
    )
    return BootstrapExchange(
        udid=udid,
        request=request,
        response=response.payload,
        response_body=response.body,
    )


def process_load_title_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Decode a final-client load/title request and build the minimal valid reply."""
    udid, request = decode_client_request(headers, body, route="load/title")
    sid = _get_header(headers, "SID")
    response = encode_load_title_response(
        udid,
        sid=sid,
        servertime=servertime,
        dynamic_key=dynamic_key,
    )
    return BootstrapExchange(
        udid=udid,
        request=request,
        response=response.payload,
        response_body=response.body,
    )
