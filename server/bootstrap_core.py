"""Transport-independent bootstrap logic for the first CGSS relive server.

This module accepts HTTP-like headers plus raw encrypted bodies and returns
wire-compatible early-bootstrap responses. Socket/TLS/DNS concerns are kept out
of this layer so reconstructed CGSS contracts can be tested deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from . import cgss_codec
from .empty_success import encode_empty_success_response
from .header_codec import decode_header_value
from .load_check import FINAL_RESOURCE_VERSION, encode_load_check_response
from .load_index import encode_load_index_response
from .load_title import encode_load_title_response
from .template_response import encode_template_success_response


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
    is_s3: bool | None = False,
    accept_old_resource_version: bool = False,
) -> BootstrapExchange:
    """Decode a final-client load/check request and build its encrypted reply.

    The HTTP-facing server defaults ``is_s3`` to false so a successful version
    check selects the statically reconstructed storages-host URL family. Set
    ``accept_old_resource_version`` only for controlled runtime differential
    tests; normal behavior still returns 214 on a resource-version mismatch.
    """
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
        is_s3=is_s3,
        accept_old_resource_version=accept_old_resource_version,
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


def process_empty_success_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    route: str,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Handle a task proven to consume only the common NetworkTask response."""
    udid, request = decode_client_request(headers, body, route=route.lstrip("/"))
    sid = _get_header(headers, "SID")
    response = encode_empty_success_response(
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


def process_load_index_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    data: Mapping[str, Any],
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Decode ``/load/index`` and return an encrypted injected archival profile."""
    udid, request = decode_client_request(headers, body, route="load/index")
    sid = _get_header(headers, "SID")
    response = encode_load_index_response(
        udid,
        data,
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


def process_template_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    route: str,
    data: Mapping[str, Any],
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Encode one explicitly supplied reconstructed non-bootstrap response.

    The template contains only the endpoint ``data`` object.  Common success
    headers, SID propagation and CGSS encryption are generated here so local
    runtime experiments do not need a bespoke Python handler for every newly
    reconstructed route.
    """
    clean_route = "/" + route.split("?", 1)[0].lstrip("/")
    udid, request = decode_client_request(headers, body, route=clean_route.lstrip("/"))
    sid = _get_header(headers, "SID")
    response = encode_template_success_response(
        udid,
        data,
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
