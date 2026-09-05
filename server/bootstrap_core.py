"""Transport-independent bootstrap and reconstructed-route logic.

This module accepts HTTP-like headers plus raw encrypted bodies and returns
wire-compatible responses. Socket/TLS/DNS concerns are kept out of this layer so
reconstructed CGSS contracts can be tested deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import cgss_codec
from .bn_consent import NORMAL_CONSENT_STATE, encode_bn_consent_state_response
from .empty_success import encode_empty_success_response
from .header_codec import decode_header_value
from .load_check import FINAL_RESOURCE_VERSION, encode_load_check_response
from .load_index import encode_load_index_response
from .load_title import encode_load_title_response
from .login_signup import encode_login_signup_response
from .migration_check import NORMAL_TRANSITION, encode_migration_check_response
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


def process_migration_check_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
    transition: int = NORMAL_TRANSITION,
) -> BootstrapExchange:
    """Decode BNID status-check and return the verified normal migration state."""
    udid, request = decode_client_request(headers, body, route="bnid/status_check/check")
    sid = _get_header(headers, "SID")
    response = encode_migration_check_response(
        udid,
        sid=sid,
        servertime=servertime,
        transition=transition,
        dynamic_key=dynamic_key,
    )
    return BootstrapExchange(
        udid=udid,
        request=request,
        response=response.payload,
        response_body=response.body,
    )


def process_login_signup_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    route: str,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
    change_domain_enabled: bool = False,
    viewer_id: int = 1,
    user_id: int = 1,
) -> BootstrapExchange:
    """Decode a final-client signup request and return the shared LoginTask contract."""
    normalized = route.lstrip("/")
    if normalized not in {"tool/signup", "tool/signup_migration"}:
        raise ValueError(f"unsupported login signup route: {route}")
    udid, request = decode_client_request(headers, body, route=normalized)
    sid = _get_header(headers, "SID")
    response = encode_login_signup_response(
        udid,
        sid=sid,
        servertime=servertime,
        change_domain_enabled=change_domain_enabled,
        dynamic_key=dynamic_key,
        viewer_id=viewer_id,
        user_id=user_id,
    )
    return BootstrapExchange(
        udid=udid,
        request=request,
        response=response.payload,
        response_body=response.body,
    )


def process_bn_consent_state_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
    consent_state: int = NORMAL_CONSENT_STATE,
) -> BootstrapExchange:
    """Decode ``/bn_consent/get_state`` and return the proven integer state field."""
    udid, request = decode_client_request(headers, body, route="bn_consent/get_state")
    sid = _get_header(headers, "SID")
    response = encode_bn_consent_state_response(
        udid,
        sid=sid,
        servertime=servertime,
        consent_state=consent_state,
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
    """Encode one explicitly supplied reconstructed non-bootstrap response."""
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


def process_application_request(
    headers: Mapping[str, str],
    body: bytes | str,
    *,
    route: str,
    handler: Callable[[Any], Mapping[str, Any]],
    servertime: int | None = None,
    dynamic_key: bytes | None = None,
) -> BootstrapExchange:
    """Run a dynamic application handler behind the common CGSS transport envelope.

    ``handler`` receives the decoded endpoint request object and returns only the
    endpoint ``data`` object. Domain/application code therefore stays independent of
    UDID headers, encryption, SID propagation and common response headers.
    """

    clean_route = "/" + route.split("?", 1)[0].lstrip("/")
    udid, request = decode_client_request(headers, body, route=clean_route.lstrip("/"))
    data = handler(request)
    if not isinstance(data, Mapping):
        raise ValueError("application handler must return a mapping data object")
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
