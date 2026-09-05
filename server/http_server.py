"""Minimal HTTP/TLS front end for the CGSS preservation bootstrap.

Early bootstrap routes are deliberately thin adapters over :mod:`bootstrap_core`
so socket/TLS choices remain independent from reconstructed CGSS contracts.

Raw ``BaseHTTPRequestHandler`` access logging is suppressed. Runtime integration
must use :mod:`server.safe_events`, whose schema intentionally excludes query
strings, request bodies, account/session identifiers, and non-whitelisted
headers. This prevents terminal transcripts from bypassing the clean-room log
boundary even if a future client route carries sensitive query parameters.
"""
from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Type

from .api_registry import (
    ApiEndpoint,
    BN_CONSENT_GET_STATE,
    BOOTSTRAP_HTTP_ROUTES,
    EMPTY_SUCCESS_HTTP_ROUTES,
    LOAD_INDEX,
    LOGIN_SIGNUP_HTTP_ROUTES,
    MIGRATION_STATUS_CHECK_HTTP_ROUTE,
    TITLE,
    VERSION_CHECK,
    by_http_path,
    load_delivered_map,
    route as api_route,
)
from .bootstrap_core import (
    process_empty_success_request,
    process_bn_consent_state_request,
    process_load_check_request,
    process_load_index_request,
    process_load_title_request,
    process_login_signup_request,
    process_migration_check_request,
)
from .load_check import FINAL_RESOURCE_VERSION
from .minimal_profile import (
    build_home_candidate_load_index_data,
    build_minimal_load_index_data,
    build_starter_visible_load_index_data,
)
from .safe_events import SafeEventLog, build_event

MAX_REQUEST_BODY = 8 * 1024 * 1024
ROUTE_VERSION_CHECK = api_route(VERSION_CHECK.path)
ROUTE_TITLE = api_route(TITLE.path)
ROUTE_LOAD_INDEX = api_route(LOAD_INDEX.path)
ROUTE_MIGRATION_STATUS_CHECK = MIGRATION_STATUS_CHECK_HTTP_ROUTE
ROUTE_BN_CONSENT_GET_STATE = api_route(BN_CONSENT_GET_STATE.path)


def make_handler(
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    load_index_data: Mapping[str, Any] | None = None,
    event_log: Path | None = None,
    api_index: Mapping[str, tuple[ApiEndpoint, ...]] | None = None,
    accept_old_resource_version: bool = False,
    resource_is_s3: bool = False,
    viewer_id: int = 1,
    user_id: int = 1,
) -> Type[BaseHTTPRequestHandler]:
    events = SafeEventLog(event_log) if event_log is not None else None
    api_index = api_index or {}

    class CGSSBootstrapHandler(BaseHTTPRequestHandler):
        server_version = "cgss-relive/0.2"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            # BaseHTTPRequestHandler's default access log includes the complete
            # raw request line. A future API may place sensitive values in the
            # query string, so never let that line escape to stderr. The
            # sanitized JSONL event log is the supported runtime trace.
            return

        def _safe_headers(self) -> dict[str, str]:
            # Passing the mapping into build_event is safe: build_event copies
            # only its explicit version-header allow-list into persisted output.
            return {key: value for key, value in self.headers.items()}

        def _record(
            self,
            route: str,
            status: int,
            *,
            headers: Mapping[str, str] | None = None,
            request: Any = None,
            response: Any = None,
            error: str | None = None,
        ) -> None:
            if events is None:
                return
            candidates = [
                {
                    "group": endpoint.group,
                    "key": endpoint.key,
                    "name": endpoint.name,
                    "literal_index": endpoint.literal_index,
                }
                for endpoint in api_index.get(route, ())
            ]
            events.append(
                build_event(
                    route=route,
                    status=status,
                    headers=headers,
                    request=request,
                    response=response,
                    error=error,
                    api_candidates=candidates,
                )
            )

        def _send_bytes(self, status: int, body: bytes, content_type: str = "application/octet-stream") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send_bytes(200, b"ok\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            route = self.path.split("?", 1)[0]
            headers = self._safe_headers()
            if route not in BOOTSTRAP_HTTP_ROUTES:
                self._record(route, 404, headers=headers, error="endpoint_not_implemented")
                self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")
                return
            if route == ROUTE_LOAD_INDEX and load_index_data is None:
                self._record(route, 503, headers=headers, error="load_index_profile_not_configured")
                self._send_bytes(503, b"load/index profile is not configured\n", "text/plain; charset=utf-8")
                return

            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._record(route, 411, headers=headers, error="content_length_required")
                self._send_bytes(411, b"content-length required\n", "text/plain; charset=utf-8")
                return
            try:
                length = int(raw_length)
            except ValueError:
                self._record(route, 400, headers=headers, error="invalid_content_length")
                self._send_bytes(400, b"invalid content-length\n", "text/plain; charset=utf-8")
                return
            if length < 0 or length > MAX_REQUEST_BODY:
                self._record(route, 413, headers=headers, error="request_body_too_large")
                self._send_bytes(413, b"request body too large\n", "text/plain; charset=utf-8")
                return

            body = self.rfile.read(length)
            try:
                if route == ROUTE_VERSION_CHECK:
                    exchange = process_load_check_request(
                        headers,
                        body,
                        final_res_ver=final_res_ver,
                        is_s3=resource_is_s3,
                        accept_old_resource_version=accept_old_resource_version,
                    )
                elif route == ROUTE_TITLE:
                    exchange = process_load_title_request(headers, body)
                elif route == ROUTE_MIGRATION_STATUS_CHECK:
                    exchange = process_migration_check_request(headers, body)
                elif route == ROUTE_BN_CONSENT_GET_STATE:
                    exchange = process_bn_consent_state_request(headers, body)
                elif route in LOGIN_SIGNUP_HTTP_ROUTES:
                    exchange = process_login_signup_request(
                        headers, body, route=route, viewer_id=viewer_id, user_id=user_id
                    )
                elif route == ROUTE_LOAD_INDEX:
                    assert load_index_data is not None
                    exchange = process_load_index_request(headers, body, data=load_index_data)
                else:
                    assert route in EMPTY_SUCCESS_HTTP_ROUTES
                    exchange = process_empty_success_request(headers, body, route=route)
            except (ValueError, UnicodeError) as exc:
                self._record(route, 400, headers=headers, error=type(exc).__name__)
                message = f"invalid CGSS {route.lstrip('/')} request: {type(exc).__name__}\n".encode("ascii")
                self._send_bytes(400, message, "text/plain; charset=utf-8")
                return

            self._record(
                route,
                200,
                headers=headers,
                request=exchange.request,
                response=exchange.response,
            )
            self._send_bytes(200, exchange.response_body)

    return CGSSBootstrapHandler


def create_server(
    host: str,
    port: int,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    load_index_data: Mapping[str, Any] | None = None,
    event_log: Path | None = None,
    api_index: Mapping[str, tuple[ApiEndpoint, ...]] | None = None,
    accept_old_resource_version: bool = False,
    resource_is_s3: bool = False,
    viewer_id: int = 1,
    user_id: int = 1,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(
            final_res_ver,
            load_index_data,
            event_log,
            api_index,
            accept_old_resource_version,
            resource_is_s3,
            viewer_id,
            user_id,
        ),
    )
    server.daemon_threads = True
    return server


def _load_profile(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("load/index profile JSON must contain an object at its root")
    if "data_headers" in value and "data" in value:
        data = value["data"]
        if not isinstance(data, dict):
            raise ValueError("load/index profile response has a non-object data field")
        return data
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the cgss-relive bootstrap endpoints")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--final-res-ver", default=FINAL_RESOURCE_VERSION)
    parser.add_argument(
        "--accept-old-resource-version",
        action="store_true",
        help=(
            "diagnostic only: return result_code=1 for an old RES-VER while still "
            "supplying required_res_ver; bypasses the native 214 gate"
        ),
    )
    parser.add_argument(
        "--resource-is-s3",
        action="store_true",
        help=(
            "return data.isS3=true from /load/check so the final client selects "
            "the CDN resource URL family instead of storages"
        ),
    )
    parser.add_argument(
        "--load-index-profile",
        type=Path,
        help="local JSON object used as /load/index data; proprietary profiles must stay uncommitted",
    )
    parser.add_argument(
        "--experimental-minimal-load-index",
        action="store_true",
        help="use the strict statically-derived 11.6.3 minimal /load/index profile",
    )
    parser.add_argument(
        "--experimental-home-load-index",
        action="store_true",
        help="use the parser-safe Home candidate with explicit empty manager containers",
    )
    parser.add_argument(
        "--experimental-starter-load-index",
        action="store_true",
        help="use the one-card synthetic Home profile backed by final 10133800 master data",
    )
    parser.add_argument("--viewer-id", type=int, default=1, help="viewer id for a synthetic profile")
    parser.add_argument("--user-id", type=int, default=1, help="user id for the local preservation identity")
    parser.add_argument(
        "--producer-name",
        default="Relive Producer",
        help="producer name for a synthetic profile",
    )
    parser.add_argument(
        "--event-log",
        type=Path,
        help="append sanitized route/key-shape events as JSONL; raw identifiers and body values are excluded",
    )
    parser.add_argument(
        "--api-map",
        type=Path,
        help="optional complete validated final_map.json used only to annotate runtime routes",
    )
    parser.add_argument("--cert", help="PEM certificate chain for HTTPS")
    parser.add_argument("--key", help="PEM private key for HTTPS")
    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    selected_profiles = sum(
        bool(value)
        for value in (
            args.load_index_profile,
            args.experimental_minimal_load_index,
            args.experimental_home_load_index,
            args.experimental_starter_load_index,
        )
    )
    if selected_profiles > 1:
        parser.error(
            "--load-index-profile, --experimental-minimal-load-index, "
            "--experimental-home-load-index and --experimental-starter-load-index "
            "are mutually exclusive"
        )

    load_index_data = None
    if args.load_index_profile:
        try:
            load_index_data = _load_profile(args.load_index_profile)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"failed to load --load-index-profile: {exc}")
    elif args.experimental_minimal_load_index:
        load_index_data = build_minimal_load_index_data(
            viewer_id=args.viewer_id,
            producer_name=args.producer_name,
        )
    elif args.experimental_home_load_index:
        load_index_data = build_home_candidate_load_index_data(
            viewer_id=args.viewer_id,
            producer_name=args.producer_name,
        )
    elif args.experimental_starter_load_index:
        load_index_data = build_starter_visible_load_index_data(
            viewer_id=args.viewer_id,
            producer_name=args.producer_name,
        )

    api_index = None
    if args.api_map:
        try:
            api_endpoints = load_delivered_map(args.api_map)
            api_index = by_http_path(api_endpoints)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"failed to load --api-map: {exc}")

    httpd = create_server(
        args.host,
        args.port,
        final_res_ver=args.final_res_ver,
        load_index_data=load_index_data,
        event_log=args.event_log,
        api_index=api_index,
        accept_old_resource_version=args.accept_old_resource_version,
        resource_is_s3=args.resource_is_s3,
        viewer_id=args.viewer_id,
        user_id=args.user_id,
    )
    scheme = "http"
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address[:2]
    print(f"cgss-relive bootstrap listening on {scheme}://{bound_host}:{bound_port}")
    if args.accept_old_resource_version:
        print("load/check resource policy: diagnostic direct success + required_res_ver advance")
    else:
        print("load/check resource policy: native 214 negotiation on mismatch")
    print(f"load/check resource URL family: {'S3/CDN' if args.resource_is_s3 else 'storages'}")
    if args.event_log:
        print(f"sanitized event log: {args.event_log}")
    if args.api_map:
        print(f"validated final ApiType map: {args.api_map}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
