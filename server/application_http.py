"""Generic dynamic-application extension for the existing CGSS HTTP front end.

This module deliberately sits *above* :mod:`server.http_server`: bootstrap/static
routes keep using the existing handler unchanged, while explicitly registered
application routes receive decoded requests through ``process_application_request``.
No endpoint-specific business logic lives here.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Type

from .bootstrap_core import process_application_request
from .http_server import MAX_REQUEST_BODY, make_handler

ApplicationHandler = Callable[[Any], Mapping[str, Any]]


def extend_handler_with_applications(
    base_handler: Type[BaseHTTPRequestHandler],
    application_handlers: Mapping[str, ApplicationHandler],
) -> Type[BaseHTTPRequestHandler]:
    """Return a handler class that intercepts only explicitly registered routes."""

    handlers = {
        "/" + route.split("?", 1)[0].lstrip("/"): handler
        for route, handler in application_handlers.items()
    }

    class CGSSApplicationHandler(base_handler):
        def do_POST(self) -> None:  # noqa: N802
            route = self.path.split("?", 1)[0]
            application_handler = handlers.get(route)
            if application_handler is None:
                super().do_POST()
                return

            headers = self._safe_headers()  # type: ignore[attr-defined]
            contract_candidates = self._contract_candidates(route)  # type: ignore[attr-defined]
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._record(  # type: ignore[attr-defined]
                    route,
                    411,
                    headers=headers,
                    error="content_length_required",
                    contract_candidates=contract_candidates,
                )
                self._send_bytes(  # type: ignore[attr-defined]
                    411,
                    b"content-length required\n",
                    "text/plain; charset=utf-8",
                )
                return
            try:
                length = int(raw_length)
            except ValueError:
                self._record(  # type: ignore[attr-defined]
                    route,
                    400,
                    headers=headers,
                    error="invalid_content_length",
                    contract_candidates=contract_candidates,
                )
                self._send_bytes(  # type: ignore[attr-defined]
                    400,
                    b"invalid content-length\n",
                    "text/plain; charset=utf-8",
                )
                return
            if length < 0 or length > MAX_REQUEST_BODY:
                self._record(  # type: ignore[attr-defined]
                    route,
                    413,
                    headers=headers,
                    error="request_body_too_large",
                    contract_candidates=contract_candidates,
                )
                self._send_bytes(  # type: ignore[attr-defined]
                    413,
                    b"request body too large\n",
                    "text/plain; charset=utf-8",
                )
                return

            body = self.rfile.read(length)
            try:
                exchange = process_application_request(
                    headers,
                    body,
                    route=route,
                    handler=application_handler,
                )
            except (KeyError, ValueError, UnicodeError) as exc:
                self._record(  # type: ignore[attr-defined]
                    route,
                    400,
                    headers=headers,
                    error=type(exc).__name__,
                    contract_candidates=contract_candidates,
                )
                message = (
                    f"invalid CGSS {route.lstrip('/')} request: {type(exc).__name__}\n"
                ).encode("ascii")
                self._send_bytes(400, message, "text/plain; charset=utf-8")  # type: ignore[attr-defined]
                return

            self._record(  # type: ignore[attr-defined]
                route,
                200,
                headers=headers,
                request=exchange.request,
                response=exchange.response,
                contract_candidates=contract_candidates,
            )
            self._send_bytes(200, exchange.response_body)  # type: ignore[attr-defined]

    return CGSSApplicationHandler


def create_application_server(
    host: str,
    port: int,
    *,
    application_handlers: Mapping[str, ApplicationHandler],
    **bootstrap_handler_kwargs: Any,
) -> ThreadingHTTPServer:
    """Create the normal CGSS front end plus explicitly registered dynamic routes."""

    base = make_handler(**bootstrap_handler_kwargs)
    handler = extend_handler_with_applications(base, application_handlers)
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server
