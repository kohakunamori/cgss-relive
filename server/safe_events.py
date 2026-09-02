"""Sanitized runtime event logging for real-client integration.

The event format intentionally excludes UDID, SID, USER-ID, PARAM, request body
values and decoded viewer/account identifiers.  It records only route/status,
version headers, object key shapes, response result codes, and optional public
ApiType endpoint identities needed to continue clean-room reconstruction.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

SAFE_HEADER_NAMES = ("APP-VER", "RES-VER", "X-Unity-Version")


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def object_keys(value: Any) -> list[str] | None:
    if not isinstance(value, Mapping):
        return None
    return sorted(str(key) for key in value.keys())


def build_event(
    *,
    route: str,
    status: int,
    headers: Mapping[str, str] | None = None,
    request: Any = None,
    response: Any = None,
    error: str | None = None,
    api_candidates: Sequence[Mapping[str, Any]] | None = None,
    timestamp: float | None = None,
) -> dict[str, Any]:
    headers = headers or {}
    event: dict[str, Any] = {
        "time": float(time.time() if timestamp is None else timestamp),
        "route": route,
        "status": int(status),
    }
    safe_headers = {
        name: value
        for name in SAFE_HEADER_NAMES
        if (value := _get_header(headers, name)) is not None
    }
    if safe_headers:
        event["headers"] = safe_headers
    if api_candidates:
        event["api_candidates"] = [
            {
                "group": str(candidate["group"]),
                "key": int(candidate["key"]),
                "name": str(candidate["name"]),
                "literal_index": int(candidate["literal_index"]),
            }
            for candidate in api_candidates
        ]
    request_keys = object_keys(request)
    if request_keys is not None:
        event["request_keys"] = request_keys
    if isinstance(response, Mapping):
        response_keys = object_keys(response)
        if response_keys is not None:
            event["response_keys"] = response_keys
        data = response.get("data")
        data_keys = object_keys(data)
        if data_keys is not None:
            event["response_data_keys"] = data_keys
        data_headers = response.get("data_headers")
        if isinstance(data_headers, Mapping):
            summary: dict[str, Any] = {}
            for name in ("result_code", "required_res_ver", "app_ver"):
                if name in data_headers:
                    summary[name] = data_headers[name]
            if summary:
                event["response_data_headers"] = summary
    if error:
        event["error"] = str(error)
    return event


class SafeEventLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def append(self, event: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(dict(event), ensure_ascii=False, sort_keys=True) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
