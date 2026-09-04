"""Verified CGSS 11.6.3 endpoint registry helpers.

A small control-plane subset is embedded for normal server routing. A complete
supplied ``final_map.json`` can optionally be loaded at runtime for diagnostics;
loading is strict and never fills missing keys or guesses endpoint records.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

EXPECTED_A_KEYS = frozenset(range(516))
EXPECTED_B_KEYS = frozenset({0, 1, 2, *range(8, 27)})


@dataclass(frozen=True)
class ApiEndpoint:
    group: str
    name: str
    key: int
    path: str
    literal_index: int


# A-group load/control surface from the final 11.6.3 ApiType.ApiList.
A_LOAD_ENDPOINTS = (
    ApiEndpoint("A", "VersionCheck", 0, "load/check", 28434),
    ApiEndpoint("A", "SetCacheClearFlg", 1, "load/set_cache_clear_flg", 28437),
    ApiEndpoint("A", "Title", 10, "load/title", 28438),
    ApiEndpoint("A", "Load", 11, "load/index", 28436),
    ApiEndpoint("A", "LoadGetExternalSiteUrl", 12, "load/get_external_site_url", 28435),
    ApiEndpoint("A", "LoadUpdateAgreementStatus", 13, "load/update_agreement_status", 28439),
)

A_LOAD_BY_KEY = {endpoint.key: endpoint for endpoint in A_LOAD_ENDPOINTS}
A_LOAD_BY_NAME = {endpoint.name: endpoint for endpoint in A_LOAD_ENDPOINTS}
A_LOAD_BY_PATH = {endpoint.path: endpoint for endpoint in A_LOAD_ENDPOINTS}

VERSION_CHECK = A_LOAD_BY_KEY[0]
SET_CACHE_CLEAR_FLG = A_LOAD_BY_KEY[1]
TITLE = A_LOAD_BY_KEY[10]
LOAD_INDEX = A_LOAD_BY_KEY[11]
LOAD_GET_EXTERNAL_SITE_URL = A_LOAD_BY_KEY[12]
LOAD_UPDATE_AGREEMENT_STATUS = A_LOAD_BY_KEY[13]

# Final native proof status:
# - SetCacheClearFlgTask has no Parse override -> common NetworkTask.Parse only.
# - LoadUpdateAgreementStatusTask.Parse is a direct tail-call to NetworkTask.Parse.
# - LoadGetExternalSiteUrlTask.Parse optionally consumes data.url, so it remains
#   diagnostic-only until functional URL semantics are needed.
EMPTY_SUCCESS_ENDPOINTS = frozenset({SET_CACHE_CLEAR_FLG, LOAD_UPDATE_AGREEMENT_STATUS})

# The complete final A-group map contains no home/index or home/load endpoint.
# The only home/* entry is a later customization mutation.
HOME_CUSTOMIZE_UPDATE = ApiEndpoint("A", "HomeCustomizeUpdate", 234, "home/update", 26713)

# B-group (VR/login) anchors; kept separate from the normal A-group bootstrap.
VR_LOGIN_CHECK = ApiEndpoint("B", "LoginCheck", 0, "vr/login/check", 33796)
VR_LOAD = ApiEndpoint("B", "Load", 9, "vr/login/load", 33797)


def route(path: str) -> str:
    """Normalize a relative endpoint path to the HTTP path used by the server."""
    return "/" + path.lstrip("/")


BOOTSTRAP_HTTP_ROUTES = frozenset(
    {
        route(VERSION_CHECK.path),
        route(SET_CACHE_CLEAR_FLG.path),
        route(TITLE.path),
        route(LOAD_INDEX.path),
        route(LOAD_UPDATE_AGREEMENT_STATUS.path),
    }
)

EMPTY_SUCCESS_HTTP_ROUTES = frozenset(route(endpoint.path) for endpoint in EMPTY_SUCCESS_ENDPOINTS)

# Runtime-proven early bootstrap routes outside the small embedded A-load subset.
# Their complete ApiType key/literal identities are intentionally not guessed here.
MIGRATION_STATUS_CHECK_HTTP_ROUTE = "/bnid/status_check/check"
LOGIN_SIGNUP_HTTP_ROUTES = frozenset({"/tool/signup", "/tool/signup_migration"})
BOOTSTRAP_HTTP_ROUTES = frozenset(
    {*BOOTSTRAP_HTTP_ROUTES, MIGRATION_STATUS_CHECK_HTTP_ROUTE, *LOGIN_SIGNUP_HTTP_ROUTES}
)


def _parse_entry(group_name: str, raw: Any) -> ApiEndpoint:
    if not isinstance(raw, list) or len(raw) != 4:
        raise ValueError(f"invalid {group_name} endpoint entry: {raw!r}")
    name, key, path, literal_index = raw
    if not isinstance(name, str) or not name:
        raise ValueError(f"invalid {group_name} enum name: {raw!r}")
    if not isinstance(key, int):
        raise ValueError(f"invalid {group_name} key: {raw!r}")
    if not isinstance(path, str) or not path or path.startswith("/"):
        raise ValueError(f"invalid {group_name} relative path: {raw!r}")
    if not isinstance(literal_index, int) or literal_index < 0:
        raise ValueError(f"invalid {group_name} literal index: {raw!r}")
    return ApiEndpoint(group_name, name, key, path, literal_index)


def parse_delivered_map(raw: Any) -> tuple[ApiEndpoint, ...]:
    """Validate and parse the complete delivered final-map object."""
    if not isinstance(raw, dict) or set(raw) != {"A", "B"}:
        raise ValueError("API map root must contain exactly groups A and B")

    parsed: list[ApiEndpoint] = []
    keys_by_group: dict[str, list[int]] = {}
    for group_name in ("A", "B"):
        entries = raw[group_name]
        if not isinstance(entries, list):
            raise ValueError(f"API map group {group_name} must be a list")
        group_entries = [_parse_entry(group_name, entry) for entry in entries]
        keys = [entry.key for entry in group_entries]
        if len(keys) != len(set(keys)):
            raise ValueError(f"API map group {group_name} contains duplicate keys")
        keys_by_group[group_name] = keys
        parsed.extend(group_entries)

    actual_a = set(keys_by_group["A"])
    actual_b = set(keys_by_group["B"])
    if actual_a != EXPECTED_A_KEYS:
        raise ValueError(
            f"API map group A key coverage mismatch: "
            f"missing={sorted(EXPECTED_A_KEYS - actual_a)}, "
            f"extra={sorted(actual_a - EXPECTED_A_KEYS)}"
        )
    if actual_b != EXPECTED_B_KEYS:
        raise ValueError(
            f"API map group B key coverage mismatch: "
            f"missing={sorted(EXPECTED_B_KEYS - actual_b)}, "
            f"extra={sorted(actual_b - EXPECTED_B_KEYS)}"
        )
    return tuple(parsed)


def load_delivered_map(path: Path) -> tuple[ApiEndpoint, ...]:
    return parse_delivered_map(json.loads(path.read_text(encoding="utf-8")))


def by_http_path(endpoints: Iterable[ApiEndpoint]) -> dict[str, tuple[ApiEndpoint, ...]]:
    """Build a one-to-many HTTP path index; aliases are preserved."""
    grouped: dict[str, list[ApiEndpoint]] = {}
    for endpoint in endpoints:
        grouped.setdefault(route(endpoint.path), []).append(endpoint)
    return {path: tuple(entries) for path, entries in grouped.items()}
