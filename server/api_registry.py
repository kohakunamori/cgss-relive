"""Verified CGSS 11.6.3 control-plane endpoint constants.

These entries are a deliberately small runtime subset of the supplied final
ApiType endpoint map.  The complete map remains an analysis input; server code
must not invent host assignments because the delivered map proves relative
key->path mappings, not per-endpoint host selection.
"""
from __future__ import annotations

from dataclasses import dataclass


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
TITLE = A_LOAD_BY_KEY[10]
LOAD_INDEX = A_LOAD_BY_KEY[11]

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
        route(TITLE.path),
        route(LOAD_INDEX.path),
    }
)
