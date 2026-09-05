"""CGSS client compatibility adapters.

Adapters own endpoint/wire DTO details and translate to/from ``server.domain``.
The preservation domain must not import this package.
"""

from .load_index import (
    CardLoadIndexBinding,
    LoadIndexProjectionPolicy,
    UnitLoadIndexBinding,
    project_home_snapshot_to_load_index_data,
)
from .member_protect import (
    MemberProtectRequest,
    parse_member_protect_request,
    project_member_protect_response_data,
)

__all__ = [
    "CardLoadIndexBinding",
    "LoadIndexProjectionPolicy",
    "MemberProtectRequest",
    "UnitLoadIndexBinding",
    "parse_member_protect_request",
    "project_home_snapshot_to_load_index_data",
    "project_member_protect_response_data",
]
