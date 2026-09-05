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
from .member_favorite import (
    MemberFavoriteEditRequest,
    parse_member_favorite_edit_request,
)
from .member_protect import (
    MemberProtectRequest,
    parse_member_protect_request,
    project_member_protect_response_data,
)
from .story_start import (
    StoryStartRequest,
    parse_story_start_request,
    project_story_start_response_data,
)
from .unit_edit import (
    MemberUnitEditRequest,
    MemberUnitEditUnitInfo,
    parse_member_unit_edit_request,
)

__all__ = [
    "CardLoadIndexBinding",
    "LoadIndexProjectionPolicy",
    "MemberFavoriteEditRequest",
    "MemberProtectRequest",
    "MemberUnitEditRequest",
    "MemberUnitEditUnitInfo",
    "StoryStartRequest",
    "UnitLoadIndexBinding",
    "parse_member_favorite_edit_request",
    "parse_member_protect_request",
    "parse_member_unit_edit_request",
    "parse_story_start_request",
    "project_home_snapshot_to_load_index_data",
    "project_member_protect_response_data",
    "project_story_start_response_data",
]
