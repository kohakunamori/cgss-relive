"""Synthetic ``/load/index`` archival profiles for CGSS Android 11.6.3.

The strict minimal profile contains only fields that the final client is known
to read on the selected bootstrap path.  The separate home-candidate profile
adds parser-safe empty containers for several Home-facing managers.  Neither
profile contains captured account data, and neither is claimed to be runtime-
accepted until exercised by the original 11.6.3 client.
"""
from __future__ import annotations

import time
from typing import Any


# ``data.common_define`` fields read unconditionally by the final 11.6.3 parser
# before it switches to ContainsKey-guarded optional fields.
REQUIRED_COMMON_DEFINE_FIELDS = (
    "expanding_count",
    "expanding_jewel",
    "expanding_max",
    "stamina_recovery_jewel",
    "stamina_recovery_time",
    "room_lvup_shortening_time",
    "room_lvup_jewel",
)

# Fields read unconditionally once ``data.user_info`` is present in the main
# player-data branch. ``tutorial_flag`` is additionally consumed by the tutorial
# bootstrap path for a fresh/local state.
REQUIRED_USER_INFO_FIELDS = (
    "tutorial_flag",
    "viewer_id",
    "name",
    "comment",
    "max_card_num",
    "max_room_storage_num",
    "friend_pt",
    "jewel",
    "free_jewel",
    "gold",
    "stamina",
    "level",
    "exp",
    "fan",
    "producer_rank",
    "birth",
    "sum_of_money",
    "last_payment_date",
    "stamina_heal_time",
)

# These top-level sections are individually ContainsKey-guarded by the final
# ``Stage.LoadTask.Parse`` and then treated as list-like containers. Supplying an
# empty list therefore avoids fabricating records whose master-data validity
# would otherwise have to be proven first.
HOME_CANDIDATE_EMPTY_LIST_SECTIONS = (
    "user_card_list",
    "user_unit_list",
    "user_chara_list",
    "album_list",
    "user_mv_unit_list",
    "user_grand_mv_unit_list",
    "item_list",
    "user_live_list",
    "master_plus_live_list",
)

# A subtle dependency proven in the final native parser: once user_unit_list is
# present (even when empty), the parser reads data.user_info.unit_slot before it
# checks the unit-list count. This field therefore belongs to the Home candidate,
# not to the strict profile where user_unit_list is absent.
HOME_CANDIDATE_USER_INFO_FIELDS = ("unit_slot",)


def build_minimal_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return the smallest statically justified archival profile.

    Values are deliberately conservative non-production defaults. The goal is
    parser compatibility, not faithful emulation of an existing account.
    """
    timestamp = int(time.time() if now is None else now)
    return {
        "common_define": {
            "expanding_count": 5,
            "expanding_jewel": 50,
            "expanding_max": 300,
            "stamina_recovery_jewel": 50,
            "stamina_recovery_time": 300,
            "room_lvup_shortening_time": 720,
            "room_lvup_jewel": 1,
        },
        "user_info": {
            # In the final native bootstrap path, local tutorial step 1000 is
            # normalized to server-side step 100. This is the lightest completed
            # tutorial branch identified so far.
            "tutorial_flag": 100,
            "viewer_id": int(viewer_id),
            "name": str(producer_name),
            "comment": "",
            "max_card_num": 300,
            "max_room_storage_num": 500,
            "friend_pt": 0,
            "jewel": 0,
            "free_jewel": 0,
            "gold": 0,
            "stamina": 100,
            "level": 1,
            "exp": 0,
            "fan": 0,
            "producer_rank": 1,
            "birth": 0,
            "sum_of_money": 0,
            "last_payment_date": 0,
            "stamina_heal_time": timestamp,
        },
    }


def build_home_candidate_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return a parser-safe candidate intended for the first Home transition.

    This deliberately does *not* invent starter cards or units. Instead it adds
    empty containers whose final-client parsers are section-guarded, allowing
    their corresponding managers to observe an explicit empty state.

    ``user_unit_list`` has one proven side dependency: its presence causes the
    parser to directly read ``user_info.unit_slot`` before list iteration.

    ``music_list`` is also special: once that optional top-level map is present,
    the final parser directly reads its ``normal`` list. ``sp`` is separately
    guarded, so the smallest safe shape is ``{"normal": []}``.
    """
    data = build_minimal_load_index_data(
        viewer_id=viewer_id,
        producer_name=producer_name,
        now=now,
    )
    data["user_info"]["unit_slot"] = 1
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        data[section] = []
    data["music_list"] = {"normal": []}
    return data


def validate_minimal_profile(data: dict[str, Any]) -> list[str]:
    """Return missing statically-required field paths for a candidate profile."""
    missing: list[str] = []
    common = data.get("common_define")
    if not isinstance(common, dict):
        missing.append("common_define")
    else:
        missing.extend(
            f"common_define.{name}"
            for name in REQUIRED_COMMON_DEFINE_FIELDS
            if name not in common
        )

    user = data.get("user_info")
    if not isinstance(user, dict):
        missing.append("user_info")
    else:
        missing.extend(
            f"user_info.{name}"
            for name in REQUIRED_USER_INFO_FIELDS
            if name not in user
        )
    return missing


def validate_home_candidate_profile(data: dict[str, Any]) -> list[str]:
    """Validate the additional statically-proven Home-candidate shapes."""
    errors = validate_minimal_profile(data)
    user = data.get("user_info")
    if isinstance(user, dict):
        for name in HOME_CANDIDATE_USER_INFO_FIELDS:
            if name not in user:
                errors.append(f"user_info.{name}")
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        value = data.get(section)
        if not isinstance(value, list):
            errors.append(section)
    music = data.get("music_list")
    if not isinstance(music, dict):
        errors.append("music_list")
    elif not isinstance(music.get("normal"), list):
        errors.append("music_list.normal")
    return errors
