"""Candidate minimal ``/load/index`` archival profile for CGSS Android 11.6.3.

This profile is intentionally synthetic and contains no captured account data.
The field set is derived from direct final-client IL2CPP reads in
``Stage.LoadTask.Parse``.  It is *not* claimed to be runtime-validated yet: the
real client may reveal additional state-dependent requirements during the first
integration run.
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


def build_minimal_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return the current smallest statically justified archival profile.

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
            # Final-client setupTutorial maps the server value 100 to the local
            # completed-tutorial step 1000, which is the lightest preservation
            # bootstrap branch identified so far.
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
