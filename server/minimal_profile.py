"""Synthetic ``/load/index`` archival profiles for CGSS Android 11.6.3.

The profiles are intentionally layered:

* strict minimal: only fields directly required on the reduced bootstrap path;
* Home candidate: explicit empty containers for selected Home-facing managers;
* starter visible: one synthetic owned card/unit/character record using a card
  proven to exist in the independently verified final 10133800 master database.

No profile contains captured account data. Runtime acceptance by the original
client remains a separate integration criterion.
"""
from __future__ import annotations

import time
from typing import Any


# ``data.common_define`` fields read unconditionally by final 11.6.3 before the
# parser switches to ContainsKey-guarded optional additions.
REQUIRED_COMMON_DEFINE_FIELDS = (
    "expanding_count",
    "expanding_jewel",
    "expanding_max",
    "stamina_recovery_jewel",
    "stamina_recovery_time",
    "room_lvup_shortening_time",
    "room_lvup_jewel",
)

# Union of direct reads from the observed final ``data.user_info`` branches plus
# tutorial_flag, which is consumed by the completed-tutorial bootstrap path.
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

# These top-level sections are individually ContainsKey-guarded by final
# ``Stage.LoadTask.Parse`` and can be represented as empty lists for the Home
# candidate. ``user_unit_list`` has an additional user_info dependency below.
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

# Once user_unit_list is present (even empty), final 11.6.3 directly reads this
# field before checking the unit-list count.
HOME_CANDIDATE_USER_INFO_FIELDS = ("unit_slot",)

# Final parser directly reads these keys for every user_card_list item. join_type,
# is_custom and custom_info are separately presence/state guarded.
STARTER_CARD_REQUIRED_FIELDS = (
    "serial_id",
    "card_id",
    "exp",
    "step",
    "love",
    "skill_level",
    "protect",
)

# The final unit parser reads ``name`` and loops exactly five times over the
# format string ``serial_id_{0}`` (w20=0..4; cmp w20,#5).
FINAL_UNIT_SLOT_COUNT = 5
STARTER_UNIT_REQUIRED_FIELDS = (
    "name",
    *(f"serial_id_{index}" for index in range(FINAL_UNIT_SLOT_COUNT)),
)
STARTER_CHARA_REQUIRED_FIELDS = ("chara_id", "fan")

# Verified by the independent 10133800 master-resource CI, not copied from an
# account response. Serial ID 1 is synthetic local ownership state.
STARTER_CARD_ID = 100001
STARTER_CHARA_ID = 101
STARTER_SERIAL_ID = 1
STARTER_UNIT_SLOT = 1


def build_minimal_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return the smallest statically justified archival profile."""
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
            # Final bootstrap normalizes server-side tutorial step 100 into the
            # local completed step 1000.
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
    """Return a parser-safe empty-state candidate for the first Home transition."""
    data = build_minimal_load_index_data(
        viewer_id=viewer_id,
        producer_name=producer_name,
        now=now,
    )
    data["user_info"]["unit_slot"] = STARTER_UNIT_SLOT
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        data[section] = []

    # Once music_list exists, final 11.6.3 directly reads normal; sp is guarded.
    data["music_list"] = {"normal": []}
    return data


def build_starter_visible_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return a tiny synthetic profile with one visible final-master starter card.

    ``100001`` / 島村卯月 is selected only because the final 10133800 master CI
    independently proves the card and chara id are present. The ownership serial,
    unit composition, producer identity and progress values are synthetic.
    """
    data = build_home_candidate_load_index_data(
        viewer_id=viewer_id,
        producer_name=producer_name,
        now=now,
    )
    data["user_card_list"] = [
        {
            "serial_id": STARTER_SERIAL_ID,
            "card_id": STARTER_CARD_ID,
            "exp": 0,
            "step": 0,
            "love": 0,
            "skill_level": 1,
            "protect": 0,
        }
    ]
    data["user_unit_list"] = [
        {
            "name": "Relive Unit",
            "serial_id_0": STARTER_SERIAL_ID,
            "serial_id_1": 0,
            "serial_id_2": 0,
            "serial_id_3": 0,
            "serial_id_4": 0,
        }
    ]
    data["user_chara_list"] = [{"chara_id": STARTER_CHARA_ID, "fan": 0}]

    # leader_serial_id is presence-guarded by the final parser, so it is not part
    # of the mandatory schema. Supplying the owned serial here is an intentional
    # functional choice for a Home-visible profile.
    data["user_info"]["leader_serial_id"] = STARTER_SERIAL_ID
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
    """Validate additional statically-proven Home-candidate container shapes."""
    errors = validate_minimal_profile(data)
    user = data.get("user_info")
    if isinstance(user, dict):
        for name in HOME_CANDIDATE_USER_INFO_FIELDS:
            if name not in user:
                errors.append(f"user_info.{name}")
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        if not isinstance(data.get(section), list):
            errors.append(section)
    music = data.get("music_list")
    if not isinstance(music, dict):
        errors.append("music_list")
    elif not isinstance(music.get("normal"), list):
        errors.append("music_list.normal")
    return errors


def _missing_item_fields(item: Any, fields: tuple[str, ...], prefix: str) -> list[str]:
    if not isinstance(item, dict):
        return [prefix]
    return [f"{prefix}.{field}" for field in fields if field not in item]


def validate_starter_visible_profile(data: dict[str, Any]) -> list[str]:
    """Validate the statically-derived one-card starter-visible contract."""
    errors = validate_home_candidate_profile(data)

    cards = data.get("user_card_list")
    if not isinstance(cards, list) or len(cards) != 1:
        errors.append("user_card_list[1]")
    else:
        errors.extend(_missing_item_fields(cards[0], STARTER_CARD_REQUIRED_FIELDS, "user_card_list[0]"))
        if isinstance(cards[0], dict):
            if cards[0].get("serial_id") != STARTER_SERIAL_ID:
                errors.append("user_card_list[0].serial_id")
            if cards[0].get("card_id") != STARTER_CARD_ID:
                errors.append("user_card_list[0].card_id")

    units = data.get("user_unit_list")
    if not isinstance(units, list) or len(units) != 1:
        errors.append("user_unit_list[1]")
    else:
        errors.extend(_missing_item_fields(units[0], STARTER_UNIT_REQUIRED_FIELDS, "user_unit_list[0]"))
        if isinstance(units[0], dict):
            if units[0].get("serial_id_0") != STARTER_SERIAL_ID:
                errors.append("user_unit_list[0].serial_id_0")
            for index in range(1, FINAL_UNIT_SLOT_COUNT):
                if units[0].get(f"serial_id_{index}") != 0:
                    errors.append(f"user_unit_list[0].serial_id_{index}")

    charas = data.get("user_chara_list")
    if not isinstance(charas, list) or len(charas) != 1:
        errors.append("user_chara_list[1]")
    else:
        errors.extend(_missing_item_fields(charas[0], STARTER_CHARA_REQUIRED_FIELDS, "user_chara_list[0]"))
        if isinstance(charas[0], dict) and charas[0].get("chara_id") != STARTER_CHARA_ID:
            errors.append("user_chara_list[0].chara_id")

    user = data.get("user_info")
    if isinstance(user, dict):
        if user.get("unit_slot") != STARTER_UNIT_SLOT:
            errors.append("user_info.unit_slot")
        leader = user.get("leader_serial_id")
        if leader is not None and leader != STARTER_SERIAL_ID:
            errors.append("user_info.leader_serial_id")
    return errors
