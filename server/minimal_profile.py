"""Synthetic ``/load/index`` archival profiles for CGSS Android 11.6.3.

The profiles are intentionally layered:

* strict minimal: only fields directly required on the reduced bootstrap path;
* Home candidate: explicit empty containers for selected Home-facing managers;
* starter visible: one synthetic owned card/unit record using a card proven to
  exist in the independently verified final 10133800 master database.

Final-client runtime tracing closes the owned-card path: the active
``WorkCardData.AddCardData`` callsite reads ``data.user_card_list``. The separate
``cs_gacha_data_cenere`` object is Cenere metadata; it is release-flag gated and
currently requires only ``cenere_id`` on the exercised preservation path.

The final ``Stage.BaseTask.setupTutorial`` gate is also statically closed:
response ``tutorial_flag=100`` maps to local ``TutorialData.step=1000`` and saves
that completed state. If local step is already 1000 the client internally forces
the logical flag to 100 before the same mapping.

The real ``user_chara_list`` block is now bounded as well: an empty array is safe;
a non-empty element hard-reads exactly ``chara_id`` and ``fan`` before
``WorkCharaData.AddCharaData``. Home startup analysis does not consume
``WorkCharaData``; the card predownload path obtains its character id directly
from ``WorkCardData.CardData.GetCharaId``. The starter therefore keeps
``user_chara_list=[]`` instead of fabricating an unnecessary character-state row.

No profile contains captured account data. Runtime acceptance by the original
client remains a separate integration criterion.
"""
from __future__ import annotations

import time
from typing import Any


REQUIRED_COMMON_DEFINE_FIELDS = (
    "expanding_count",
    "expanding_jewel",
    "expanding_max",
    "stamina_recovery_jewel",
    "stamina_recovery_time",
    "room_lvup_shortening_time",
    "room_lvup_jewel",
)

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

# Exact final-client setupTutorial mapping at RVA 0x476E1E4:
#   logical flag == 100 -> TutorialData.set_step(1000) -> Save().
# If the local step is already 1000, setupTutorial substitutes logical flag 100
# regardless of the response value, preserving the completed state.
COMPLETED_TUTORIAL_FLAG = 100
COMPLETED_TUTORIAL_LOCAL_STEP = 1000

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

# Runtime-proven final-client owned-card source for WorkCardData.AddCardData.
STARTER_WORK_CARD_SECTION = "user_card_list"
STARTER_CENERE_SECTION = "cs_gacha_data_cenere"
STARTER_CARD_REQUIRED_FIELDS = (
    "serial_id",
    "card_id",
    "exp",
    "step",
    "love",
    "skill_level",
    "protect",
)

FINAL_UNIT_SLOT_COUNT = 5
# The primary final unit pass hard-reads unit_slot (1-based) and name. A later
# independent pass hard-reads unit_id and name. The formatted serial_id_0..4
# slots are presence/default safe, but the synthetic starter keeps all five
# explicit for deterministic local state.
STARTER_UNIT_REQUIRED_FIELDS = (
    "unit_slot",
    "unit_id",
    "name",
    *(f"serial_id_{index}" for index in range(FINAL_UNIT_SLOT_COUNT)),
)

# Card identity is independently verified against final 10133800 master.
# Ownership serial, user unit id, slot selection and progress are synthetic local
# state. No historical account payload is copied into the profile.
STARTER_CARD_ID = 100001
STARTER_SERIAL_ID = 1
STARTER_CENERE_ID = 1
STARTER_UNIT_ID = 1
STARTER_UNIT_SLOT = 1
STARTER_CARD_RELEASE_FLAG = 33
STARTER_CARD_RELEASE_KEY = "cenere_update_2023_start_time"
STARTER_CARD_RELEASE_TIME = 1


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
            "tutorial_flag": COMPLETED_TUTORIAL_FLAG,
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
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        data[section] = []
    data["music_list"] = {"normal": []}
    data["loading_tips_info"] = {
        "possession_sticker_data": {},
        "loading_sticker_num": 0,
    }
    return data


def build_starter_visible_load_index_data(
    *,
    viewer_id: int = 1,
    producer_name: str = "Relive Producer",
    now: int | None = None,
) -> dict[str, Any]:
    """Return a tiny synthetic profile with one visible final-master starter card."""
    data = build_home_candidate_load_index_data(
        viewer_id=viewer_id,
        producer_name=producer_name,
        now=now,
    )
    # Final-client runtime evidence proves the cs_gacha_data_cenere card merge
    # is gated by ReleaseFlagDictionary.GetIsReleased(33). The enum-to-key path
    # resolves flag 33 to cenere_update_2023_start_time in common_define; any
    # positive release time <= current server time is released.
    data["common_define"][STARTER_CARD_RELEASE_KEY] = STARTER_CARD_RELEASE_TIME
    data[STARTER_CENERE_SECTION] = {"cenere_id": STARTER_CENERE_ID}
    data[STARTER_WORK_CARD_SECTION] = [
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
            "unit_slot": STARTER_UNIT_SLOT,
            "unit_id": STARTER_UNIT_ID,
            "name": "Relive Unit",
            "serial_id_0": STARTER_SERIAL_ID,
            "serial_id_1": 0,
            "serial_id_2": 0,
            "serial_id_3": 0,
            "serial_id_4": 0,
        }
    ]
    # Keep user_chara_list empty. The final parser proves [] is safe, while Home
    # startup resolves chara id from the WorkCardData card and has no proven
    # WorkCharaData consumer.
    data["user_info"]["leader_serial_id"] = STARTER_SERIAL_ID
    # Runtime LoadTask.Parse evidence (0x485def4..0x485df4c) hard-reads the
    # active 1-based unit slot from user_info before iterating user_unit_list.
    data["user_info"]["unit_slot"] = STARTER_UNIT_SLOT
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
    if isinstance(user, dict) and user.get("tutorial_flag") != COMPLETED_TUTORIAL_FLAG:
        errors.append("user_info.tutorial_flag")
    for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
        if not isinstance(data.get(section), list):
            errors.append(section)
    music = data.get("music_list")
    if not isinstance(music, dict):
        errors.append("music_list")
    elif not isinstance(music.get("normal"), list):
        errors.append("music_list.normal")
    loading_tips = data.get("loading_tips_info")
    if not isinstance(loading_tips, dict):
        errors.append("loading_tips_info")
    else:
        if not isinstance(loading_tips.get("possession_sticker_data"), dict):
            errors.append("loading_tips_info.possession_sticker_data")
        if loading_tips.get("loading_sticker_num") != 0:
            errors.append("loading_tips_info.loading_sticker_num")
    return errors


def _missing_item_fields(item: Any, fields: tuple[str, ...], prefix: str) -> list[str]:
    if not isinstance(item, dict):
        return [prefix]
    return [f"{prefix}.{field}" for field in fields if field not in item]


def validate_starter_visible_profile(data: dict[str, Any]) -> list[str]:
    """Validate the statically-derived one-card starter-visible contract."""
    errors = validate_home_candidate_profile(data)
    common = data.get("common_define")
    if not isinstance(common, dict) or common.get(STARTER_CARD_RELEASE_KEY) != STARTER_CARD_RELEASE_TIME:
        errors.append(f"common_define.{STARTER_CARD_RELEASE_KEY}")

    cenere = data.get(STARTER_CENERE_SECTION)
    if cenere != {"cenere_id": STARTER_CENERE_ID}:
        errors.append(STARTER_CENERE_SECTION)

    cards = data.get(STARTER_WORK_CARD_SECTION)
    card_prefix = f"{STARTER_WORK_CARD_SECTION}[0]"
    if not isinstance(cards, list) or len(cards) != 1:
        errors.append(f"{STARTER_WORK_CARD_SECTION}[1]")
    else:
        card = cards[0]
        errors.extend(_missing_item_fields(card, STARTER_CARD_REQUIRED_FIELDS, card_prefix))
        if isinstance(card, dict):
            if card.get("serial_id") != STARTER_SERIAL_ID:
                errors.append(f"{card_prefix}.serial_id")
            if card.get("card_id") != STARTER_CARD_ID:
                errors.append(f"{card_prefix}.card_id")

    units = data.get("user_unit_list")
    if not isinstance(units, list) or len(units) != 1:
        errors.append("user_unit_list[1]")
    else:
        errors.extend(_missing_item_fields(units[0], STARTER_UNIT_REQUIRED_FIELDS, "user_unit_list[0]"))
        if isinstance(units[0], dict):
            if units[0].get("unit_slot") != STARTER_UNIT_SLOT:
                errors.append("user_unit_list[0].unit_slot")
            if units[0].get("unit_id") != STARTER_UNIT_ID:
                errors.append("user_unit_list[0].unit_id")
            if units[0].get("serial_id_0") != STARTER_SERIAL_ID:
                errors.append("user_unit_list[0].serial_id_0")
            for index in range(1, FINAL_UNIT_SLOT_COUNT):
                if units[0].get(f"serial_id_{index}") != 0:
                    errors.append(f"user_unit_list[0].serial_id_{index}")

    # The exact user_chara_list parser is empty-array safe. Keep it empty until a
    # runtime or bounded Home consumer proves WorkCharaData is required.
    if data.get("user_chara_list") != []:
        errors.append("user_chara_list")

    user = data.get("user_info")
    if isinstance(user, dict):
        if user.get("unit_slot") != STARTER_UNIT_SLOT:
            errors.append("user_info.unit_slot")
        leader = user.get("leader_serial_id")
        if leader is not None and leader != STARTER_SERIAL_ID:
            errors.append("user_info.leader_serial_id")
    return errors
