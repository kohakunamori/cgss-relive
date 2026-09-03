# CGSS Android 11.6.3 `/load/index` parser reduction

This note records the clean-room reduction of final Android 11.6.3
`Stage.LoadTask.Parse` and the synthetic profiles implemented by the server.
Static evidence from the exact final IL2CPP specimen supersedes historical
response-shape assumptions.

## Final parser target

- `Stage.LoadTask.Parse`: RVA `0x04850a94`
- parser body begins near `0x04852398`
- the earlier `0x04850a94..0x04852397` region is largely static key setup rather
  than ordinary response reads
- missing hard children commonly branch to the shared early exit near
  `0x0486fa88`

A hard-key miss can stop the remainder of the parser while the framework still
sees the common/base success result. Therefore server `result_code=1` is not by
itself proof that all `/load/index` state was populated.

## Parser primitives

The final parser repeatedly uses three patterns:

1. **hard read** — direct `JsonData.get_Item(key)` followed by a null check;
   missing value can jump to the shared early exit;
2. **guard read** — key enumeration/ContainsKey-style check; missing key skips
   that feature block safely;
3. **array guard** — count `< 1` skips the element loop, so an explicitly empty
   array is safe for that block.

The function references hundreds of strings. That is not the number of mandatory
response fields.

## Required envelope and `common_define`

For the established-account/non-newbie preservation path:

```text
data
└─ common_define
```

with these seven direct integer children:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

`producer_capability_reset_item_jewel` is guarded and may be omitted.

## `user_info`

The normal path hard-reads `tutorial_flag`, and when `user_info` is present the
observed scalar passes require the full synthetic set currently emitted by
`build_minimal_load_index_data()`:

```text
tutorial_flag
viewer_id
name
comment
max_card_num
max_room_storage_num
friend_pt
jewel
free_jewel
gold
stamina
level
exp
fan
producer_rank
birth
sum_of_money
last_payment_date
stamina_heal_time
```

The actual date key is `birth`; `birthday` and `last_login` are not parser keys in
the analyzed function. `leader_serial_id`, emblem/support serial additions and
similar trailing fields are guarded.

## `user_unit_list`: final conservative contract

Top-level `user_unit_list` is presence-guarded and may be omitted or empty.

For a non-empty unit element, the first confirmed pass directly reads:

```text
unit_slot   # 1-based; client stores value-1
name
```

It then checks formatted keys `serial_id_0` through `serial_id_4` in a loop whose
upper bound is statically fixed by `cmp w20,#5`. Missing/zero serial keys are safe
in this pass.

A later independent unit-processing pass directly reads:

```text
unit_id
name
```

To satisfy both known passes, the starter-visible profile uses:

```json
{
  "unit_slot": 1,
  "unit_id": 1,
  "name": "Relive Unit",
  "serial_id_0": 1,
  "serial_id_1": 0,
  "serial_id_2": 0,
  "serial_id_3": 0,
  "serial_id_4": 0
}
```

This is synthetic preservation state, not copied account state.

## Card/chara starter state

The frozen `10133800` master independently proves:

```text
card_id 100001 = 島村卯月
chara_id 101
```

The synthetic ownership serial is `1`.

Current starter card core:

```json
{
  "serial_id": 1,
  "card_id": 100001,
  "exp": 0,
  "step": 0,
  "love": 0,
  "skill_level": 1,
  "protect": 0
}
```

Current synthetic character row:

```json
{"chara_id": 101, "fan": 0}
```

The server also sets guarded `leader_serial_id=1` as the initial Home leader.

## Other sections

Most observed feature/data sections are top-level guarded and may be omitted.
Examples include item, room, live, event, story, login-bonus, popup, panel mission
and campaign sections.

Safe rule:

> If a whole guarded feature is not needed, omit the key rather than sending a
> partially populated object.

Some guarded parents have hard children once present. Example: `music_list`, if
provided, must contain `normal`, which may itself be an empty array.

## Implemented profile layers

`server/minimal_profile.py` keeps three distinct profiles so runtime differentials
remain interpretable.

### 1. Strict minimal

`build_minimal_load_index_data()` provides common/user bootstrap scalars only.

```powershell
python -m server.http_server --experimental-minimal-load-index
```

### 2. Empty Home candidate

`build_home_candidate_load_index_data()` adds selected explicit empty manager
containers plus `music_list={"normal": []}`.

```powershell
python -m server.http_server --experimental-home-load-index
```

### 3. Starter-visible candidate — first runtime choice

`build_starter_visible_load_index_data()` adds:

- one synthetic owned serial `1` for final-master card `100001`;
- one unit carrying `unit_slot=1`, `unit_id=1`, name and five serial slots;
- one `user_chara_list` row for `chara_id=101`;
- guarded `leader_serial_id=1`.

```powershell
python -m server.http_server `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer"
```

Use this profile for the first real-device run. Empty/strict profiles are
fallback differentials only.

## `/load/index` success -> Home is now statically closed

The final call graph is:

```text
BootMain.StartConnect
  -> new Stage.LoadTask (type 11 = /load/index)
  -> NetworkManager.Connect
  -> UnityWebRequest response/decrypt/JsonData
  -> NetworkTask.CheckResult
  -> virtual Stage.LoadTask.Parse (0x04850a94)
  -> Parse == 1
  -> BootMain.CallbackOnSuccessLoad
  -> BootMain.LastInitialized
  -> BootMain.ChangeView
  -> Stage.SceneManager.ChangeView
```

The final `StageSceneDefine.eViewId` enum directly maps:

```text
BootMain       = 5
Home           = 6
Login_Bonus    = 7
Asset_Download = 8
```

`BootMain.ChangeView` has the exact bounded branch:

```text
call LoginBonusData.IsExistLoginBonus
...
mov  w8, #6
cinc w1, w8, ne
branch Stage.SceneManager.ChangeView
```

Thus:

```text
no login bonus -> Home (6)
login bonus    -> Login_Bonus (7)
```

Independent call-site corroboration includes:

```text
Stage.Footer.OnClickHomeButton -> ChangeView(6)
Stage.MenuTop.OnPushOsBackKey  -> ChangeView(6)
```

The old statement that IDs 6/7 were statically unclosed is obsolete.

There is no statically proven mandatory network request immediately after a
successful `/load/index`. `/load/update_agreement_status` is driven by Home UI
interaction; `/load/title` is a Title-screen/user-driven task rather than a hard
Home prerequisite.

## Pre-`/load/index` resource stage

The parent bootstrap chain is also now statically closed:

```text
/load/check 214
-> persist RES_VER=10133800
-> ResourcesManager.GameInitialize resumes
-> AssetManager.InitializeManifest
-> DownloadOrLoadForInitialize resource work
-> GameInitialize completes
-> BootMain.Initialize resumes
-> BootMain.StartConnect
-> /load/index
```

A second `/load/check` is not a required link. In runtime logs, resource-plane
requests after the 214 are the expected evidence that this stage advanced.

## Proven vs runtime-pending

Statically proven or strongly closed for final 11.6.3:

- hard `data/common_define` prefix and seven direct integers;
- established-account `user_info` scalar set;
- guard-heavy nature of the accumulated schema;
- non-empty unit `unit_slot + name` first pass;
- fixed five serial slots;
- later unit pass requiring `unit_id + name`;
- `/load/index` success callback chain;
- `Home=6`, `Login_Bonus=7`, `Asset_Download=8`;
- `/load/title` is not a mandatory link in the Home chain;
- 214 continues into resource initialization before `/load/index`.

Still runtime-pending:

- original-client acceptance of the synthetic starter profile;
- actual visible rendering of Home with the local compatibility stack;
- first unsupported endpoint/local-state blocker after Home entry.
