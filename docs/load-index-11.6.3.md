# CGSS Android 11.6.3 `/load/index` parser reduction

This note records the clean-room reduction of final Android 11.6.3
`Stage.LoadTask.Parse` and the synthetic profiles implemented by the server.
Static evidence from the exact final IL2CPP specimen supersedes historical
response-shape assumptions.

## Final parser target

- `Stage.LoadTask.Parse`: RVA `0x04850a94`
- ordinary response reads begin near `0x04852398`
- the preceding region is largely static key registration/setup
- missing hard children commonly branch to the shared early exit near
  `0x0486fa88`

A hard-key miss can therefore stop later state initialization while the common
framework still observes success. Server-side `result_code=1` is not sufficient
proof that Home state was populated.

## Parser primitives

The final parser repeatedly uses three patterns:

1. **hard read** — direct `JsonData.get_Item(key)` followed by null check; missing
   value can jump to shared early exit;
2. **guard read** — key-enumeration/ContainsKey-style test; missing key skips the
   whole feature block safely;
3. **array guard** — count `< 1` skips the element loop, so an explicitly empty
   array is safe for that particular block.

The hundreds of referenced strings are not hundreds of mandatory response keys.

## Required `common_define`

For the established-account path:

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

The tutorial gate hard-reads `tutorial_flag`. Once the normal `user_info` scalar
passes are entered, the synthetic profile supplies:

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

The actual date key is `birth`; `birthday` and `last_login` are not keys in the
analyzed final parser. `leader_serial_id`, emblem/support serial fields and
similar tail state are guarded.

`BaseTask.setupTutorial` at RVA `0x0476e1e4` receives the decoded
`tutorial_flag`. The exact completed/non-newbie value is being independently
closed by the bounded `scripts/analyze-tutorial-flag.py` pass; until that report
is applied, the current numeric starter value must not be treated as proven merely
because parsing reaches this call.

## Correct card-state split

This is important for Home entry and supersedes the older starter implementation.

Final `LoadTask.Parse` contains two different card-looking blocks:

### `user_card_list` at approximately `0x48589cc`

This top-level key is guarded and empty-safe. Its observed element handling is a
Cenere/merge-style path with individually guarded fields. Static evidence does
**not** show this block invoking `WorkCardData.AddCardData`.

For the synthetic starter it is intentionally kept:

```json
"user_card_list": []
```

### `cs_gacha_data_cenere` at approximately `0x4858d70`

The exact guarded literal is:

```text
cs_gacha_data_cenere
```

When this array is present and non-empty, each element first invokes:

```text
WorkCardData.AddCardData
```

and then hard-reads seven fields:

```text
serial_id
card_id
exp
step
love
skill_level
protect
```

`join_type` is guarded/optional.

This is therefore the statically proven container that creates the WorkCardData
object later consumed by Home.

The synthetic card is now emitted as:

```json
"cs_gacha_data_cenere": [
  {
    "serial_id": 1,
    "card_id": 100001,
    "exp": 0,
    "step": 0,
    "love": 0,
    "skill_level": 1,
    "protect": 0
  }
]
```

The final `10133800` master independently proves:

```text
card_id 100001 = 島村卯月
chara_id 101
```

The ownership serial `1` remains purely synthetic preservation state.

## Why the WorkCardData container matters to Home

Bounded exact-specimen Home analysis closes the immediate consumer:

```text
Stage.Home.Start
 -> Stage.Home.PreDownloadList
 -> Stage.Home.CardDownloadList(... serialId ...)
```

The actual startup worker is pinned at:

```text
Stage.Home.CardDownloadList @ 0x03ec0d70
```

It calls:

```text
Stage.WorkCardData.GetCardDataWithSerial(serialId)
```

and subsequently uses the returned `CardData` for image/chara/rarity/resource
preparation. Therefore a unit slot that references serial `1` must have caused a
real WorkCardData object for serial `1` to be created during `/load/index`.

Putting the synthetic card only in `user_card_list` did not statically guarantee
that invariant. `server/minimal_profile.py` now keeps `user_card_list=[]` and
puts the one starter card only in `cs_gacha_data_cenere`; the validator rejects a
second copy in `user_card_list`.

## `user_unit_list`: conservative final contract

Top-level `user_unit_list` is guarded and may be omitted or empty.

For a non-empty unit element, the first confirmed pass directly reads:

```text
unit_slot   # 1-based; client stores value-1
name
```

It then scans exactly five formatted keys:

```text
serial_id_0
serial_id_1
serial_id_2
serial_id_3
serial_id_4
```

Missing/zero serial values are safe in this pass.

A later independent pass directly reads:

```text
unit_id
name
```

The starter-visible unit therefore conservatively supplies both IDs and all five
serial keys:

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

The serial `1` reference is now backed by the WorkCardData record described
above.

## Character and leader state

The synthetic character row remains:

```json
{"chara_id": 101, "fan": 0}
```

and guarded `user_info.leader_serial_id=1` is supplied for the initial leader.
These are synthetic local state; no captured account payload is copied.

## Optional feature sections and Home banner data

Most feature/data sections are top-level guarded and may be omitted. Examples
include item, room, live, event, story, login bonus, popup, panel mission,
campaign, lottery, questionnaire and MV-related sections.

Safe rule:

> If a whole guarded feature is not needed, omit the key rather than sending a
> partially populated object.

This remains true even though Home startup touches many WorkData managers.
Targeted `Stage.HomeCustomUtil.SetBannerAssetList` analysis shows that absent
business data for several optional systems follows ordinary skip/continue paths,
including entry-SP-campaign, lottery, cookie-swap, questionnaire and MV
connection cases. Some singleton/type-pointer null checks do flow to a shared
exception helper, but those are runtime-instance invariants and are not evidence
that the corresponding `/load/index` JSON key must be fabricated.

`sp_campaign` is explicitly C-class/guarded in the final key registry. Do not add
it merely because Home queries campaign WorkData.

`music_list` is a representative guarded-parent caveat: if the key is sent, it
must contain `normal`, though `normal` may be an empty array.

## Implemented profile layers

`server/minimal_profile.py` keeps three differential profiles.

### 1. Strict minimal

`build_minimal_load_index_data()` emits the hard common/user scalar core only.

```powershell
python -m server.http_server --experimental-minimal-load-index
```

### 2. Empty Home candidate

`build_home_candidate_load_index_data()` adds selected explicit empty manager
lists and `music_list={"normal": []}`.

```powershell
python -m server.http_server --experimental-home-load-index
```

### 3. Starter-visible candidate — first runtime choice

`build_starter_visible_load_index_data()` adds:

- `cs_gacha_data_cenere[0]` with serial `1`, final-master card `100001`, and all
  seven hard WorkCardData fields;
- keeps `user_card_list=[]`;
- one unit with `unit_slot=1`, `unit_id=1`, name and five serial slots, with
  `serial_id_0=1`;
- one `user_chara_list` row for `chara_id=101`;
- guarded `leader_serial_id=1`.

```powershell
python -m server.http_server `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer"
```

Starter-visible remains the first real-device profile. Empty/strict are fallback
differentials only.

## `/load/index` success -> Home

The final call graph is statically closed:

```text
BootMain.StartConnect
 -> Stage.LoadTask (/load/index)
 -> NetworkManager.Connect
 -> response/decrypt/JsonData
 -> NetworkTask.CheckResult
 -> Stage.LoadTask.Parse
 -> Parse == 1
 -> BootMain.CallbackOnSuccessLoad
 -> BootMain.LastInitialized
 -> BootMain.ChangeView
 -> Stage.SceneManager.ChangeView
```

Final `StageSceneDefine.eViewId` values:

```text
BootMain       = 5
Home           = 6
Login_Bonus    = 7
Asset_Download = 8
```

`BootMain.ChangeView` calls `LoginBonusData.IsExistLoginBonus` and selects Home 6
when no login bonus exists, otherwise Login_Bonus 7.

There is no statically proven mandatory network request immediately after
successful `/load/index`. Home startup first performs local/resource-facing
prechecks and predownload-list construction. Therefore post-Home API endpoints
should be restored only when runtime evidence proves they are requested.

## Pre-`/load/index` resource stage

The parent bootstrap chain is also statically closed:

```text
/load/check 214
 -> persist RES_VER=10133800
 -> SetupNetwork becomes ready
 -> ResourcesManager.GameInitialize resumes
 -> AssetManager.InitializeManifest
 -> DownloadOrLoadForInitialize
 -> resource requests
 -> GameInitialize completes
 -> BootMain.StartConnect
 -> /load/index
```

A second `/load/check` is not a required link. Sanitized `@resource/*` events
after 214 are the expected runtime evidence that this stage advanced.

## Proven vs runtime-pending

Statically proven/strongly closed for final 11.6.3:

- hard `data/common_define` prefix and seven direct integers;
- established-account `user_info` scalar set once that path is entered;
- card WorkData creation belongs to `cs_gacha_data_cenere`, not the ambiguous
  `user_card_list` merge block;
- Home's card predownload path immediately resolves unit serial through
  `WorkCardData.GetCardDataWithSerial`;
- non-empty unit `unit_slot + name`, fixed five serial slots, and later
  `unit_id + name` pass;
- guard-heavy optional feature sections;
- `/load/index` success callback chain;
- `Home=6`, `Login_Bonus=7`, `Asset_Download=8`;
- 214 continues into resource initialization before `/load/index`;
- `/load/title` is not a hard Home prerequisite.

Still pending or being closed:

- exact `tutorial_flag` value/condition for the established-account path;
- original-client acceptance of the corrected synthetic starter profile;
- visible Home rendering with the local TLS/resource stack;
- first unsupported endpoint/local-state blocker after Home.
