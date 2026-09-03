# CGSS Android 11.6.3 `/load/index` parser reduction

This note records the current clean-room reduction of final Android 11.6.3
`Stage.LoadTask.Parse` and the synthetic profiles implemented by the server.
Static evidence from the final IL2CPP specimen supersedes earlier historical
response-shape assumptions.

## Final parser target

- `Stage.LoadTask.Parse`: RVA `0x04850a94`
- parser body begins near `0x04852398`
- the earlier `0x04850a94..0x04852397` region is largely static key setup rather
  than ordinary response reads
- missing hard children commonly branch to the shared early exit near
  `0x0486fa88`

A critical semantic detail is that an early hard-key miss can stop the remainder
of this parser while the framework still sees the common/base success result.
Therefore “server returned result_code=1” is not evidence that the entire
`/load/index` state was populated.

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

For the established-account/non-newbie path used by preservation tests, the
server should provide:

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

The earlier repository note that an empty `user_unit_list` required
`user_info.unit_slot` was incorrect. Final static evidence shows the top-level
unit list is guarded and an empty list is safe. `unit_slot` belongs to each
**non-empty unit element**, not `user_info`.

## `user_unit_list`: corrected final contract

Top-level `user_unit_list` is presence-guarded and may be omitted or empty.

For a non-empty unit element, the first confirmed pass directly reads:

```text
unit_slot   # 1-based; client stores value-1
name
```

It then checks formatted keys `serial_id_0` through `serial_id_4` in a loop whose
upper bound is statically fixed by `cmp w20,#5`. Missing/zero serial keys are
safe in this pass.

A later independent unit-processing entry also directly reads `unit_id` and
`name`. To satisfy both known passes, the starter-visible profile deliberately
uses the conservative shape:

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

This is synthetic preservation state. `unit_slot=1` and `unit_id=1` are not
copied from an account capture.

The exact second-pass requirements for optional pose/costume/dress-customize
substructures remain below the threshold for claiming them mandatory; the
server does not invent them without runtime/static evidence.

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

The server also sets guarded `leader_serial_id=1` as a functional Home choice.

## Other sections

Most observed feature/data sections are top-level guarded and may be omitted.
Examples include item, room, live, event, story, login-bonus, popup, panel mission
and many campaign sections.

The safe rule is:

> if a whole guarded feature is not needed, omit the key instead of sending a
> partially populated object.

Some guarded keys have hard children once present. For example `music_list`, if
provided, must contain `normal` (which may itself be an empty array).

## Implemented profile layers

`server/minimal_profile.py` keeps three distinct profiles so runtime differentials
remain interpretable.

### 1. Strict minimal

`build_minimal_load_index_data()` provides the common/user bootstrap scalars only.

```powershell
python -m server.http_server --experimental-minimal-load-index
```

### 2. Empty Home candidate

`build_home_candidate_load_index_data()` adds selected explicit empty manager
containers plus `music_list={"normal": []}`. It no longer adds a synthetic
`user_info.unit_slot`.

```powershell
python -m server.http_server --experimental-home-load-index
```

### 3. Starter-visible candidate — first runtime choice

`build_starter_visible_load_index_data()` adds:

- one synthetic owned serial `1` for final-master card `100001`;
- one corrected unit carrying `unit_slot=1`, `unit_id=1`, name and five serial
  slots;
- one `user_chara_list` row for `chara_id=101`;
- guarded `leader_serial_id=1`.

```powershell
python -m server.http_server `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer"
```

The starter-visible profile should be the first real-device test. Empty/strict
profiles are differential fallbacks only.

## `/load/index` success -> Home control flow

The final static call graph closes the success side as:

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
  -> Stage.SceneManager.ChangeView(next = loginBonus ? 7 : 6)
  -> Home semantics
```

There is no statically proven mandatory network request immediately after
successful `/load/index`. `/load/update_agreement_status` is driven by a Home UI
interaction; `/load/title` is a Title-screen user-driven task rather than a hard
Home prerequisite.

The exact enum names behind view IDs `6` and `7` remain unclosed statically, so a
real-device transition is still required before labeling that mapping as fully
confirmed.

## Proven vs runtime-pending

Statically proven or strongly closed for final 11.6.3:

- hard `data/common_define` prefix and seven direct integers;
- established-account `user_info` scalar set;
- optional/guard-heavy nature of the accumulated schema;
- non-empty unit `unit_slot + name` first pass;
- fixed five serial slots;
- later unit pass requiring `unit_id + name`;
- `/load/index` success callback chain toward Home;
- `/load/title` is not a mandatory link in that chain.

Still runtime-pending:

- original-client acceptance of the synthetic starter profile;
- visible identity of ChangeView IDs 6/7;
- whether a local resource prerequisite blocks BootMain before `/load/index`;
- first unsupported/local-state blocker after Home transition.
