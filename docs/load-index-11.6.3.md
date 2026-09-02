# CGSS Android 11.6.3 `/load/index` parser reduction

This note records static schema work against the supplied final Android 11.6.3
XAPK. It deliberately separates direct final-client reads from optional fields,
historical response examples, and synthetic compatibility choices.

## Specimen

- runtime: Unity IL2CPP, metadata v31
- arm64 `libil2cpp.so` SHA-256:
  `2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5`
- `global-metadata.dat` SHA-256:
  `2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586`
- `Stage.LoadTask.Parse` starts at RVA `0x04850a94`; analyzed return is near
  `0x0486fab0`

The function references more than 400 unique managed strings. That is **not** the
number of mandatory response fields: much of the final accumulated schema is
behind `ContainsKey` and feature/state branches.

## Required `data.common_define` prefix

The observed branch directly indexes these seven members before switching to
presence-guarded additions:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

## `user_info` bootstrap and player reads

The completed-tutorial bootstrap uses server-side `tutorial_flag=100`, which the
final client normalizes to local completed tutorial step `1000`.

Observed direct `user_info` reads on the reduced bootstrap/player path are:

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

`leader_serial_id` is presence-guarded and therefore not globally mandatory. The
starter-visible profile supplies it as a functional Home choice.

There is one important conditional dependency: if `user_unit_list` is present,
even as an empty list, the final parser reads `user_info.unit_slot` before
iterating units. Therefore `unit_slot` belongs to the Home candidate layer, not
the strict-minimal layer.

## `user_card_list`: final item contract

`data.user_card_list` is top-level presence-guarded. Once an item exists, final
11.6.3 directly reads the following core fields:

```text
serial_id
card_id
exp
step
love
skill_level
protect
```

`join_type`, custom-card state and related additions are separately guarded.
Historical item field `level` is not part of the direct core reads observed in
the final loops, so it is not copied merely to imitate old responses.

Minimal synthetic card shape:

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

The ownership serial is synthetic. `card_id=100001` is independently proven to
exist in the frozen final `10133800` master database and maps to 島村卯月,
`chara_id=101`.

## `user_unit_list`: final contract and correction

The final client contains more than one unit-processing pass. The first observed
pass reads `name` and traverses the formatted key `serial_id_{0}` in a loop whose
tail is statically bounded by `cmp w20,#5`. Therefore the unit has exactly five
serial slots:

```text
serial_id_0
serial_id_1
serial_id_2
serial_id_3
serial_id_4
```

A later independent final-client pass also directly reads `unit_id` and `name`
before traversing the same five serial slots. Consequently **`unit_id` is
mandatory for a non-empty `user_unit_list`**. This supersedes the earlier note
that inferred unit numbering solely from list position.

Current minimum non-empty unit shape:

```json
{
  "unit_id": 1,
  "name": "Relive Unit",
  "serial_id_0": 1,
  "serial_id_1": 0,
  "serial_id_2": 0,
  "serial_id_3": 0,
  "serial_id_4": 0
}
```

`unit_id=1`, ownership serial `1`, selected `unit_slot=1`, and progress values are
synthetic preservation state. No historical account payload is copied into the
profile.

## `user_chara_list`

This section is top-level presence-guarded. When an item exists, final 11.6.3
directly reads:

```text
chara_id
fan
```

For the verified starter card the synthetic state therefore uses:

```json
{"chara_id": 101, "fan": 0}
```

## Profile layers implemented

`server/minimal_profile.py` exposes three intentionally separate contracts.

### 1. Strict minimal

`build_minimal_load_index_data()` supplies only the reduced direct
`common_define` / `user_info` requirements.

```bash
python -m server.http_server \
  --experimental-minimal-load-index \
  --viewer-id 1 \
  --producer-name "Relive Producer"
```

### 2. Empty Home candidate

`build_home_candidate_load_index_data()` adds parser-safe empty Home-facing
containers, `music_list={"normal": []}`, and the required `user_info.unit_slot`
dependency introduced by the presence of `user_unit_list`.

```bash
python -m server.http_server --experimental-home-load-index
```

### 3. Starter-visible candidate

`build_starter_visible_load_index_data()` adds only:

- one synthetic owned serial `1` for final-master card `100001`;
- one unit with `unit_id=1`, the owned serial in slot 0, and slots 1..4 empty;
- one `user_chara_list` row for final-master `chara_id=101`;
- functional `leader_serial_id=1`.

```bash
python -m server.http_server \
  --experimental-starter-load-index \
  --viewer-id 1 \
  --producer-name "Relive Producer"
```

Builders and validators are unit-tested. The starter-visible response also has a
real TCP/HTTP -> CGSS encrypted response -> decode round-trip test. That proves
server-side transport integrity, **not yet original-client acceptance**.

## Proven vs pending

Statically proven for this exact final 11.6.3 specimen:

- reduced direct `common_define` prefix;
- observed direct `user_info` reads;
- `user_unit_list` presence implies direct `user_info.unit_slot` access;
- core non-empty `user_card_list` item reads;
- exactly five unit serial slots;
- a later final unit pass makes `unit_id` mandatory for non-empty units;
- direct `user_chara_list` item fields;
- many other accumulated fields are presence/state guarded;
- `/load/index` uses the reconstructed common CGSS response envelope.

Independently proven from frozen final resource version `10133800`:

- manifest/master hash chain and SQLite integrity;
- 220,837 manifest rows / 220,803 unique resource hashes;
- 4,314 `card_data` rows;
- `100001` / 島村卯月 / `chara_id=101` exists in the final master.

Still pending runtime proof:

- original 11.6.3 acceptance of the synthetic profile layers;
- successful transition from `/load/index` into the Home scene;
- exact first endpoint requested after successful `/load/index`;
- any additional non-network local-state/content requirement discovered at Home;
- the next compatibility-server blocker after Home entry.

The next device run should start with the starter-visible profile plus sanitized
server event logging and ADB logcat. Fall back to empty-Home or strict-minimal only
as controlled differential tests.
