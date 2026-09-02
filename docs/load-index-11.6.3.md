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
- `Stage.LoadTask.Parse` starts at RVA `0x04850a94`; the analyzed function body
  returns at approximately `0x0486fab0`

The full function references 1,205 managed string-literal usages representing
412 unique strings. That is **not** the number of mandatory response fields:
much of the final game's accumulated schema is behind `ContainsKey` and/or
feature/state branches.

## Required `data.common_define` prefix

The parser directly indexes:

| RVA | field |
| ---: | --- |
| `0x048524d4` | `data` |
| `0x048524ec` | `common_define` |
| `0x04852530` | `expanding_count` |
| `0x04852588` | `expanding_jewel` |
| `0x048525b4` | `expanding_max` |
| `0x048525e4` | `stamina_recovery_jewel` |
| `0x04852614` | `stamina_recovery_time` |
| `0x04852644` | `room_lvup_shortening_time` |
| `0x04852674` | `room_lvup_jewel` |

These seven members are read without preceding key-presence checks on the
observed branch. Immediately afterwards the function switches to the repeated
presence-guard pattern for many later additions.

## `user_info` bootstrap and player reads

A tutorial-state branch reads `data.user_info.tutorial_flag` around
`0x048584c0`. The final setup path maps server value `100` to the local completed
tutorial step `1000`, so the synthetic preservation profiles use `100`.

The observed direct `user_info` reads across the bootstrap/player construction
branches are:

- `viewer_id`
- `name`
- `comment`
- `max_card_num`
- `max_room_storage_num`
- `friend_pt`
- `jewel`
- `free_jewel`
- `gold`
- `stamina`
- `level`
- `exp`
- `fan`
- `producer_rank`
- `birth`
- `sum_of_money`
- `last_payment_date`
- `stamina_heal_time`
- plus `tutorial_flag` for bootstrap

`leader_serial_id` is **not** globally mandatory. The later player-info branch
checks its presence before reading it, as it does for the support serial IDs and
emblem fields. The starter-visible profile supplies `leader_serial_id=1` as a
functional Home choice, not as a schema requirement.

## `user_card_list`: final item contract

The top-level `data.user_card_list` section is `ContainsKey`-guarded. Once an
item exists, the first final parser loop directly reads:

| RVA | item field |
| ---: | --- |
| `0x04858e88` | `serial_id` |
| `0x04858ea8` | `card_id` |
| `0x04858ef8` | `exp` |
| `0x04858f58` | `step` |
| `0x04858f84` | `love` |
| `0x04858fc8` | `skill_level` |
| `0x04858ff8` | `protect` |

`join_type` is presence-guarded in the same loop. A later Home/state card loop
around `0x0485cbd8` re-reads the same core fields; `is_custom`, `custom_info`, and
`join_type` are optional/state-guarded there as well.

Notably, the historical response field `level` is not part of these direct final
card-item reads. The synthetic starter card therefore does not add it merely to
imitate an old response.

The minimal final-parser card shape is therefore:

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

The ownership `serial_id=1` is synthetic. Card ID `100001` is not guessed: the
independent final-resource CI resolves and verifies resource version `10133800`,
opens the resulting `master.mdb`, and confirms `card_data.id=100001` is
`島村卯月` with `chara_id=101`.

## `user_unit_list`: exactly five final slots

The section itself is presence-guarded, but there is an important side
dependency: **as soon as `user_unit_list` is present, even if it is empty, the
final parser directly reads `data.user_info.unit_slot`** around `0x04859298`.
This is why `unit_slot` belongs to the Home candidate but not the strict profile.

For each non-empty unit item, final 11.6.3 directly reads:

- `name` around `0x04859364`
- the formatted key `serial_id_{0}` around `0x04859310`

The inner loop is statically fixed to five slots. At the tail:

```text
0x04859680  add w20, w20, #1
0x04859684  cmp w20, #5
            ... branch back while lower ...
```

Therefore the final item contract is:

```json
{
  "name": "Relive Unit",
  "serial_id_0": 1,
  "serial_id_1": 0,
  "serial_id_2": 0,
  "serial_id_3": 0,
  "serial_id_4": 0
}
```

A non-zero slot is resolved against the owned-card serial IDs; zero follows the
empty-slot path. Historical `unit_id` and `viewer_id` are not direct-read in this
final loop. Unit numbering is constructed from list position.

## `user_chara_list`

This top-level section is also presence-guarded. When an item exists, final
11.6.3 directly reads:

- `chara_id` around `0x0485d244`
- `fan` around `0x0485d248`

For the verified `100001` starter card the synthetic state therefore includes:

```json
{"chara_id": 101, "fan": 0}
```

## Profile layers implemented

`server/minimal_profile.py` intentionally exposes three different contracts.
They must not be conflated.

### 1. Strict minimal

`build_minimal_load_index_data()` contains only the reduced direct
`common_define` / `user_info` requirements. It omits Home manager sections.

CLI:

```bash
python -m server.http_server \
  --experimental-minimal-load-index \
  --viewer-id 1 \
  --producer-name "Relive Producer"
```

### 2. Empty Home candidate

`build_home_candidate_load_index_data()` adds explicitly empty, section-guarded
Home-facing lists and `music_list={"normal": []}`. Because it supplies an empty
`user_unit_list`, it also supplies the proven `user_info.unit_slot` dependency.

CLI:

```bash
python -m server.http_server --experimental-home-load-index
```

This profile is useful for determining whether Home requires owned content, but
it deliberately has no card/unit.

### 3. Starter-visible candidate

`build_starter_visible_load_index_data()` starts from the Home candidate and adds
only:

- one owned synthetic serial (`1`) for final-master card `100001`;
- one five-slot unit with that serial in slot 0 and zeros elsewhere;
- one `user_chara_list` record for final-master `chara_id=101`;
- optional functional `leader_serial_id=1`.

CLI:

```bash
python -m server.http_server \
  --experimental-starter-load-index \
  --viewer-id 1 \
  --producer-name "Relive Producer"
```

The builder and validator are covered by unit tests, and the entire profile is
covered by a real HTTP -> CGSS response codec -> decode round-trip test. This
proves server serialization/encryption integrity, not yet original-client
acceptance.

## Proven vs pending

Statically proven for this exact 11.6.3 specimen:

- direct `common_define` prefix;
- observed direct `user_info` reads;
- `user_unit_list` presence implies a direct `user_info.unit_slot` read;
- direct core `user_card_list` item fields;
- optional `join_type` / custom-card fields;
- exactly five unit serial slots (`serial_id_0..4`);
- direct `user_chara_list` item fields;
- many other schema additions are presence/state guarded;
- `/load/index` uses the reconstructed common CGSS response envelope.

Independently proven from final resource version `10133800`:

- `master.mdb` integrity and hash chain;
- `card_data` exists and contains 4,314 records;
- `100001` / 島村卯月 / `chara_id=101` exists in that final master.

Still pending runtime proof:

- original 11.6.3 acceptance of each synthetic profile layer;
- the exact first endpoint requested after `/load/index` succeeds;
- whether a Home scene demands additional non-network local state or content;
- which subsequent API route becomes the next compatibility-server blocker.

The next device run should therefore start with the starter-visible profile and a
sanitized event log, then fall back to empty-Home or strict-minimal only as a
controlled differential test.
