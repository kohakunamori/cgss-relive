# CGSS Android 11.6.3 `/load/index` parser reduction

This note records static schema work against the supplied final Android 11.6.3
XAPK.  It deliberately distinguishes fields that are directly required by the
current parser from fields that are only referenced behind optional/stateful
branches.

## Specimen

- runtime: Unity IL2CPP, metadata v31
- arm64 `libil2cpp.so` SHA-256:
  `2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5`
- `global-metadata.dat` SHA-256:
  `2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586`
- `Stage.LoadTask.Parse` RVA starts at `0x04850a94`; the analyzed function body
  returns at approximately `0x0486fab0`.

The full function references 1,205 managed string-literal usages representing
412 unique strings.  That number is **not** the number of required response
fields: much of the final game's accumulated schema is guarded by `ContainsKey`
or by feature/state branches.

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

These seven `common_define` members are read without a preceding key-presence
check in the current branch.

Immediately afterwards the parser switches to the dictionary/`ContainsKey`
pattern.  For example `producer_capability_reset_item_jewel` is tested through a
virtual dictionary call and skipped on false (`tbz` at `0x04852740`) before the
actual value read.  The same pattern repeats for many later additions such as
potential limits, over-limit settings, room expansion extras, campaign fields,
and other post-launch systems.

Therefore the final schema must not be modelled as "all 400+ referenced strings
are mandatory".

## `user_info` bootstrap and main-data reads

A tutorial-state branch reads:

- `data.user_info.tutorial_flag` at `0x048584c0` when the local tutorial state is
  not already the completed internal step.

The current tutorial setup path maps server `tutorial_flag = 100` to the local
completed tutorial step `1000`, making it a useful preservation bootstrap state.

The parser later checks whether `data.user_info` exists.  Once present, one
player-data branch directly reads:

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
- `stamina_heal_time`

The relevant literal loads span roughly `0x04858688` through `0x0485896c`.

A later state-dependent player-info construction branch re-enters
`data.user_info` around `0x0485ba04` and directly reads the union below:

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

For a first synthetic preservation profile we therefore use the union of the
direct fields from both observed `user_info` paths plus `tutorial_flag`.

## Implemented candidate profile

`server/minimal_profile.py` now provides:

- `build_minimal_load_index_data()`
- `validate_minimal_profile()`
- explicit required-field constants derived from the direct reads above

The builder contains no captured user/account data.  It uses a synthetic viewer,
producer name, zero balances and conservative non-zero capacity/recovery values.

It is exposed by the HTTP server only through the explicitly experimental flag:

```bash
python -m server.http_server \
  --experimental-minimal-load-index \
  --viewer-id 1 \
  --producer-name "Relive Producer"
```

A local JSON profile remains supported with `--load-index-profile` and takes a
separate path.

## What is proven vs pending

Statically proven for this exact 11.6.3 specimen:

- the direct `common_define` prefix above;
- the direct `user_info` field reads above;
- many later schema additions are presence-guarded rather than globally
  mandatory;
- `/load/index` uses the already reconstructed common CGSS response envelope.

Still pending runtime proof:

- whether a completely fresh 11.6.3 install reaches every state-dependent branch
  represented in the current candidate profile;
- which top-level list/map sections can be absent versus must exist empty;
- the first endpoint requested after the synthetic `/load/index` is accepted;
- whether any local tutorial/account state must be initialized before the client
  will advance to Home.

The experimental profile must therefore remain labelled as a candidate until a
real 11.6.3 client accepts it.
