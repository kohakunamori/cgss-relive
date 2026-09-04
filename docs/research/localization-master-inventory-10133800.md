# Final master localization inventory — resource 10133800

Date: 2026-09-04

Branch: `localization/zh-cn-complete`

Inventory implementation: `localization/tools/inventory_master_text.py` schema v2.

Validated against the frozen final `10133800` resource bootstrap in GitHub Actions run `33858725822` at commit `0d2998e00ba86691d0c1a05115277d6a6c2c2bf4`.

## Safety model

The CI job downloads and validates the final manifest/master only into ephemeral `work/` storage, runs the inventory, deletes `master.mdb`, the manifest, compressed bootstrap material and bootstrap metadata, then uploads only the sanitized inventory report.

The inventory contains table/column names and aggregate statistics only. It does not contain source string values, samples, APK data, AssetBundles or database bodies.

## Final-master surface

Sanitized schema-v2 result:

```text
non-SQLite-internal tables         908
tables with TEXT-affinity columns  335
TEXT-affinity columns               839

user-visible candidates             330
internal/structural candidates      299
manual-review fields                167
empty text fields                    43
```

The earlier project-wide aggregate of 909 master tables is not directly comparable: this inventory intentionally excludes `sqlite_%` internal tables.

Of the 330 current user-visible candidates:

```text
candidate columns containing CJK/Japanese values   305
candidate columns without CJK/Japanese values       25
candidate fields on tables lacking a declared PK    11
candidate non-empty cells                        710138
candidate cells containing CJK/Japanese          703206
```

The cell totals are **not translation-unit counts**: many rows repeat identical strings. A hash-only unique-value counter is the next workload-estimation improvement.

294 candidate columns both contain CJK/Japanese data and live on tables with a declared primary key. Those columns account for 704505 non-empty cells / 700826 CJK-containing cells and are the strongest initial source-catalog surface.

## High-signal candidate groups

These are discovery candidates, not yet an approved translation field map.

```text
story_detail          7124 rows   title, sub_title
limited_mission       8546 rows   discription, discription_detail
gacha_data            4787 rows   name, dicription
emblem                 4137 rows   name, discription
normal_mission         3081 rows   discription, discription_detail
skill_data             2133 rows   skill_name, explain
item_data              1633 rows   name, comment, comment2, name_kana
meetup_memory_data     1170 rows   title, sub_title, description, talk_chara_name
tips                    993 rows   title, comment
push_chara_message      760 rows   title, description
stamp_list              838 rows   name, description
music_data              532 rows   name, composer, lyricist, name_kana
chara_data              259 rows   name, name_kana, favorite, voice
sticker_data            308 rows   title/name-description related fields
```

`name_kana` and similar fields are intentionally still candidates: they may be display/search/sort metadata rather than fields that should receive a Chinese rendering. Final inclusion requires consumer/runtime evidence or UI verification.

## Known heuristic false positives / review traps

The v2 classifier removes all-text numeric/date columns and gives obvious resource/layout hints priority, which reduced the first-pass `review` set from 415 to 167 and increased internal/structural classification from 22 to 299.

Some weak-name-hint cases still require review. Examples include layout/configuration fields such as `live_ver_button_design.button_text_pos_x` and ASCII-only `reward_text_*` fields. No bulk source catalog should be generated directly from the heuristic candidate set.

## Tables without declared primary keys

Current candidate fields on no-declared-PK tables include surfaces such as carnival/tutorial/room-item data. These need one of:

1. a proven unique column/composite key;
2. a deterministic row identity derived from stable columns;
3. resource-level identity outside the master table;
4. runtime context identity.

Do not use physical SQLite row order as a long-term translation key unless no stable semantic identity exists and the frozen database hash is part of the contract.

## Next execution steps

1. Add hash-only unique-value counts to the sanitized inventory to estimate actual translation workload without exposing source strings.
2. Generate a **suggested** master field map from high-confidence candidates, then review it before source extraction.
3. Build the local proprietary source catalog only from the reviewed field map using `build_master_source_catalog.py`.
4. Add placeholder/format-token extraction before any machine translation is accepted.
5. In parallel, continue 11.6.3 client analysis for the concrete `UnityEngine.UI.Text` / TMP setter paths and font assets required by M1 (`Hello Chinese`).

This closes the first real-data M0 checkpoint: the final master text surface is now reproducibly measurable rather than estimated from table names or historical tooling.
