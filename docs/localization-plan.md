# CGSS 11.6.3 Complete Simplified-Chinese Localization Plan

This document is the execution plan for a complete `zh-CN` localization of the frozen final Android CGSS client (`11.6.3`, versionCode `438`) while preserving the existing clean-room relive baseline.

## Mission

Deliver a reproducible localized client/runtime/resource stack in which every player-visible Japanese string reachable in preserved game flows has a reviewed Simplified-Chinese representation, with correct CJK rendering, layout, placeholders, resource integrity, and deterministic build output.

The localization project is **parallel to**, not a replacement for, the preservation baseline:

- **Preservation acceptance target:** untouched official 11.6.3 client + local relive stack.
- **Localization acceptance target:** derived/re-signed 11.6.3 client + localization runtime/overlays + the same relive stack.
- A success observed only in the localized client never counts as evidence that the untouched-client preservation target is solved.

## Non-negotiable boundaries

Do not commit original APK/XAPK files, split APKs, `libil2cpp.so`, `global-metadata.dat`, `master.mdb`, downloaded AssetBundles, scenario bodies, textures, audio, production credentials, or bulk proprietary dumps.

Generated source catalogs containing game text stay local/gitignored. Reproducible extractors, schemas, hashes/IDs, translation tooling, Chinese translations, review metadata, and bounded sanitized reports may be versioned.

## Target architecture

Localization is intentionally hybrid because CGSS text is not stored in one place.

```text
11.6.3 client
  |-- Android resources / bootstrap patch
  |-- localization native runtime
  |     |-- UnityEngine.UI.Text interception
  |     |-- TMP_Text/TextMeshProUGUI interception
  |     |-- context-aware translation lookup
  |     `-- font fallback / layout fixes
  |
  |-- resource localization overlay
  |     |-- master.mdb-derived data
  |     |-- scenario resources
  |     |-- TextAsset / serialized strings
  |     `-- localized Texture/Sprite/AssetBundle objects
  |
  `-- relive server localization
        |-- synthetic/local API strings
        |-- local notices/help
        `-- localized WebView content

                     -> locale pack (zh-CN)
```

Do not binary-patch `libil2cpp.so` unless runtime evidence shows that a stable loader/hook cannot solve the required path. Prefer a small APK bootstrap that loads a separately maintained localization native library and resolves IL2CPP/Unity targets at runtime.

## Definition of "complete"

A release may call itself complete only when the following categories are covered or explicitly allowlisted as intentionally untranslated (for example a trademark/logo):

1. Android wrapper strings and launch-time dialogs.
2. Title/bootstrap/download/update/error UI.
3. Home and every main navigation surface.
4. LIVE selection, unit selection, settings, pause/result UI.
5. Idol/card/unit/skill/ability/filter/sort UI.
6. Room, shop, present box, mission, profile, settings and secondary screens.
7. Master-derived card/character/skill/item/furniture/event/mission/etc. player-visible fields.
8. Story/commu/event/card scenario dialogue, speaker labels, choices and titles.
9. Localized server-generated messages and local WebView/help/notices.
10. Player-visible text embedded in textures/sprites/tutorial art.
11. Simplified-Chinese glyph coverage, typography and layout.
12. Rare/error/legacy flows discovered by runtime coverage logging.

## Translation identity model

Never make raw Japanese text the long-term primary key. Stable IDs must carry context.

Preferred examples:

```text
UI.Home.Footer.Live
UI.Common.Confirm
Master.Card.100001.Name
Master.Skill.1021.Description
Scenario.50123001.Line.41
Scenario.50123001.Choice.3
```

When a stable semantic ID is not yet known, discovery may temporarily derive a key from scene + hierarchy + component + source hash. Temporary keys must be migratable once the true resource/master/scenario identity is known.

A translation record tracks at least:

- stable ID;
- source SHA-256 (source text itself may stay local);
- locale;
- translated text;
- status (`machine`, `translated`, `reviewed`, `approved`);
- optional context and notes;
- placeholder/signature metadata when formatting tokens are present.

## Workstreams

### A. Text discovery

Build static and runtime inventories that answer where a visible string came from:

- Android resources;
- IL2CPP/native string path;
- `UnityEngine.UI.Text`;
- TextMeshPro/TMP;
- `master.mdb`;
- scenario resources;
- serialized `TextAsset` / MonoBehaviour content;
- resource-server/API response;
- texture/sprite.

Discovery output must be machine-readable and should avoid emitting proprietary source strings in shareable reports. Local source catalogs may contain them under ignored working paths.

### B. Runtime localization core

Implement a small localization runtime that can:

- load a locale pack;
- resolve Text/TMP setters and CGSS wrapper methods where appropriate;
- build context-aware translation keys;
- preserve formatting tokens;
- report unknown Japanese strings;
- apply font fallback and bounded per-key layout fixes;
- fail open to original text instead of crashing the game.

### C. Font and typography

Determine the exact 11.6.3 text stack before choosing an injection technique. Prefer the original game font with a CJK fallback rather than globally replacing styling.

Acceptance includes:

- common Simplified-Chinese characters;
- punctuation/full-width forms;
- Japanese/Latin/numerals/symbols still rendering;
- no missing-glyph squares;
- original outline/shadow/material behavior retained where practical.

### D. Master database localization

Inventory all text-bearing columns across the final master database. Classify each field as player-visible, internal, or review-required. Maintain a declarative localization schema instead of manually editing SQLite files.

Pipeline:

```text
original local master.mdb
 -> inventory/extract
 -> stable master keys
 -> zh-CN translation data
 -> localized master build
 -> resource overlay/manifest integration
```

The preserved original object remains immutable.

### E. Scenario localization

Reverse the exact final scenario representation and define a canonical intermediate representation containing stable scenario/line/choice identity, speaker information, control commands and voice references.

Pipeline:

```text
scenario resource -> decoder -> canonical IR -> translation/review
                  -> validator -> encoder -> localized resource
```

Translation quality requires a project glossary plus per-character voice/style guidance. LLM output may be used as a first pass, never as the final quality gate by itself.

### F. Texture/AssetBundle localization

Inventory player-visible Japanese embedded in Texture2D/Sprite/atlases. Prioritize tutorial/instruction/action-critical graphics, then banners/event art and decorative text.

Rebuilds must preserve dimensions, import/texture settings, alpha, sprite rect/pivot/border and atlas relationships as required by the original asset.

### G. Layout and visual QA

Chinese text can change line wrapping and width. Maintain layout overrides by stable localization key rather than one-off manual prefab edits where possible.

Track:

- clipping/ellipsis;
- unexpected line count;
- autosize/font-size changes;
- missing glyphs;
- broken rich-text/format tags;
- screenshot regressions.

### H. Server/WebView localization

Any text synthesized by `cgss-relive` should be localized at the source instead of generating Japanese and relying on a client hook to translate it again. Local WebView/help/notice pages should be locale-aware.

## Coverage and release gates

The project will eventually generate a coverage report similar to:

```text
UI discovered/translated/approved
master fields discovered/translated/approved
scenario lines discovered/translated/approved
choices discovered/translated/approved
texture-text assets discovered/localized/approved
runtime unknown Japanese count
missing glyph count
fatal layout overflow count
```

Final release gates:

- untranslated runtime Japanese: `0` outside explicit allowlist;
- untranslated declared master fields: `0`;
- untranslated scenario/choice entries: `0`;
- known required texture text: `0`;
- missing Chinese glyphs: `0`;
- fatal layout overflows: `0`;
- localization data/schema validation passes;
- localized split install set rebuilds, aligns, signs and installs reproducibly;
- preservation CI for the untouched client remains independent and green.

## Milestones

### M0 - Localization reconnaissance

Deliverables:

- master text-column inventory;
- runtime Text/TMP discovery plan/tooling;
- font architecture report;
- initial scenario-format map;
- initial texture-text inventory strategy;
- translation schema and glossary conventions.

Acceptance: every major text source is classified and has an extraction/translation strategy.

### M1 - "Hello Chinese" production path

Produce a derived/re-signed 11.6.3 install set that displays at least one controlled Simplified-Chinese UI string through the intended production localization loader (not a PC-attached transient Frida-only patch).

Acceptance: reboot/relaunch works without the development host injecting the text.

### M2 - Runtime core + font fallback

Deliver locale-pack loading, context lookup, unknown-string logging, formatting-token safety and Chinese font fallback.

Acceptance: arbitrary test translations can be rendered safely across the discovered Unity text stacks.

### M3 - Core UI localization

Cover Title, Home, Menu, LIVE, Unit, Idol/Card, Settings and Result.

Acceptance: the normal core game loop contains no unexplained Japanese text.

### M4 - Master localization

Translate all declared player-visible final-master fields and serve/build them as a localization overlay.

Acceptance: master coverage report reaches 100% approved for in-scope fields.

### M5 - Scenario engine

Implement lossless-ish decode/IR/re-encode for the final scenario format and prove one complete commu end-to-end.

### M6 - Full scenario translation

Translate/review all preserved story categories, choices and titles using glossary/character style guidance.

### M7 - Texture localization

Localize all required player-visible text embedded in graphics while preserving asset integrity.

### M8 - Long-tail surfaces

Cover rare dialogs, error paths, legacy screens, local WebView/help/notices and other runtime-discovered misses.

### M9 - Complete QA

Drive all coverage counters to release gates, perform screenshot/device regression passes and freeze the first complete `zh-CN` translation pack.

## CI strategy

Keep separate jobs/workflows for:

1. untouched preservation regression;
2. localized APK/split build smoke;
3. localization data/schema/placeholder validation;
4. runtime/device localization smoke when a suitable runner is available.

Never upload proprietary source assets from Actions. Generated localized APKs/assets should also remain private/ephemeral unless distribution policy is explicitly decided later.

## Immediate execution queue

The first implementation sprint starts now:

1. Add a shareable master text inventory tool that emits metadata/statistics but not source strings.
2. Add translation-entry schema and tests.
3. Run the inventory against the local final `master.mdb` and convert the result into a reviewed field-classification map.
4. Add a local-only source-catalog generator keyed by table/primary-key/column + source hash.
5. Extend final-client analysis to locate the concrete Text/TMP render/setter path and font assets.
6. Use rooted-device runtime evidence to choose the production hook point.
7. Implement M1 loader + first Chinese render, then freeze that path before bulk translation work.

The ordering is deliberate: prove `extract -> identify -> translate -> rebuild/lookup -> render` before committing large amounts of human translation work.
