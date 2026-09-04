# Localization workspace

This directory contains reproducible tooling and versioned metadata for the CGSS 11.6.3 localization effort.

Primary target: complete Simplified-Chinese (`zh-CN`) localization of the frozen final Android client while keeping the untouched-client preservation baseline independent.

See [`docs/localization-plan.md`](../docs/localization-plan.md) for architecture, milestones, coverage gates and the immediate execution queue.

## Rules

- Do not commit original APK/XAPK/split APKs, game databases, AssetBundles, scenario bodies, textures, audio, IL2CPP binaries/metadata or bulk source-text dumps.
- Generated source catalogs stay in ignored local working paths.
- Prefer stable semantic translation IDs over raw Japanese text keys.
- Every extraction/rebuild path must be reproducible and testable.
- Runtime localization must fail open to original text rather than crash the game.
- Preservation success and localized-client success are separate acceptance targets.

## Layout

```text
localization/
  README.md
  schema/          # versioned translation/data contracts
  tools/           # extraction, inventory, build and QA tooling
  translations/    # locale packs (added as reviewed data becomes available)
  glossary/        # terminology and character voice/style guidance
  runtime/         # production localization loader/hooks (M1+)
```

## Current M0 tools

### Master text inventory

`tools/inventory_master_text.py` scans a local SQLite `master.mdb` and reports text-bearing tables/columns, candidate classification, counts and maximum lengths without emitting source string values.

```bash
python localization/tools/inventory_master_text.py \
  work/final/master.mdb \
  --output work/localization/master-text-inventory.json
```

Use the sanitized inventory to review which columns are genuinely player-visible. Do not treat the heuristic classification as authoritative.

### Master source catalog

After reviewing the inventory, write a field map conforming to `schema/master-field-map.schema.json`. The catalog builder exports only the explicitly selected fields and constructs stable IDs from table + primary key + column.

```bash
python localization/tools/build_master_source_catalog.py \
  work/final/master.mdb \
  work/localization/master-fields.json \
  --output localization/catalogs/source/master.zh-source.json
```

The resulting catalog **contains original game strings** and is intentionally gitignored. It is a local translator/build input, not a repository artifact.

Translation entries intended for versioned locale packs conform to `schema/translation-entry.schema.json` and use the source SHA-256 to detect source drift without requiring bulk Japanese source text in Git.

## Immediate next step

Run the inventory on the frozen final `10133800` master, review the candidate fields into a field map, build the first local source catalog, and then move to final-client Text/TMP/font discovery for the M1 production localization loader.
