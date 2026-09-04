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

## Initial layout

```text
localization/
  README.md
  schema/          # versioned translation/data contracts
  tools/           # extraction, inventory, build and QA tooling
  translations/    # locale packs (added as reviewed data becomes available)
  glossary/        # terminology and character voice/style guidance
  runtime/         # production localization loader/hooks (M1+)
```

The first active work item is a non-leaking inventory of text-bearing columns in the final local `master.mdb`, followed by a reviewed field-classification map and source-catalog generator.
