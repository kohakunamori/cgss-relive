# cgss-relive

> THE IDOLM@STER CINDERELLA GIRLS STARLIGHT STAGE / デレステ preservation and offline reimplementation research.

`cgss-relive` is a clean-room preservation project for studying the current Android client, documenting its network/resource contracts, preserving user-obtainable game data, and building a minimal compatible local server for long-term archival use.

## Goals

1. Reproducibly fingerprint and inspect a legitimately installed Android client.
2. Document the client architecture, Unity runtime mode, endpoints, request/response formats, local persistence and resource bootstrap flow.
3. Preserve manifests, master database metadata and asset inventories without committing copyrighted game binaries to Git.
4. Implement a minimal local compatibility server, progressing from title/bootstrap to home and then offline LIVE/MV-oriented functionality.
5. Keep reverse-engineering notes and generated interfaces reproducible so future client versions can be compared.

## Non-goals

- Do not commit original APKs, split APKs, downloaded game assets, audio, card art, models, or bulk decompiler output.
- Do not publish real account credentials, session tokens, device identifiers, signing secrets, or production-service secrets.
- Do not depend on modifying the live service or other players' data.

## Repository layout

```text
docs/
  architecture.md          # architecture map and research checkpoints
  apk-workflow.md          # reproducible APK acquisition / inspection workflow
  preservation-plan.md     # preservation milestones and acceptance criteria
scripts/
  pull-installed-apk.ps1   # pull base/split APKs from an Android device
  inspect-apk.py           # static fingerprint and Unity runtime detector
captures/                  # sanitized protocol fixtures only (no secrets)
server/                    # clean-room compatible server implementation (later)
tests/                     # protocol and regression tests (later)
```

## Baseline Android package

Official Google Play package:

```text
jp.co.bandainamcoent.BNEI0242
```

For preservation work, prefer extracting the APK set from your own installed copy with ADB. This records exactly what the tested device is running and avoids ambiguity around repacked third-party APKs.

## First run

On Windows with ADB available:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./scripts/pull-installed-apk.ps1
python ./scripts/inspect-apk.py ./work/apk
```

Then follow [`docs/apk-workflow.md`](docs/apk-workflow.md).

## Research references

Useful prior art includes:

- `toyobayashi/mishiro` — CGSS desktop/resource tooling.
- `toyobayashi/CGSSAssetsDownloader` — historical manifest/resource downloader.
- `OpenCGSS/DereTore` — CGSS audio/beatmap tooling.
- `BA-Momoi/cgss-resource-tool` — actively maintained 2026 resource query/download/unpack tooling.
- `wsdslm/StarlightStageSpoofer` — historical documentation of older request protection; treat it as historical only and verify every assumption against the current client.

These projects are references for formats and terminology; `cgss-relive` should keep its server implementation clean-room and versioned against observed current-client behavior.

## Status

**Phase 0 — repository/bootstrap started.** Next concrete artifact is a fingerprint of the current installed Android APK set, followed by endpoint/static-string inventory and a first launch network trace.
