# cgss-relive

> THE IDOLM@STER CINDERELLA GIRLS STARLIGHT STAGE / デレステ preservation and offline reimplementation research.

`cgss-relive` is a clean-room preservation project for studying the final Android client, documenting its network/resource contracts, preserving user-obtainable game data, and building a minimal compatible local server for long-term archival use.

## Goals

1. Reproducibly fingerprint and inspect a legitimately installed Android client.
2. Document the client architecture, Unity runtime mode, endpoints, request/response formats, local persistence and resource bootstrap flow.
3. Preserve manifests, master database metadata and asset inventories without committing copyrighted game binaries to Git.
4. Implement a minimal local compatibility server, progressing from title/bootstrap to home and then offline LIVE/MV-oriented functionality.
5. Keep reverse-engineering notes and generated interfaces reproducible so future researchers can reproduce the preserved environment.

## Non-goals

- Do not commit original APKs, split APKs, downloaded game assets, audio, card art, models, or bulk decompiler output.
- Do not publish real account credentials, session tokens, device identifiers, signing secrets, or production-service secrets.
- Do not depend on modifying the live service or other players' data.

## Repository layout

```text
docs/
  architecture.md              # architecture map and research checkpoints
  apk-workflow.md              # reproducible APK acquisition / inspection workflow
  resource-bootstrap.md        # final manifest/master resource bootstrap
  protocol-historical.md       # old API envelope, only as final-client search targets
  preservation-plan.md         # preservation milestones and acceptance criteria
  research/                    # dated evidence and hypotheses
scripts/
  analyze-installed-client.ps1 # one-command acquisition + static triage
  pull-installed-apk.ps1       # pull base/split APKs from an Android device
  inspect-apk.py               # static fingerprint and Unity runtime detector
  extract-analysis-targets.py  # minimal IL2CPP/Unity/DEX working-set extractor
  scan-analysis-targets.py     # protocol/resource indicator binary scanner
  fetch-resource-bootstrap.py  # verified manifest + master.mdb bootstrap
captures/                      # sanitized protocol fixtures only (no secrets)
server/                        # clean-room compatible server implementation (later)
tests/                         # helper/protocol/regression tests
```

## Baseline Android package

Official Google Play package:

```text
jp.co.bandainamcoent.BNEI0242
```

For preservation work, prefer extracting the APK set from your own installed copy with ADB. This records exactly what the tested device is running and avoids ambiguity around repacked third-party APKs.

## First run — recommended

On Windows with ADB and Python 3 available:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./scripts/analyze-installed-client.ps1
```

This performs:

```text
ADB installed APK/split acquisition
  -> version + SHA-256 fingerprint
  -> Unity / Mono / IL2CPP detection
  -> minimal high-value binary extraction
  -> current/historical protocol string scan
  -> APK signing-certificate report when apksigner is available
```

It intentionally does **not** bulk-decompile by default. If `jadx` and `apktool` are installed and full local output is useful:

```powershell
./scripts/analyze-installed-client.ps1 -Decompile
```

All proprietary/reverse-engineering outputs remain under `work/` and are gitignored.

See [`docs/apk-workflow.md`](docs/apk-workflow.md) for the detailed workflow.

## Freeze the final resource bootstrap

The current archival target is resource version `10133800` pending final-client confirmation.

```powershell
python ./scripts/fetch-resource-bootstrap.py --version 10133800
```

This verifies the compressed Android manifest hash, decodes the CGSS LZ4 wrapper, validates the manifest SQLite database, resolves `master.mdb`, then verifies/decodes/validates that database as well.

See [`docs/resource-bootstrap.md`](docs/resource-bootstrap.md).

## Current working hypotheses

These are deliberately kept separate from specimen-derived facts:

```text
candidate final Android app: 11.6.3
candidate final resource:    10133800
candidate final Unity:       2022.3.56f1
historical backend:          IL2CPP
```

The first local specimen run should replace hypotheses with authoritative hashes/version/runtime evidence.

## Research references

Useful prior art includes:

- `toyobayashi/mishiro` — CGSS desktop/resource tooling.
- `toyobayashi/CGSSAssetsDownloader` — historical manifest/resource downloader.
- `OpenCGSS/DereTore` — CGSS audio/beatmap tooling.
- `BA-Momoi/cgss-resource-tool` — actively maintained 2026 resource query/download/unpack tooling.
- KisaragiSan `cgssapi.py` — historical API-envelope reference.
- `wsdslm/StarlightStageSpoofer` — historical request-protection research.

These projects are references for formats and terminology; `cgss-relive` keeps the compatibility-server implementation clean-room and versioned against observed final-client behavior.

## Status

### M0 — client specimen

Tooling is ready. Issue #1 tracks final APK/split fingerprinting, signing certificate, Unity version and IL2CPP/managed classification.

### M1 — resource freeze

Bootstrap tooling is ready. Issue #2 tracks final `10133800` manifest/master verification and the subsequent complete resource inventory/archive.

### M2 — control/API protocol

Historical MessagePack/AES/header behavior is documented only as a verification target. Implementation begins after the final client's static strings and cold-launch behavior establish the actual transport contract.
