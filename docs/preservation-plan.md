# Preservation plan

The project is intentionally staged so each milestone produces a usable archival artifact even if later server work becomes difficult.

## M0 — Reproducible client specimen

**Deliverables**

- ADB extraction script.
- APK/split acquisition manifest.
- SHA-256 hashes and package version.
- signer/certificate fingerprint procedure.
- Unity version + scripting backend classification.

**Acceptance**

Another researcher with the same installed build can produce matching hashes/metadata without relying on a third-party repack.

## M1 — Resource freeze

**Deliverables**

- resource-version detector;
- manifest downloader/parser;
- manifest schema documentation;
- `master.mdb` acquisition/parser;
- complete resource inventory with expected hash/size/type;
- resumable local archival downloader;
- verification command that reports missing/corrupt objects.

**Storage rule**

Do not place the proprietary resource archive itself in this public repository. Store it in a user-selected archival directory/object store. The repo contains only tooling and metadata needed to reproduce/verify the archive.

**Acceptance**

Given a resource version, the tool can enumerate the complete expected archive and prove whether a local archive is complete.

## M2 — Client startup protocol map

**Deliverables**

- ordered cold-launch request sequence;
- endpoint table: method, path, request fields, response fields;
- required headers/device/version fields;
- serialization/compression/protection envelope description;
- sanitized fixtures for each startup endpoint;
- error-code observations.

**Acceptance**

A test harness can parse and regenerate the recorded startup envelopes without copying decompiled implementation code.

## M3 — Local title/bootstrap server

**Deliverables**

- local server skeleton;
- compatibility version endpoint(s);
- resource-version response;
- synthetic archival account/profile bootstrap;
- deterministic server clock/config;
- endpoint logging with secret redaction.

**Acceptance**

A dedicated test client reaches the title/bootstrap stage using local infrastructure without contacting production API hosts. Resource CDN may still be remote at this milestone.

## M4 — Home screen offline

**Deliverables**

- player state model;
- owned-idol/card/unit state sufficient for UI;
- master-data-driven defaults;
- home/navigation response set;
- local resource CDN/proxy mode.

**Acceptance**

A fresh archival profile can enter and remain on the main/home UI, navigate core menus, and restart without production API dependence.

## M5 — Asset-local operation

**Deliverables**

- local manifest endpoint;
- hash-addressed asset server;
- correct MIME/range/cache behavior as required by client;
- validation against the frozen resource inventory;
- optional upstream fill mode for development only.

**Acceptance**

With the network route to the original asset CDN disabled, the client can acquire required resources from the local archive.

## M6 — Preservation gameplay MVP

Priority order:

1. album/card/idol viewers;
2. commu/story playback;
3. music catalog and jacket/metadata display;
4. LIVE practice path;
5. 3D MV path;
6. photo studio / room.

**Acceptance**

At least one representative LIVE/MV can be entered, played/rendered, exited and repeated entirely against local services and local assets.

## M7 — Long-term reproducibility

**Deliverables**

- containerized/server release;
- Windows/WSL startup scripts;
- backup/restore format for archival profiles and asset indexes;
- protocol regression tests;
- documented client patch/redirect procedure if endpoint replacement is necessary;
- release checklist and known limitations.

**Acceptance**

A clean machine with an archived client specimen plus a separately held asset archive can reproduce the preserved experience from documentation alone.

## Immediate next evidence required

Run:

```powershell
./scripts/pull-installed-apk.ps1
python ./scripts/inspect-apk.py ./work/apk/<timestamp>
```

The first useful files to inspect are:

```text
work/apk/<timestamp>/manifest.json
work/apk/<timestamp>/inspection.json
work/apk/<timestamp>/package-dumpsys.txt
```

Once these exist, the next implementation decision becomes deterministic: managed `Assembly-CSharp.dll` analysis versus IL2CPP metadata/native analysis.
