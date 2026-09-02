# APK acquisition and reverse-engineering workflow

This document defines the reproducible workflow for the Android client (`jp.co.bandainamcoent.BNEI0242`). The repository stores tooling, hashes, notes and clean-room interface descriptions; it does **not** store proprietary APKs or bulk decompiler output.

## 1. Acquire a known-good installed APK set

Preferred source: your own device/emulator with the official app installed.

```powershell
./scripts/pull-installed-apk.ps1
```

The script writes to `work/apk/<timestamp>/`:

- `base.apk` and any split APKs returned by `pm path`;
- `package-dumpsys.txt` with Android package metadata;
- `manifest.json` containing version name/code, device serial, file sizes and SHA-256 hashes.

If multiple ADB devices are connected:

```powershell
./scripts/pull-installed-apk.ps1 -Serial emulator-5554
```

## 2. Fingerprint before decompiling

```powershell
python ./scripts/inspect-apk.py ./work/apk/<timestamp>
```

Record the generated `inspection.json` in the research notes (not necessarily the whole local working directory). Important outputs:

- APK/split hashes;
- ABIs;
- Unity detection;
- Mono/managed vs IL2CPP runtime classification;
- candidate Unity version strings;
- static URL/domain strings;
- hashes of `Assembly-CSharp.dll`, `global-metadata.dat`, `libil2cpp.so` and DEX files when present.

### Runtime fork

If the client contains `assets/bin/Data/Managed/Assembly-CSharp.dll`, treat it as a managed/Mono-oriented Unity build and start from the managed assembly.

If it contains both `lib/*/libil2cpp.so` and `assets/bin/Data/Managed/Metadata/global-metadata.dat`, treat it as IL2CPP and use a metadata-aware IL2CPP analysis tool before doing native disassembly.

Do not assume historical CGSS findings still match the final client. The project has existed through multiple Unity generations.

## 3. Static analysis working tree

Recommended local tools:

- `jadx` for Java/Kotlin/DEX wrapper code and Android integrations;
- `apktool` for manifest/resources/smali inspection;
- a .NET decompiler when the build still includes managed game assemblies;
- Cpp2IL / Il2CppInspector / Il2CppDumper-class tooling if the current build is IL2CPP;
- Ghidra/IDA only after the higher-level metadata pass identifies the native targets that matter.

Example local commands:

```powershell
jadx -d work/jadx-out work/apk/<timestamp>/base.apk
apktool d -f work/apk/<timestamp>/base.apk -o work/apktool-out
```

For split installs, inspect every split inventory first. Native libraries/resources can live outside `base.apk`.

## 4. First static questions to answer

Do not attempt full-program understanding. Answer these in order:

1. Exact Unity version and scripting backend.
2. Startup scene / bootstrap classes.
3. HTTP stack (`UnityWebRequest`, native libcurl wrapper, custom layer, etc.).
4. Production API host(s) and resource/CDN host(s).
5. Client/version/resource-version negotiation.
6. Request envelope: method/path, headers, serialization, compression, encryption/MAC if any.
7. Local identifiers and persistence: PlayerPrefs, SQLite, files, account/session material.
8. Asset bootstrap: manifest path, manifest DB schema, `master.mdb` acquisition, cache layout.
9. Minimum API sequence from cold launch to title/home.
10. LIVE/MV entry dependencies that are server-owned versus asset/master-data-owned.

Write conclusions as versioned observations, e.g.:

```text
Observed on client 11.x.y, versionCode N, base.apk sha256=...
```

## 5. Dynamic observation order

Use the least invasive observation that answers the question:

1. `adb logcat` during cold launch.
2. DNS/SNI/connection metadata to identify hosts without decrypting traffic.
3. App-private cache/database inventory on a dedicated test device where you control the environment.
4. HTTP(S) interception on the dedicated test client only when payload structure is necessary.
5. Runtime instrumentation only for functions that cannot be reconstructed reliably from static analysis.

Never commit production session tokens, transfer credentials, device IDs, cookies or authorization headers. Put raw traces under `captures/raw/` (gitignored) and create explicit sanitized fixtures for tests.

## 6. Clean-room server boundary

The server should be implemented from documented input/output behavior, not by copying decompiled proprietary source. Safe artifacts to commit include:

- endpoint tables;
- field schemas inferred from observations;
- protocol parsers/reimplementations written from scratch;
- sanitized request/response fixtures;
- resource-manifest schema notes;
- compatibility tests;
- patches that redirect a locally owned test client to a local server, where needed.

## 7. Candidate final Android build

Third-party package indexes list Android `11.6.3` dated 2025-10-20 for package `jp.co.bandainamcoent.BNEI0242`. Treat that only as a **candidate final/reference version** until the version and signer are verified against an installed official copy.

The acquisition manifest from ADB is the authoritative sample identity for this project.
