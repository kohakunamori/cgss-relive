# Architecture map

This is a working map, not a claim that every historical detail still applies to the final client. Every item must eventually be tagged as **observed-current**, **historical-reference**, or **hypothesis**.

## Client

- Android package: `jp.co.bandainamcoent.BNEI0242`
- Engine: Unity (confirmed historically; current scripting backend must be fingerprinted from the APK set).
- Current resource tooling in the community emulates a Unity `2022.3.56f1` user agent; verify this directly from the final APK before treating it as authoritative.

## Data planes

### 1. API/control plane

Responsibilities expected to remain server-owned:

- application/version checks;
- session/account bootstrap;
- player profile/state;
- home-screen state;
- inventory/cards/units;
- gacha/event/social/mission state;
- LIVE start/result bookkeeping;
- announcements and time-dependent state.

For preservation, the first server milestone is not feature parity. It is a deterministic local bootstrap profile capable of taking a clean client from launch to a stable home state.

### 2. Resource plane

Historical and currently maintained community tooling shows a separate resource system built around:

- versioned manifest downloads;
- a SQLite resource manifest;
- `master.mdb` as a master-data SQLite database;
- Unity AssetBundles for graphics/models/scenes;
- CRI ACB/AWB/HCA for audio;
- BDB/MDB generic data resources;
- content-addressed/hash-based CDN paths.

A maintained 2026 community implementation describes this current manifest bootstrap shape:

```text
/dl/<resource_version>/manifests/all_dbmanifest
/dl/<resource_version>/manifests/Android_AHigh_SHigh
```

and a CDN host of:

```text
asset-starlight-stage.akamaized.net
```

It then obtains `master.mdb` through the resource manifest and the generic resource path. Treat these as strong leads to verify against current-client static strings and live requests.

### 3. Local persistence plane

Inventory on a dedicated test installation should distinguish:

- immutable APK/split content;
- Unity/cache files;
- downloaded resources;
- PlayerPrefs/shared preferences;
- SQLite databases;
- user/session/account state;
- generated photos/screenshots/logs.

The preservation design should avoid requiring a copied live account state. The local server should be able to synthesize a fresh archival profile.

## Proposed relive architecture

```text
                    +----------------------+
                    |  archived Android    |
                    |  CGSS client         |
                    +----------+-----------+
                               |
                  local DNS / endpoint redirect
                               |
          +--------------------+---------------------+
          |                                          |
+---------v---------+                       +--------v---------+
| cgss-relive API   |                       | local asset CDN  |
| compatibility     |                       | / resource store |
| server            |                       +--------+---------+
+---------+---------+                                |
          |                                          |
+---------v------------------+              +---------v----------------+
| deterministic archival DB |              | manifest + master index  |
| profile / units / unlocks  |              | content-addressed files |
+----------------------------+              +--------------------------+
```

## Separation rules

The repository should distinguish four artifact classes:

1. **Source** — original code written for cgss-relive; commit normally.
2. **Derived metadata** — schemas, hashes, endpoint names, field descriptions; commit when safe.
3. **Sanitized fixtures** — minimal request/response examples with secrets removed; commit for tests.
4. **Proprietary payloads** — APKs, full decompiler output, game assets/audio/databases; keep outside Git.

## Research priority

### P0 — sample identity

- final/current Android version;
- official signer fingerprint;
- base/split hashes;
- Unity version;
- Mono vs IL2CPP;
- ABI set.

### P1 — startup/resource bootstrap

- endpoint/domain inventory;
- application/resource version checks;
- manifest and master database flow;
- cache paths;
- title-screen request sequence.

### P2 — protocol envelope

- serialization format;
- compression;
- encryption/MAC/signature behavior;
- required headers and device metadata;
- error envelope.

### P3 — minimal local server

- health/version/bootstrap endpoints;
- fixed local profile;
- deterministic clock policy;
- home transition;
- sanitized contract tests.

### P4 — preserved gameplay surfaces

Prioritize features with high archival value and low dependence on live social/economy state:

1. card/idol viewing;
2. commu/story playback;
3. music selection;
4. LIVE practice/offline LIVE;
5. 3D MV;
6. photo studio / room where feasible.

Gacha, rankings, payments and social systems are not required for the preservation MVP.
