# Current-state research notes — 2026-09

Status labels:

- **Verified** — confirmed by current official/public source or our own specimen.
- **Strong lead** — current community implementation or package index; must be verified against our specimen.
- **Historical** — useful older implementation detail; do not assume unchanged.

## Client identity

### Verified

- Android package name: `jp.co.bandainamcoent.BNEI0242`.
- Official Google Play listing still exists.

### Strong lead

- APKPure indexes `11.6.3`, dated 2025-10-20, as the newest Android package revision.
- Treat `11.6.3` as the candidate final Android client until an official installed copy is fingerprinted with ADB.

## Unity/runtime

### Verified

- CGSS is a Unity title historically and current resource requests identify as Unity.

### Strong lead

A maintained resource tool updated in August 2026 sends:

```text
User-Agent: UnityPlayer/2022.3.56f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)
X-Unity-Version: 2022.3.56f1
```

This strongly suggests the final resource client generation uses Unity `2022.3.56f1`, but we will not mark this verified until `globalgamemanagers` / APK strings confirm it.

The scripting backend (Mono/managed vs IL2CPP) remains **unknown** until the APK set is inspected.

## Resource plane

### Strong lead — resource version

A maintained August 2026 resource project references:

```text
manifest_10133800.db
```

so `10133800` is the current candidate frozen resource version.

### Strong lead — bootstrap/CDN

Current community code documents:

```text
truth-version helper:
  https://starlight.kirara.ca/api/v1/info

official resource CDN host:
  asset-starlight-stage.akamaized.net

manifest bootstrap:
  /dl/<ver>/manifests/all_dbmanifest
  /dl/<ver>/manifests/Android_AHigh_SHigh

master database:
  lookup master.mdb hash in the resource manifest
  fetch through the generic resource path
```

The manifest database and `master.mdb` are SQLite after CGSS LZ4-wrapper decompression.

## Historical API/control plane

Older open implementations describe the production API host as:

```text
apis.game.starlight-stage.jp
```

and describe a request/response envelope involving:

- MessagePack payloads;
- Base64 wrapping;
- AES-CBC;
- per-request/body key material;
- UDID-derived IV behavior;
- custom headers such as `APP-VER`, `RES-VER`, `PARAM`, `SID`, `UDID`, `USER-ID`, `X-Unity-Version`.

This is **historical** (not yet current-client evidence). It is useful because it gives us exact symbols/field names to search for in the final APK.

## Fastest next static searches after APK acquisition

Search managed metadata/strings and DEX/native strings for:

```text
apis.game.starlight-stage.jp
asset-starlight-stage.akamaized.net
APP-VER
RES-VER
PARAM
SID
UDID
USER-ID
viewer_id
MessagePack
msgpack
Rijndael
AES
UnityWebRequest
2022.3.56f1
all_dbmanifest
Android_AHigh_SHigh
master.mdb
```

If these symbols survive, map callers rather than browsing the entire decompilation.

## Current working target

For planning only:

```text
candidate app version:      11.6.3
candidate resource version: 10133800
candidate Unity version:    2022.3.56f1
package:                    jp.co.bandainamcoent.BNEI0242
```

All three candidate versions must be replaced by specimen-derived facts once `manifest.json` and `inspection.json` are produced by the repository scripts.
