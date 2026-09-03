# Android specimen: CGSS 11.6.3 XAPK

This document records reproducible facts obtained from the exact final XAPK
specimen. Original APK/XAPK binaries and extracted proprietary game binaries are
intentionally **not** committed.

## Identity

| Field | Value |
| --- | --- |
| Package | `jp.co.bandainamcoent.BNEI0242` |
| App version | `11.6.3` |
| versionCode | `438` |
| Launchable activity | `jp.co.cygames.stage.StageUnityPlayerActivity` |
| minSdk | `26` |
| targetSdk | `35` |
| XAPK SHA-256 | `609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d` |

The launchable activity is not guessed from Unity conventions. The exact
hash-verified XAPK GitHub Actions pass scans its APK splits with Android `aapt dump
badging`, accepts only the expected package/version identity, and requires exactly
one distinct MAIN/LAUNCHER activity. The verified result has one matching split
APK and one launchable activity.

### APK splits

| Split | Size | SHA-256 |
| --- | ---: | --- |
| `jp.co.bandainamcoent.BNEI0242.apk` (base) | 96,869,378 | `c73fc868bcaaccb7912eddb4d6651189d52526c5df5c31ec9b12de8c06c19cee` |
| `config.arm64_v8a.apk` | 57,628,903 | `da2d09804bdc33a586e684599a42f496db4f43ceedc4359f45b89f8fc571d3c7` |
| `config.armeabi_v7a.apk` | 57,321,841 | `a5b5a8dafcb35a3e30f8de74d34dd5d176aa394f81e324cebb19b1aeb1412c04` |

## Signing provenance

All three APK splits contain the same APK Signature Scheme v2 signer certificate.

- certificate SHA-256: `336ca2245718a9ca1672bf0bf2d324b29a836d899848ac0e8c08ba79097c03b3`
- subject / issuer: `C=jp, ST=Tokyo, L=Shinagawa-ku, O=NAMCO BANDAI Games Inc., OU=NAMCO BANDAI Games Inc., CN=NAMCO BANDAI Games Inc.`
- serial: `4CC13C7A`
- validity observed in certificate: 2010-10-22 through 2038-03-09

The matching signer across base and ABI splits plus the Bandai Namco certificate
identity is a strong provenance signal for the contained APK set. The fingerprint
has not been independently compared with a separately acquired official-store
copy, so it should not be described as independently authenticated solely from
this report.

## Unity / IL2CPP

The specimen is unambiguously IL2CPP.

- Unity version: **`2022.3.56f1`**
  - directly present in `globalgamemanagers`
  - also present in `libunity.so` as `2022.3.56f1 (dd0c98481d00)`
- `global-metadata.dat` magic: `0xFAB11BAF`
- IL2CPP metadata version: **31**
- metadata structure counts:
  - 37,251 managed string literals
  - 31,804 type definitions
  - 222,595 method definitions
  - 95 images/assemblies
- `Assembly-CSharp.dll` contains 21,083 type definitions in the metadata image map.

### Key binary fingerprints

| Object | SHA-256 |
| --- | --- |
| `global-metadata.dat` | `2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586` |
| arm64 `libil2cpp.so` | `2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5` |
| arm64 `libunity.so` | `b6ec9b930e48898d0b3dd292e8d1468c94d825058f2253f9980f6e5d559ac257` |
| `globalgamemanagers` | `d5ffd4617d8c7e838057d4ba5a3fdbe6b625f8b6c4d051d559554bfdcfb66288` |
| `ScriptingAssemblies.json` | `67387ee14514c5ec0b331ab036ce1f70c78fb32c9a6d0d29fd6217be4048563f` |

The arm64 split contains a ~142 MB `libil2cpp.so` and a ~25 MB `libunity.so`;
the base APK contains
`assets/bin/Data/Managed/Metadata/global-metadata.dat` and Unity bootstrap
metadata.

## Current-client network surface

The following are present as managed string literals in the **11.6.3** IL2CPP
metadata, so they are current-client evidence rather than assumptions copied from
older tools.

### Hosts

- `apis.game.starlight-stage.jp/`
- `ext-api.game.starlight-stage.jp/`
- `stream-api.starlight-stage.jp/`
- `storages.game.starlight-stage.jp/`
- `asset-starlight-stage.akamaized.net/`

### Request/header vocabulary

Confirmed current literals include:

- `APP-VER`
- `RES-VER`
- `PARAM`
- `SID`
- `UDID`
- `USER-ID`
- `DEVICE`
- `DEVICE-ID`
- `DEVICE-NAME`
- `GRAPHICS-DEVICE-NAME`
- `IP-ADDRESS`
- `PLATFORM-OS-VERSION`
- `CARRIER`
- `KEYCHAIN`
- `PROCESSOR-TYPE`
- `RETRY-FLAG`

`MessagePack.*` types and the CGSS AES/cryptography classes are also present in
the current metadata. Subsequent final-client analysis has already closed the
current MessagePack/AES request/response envelope; this vocabulary section is
kept as specimen evidence, not as an open crypto task.

### Core request/crypto classes

Current metadata resolves the following high-value classes and method surfaces:

- `Cute.NetworkTask`
  - `PrepareHeaders`
  - `PreparePostData`
  - `CreateBody`
  - `SetResponseData`
  - `CheckResult`
  - `Parse`
  - `AddHeaderUdid`
  - `AddHeaderUserId`
  - `AddHeaderSessionId`
  - `AddHeaderParam`
  - `AddHeaderVersion`
  - `AddHeaderDeviceId`
  - `AddHeaderDeviceName`
  - `AddHeaderGraphicsDeviceName`
  - `AddHeaderIpAddress`
  - `AddHeaderPlatformOsVersion`
  - `AddHeaderCarrier`
  - `AddHeaderKeyChain`
  - `AddHeaderProcessorType`
  - `AddHeaderRetryFlag`
- `Cute.NetworkManager`
  - connection/task dispatch and result handling
- `Cute.CryptAES`
  - `encrypt`, `decrypt`, `EncryptRJ256`, `DecryptRJ256` and node variants
- `Cute.AES256Crypt`
  - `Encrypt`, `Decrypt`
- `Cute.Cryptographer`
  - IV/key generation, encode/decode, MD5/SHA-256 helpers
- `Cute.Certification`
  - login/session/UDID state and `VersionCheckTaskExec`
- `Cute.VersionCheckTask`
- `Cute.BootNetwork`
  - including `SetupNetworkCertification`
- `Cute.Header`
  - fields include `result_code`, `viewer_id`, `udid`, `sid`,
    `required_res_ver`, `download_list`, `download_url`, `servertime`
- `Cute.CustomPreference`
  - application, stream/concert, resource, manifest, blob and master URL builders

## Startup/API path evidence

The final-client metadata contains the startup paths themselves, including:

- `load/check`
- `load/index`
- `load/title`
- `load/get_external_site_url`
- `load/set_cache_clear_flg`
- `load/update_agreement_status`
- `home/update`
- `profile/get_profile`

It also contains large sets of live/story/friend/room/gacha/event endpoints
including `live/start`, `live/end` and `story/start`.

Current clean-room work has already reduced the hard bootstrap to `/load/check`,
resource initialization and `/load/index`; later endpoint restoration remains
runtime/blocker driven.

## Resource bootstrap evidence

Current 11.6.3 metadata contains:

- `all_dbmanifest`
- `master.mdb`
- `manifests`
- `resources/Generic/`
- `Generic/Blob`
- `Generic/Master`
- manifest SQL including resource-name -> hash lookups

The APK contains the exact resource-version-like literal:

```text
10133000
```

It does **not** contain `10133800` as a managed literal.

The frozen preservation state is now independently verified as:

```text
binary/default RES_VER  10133000
final resource revision 10133800
manifest rows            220837
unique hashes            220803
```

The final-client 214 path persists server `required_res_ver=10133800`, after
which the statically closed parent continuation proceeds into manifest/resource
initialization. The local resource stack preserves the final
`all_dbmanifest -> Android_AHigh_SHigh -> manifest SQLite -> master.mdb` chain.

## Reproduction helpers

For a local XAPK:

```powershell
python .\scripts\unpack-xapk.py .\client.xapk -o .\work\apk\11.6.3-xapk
python .\scripts\inspect-apk.py .\work\apk\11.6.3-xapk -o .\work\apk\11.6.3-xapk\inspection.json
python .\scripts\extract-analysis-targets.py .\work\apk\11.6.3-xapk -o .\work\apk\11.6.3-xapk\analysis-targets
python .\scripts\inspect-il2cpp-metadata.py .\work\apk\11.6.3-xapk\analysis-targets\assets\bin\Data\Managed\Metadata\global-metadata.dat -o .\work\apk\11.6.3-xapk\metadata-report.json
```

The repository's exact-specimen Actions workflow additionally verifies the
frozen XAPK/libil2cpp/metadata hashes, extracts only a sanitized launchable
activity identity, runs bounded targeted IL2CPP passes, deletes all raw specimen
material, and uploads only sanitized derived reports.

## Current preservation boundary

The old M0/M1/M2/M3 planning sequence is complete enough that it must not be used
as a reason to restart solved research:

- exact final application specimen identity: closed;
- resource revision 10133800 freeze/bootstrap: closed;
- current transport codec/version negotiation: closed;
- `/load/index` parser/Home control-flow reduction: closed enough for a real
  starter-profile experiment;
- deterministic host stack/resource/TLS/device-preflight tooling: implemented.

The decisive remaining acceptance milestone is **runtime**, not another specimen
inventory pass: launch this untouched final application on the rooted test device,
observe TLS acceptance, native 214 resource continuation, `/load/index`, and
visible Home/Login Bonus -> Home. Static analysis and server-side success must not
be reported as visible Home acceptance.
