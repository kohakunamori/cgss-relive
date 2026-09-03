# AGENT HANDOFF — cgss-relive

Authoritative continuation point for `kohakunamori/cgss-relive`.

**Do not restart solved research.** Fetch actual `main`, verify CI, then continue
from original-client runtime integration.

## Mission

Make the original untouched final Android CGSS client 11.6.3 boot against a
clean-room local compatibility stack, enter preserved Home, then restore later
offline endpoints/content one blocker at a time.

Final specimen:

```text
package:          jp.co.bandainamcoent.BNEI0242
app version:      11.6.3
versionCode:      438
Unity:            2022.3.56f1
runtime:          IL2CPP
metadata version: 31
```

Exact frozen hashes:

```text
XAPK SHA256
609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d

arm64 libil2cpp.so SHA256
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat SHA256
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

The repository now contains an ephemeral GitHub Actions analysis workflow which
downloads the public specimen, verifies all three hashes, runs targeted IL2CPP
analysis, deletes binaries, and uploads only bounded/sanitized reports.

Never commit APK/XAPK, `libil2cpp.so`, metadata, master/manifest databases,
resource bodies, production credentials/session values, plaintext client-static
keys/salts, raw sensitive captures, or bulk decompiler output.

## Required reading

```text
docs/load-check-11.6.3.md
docs/load-index-11.6.3.md
docs/rooted-device-integration.md
docs/runtime-event-analysis.md
docs/local-resource-server.md
docs/resource-bootstrap.md
docs/protocol-11.6.3.md
docs/research/2026-09-03-final-client-bootstrap-closure.md
```

## Protocol — solved

Final request/response codec:

```text
JSON -> MessagePack -> Base64 -> AES-256-CBC -> Base64(cipher || dynamic 32-byte key)
IV = UDID-derived 16 bytes
```

Implemented/tested in:

```text
server/cgss_codec.py
server/header_codec.py
server/bootstrap_core.py
```

Final result codes:

```text
success           1
session error     201
app-version error 204
resource-version  214
```

Do not rediscover solved crypto unless an original-client runtime contradicts a
specific fixture.

## Resource versions — keep both

```text
binary/default RES_VER: 10133000
final frozen revision:  10133800
```

Issue #2 resource freeze is complete.

Frozen facts:

```text
manifest rows          220837
unique resource hashes 220803
archive planned        220803
archive skipped        0
master tables          909
card_data rows          4314
```

Archive:

```text
resource-cache/10133800/objects/<hash[0:2]>/<hash>
```

## `/load/check` — native 214 semantics

Default server policy:

```text
/load/check RES-VER=10133000
  -> result_code=214
  -> required_res_ver=10133800
  -> data.isS3=false
```

Final static evidence proves:

- 214 is accepted by the network result path;
- `required_res_ver` is persisted to Savedata `RES_VER`;
- no immediate `/load/check` resend occurs inside that network coroutine.

Do **not** expect or require:

```text
214 -> immediate /load/check 10133800
```

The diagnostic flag `--accept-old-resource-version` still exists only for a
controlled differential; it is not the native/default model.

## Bootstrap resource continuation — now statically closed

The old handoff gap “214 -> unknown higher-level transition” is obsolete.

Exact final chain:

```text
Stage.BootMain.<Initialize>d__14.MoveNext
  -> Stage.ResourcesManager.GameInitialize        @ 0x037340ac
  -> <GameInitialize>d__85.MoveNext               @ 0x0374ed34
  -> Cute.BootNetwork.SetupNetwork                @ 0x050c6c84
  -> <SetupNetworkCoroutine>d__11.MoveNext        @ 0x050c74dc
  -> Cute.Certification.Login                     @ 0x050bdd9c
  -> Cute.Certification.VersionCheckTaskExec      @ 0x050bde1c
  -> <VersionCheckTaskExec>d__43.MoveNext         @ 0x050bf3c8
  -> /load/check
  -> 214 + required_res_ver=10133800
  -> Savedata RES_VER=10133800
  -> SetupNetwork becomes ready
  -> GameInitialize resumes
  -> Cute.AssetManager.InitializeManifest         @ 0x050a9000
  -> DownloadOrLoadForInitialize resource work
  -> GameInitialize completes
  -> BootMain.Initialize resumes
  -> BootMain.StartConnect                        @ 0x039c9a24
  -> /load/index
```

Critical RVA correction:

```text
0x0374ed34 = <GameInitialize>d__85.MoveNext entry
0x0374eed8 = BL Cute.BootNetwork.SetupNetwork call site
```

Never regress to labeling `0x0374eed8` as the coroutine entry.

## Resource hosts / server

`VersionCheckTask.Parse` writes `data.isS3` into `NetworkUtil.isS3`.

```text
isS3=false -> storages.game.starlight-stage.jp
isS3=true  -> asset-starlight-stage.akamaized.net
```

Compatibility server fixes `isS3=false` for deterministic local preservation.

`server/resource_server.py` supports reconstructed final URL families, manifest DB
filename resolution, wire manifests, GET/HEAD/ranges/TLS, and now optional:

```text
--event-log <sanitized.jsonl>
```

Resource event logging never records filename/hash/query. Only these synthetic
routes are emitted:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

This is important because after a native 214, a resource request is the expected
next observable proof of progress even if no second `/load/check` exists.

## Endpoint map

Final map:

```text
A: 516 records, keys 0..515 continuous
B: 22 records
```

Load routes:

```text
0   load/check
1   load/set_cache_clear_flg
10  load/title
11  load/index
12  load/get_external_site_url
13  load/update_agreement_status
```

No final `home/index` or `home/load`. `home/update` is later.

Implemented:

```text
/load/check
/load/title
/load/index
/load/set_cache_clear_flg
/load/update_agreement_status
```

`/load/get_external_site_url` remains deliberately un-faked until an actual
caller proves required business semantics.

`/load/title` is a Title/user-driven branch, not a mandatory Home bootstrap link.

## `/load/index` parser

Target:

```text
Stage.LoadTask.Parse RVA 0x04850a94
```

Hard normal-path envelope:

```text
data
└─ common_define
```

Required direct `common_define` ints:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

Current direct synthetic `user_info` scalar set:

```text
tutorial_flag
viewer_id
name
comment
max_card_num
max_room_storage_num
friend_pt
jewel
free_jewel
gold
stamina
level
exp
fan
producer_rank
birth
sum_of_money
last_payment_date
stamina_heal_time
```

Most feature sections are guard/empty safe. Do not add partially populated guarded
objects: once a guarded parent is present, some child reads become hard.

## Unit/starter contract

Top-level `user_unit_list` may be absent/empty.

For non-empty unit:

```text
first pass: unit_slot + name
fixed loop: serial_id_0 .. serial_id_4 (exactly five)
later pass: unit_id + name
```

Starter-visible synthetic state:

```text
card_id          100001 = 島村卯月
chara_id         101
serial_id        1
unit_slot        1
unit_id          1
leader_serial_id 1
```

Starter-visible is the first runtime profile. Empty/strict are differential
fallbacks only.

## `/load/index` -> Home — now statically closed

Success tail:

```text
/load/index
 -> Stage.LoadTask.Parse
 -> BootMain.CallbackOnSuccessLoad
 -> BootMain.LastInitialized
 -> BootMain.ChangeView
 -> SceneManager.ChangeView
```

Final `StageSceneDefine.eViewId` mapping:

```text
BootMain       = 5
Home           = 6
Login_Bonus    = 7
Asset_Download = 8
```

`BootMain.ChangeView` computes:

```text
next = LoginBonusData.IsExistLoginBonus() ? 7 : 6
```

Independent call sites also use `ChangeView(6)` from Home UI/back navigation.
Therefore IDs 6/7 are no longer a static gap.

Visible Home with the local stack is still runtime-pending because static control
flow does not claim what an unrun original client rendered.

## Runtime analyzer

`scripts/analyze-runtime-events.py` report schema is now **3**.

Important resource-negotiation fields include:

```text
server_returned_214
observed_later_control_request_after_214
observed_resource_request_after_214
observed_successful_resource_response_after_214
observed_later_10133800_load_check_after_214
server_returned_direct_success_with_required_res_ver
server_returned_success_for_10133800
```

Hard phases now include:

```text
resource_version_214_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

The runtime log must never contain UDID, SID, USER-ID, PARAM, viewer-id values,
decoded request/response values, resource filenames, or object hashes.

## TLS integration

Static evidence still supports:

```text
original HTTPS hostname
-> rooted hosts/DNS redirect
-> test CA installed as Android system CA
-> adb reverse / host bridge
-> local TLS server
```

Main API uses UnityWebRequest. No managed custom `CertificateHandler` validation or
managed/Java pinning was found on the proven API path. Use SANs for each original
hostname; API and storage hostnames need appropriate certificates.

## First real-device run

Control server first:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter-control.jsonl `
  --api-map .\work\final_map.json
```

Native 214 should be tested first. Redirect the storage hostname and run the
resource server with its own sanitized event log when the client enters resource
initialization.

Expected observable progression is now:

```text
/load/check 214
-> @resource/manifest and/or @resource/<category>
-> /load/index
-> static Home(6) / Login_Bonus(7) tail
```

Do not wait for a second `/load/check` before enabling/diagnosing the resource
plane.

## Remaining real blockers

Static high-value bootstrap gaps are mostly closed. The remaining decisive work is
runtime integration:

1. original untouched 11.6.3 trusts local TLS and reaches `/load/check`;
2. native 214 causes actual resource-plane traffic using local 10133800 archive;
3. resource initialization completes and `/load/index` is reached;
4. starter-visible response is accepted and Home visibly renders;
5. capture the first unsupported post-Home endpoint/state and implement only that.

If no device is available, continue deterministic tooling/tests/docs and targeted
bounded static analysis. Do not redo solved crypto/map/resource freeze work.

## Issue status

```text
#1 M0 final specimen: closed
#2 M1 final 10133800 resource freeze: closed
#3 M2 final-client transport/startup/Home acceptance: open
```
