# AGENT HANDOFF — cgss-relive

Authoritative continuation point for `kohakunamori/cgss-relive`.

**Do not restart solved research.** The authoritative local worktree is
`D:\Project\cgss-relive`, branch `client-research-fixed`. Use AgentDock for host,
ADB, Frida, and device operations; WebCodex is retired. Preserve the current
working tree before any branch/reset operation, verify tests/CI, then continue
from the first unsupported post-Home dependency.

## Mission

Make the original untouched final Android CGSS client 11.6.3 boot against a
clean-room local compatibility stack, enter preserved Home, then restore later
offline endpoints/content one blocker at a time.

Final specimen:

```text
package          jp.co.bandainamcoent.BNEI0242
app version      11.6.3
versionCode      438
Unity            2022.3.56f1
runtime          IL2CPP
metadata version 31
```

Exact frozen hashes:

```text
XAPK
609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d

arm64 libil2cpp.so
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

Never commit APK/XAPK, `libil2cpp.so`, metadata, manifest/master DBs, resource
bodies, production credentials/session values, plaintext static key/salt, raw
sensitive captures, or bulk decompiler output.

The exact-specimen Actions workflow verifies the frozen hashes, runs bounded
analysis, deletes raw binaries and uploads only sanitized derived reports.

## Read first

```text
docs/rooted-device-integration.md
docs/load-check-11.6.3.md
docs/load-index-11.6.3.md
docs/load-task-param-11.6.3.md
docs/runtime-event-analysis.md
docs/local-resource-server.md
docs/resource-bootstrap.md
docs/protocol-11.6.3.md
```

## Protocol — solved

```text
JSON -> MessagePack -> Base64 -> AES-256-CBC -> Base64(cipher || dynamic 32-byte key)
IV = UDID-derived 16 bytes
```

Implemented/tested in `server/cgss_codec.py`, `server/header_codec.py`, and
`server/bootstrap_core.py`.

Result codes:

```text
1   success
201 session error
204 app-version error
214 resource-version transition
```

Do not rediscover crypto unless original-client runtime contradicts a concrete
fixture.

## Resource versions/freeze

```text
binary/default RES_VER 10133000
final frozen revision  10133800
```

Frozen facts:

```text
manifest rows          220837
unique hashes          220803
archive planned        220803
archive skipped        0
master tables          909
card_data rows          4314
```

Archive layout:

```text
resource-cache/10133800/objects/<hash[0:2]>/<hash>
```

Bootstrap wire files:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

## Resource filename resolver — final-manifest complete

Final `manifests.name` is not universally a basename. Aggregate final DB facts:

```text
names containing '/'          12317
unique basenames              220652
basename collision groups        137
basename hash-conflict groups    130
```

Therefore basename aliases are unsafe.

`server/resource_server.py` now resolves filename URLs by exact relative suffix,
longest-first. `.lz4` stripping happens at the same suffix depth. No fuzzy
basename alias is built.

The real final 10133800 DB is checked by
`scripts/verify-final-manifest-resolution.py`. Closed aggregate result:

```text
rows              220837
resolved          220837
unresolved             0
mismatched             0
unknown category        0
path-shaped names   12317

AssetBundles       207694
Sound                11832
Generic                826
Movie                  485
```

Do not regress to leaf-only lookup or infer that a future runtime 404 is a
basename problem.

## Resource preflight — schema 3

`scripts/preflight-local-resources.py` must report `ready=true` before a real
device run. It emits only counts/booleans/failure codes.

It checks:

```text
manifest SQLite quick_check
manifest rows == 220837
unique hashes == 220803
all expected objects present/non-zero
all_dbmanifest parses Android_AHigh_SHigh MD5
Android_AHigh_SHigh bytes match that MD5
CGSS wrapper/LZ4 decode succeeds
decoded bytes are SQLite
decoded SQLite bytes == supplied manifest DB
master.mdb manifest entry exists
master.mdb object exists
master.mdb actual MD5 == manifest hash
```

Do not replace these strong gates with existence-only checks.

## `/load/check` — native semantics

Untouched binary startup:

```text
request RES-VER=10133000
 -> result_code=214
 -> required_res_ver=10133800
 -> data.isS3=false
```

214 is accepted, the required version is persisted, and there is **no automatic
same-task retry** of `/load/check`.

Higher-level continuation:

```text
/load/check 214
 -> Savedata RES_VER=10133800
 -> SetupNetwork ready
 -> GameInitialize resumes
 -> AssetManager.InitializeManifest
 -> DownloadOrLoadForInitialize
 -> resource work
 -> GameInitialize completes
 -> BootMain.StartConnect
 -> /load/index
```

`--accept-old-resource-version` is diagnostic only.

## Resource host / URL families

Server fixes `isS3=false`:

```text
API      apis.game.starlight-stage.jp
resource storages.game.starlight-stage.jp
```

Supported final families include:

```text
/dl/<ver>/manifests/<file>
/dl/<ver>/[Low|High/]AssetBundles/<Platform>/<tail>
/dl/resources/[Low|High/]AssetBundles/<Platform>/<tail>
/dl/<ver>/[Low|High/]Sound/<Platform|Common>/<tail>
/dl/resources/[Low|High/]Movie/<tail>
/dl/<ver>/Generic/Blob|Master/<tail>
resource/hush Generic forms
per-bundle .../manifest/<file>
```

isS3=false appends filename/hash directly. Do not invent a universal CDN-style
`<prefix2>/<hash>` route.

Resource evidence is category-only:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

No name/hash/query is logged.

## `/load/index` reduced starter

`Stage.LoadTask.Parse` RVA `0x04850a94`.

Required `common_define` ints:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

Current `user_info` scalar core:

```text
tutorial_flag viewer_id name comment
max_card_num max_room_storage_num
friend_pt jewel free_jewel gold stamina
level exp fan producer_rank birth
sum_of_money last_payment_date stamina_heal_time
```

Completed tutorial is closed:

```text
wire tutorial_flag=100 -> local TutorialData.step=1000 -> Save
```

Do not send wire value 1000.

Final-master starter identity:

```text
card_id 100001 = 島村卯月
```

Synthetic state:

```text
serial_id        1
unit_slot        1
unit_id          1
leader_serial_id 1
```

Correct owned-card container:

```text
user_card_list = []
cs_gacha_data_cenere = [one card]
```

A non-empty `cs_gacha_data_cenere` calls `WorkCardData.AddCardData` and hard-reads:

```text
serial_id card_id exp step love skill_level protect
```

Home card predownload resolves unit serial through WorkCardData, so serial 1 must
exist there.

Unit contract:

```text
unit_slot + name
serial_id_0 .. serial_id_4
later: unit_id + name
```

Current serial slots are `[1,0,0,0,0]`.

`user_chara_list` is a real parser block; empty array is proven safe. A row would
hard-read `chara_id` + `fan` and create WorkCharaData, but bounded Home startup has
no WorkCharaData consumer. Current starter therefore intentionally keeps:

```text
user_chara_list = []
```

Do not re-add it without runtime/consumer evidence.

## `LoadTaskParam` — request-side, not response-side

The remaining `load_state` / `next_api` ambiguity is now statically closed by the
exact final specimen. Bounded exact run `33743831567` established:

```text
LoadTaskParam : BaseParam : PostParams
NetworkTask.Params : PostParams @ +0x30
LoadTaskParam.load_state @ +0x40
LoadTaskParam.next_api   @ +0x50
```

`Stage.LoadTask.SetParameter @ 0x04877A14` constructs/initializes the parameter
object through `Stage.BaseParam::.ctor`, writes `load_state` and `next_api` on the
same `x20` object from local/task state, then stores that object into
`NetworkTask.Params` at `this+0x30`.

This corrects the older attempted model that treated `this+0x30` as a child-load
site. It is a write/assignment site. These fields are outbound task/request
parameter state and are **not** `/load/index` response requirements. Do not add
either key to the starter response. See `docs/load-task-param-11.6.3.md`.

## `/load/index` -> Home — statically closed

```text
/load/index
 -> LoadTask.Parse
 -> BootMain.CallbackOnSuccessLoad
 -> BootMain.LastInitialized
 -> BootMain.ChangeView
 -> SceneManager.ChangeView
```

View IDs:

```text
BootMain       5
Home           6
Login_Bonus    7
Asset_Download 8
```

Visible Home is now **runtime-closed on the original 11.6.3 client**.

2026-09-05 first-time Asset Download evidence on OnePlus 8T (`b57d21c6`):

```text
AssetDownload.FinishLoadCommonData @ 0x398850c
 -> AssetDownload.FinishLoadStandardData @ 0x3988624
 -> SceneManager.ChangeView(view=6, is_force=false)
 -> Stage.Home.Start @ 0x3ec16f8
 -> Stage.Home.FinishLoad @ 0x3ec49ac
 -> Stage.Home.StartViewProcess @ 0x3ecce20
```

No parser return, result code, scene ID, verifier result, or callback was forced.
The 4927-item first-time predownload completed through the original Asset Download
UI while asset traffic used the official CDN family. The main runtime trace
contains no exception/error signal after Home entry.

A subsequent cold start is even stronger: the observed scene sequence is exactly
`4 -> 5 -> 6` with **no view 8**, `/load/index` returns naturally, then the same
`Home.Start -> Home.FinishLoad -> Home.StartViewProcess` lifecycle executes.
This proves the first-time predownload state persisted and Home is reproducibly
reachable rather than a one-run transition.

Research-only evidence (gitignored):

```text
work/runtime/home-official-assets-s3-clean.jsonl
work/runtime/asset-download-completion-live.jsonl
work/runtime/cgss-home-after-download.png
work/runtime/home-cold-after-download.jsonl
work/runtime/cgss-home-cold-verified.png
work/runtime-api-home-cold-after-download.jsonl
```

## TLS / local topology

Use one multi-SAN leaf containing at least:

```text
apis.game.starlight-stage.jp
storages.game.starlight-stage.jp
```

Topology:

```text
Android original names -> 127.0.0.1:443
    adb reverse tcp:443 -> host tcp:8445
    server.tls_mux :8445
      API Host      -> HTTP :8080
      storages Host -> HTTP :8081
```

`scripts/run-rooted-local-stack.py` refuses readiness until:

1. resource preflight schema 3 passes;
2. API/resource backend health passes;
3. TLS mux starts;
4. API hostname passes CA-chain + exact hostname SAN/SNI verification and Host
   routing using `work/tls/ca.cert.pem`;
5. storages hostname passes the same verification.

This removes wrong CA/leaf/SAN as host-side unknowns. Android system-CA trust is
still a device-side gate.

## Device preparation

`scripts/prepare-device-tunnel.ps1` default is now:

```text
device tcp:443 -> host tcp:8445
```

Do not regress to old 8443.

After manual hosts/system-CA setup and after host stack readiness:

```powershell
.\scripts\prepare-device-tunnel.ps1 -RequireRoot
.\scripts\check-rooted-device.ps1
```

`check-rooted-device.ps1` is read-only. Core `ready=true` requires:

```text
ADB state device
root uid=0
package jp.co.bandainamcoent.BNEI0242 installed
versionName 11.6.3
versionCode 438
reverse tcp:443 -> tcp:8445 present
API hostname -> 127.0.0.1 hosts entry
storages hostname -> 127.0.0.1 hosts entry
```

Exact-byte local-CA presence in common system CA directories is advisory only;
root managers may transform certificate files.

CI now parses all `scripts/*.ps1` via the PowerShell AST parser without executing
ADB commands.

## Runtime analyzer

`scripts/analyze-runtime-events.py` schema 4. Important phases:

```text
resource_version_214_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

Do not require a second `/load/check`.

## First real-device sequence

1. Generate multi-SAN test CA/leaf.
2. Manually install CA into Android system trust and map both original names to
   127.0.0.1.
3. Start `scripts/run-rooted-local-stack.py`; require readiness.
4. Run `scripts/prepare-device-tunnel.ps1 -RequireRoot`.
5. Run `scripts/check-rooted-device.ps1`; require core `ready:true`.
6. Launch untouched original 11.6.3.
7. Keep raw process logcat only under private/gitignored work state; preserve
   shareable sanitized control/resource/device JSONL.
8. Analyze the merged timeline and inspect the actual screen state.

Expected high-level progression:

```text
/load/check 214
 -> resource bootstrap/work
 -> /load/index
 -> Home(6) or Login_Bonus(7) -> Home
```

## Remaining blockers

The original-client bootstrap/Home milestone is closed. Do **not** spend more time
on CA trust, `/load/check` 214, resource initialization, `/load/index`, owned-card
startup, first-time predownload, or Home-entry mechanics unless a later cold run
produces contradictory evidence.

Next work starts **after Home**:

1. observe the first user-visible Home interaction or naturally scheduled task
   that requests an unsupported API/local-state dependency;
2. identify the exact native parser/consumer for that one dependency;
3. implement the smallest clean-room server/state contract supported by runtime
   evidence;
4. add a focused test and rerun the original client;
5. repeat one blocker at a time.

Preserve the same rule: never manufacture success responses, force scenes, swallow
exceptions, bypass parsers, or convert research-only Frida instrumentation into a
preservation requirement.

## Issue state

```text
#1 M0 final specimen: closed
#2 M1 final 10133800 resource freeze: closed
#3 M2 final transport/startup/Home acceptance: closed 2026-09-05
#4 M3 post-Home offline functionality recovery: open
```
