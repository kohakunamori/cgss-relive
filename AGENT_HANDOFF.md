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

The repository contains an ephemeral exact-specimen GitHub Actions analysis
workflow. It verifies the hashes, runs bounded targeted analysis, deletes raw
binaries, and uploads only sanitized reports.

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

Do not rediscover solved crypto unless original-client runtime contradicts a
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

Before any real-device run, `scripts/preflight-local-resources.py` must report
`ready=true`. It checks the final manifest DB, both wire manifests and every
220803 expected object without emitting names/hashes.

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

The diagnostic flag `--accept-old-resource-version` exists only for a controlled
differential; it is not the native/default model.

## Bootstrap resource continuation — statically closed

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

## Resource hosts / local server

`VersionCheckTask.Parse` writes `data.isS3` into `NetworkUtil.isS3`.

```text
isS3=false -> storages.game.starlight-stage.jp
isS3=true  -> asset-starlight-stage.akamaized.net
```

Compatibility server fixes `isS3=false` for deterministic local preservation.

`server/resource_server.py` supports the reconstructed final storages URL
families, manifest DB filename resolution, wire manifests, GET/HEAD/ranges and a
sanitized resource event log.

Only category routes are logged:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

Filename/hash/query values are never written to the runtime evidence log or the
resource server's default console access log.

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

`/load/get_external_site_url` remains deliberately un-faked until a real caller
proves required business semantics.

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

Most feature sections are guarded/empty safe. Do not add partially populated
guarded objects: once a guarded parent is present, some child reads become hard.

## Tutorial gate — closed

Exact `Stage.BaseTask.setupTutorial @ 0x0476e1e4` proves:

```text
wire tutorial_flag=100
 -> TutorialData.set_step(1000)
 -> Save()
```

If local step is already `1000`, the method normalizes the logical flag to `100`.
Therefore:

```text
COMPLETED_TUTORIAL_FLAG       = 100
COMPLETED_TUTORIAL_LOCAL_STEP = 1000
```

Do not change the response value to `1000`; `1000` is the persisted local step.

## Starter card/unit contract — closed enough for first runtime

Card identity from final master:

```text
card_id 100001 = 島村卯月
```

Synthetic ownership/unit state:

```text
serial_id        1
unit_slot        1
unit_id          1
leader_serial_id 1
```

Important card-container correction:

```text
user_card_list = []
```

The actual parser block that creates a WorkCardData object is the exact literal:

```text
cs_gacha_data_cenere
```

A non-empty element calls `WorkCardData.AddCardData` and hard-reads:

```text
serial_id
card_id
exp
step
love
skill_level
protect
```

The starter puts serial `1` / card `100001` there.

`Stage.Home.CardDownloadList @ 0x03ec0d70` immediately resolves the unit serial via
`WorkCardData.GetCardDataWithSerial`, so this correction is required before Home
predownload state can work.

For non-empty `user_unit_list`:

```text
first pass: unit_slot + name
fixed loop: serial_id_0 .. serial_id_4 (exactly five)
later pass: unit_id + name
```

The starter explicitly sets all five serial slots and uses `serial_id_0=1`.

## `user_chara_list` — now closed for starter minimization

The key is real. Exact string literal:

```text
user_chara_list = 0x085c6820
```

Final `LoadTask.Parse` xref is in the `0x0485d17c` region. The bounded block
proves:

```text
JsonData.get_Count
cmp w0,#1
b.lt -> next block
```

so `user_chara_list=[]` is safe.

If a row is supplied, it hard-reads exactly:

```text
chara_id
fan
```

then calls `Stage.WorkCharaData.AddCharaData` at call site `0x0485d2b8`.

The old synthetic `{chara_id:101, fan:0}` row was structurally valid but not
needed for the first Home experiment. Bounded Home startup analysis contains no
`WorkCharaData` consumer. The real card predownload worker instead obtains
character identity directly from its WorkCardData card:

```text
WorkCardData.CardData.GetCharaId @ 0x03ec0fdc
WorkCardData.CardData.GetCharaId @ 0x03ec1294
```

Therefore the current starter deliberately keeps:

```text
user_chara_list = []
```

Do not re-add the synthetic character row without runtime or bounded consumer
evidence.

## `/load/index` -> Home — statically closed

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
Visible Home with the local stack is still runtime-pending because static control
flow does not claim what an unrun original client rendered.

## Home startup state analysis

Exact/bounded `Stage.Home.Start` and `StartViewProcess` analysis does not reveal a
mandatory post-`/load/index` API call. Startup enters local/resource-facing
helpers including `PreDownloadList`, banner/popup preparation and view setup.

The real `CardDownloadList` is the most important starter dependency and is why a
valid WorkCardData serial is kept. Optional campaign/lottery/questionnaire/MV
WorkData observed through banner setup remains skip/default-safe; do not populate
those `/load/index` sections without runtime evidence.

## Runtime analyzer

`scripts/analyze-runtime-events.py` report schema is **3**.

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

Hard phases include:

```text
resource_version_214_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

Runtime logs must never contain UDID, SID, USER-ID, PARAM, viewer-id values,
decoded request/response values, resource filenames, or object hashes.

## Rooted-device stack — preferred topology

The untouched client reaches more than one original HTTPS hostname on port 443.
Use one multi-SAN leaf certificate and a single local TLS mux:

```text
Android original client
  -> hosts/DNS: API + storages names -> 127.0.0.1
  -> adb reverse tcp:443 -> host tcp:8445
  -> server.tls_mux :8445
       ├─ apis.game.starlight-stage.jp     -> HTTP 127.0.0.1:8080
       └─ storages.game.starlight-stage.jp -> HTTP 127.0.0.1:8081
```

The test CA must be installed as an Android **system CA** on the rooted device.
The leaf SANs must include at least:

```text
apis.game.starlight-stage.jp
storages.game.starlight-stage.jp
```

## First real-device run — use the supervisor

Preferred launch is now one foreground command rather than three manually managed
servers:

```powershell
python .\scripts\run-rooted-local-stack.py `
  --resource-root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --api-map .\work\final_map.json `
  --viewer-id 1 `
  --producer-name "Relive Producer"
```

The supervisor:

1. runs the full 10133800 resource preflight and refuses to start on failure;
2. starts control API on `127.0.0.1:8080` with starter-visible profile;
3. health-checks it;
4. starts resource backend on `127.0.0.1:8081` and health-checks it;
5. starts the multi-SAN TLS mux on `127.0.0.1:8445`;
6. tears down the whole stack if any child exits unexpectedly.

Default is native 214 behavior. The supervisor exposes
`--accept-old-resource-version` only as an explicit diagnostic differential.

Then bridge the rooted device:

```powershell
.\scripts\prepare-device-tunnel.ps1 `
  -DevicePort 443 `
  -HostPort 8445 `
  -RequireRoot
```

The device still needs both original hostnames redirected to `127.0.0.1` and the
multi-SAN test CA installed as a system CA.

Expected observable progression:

```text
/load/check 214
-> @resource/manifest and/or @resource/<category>
-> /load/index
-> static Home(6) / Login_Bonus(7) tail
```

Do not wait for a second `/load/check` before diagnosing the resource plane.

## Remaining real blockers

Static high-value bootstrap gaps are now mostly closed. The decisive work is
runtime integration:

1. original untouched 11.6.3 trusts local TLS and reaches `/load/check`;
2. native 214 causes actual resource-plane traffic using local 10133800 archive;
3. resource initialization completes and `/load/index` is reached;
4. reduced starter-visible response is accepted and Home visibly renders;
5. capture the first unsupported post-Home endpoint/state and implement only that.

If no device is available, continue deterministic tooling/tests/docs and narrowly
bounded exact-specimen analysis. Do not redo solved crypto/map/resource-freeze
work and do not expand the starter payload without a demonstrated consumer.

## Issue status

```text
#1 M0 final specimen: closed
#2 M1 final 10133800 resource freeze: closed
#3 M2 final-client transport/startup/Home acceptance: open
```
