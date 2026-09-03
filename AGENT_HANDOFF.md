# AGENT HANDOFF — cgss-relive

This is the authoritative continuation entry point for `kohakunamori/cgss-relive`.
**Do not restart solved research.** Fetch the actual `main` HEAD first, verify CI,
then continue from the runtime-integration milestone.

Snapshot when this handoff was refreshed:

```text
main: 5e740b7483cfbd3ce8a3a4ac301876bc4a6bb88c
```

The repository may have advanced after this line was written.

## Mission

Make the original untouched final Android CGSS client boot against a clean-room
local compatibility stack and eventually enter/use preserved Home/content.

Final specimen:

```text
package:          jp.co.bandainamcoent.BNEI0242
app version:      11.6.3
versionCode:      438
Unity:            2022.3.56f1
runtime:          IL2CPP
metadata version: 31
```

Never commit APK/XAPK, `libil2cpp.so`, metadata, master/manifest databases,
resource bodies, production credentials/session values, plaintext client-static
keys/salts, raw sensitive captures, or bulk decompiler output.

## Required reading

Read these before changing protocol/runtime code:

```text
docs/load-check-11.6.3.md
docs/load-index-11.6.3.md
docs/rooted-device-integration.md
docs/runtime-event-analysis.md
docs/local-resource-server.md
docs/resource-bootstrap.md
docs/protocol-11.6.3.md
```

## Solved protocol facts — do not regress

The final request/response codec is implemented and tested:

```text
JSON -> MessagePack -> Base64 -> AES-256-CBC -> Base64(cipher || dynamic 32-byte key)
IV = UDID-derived 16 bytes
```

UDID-header decoding, PARAM/SID/viewer wrapper research and final response wrapping
are already in:

```text
server/cgss_codec.py
server/header_codec.py
server/bootstrap_core.py
```

Do not rediscover them unless a real-client observation contradicts a concrete
fixture.

Final result codes currently proven:

```text
success           1
session error     201
app-version error 204
resource-version  214
```

## Resource versions — keep both values

Final binary/default literal:

```text
10133000
```

Independently verified final server/resource revision:

```text
10133800
```

Frozen resource verification is complete. Issue #2 is closed.

Important frozen counts:

```text
manifest rows          220837
unique resource hashes 220803
archive planned        220803
archive skipped        0
master tables          909
card_data rows          4314
```

Archive layout:

```text
resource-cache/10133800/objects/<hash[0:2]>/<hash>
```

## Correct `/load/check` semantics

This was materially corrected by final 11.6.3 static control-flow analysis.

For incoming old `RES-VER`, default compatibility behavior is:

```text
/load/check RES-VER=10133000
  -> result_code=214
  -> required_res_ver=10133800
  -> data.isS3=false
```

**214 does not automatically resend `/load/check` inside the same d48 network
coroutine.** Common result handling persists `required_res_ver` into Savedata
`RES_VER`; later resource/update/version-check behavior belongs to a higher-level
state machine.

Do not describe this as `214 -> immediate retry` without runtime evidence.

The server also has an explicit differential mode:

```text
--accept-old-resource-version
```

This returns:

```text
result_code=1
required_res_ver=10133800
data.isS3=false
```

for an old request. It exists only to separate a 214/resource-stage blocker from
a later BootMain `/load/index` blocker. It is not the default protocol model.

## Resource host and URL builders

`VersionCheckTask.Parse` writes `data.isS3` into `NetworkUtil.isS3`.

Final resource hosts:

```text
isS3=false -> storages.game.starlight-stage.jp
isS3=true  -> asset-starlight-stage.akamaized.net
```

The compatibility server fixes `isS3=false` for deterministic offline tests.

Do not regress to the old assumption that every resource URL is:

```text
/dl/resources/<Category>/<hh>/<hash>
```

Final-client builders include:

```text
/dl/<ver>/manifests/<file>
/dl/<ver>/[Low|High/]AssetBundles/<Platform>/...
/dl/resources/[Low|High/]AssetBundles/<Platform>/...[.lz4]
/dl/<ver>/[Low|High/]Sound/<Platform|Common>/...
/dl/resources/[Low|High/]Movie/...
/dl/<ver>/Generic/Blob|Master/...
/dl/resources/Generic/...
```

Hash-prefix sharding exists only in specific CDN/isS3 branches.

`server/resource_server.py` now:

- serves statically reconstructed final-client URL families;
- maps them to the content-addressed archive;
- can load a local final manifest SQLite DB read-only with `--manifest-db` for
  filename -> hash resolution;
- can serve locally placed verified wire bootstrap manifests from
  `<root>/manifests/` at `/dl/10133800/manifests/*`;
- supports GET/HEAD/range/TLS;
- never synthesizes proprietary manifest/resource data.

## TLS integration

Static final-client evidence:

- main API stack uses UnityWebRequest;
- no managed `CertificateHandler` subclass / `ValidateCertificate` override;
- no managed/Java pinning wired into the API path;
- manifest has no custom networkSecurityConfig/cleartext opt-in;
- targetSdk 35.

Preferred integration remains:

```text
original HTTPS hostname
-> reversible rooted hosts/DNS redirect
-> test CA trusted as Android system CA
-> adb reverse / host bridge
-> local TLS server
```

Use a cert SAN matching each original hostname. Do not assume the control API cert
also covers `storages.game.starlight-stage.jp`.

## Final endpoint map

Validated final map facts:

```text
A: 516 records, keys 0..515 continuously
B: 22 records
```

Six `load/*` routes:

```text
0   load/check
1   load/set_cache_clear_flg
10  load/title
11  load/index
12  load/get_external_site_url
13  load/update_agreement_status
```

There is no final `home/index` or `home/load`. `home/update` is later.

Implemented control routes:

```text
/load/check
/load/title
/load/index
/load/set_cache_clear_flg
/load/update_agreement_status
```

`/load/get_external_site_url` remains deliberately un-faked until a caller proves
what business URL it needs.

## Correct bootstrap mainline

Another important correction: `/load/title` is **not** a proven hard prerequisite
for Home. It is a Title-screen/user-driven task.

Current statically closed mainline:

```text
ResourcesManager.GameInitialize
 -> BootNetwork.SetupNetwork
 -> SetupNetworkCoroutine
 -> Certification.Login
 -> /load/check (existing viewer)
 -> [higher-level resource/view transition NOT yet statically closed]
 -> BootMain.FinishLoad
 -> BootMain.Initialize
 -> asset predownload/verify
 -> BootMain.StartConnect
 -> /load/index
 -> Stage.LoadTask.Parse (RVA 0x04850a94)
 -> Parse == 1
 -> BootMain.CallbackOnSuccessLoad
 -> BootMain.LastInitialized
 -> BootMain.ChangeView
 -> SceneManager.ChangeView(next = loginBonus ? 7 : 6)
 -> Home semantics
```

Static gaps that remain real gaps:

- exact `/load/check success/214 -> BootMain` higher-level transition;
- resource-download-complete -> later version-check call site;
- exact enum names/visible mapping for ChangeView IDs 6 and 7.

Do not invent answers for these without raw-binary static evidence or device
runtime evidence.

## `/load/index` parser facts

`Stage.LoadTask.Parse` target:

```text
RVA 0x04850a94
```

Hard envelope on the normal established-account path:

```text
data
└─ common_define
```

Seven direct `common_define` ints:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

Current direct `user_info` synthetic scalar set:

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

Most accumulated feature sections are guard/empty safe. A major failure mode is
**providing a guarded parent but omitting one of its hard children**: the parser
can jump to its shared early exit and still leave the framework with the common
success result. Therefore do not add partial empty objects indiscriminately.

## Correct unit contract

This was fixed in code at commit:

```text
2b9609868e7502534723b012a7caec4cd84c8999
```

Top-level `user_unit_list` is guarded and may be omitted/empty.

A non-empty unit's first final parse pass hard-reads:

```text
unit_slot   # 1-based
name
```

Then it scans exactly five formatted slots (`cmp w20,#5`):

```text
serial_id_0
serial_id_1
serial_id_2
serial_id_3
serial_id_4
```

Missing/zero serial entries are safe in that first pass.

A later independent pass directly reads:

```text
unit_id
name
```

The starter-visible profile conservatively supplies both `unit_slot` and
`unit_id`, plus all five serial keys. The old repository claim that
`user_info.unit_slot` was required for an empty list was wrong and has been
removed.

## Starter-visible first

Final master independently proves:

```text
card_id 100001 = 島村卯月
chara_id 101
```

Synthetic preservation state:

```text
serial_id        1
unit_slot        1
unit_id          1
leader_serial_id 1
```

Use this first:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter.jsonl `
  --api-map .\work\final_map.json
```

Use empty/strict profiles only as differential fallbacks.

## Runtime analyzer semantics

`scripts/analyze-runtime-events.py` report schema is now **2**.

It deliberately distinguishes:

```text
server_returned_214
observed_later_control_request_after_214
observed_later_10133800_load_check_after_214
server_returned_direct_success_with_required_res_ver
observed_followup_request_after_direct_success
server_returned_success_for_10133800
observed_followup_request_after_10133800_success
```

There is no “automatic retry observed” field anymore.

`/load/title` remains in `reached`, but it does not advance the hard-mainline
`phase` because it is not statically proven to sit between check and index.

The event log must never contain UDID, SID, USER-ID, PARAM, viewer-id values, or
decoded request/response values.

## Recent implementation sequence

Key recent commits, oldest -> newest around this handoff:

```text
2b960986  fix: align starter unit with final parser
dd4c6d6c  feat: serve final-client resource URL families
f6da209a  test: cover final-client resource URL families
757cf340  feat: add explicit load-check resource policy controls
21cbd815  feat: expose load-check runtime differential controls
703b0394  feat: expose direct-success load-check diagnostic mode
374d7ffd  test: cover load-check resource policies
4201d43c  docs: align local resource server with final URL builders
eb6b1c19  docs: rewrite final-client rooted integration flow
6cdfe96f  docs: correct final load-index unit and Home semantics
10c2729a  docs: correct final load-check 214 semantics
5a0b1bdf  fix: model load-check followups without retry claim
ba862e77  test: distinguish later checks from automatic retries
5e740b74  docs: remove automatic-retry language from runtime analysis
```

Always fetch actual HEAD/CI rather than assuming this list is final.

## Next execution order

1. Fetch `main`, verify CI green.
2. If rooted Android + original untouched 11.6.3 is available, run native-214
   starter-visible path with sanitized event log + local logcat.
3. Run equivalent `--accept-old-resource-version` direct-success differential.
4. If native mode enters resource update, redirect
   `storages.game.starlight-stage.jp`, use `server.resource_server` with the local
   frozen archive/manifest DB/wire manifests, and record exact requested paths.
5. If `/load/index` is reached, observe whether a later client action/Home appears.
6. Only add response fields/endpoints proven necessary by the first observed
   blocker.
7. Keep Issue #3 synchronized and CI green.

If no device/raw binary is available, the remaining high-value work is limited to
deterministic tooling/docs/tests. Do not fabricate the three static gaps listed
above and do not redo solved crypto/resource-version/map research.

## Issue status

```text
#1 M0 final specimen: closed
#2 M1 final 10133800 resource freeze: closed
#3 M2 final-client transport/startup/Home acceptance: open
```
